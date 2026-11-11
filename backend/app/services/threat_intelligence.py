from __future__ import annotations
import ipaddress
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime, timezone
from typing import Protocol
from urllib.parse import urlsplit

from app.schemas.alerts import Alert, EvidenceReference
from app.schemas.events import SecurityEvent
from app.schemas.threat_intelligence import (
    Indicator,
    ThreatIntelIndicatorResult,
    ThreatIntelligenceResult,
    ThreatIntelLookup,
)

from app.core.config import settings
from app.services import ti_cache


def _build_providers() -> list:
    """Construct the list of threat‑intel providers based on the current mode.

    * Demo mode – only DemoThreatIntelProvider (no external calls).
    * Live mode – include each configured live provider. If neither API key is
      present the returned list is empty, letting the caller react accordingly.
    """
    if settings.agent_mode == "demo":
        from .demo_agents import DemoThreatIntelProvider
        return [DemoThreatIntelProvider()]

    providers = []
    if settings.virustotal_api_key:
        from .virustotal_provider import VirusTotalProvider
        providers.append(VirusTotalProvider())
    if settings.abuseipdb_api_key:
        try:
            from .abuseipdb import AbuseIPDBProvider
            providers.append(AbuseIPDBProvider())
        except ImportError:
            pass
    return providers


class ThreatIntelError(RuntimeError):
    """Raised when intelligence extraction, lookup, or validation fails."""


class ThreatIntelProvider(Protocol):
    @property
    def name(self) -> str:
        ...

    def lookup(self, indicator: Indicator) -> ThreatIntelLookup:
        ...


_IP = re.compile(r"(?<![\w:.])[0-9A-Fa-f:.]+(?![\w:.])")
_HASH = re.compile(r"(?<![A-Fa-f0-9])([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})(?![A-Fa-f0-9])")
_URL = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+")
_DOMAIN = re.compile(r"(?i)(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
_EXECUTABLE_SUFFIXES = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".sys")


def _hash_type(value: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]


def _add(
    found: dict[tuple[str, str], Indicator],
    indicator_type: str,
    value: str,
    event: SecurityEvent,
    field: str,
) -> None:
    normalized = value.strip().rstrip(".,;)")
    if indicator_type in {"ipv4", "ipv6"}:
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            return
        if address.version == 4:
            indicator_type = "ipv4"
        else:
            indicator_type = "ipv6"
        normalized = str(address)
    elif indicator_type in {"md5", "sha1", "sha256"}:
        normalized = normalized.lower()
    elif indicator_type == "url":
        parsed = urlsplit(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return
        normalized = normalized.rstrip("/")
    elif indicator_type == "domain":
        normalized = normalized.lower().rstrip(".")
        labels = normalized.split(".")
        if (
            len(labels) < 2
            or any(
                not label
                or len(label) > 63
                or label[0] == "-"
                or label[-1] == "-"
                for label in labels
            )
            or normalized.endswith(_EXECUTABLE_SUFFIXES)
        ):
            return
    key = (indicator_type, normalized)
    if key not in found:
        found[key] = Indicator(
            indicator_type=indicator_type,
            normalized_value=normalized,
            original_value=value,
            source_event_ids=[event.event_id],
            source_fields=[field],
        )
    else:
        current = found[key]
        if event.event_id not in current.source_event_ids:
            current.source_event_ids.append(event.event_id)
        if field not in current.source_fields:
            current.source_fields.append(field)


def extract_indicators(events: list[SecurityEvent]) -> list[Indicator]:
    found: dict[tuple[str, str], Indicator] = {}
    for event in events:
        fields = {
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "domain": event.domain,
            "file_hash": event.file_hash,
            "command_line": event.command_line,
        }
        fields.update(
            {
                f"raw_payload.{key}": value
                for key, value in event.raw_payload.items()
                if isinstance(value, (str, int, float))
            }
        )
        for field, raw_value in fields.items():
            if not raw_value:
                continue
            value = str(raw_value)
            for match in _URL.findall(value):
                _add(found, "url", match, event, field)
            for match in _IP.findall(value):
                try:
                    address = ipaddress.ip_address(match)
                except ValueError:
                    continue
                _add(found, f"ipv{address.version}", match, event, field)
            for match in _HASH.findall(value):
                _add(found, _hash_type(match), match, event, field)
            for match in _DOMAIN.findall(value):
                if not any(match in url for url in _URL.findall(value)):
                    _add(found, "domain", match, event, field)
    return list(found.values())


def normalize_manual_indicator(value: str, requested_type: str) -> Indicator:
    normalized = value.strip()
    if not normalized:
        raise ThreatIntelError("IOC value is required.")

    detected_type = requested_type
    hash_type_by_length = {32: "md5", 40: "sha1", 64: "sha256"}
    if detected_type == "auto":
        if re.fullmatch(r"[0-9A-Fa-f]{32}", normalized):
            detected_type = "md5"
        elif re.fullmatch(r"[0-9A-Fa-f]{40}", normalized):
            detected_type = "sha1"
        elif re.fullmatch(r"[0-9A-Fa-f]{64}", normalized):
            detected_type = "sha256"
        else:
            try:
                address = ipaddress.ip_address(normalized)
                detected_type = f"ipv{address.version}"
            except ValueError:
                parsed = urlsplit(normalized)
                if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
                    detected_type = "url"
                else:
                    detected_type = "domain"

    if detected_type in {"ipv4", "ipv6"}:
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError as error:
            raise ThreatIntelError("The IOC is not a valid IPv4 or IPv6 address.") from error
        if detected_type != f"ipv{address.version}":
            raise ThreatIntelError(f"The IOC does not match the selected {detected_type} type.")
        normalized = str(address)
    elif detected_type == "domain":
        normalized = normalized.lower().rstrip(".")
        if (
            len(normalized) > 253
            or "." not in normalized
            or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                   for label in normalized.split("."))
        ):
            raise ThreatIntelError("The IOC is not a valid domain.")
    elif detected_type == "url":
        parsed = urlsplit(normalized)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ThreatIntelError("The IOC is not a valid HTTP or HTTPS URL.")
        normalized = normalized.rstrip("/")
    elif detected_type in {"md5", "sha1", "sha256"}:
        expected_length = {32: "md5", 40: "sha1", 64: "sha256"}[len(normalized)] if len(normalized) in hash_type_by_length else None
        if expected_length != detected_type or not re.fullmatch(r"[0-9A-Fa-f]+", normalized):
            raise ThreatIntelError(f"The IOC is not a valid {detected_type.upper()} hash.")
        normalized = normalized.lower()

    return Indicator(
        indicator_type=detected_type,
        normalized_value=normalized,
        original_value=value.strip(),
        source_event_ids=["manual-enrichment"],
        source_fields=["manual_ioc"],
    )


class MockThreatIntelProvider:
    name = "mock"

    def __init__(self, lookups: dict[tuple[str, str], ThreatIntelLookup] | None = None):
        self.lookups = lookups or {}

    def lookup(self, indicator: Indicator) -> ThreatIntelLookup:
        return self.lookups.get(
            (indicator.indicator_type, indicator.normalized_value),
            ThreatIntelLookup(
                indicator_type=indicator.indicator_type,
                normalized_value=indicator.normalized_value,
                provider_name=self.name,
                verdict="unknown",
                evidence_summary="No intelligence provider result is available.",
                lookup_timestamp=datetime.now(timezone.utc),
                lookup_status="unavailable",
            ),
        )


class ThreatIntelligenceAgent:
    def __init__(
        self,
        providers: list[ThreatIntelProvider] | ThreatIntelProvider,
        timeout_seconds: float = 30,
    ):
        self.providers = providers if isinstance(providers, list) else [providers]
        self.timeout_seconds = timeout_seconds

    def evaluate(
        self,
        alert: Alert,
        indicators: list[Indicator],
        events: list[SecurityEvent] | None = None,
    ) -> ThreatIntelligenceResult:
        if not indicators:
            raise ThreatIntelError("No indicators are available for this alert.")
        if events is not None:
            event_fields = {
                event.event_id: {
                    "event_id", "source", "event_type", "timestamp", "host_id",
                    "user_id", "process_id", "parent_process_id", "process_name",
                    "command_line", "source_ip", "destination_ip", "domain",
                    "file_hash", "raw_payload",
                    *{f"raw_payload.{key}" for key in event.raw_payload},
                }
                for event in events
            }
            if any(
                event_id not in event_fields
                or not set(indicator.source_fields).issubset(event_fields[event_id])
                for indicator in indicators
                for event_id in indicator.source_event_ids
            ):
                raise ThreatIntelError("Indicator references unavailable event evidence.")
        if not self.providers:
            unavailable = [
                ThreatIntelIndicatorResult(
                    indicator_type=indicator.indicator_type,
                    normalized_value=indicator.normalized_value,
                    original_value=indicator.original_value,
                    source_event_ids=indicator.source_event_ids,
                    source_fields=indicator.source_fields,
                    provider_name="none",
                    verdict="unknown",
                    evidence_summary="No threat intelligence provider is configured.",
                    lookup_timestamp=datetime.now(timezone.utc),
                    lookup_status="unavailable",
                )
                for indicator in indicators
            ]
            return ThreatIntelligenceResult(
                alert_id=alert.alert_id,
                investigation_summary="No threat intelligence provider is configured.",
                indicators=unavailable,
                missing_information=["No threat intelligence provider is configured."],
                recommended_next_steps=["Configure an approved threat intelligence provider."],
                evidence_references=[
                    EvidenceReference(event_id=event_id, fields=indicator.source_fields)
                    for indicator in indicators
                    for event_id in indicator.source_event_ids
                ],
            )
        # Prepare results per provider/indicator
        all_results: list[tuple[ThreatIntelProvider, Indicator, ThreatIntelLookup, bool]] = []
        # Use a single-thread executor for timeout handling (consistent with original design)
        executor = ThreadPoolExecutor(max_workers=1)
        for provider in self.providers:
            def _lookup_all() -> list[tuple[Indicator, ThreatIntelLookup, bool]]:
                out: list[tuple[Indicator, ThreatIntelLookup, bool]] = []
                for indicator in indicators:
                    cached = ti_cache.get_cached(provider.name, indicator.indicator_type, indicator.normalized_value)
                    if cached:
                        out.append((indicator, cached, True))
                        continue
                    try:
                        lookup = provider.lookup(indicator)
                        # Cache only successful "available" lookups
                        ti_cache.set_cached(provider.name, indicator.indicator_type, indicator.normalized_value, lookup)
                        out.append((indicator, lookup, False))
                    except Exception as exc:
                        # Create an unavailable lookup preserving original indicator info
                        unavailable = ThreatIntelLookup(
                            indicator_type=indicator.indicator_type,
                            normalized_value=indicator.normalized_value,
                            provider_name=provider.name,
                            verdict="unknown",
                            evidence_summary=f"Provider error: {exc}",
                            lookup_timestamp=datetime.now(timezone.utc),
                            lookup_status="unavailable",
                        )
                        out.append((indicator, unavailable, False))
                return out
            try:
                provider_results = executor.submit(_lookup_all).result(timeout=self.timeout_seconds)
            except TimeoutError as error:
                executor.shutdown(wait=False, cancel_futures=True)
                raise ThreatIntelError("Threat intelligence provider timed out.") from error
            except Exception as error:
                executor.shutdown(wait=False, cancel_futures=True)
                raise ThreatIntelError(f"Threat intelligence provider failed: {error}") from error
            for ind, lk, cached_flag in provider_results:
                all_results.append((provider, ind, lk, cached_flag))
        executor.shutdown(wait=False, cancel_futures=True)

        # Assemble final ThreatIntelligenceResult aligning indicators with lookups
        results: list[ThreatIntelIndicatorResult] = []
        references: list[EvidenceReference] = []
        for provider, indicator, lookup, cached_flag in all_results:
            if lookup.normalized_value != indicator.normalized_value:
                raise ThreatIntelError("Provider returned a mismatched indicator.")
            results.append(
                ThreatIntelIndicatorResult(
                    indicator_type=indicator.indicator_type,
                    normalized_value=indicator.normalized_value,
                    original_value=indicator.original_value,
                    source_event_ids=indicator.source_event_ids,
                    source_fields=indicator.source_fields,
                    provider_name=lookup.provider_name,
                    verdict=lookup.verdict,
                    reputation_score=lookup.reputation_score,
                    confidence=lookup.confidence,
                    analysis_stats=lookup.analysis_stats,
                    evidence_summary=lookup.evidence_summary,
                    source_reference=lookup.source_reference,
                    lookup_timestamp=lookup.lookup_timestamp,
                    lookup_status=lookup.lookup_status,
                    cached=cached_flag,
                )
            )
            references.extend(
                EvidenceReference(event_id=event_id, fields=indicator.source_fields)
                for event_id in indicator.source_event_ids
            )
        return ThreatIntelligenceResult(
            alert_id=alert.alert_id,
            investigation_summary="Threat intelligence results are reported per indicator; unknown results are not treated as malicious.",
            indicators=results,
            missing_information=[
                "Provider intelligence is unavailable."
                for result in results
                if result.lookup_status != "available"
            ],
            recommended_next_steps=["Review unknown indicators with an approved intelligence source."],
            evidence_references=references,
        )

class CrewAIThreatIntelProvider:
    """CrewAI-backed provider for a configured intelligence source."""

    name = "crewai"

    def __init__(self):
        from crewai import Agent, Crew, LLM, Process, Task

        if not os.getenv("SHERLOCK_LLM_MODEL"):
            raise ThreatIntelError("SHERLOCK_LLM_MODEL is not configured.")
        self._agent = Agent(
            role="threat intelligence analyst",
            goal="Assess only the supplied indicator lookup evidence.",
            backstory=(
                "You are a cautious analyst. Unknown provider results remain "
                "unknown, and you never invent reputation or source references."
            ),
            allow_delegation=False,
            llm=LLM(model=os.environ["SHERLOCK_LLM_MODEL"], temperature=0),
        )
        self._task_type = Task
        self._crew_type = Crew
        self._process = Process.sequential

    def lookup(self, indicator: Indicator) -> ThreatIntelLookup:
        prompt = json.dumps(
            {
                "instructions": (
                    "Return JSON only matching ThreatIntelLookup. Use only this "
                    "indicator. If no provider evidence is supplied, use unknown "
                    "verdict and unavailable lookup_status; never fabricate a "
                    "score or source reference."
                ),
                "indicator": indicator.model_dump(mode="json"),
            }
        )
        try:
            raw_output = self._crew_type(
                agents=[self._agent],
                tasks=[
                    self._task_type(
                        description=prompt,
                        expected_output="A single JSON object matching ThreatIntelLookup.",
                        agent=self._agent,
                    )
                ],
                process=self._process,
            ).kickoff().raw
            return ThreatIntelLookup.model_validate_json(raw_output)
        except Exception as error:
            raise ThreatIntelError(
                "CrewAI threat-intelligence provider returned invalid output."
            ) from error
