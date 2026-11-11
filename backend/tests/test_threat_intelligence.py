import json
import time
from datetime import datetime, timezone

import pytest

from app.schemas.alerts import Alert
from app.schemas.events import SecurityEvent
from app.schemas.threat_intelligence import Indicator, ThreatIntelLookup
from app.services.threat_intelligence import (
    MockThreatIntelProvider,
    ThreatIntelError,
    ThreatIntelligenceAgent,
    extract_indicators,
)


def event() -> SecurityEvent:
    return SecurityEvent(
        event_id="ti-event-1",
        source="sysmon",
        event_type="network_connection",
        timestamp=datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc),
        source_ip="8.8.8.8",
        domain="Example.COM",
        command_line=(
            "curl https://example.com/path "
            "00112233445566778899aabbccddeeff"
        ),
        raw_payload={
            "EventRecordID": "ti-event-1",
            "DestinationIp": "8.8.8.8",
            "QueryName": "Example.COM",
            "Hashes": (
                "MD5=00112233445566778899aabbccddeeff "
                "SHA256=" + "a" * 64
            ),
        },
    )


def alert() -> Alert:
    return Alert(
        alert_id="SOC-001-ti",
        rule_id="SOC-001",
        rule_name="Suspicious PowerShell Execution",
        severity="medium",
        title="Suspicious PowerShell Execution",
        event_ids=["ti-event-1"],
        source_event_ids=["ti-event-1"],
    )


def test_extracts_and_deduplicates_indicator_types() -> None:
    indicators = extract_indicators([event()])
    values = {(item.indicator_type, item.normalized_value) for item in indicators}

    assert ("ipv4", "8.8.8.8") in values
    assert ("domain", "example.com") in values
    assert ("url", "https://example.com/path") in values
    assert ("md5", "00112233445566778899aabbccddeeff") in values
    assert ("sha256", "a" * 64) in values
    assert len(values) == len(indicators)
    assert all(item.source_event_ids == ["ti-event-1"] for item in indicators)


def test_private_ip_is_extracted_but_not_marked_malicious() -> None:
    private = event().model_copy(update={"source_ip": "192.168.1.10"})
    indicators = extract_indicators([private])
    provider = MockThreatIntelProvider()
    lookup = provider.lookup(
        next(item for item in indicators if item.indicator_type == "ipv4"
             and item.normalized_value == "192.168.1.10")
    )

    assert lookup.verdict == "unknown"
    assert lookup.lookup_status == "unavailable"


def test_rejects_executable_names_as_domains_but_keeps_valid_domains() -> None:
    candidate = event().model_copy(
        update={
            "domain": "updates.example.net",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe https://updates.example.net/a",
        }
    )
    indicators = extract_indicators([candidate])
    domains = {
        item.normalized_value
        for item in indicators
        if item.indicator_type == "domain"
    }

    assert "updates.example.net" in domains
    assert "powershell.exe" not in domains


def test_mock_provider_returns_configured_and_unknown_results() -> None:
    indicator = Indicator(
        indicator_type="domain",
        normalized_value="example.com",
        original_value="Example.COM",
        source_event_ids=["ti-event-1"],
        source_fields=["domain"],
    )
    configured = ThreatIntelLookup(
        indicator_type="domain",
        normalized_value="example.com",
        provider_name="mock",
        verdict="benign",
        reputation_score=10,
        confidence=0.8,
        evidence_summary="Mock fixture result.",
        source_reference="mock://example.com",
        lookup_timestamp=datetime.now(timezone.utc),
        lookup_status="available",
    )
    result = MockThreatIntelProvider({("domain", "example.com"): configured}).lookup(
        indicator
    )

    assert result.verdict == "benign"
    assert result.source_reference == "mock://example.com"


def test_agent_rejects_mismatched_provider_result() -> None:
    indicator = Indicator(
        indicator_type="domain",
        normalized_value="example.com",
        original_value="example.com",
        source_event_ids=["ti-event-1"],
        source_fields=["domain"],
    )

    class BadProvider:
        name = "bad"

        def lookup(self, value: Indicator) -> ThreatIntelLookup:
            return ThreatIntelLookup(
                indicator_type="domain",
                normalized_value="other.example",
                provider_name="bad",
                verdict="unknown",
                evidence_summary="Invalid fixture.",
                lookup_timestamp=datetime.now(timezone.utc),
                lookup_status="unknown",
            )

    with pytest.raises(ThreatIntelError, match="mismatched"):
        ThreatIntelligenceAgent(BadProvider()).evaluate(alert(), [indicator])


def test_agent_provider_timeout_and_unknown_output() -> None:
    indicator = Indicator(
        indicator_type="ipv4",
        normalized_value="8.8.8.8",
        original_value="8.8.8.8",
        source_event_ids=["ti-event-1"],
        source_fields=["source_ip"],
    )
    result = ThreatIntelligenceAgent(MockThreatIntelProvider()).evaluate(
        alert(), [indicator], [event()]
    )
    assert result.indicators[0].verdict == "unknown"
    assert result.indicators[0].lookup_status == "unavailable"

    class SlowProvider:
        name = "slow"

        def lookup(self, value: Indicator) -> ThreatIntelLookup:
            time.sleep(0.1)
            return MockThreatIntelProvider().lookup(value)

    with pytest.raises(ThreatIntelError, match="timed out"):
        ThreatIntelligenceAgent(SlowProvider(), timeout_seconds=0.01).evaluate(
            alert(), [indicator]
        )


def test_agent_rejects_invalid_event_reference() -> None:
    indicator = Indicator(
        indicator_type="ipv4",
        normalized_value="8.8.8.8",
        original_value="8.8.8.8",
        source_event_ids=["missing"],
        source_fields=["source_ip"],
    )

    with pytest.raises(ThreatIntelError, match="unavailable event evidence"):
        ThreatIntelligenceAgent(MockThreatIntelProvider()).evaluate(
            alert(), [indicator], [event()]
        )
