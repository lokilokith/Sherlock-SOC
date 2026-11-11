from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable
from urllib.parse import quote
import base64
import hashlib
import ipaddress

import httpx

from app.core.config import settings
from app.schemas.threat_intelligence import Indicator, ThreatIntelLookup
from app.services.rate_limiter import RateLimiter


class VirusTotalProvider:
    name = "virustotal"
    _base_url = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        http_get: Callable[..., httpx.Response] | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self._http_get = http_get or httpx.get
        self._rate_limiter = rate_limiter or RateLimiter(settings.vt_rate_limit_per_min)

    def lookup(self, indicator: Indicator) -> ThreatIntelLookup:
        timestamp = datetime.now(timezone.utc)
        if indicator.indicator_type in {"ipv4", "ipv6"}:
            address = ipaddress.ip_address(indicator.normalized_value)
            if not address.is_global:
                return self._unavailable(
                    indicator, timestamp, "Private, loopback, or reserved IP was not submitted."
                )
        endpoint = {
            "ipv4": "ip_addresses",
            "ipv6": "ip_addresses",
            "domain": "domains",
            "url": "urls",
            "md5": "files",
            "sha1": "files",
            "sha256": "files",
        }.get(indicator.indicator_type)
        if endpoint is None:
            return self._unavailable(indicator, timestamp, "Unsupported indicator type.")
        if not settings.virustotal_api_key:
            return self._unavailable(indicator, timestamp, "VirusTotal API key is not configured.")
        if not self._rate_limiter.allow():
            return self._unavailable(indicator, timestamp, "VirusTotal rate limit reached.")

        try:
            response = self._http_get(
                    f"{self._base_url}/{endpoint}/{quote(self._resource_id(indicator), safe='')}",
                headers={"x-apikey": settings.virustotal_api_key},
                timeout=10.0,
            )
        except httpx.RequestError as exc:
            return self._unavailable(indicator, timestamp, f"VirusTotal request failed: {exc}")

        if response.status_code != 200:
            status = "unknown" if response.status_code == 404 else "unavailable"
            return self._unavailable(
                indicator,
                timestamp,
                f"VirusTotal returned HTTP {response.status_code}.",
                status=status,
            )

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious:
            verdict = "malicious"
        elif suspicious:
            verdict = "suspicious"
        else:
            verdict = "unknown"
        total = sum(value for value in stats.values() if isinstance(value, int))
        confidence = (malicious + suspicious) / total if total else None
        return ThreatIntelLookup(
            indicator_type=indicator.indicator_type,
            normalized_value=indicator.normalized_value,
            provider_name=self.name,
            verdict=verdict,
            reputation_score=self._reputation_score(attributes.get("reputation")),
            confidence=confidence,
            analysis_stats={
                key: value for key, value in stats.items() if isinstance(value, int)
            },
            evidence_summary=f"VirusTotal analysis statistics: {stats}.",
            source_reference=self._source_reference(indicator),
            lookup_timestamp=timestamp,
            lookup_status="available",
        )

    def _unavailable(
        self, indicator: Indicator, timestamp: datetime, summary: str, status: str = "unavailable"
    ) -> ThreatIntelLookup:
        return ThreatIntelLookup(
            indicator_type=indicator.indicator_type,
            normalized_value=indicator.normalized_value,
            provider_name=self.name,
            verdict="unknown",
            evidence_summary=summary,
            lookup_timestamp=timestamp,
            lookup_status=status,
            analysis_stats={},
        )

    @staticmethod
    def _reputation_score(value: object) -> float | None:
        if isinstance(value, (int, float)):
            return max(0.0, min(100.0, float(value)))
        return None

    def _resource_id(self, indicator: Indicator) -> str:
        if indicator.indicator_type == "url":
            digest = hashlib.sha256(indicator.normalized_value.encode()).digest()
            return base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return indicator.normalized_value

    def _source_reference(self, indicator: Indicator) -> str:
        section = {
            "url": "url",
            "domain": "domain",
            "ipv4": "ip-address",
            "ipv6": "ip-address",
        }.get(indicator.indicator_type, "file")
        return (
            f"https://www.virustotal.com/gui/{section}/"
            f"{quote(self._resource_id(indicator), safe='')}"
        )
