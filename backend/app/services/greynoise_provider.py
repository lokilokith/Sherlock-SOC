from datetime import datetime, timezone
import ipaddress
from typing import Callable

import httpx

from app.schemas.threat_intelligence import Indicator, ThreatIntelLookup
from app.services.rate_limiter import RateLimiter


class GreyNoiseProvider:
    name = "greynoise"

    def __init__(self, http_get: Callable[..., httpx.Response] | None = None, rate_limiter: RateLimiter | None = None) -> None:
        self._http_get = http_get or httpx.get
        self._rate_limiter = rate_limiter or RateLimiter(4)

    def lookup(self, indicator: Indicator) -> ThreatIntelLookup:
        timestamp = datetime.now(timezone.utc)
        if indicator.indicator_type not in {"ipv4", "ipv6"}:
            return self._result(indicator, timestamp, "GreyNoise Community supports IP indicators only.")
        if not ipaddress.ip_address(indicator.normalized_value).is_global:
            return self._result(indicator, timestamp, "Private, loopback, or reserved IP was not submitted.")
        if not self._rate_limiter.allow():
            return self._result(indicator, timestamp, "GreyNoise rate limit reached.")
        try:
            response = self._http_get(f"https://www.greynoise.io/v3/community/{indicator.normalized_value}", timeout=10.0)
        except httpx.RequestError as exc:
            return self._result(indicator, timestamp, f"GreyNoise request failed: {exc}")
        if response.status_code == 404:
            return ThreatIntelLookup(indicator_type=indicator.indicator_type, normalized_value=indicator.normalized_value, provider_name=self.name, verdict="unknown", analysis_stats={}, evidence_summary="GreyNoise Community: IP not observed scanning the internet.", source_reference=f"https://viz.greynoise.io/ip/{indicator.normalized_value}", lookup_timestamp=timestamp, lookup_status="available")
        if response.status_code == 429:
            return self._result(indicator, timestamp, "GreyNoise rate limit reached.")
        if response.status_code != 200:
            return self._result(indicator, timestamp, f"GreyNoise returned HTTP {response.status_code}.")
        data = response.json()
        classification = str(data.get("classification", "unknown")).lower()
        verdict = "malicious" if classification == "malicious" else "suspicious" if classification in {"suspicious", "benign"} else "unknown"
        return ThreatIntelLookup(indicator_type=indicator.indicator_type, normalized_value=indicator.normalized_value, provider_name=self.name, verdict=verdict, analysis_stats={"noise": int(bool(data.get("noise"))), "riot": int(bool(data.get("riot")))}, evidence_summary=data.get("message") or f"GreyNoise classification: {classification}.", source_reference=f"https://viz.greynoise.io/ip/{indicator.normalized_value}", lookup_timestamp=timestamp, lookup_status="available")

    def _result(self, indicator: Indicator, timestamp: datetime, summary: str) -> ThreatIntelLookup:
        return ThreatIntelLookup(indicator_type=indicator.indicator_type, normalized_value=indicator.normalized_value, provider_name=self.name, verdict="unknown", evidence_summary=summary, lookup_timestamp=timestamp, lookup_status="unavailable")
