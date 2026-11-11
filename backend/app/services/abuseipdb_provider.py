from datetime import datetime, timezone
import ipaddress
from typing import Callable

import httpx

from app.core.config import settings
from app.schemas.threat_intelligence import Indicator, ThreatIntelLookup
from app.services.rate_limiter import RateLimiter


class AbuseIPDBProvider:
    name = "abuseipdb"
    _url = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, http_get: Callable[..., httpx.Response] | None = None, rate_limiter: RateLimiter | None = None) -> None:
        self._http_get = http_get or httpx.get
        self._rate_limiter = rate_limiter or RateLimiter(settings.abuse_rate_limit_per_min)

    def lookup(self, indicator: Indicator) -> ThreatIntelLookup:
        timestamp = datetime.now(timezone.utc)
        if indicator.indicator_type not in {"ipv4", "ipv6"}:
            return self._result(indicator, timestamp, "Unsupported indicator type.")
        if not ipaddress.ip_address(indicator.normalized_value).is_global:
            return self._result(indicator, timestamp, "Private, loopback, or reserved IP was not submitted.")
        if not settings.abuseipdb_api_key:
            return self._result(indicator, timestamp, "AbuseIPDB API key is not configured.")
        if not self._rate_limiter.allow():
            return self._result(indicator, timestamp, "AbuseIPDB rate limit reached.")
        try:
            response = self._http_get(self._url, params={"ipAddress": indicator.normalized_value, "maxAgeInDays": 90}, headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"}, timeout=10.0)
        except httpx.RequestError as exc:
            return self._result(indicator, timestamp, f"AbuseIPDB request failed: {exc}")
        if response.status_code == 401 or response.status_code == 403:
            return self._result(indicator, timestamp, "AbuseIPDB authentication failed.")
        if response.status_code == 429:
            return self._result(indicator, timestamp, "AbuseIPDB rate limit reached.")
        if response.status_code != 200:
            return self._result(indicator, timestamp, f"AbuseIPDB returned HTTP {response.status_code}.")
        data = response.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        verdict = "malicious" if score >= 75 else "suspicious" if score > 0 else "unknown"
        return ThreatIntelLookup(
            indicator_type=indicator.indicator_type,
            normalized_value=indicator.normalized_value,
            provider_name=self.name,
            verdict=verdict,
            reputation_score=float(score),
            analysis_stats={"total_reports": int(data.get("totalReports", 0)), "distinct_reporters": int(data.get("numDistinctUsers", 0))},
            evidence_summary=f"AbuseIPDB confidence score: {score}.",
            source_reference=f"https://www.abuseipdb.com/check/{indicator.normalized_value}",
            lookup_timestamp=timestamp,
            lookup_status="available",
        )

    def _result(self, indicator: Indicator, timestamp: datetime, summary: str) -> ThreatIntelLookup:
        return ThreatIntelLookup(indicator_type=indicator.indicator_type, normalized_value=indicator.normalized_value, provider_name=self.name, verdict="unknown", evidence_summary=summary, lookup_timestamp=timestamp, lookup_status="unavailable")
