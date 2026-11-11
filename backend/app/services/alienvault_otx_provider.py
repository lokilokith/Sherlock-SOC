from datetime import datetime, timezone
import ipaddress
from typing import Callable
from urllib.parse import quote

import httpx

from app.core.config import settings
from app.schemas.threat_intelligence import Indicator, ThreatIntelLookup
from app.services.rate_limiter import RateLimiter


class AlienVaultOTXProvider:
    name = "alienvault_otx"
    _url = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self, http_get: Callable[..., httpx.Response] | None = None, rate_limiter: RateLimiter | None = None) -> None:
        self._http_get = http_get or httpx.get
        self._rate_limiter = rate_limiter or RateLimiter(4)

    def lookup(self, indicator: Indicator) -> ThreatIntelLookup:
        timestamp = datetime.now(timezone.utc)
        sections = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "url", "md5": "file", "sha1": "file", "sha256": "file"}
        section = sections.get(indicator.indicator_type)
        if section is None:
            return self._result(indicator, timestamp, "Unsupported indicator type.")
        if indicator.indicator_type in {"ipv4", "ipv6"} and not ipaddress.ip_address(indicator.normalized_value).is_global:
            return self._result(indicator, timestamp, "Private, loopback, or reserved IP was not submitted.")
        if not settings.otx_api_key:
            return self._result(indicator, timestamp, "AlienVault OTX API key is not configured.")
        if not self._rate_limiter.allow():
            return self._result(indicator, timestamp, "AlienVault OTX rate limit reached.")
        try:
            response = self._http_get(
                f"{self._url}/{section}/{quote(indicator.normalized_value, safe='')}/general",
                headers={"X-OTX-API-KEY": settings.otx_api_key},
                timeout=10.0,
            )
        except httpx.RequestError as exc:
            return self._result(indicator, timestamp, f"AlienVault OTX request failed: {exc}")
        if response.status_code in {401, 403}:
            return self._result(indicator, timestamp, "AlienVault OTX authentication failed.")
        if response.status_code == 429:
            return self._result(indicator, timestamp, "AlienVault OTX rate limit reached.")
        if response.status_code != 200:
            return self._result(indicator, timestamp, f"AlienVault OTX returned HTTP {response.status_code}.")
        data = response.json()
        pulse_count = int(data.get("pulse_info", {}).get("count", 0))
        verdict = "malicious" if pulse_count else "unknown"
        return ThreatIntelLookup(indicator_type=indicator.indicator_type, normalized_value=indicator.normalized_value, provider_name=self.name, verdict=verdict, analysis_stats={"pulse_count": pulse_count}, evidence_summary=f"AlienVault OTX pulse count: {pulse_count}.", source_reference=f"https://otx.alienvault.com/indicator/{indicator.indicator_type}/{quote(indicator.normalized_value, safe='')}", lookup_timestamp=timestamp, lookup_status="available")

    def _result(self, indicator: Indicator, timestamp: datetime, summary: str) -> ThreatIntelLookup:
        return ThreatIntelLookup(indicator_type=indicator.indicator_type, normalized_value=indicator.normalized_value, provider_name=self.name, verdict="unknown", evidence_summary=summary, lookup_timestamp=timestamp, lookup_status="unavailable")
