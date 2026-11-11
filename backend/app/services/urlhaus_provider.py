from datetime import datetime, timezone
from typing import Callable

import httpx

from app.core.config import settings
from app.schemas.threat_intelligence import Indicator, ThreatIntelLookup
from app.services.rate_limiter import RateLimiter


class URLhausProvider:
    name = "urlhaus"
    _url = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self, http_post: Callable[..., httpx.Response] | None = None, rate_limiter: RateLimiter | None = None) -> None:
        self._http_post = http_post or httpx.post
        self._rate_limiter = rate_limiter or RateLimiter(4)

    def lookup(self, indicator: Indicator) -> ThreatIntelLookup:
        timestamp = datetime.now(timezone.utc)
        if indicator.indicator_type != "url":
            return self._result(indicator, timestamp, "Unsupported indicator type.")
        if not settings.urlhaus_auth_key:
            return self._result(indicator, timestamp, "URLhaus authentication key is not configured.")
        if not self._rate_limiter.allow():
            return self._result(indicator, timestamp, "URLhaus rate limit reached.")
        try:
            response = self._http_post(self._url, data={"url": indicator.normalized_value}, headers={"Auth-Key": settings.urlhaus_auth_key}, timeout=10.0)
        except httpx.RequestError as exc:
            return self._result(indicator, timestamp, f"URLhaus request failed: {exc}")
        if response.status_code == 429:
            return self._result(indicator, timestamp, "URLhaus rate limit reached.")
        if response.status_code in {401, 403}:
            return self._result(indicator, timestamp, "URLhaus authentication failed.")
        if response.status_code != 200:
            return self._result(indicator, timestamp, f"URLhaus returned HTTP {response.status_code}.")
        data = response.json()
        status = str(data.get("query_status", "unknown"))
        if status == "no_results":
            return ThreatIntelLookup(indicator_type=indicator.indicator_type, normalized_value=indicator.normalized_value, provider_name=self.name, verdict="unknown", analysis_stats={}, evidence_summary="URLhaus: no results for this URL.", source_reference="https://urlhaus.abuse.ch/", lookup_timestamp=timestamp, lookup_status="available")
        if status != "ok":
            return self._result(indicator, timestamp, f"URLhaus query status: {status}.")
        tags = data.get("tags") or []
        return ThreatIntelLookup(indicator_type=indicator.indicator_type, normalized_value=indicator.normalized_value, provider_name=self.name, verdict="malicious", analysis_stats={"urls": int(len(data.get("urls") or []))}, evidence_summary=f"URLhaus threat: {data.get('threat', 'malware')}; tags: {', '.join(tags) if tags else 'none'}.", source_reference=data.get("urlhaus_reference") or "https://urlhaus.abuse.ch/", lookup_timestamp=timestamp, lookup_status="available")

    def _result(self, indicator: Indicator, timestamp: datetime, summary: str) -> ThreatIntelLookup:
        return ThreatIntelLookup(indicator_type=indicator.indicator_type, normalized_value=indicator.normalized_value, provider_name=self.name, verdict="unknown", evidence_summary=summary, lookup_timestamp=timestamp, lookup_status="unavailable")
