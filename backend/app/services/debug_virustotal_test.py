import json
from datetime import datetime, timezone

import httpx

from app.core.config import settings
from app.schemas.threat_intelligence import Indicator
from app.services.threat_intelligence import ThreatIntelligenceAgent
from app.services.virustotal_provider import VirusTotalProvider

TEST_MD5 = "44d88612fea8a8f36de82e1278abb02f"

def print_header(msg: str) -> None:
    print(f"=== {msg} ===")

# Global counter for outbound HTTP requests (only for this script)
_outbound_requests = 0

def _counted_get(*args, **kwargs):
    global _outbound_requests
    _outbound_requests += 1
    return httpx.get(*args, **kwargs)


def direct_request() -> None:
    """Perform a single GET request to VirusTotal file endpoint and report real HTTP status."""
    if not settings.virustotal_api_key:
        print("API key not configured.")
        return
    url = f"https://www.virustotal.com/api/v3/files/{TEST_MD5}"
    headers = {"x-apikey": settings.virustotal_api_key}
    try:
        # use the counted wrapper to track outbound requests
        resp = _counted_get(url, headers=headers, timeout=10.0)
    except httpx.RequestError as exc:
        print(f"Request error: {exc}")
        return
    print(f"HTTP status code: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        print("Analysis statistics:")
        print(json.dumps(stats, indent=2))
        reputation = attrs.get("reputation")
        print(f"Reputation field: {reputation}")
        source_ref = f"https://www.virustotal.com/gui/file/{TEST_MD5}"
        print(f"Source reference (GUI URL): {source_ref}")
        print(f"Lookup timestamp (UTC): {datetime.now(timezone.utc).isoformat()}")
    elif resp.status_code == 401:
        print("Authentication failed – invalid API key.")
    elif resp.status_code == 404:
        print("Resource not found (the hash is unknown to VirusTotal).")
    elif resp.status_code == 429:
        retry = resp.headers.get("Retry-After")
        print(f"Rate limited – Retry-After: {retry} seconds.")
    else:
        print(f"Unexpected response: {resp.text[:200]}")


def agent_cache_test() -> None:
    """Use a controlled response to demonstrate the shared lookup cache."""
    if not settings.virustotal_api_key:
        print("API key not configured - cannot run cache test.")
        return
    from app.services import ti_cache as cache_mod

    cache_mod._cache.clear()
    global _outbound_requests
    _outbound_requests = 0

    def mocked_get(*args, **kwargs):
        global _outbound_requests
        _outbound_requests += 1
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 1}
                    }
                }
            },
            request=httpx.Request("GET", args[0]),
        )

    provider = VirusTotalProvider(http_get=mocked_get)
    agent = ThreatIntelligenceAgent([provider])
    from app.schemas.alerts import Alert

    dummy_alert = Alert(
        alert_id="debug",
        rule_id="debug",
        rule_name="debug",
        severity="low",
        title="debug",
        description="debug",
        timestamp=datetime.now(timezone.utc),
        host_id="debug",
        event_ids=["debug"],
    )
    indicator = Indicator(
        indicator_type="md5",
        normalized_value=TEST_MD5,
        original_value=TEST_MD5,
        source_event_ids=["debug"],
        source_fields=["raw_payload"],
    )
    result1 = agent.evaluate(dummy_alert, [indicator])
    print_header("First lookup (mocked request)")
    print(f"Lookup status: {result1.indicators[0].lookup_status}")
    print(f"Cached flag: {result1.indicators[0].cached}")
    result2 = agent.evaluate(dummy_alert, [indicator])
    print_header("Second lookup (cache)")
    print(f"Lookup status: {result2.indicators[0].lookup_status}")
    print(f"Cached flag: {result2.indicators[0].cached}")
    print(f"Outbound HTTP requests made: {_outbound_requests}")


if __name__ == "__main__":
    print_header("Direct VirusTotal request")
    direct_request()
    print_header("Agent cache demonstration")
    agent_cache_test()
