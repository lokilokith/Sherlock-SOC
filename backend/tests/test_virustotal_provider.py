import httpx

from app.core.config import settings
from app.schemas.threat_intelligence import Indicator
from app.services import virustotal_provider
from app.services.rate_limiter import RateLimiter
from app.services.virustotal_provider import VirusTotalProvider
from dataclasses import replace


def indicator(value: str = "44d88612fea8a8f36de82e1278abb02f") -> Indicator:
    return Indicator(
        indicator_type="md5",
        normalized_value=value,
        original_value=value,
        source_event_ids=["event-1"],
        source_fields=["file_hash"],
    )


def test_zero_malicious_detections_are_unknown(monkeypatch) -> None:
    monkeypatch.setattr(
        virustotal_provider,
        "settings",
        replace(settings, virustotal_api_key="test-key"),
    )
    response = httpx.Response(
        200,
        json={"data": {"attributes": {"last_analysis_stats": {
            "malicious": 0, "suspicious": 0, "undetected": 70
        }}}},
        request=httpx.Request("GET", "https://example.test"),
    )
    lookup = VirusTotalProvider(
        http_get=lambda *args, **kwargs: response,
        rate_limiter=RateLimiter(10),
    ).lookup(indicator())

    assert lookup.lookup_status == "available"
    assert lookup.verdict == "unknown"
    assert lookup.analysis_stats["undetected"] == 70


def test_malicious_suspicious_and_http_errors(monkeypatch) -> None:
    monkeypatch.setattr(
        virustotal_provider,
        "settings",
        replace(settings, virustotal_api_key="test-key"),
    )
    provider = VirusTotalProvider(
        http_get=lambda *args, **kwargs: httpx.Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {
                "malicious": 4, "suspicious": 2, "undetected": 60
            }}}},
            request=httpx.Request("GET", "https://example.test"),
        ),
        rate_limiter=RateLimiter(10),
    )
    assert provider.lookup(indicator()).verdict == "malicious"

    for status in (401, 403, 429, 500):
        provider = VirusTotalProvider(
            http_get=lambda *args, status=status, **kwargs: httpx.Response(
                status,
                request=httpx.Request("GET", "https://example.test"),
            ),
            rate_limiter=RateLimiter(10),
        )
        lookup = provider.lookup(indicator())
        assert lookup.lookup_status == "unavailable"
        assert lookup.verdict == "unknown"

    provider = VirusTotalProvider(
        http_get=lambda *args, **kwargs: httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.test"),
        ),
        rate_limiter=RateLimiter(10),
    )
    assert provider.lookup(indicator()).lookup_status == "unknown"


def test_timeout_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(
        virustotal_provider,
        "settings",
        replace(settings, virustotal_api_key="test-key"),
    )

    def timeout(*args, **kwargs):
        raise httpx.ReadTimeout("timed out")

    lookup = VirusTotalProvider(
        http_get=timeout,
        rate_limiter=RateLimiter(10),
    ).lookup(indicator())
    assert lookup.lookup_status == "unavailable"
    assert lookup.verdict == "unknown"
