import httpx
from dataclasses import replace

from app.core.config import settings
from app.schemas.alerts import Alert
from app.schemas.threat_intelligence import Indicator
from app.services import ti_cache
from app.services.debug_virustotal_test import VirusTotalProvider
from app.services.threat_intelligence import ThreatIntelligenceAgent
from app.services import virustotal_provider


def _alert() -> Alert:
    return Alert(
        alert_id="debug",
        rule_id="debug",
        rule_name="debug",
        severity="low",
        title="debug",
        event_ids=["debug"],
    )


def _indicator() -> Indicator:
    return Indicator(
        indicator_type="md5",
        normalized_value="44d88612fea8a8f36de82e1278abb02f",
        original_value="44d88612fea8a8f36de82e1278abb02f",
        source_event_ids=["debug"],
        source_fields=["raw_payload"],
    )


def test_diagnostic_imports_without_network(monkeypatch) -> None:
    def unexpected_request(*args, **kwargs):
        raise AssertionError("diagnostic import performed a network request")

    monkeypatch.setattr(httpx, "get", unexpected_request)
    assert VirusTotalProvider.__name__ == "VirusTotalProvider"


def test_virustotal_cache_reuses_available_lookup(monkeypatch) -> None:
    ti_cache._cache.clear()
    monkeypatch.setattr(
        virustotal_provider,
        "settings",
        replace(settings, virustotal_api_key="test-key"),
    )
    requests = 0

    def mocked_get(*args, **kwargs):
        nonlocal requests
        requests += 1
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
    result1 = ThreatIntelligenceAgent([provider]).evaluate(_alert(), [_indicator()])
    result2 = ThreatIntelligenceAgent([provider]).evaluate(_alert(), [_indicator()])

    assert result1.indicators[0].cached is False
    assert result2.indicators[0].cached is True
    assert result1.indicators[0].provider_name == "virustotal"
    assert result2.indicators[0].lookup_status == "available"
    assert requests == 1
