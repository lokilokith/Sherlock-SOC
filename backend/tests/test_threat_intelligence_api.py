import json
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.services import store
from app.services.threat_intelligence import ThreatIntelError, normalize_manual_indicator
from app.persistence.db import SessionLocal
from app.persistence.models import ThreatIntelIndicatorRecord, ThreatIntelLookupRecord
from app.schemas.threat_intelligence import Indicator, ThreatIntelLookup
from app import main as main_module


client = TestClient(app)


def setup_function() -> None:
    store.clear()


def test_manual_ioc_normalization_and_invalid_values() -> None:
    indicator = normalize_manual_indicator(
        "44D88612FEA8A8F36DE82E1278ABB02F", "auto"
    )
    assert indicator.indicator_type == "md5"
    assert indicator.normalized_value == "44d88612fea8a8f36de82e1278abb02f"

    try:
        normalize_manual_indicator("not a valid ioc", "ipv4")
    except ThreatIntelError:
        pass
    else:
        raise AssertionError("Invalid IPv4 IOC was accepted.")


def test_threat_intelligence_persists_and_retrieves() -> None:
    payload = [
        {
            "EventID": 1,
            "EventRecordID": "ti-api-event",
            "UtcTime": "2026-11-03T09:00:00Z",
            "Computer": "SIMULATED-WIN01",
            "SourceIp": "8.8.8.8",
            "QueryName": "example.com",
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand https://example.com/path",
        }
    ]
    client.post("/api/v1/events/import", content=json.dumps(payload))
    result = client.post("/api/v1/alerts/SOC-001-ti-api-event/threat-intelligence")

    assert result.status_code == 200
    assert result.json()["indicators"]
    assert result.json()["indicators"][0]["source_event_ids"] == ["ti-api-event"]

    retrieved = client.get(
        "/api/v1/alerts/SOC-001-ti-api-event/threat-intelligence"
    )
    assert retrieved.status_code == 200
    assert retrieved.json() == result.json()


def test_threat_intelligence_missing_alert_and_indicators() -> None:
    missing_alert = client.post(
        "/api/v1/alerts/missing/threat-intelligence"
    )
    assert missing_alert.status_code == 404

    payload = [
        {
            "EventID": 1,
            "EventRecordID": "ti-no-indicator",
            "UtcTime": "2026-11-03T09:00:00Z",
            "Computer": "SIMULATED-WIN01",
            "Image": "notepad.exe",
            "CommandLine": "notepad.exe",
        }
    ]
    client.post("/api/v1/events/import", content=json.dumps(payload))
    no_indicators = client.post(
        "/api/v1/alerts/SOC-001-ti-no-indicator/threat-intelligence"
    )

    assert no_indicators.status_code == 404


def test_threat_intelligence_retrieval_without_prior_result_is_404() -> None:
    payload = [
        {
            "EventID": 1,
            "EventRecordID": "ti-retrieval-only",
            "UtcTime": "2026-11-03T09:00:00Z",
            "Computer": "SIMULATED-WIN01",
            "SourceIp": "8.8.8.8",
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand simulated",
        }
    ]
    client.post("/api/v1/events/import", content=json.dumps(payload))
    response = client.get(
        "/api/v1/alerts/SOC-001-ti-retrieval-only/threat-intelligence"
    )

    assert response.status_code == 404


def test_threat_intelligence_console_serializes_empty_and_malformed_records() -> None:
    response = client.get("/api/v1/threat-intelligence/console")
    assert response.status_code == 200
    assert response.json() == {"records": []}

    timestamp = datetime.now(timezone.utc)
    with SessionLocal() as session:
        session.add_all([
            ThreatIntelLookupRecord(
                alert_id="console-existing",
                indicator_type="ipv4",
                normalized_value="8.8.8.8",
                provider_name="virustotal",
                verdict="unknown",
                analysis_stats_json='{"malicious": 0}',
                cached=False,
                evidence_summary="Persisted provider record.",
                source_reference="https://example.com/provider",
                lookup_timestamp=timestamp,
                lookup_status="available",
            ),
            ThreatIntelLookupRecord(
                alert_id="console-malformed",
                indicator_type="domain",
                normalized_value="example.com",
                provider_name="demo-mock",
                verdict="unknown",
                analysis_stats_json="{malformed",
                cached=False,
                evidence_summary="Historical demo record.",
                source_reference=None,
                lookup_timestamp=timestamp,
                lookup_status="available",
            ),
        ])
        session.commit()

    response = client.get("/api/v1/threat-intelligence/console")
    assert response.status_code == 200
    records = {record["provider_name"]: record for record in response.json()["records"]}
    assert records["virustotal"]["analysis_stats"] == {"malicious": 0}
    assert records["demo-mock"]["analysis_stats"] == {}
    assert records["demo-mock"]["historical_demo"] is True
    assert records["virustotal"]["normalized_value"] == "8.8.8.8"


def test_manual_multi_provider_lookup(monkeypatch) -> None:
    monkeypatch.setattr(main_module, "settings", type("Settings", (), {"agent_mode": "live"})())
    main_module.ti_cache._cache.clear()

    class FakeProvider:
        def __init__(self, name: str) -> None:
            self.name = name

        def lookup(self, indicator: Indicator) -> ThreatIntelLookup:
            return ThreatIntelLookup(
                indicator_type=indicator.indicator_type,
                normalized_value=indicator.normalized_value,
                provider_name=self.name,
                verdict="unknown",
                analysis_stats={},
                evidence_summary=f"{self.name} test lookup",
                lookup_timestamp=datetime.now(timezone.utc),
                lookup_status="available",
            )

    monkeypatch.setattr(main_module, "VirusTotalProvider", lambda: FakeProvider("virustotal"))
    monkeypatch.setattr(main_module, "AbuseIPDBProvider", lambda: FakeProvider("abuseipdb"))
    monkeypatch.setattr(main_module, "AlienVaultOTXProvider", lambda: FakeProvider("alienvault_otx"))
    monkeypatch.setattr(main_module, "GreyNoiseProvider", lambda: FakeProvider("greynoise"))
    monkeypatch.setattr(main_module, "URLhausProvider", lambda: FakeProvider("urlhaus"))

    response = client.post(
        "/api/v1/threat-intelligence/lookup",
        json={"value": "44d88612fea8a8f36de82e1278abb02f", "indicator_type": "auto"},
    )
    assert response.status_code == 200
    assert {item["provider_name"] for item in response.json()} == {"virustotal", "alienvault_otx"}
