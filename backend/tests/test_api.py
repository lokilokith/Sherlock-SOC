import json

from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.main import app
from app.persistence.models import EvidenceRecord
from app.persistence.db import SessionLocal
from app.services import store
import app.main as main_module


client = TestClient(app)


def setup_function() -> None:
    store.clear()


def test_live_agents_use_deterministic_fallback_without_llm(monkeypatch) -> None:
    from app.services.forensics import ForensicsError
    from app.services.triage import TriageError

    previous_mode = main_module.settings.agent_mode
    object.__setattr__(main_module.settings, "agent_mode", "live")
    monkeypatch.setattr(
        main_module,
        "CrewAITriageProvider",
        lambda: (_ for _ in ()).throw(TriageError("LLM not configured")),
    )
    monkeypatch.setattr(
        main_module,
        "CrewAIForensicsProvider",
        lambda: (_ for _ in ()).throw(ForensicsError("LLM not configured")),
    )
    monkeypatch.setattr(main_module, "_build_providers", lambda: [])

    try:
        triage, forensics, threat_intelligence = main_module.build_agents()

        assert triage.__class__.__name__ == "TriageAgent"
        assert triage.provider.__class__.__name__ == "DemoTriageProvider"
        assert forensics.provider.__class__.__name__ == "DemoForensicsProvider"
        assert threat_intelligence.providers == []
    finally:
        object.__setattr__(main_module.settings, "agent_mode", previous_mode)


def test_import_and_alert_retrieval_endpoints() -> None:
    payload = [
        {
            "EventID": 1,
            "EventRecordID": "api-event-1",
            "UtcTime": "2026-11-03T09:00:00Z",
            "Computer": "SIMULATED-WIN01",
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand U2ltdWxhdGVk",
        }
    ]

    response = client.post("/api/v1/events/import", content=json.dumps(payload))
    assert response.status_code == 200
    assert response.json()["valid_count"] == 1

    events = client.get("/api/v1/events")
    alerts = client.get("/api/v1/alerts")
    assert events.status_code == 200
    assert len(events.json()) == 1
    assert alerts.status_code == 200
    assert len(alerts.json()) == 1

    alert_id = alerts.json()[0]["alert_id"]
    alert = client.get(f"/api/v1/alerts/{alert_id}")
    assert alert.status_code == 200
    assert alert.json()["source_event_ids"] == ["api-event-1"]


def test_invalid_json_and_empty_input() -> None:
    invalid = client.post("/api/v1/events/import", content="{")
    empty = client.post("/api/v1/events/import", content="")

    assert invalid.status_code == 400
    assert "Malformed JSON" in invalid.json()["detail"]
    assert empty.status_code == 200
    assert empty.json()["valid_count"] == 0


def test_missing_alert_returns_not_found() -> None:
    response = client.get("/api/v1/alerts/not-found")

    assert response.status_code == 404


def test_investigation_summary_reads_persisted_records() -> None:
    response = client.get("/api/v1/investigations/summary")

    assert response.status_code == 200
    assert response.json() == {
        "total": 0,
        "completed": 0,
        "partial": 0,
        "failed": 0,
        "running": 0,
    }


def test_triage_retrieval_returns_404_when_missing() -> None:
    response = client.get("/api/v1/alerts/not-found/triage")

    assert response.status_code == 404


def test_forensics_reports_missing_alert_and_missing_evidence() -> None:
    missing_alert = client.post("/api/v1/alerts/not-found/forensics")
    assert missing_alert.status_code == 404

    payload = [
        {
            "EventID": 1,
            "EventRecordID": "api-forensics",
            "UtcTime": "2026-11-03T09:00:00Z",
            "Computer": "SIMULATED-WIN01",
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand simulated",
        }
    ]
    client.post("/api/v1/events/import", content=json.dumps(payload))
    with SessionLocal() as session:
        session.execute(
            delete(EvidenceRecord).where(
                EvidenceRecord.alert_id == "SOC-001-api-forensics"
            )
        )
        session.commit()
    no_evidence = client.post("/api/v1/alerts/SOC-001-api-forensics/forensics")

    assert no_evidence.status_code == 422
