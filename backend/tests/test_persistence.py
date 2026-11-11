import json

from fastapi.testclient import TestClient

from app.main import app
from app.persistence.db import SessionLocal
from app.persistence.repository import (
    get_alert,
    get_events_for_alert,
    list_alerts,
    list_events,
    save_triage_result,
)
from app.services.triage import TriageAgent
from app.schemas.alerts import EvidenceReference
from app.schemas.forensics import ForensicAnalysis
from app.persistence.repository import get_forensic_analysis, save_forensic_analysis
from app.services import store


client = TestClient(app)


def setup_function() -> None:
    store.clear()


def payload() -> list[dict]:
    return [
        {
            "EventID": 1,
            "EventRecordID": "persisted-001",
            "UtcTime": "2026-11-03T09:00:00Z",
            "Computer": "SIMULATED-WIN01",
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand U2ltdWxhdGVk",
        }
    ]


def test_duplicate_import_does_not_duplicate_events_or_alerts() -> None:
    first = client.post("/api/v1/events/import", content=json.dumps(payload()))
    second = client.post("/api/v1/events/import", content=json.dumps(payload()))

    assert first.status_code == 200
    assert second.status_code == 200
    assert len(client.get("/api/v1/events").json()) == 1
    assert len(client.get("/api/v1/alerts").json()) == 1


def test_persistence_survives_new_database_session() -> None:
    client.post("/api/v1/events/import", content=json.dumps(payload()))

    with SessionLocal() as new_session:
        events = list_events(new_session)
        alerts = list_alerts(new_session)

    assert events[0].event_id == "persisted-001"
    assert events[0].raw_payload["EventRecordID"] == "persisted-001"
    assert alerts[0].source_event_ids == ["persisted-001"]
    assert alerts[0].evidence_references[0].event_id == "persisted-001"


def test_triage_reads_persisted_alert_and_event_evidence() -> None:
    client.post("/api/v1/events/import", content=json.dumps(payload()))

    with SessionLocal() as session:
        persisted_alert = get_alert(session, "SOC-001-persisted-001")
        persisted_events = get_events_for_alert(session, persisted_alert.alert_id)
        triage = TriageAgent(
            lambda prompt: json.dumps(
                {
                    "alert_id": persisted_alert.alert_id,
                    "investigation_priority": "high",
                    "explanation": "Encoded execution requires review.",
                    "missing_information": ["Decoded command"],
                    "evidence_refs": ["persisted-001"],
                }
            )
        ).evaluate(persisted_alert, persisted_events)
        save_triage_result(session, triage)

    assert triage.evidence_refs == ["persisted-001"]


def test_triage_retrieval_returns_persisted_result() -> None:
    client.post("/api/v1/events/import", content=json.dumps(payload()))
    result = {
        "alert_id": "SOC-001-persisted-001",
        "investigation_priority": "high",
        "explanation": "Encoded execution requires review.",
        "missing_information": ["Decoded command"],
        "evidence_refs": ["persisted-001"],
    }
    with SessionLocal() as session:
        save_triage_result(session, TriageAgent(lambda prompt: json.dumps(result)).evaluate(
            get_alert(session, "SOC-001-persisted-001"),
            get_events_for_alert(session, "SOC-001-persisted-001"),
        ))

    response = client.get("/api/v1/alerts/SOC-001-persisted-001/triage")

    assert response.status_code == 200
    assert response.json()["evidence_refs"] == ["persisted-001"]


def test_forensic_result_persists_and_retrieves() -> None:
    client.post("/api/v1/events/import", content=json.dumps(payload()))
    result = ForensicAnalysis(
        alert_id="SOC-001-persisted-001",
        investigation_summary="Observed encoded PowerShell.",
        timeline=[],
        missing_evidence=["Decoded command"],
        confidence=0.8,
        confidence_explanation="The command line is directly observed.",
        evidence_references=[
            EvidenceReference(event_id="persisted-001", fields=["command_line"])
        ],
    )

    with SessionLocal() as session:
        save_forensic_analysis(session, result)
        retrieved = get_forensic_analysis(session, result.alert_id)

    assert retrieved is not None
    assert retrieved.evidence_references[0].event_id == "persisted-001"
