from fastapi.testclient import TestClient

from app.main import app
from app.persistence.db import SessionLocal, initialize_database
from app.persistence.models import AlertRecord


def _client() -> TestClient:
    initialize_database()
    return TestClient(app)


def test_alert_lifecycle_status_assignment_notes_and_history() -> None:
    with SessionLocal() as session:
        session.add(AlertRecord(
            alert_id="alert-lifecycle-test",
            rule_id="SOC-001",
            rule_name="Encoded PowerShell",
            severity="high",
            title="Lifecycle test",
            matched_indicators_json="[]",
            status="New",
            priority="P3",
        ))
        session.commit()

    with _client() as client:
        response = client.patch(
            "/api/v1/alerts/alert-lifecycle-test/status",
            json={"status": "Acknowledged"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "Acknowledged"

        response = client.patch(
            "/api/v1/alerts/alert-lifecycle-test/assignment",
            json={"owner": "analyst1"},
        )
        assert response.status_code == 200
        assert response.json()["owner"] == "analyst1"
        assert response.json()["assigned_at"] is not None

        response = client.patch(
            "/api/v1/alerts/alert-lifecycle-test/priority",
            json={"priority": "p1"},
        )
        assert response.status_code == 200
        assert response.json()["priority"] == "P1"

        response = client.post(
            "/api/v1/alerts/alert-lifecycle-test/notes",
            json={"note": "Corroborated with endpoint telemetry."},
        )
        assert response.status_code == 200
        assert response.json()["note"].startswith("Corroborated")

        history = client.get("/api/v1/alerts/alert-lifecycle-test/history")
        assert history.status_code == 200
        assert [item["event_type"] for item in history.json()] == [
            "priority", "assignment", "status"
        ]


def test_invalid_alert_status_transition_is_rejected() -> None:
    with SessionLocal() as session:
        session.add(AlertRecord(
            alert_id="alert-invalid-transition",
            rule_id="SOC-001",
            rule_name="Encoded PowerShell",
            severity="medium",
            title="Invalid transition test",
            matched_indicators_json="[]",
            status="Closed",
        ))
        session.commit()

    with _client() as client:
        response = client.patch(
            "/api/v1/alerts/alert-invalid-transition/status",
            json={"status": "Investigating"},
        )
        assert response.status_code == 409
