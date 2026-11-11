import json

from fastapi.testclient import TestClient

import app.main as main_module
from app.main import app
from app.services import store


client = TestClient(app)


def setup_function() -> None:
    store.clear()


def test_investigation_api_executes_and_gets_without_reexecution(monkeypatch) -> None:
    calls: list[str] = []

    class StubCoordinator:
        def investigate(self, *args, **kwargs):
            calls.append("investigate")
            from tests.helpers import build_report

            return build_report()

    monkeypatch.setattr(main_module, "build_coordinator", lambda: StubCoordinator())
    payload = [
        {
            "EventID": 1,
            "EventRecordID": "api-investigation",
            "UtcTime": "2026-11-03T09:00:00Z",
            "Computer": "SIMULATED-WIN01",
            "Image": "powershell.exe",
            "ProcessGuid": "{SIMULATED-API}",
            "ProcessId": 1001,
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ParentProcessGuid": "{SIMULATED-PARENT}",
            "SourceIp": "8.8.8.8",
            "CommandLine": "powershell.exe -EncodedCommand simulated",
        }
    ]
    imported = client.post("/api/v1/events/import", content=json.dumps(payload))
    assert imported.status_code == 200
    alert_id = client.get("/api/v1/alerts").json()[0]["alert_id"]

    response = client.post(f"/api/v1/alerts/{alert_id}/investigate")
    assert response.status_code == 200
    investigation_id = response.json()["investigation_id"]
    retrieved = client.get(f"/api/v1/investigations/{investigation_id}")
    listed = client.get(f"/api/v1/alerts/{alert_id}/investigations")

    assert retrieved.status_code == 200
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert calls == ["investigate"]


def test_investigation_api_missing_alert_and_evidence() -> None:
    assert client.post("/api/v1/alerts/missing/investigate").status_code == 404
    assert client.get("/api/v1/investigations/missing").status_code == 404
    assert client.get("/api/v1/alerts/missing/investigations").status_code == 404


def test_list_investigations_endpoint(monkeypatch) -> None:
    from tests.helpers import build_report

    report = build_report()

    class StubCoordinator:
        def investigate(self, *args, **kwargs):
            return report

    monkeypatch.setattr(main_module, "build_coordinator", lambda: StubCoordinator())

    payload = [
        {
            "EventID": 1,
            "EventRecordID": "api-inv-list",
            "UtcTime": "2026-11-03T09:00:00Z",
            "Computer": "SIMULATED-WIN01",
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand simulated",
        }
    ]
    imported = client.post("/api/v1/events/import", content=json.dumps(payload))
    assert imported.status_code == 200
    alert_id = client.get("/api/v1/alerts").json()[0]["alert_id"]

    investigate_res = client.post(f"/api/v1/alerts/{alert_id}/investigate")
    assert investigate_res.status_code == 200

    list_res = client.get("/api/v1/investigations")
    assert list_res.status_code == 200
    data = list_res.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1
    assert data["limit"] == 50
    assert data["offset"] == 0
    assert data["items"][0]["investigation_id"] == report.investigation_id


    paginated = client.get("/api/v1/investigations?limit=1&offset=0")
    assert paginated.status_code == 200
    p_data = paginated.json()
    assert len(p_data["items"]) == 1
    assert p_data["limit"] == 1

