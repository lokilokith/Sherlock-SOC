from app.persistence.db import SessionLocal
from app.services.advanced_soc import (
    detection_coverage,
    hunting_query,
    ioc_explorer,
    list_mitre_techniques,
    mitre_matrix,
    mitre_overview,
)
from app.main import app
from fastapi.testclient import TestClient


def test_mitre_enterprise_dataset_loads() -> None:
    overview = mitre_overview()
    assert overview["loaded"] is True
    assert overview["technique_count"] >= 800
    matrix = mitre_matrix()
    assert len(matrix["tactics"]) == 15
    technique = list_mitre_techniques("T1059.001")
    assert technique
    assert any(item["id"] == "T1059.001" for item in technique)


def test_soc_workbench_empty_database_is_safe() -> None:
    with SessionLocal() as session:
        assert detection_coverage(session)["covered_rules"] == 0
        assert hunting_query(session)["total"] == 0
        assert ioc_explorer(session, "127.0.0.1")["related_event_count"] == 0


def test_advanced_api_routes_are_registered() -> None:
    client = TestClient(app)
    overview = client.get("/api/v1/mitre/overview")
    matrix = client.get("/api/v1/mitre/matrix")
    graph = client.get("/api/v1/investigations/not-found/evidence-graph")
    assert overview.status_code == 200
    assert overview.json()["technique_count"] >= 800
    assert matrix.status_code == 200
    assert graph.status_code == 200
    assert graph.json()["found"] is False
