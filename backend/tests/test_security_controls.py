import json

from fastapi.testclient import TestClient

from app.main import app
from app.services import store


client = TestClient(app)


def setup_function() -> None:
    store.clear()


def test_security_headers_are_present() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_oversized_import_is_rejected() -> None:
    response = client.post(
        "/api/v1/events/import",
        content=json.dumps([]),
        headers={"content-length": str(5 * 1024 * 1024 + 1)},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "Event import is too large."
