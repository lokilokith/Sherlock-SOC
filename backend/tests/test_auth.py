import json
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from app.core import config
from app.persistence import repository
from app.persistence.db import SessionLocal
from app.persistence.models import SessionRecord, UserRecord
from app.main import app
from app.services import auth
from app.services import store


client = TestClient(app)


def setup_function() -> None:
    store.clear()


def test_protected_import_requires_analyst_auth(monkeypatch) -> None:
    enabled_settings = replace(config.settings, auth_enabled=True)
    monkeypatch.setattr(config, "settings", enabled_settings)
    monkeypatch.setattr(auth, "settings", enabled_settings)

    response = client.post(
        "/api/v1/events/import",
        content=json.dumps([]),
    )

    assert response.status_code == 401


def test_public_reads_use_the_isolated_demo_database(monkeypatch) -> None:
    enabled_settings = replace(config.settings, auth_enabled=True)
    monkeypatch.setattr(config, "settings", enabled_settings)
    monkeypatch.setattr(auth, "settings", enabled_settings)
    import app.main as main_module

    monkeypatch.setattr(main_module, "settings", enabled_settings)
    with SessionLocal() as session:
        private_events = [
            {
                "event_id": "private-release-event",
                "source": "private",
                "event_type": "unknown",
                "timestamp": "2026-11-05T00:00:00Z",
                "raw_payload": {"private": True},
            }
        ]
        from app.schemas.events import SecurityEvent

        event = SecurityEvent.model_validate(private_events[0])
        repository.save_events(session, [event])

    public_client = TestClient(app)
    response = public_client.get("/api/v1/events")

    assert response.status_code == 200
    assert all(item["event_id"] != "private-release-event" for item in response.json())
    store.clear()


def test_production_auth_rejects_insecure_cookie_configuration(monkeypatch) -> None:
    production_settings = replace(
        config.settings,
        auth_enabled=True,
        environment="production",
        secure_cookies=False,
        analyst_password="test-password",
    )
    monkeypatch.setattr(auth, "settings", production_settings)

    with pytest.raises(RuntimeError, match="SHERLOCK_SECURE_COOKIES"):
        auth.ensure_analyst_user()


def _auth_settings(monkeypatch, password: str):
    enabled_settings = replace(
        config.settings,
        auth_enabled=True,
        analyst_username="analyst",
        analyst_password=password,
    )
    monkeypatch.setattr(config, "settings", enabled_settings)
    monkeypatch.setattr(auth, "settings", enabled_settings)
    import app.main as main_module

    monkeypatch.setattr(main_module, "settings", enabled_settings)
    return enabled_settings


def _seed_analyst(password: str) -> None:
    with SessionLocal() as session:
        session.add(
            UserRecord(
                username="analyst",
                password_hash=auth._password_hash(password),
                role="analyst",
            )
        )
        session.commit()


def test_valid_credentials_create_a_session_and_invalid_credentials_fail(monkeypatch) -> None:
    _auth_settings(monkeypatch, "correct-password")
    _seed_analyst("correct-password")

    valid = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-password"},
    )
    invalid_password = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "wrong-password"},
    )
    invalid_username = client.post(
        "/api/v1/auth/login",
        json={"username": "missing", "password": "correct-password"},
    )

    assert valid.status_code == 200
    assert valid.cookies.get(auth.SESSION_COOKIE)
    assert invalid_password.status_code == 401
    assert invalid_username.status_code == 401


def test_existing_bootstrap_account_is_not_overwritten(monkeypatch) -> None:
    settings = _auth_settings(monkeypatch, "new-configured-password")
    _seed_analyst("original-password")

    auth.ensure_analyst_user()

    with SessionLocal() as session:
        user = session.get(UserRecord, settings.analyst_username)
        assert user is not None
        assert auth._password_matches("original-password", user.password_hash)
        assert not auth._password_matches("new-configured-password", user.password_hash)


def test_password_reset_changes_hash_and_invalidates_sessions(monkeypatch) -> None:
    _auth_settings(monkeypatch, "original-password")
    _seed_analyst("original-password")
    with SessionLocal() as session:
        session.add(
            SessionRecord(
                token_hash="existing-session",
                username="analyst",
                created_at=auth.datetime.now(auth.timezone.utc),
                expires_at=auth.datetime.now(auth.timezone.utc)
                + auth.timedelta(hours=1),
            )
        )
        session.commit()

    auth.reset_analyst_password("replacement-password")

    with SessionLocal() as session:
        user = session.get(UserRecord, "analyst")
        sessions = session.query(SessionRecord).count()
        assert user is not None
        assert not auth._password_matches("original-password", user.password_hash)
        assert auth._password_matches("replacement-password", user.password_hash)
        assert sessions == 0


def test_password_reset_rejects_short_password(monkeypatch) -> None:
    _auth_settings(monkeypatch, "original-password")
    _seed_analyst("original-password")

    with pytest.raises(ValueError, match="at least"):
        auth.reset_analyst_password("short")


def test_login_rate_limiting(monkeypatch) -> None:
    _auth_settings(monkeypatch, "correct-password")
    _seed_analyst("correct-password")
    auth.clear_all_login_rate_limits()

    # Configure tight limit for test: 3 attempts, 60s window
    rate_limit_settings = replace(
        config.settings,
        auth_enabled=True,
        analyst_password="correct-password",
        login_rate_limit_max_attempts=3,
        login_rate_limit_window_seconds=60,
    )
    monkeypatch.setattr(config, "settings", rate_limit_settings)
    monkeypatch.setattr(auth, "settings", rate_limit_settings)
    import app.main as main_module
    monkeypatch.setattr(main_module, "settings", rate_limit_settings)

    # 1st failed attempt
    res1 = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "wrong1"})
    assert res1.status_code == 401

    # 2nd failed attempt
    res2 = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "wrong2"})
    assert res2.status_code == 401

    # 3rd failed attempt
    res3 = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "wrong3"})
    assert res3.status_code == 401

    # 4th attempt should be rate limited (HTTP 429)
    res4 = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "wrong4"})
    assert res4.status_code == 429
    assert "Too many failed login attempts" in res4.json()["detail"]
    assert "Retry-After" in res4.headers

    # Even with correct password, blocked during rate limit
    res5 = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "correct-password"})
    assert res5.status_code == 429

    # Resetting rate limit allows successful login
    auth.reset_login_rate_limit("testclient:analyst")
    res6 = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "correct-password"})
    assert res6.status_code == 200
    assert res6.json()["username"] == "analyst"


def test_public_reads_cannot_expose_analyst_investigations(monkeypatch) -> None:
    enabled_settings = replace(config.settings, auth_enabled=True, analyst_password="analyst-password")
    monkeypatch.setattr(config, "settings", enabled_settings)
    monkeypatch.setattr(auth, "settings", enabled_settings)
    import app.main as main_module
    monkeypatch.setattr(main_module, "settings", enabled_settings)

    from tests.helpers import build_report

    # Save an investigation into the analyst database (SessionLocal)
    with SessionLocal() as session:
        repository.save_investigation(session, build_report())

    # Unauthenticated request should read from DemoSessionLocal, which does not have this analyst investigation
    res = client.get("/api/v1/investigations")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 0
    assert len(data["items"]) == 0


def test_administrator_account_management_role_authorization(monkeypatch) -> None:
    settings = _auth_settings(monkeypatch, "admin-password")
    settings = replace(settings, analyst_password="admin-password")
    monkeypatch.setattr(config, "settings", settings)
    monkeypatch.setattr(auth, "settings", settings)
    with SessionLocal() as session:
        session.add_all([
            UserRecord(
                id="admin", username="admin",
                password_hash=auth._password_hash("admin-password-123"),
                role="admin", active=True,
            ),
            UserRecord(
                id="analyst", username="analyst-user",
                password_hash=auth._password_hash("analyst-password-123"),
                role="analyst", active=True,
            ),
        ])
        session.commit()

    unauthenticated = TestClient(app)
    assert unauthenticated.get("/api/v1/admin/users").status_code == 401

    administrator = TestClient(app)
    login = administrator.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin-password-123"},
    )
    assert login.status_code == 200
    assert administrator.get("/api/v1/admin/users").status_code == 200
    created = administrator.post(
        "/api/v1/admin/users",
        json={"username": "created-analyst", "password": "analyst-password-123", "role": "analyst"},
    )
    assert created.status_code == 201
    deactivated = administrator.patch(
        "/api/v1/admin/users/created-analyst",
        json={"role": "analyst", "active": False},
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["active"] is False
    reactivated = administrator.patch(
        "/api/v1/admin/users/created-analyst",
        json={"role": "analyst", "active": True},
    )
    assert reactivated.status_code == 200
    assert reactivated.json()["active"] is True

    analyst = TestClient(app)
    login = analyst.post(
        "/api/v1/auth/login",
        json={"username": "analyst-user", "password": "analyst-password-123"},
    )
    assert login.status_code == 200
    assert analyst.get("/api/v1/admin/users").status_code == 403
    assert analyst.post(
        "/api/v1/admin/users",
        json={"username": "blocked-user", "password": "analyst-password-123", "role": "analyst"},
    ).status_code == 403
