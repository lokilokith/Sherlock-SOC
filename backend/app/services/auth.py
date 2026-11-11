import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from threading import Lock

from fastapi import HTTPException, Request, Response
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.persistence.db import SessionLocal
from app.persistence.models import SessionRecord, UserRecord
from app.schemas.auth import AuthenticatedUser

SESSION_COOKIE = "sherlock_session"
_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1
MIN_PASSWORD_LENGTH = 12

_rate_limit_lock = Lock()
_failed_login_attempts: dict[str, list[float]] = {}


def check_login_rate_limit(client_key: str) -> None:
    now = datetime.now(timezone.utc).timestamp()
    window = settings.login_rate_limit_window_seconds
    max_attempts = settings.login_rate_limit_max_attempts

    with _rate_limit_lock:
        timestamps = [t for t in _failed_login_attempts.get(client_key, []) if now - t < window]
        _failed_login_attempts[client_key] = timestamps
        if len(timestamps) >= max_attempts:
            retry_after = int(window - (now - timestamps[0])) + 1
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts. Please try again later.",
                headers={"Retry-After": str(max(retry_after, 1))},
            )


def record_failed_login(client_key: str) -> None:
    now = datetime.now(timezone.utc).timestamp()
    window = settings.login_rate_limit_window_seconds
    with _rate_limit_lock:
        timestamps = [t for t in _failed_login_attempts.get(client_key, []) if now - t < window]
        timestamps.append(now)
        _failed_login_attempts[client_key] = timestamps


def reset_login_rate_limit(client_key: str) -> None:
    with _rate_limit_lock:
        _failed_login_attempts.pop(client_key, None)


def clear_all_login_rate_limits() -> None:
    with _rate_limit_lock:
        _failed_login_attempts.clear()


def _password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P
    )
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P, salt.hex(), digest.hex()
    )


def _password_matches(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = encoded.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode(),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def ensure_analyst_user() -> None:
    if not settings.auth_enabled:
        return
    if settings.environment.lower() == "production" and not settings.secure_cookies:
        raise RuntimeError(
            "SHERLOCK_SECURE_COOKIES must be enabled in production."
        )
    if "*" in settings.cors_origins:
        raise RuntimeError(
            "Wildcard CORS origins are not allowed with authentication enabled."
        )
    if not settings.analyst_username:
        raise RuntimeError("SHERLOCK_ANALYST_USERNAME must not be empty.")
    with SessionLocal() as session:
        user = session.get(UserRecord, settings.analyst_username)
        if user is None and session.scalar(select(func.count()).select_from(UserRecord)) == 0:
            raise RuntimeError(
                "No SHERLOCK user account exists. Run "
                "'python -m app.cli bootstrap-admin' first."
            )
        if user is not None:
            if user.id in (None, ""):
                user.id = user.username
            for field, value in (
                ("id", user.id or user.username),
                ("created_at", user.created_at or datetime.now(timezone.utc)),
            ):
                setattr(user, field, value)
            session.commit()


def bootstrap_admin(username: str, password: str, email: str | None = None) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    now = datetime.now(timezone.utc)
    with SessionLocal() as session:
        if session.scalar(select(func.count()).select_from(UserRecord)) > 0:
            raise RuntimeError("A SHERLOCK user account already exists.")
        if session.scalar(select(UserRecord).where(UserRecord.username == username)):
            raise RuntimeError(f"User '{username}' already exists.")
        session.add(UserRecord(
            id=username,
            username=username,
            email=email,
            password_hash=_password_hash(password),
            role="admin",
            active=True,
            created_at=now,
        ))
        session.commit()


def reset_analyst_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Analyst password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    with SessionLocal() as session:
        user = session.get(UserRecord, settings.analyst_username)
        if user is None:
            raise RuntimeError(
                f"Analyst account '{settings.analyst_username}' does not exist."
            )
        user.password_hash = _password_hash(password)
        session.execute(
            delete(SessionRecord).where(
                SessionRecord.username == settings.analyst_username
            )
        )
        session.commit()


def authenticate(session: Session, username: str, password: str) -> UserRecord | None:
    user = session.scalar(
        select(UserRecord).where(
            UserRecord.username == username, UserRecord.active.is_(True)
        )
    )
    if user is None or not _password_matches(password, user.password_hash):
        return None
    return user


def create_session(username: str) -> str:
    raw_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    with SessionLocal() as session:
        session.add(
            SessionRecord(
                token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
                username=username,
                created_at=now,
                expires_at=now + timedelta(seconds=settings.session_ttl_seconds),
            )
        )
        session.commit()
    return raw_token


def _token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def current_user(request: Request) -> AuthenticatedUser | None:
    if not settings.auth_enabled:
        return AuthenticatedUser(username="test", role="analyst")
    raw_token = request.cookies.get(SESSION_COOKIE)
    if not raw_token:
        return None
    now = datetime.now(timezone.utc)
    with SessionLocal() as session:
        record = session.scalar(
            select(SessionRecord)
            .join(UserRecord, UserRecord.username == SessionRecord.username)
            .where(
                SessionRecord.token_hash == _token_hash(raw_token),
                SessionRecord.expires_at > now,
                UserRecord.active.is_(True),
            )
        )
        if record is None:
            return None
        user = session.scalar(
            select(UserRecord).where(UserRecord.username == record.username)
        )
        return AuthenticatedUser(
            username=record.username,
            role=user.role if user is not None else "analyst",
        )


def require_analyst(request: Request) -> AuthenticatedUser:
    user = current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Analyst authentication required.")
    return user


def require_admin(request: Request) -> AuthenticatedUser:
    user = require_analyst(request)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required.")
    return user


def set_session_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
    )


def revoke_session(request: Request) -> None:
    raw_token = request.cookies.get(SESSION_COOKIE)
    if not raw_token:
        return
    with SessionLocal() as session:
        session.execute(
            delete(SessionRecord).where(
                SessionRecord.token_hash == _token_hash(raw_token)
            )
        )
        session.commit()


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE)
