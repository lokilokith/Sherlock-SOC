import os
from dataclasses import dataclass
from typing import Literal, cast
from pathlib import Path

# Load environment variables from the project root .env file, if present.
# This works regardless of the current working directory (backend or project root).
PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_PATH = PROJECT_ROOT / ".env"
if ENV_PATH.is_file():
    # Simple .env parser – lines like KEY=VALUE, ignore comments and blanks.
    with ENV_PATH.open() as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                # Do not override if already set (e.g., system env).
                os.environ.setdefault(key.strip(), val.strip())



from dataclasses import dataclass
from typing import Literal, cast


AgentMode = Literal["demo", "live"]


def _agent_mode() -> AgentMode:
    value = os.getenv("SHERLOCK_AGENT_MODE", "demo").strip().lower()
    if value not in {"demo", "live"}:
        raise ValueError("SHERLOCK_AGENT_MODE must be either 'demo' or 'live'.")
    return cast(AgentMode, value)


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "SHERLOCK")
    environment: str = os.getenv("APP_ENV", "development")
    database_url: str = os.getenv(
        "SHERLOCK_DATABASE_URL",
        f"sqlite:///{(PROJECT_ROOT / 'data' / 'sherlock.db').as_posix()}",
    )
    demo_database_url: str = os.getenv(
        "SHERLOCK_DEMO_DATABASE_URL",
        f"sqlite:///{(PROJECT_ROOT / 'data' / 'demo.db').as_posix()}",
    )
    cors_origins: tuple[str, ...] = tuple(
        origin.strip()
        for origin in os.getenv(
            "SHERLOCK_CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173"
        ).split(",")
        if origin.strip()
    )
    max_import_bytes: int = int(
        os.getenv("SHERLOCK_MAX_IMPORT_BYTES", str(5 * 1024 * 1024))
    )
    agent_mode: AgentMode = _agent_mode()
    auth_enabled: bool = os.getenv("SHERLOCK_AUTH_ENABLED", "true").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    analyst_username: str = os.getenv("SHERLOCK_ANALYST_USERNAME", "analyst").strip()
    analyst_password: str = os.getenv("SHERLOCK_ANALYST_PASSWORD", "")
    session_ttl_seconds: int = int(
        os.getenv("SHERLOCK_SESSION_TTL_SECONDS", str(8 * 60 * 60))
    )
    secure_cookies: bool = os.getenv("SHERLOCK_SECURE_COOKIES", "false").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    login_rate_limit_max_attempts: int = int(
        os.getenv("SHERLOCK_LOGIN_MAX_ATTEMPTS", "5")
    )
    login_rate_limit_window_seconds: int = int(
        os.getenv("SHERLOCK_LOGIN_WINDOW_SECONDS", "300")
    )
    # Threat intelligence provider configuration
    virustotal_api_key: str = os.getenv("SHERLOCK_VIRUSTOTAL_API_KEY", "")
    abuseipdb_api_key: str = os.getenv("SHERLOCK_ABUSEIPDB_API_KEY", "")
    otx_api_key: str = os.getenv("SHERLOCK_OTX_API_KEY", "")
    urlhaus_auth_key: str = os.getenv("SHERLOCK_URLHAUS_AUTH_KEY", "")
    ti_cache_ttl_seconds: int = int(os.getenv("SHERLOCK_TI_CACHE_TTL_SECONDS", "86400"))
    vt_rate_limit_per_min: int = int(os.getenv("SHERLOCK_VT_RATE_LIMIT_PER_MIN", "4"))
    abuse_rate_limit_per_min: int = int(os.getenv("SHERLOCK_ABUSE_RATE_LIMIT_PER_MIN", "4"))

settings = Settings()
