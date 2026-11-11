import os
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _sqlite_url(path: str) -> str:
    sqlite_path = Path(path)
    if not sqlite_path.is_absolute():
        sqlite_path = PROJECT_ROOT / sqlite_path
    return f"sqlite:///{sqlite_path.as_posix()}"


def database_url() -> str:
    configured = os.getenv("SHERLOCK_DATABASE_URL")
    if configured:
        if configured.startswith("sqlite:///"):
            return _sqlite_url(configured.removeprefix("sqlite:///"))
        return configured
    return _sqlite_url("data/sherlock.db")


def _engine(url: str):
    return create_engine(url, connect_args={"check_same_thread": False})


engine = _engine(database_url())
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
demo_url = os.getenv("SHERLOCK_DEMO_DATABASE_URL")
if demo_url and demo_url.startswith("sqlite:///"):
    demo_url = _sqlite_url(demo_url.removeprefix("sqlite:///"))
demo_engine = _engine(demo_url or _sqlite_url("data/demo.db"))
DemoSessionLocal = sessionmaker(
    bind=demo_engine, autoflush=False, expire_on_commit=False
)


def get_session() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session


def initialize_database(target_engine=engine) -> None:
    from app.persistence import models

    Base.metadata.create_all(target_engine)
    if "alerts" in inspect(target_engine).get_table_names():
        columns = {
            column["name"] for column in inspect(target_engine).get_columns("alerts")
        }
        if "matched_indicators_json" not in columns:
            with target_engine.begin() as connection:
                connection.execute(
                    text(
                        "ALTER TABLE alerts ADD COLUMN "
                        "matched_indicators_json TEXT NOT NULL DEFAULT '[]'"
                    )
                )
        lifecycle_columns = {
            "status": "VARCHAR(50) NOT NULL DEFAULT 'New'",
            "priority": "VARCHAR(50) NOT NULL DEFAULT 'P3'",
            "owner": "VARCHAR(100)",
            "assigned_at": "DATETIME",
            "occurrence_count": "INTEGER NOT NULL DEFAULT 1",
        }
        with target_engine.begin() as connection:
            for name, definition in lifecycle_columns.items():
                if name not in columns:
                    connection.execute(
                        text(f"ALTER TABLE alerts ADD COLUMN {name} {definition}")
                    )
    if "investigations" in inspect(target_engine).get_table_names():
        columns = {
            column["name"]
            for column in inspect(target_engine).get_columns("investigations")
        }
        additions = {
            "report_json": "TEXT",
            "agent_execution_status_json": "TEXT NOT NULL DEFAULT '{}'",
            "triage_result_ref": "VARCHAR(255)",
            "forensic_result_ref": "VARCHAR(255)",
            "threat_intelligence_result_ref": "VARCHAR(255)",
        }
        with target_engine.begin() as connection:
            for name, definition in additions.items():
                if name not in columns:
                    connection.execute(
                        text(
                            f"ALTER TABLE investigations ADD COLUMN "
                            f"{name} {definition}"
                        )
                    )
    if "threat_intelligence_lookups" in inspect(target_engine).get_table_names():
        columns = {
            column["name"]
            for column in inspect(target_engine).get_columns(
                "threat_intelligence_lookups"
            )
        }
        additions = {
            "analysis_stats_json": "TEXT NOT NULL DEFAULT '{}'",
            "cached": "BOOLEAN NOT NULL DEFAULT 0",
        }
        with target_engine.begin() as connection:
            for name, definition in additions.items():
                if name not in columns:
                    connection.execute(
                        text(
                            f"ALTER TABLE threat_intelligence_lookups ADD COLUMN "
                            f"{name} {definition}"
                        )
                    )
    if "users" in inspect(target_engine).get_table_names():
        columns = {
            column["name"] for column in inspect(target_engine).get_columns("users")
        }
        additions = {
            "id": "VARCHAR(100)",
            "email": "VARCHAR(255)",
            "created_at": "DATETIME",
            "last_login_at": "DATETIME",
        }
        with target_engine.begin() as connection:
            for name, definition in additions.items():
                if name not in columns:
                    connection.execute(
                        text(f"ALTER TABLE users ADD COLUMN {name} {definition}")
                    )
            if "id" in additions:
                connection.execute(text("UPDATE users SET id = username WHERE id IS NULL OR id = ''"))
            connection.execute(text("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"))
