import os
import tempfile
from pathlib import Path

import pytest

test_root = Path(tempfile.mkdtemp(prefix="sherlock-tests-"))
os.environ["SHERLOCK_AUTH_ENABLED"] = "false"
os.environ["SHERLOCK_DATABASE_URL"] = f"sqlite:///{(test_root / 'analyst.db').as_posix()}"
os.environ["SHERLOCK_DEMO_DATABASE_URL"] = f"sqlite:///{(test_root / 'demo.db').as_posix()}"


@pytest.fixture(autouse=True)
def isolate_database() -> None:
    from app.persistence.db import SessionLocal, initialize_database
    from app.persistence.repository import clear_all

    initialize_database()
    with SessionLocal() as session:
        clear_all(session)
        session.commit()
