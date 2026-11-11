from app.persistence.db import SessionLocal
from app.persistence.repository import clear_all


def clear() -> None:
    with SessionLocal() as session:
        clear_all(session)
