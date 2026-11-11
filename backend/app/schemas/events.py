from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    source: str
    event_type: str
    timestamp: datetime
    host_id: str | None = None
    user_id: str | None = None
    process_id: int | None = None
    parent_process_id: int | None = None
    process_name: str | None = None
    command_line: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    domain: str | None = None
    file_hash: str | None = None
    raw_payload: dict[str, Any]


class EventImportError(BaseModel):
    index: int
    message: str


class EventImportResult(BaseModel):
    valid_count: int
    invalid_count: int
    events: list[SecurityEvent]
    errors: list[EventImportError]
