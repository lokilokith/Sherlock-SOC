from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.events import SecurityEvent


def valid_event_data() -> dict:
    return {
        "event_id": "sysmon-001",
        "source": "sysmon",
        "event_type": "process_create",
        "timestamp": "2026-11-03T09:00:00Z",
        "raw_payload": {"EventID": 1, "Image": "cmd.exe"},
    }


def test_valid_event_parsing_preserves_evidence() -> None:
    event = SecurityEvent.model_validate(valid_event_data())

    assert event.event_id == "sysmon-001"
    assert event.source == "sysmon"
    assert event.timestamp == datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)
    assert event.raw_payload == {"EventID": 1, "Image": "cmd.exe"}


def test_missing_optional_fields_are_none() -> None:
    event = SecurityEvent.model_validate(valid_event_data())

    assert event.host_id is None
    assert event.process_id is None
    assert event.command_line is None


def test_invalid_timestamp_is_rejected() -> None:
    data = valid_event_data()
    data["timestamp"] = "not-a-timestamp"

    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(data)


def test_invalid_event_structure_is_rejected() -> None:
    data = valid_event_data()
    del data["event_id"]

    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(data)


def test_unexpected_event_fields_are_rejected() -> None:
    data = valid_event_data()
    data["unexpected"] = "not allowed"

    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(data)
