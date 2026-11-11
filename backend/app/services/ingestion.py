import json
from typing import Any

from pydantic import ValidationError

from app.schemas.events import (
    EventImportError,
    EventImportResult,
    SecurityEvent,
)


class EventIngestionError(ValueError):
    """Raised when the complete event document cannot be parsed."""


def _event_type(payload: dict[str, Any]) -> str:
    event_id = payload.get("EventID")
    if event_id == 1 or str(event_id) == "1":
        return "process_create"
    if event_id == 3 or str(event_id) == "3":
        return "network_connection"
    return str(payload.get("event_type") or payload.get("EventType") or "unknown")


def normalize_sysmon_event(payload: dict[str, Any]) -> SecurityEvent:
    """Convert one Sysmon-style object while retaining the complete payload."""
    original_event_id = (
        payload.get("event_id")
        or payload.get("EventId")
        or payload.get("EventRecordID")
    )
    return SecurityEvent.model_validate(
        {
            "event_id": str(original_event_id) if original_event_id is not None else None,
            "source": payload.get("source", "sysmon"),
            "event_type": _event_type(payload),
            "timestamp": payload.get("timestamp") or payload.get("UtcTime"),
            "host_id": payload.get("host_id") or payload.get("Computer"),
            "user_id": payload.get("user_id") or payload.get("User"),
            "process_id": payload.get("process_id") or payload.get("ProcessId"),
            "parent_process_id": payload.get("parent_process_id")
            or payload.get("ParentProcessId"),
            "process_name": payload.get("process_name") or payload.get("Image"),
            "command_line": payload.get("command_line") or payload.get("CommandLine"),
            "source_ip": payload.get("source_ip") or payload.get("SourceIp"),
            "destination_ip": payload.get("destination_ip")
            or payload.get("DestinationIp"),
            "domain": payload.get("domain") or payload.get("QueryName"),
            "file_hash": payload.get("file_hash") or payload.get("Hashes"),
            "raw_payload": payload,
        }
    )


def ingest_json_document(document: str | bytes) -> EventImportResult:
    if not document or not document.strip():
        return EventImportResult(valid_count=0, invalid_count=0, events=[], errors=[])

    try:
        decoded = json.loads(document)
    except json.JSONDecodeError as error:
        raise EventIngestionError(
            f"Malformed JSON at line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error

    if isinstance(decoded, dict) and "events" in decoded:
        decoded = decoded["events"]
    if not isinstance(decoded, list):
        raise EventIngestionError("The JSON document must contain an array of events.")

    events: list[SecurityEvent] = []
    errors: list[EventImportError] = []
    for index, payload in enumerate(decoded):
        if not isinstance(payload, dict):
            errors.append(
                EventImportError(index=index, message="Event must be a JSON object.")
            )
            continue
        try:
            events.append(normalize_sysmon_event(payload))
        except ValidationError as error:
            errors.append(
                EventImportError(index=index, message="; ".join(
                    f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
                    for item in error.errors()
                ))
            )

    return EventImportResult(
        valid_count=len(events),
        invalid_count=len(errors),
        events=events,
        errors=errors,
    )
