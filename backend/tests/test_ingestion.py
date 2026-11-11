import json

import pytest

from app.services.ingestion import EventIngestionError, ingest_json_document


def event(command_line: str = "powershell.exe -Command Get-Date") -> dict:
    return {
        "EventID": 1,
        "EventRecordID": "sysmon-1",
        "UtcTime": "2026-11-03T09:00:00Z",
        "Computer": "SIMULATED-WIN01",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": command_line,
        "ProcessId": 10,
    }


def test_successful_import_normalizes_and_preserves_raw_data() -> None:
    payload = event()
    result = ingest_json_document(json.dumps([payload]))

    assert result.valid_count == 1
    assert result.invalid_count == 0
    assert result.events[0].event_id == "sysmon-1"
    assert result.events[0].event_type == "process_create"
    assert result.events[0].raw_payload == payload


def test_sysmon_event_id_3_normalizes_as_network_connection() -> None:
    payload = {
        "EventID": 3,
        "EventRecordID": "sysmon-network-1",
        "UtcTime": "2026-11-03T09:00:00Z",
        "Computer": "SIMULATED-WIN01",
        "Image": "C:\\Windows\\System32\\svchost.exe",
        "SourceIp": "192.0.2.10",
        "SourcePort": 51514,
        "DestinationIp": "198.51.100.20",
        "DestinationPort": 443,
        "Protocol": "tcp",
    }

    result = ingest_json_document(json.dumps([payload]))

    assert result.valid_count == 1
    assert result.events[0].event_type == "network_connection"
    assert result.events[0].raw_payload == payload


def test_invalid_json_is_reported() -> None:
    with pytest.raises(EventIngestionError, match="Malformed JSON"):
        ingest_json_document("{")


def test_empty_input_is_safe() -> None:
    result = ingest_json_document("")

    assert result.valid_count == 0
    assert result.invalid_count == 0


def test_invalid_individual_event_is_reported_without_discarding_valid_events() -> None:
    invalid = event()
    del invalid["UtcTime"]
    result = ingest_json_document(json.dumps([event(), invalid]))

    assert result.valid_count == 1
    assert result.invalid_count == 1
    assert result.errors[0].index == 1


def test_envelope_format_is_supported() -> None:
    result = ingest_json_document(json.dumps({"events": [event()]}))

    assert result.valid_count == 1
