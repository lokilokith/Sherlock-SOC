import json
import time

import pytest

from app.schemas.alerts import Alert, EvidenceReference
from app.schemas.events import SecurityEvent
from app.services.forensics import ForensicsAgent, ForensicsError


def alert() -> Alert:
    return Alert(
        alert_id="SOC-001-forensics",
        rule_id="SOC-001",
        rule_name="Suspicious PowerShell Execution",
        severity="high",
        title="Suspicious PowerShell Execution",
        event_ids=["parent", "child"],
        source_event_ids=["parent", "child"],
    )


def events() -> list[SecurityEvent]:
    return [
        SecurityEvent(
            event_id="child",
            source="sysmon",
            event_type="process_create",
            timestamp="2026-11-03T09:02:00Z",
            process_id=200,
            parent_process_id=100,
            process_name="powershell.exe",
            command_line="powershell.exe -EncodedCommand simulated",
            raw_payload={"EventRecordID": "child"},
        ),
        SecurityEvent(
            event_id="parent",
            source="sysmon",
            event_type="process_create",
            timestamp="2026-11-03T09:01:00Z",
            process_id=100,
            process_name="cmd.exe",
            command_line="cmd.exe",
            raw_payload={"EventRecordID": "parent"},
        ),
    ]


def output() -> str:
    return json.dumps(
        {
            "alert_id": "SOC-001-forensics",
            "investigation_summary": "Observed a PowerShell process creation.",
            "timeline": [
                {
                    "timestamp": "2026-11-03T09:01:00Z",
                    "event_id": "parent",
                    "summary": "Parent process observed.",
                    "evidence_fields": ["process_id", "process_name"],
                },
                {
                    "timestamp": "2026-11-03T09:02:00Z",
                    "event_id": "child",
                    "summary": "PowerShell child process observed.",
                    "evidence_fields": ["parent_process_id", "command_line"],
                },
            ],
            "process_relationships": [
                {
                    "parent_event_id": "parent",
                    "child_event_id": "child",
                    "relationship": "observed parent process",
                    "evidence_fields": ["process_id", "parent_process_id"],
                }
            ],
            "observed_behaviors": [
                {
                    "description": "Encoded PowerShell command was observed.",
                    "evidence_refs": [
                        {
                            "event_id": "child",
                            "fields": ["command_line"],
                        }
                    ],
                }
            ],
            "hypotheses": [],
            "missing_evidence": ["Decoded command content"],
            "confidence": 0.9,
            "confidence_explanation": "The process IDs directly support the relationship.",
            "evidence_references": [
                {
                    "event_id": "child",
                    "fields": ["process_name", "command_line"],
                }
            ],
            "recommended_next_steps": ["Obtain decoded command content."],
        }
    )


def test_forensics_validates_timeline_and_relationships() -> None:
    result = ForensicsAgent(lambda prompt: output()).evaluate(alert(), events())

    assert [entry.event_id for entry in result.timeline] == ["parent", "child"]
    assert result.process_relationships[0].child_event_id == "child"


def test_missing_process_relationship_is_explicitly_supported() -> None:
    event = events()[0].model_copy(update={"parent_process_id": None})
    result_data = json.loads(output())
    result_data["timeline"] = [result_data["timeline"][1]]
    result_data["evidence_references"] = [
        {"event_id": "child", "fields": ["process_name", "command_line"]}
    ]
    result_data["process_relationships"] = []
    result_data["missing_evidence"] = ["Parent process relationship is unavailable."]

    result = ForensicsAgent(lambda prompt: json.dumps(result_data)).evaluate(
        alert(), [event]
    )

    assert result.process_relationships == []
    assert result.missing_evidence


def test_invalid_event_id_is_rejected() -> None:
    result_data = json.loads(output())
    result_data["evidence_references"] = [
        {"event_id": "missing", "fields": ["command_line"]}
    ]

    with pytest.raises(ForensicsError, match="unavailable evidence"):
        ForensicsAgent(lambda prompt: json.dumps(result_data)).evaluate(alert(), events())


def test_unordered_timeline_is_rejected() -> None:
    result_data = json.loads(output())
    result_data["timeline"].reverse()

    with pytest.raises(ForensicsError, match="chronological"):
        ForensicsAgent(lambda prompt: json.dumps(result_data)).evaluate(alert(), events())


def test_provider_failure_and_timeout_are_reported() -> None:
    def failed(prompt: str) -> str:
        raise RuntimeError("provider unavailable")

    with pytest.raises(ForensicsError, match="provider failed"):
        ForensicsAgent(failed).evaluate(alert(), events())

    def slow(prompt: str) -> str:
        time.sleep(0.1)
        return output()

    with pytest.raises(ForensicsError, match="timed out"):
        ForensicsAgent(slow, timeout_seconds=0.01).evaluate(alert(), events())
