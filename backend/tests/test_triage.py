import json
import time

import pytest

from app.schemas.alerts import Alert
from app.schemas.events import SecurityEvent
from app.services.triage import TriageAgent, TriageError


def alert() -> Alert:
    return Alert(
        alert_id="SOC-001-test",
        rule_id="SOC-001",
        rule_name="Suspicious PowerShell Execution",
        severity="medium",
        title="Suspicious PowerShell Execution",
        event_ids=["event-1"],
        source_event_ids=["event-1"],
    )


def event() -> SecurityEvent:
    return SecurityEvent(
        event_id="event-1",
        source="sysmon",
        event_type="process_create",
        timestamp="2026-11-03T09:00:00Z",
        process_name="powershell.exe",
        command_line="powershell.exe -EncodedCommand simulated",
        raw_payload={"EventRecordID": "event-1"},
    )


def valid_output() -> str:
    return json.dumps(
        {
            "alert_id": "SOC-001-test",
            "investigation_priority": "high",
            "explanation": "The event contains an encoded command.",
            "missing_information": ["Decoded command content"],
            "evidence_refs": ["event-1"],
        }
    )


def test_triage_validates_mock_output_and_evidence() -> None:
    result = TriageAgent(lambda prompt: valid_output()).evaluate(alert(), [event()])

    assert result.investigation_priority == "high"
    assert result.evidence_refs == ["event-1"]


def test_triage_rejects_malformed_output() -> None:
    with pytest.raises(TriageError, match="malformed"):
        TriageAgent(lambda prompt: "not json").evaluate(alert(), [event()])


def test_triage_rejects_unavailable_evidence() -> None:
    output = json.loads(valid_output())
    output["evidence_refs"] = ["missing-event"]

    with pytest.raises(TriageError, match="unavailable evidence"):
        TriageAgent(lambda prompt: json.dumps(output)).evaluate(alert(), [event()])


def test_triage_reports_provider_failure() -> None:
    def failed_provider(prompt: str) -> str:
        raise RuntimeError("provider unavailable")

    with pytest.raises(TriageError, match="provider failed"):
        TriageAgent(failed_provider).evaluate(alert(), [event()])


def test_triage_reports_timeout() -> None:
    def slow_provider(prompt: str) -> str:
        time.sleep(0.1)
        return valid_output()

    with pytest.raises(TriageError, match="timed out"):
        TriageAgent(slow_provider, timeout_seconds=0.01).evaluate(alert(), [event()])
