import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.persistence.db import SessionLocal
from app.persistence.repository import (
    get_alert,
    get_events_for_alert,
    get_investigation,
    list_investigations,
    save_investigation,
)
from app.schemas.alerts import Alert, EvidenceReference, TriageResult
from app.schemas.events import SecurityEvent
from app.schemas.forensics import EvidenceFinding, ForensicAnalysis
from app.schemas.threat_intelligence import (
    ThreatIntelIndicatorResult,
    ThreatIntelligenceResult,
)
from app.services import store
from app.services.coordinator import InvestigationCoordinator, InvestigationError


client = TestClient(app)


def setup_function() -> None:
    store.clear()


def make_alert() -> Alert:
    return Alert(
        alert_id="SOC-001-coordinator",
        title="Suspicious PowerShell Execution",
        severity="high",
        event_ids=["coord-event"],
        source_event_ids=["coord-event"],
        rule_id="SOC-001",
        rule_name="Suspicious PowerShell Execution",
        evidence_references=[
            EvidenceReference(
                event_id="coord-event", fields=["command_line", "source_ip"]
            )
        ],
    )


def make_event() -> SecurityEvent:
    return SecurityEvent(
        event_id="coord-event",
        source="sysmon",
        event_type="process_creation",
        timestamp=datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc),
        process_name="powershell.exe",
        command_line="powershell.exe -EncodedCommand simulated",
        source_ip="8.8.8.8",
        raw_payload={"EventRecordID": "coord-event"},
    )


def make_forensics(alert_id: str) -> ForensicAnalysis:
    reference = EvidenceReference(event_id="coord-event", fields=["command_line"])
    return ForensicAnalysis(
        alert_id=alert_id,
        investigation_summary="Observed PowerShell execution.",
        timeline=[],
        observed_behaviors=[
            EvidenceFinding(
                description="Encoded command execution was observed.",
                evidence_refs=[reference],
            )
        ],
        evidence_references=[reference],
        confidence=0.8,
        confidence_explanation="The command line is directly observed.",
    )


def make_threat_intel(alert_id: str, verdict: str = "unknown") -> ThreatIntelligenceResult:
    return ThreatIntelligenceResult(
        alert_id=alert_id,
        investigation_summary="Provider result is reported without treating it as proof.",
        indicators=[
            ThreatIntelIndicatorResult(
                indicator_type="ipv4",
                normalized_value="8.8.8.8",
                original_value="8.8.8.8",
                source_event_ids=["coord-event"],
                source_fields=["source_ip"],
                provider_name="mock",
                verdict=verdict,
                evidence_summary="Fixture result.",
                lookup_timestamp=datetime.now(timezone.utc),
                lookup_status="available" if verdict != "unknown" else "unknown",
            )
        ],
        evidence_references=[
            EvidenceReference(event_id="coord-event", fields=["source_ip"])
        ],
    )


class FakeAgent:
    def __init__(self, name: str, calls: list[str], result: object = None, error: Exception = None):
        self.name = name
        self.calls = calls
        self.result = result
        self.error = error

    def evaluate(self, *args: object) -> object:
        self.calls.append(self.name)
        if self.error is not None:
            raise self.error
        return self.result


def coordinator(
    calls: list[str],
    triage: object = None,
    forensics: object = None,
    threat_intel: object = None,
) -> InvestigationCoordinator:
    return InvestigationCoordinator(
        FakeAgent("triage", calls, triage),
        FakeAgent("forensics", calls, forensics),
        FakeAgent("threat_intelligence", calls, threat_intel),
    )


def results(alert_id: str) -> tuple[TriageResult, ForensicAnalysis, ThreatIntelligenceResult]:
    return (
        TriageResult(
            alert_id=alert_id,
            investigation_priority="high",
            explanation="Encoded execution requires investigation.",
            evidence_refs=["coord-event"],
        ),
        make_forensics(alert_id),
        make_threat_intel(alert_id),
    )


def test_successful_execution_order_and_report() -> None:
    calls: list[str] = []
    triage, forensics, intelligence = results(make_alert().alert_id)
    report = coordinator(calls, triage, forensics, intelligence).investigate(
        "investigation-SOC-001-coordinator", make_alert(), [make_event()]
    )

    assert calls == ["triage", "forensics", "threat_intelligence"]
    assert report.investigation_status == "completed"
    assert all(
        status.status == "completed"
        for status in report.agent_execution_status.values()
    )
    assert report.observed_facts
    assert all(finding.source == "forensics" for finding in report.observed_facts)
    assert report.overall_confidence < 1.0
    assert "evidence completeness" in report.overall_confidence_explanation


def test_individual_failure_produces_partial_report() -> None:
    calls: list[str] = []
    triage, _, intelligence = results(make_alert().alert_id)
    failing = FakeAgent("forensics", calls, error=RuntimeError("provider down"))
    coordinator_instance = InvestigationCoordinator(
        FakeAgent("triage", calls, triage),
        failing,
        FakeAgent("threat_intelligence", calls, intelligence),
    )

    report = coordinator_instance.investigate(
        "investigation-SOC-001-coordinator", make_alert(), [make_event()]
    )

    assert report.investigation_status == "partial"
    assert report.agent_execution_status["forensics"].status == "failed"
    assert report.agent_execution_status["forensics"].error_category == "unexpected_failure"
    assert report.triage_analysis is not None
    assert report.threat_intelligence_analysis is not None
    assert report.missing_evidence == list(dict.fromkeys(report.missing_evidence))


def test_unavailable_intelligence_warning_is_not_duplicated() -> None:
    calls: list[str] = []
    triage, forensics, intelligence = results(make_alert().alert_id)
    unavailable = intelligence.model_copy(
        update={
            "indicators": [
                intelligence.indicators[0].model_copy(
                    update={"lookup_status": "unavailable"}
                )
            ],
            "missing_information": ["Provider intelligence is unavailable."],
        }
    )
    report = coordinator(calls, triage, forensics, unavailable).investigate(
        "investigation-SOC-001-coordinator", make_alert(), [make_event()]
    )

    warnings = [
        item
        for item in report.missing_evidence
        if "threat_intelligence" in item
    ]
    assert warnings == ["threat_intelligence: provider intelligence was unavailable."]


def test_multiple_agent_failures_are_recorded_independently() -> None:
    calls: list[str] = []
    _, _, intelligence = results(make_alert().alert_id)
    report = InvestigationCoordinator(
        FakeAgent("triage", calls, error=RuntimeError("triage down")),
        FakeAgent("forensics", calls, error=RuntimeError("forensics down")),
        FakeAgent("threat_intelligence", calls, intelligence),
    ).investigate("investigation-SOC-001-coordinator", make_alert(), [make_event()])

    assert report.investigation_status == "partial"
    assert report.agent_execution_status["triage"].status == "failed"
    assert report.agent_execution_status["forensics"].status == "failed"
    assert report.agent_execution_status["threat_intelligence"].status == "completed"


def test_invalid_evidence_field_is_rejected_and_agent_marked_failed() -> None:
    calls: list[str] = []
    triage, _, intelligence = results(make_alert().alert_id)
    invalid = make_forensics(make_alert().alert_id).model_copy(
        update={
            "evidence_references": [
                EvidenceReference(event_id="coord-event", fields=["does_not_exist"])
            ]
        }
    )
    report = InvestigationCoordinator(
        FakeAgent("triage", calls, triage),
        FakeAgent("forensics", calls, invalid),
        FakeAgent("threat_intelligence", calls, intelligence),
    ).investigate("investigation-SOC-001-coordinator", make_alert(), [make_event()])

    assert report.agent_execution_status["forensics"].status == "failed"
    assert report.agent_execution_status["forensics"].error_category == "validation_error"
    assert report.investigation_status == "partial"


def test_invalid_event_id_is_rejected() -> None:
    triage, forensics, intelligence = results(make_alert().alert_id)
    invalid_triage = triage.model_copy(update={"evidence_refs": ["missing-event"]})
    report = coordinator([], invalid_triage, forensics, intelligence).investigate(
        "investigation-SOC-001-coordinator", make_alert(), [make_event()]
    )

    assert report.agent_execution_status["triage"].status == "failed"
    assert report.agent_execution_status["triage"].error_category == "validation_error"


def test_conflicting_findings_are_retained() -> None:
    triage, forensics, _ = results(make_alert().alert_id)
    low_priority = triage.model_copy(update={"investigation_priority": "low"})
    report = coordinator(
        [], low_priority, forensics, make_threat_intel(make_alert().alert_id, "malicious")
    ).investigate("investigation-SOC-001-coordinator", make_alert(), [make_event()])

    assert report.conflicting_findings
    assert report.conflicting_findings[0].classification == "reputation"


def test_missing_evidence_is_rejected() -> None:
    triage, forensics, intelligence = results(make_alert().alert_id)
    with pytest.raises(InvestigationError, match="no persisted evidence"):
        coordinator([], triage, forensics, intelligence).investigate(
            "investigation-SOC-001-coordinator", make_alert(), []
        )


def test_retry_preserves_previous_successful_agent_result() -> None:
    triage, forensics, intelligence = results(make_alert().alert_id)
    previous = coordinator([], triage, forensics, intelligence).investigate(
        "investigation-SOC-001-coordinator", make_alert(), [make_event()]
    )
    calls: list[str] = []
    retry = InvestigationCoordinator(
        FakeAgent("triage", calls, error=RuntimeError("temporary failure")),
        FakeAgent("forensics", calls, forensics),
        FakeAgent("threat_intelligence", calls, intelligence),
    ).investigate(
        "investigation-SOC-001-coordinator",
        make_alert(),
        [make_event()],
        previous,
    )

    assert retry.agent_execution_status["triage"].status == "failed"
    assert retry.triage_analysis == previous.triage_analysis
    assert retry.investigation_status == "partial"


def test_investigation_persistence_and_retrieval() -> None:
    triage, forensics, intelligence = results(make_alert().alert_id)
    report = coordinator([], triage, forensics, intelligence).investigate(
        "investigation-SOC-001-coordinator", make_alert(), [make_event()]
    )
    with SessionLocal() as session:
        save_investigation(session, report)
        retrieved = get_investigation(session, report.investigation_id)
        listed = list_investigations(session, report.alert_id)

    assert retrieved is not None
    assert retrieved.agent_execution_status == report.agent_execution_status
    assert len(listed) == 1
