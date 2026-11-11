from datetime import datetime, timezone

from app.schemas.alerts import Alert, EvidenceReference
from app.schemas.events import SecurityEvent
from app.schemas.threat_intelligence import (
    ThreatIntelIndicatorResult,
    ThreatIntelligenceResult,
)
from app.services.scoring import (
    detection_confidence,
    evidence_completeness,
    threat_assessment_confidence,
)


def event(**updates: object) -> SecurityEvent:
    values: dict[str, object] = {
        "event_id": "score-event",
        "source": "sysmon",
        "event_type": "process_create",
        "timestamp": datetime.now(timezone.utc),
        "process_name": "pwsh.exe",
        "process_id": 1001,
        "parent_process_id": 900,
        "command_line": "pwsh.exe -EncodedCommand simulated",
        "raw_payload": {},
    }
    values.update(updates)
    return SecurityEvent.model_validate(values)


def alert(indicators: list[str]) -> Alert:
    return Alert(
        alert_id="SOC-001-score",
        title="Simulated detection",
        severity="high",
        event_ids=["score-event"],
        matched_indicators=indicators,
        evidence_references=[
            EvidenceReference(
                event_id="score-event",
                fields=["process_name", "command_line"],
            )
        ],
    )


def test_detection_score_distinguishes_single_and_multiple_indicators() -> None:
    single = detection_confidence(alert(["encoded_command"]), [event()])
    multiple = detection_confidence(
        alert(["encoded_command", "hidden_window", "no_profile"]), [event()]
    )

    assert single.value is not None
    assert multiple.value is not None
    assert multiple.value > single.value
    assert "rule match" in multiple.explanation
    assert "not malicious intent" in multiple.explanation


def test_process_evidence_completeness_reports_missing_decoded_content() -> None:
    score = evidence_completeness(
        alert(["encoded_command"]),
        [event()],
        ["triage: Decoded command content"],
    )

    assert score.value is not None
    assert score.value < 1
    assert "decoded command content" in score.explanation


def test_duplicate_missing_evidence_has_one_penalty_and_one_explanation() -> None:
    score = evidence_completeness(
        alert(["encoded_command"]),
        [event()],
        [
            "triage: Decoded command content",
            "forensics: Decoded command content",
            "threat_intelligence: Provider intelligence is unavailable.",
        ],
    )

    assert score.value == 0.7
    assert score.explanation.count("decoded command content") == 1
    assert score.explanation.count("agent-reported investigation gaps") == 1


def test_complete_process_evidence_scores_higher() -> None:
    complete = evidence_completeness(
        alert(["encoded_command"]),
        [event(raw_payload={"DecodedCommand": "simulated"})],
        [],
    )

    assert complete.value == 1.0


def test_network_completeness_does_not_require_process_creation_fields() -> None:
    score = evidence_completeness(
        alert(["encoded_command"]),
        [
            event(
                event_type="network_connection",
                process_id=None,
                parent_process_id=None,
                command_line=None,
                source_ip="192.0.2.10",
                destination_ip="198.51.100.20",
                raw_payload={
                    "SourcePort": 50000,
                    "DestinationPort": 443,
                    "Protocol": "tcp",
                },
            )
        ],
        [],
    )

    assert score.value == 1.0


def test_unknown_threat_intelligence_is_insufficient_evidence() -> None:
    result = ThreatIntelligenceResult(
        alert_id="SOC-001-score",
        investigation_summary="Unknown.",
        indicators=[
            ThreatIntelIndicatorResult(
                indicator_type="url",
                normalized_value="https://example.test",
                original_value="https://example.test",
                source_event_ids=["score-event"],
                source_fields=["command_line"],
                provider_name="demo-mock",
                verdict="unknown",
                evidence_summary="No external lookup.",
                lookup_timestamp=datetime.now(timezone.utc),
                lookup_status="unknown",
            )
        ],
        evidence_references=[
            EvidenceReference(event_id="score-event", fields=["command_line"])
        ],
    )

    score = threat_assessment_confidence(result)

    assert score.value is None
    assert "Insufficient evidence" in score.explanation
