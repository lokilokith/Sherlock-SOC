from dataclasses import dataclass

from app.schemas.alerts import Alert
from app.schemas.events import SecurityEvent
from app.schemas.threat_intelligence import ThreatIntelligenceResult


@dataclass(frozen=True)
class Score:
    value: float | None
    explanation: str


def detection_confidence(alert: Alert, events: list[SecurityEvent]) -> Score:
    count = len(alert.matched_indicators)
    if count == 0:
        return Score(None, "No deterministic detection indicators were matched.")
    event_map = {event.event_id: event for event in events}
    fields = {
        field
        for reference in alert.evidence_references
        for field in reference.fields
        if reference.event_id in event_map
    }
    indicator_score = min(0.55 + 0.12 * min(count, 3), 0.91)
    field_bonus = 0.04 * len({"process_name", "command_line"} & fields)
    value = round(min(indicator_score + field_bonus, 0.99), 2)
    return Score(
        value,
        (
            f"{count} matched detection indicator(s) contributed "
            f"{indicator_score:.2f}; supporting process/command fields "
            f"contributed {field_bonus:.2f}. This supports the rule match, "
            "not malicious intent or its probability."
        ),
    )


def evidence_completeness(
    alert: Alert,
    events: list[SecurityEvent],
    missing_evidence: list[str],
) -> Score:
    alert_events = [
        event for event in events
        if event.event_id in set(alert.event_ids)
    ]
    if not alert_events:
        return Score(0.0, "No persisted event evidence is available.")
    available: set[str] = set()
    missing: list[str] = []
    event_scores: list[float] = []
    for event in alert_events:
        if event.event_type == "process_create":
            checks = (
                ("process identity", bool(event.process_name)),
                ("process identifier", event.process_id is not None),
                ("parent process context", event.parent_process_id is not None),
                ("command line", bool(event.command_line)),
                ("decoded command content", bool(event.raw_payload.get("DecodedCommand"))),
            )
        elif event.event_type == "network_connection":
            checks = (
                ("process image", bool(event.process_name)),
                ("source and destination IPs", bool(event.source_ip and event.destination_ip)),
                (
                    "network ports and protocol",
                    all(
                        key in event.raw_payload
                        for key in ("SourcePort", "DestinationPort", "Protocol")
                    ),
                ),
            )
        else:
            checks = ()
        if not checks:
            event_scores.append(0.5)
            missing.append(f"{event.event_id}: unsupported event type")
            continue
        present_count = 0
        for label, present in checks:
            if present:
                available.add(label)
                present_count += 1
            else:
                missing.append(f"{event.event_id}: {label}")
        event_scores.append(present_count / len(checks))
    value = sum(event_scores) / len(event_scores)
    extra_missing = [
        item for item in missing_evidence
        if item and "provider intelligence" not in item.lower()
    ]
    if extra_missing:
        value = max(0.0, value - 0.1)
        missing.append("agent-reported investigation gaps")
    value = round(value, 2)
    return Score(
        value,
        (
            f"Available: {', '.join(sorted(available)) or 'none'}. "
            f"Missing: {', '.join(missing) if missing else 'none'}."
        ),
    )


def threat_assessment_confidence(
    result: ThreatIntelligenceResult | None,
) -> Score:
    if result is None or not result.indicators:
        return Score(
            None,
            "Insufficient evidence: no threat-intelligence result is available.",
        )
    available = [
        indicator
        for indicator in result.indicators
        if indicator.lookup_status == "available"
        and indicator.verdict != "unknown"
    ]
    if not available:
        return Score(
            None,
            "Insufficient evidence: intelligence is unknown or unavailable; "
            "no malicious-activity confidence is claimed.",
        )
    provider_confidences = [
        indicator.confidence
        for indicator in available
        if indicator.confidence is not None
    ]
    base = max(provider_confidences) if provider_confidences else 0.3
    value = round(min(base * 0.6, 0.6), 2)
    return Score(
        value,
        (
            f"Based on {len(available)} available provider result(s), capped at "
            "0.60 because reputation alone does not prove malicious execution."
        ),
    )
