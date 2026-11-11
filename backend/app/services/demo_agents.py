import json
from datetime import datetime, timezone

from app.schemas.alerts import Alert, EvidenceReference, TriageResult
from app.schemas.events import SecurityEvent
from app.schemas.forensics import EvidenceFinding, ForensicAnalysis, ForensicTimelineEntry
from app.schemas.threat_intelligence import Indicator, ThreatIntelLookup
from app.services.forensics import ForensicsAgent
from app.services.threat_intelligence import ThreatIntelligenceAgent
from app.services.triage import TriageAgent


def _reference(event: SecurityEvent, fields: list[str]) -> EvidenceReference:
    return EvidenceReference(event_id=event.event_id, fields=fields)


class DemoTriageAgent:
    def evaluate(self, alert: Alert, events: list[SecurityEvent]) -> TriageResult:
        return TriageResult(
            alert_id=alert.alert_id,
            investigation_priority="high" if alert.severity == "high" else "medium",
            explanation=(
                f"DEMO result: deterministic rule {alert.rule_id} matched "
                f"{', '.join(alert.matched_indicators) or 'no rule indicators'}. "
                "This is not confirmation of malicious intent."
            ),
            missing_information=["Decoded command content"],
            evidence_refs=[event.event_id for event in events],
        )


class DemoTriageProvider:
    def __call__(self, prompt: str) -> str:
        payload = json.loads(prompt)
        alert = Alert.model_validate(payload["alert"])
        events = [SecurityEvent.model_validate(event) for event in payload["events"]]
        return DemoTriageAgent().evaluate(alert, events).model_dump_json()


class DemoForensicsAgent:
    def evaluate(self, alert: Alert, events: list[SecurityEvent]) -> ForensicAnalysis:
        ordered = sorted(events, key=lambda event: event.timestamp)
        fields = ["timestamp", "process_name", "command_line"]
        references = [_reference(event, fields) for event in ordered]
        return ForensicAnalysis(
            alert_id=alert.alert_id,
            investigation_summary=(
                "DEMO result: activity was reconstructed only from persisted "
                "alert-associated events."
            ),
            timeline=[
                ForensicTimelineEntry(
                    timestamp=event.timestamp,
                    event_id=event.event_id,
                    summary=f"Observed {event.process_name or event.event_type} event.",
                    evidence_fields=fields,
                )
                for event in ordered
            ],
            process_relationships=[],
            observed_behaviors=[
                EvidenceFinding(
                    description=(
                        "DEMO observation: persisted event fields contain the "
                        "detected command-line indicators."
                    ),
                    evidence_refs=references,
                )
            ],
            hypotheses=[
                EvidenceFinding(
                    description=(
                        "DEMO hypothesis: execution may warrant analyst review; "
                        "intent is not proven by these events."
                    ),
                    evidence_refs=references,
                )
            ],
            missing_evidence=["Decoded command content"],
            confidence=0.7,
            confidence_explanation=(
                "Confidence is limited to directly persisted fields; no "
                "unsupported process relationship was inferred."
            ),
            evidence_references=references,
            recommended_next_steps=["Review the command under analyst control."],
        )


class DemoForensicsProvider:
    def __call__(self, prompt: str) -> str:
        payload = json.loads(prompt)
        alert = Alert.model_validate(payload["alert"])
        events = [SecurityEvent.model_validate(event) for event in payload["events"]]
        return DemoForensicsAgent().evaluate(alert, events).model_dump_json()


class DemoThreatIntelProvider:
    name = "demo-mock"

    def lookup(self, indicator: Indicator) -> ThreatIntelLookup:
        return ThreatIntelLookup(
            indicator_type=indicator.indicator_type,
            normalized_value=indicator.normalized_value,
            provider_name=self.name,
            verdict="unknown",
            evidence_summary=(
                "DEMO result: no external intelligence lookup was performed."
            ),
            lookup_timestamp=datetime.now(timezone.utc),
            lookup_status="unknown",
        )


def build_demo_triage_agent() -> TriageAgent:
    return TriageAgent(DemoTriageProvider())


def build_demo_forensics_agent() -> ForensicsAgent:
    return ForensicsAgent(DemoForensicsProvider())


def build_demo_threat_intelligence_agent() -> ThreatIntelligenceAgent:
    return ThreatIntelligenceAgent(DemoThreatIntelProvider())
