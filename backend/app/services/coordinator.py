from datetime import datetime, timezone
from typing import Callable

from app.schemas.alerts import Alert, EvidenceReference, TriageResult
from app.schemas.events import SecurityEvent
from app.schemas.forensics import ForensicAnalysis
from app.schemas.investigations import (
    AgentExecutionStatus,
    InvestigationFinding,
    InvestigationReport,
)
from app.schemas.threat_intelligence import ThreatIntelligenceResult
from app.services.forensics import ForensicsAgent, ForensicsError
from app.services.threat_intelligence import (
    ThreatIntelError,
    ThreatIntelligenceAgent,
    extract_indicators,
)
from app.services.triage import TriageAgent, TriageError
from app.services.scoring import (
    detection_confidence,
    evidence_completeness,
    threat_assessment_confidence,
)


class InvestigationError(RuntimeError):
    """Raised when an investigation cannot be started or validated."""


def _event_fields(event: SecurityEvent) -> set[str]:
    return {
        "event_id",
        "source",
        "event_type",
        "timestamp",
        "host_id",
        "user_id",
        "process_id",
        "parent_process_id",
        "process_name",
        "command_line",
        "source_ip",
        "destination_ip",
        "domain",
        "file_hash",
        "raw_payload",
        *{f"raw_payload.{key}" for key in event.raw_payload},
    }


def _validate_reference(
    reference: EvidenceReference, events: dict[str, SecurityEvent]
) -> None:
    event = events.get(reference.event_id)
    if event is None:
        raise InvestigationError(
            f"Agent output references unavailable event {reference.event_id}."
        )
    if not set(reference.fields).issubset(_event_fields(event)):
        raise InvestigationError(
            f"Agent output references unavailable fields for event "
            f"{reference.event_id}."
        )


def _validate_outputs(
    alert: Alert,
    events: list[SecurityEvent],
    triage: TriageResult | None,
    forensics: ForensicAnalysis | None,
    threat_intel: ThreatIntelligenceResult | None,
) -> None:
    event_map = {event.event_id: event for event in events}
    if triage is not None:
        if triage.alert_id != alert.alert_id or not set(triage.evidence_refs).issubset(
            event_map
        ):
            raise InvestigationError("Triage output contains invalid references.")
    if forensics is not None:
        if forensics.alert_id != alert.alert_id:
            raise InvestigationError("Forensics output references the wrong alert.")
        references = list(forensics.evidence_references)
        references.extend(
            reference
            for finding in [*forensics.observed_behaviors, *forensics.hypotheses]
            for reference in finding.evidence_refs
        )
        references.extend(
            EvidenceReference(
                event_id=entry.event_id, fields=entry.evidence_fields
            )
            for entry in forensics.timeline
        )
        references.extend(
            EvidenceReference(
                event_id=event_id, fields=relationship.evidence_fields
            )
            for relationship in forensics.process_relationships
            for event_id in (
                relationship.parent_event_id,
                relationship.child_event_id,
            )
        )
        for reference in references:
            _validate_reference(reference, event_map)
    if threat_intel is not None:
        if threat_intel.alert_id != alert.alert_id:
            raise InvestigationError(
                "Threat intelligence output references the wrong alert."
            )
        for result in threat_intel.indicators:
            for event_id in result.source_event_ids:
                _validate_reference(
                    EvidenceReference(event_id=event_id, fields=result.source_fields),
                    event_map,
                )
        for reference in threat_intel.evidence_references:
            _validate_reference(reference, event_map)


def _validate_agent_result(
    name: str, result: object, alert: Alert, events: list[SecurityEvent]
) -> None:
    expected_types = {
        "triage": TriageResult,
        "forensics": ForensicAnalysis,
        "threat_intelligence": ThreatIntelligenceResult,
    }
    if not isinstance(result, expected_types[name]):
        raise InvestigationError(f"{name} agent returned malformed output.")
    _validate_outputs(
        alert,
        events,
        result if name == "triage" and isinstance(result, TriageResult) else None,
        result
        if name == "forensics" and isinstance(result, ForensicAnalysis)
        else None,
        result
        if name == "threat_intelligence"
        and isinstance(result, ThreatIntelligenceResult)
        else None,
    )


class InvestigationCoordinator:
    def __init__(
        self,
        triage_agent: TriageAgent,
        forensics_agent: ForensicsAgent,
        threat_intelligence_agent: ThreatIntelligenceAgent,
    ) -> None:
        self.triage_agent = triage_agent
        self.forensics_agent = forensics_agent
        self.threat_intelligence_agent = threat_intelligence_agent

    def investigate(
        self,
        investigation_id: str,
        alert: Alert,
        events: list[SecurityEvent],
        previous_report: InvestigationReport | None = None,
        operating_mode: str = "unknown",
    ) -> InvestigationReport:
        if not events:
            raise InvestigationError("Alert has no persisted evidence.")
        event_map = {event.event_id: event for event in events}
        for reference in alert.evidence_references:
            _validate_reference(reference, event_map)

        statuses = {
            name: AgentExecutionStatus(status="pending")
            for name in ("triage", "forensics", "threat_intelligence")
        }
        results: dict[str, object | None] = {
            "triage": None,
            "forensics": None,
            "threat_intelligence": None,
        }
        missing: list[str] = []
        findings: list[InvestigationFinding] = []
        references: list[EvidenceReference] = []

        def run_agent(
            name: str,
            callback: Callable[[], object],
            error_types: tuple[type[Exception], ...],
        ) -> None:
            statuses[name] = AgentExecutionStatus(status="running")
            try:
                result = callback()
                _validate_agent_result(name, result, alert, events)
                results[name] = result
                statuses[name] = AgentExecutionStatus(status="completed")
            except error_types as error:
                previous_result = (
                    getattr(
                        previous_report,
                        {
                            "triage": "triage_analysis",
                            "forensics": "forensic_analysis",
                            "threat_intelligence": "threat_intelligence_analysis",
                        }[name],
                        None,
                    )
                    if previous_report is not None
                    else None
                )
                if previous_result is not None:
                    results[name] = previous_result
                statuses[name] = AgentExecutionStatus(
                    status="failed",
                    error_category=_error_category(error),
                    error=str(error),
                )
                missing.append(f"{name}: {error}")
            except Exception as error:
                previous_result = (
                    getattr(
                        previous_report,
                        {
                            "triage": "triage_analysis",
                            "forensics": "forensic_analysis",
                            "threat_intelligence": "threat_intelligence_analysis",
                        }[name],
                        None,
                    )
                    if previous_report is not None
                    else None
                )
                if previous_result is not None:
                    results[name] = previous_result
                statuses[name] = AgentExecutionStatus(
                    status="failed",
                    error_category="unexpected_failure",
                    error=str(error),
                )
                missing.append(f"{name}: unexpected provider failure.")

        run_agent(
            "triage",
            lambda: self.triage_agent.evaluate(alert, events),
            (TriageError, InvestigationError),
        )
        run_agent(
            "forensics",
            lambda: self.forensics_agent.evaluate(alert, events),
            (ForensicsError, InvestigationError),
        )

        indicators = extract_indicators(events)
        if not indicators:
            statuses["threat_intelligence"] = AgentExecutionStatus(
                status="skipped",
                error_category="insufficient_evidence",
                error="No indicators were found in persisted evidence.",
            )
            missing.append("threat_intelligence: no indicators were available.")
        else:
            run_agent(
                "threat_intelligence",
                lambda: self.threat_intelligence_agent.evaluate(
                    alert, indicators, events
                ),
                (ThreatIntelError, InvestigationError),
            )
            threat_result = results["threat_intelligence"]
            provider_unavailable = (
                isinstance(threat_result, ThreatIntelligenceResult)
                and threat_result.indicators
                and all(
                    indicator.lookup_status == "unavailable"
                    for indicator in threat_result.indicators
                )
            )
            if provider_unavailable:
                statuses["threat_intelligence"] = AgentExecutionStatus(
                    status="failed",
                    error_category="provider_unavailable",
                    error="Threat intelligence provider returned no available lookups.",
                )
                missing.append(
                    "threat_intelligence: provider intelligence was unavailable."
                )

        triage = results["triage"]
        forensics = results["forensics"]
        threat_intel = results["threat_intelligence"]
        _validate_outputs(
            alert,
            events,
            triage if isinstance(triage, TriageResult) else None,
            forensics if isinstance(forensics, ForensicAnalysis) else None,
            (
                threat_intel
                if isinstance(threat_intel, ThreatIntelligenceResult)
                else None
            ),
        )

        if isinstance(triage, TriageResult):
            references.extend(
                EvidenceReference(event_id=event_id, fields=["event_id"])
                for event_id in triage.evidence_refs
            )
            findings.append(
                InvestigationFinding(
                    description=triage.explanation,
                    source="triage",
                    classification="hypothesis",
                    evidence_references=[
                        EvidenceReference(event_id=event_id, fields=["event_id"])
                        for event_id in triage.evidence_refs
                    ],
                )
            )
            missing.extend(f"triage: {item}" for item in triage.missing_information)
        if isinstance(forensics, ForensicAnalysis):
            references.extend(forensics.evidence_references)
            findings.extend(
                InvestigationFinding(
                    description=finding.description,
                    source="forensics",
                    classification="observed_fact",
                    evidence_references=finding.evidence_refs,
                )
                for finding in forensics.observed_behaviors
            )
            findings.extend(
                InvestigationFinding(
                    description=finding.description,
                    source="forensics",
                    classification="hypothesis",
                    evidence_references=finding.evidence_refs,
                )
                for finding in forensics.hypotheses
            )
            missing.extend(f"forensics: {item}" for item in forensics.missing_evidence)
        if isinstance(threat_intel, ThreatIntelligenceResult):
            references.extend(threat_intel.evidence_references)
            for result in threat_intel.indicators:
                classification = (
                    "reputation"
                    if result.lookup_status == "available"
                    else "unknown"
                )
                findings.append(
                    InvestigationFinding(
                        description=result.evidence_summary,
                        source="threat_intelligence",
                        classification=classification,
                        evidence_references=[
                            EvidenceReference(
                                event_id=event_id, fields=result.source_fields
                            )
                            for event_id in result.source_event_ids
                        ],
                    )
                )
            if not provider_unavailable:
                missing.extend(
                    f"threat_intelligence: {item}"
                    for item in threat_intel.missing_information
                )

        conflicts: list[InvestigationFinding] = []
        if (
            isinstance(triage, TriageResult)
            and isinstance(threat_intel, ThreatIntelligenceResult)
            and triage.investigation_priority.lower() in {"low", "normal"}
            and any(
                result.verdict == "malicious"
                for result in threat_intel.indicators
            )
        ):
            intel_refs = [
                EvidenceReference(
                    event_id=event_id, fields=result.source_fields
                )
                for result in threat_intel.indicators
                if result.verdict == "malicious"
                for event_id in result.source_event_ids
            ]
            conflicts.append(
                InvestigationFinding(
                    description=(
                        "Triage priority conflicts with malicious provider "
                        "reputation; neither result is treated as proof."
                    ),
                    source="coordinator",
                    classification="reputation",
                    evidence_references=intel_refs,
                )
            )

        completed_count = sum(
            status.status == "completed" for status in statuses.values()
        )
        investigation_status = (
            "completed"
            if completed_count == len(statuses)
            else "partial"
            if completed_count
            else "failed"
        )
        unique_missing: list[str] = []
        seen_missing: set[str] = set()
        for item in missing:
            detail = item.split(": ", 1)[1] if ": " in item else item
            key = detail.casefold()
            if key not in seen_missing:
                seen_missing.add(key)
                unique_missing.append(item)
        missing = unique_missing
        detection_score = detection_confidence(alert, events)
        completeness_score = evidence_completeness(alert, events, missing)
        threat_score = threat_assessment_confidence(
            threat_intel if isinstance(threat_intel, ThreatIntelligenceResult) else None
        )
        return InvestigationReport(
            investigation_id=investigation_id,
            alert_id=alert.alert_id,
            operating_mode=operating_mode,
            investigation_status=investigation_status,
            created_at=datetime.now(timezone.utc),
            alert_summary=alert,
            triage_analysis=triage if isinstance(triage, TriageResult) else None,
            forensic_analysis=(
                forensics if isinstance(forensics, ForensicAnalysis) else None
            ),
            threat_intelligence_analysis=(
                threat_intel
                if isinstance(threat_intel, ThreatIntelligenceResult)
                else None
            ),
            consolidated_findings=findings,
            observed_facts=[
                finding
                for finding in findings
                if finding.classification == "observed_fact"
            ],
            hypotheses=[
                finding
                for finding in findings
                if finding.classification == "hypothesis"
            ],
            conflicting_findings=conflicts,
            missing_evidence=missing,
            agent_execution_status=statuses,
            overall_confidence=completeness_score.value or 0.0,
            overall_confidence_explanation=(
                "Legacy compatibility field equal to evidence completeness; "
                "use the three component scores for interpretation."
            ),
            overall_confidence_label="Legacy evidence-completeness compatibility field",
            detection_confidence=detection_score.value,
            detection_confidence_explanation=detection_score.explanation,
            evidence_completeness=completeness_score.value,
            evidence_completeness_explanation=completeness_score.explanation,
            threat_assessment_confidence=threat_score.value,
            threat_assessment_confidence_explanation=threat_score.explanation,
            recommended_next_steps=[
                "Review unknown or unavailable intelligence before response actions."
            ],
            evidence_references=references,
        )


def _error_category(error: Exception) -> str:
    message = str(error).lower()
    if "timed out" in message or "timeout" in message:
        return "timeout"
    if "reference" in message or "evidence" in message:
        return "validation_error"
    if "provider" in message:
        return "provider_failure"
    return "agent_failure"
