from datetime import datetime, timezone

from app.schemas.alerts import Alert, EvidenceReference, TriageResult
from app.schemas.forensics import ForensicAnalysis
from app.schemas.investigations import AgentExecutionStatus, InvestigationReport
from app.schemas.threat_intelligence import (
    ThreatIntelIndicatorResult,
    ThreatIntelligenceResult,
)


def build_report() -> InvestigationReport:
    alert = Alert(
        alert_id="SOC-001-api-investigation",
        title="Suspicious PowerShell Execution",
        severity="medium",
        event_ids=["api-investigation"],
        source_event_ids=["api-investigation"],
    )
    reference = EvidenceReference(
        event_id="api-investigation", fields=["command_line"]
    )
    return InvestigationReport(
        investigation_id="investigation-SOC-001-api-investigation",
        alert_id=alert.alert_id,
        investigation_status="completed",
        created_at=datetime.now(timezone.utc),
        alert_summary=alert,
        triage_analysis=TriageResult(
            alert_id=alert.alert_id,
            investigation_priority="high",
            explanation="Observed encoded execution.",
            evidence_refs=["api-investigation"],
        ),
        forensic_analysis=ForensicAnalysis(
            alert_id=alert.alert_id,
            investigation_summary="Observed execution.",
            timeline=[],
            confidence=0.8,
            confidence_explanation="Direct evidence.",
            evidence_references=[reference],
        ),
        threat_intelligence_analysis=ThreatIntelligenceResult(
            alert_id=alert.alert_id,
            investigation_summary="Unknown intelligence.",
            indicators=[
                ThreatIntelIndicatorResult(
                    indicator_type="ipv4",
                    normalized_value="8.8.8.8",
                    original_value="8.8.8.8",
                    source_event_ids=["api-investigation"],
                    source_fields=["source_ip"],
                    provider_name="mock",
                    verdict="unknown",
                    evidence_summary="Unavailable.",
                    lookup_timestamp=datetime.now(timezone.utc),
                    lookup_status="unavailable",
                )
            ],
            evidence_references=[
                EvidenceReference(
                    event_id="api-investigation", fields=["source_ip"]
                )
            ],
        ),
        agent_execution_status={
            name: AgentExecutionStatus(status="completed")
            for name in ("triage", "forensics", "threat_intelligence")
        },
        overall_confidence=1.0,
    )
