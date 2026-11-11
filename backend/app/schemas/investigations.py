from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.alerts import Alert, EvidenceReference, TriageResult
from app.schemas.forensics import ForensicAnalysis
from app.schemas.threat_intelligence import ThreatIntelligenceResult


AgentState = Literal["pending", "running", "completed", "failed", "skipped"]


class AgentExecutionStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AgentState
    error_category: str | None = None
    error: str | None = None


class InvestigationFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str
    source: str
    classification: Literal["observed_fact", "hypothesis", "reputation", "unknown"]
    evidence_references: list[EvidenceReference] = Field(default_factory=list)


class AnalystAssessment(BaseModel):
    conclusion: str
    status: str
    uncertainty: str = ""
    next_actions: list[str] = Field(default_factory=list)
    assessor: str
    updated_at: datetime | None = None



class InvestigationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    investigation_id: str
    alert_id: str
    operating_mode: Literal["demo", "live", "unknown"] = "unknown"
    investigation_status: Literal["completed", "partial", "failed"]
    created_at: datetime
    alert_summary: Alert
    triage_analysis: TriageResult | None = None
    forensic_analysis: ForensicAnalysis | None = None
    threat_intelligence_analysis: ThreatIntelligenceResult | None = None
    consolidated_findings: list[InvestigationFinding] = Field(default_factory=list)
    observed_facts: list[InvestigationFinding] = Field(default_factory=list)
    hypotheses: list[InvestigationFinding] = Field(default_factory=list)
    conflicting_findings: list[InvestigationFinding] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    agent_execution_status: dict[str, AgentExecutionStatus]
    overall_confidence: float = Field(ge=0, le=1)
    overall_confidence_explanation: str = (
        "Confidence reflects evidence completeness, not detection-rule certainty."
    )
    overall_confidence_label: str = "Legacy evidence-completeness compatibility field"
    detection_confidence: float | None = Field(
        default=None,
        ge=0,
        le=1,
        description=(
            "Legacy field name for Detection Rule Match Strength; this is "
            "not a probability of malicious activity."
        ),
    )
    detection_confidence_explanation: str = (
        "Detection Rule Match Strength measures how strongly observed fields "
        "match the deterministic detection rule, not malicious intent."
    )
    evidence_completeness: float | None = Field(default=None, ge=0, le=1)
    evidence_completeness_explanation: str = ""
    threat_assessment_confidence: float | None = Field(default=None, ge=0, le=1)
    threat_assessment_confidence_explanation: str = ""
    recommended_next_steps: list[str] = Field(default_factory=list)
    evidence_references: list[EvidenceReference] = Field(default_factory=list)
    analyst_assessment: AnalystAssessment | None = None


class InvestigationListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[InvestigationReport]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)
