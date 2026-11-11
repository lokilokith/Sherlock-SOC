from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.alerts import EvidenceReference


class ForensicTimelineEntry(BaseModel):
    timestamp: datetime
    event_id: str
    summary: str
    evidence_fields: list[str] = Field(min_length=1)


class ProcessRelationship(BaseModel):
    parent_event_id: str
    child_event_id: str
    relationship: str
    evidence_fields: list[str] = Field(min_length=1)


class EvidenceFinding(BaseModel):
    description: str
    evidence_refs: list[EvidenceReference] = Field(min_length=1)


class ForensicAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str
    investigation_summary: str
    timeline: list[ForensicTimelineEntry]
    process_relationships: list[ProcessRelationship] = Field(default_factory=list)
    observed_behaviors: list[EvidenceFinding] = Field(default_factory=list)
    hypotheses: list[EvidenceFinding] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    confidence_explanation: str
    evidence_references: list[EvidenceReference] = Field(min_length=1)
    recommended_next_steps: list[str] = Field(default_factory=list)
