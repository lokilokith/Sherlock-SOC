from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EvidenceReference(BaseModel):
    event_id: str
    fields: list[str]


class TriageResult(BaseModel):
    alert_id: str
    investigation_priority: str
    explanation: str
    missing_information: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str
    title: str
    severity: str
    event_ids: list[str]
    description: str | None = None
    rule_id: str = ""
    rule_name: str = ""
    timestamp: datetime | None = None
    host_id: str | None = None
    source_event_ids: list[str] = Field(default_factory=list)
    matched_indicators: list[str] = Field(default_factory=list)
    evidence_references: list[EvidenceReference] = Field(default_factory=list)
    status: str = "New"
    priority: str = "P3"
    owner: str | None = None
    assigned_at: datetime | None = None
    occurrence_count: int = 1
    acknowledgment_status: str = "pending"
    age_hours: float = 0


class AlertStatusUpdate(BaseModel):
    status: str
    note: str | None = None


class AlertAssignmentUpdate(BaseModel):
    owner: str | None


class AlertPriorityUpdate(BaseModel):
    priority: str


class AlertNoteCreate(BaseModel):
    note: str = Field(min_length=1)
    investigation_id: str | None = None


class AlertLifecycleEvent(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: str
    event_type: str
    previous_value: str | None = None
    new_value: str | None = None
    actor: str | None = None
    timestamp: datetime
    details: str | None = None


class AlertNote(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: str
    investigation_id: str | None = None
    author: str | None = None
    note: str
    created_at: datetime
