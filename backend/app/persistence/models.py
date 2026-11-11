import json
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.persistence.db import Base


class EventRecord(Base):
    __tablename__ = "events"
    __table_args__ = (UniqueConstraint("source", "event_id"),)

    event_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    host_id: Mapped[str | None] = mapped_column(String(255))
    user_id: Mapped[str | None] = mapped_column(String(255))
    process_id: Mapped[int | None] = mapped_column(Integer)
    parent_process_id: Mapped[int | None] = mapped_column(Integer)
    process_name: Mapped[str | None] = mapped_column(String(500))
    command_line: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(255))
    destination_ip: Mapped[str | None] = mapped_column(String(255))
    domain: Mapped[str | None] = mapped_column(String(500))
    file_hash: Mapped[str | None] = mapped_column(String(500))
    raw_payload_json: Mapped[str] = mapped_column(Text, nullable=False)

    evidence_references: Mapped[list["EvidenceRecord"]] = relationship(
        back_populates="event", cascade="all, delete-orphan"
    )

    @property
    def raw_payload(self) -> dict[str, Any]:
        return json.loads(self.raw_payload_json)


class AlertRecord(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    host_id: Mapped[str | None] = mapped_column(String(255))
    matched_indicators_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="New")
    priority: Mapped[str] = mapped_column(String(50), nullable=False, default="P3")
    owner: Mapped[str | None] = mapped_column(String(100))
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    evidence_references: Mapped[list["EvidenceRecord"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )
    lifecycle_events: Mapped[list["AlertLifecycleRecord"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )
    notes: Mapped[list["AlertNoteRecord"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )


class AlertLifecycleRecord(Base):
    __tablename__ = "alert_lifecycle_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    previous_value: Mapped[str | None] = mapped_column(String(100))
    new_value: Mapped[str | None] = mapped_column(String(100))
    actor: Mapped[str | None] = mapped_column(String(100))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    details: Mapped[str | None] = mapped_column(Text)
    alert: Mapped["AlertRecord"] = relationship(back_populates="lifecycle_events")


class AlertNoteRecord(Base):
    __tablename__ = "alert_notes"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id"), nullable=False)
    investigation_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigations.investigation_id")
    )
    author: Mapped[str | None] = mapped_column(String(100))
    note: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    alert: Mapped["AlertRecord"] = relationship(back_populates="notes")


class InvestigationAlertRecord(Base):
    __tablename__ = "investigation_alerts"
    __table_args__ = (UniqueConstraint("investigation_id", "alert_id"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.investigation_id"), nullable=False
    )
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id"), nullable=False)


class EvidenceRecord(Base):
    __tablename__ = "evidence_references"
    __table_args__ = (UniqueConstraint("alert_id", "event_id"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id"), nullable=False)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.event_id"), nullable=False)
    fields_json: Mapped[str] = mapped_column(Text, nullable=False)

    alert: Mapped[AlertRecord] = relationship(back_populates="evidence_references")
    event: Mapped[EventRecord] = relationship(back_populates="evidence_references")

    @property
    def fields(self) -> list[str]:
        return json.loads(self.fields_json)


class InvestigationRecord(Base):
    __tablename__ = "investigations"

    investigation_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.alert_id"))
    report_json: Mapped[str | None] = mapped_column(Text)
    agent_execution_status_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="{}"
    )
    triage_result_ref: Mapped[str | None] = mapped_column(
        ForeignKey("triage_results.alert_id")
    )
    forensic_result_ref: Mapped[str | None] = mapped_column(
        ForeignKey("forensic_results.alert_id")
    )
    threat_intelligence_result_ref: Mapped[str | None] = mapped_column(
        ForeignKey("threat_intelligence_results.alert_id")
    )


class TriageRecord(Base):
    __tablename__ = "triage_results"

    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id"), primary_key=True)
    result_json: Mapped[str] = mapped_column(Text, nullable=False)


class ForensicRecord(Base):
    __tablename__ = "forensic_results"

    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id"), primary_key=True)
    result_json: Mapped[str] = mapped_column(Text, nullable=False)


class ThreatIntelIndicatorRecord(Base):
    __tablename__ = "threat_intelligence_indicators"
    __table_args__ = (UniqueConstraint("alert_id", "indicator_type", "normalized_value"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id"), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(50), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(1000), nullable=False)
    original_value: Mapped[str] = mapped_column(String(1000), nullable=False)
    source_event_ids_json: Mapped[str] = mapped_column(Text, nullable=False)
    source_fields_json: Mapped[str] = mapped_column(Text, nullable=False)


class ThreatIntelLookupRecord(Base):
    __tablename__ = "threat_intelligence_lookups"
    __table_args__ = (UniqueConstraint("alert_id", "indicator_type", "normalized_value"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id"), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(50), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(1000), nullable=False)
    provider_name: Mapped[str] = mapped_column(String(255), nullable=False)
    verdict: Mapped[str] = mapped_column(String(50), nullable=False)
    reputation_score: Mapped[float | None]
    confidence: Mapped[float | None]
    analysis_stats_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    cached: Mapped[bool] = mapped_column(default=False, nullable=False)
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)
    source_reference: Mapped[str | None] = mapped_column(String(1000))
    lookup_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lookup_status: Mapped[str] = mapped_column(String(50), nullable=False)


class ThreatIntelResultRecord(Base):
    __tablename__ = "threat_intelligence_results"

    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id"), primary_key=True)
    result_json: Mapped[str] = mapped_column(Text, nullable=False)


class UserRecord(Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(100), primary_key=True)
    id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, default="")
    email: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(500), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="analyst")
    active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SessionRecord(Base):
    __tablename__ = "auth_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(ForeignKey("users.username"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ValidationRunRecord(Base):
    __tablename__ = "validation_runs"

    run_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    report_json: Mapped[str] = mapped_column(Text, nullable=False)
