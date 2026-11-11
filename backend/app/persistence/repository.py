import json
from datetime import datetime, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, joinedload

from app.persistence.models import (
    AlertRecord,
    EvidenceRecord,
    EventRecord,
    InvestigationRecord,
    TriageRecord,
    ForensicRecord,
    ThreatIntelIndicatorRecord,
    ThreatIntelLookupRecord,
    ThreatIntelResultRecord,
    ValidationRunRecord,
    SessionRecord,
    UserRecord,
)
from app.schemas.alerts import Alert, EvidenceReference, TriageResult
from app.schemas.forensics import ForensicAnalysis
from app.schemas.events import SecurityEvent
from app.schemas.threat_intelligence import (
    Indicator,
    ThreatIntelligenceResult,
)
from app.schemas.investigations import InvestigationReport
from app.schemas.investigation_summary import InvestigationSummary
from app.schemas.validation import ValidationRun


def _event_record(event: SecurityEvent) -> EventRecord:
    return EventRecord(
        event_id=event.event_id,
        source=event.source,
        event_type=event.event_type,
        timestamp=event.timestamp,
        host_id=event.host_id,
        user_id=event.user_id,
        process_id=event.process_id,
        parent_process_id=event.parent_process_id,
        process_name=event.process_name,
        command_line=event.command_line,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        domain=event.domain,
        file_hash=event.file_hash,
        raw_payload_json=json.dumps(event.raw_payload),
    )


def _event_schema(record: EventRecord) -> SecurityEvent:
    return SecurityEvent(
        event_id=record.event_id,
        source=record.source,
        event_type=record.event_type,
        timestamp=record.timestamp,
        host_id=record.host_id,
        user_id=record.user_id,
        process_id=record.process_id,
        parent_process_id=record.parent_process_id,
        process_name=record.process_name,
        command_line=record.command_line,
        source_ip=record.source_ip,
        destination_ip=record.destination_ip,
        domain=record.domain,
        file_hash=record.file_hash,
        raw_payload=record.raw_payload,
    )


def save_events(session: Session, events: list[SecurityEvent]) -> list[SecurityEvent]:
    new_events: list[SecurityEvent] = []
    for event in events:
        if session.get(EventRecord, event.event_id) is not None:
            continue
        session.add(_event_record(event))
        new_events.append(event)
    session.commit()
    return new_events


def save_alerts(session: Session, alerts: list[Alert]) -> None:
    for alert in alerts:
        existing = session.get(AlertRecord, alert.alert_id)
        if existing is not None:
            existing.occurrence_count += 1
            existing_ids = {item.event_id for item in existing.evidence_references}
            for reference in alert.evidence_references:
                if reference.event_id not in existing_ids:
                    existing.evidence_references.append(EvidenceRecord(
                        alert_id=alert.alert_id,
                        event_id=reference.event_id,
                        fields_json=json.dumps(reference.fields),
                    ))
            continue
        record = AlertRecord(
            alert_id=alert.alert_id,
            rule_id=alert.rule_id,
            rule_name=alert.rule_name,
            severity=alert.severity,
            title=alert.title,
            description=alert.description,
            timestamp=alert.timestamp,
            host_id=alert.host_id,
            matched_indicators_json=json.dumps(alert.matched_indicators),
        )
        record.evidence_references = [
            EvidenceRecord(
                alert_id=alert.alert_id,
                event_id=reference.event_id,
                fields_json=json.dumps(reference.fields),
            )
            for reference in alert.evidence_references
        ]
        session.add(record)
    session.commit()


def list_events(session: Session) -> list[SecurityEvent]:
    return [_event_schema(record) for record in session.scalars(
        select(EventRecord).order_by(EventRecord.timestamp)
    )]


def get_event(session: Session, event_id: str) -> EventRecord | None:
    return session.get(EventRecord, event_id)


def list_evidence_for_alert(session: Session, alert_id: str) -> list[EvidenceRecord]:
    return list(session.scalars(
        select(EvidenceRecord).where(EvidenceRecord.alert_id == alert_id)
    ))


def list_threat_intelligence_lookups(
    session: Session, alert_id: str
) -> list[ThreatIntelLookupRecord]:
    return list(session.scalars(
        select(ThreatIntelLookupRecord).where(
            ThreatIntelLookupRecord.alert_id == alert_id
        )
    ))


def _alert_schema(record: AlertRecord) -> Alert:
    references = [
        EvidenceReference(event_id=item.event_id, fields=item.fields)
        for item in record.evidence_references
    ]
    event_ids = [item.event_id for item in references]
    now = datetime.now(timezone.utc)
    timestamp = record.timestamp
    if timestamp is not None and timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    age_hours = max(0.0, (now - timestamp).total_seconds() / 3600) if timestamp else 0.0
    return Alert(
        alert_id=record.alert_id,
        rule_id=record.rule_id,
        rule_name=record.rule_name,
        severity=record.severity,
        title=record.title,
        description=record.description,
        timestamp=record.timestamp,
        host_id=record.host_id,
        event_ids=event_ids,
        source_event_ids=event_ids,
        matched_indicators=json.loads(record.matched_indicators_json),
        evidence_references=references,
        status=record.status,
        priority=record.priority,
        owner=record.owner,
        assigned_at=record.assigned_at,
        occurrence_count=record.occurrence_count,
        acknowledgment_status="acknowledged" if record.status != "New" else "pending",
        age_hours=age_hours,
    )


def list_alerts(session: Session) -> list[Alert]:
    records = session.scalars(
        select(AlertRecord)
        .options(joinedload(AlertRecord.evidence_references))
        .order_by(AlertRecord.timestamp)
    ).unique()
    return [_alert_schema(record) for record in records]


def get_alert(session: Session, alert_id: str) -> Alert | None:
    record = session.scalars(
        select(AlertRecord)
        .options(joinedload(AlertRecord.evidence_references))
        .where(AlertRecord.alert_id == alert_id)
    ).unique().first()
    return _alert_schema(record) if record else None


def get_events_for_alert(session: Session, alert_id: str) -> list[SecurityEvent]:
    records = session.scalars(
        select(EventRecord)
        .join(EvidenceRecord, EvidenceRecord.event_id == EventRecord.event_id)
        .where(EvidenceRecord.alert_id == alert_id)
        .order_by(EventRecord.timestamp)
    ).all()
    return [_event_schema(record) for record in records]


def save_triage_result(session: Session, result: TriageResult) -> None:
    record = session.get(TriageRecord, result.alert_id)
    if record is None:
        record = TriageRecord(alert_id=result.alert_id, result_json=result.model_dump_json())
        session.add(record)
    else:
        record.result_json = result.model_dump_json()
    session.commit()


def get_triage_result(session: Session, alert_id: str) -> TriageResult | None:
    record = session.get(TriageRecord, alert_id)
    return TriageResult.model_validate_json(record.result_json) if record else None


def save_forensic_analysis(session: Session, result: ForensicAnalysis) -> None:
    record = session.get(ForensicRecord, result.alert_id)
    if record is None:
        session.add(
            ForensicRecord(
                alert_id=result.alert_id,
                result_json=result.model_dump_json(),
            )
        )
    else:
        record.result_json = result.model_dump_json()
    session.commit()


def get_forensic_analysis(
    session: Session, alert_id: str
) -> ForensicAnalysis | None:
    record = session.get(ForensicRecord, alert_id)
    return ForensicAnalysis.model_validate_json(record.result_json) if record else None


def save_threat_intelligence(
    session: Session, result: ThreatIntelligenceResult
) -> None:
    for indicator in result.indicators:
        indicator_record = session.scalars(
            select(ThreatIntelIndicatorRecord).where(
                ThreatIntelIndicatorRecord.alert_id == result.alert_id,
                ThreatIntelIndicatorRecord.indicator_type == indicator.indicator_type,
                ThreatIntelIndicatorRecord.normalized_value == indicator.normalized_value,
            )
        ).first()
        if indicator_record is None:
            session.add(
                ThreatIntelIndicatorRecord(
                    alert_id=result.alert_id,
                    indicator_type=indicator.indicator_type,
                    normalized_value=indicator.normalized_value,
                    original_value=indicator.original_value,
                    source_event_ids_json=json.dumps(indicator.source_event_ids),
                    source_fields_json=json.dumps(indicator.source_fields),
                )
            )
        lookup_record = session.scalars(
            select(ThreatIntelLookupRecord).where(
                ThreatIntelLookupRecord.alert_id == result.alert_id,
                ThreatIntelLookupRecord.indicator_type == indicator.indicator_type,
                ThreatIntelLookupRecord.normalized_value == indicator.normalized_value,
            )
        ).first()
        values = {
            "provider_name": indicator.provider_name,
            "verdict": indicator.verdict,
            "reputation_score": indicator.reputation_score,
            "confidence": indicator.confidence,
            "analysis_stats_json": json.dumps(indicator.analysis_stats),
            "cached": indicator.cached,
            "evidence_summary": indicator.evidence_summary,
            "source_reference": indicator.source_reference,
            "lookup_timestamp": indicator.lookup_timestamp,
            "lookup_status": indicator.lookup_status,
        }
        if lookup_record is None:
            session.add(
                ThreatIntelLookupRecord(
                    alert_id=result.alert_id,
                    indicator_type=indicator.indicator_type,
                    normalized_value=indicator.normalized_value,
                    **values,
                )
            )
        else:
            for key, value in values.items():
                setattr(lookup_record, key, value)
    result_record = session.get(ThreatIntelResultRecord, result.alert_id)
    if result_record is None:
        session.add(
            ThreatIntelResultRecord(
                alert_id=result.alert_id, result_json=result.model_dump_json()
            )
        )
    else:
        result_record.result_json = result.model_dump_json()
    session.commit()


def get_threat_intelligence(
    session: Session, alert_id: str
) -> ThreatIntelligenceResult | None:
    record = session.get(ThreatIntelResultRecord, alert_id)
    return (
        ThreatIntelligenceResult.model_validate_json(record.result_json)
        if record
        else None
    )


def list_manual_threat_intelligence(session: Session) -> list[ThreatIntelligenceResult]:
    records = session.scalars(
        select(ThreatIntelResultRecord).where(
            ThreatIntelResultRecord.alert_id.like("manual-%")
        ).order_by(ThreatIntelResultRecord.alert_id.desc())
    )
    results = []
    for record in records:
        try:
            results.append(ThreatIntelligenceResult.model_validate_json(record.result_json))
        except Exception:
            continue
    return results


def list_threat_intelligence_records(session: Session) -> list[tuple[ThreatIntelLookupRecord, ThreatIntelIndicatorRecord | None]]:
    records = session.scalars(
        select(ThreatIntelLookupRecord)
        .order_by(ThreatIntelLookupRecord.lookup_timestamp.desc())
    ).all()
    pairs: list[tuple[ThreatIntelLookupRecord, ThreatIntelIndicatorRecord | None]] = []
    for record in records:
        indicator = session.scalars(
            select(ThreatIntelIndicatorRecord).where(
                ThreatIntelIndicatorRecord.alert_id == record.alert_id,
                ThreatIntelIndicatorRecord.indicator_type == record.indicator_type,
                ThreatIntelIndicatorRecord.normalized_value == record.normalized_value,
            )
        ).first()
        pairs.append((record, indicator))
    return pairs


def save_investigation(
    session: Session, report: InvestigationReport
) -> None:
    record = session.get(InvestigationRecord, report.investigation_id)
    values = {
        "status": report.investigation_status,
        "alert_id": report.alert_id,
        "created_at": report.created_at,
        "report_json": report.model_dump_json(),
        "agent_execution_status_json": json.dumps(
            {
                name: status.model_dump(mode="json")
                for name, status in report.agent_execution_status.items()
            }
        ),
        "triage_result_ref": (
            report.alert_id if report.triage_analysis is not None else None
        ),
        "forensic_result_ref": (
            report.alert_id if report.forensic_analysis is not None else None
        ),
        "threat_intelligence_result_ref": (
            report.alert_id
            if report.threat_intelligence_analysis is not None
            else None
        ),
    }
    if record is None:
        session.add(InvestigationRecord(investigation_id=report.investigation_id, **values))
    else:
        for key, value in values.items():
            setattr(record, key, value)
    session.commit()


def get_investigation(
    session: Session, investigation_id: str
) -> InvestigationReport | None:
    record = session.get(InvestigationRecord, investigation_id)
    if record is None or record.report_json is None:
        return None
    return InvestigationReport.model_validate_json(record.report_json)


def list_investigations(
    session: Session, alert_id: str
) -> list[InvestigationReport]:
    records = session.scalars(
        select(InvestigationRecord)
        .where(InvestigationRecord.alert_id == alert_id)
        .order_by(InvestigationRecord.created_at)
    )
    return [
        InvestigationReport.model_validate_json(record.report_json)
        for record in records
        if record.report_json is not None
    ]


def list_all_investigations(
    session: Session, limit: int = 50, offset: int = 0
) -> tuple[list[InvestigationReport], int]:
    total = session.scalar(select(func.count(InvestigationRecord.investigation_id))) or 0
    records = session.scalars(
        select(InvestigationRecord)
        .order_by(InvestigationRecord.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    items = [
        InvestigationReport.model_validate_json(record.report_json)
        for record in records
        if record.report_json is not None
    ]
    return items, total


def investigation_summary(session: Session) -> InvestigationSummary:
    counts = dict(
        session.execute(
            select(InvestigationRecord.status, func.count())
            .group_by(InvestigationRecord.status)
        ).all()
    )
    return InvestigationSummary(
        total=sum(counts.values()),
        completed=counts.get("completed", 0),
        partial=counts.get("partial", 0),
        failed=counts.get("failed", 0),
        running=counts.get("running", 0),
    )


def clear_all(session: Session) -> None:
    session.execute(delete(SessionRecord))
    session.execute(delete(UserRecord))
    session.execute(delete(EvidenceRecord))
    session.execute(delete(InvestigationRecord))
    session.execute(delete(TriageRecord))
    session.execute(delete(ForensicRecord))
    session.execute(delete(ThreatIntelIndicatorRecord))
    session.execute(delete(ThreatIntelLookupRecord))
    session.execute(delete(ThreatIntelResultRecord))
    session.execute(delete(AlertRecord))
    session.execute(delete(EventRecord))


def save_validation_run(session: Session, run: ValidationRun) -> None:
    record = session.get(ValidationRunRecord, run.run_id)
    if record is None:
        session.add(ValidationRunRecord(
            run_id=run.run_id, executed_at=run.executed_at,
            report_json=run.model_dump_json(),
        ))
    else:
        record.report_json = run.model_dump_json()
    session.commit()


def get_validation_run(session: Session, run_id: str) -> ValidationRun | None:
    record = session.get(ValidationRunRecord, run_id)
    return ValidationRun.model_validate_json(record.report_json) if record else None


def list_validation_runs(session: Session) -> list[ValidationRun]:
    records = session.scalars(
        select(ValidationRunRecord).order_by(ValidationRunRecord.executed_at.desc())
    )
    return [ValidationRun.model_validate_json(record.report_json) for record in records]


def create_investigation(
    session: Session, investigation_id: str, alert_id: str | None = None
) -> InvestigationRecord:
    record = InvestigationRecord(
        investigation_id=investigation_id,
        alert_id=alert_id,
        status="open",
        created_at=datetime.now(timezone.utc),
    )
    session.add(record)
    session.commit()
    return record
