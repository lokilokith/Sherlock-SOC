from fastapi import Depends, FastAPI, HTTPException, Request
import json
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.config import settings
from app.persistence import repository
from app.persistence.db import (
    DemoSessionLocal,
    SessionLocal,
    demo_engine,
    initialize_database,
)
from datetime import datetime, timezone
from sqlalchemy import select
from app.persistence.models import AlertLifecycleRecord, AlertNoteRecord
from app.schemas.alerts import (
    Alert,
    AlertAssignmentUpdate,
    AlertLifecycleEvent,
    AlertNote,
    AlertNoteCreate,
    AlertPriorityUpdate,
    AlertStatusUpdate,
    TriageResult,
)
from app.schemas.auth import (
    AuthenticatedUser,
    ChangePasswordRequest,
    CreateUserRequest,
    LoginRequest,
    ManagedUser,
    UpdateUserRequest,
)
from app.schemas.events import EventImportResult, SecurityEvent
from app.schemas.forensics import ForensicAnalysis
from app.schemas.investigations import (
    AnalystAssessment,
    InvestigationListResponse,
    InvestigationReport,
)
from app.schemas.investigation_summary import InvestigationSummary
from app.schemas.runtime import RuntimeMode
from app.schemas.threat_intelligence import (
    ManualIOCRequest,
    ThreatIntelIndicatorResult,
    ThreatIntelligenceResult,
)
from app.schemas.validation import ValidationDataset, ValidationRule, ValidationRun
from app.services.detection import detect_alerts, detect_behavioural_alerts, detection_rule_catalog
from app.services.ingestion import EventIngestionError, ingest_json_document
from app.services import store
from app.services.triage import CrewAITriageProvider, TriageAgent, TriageError
from app.services.forensics import (
    CrewAIForensicsProvider,
    ForensicsAgent,
    ForensicsError,
)
from app.services.threat_intelligence import (
    CrewAIThreatIntelProvider,
    MockThreatIntelProvider,
    ThreatIntelError,
    ThreatIntelligenceAgent,
    _build_providers,
    extract_indicators,
    normalize_manual_indicator,
)
from app.services.virustotal_provider import VirusTotalProvider
from app.services.abuseipdb_provider import AbuseIPDBProvider
from app.services.alienvault_otx_provider import AlienVaultOTXProvider
from app.services.greynoise_provider import GreyNoiseProvider
from app.services.urlhaus_provider import URLhausProvider
from app.services import ti_cache
import uuid
from app.services.demo_agents import (
    build_demo_forensics_agent,
    build_demo_triage_agent,
    build_demo_threat_intelligence_agent,
)
from app.services.coordinator import (
    InvestigationCoordinator,
    InvestigationError,
)
from app.services.advanced_soc import (
    attack_storyline,
    detection_coverage,
    evidence_graph,
    evidence_quality,
    get_mitre_technique,
    hunting_query,
    ioc_explorer,
    list_mitre_techniques,
    mitre_matrix,
    mitre_overview,
    soc_copilot,
)
from app.services.auth import (
    authenticate,
    check_login_rate_limit,
    clear_session_cookie,
    create_session,
    ensure_analyst_user,
    record_failed_login,
    require_analyst,
    require_admin,
    reset_login_rate_limit,
    revoke_session,
    set_session_cookie,
)
from app.services.validation import dataset_metadata, rules, run_validation
from fastapi.responses import PlainTextResponse
from datetime import datetime, timezone
from sqlalchemy import delete
from app.persistence.models import SessionRecord, UserRecord
from app.services import auth


def safe_json_object(value: object, fallback: dict | None = None) -> dict:
    if fallback is None:
        fallback = {}
    if not isinstance(value, str) or not value.strip():
        return fallback
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback
    return parsed if isinstance(parsed, dict) else fallback


def safe_json_list(value: object) -> list:
    if not isinstance(value, str) or not value.strip():
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []

app = FastAPI(title=settings.app_name)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=settings.auth_enabled,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response


app.add_middleware(SecurityHeadersMiddleware)


class OriginValidationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            if origin and origin not in settings.cors_origins:
                return Response(status_code=403, content="Cross-site request blocked")
        return await call_next(request)


app.add_middleware(OriginValidationMiddleware)
initialize_database()
initialize_database(demo_engine)
ensure_analyst_user()


def seed_demo_database() -> None:
    with DemoSessionLocal() as session:
        if repository.list_alerts(session):
            return
        from pathlib import Path

        sample_path = (
            Path(__file__).resolve().parents[2]
            / "data"
            / "samples"
            / "sysmon_events.json"
        )
        if not sample_path.is_file():
            raise RuntimeError("Synthetic demo dataset is missing.")
        result = ingest_json_document(sample_path.read_bytes())
        repository.save_events(session, result.events)
        repository.save_alerts(session, detect_behavioural_alerts(result.events))


seed_demo_database()


def session_factory_for_request(request: Request):
    if not settings.auth_enabled:
        return SessionLocal
    from app.services.auth import current_user

    return SessionLocal if current_user(request) is not None else DemoSessionLocal


def build_agents() -> tuple[object, object, object]:
    if settings.agent_mode == "demo":
        return (
            build_demo_triage_agent(),
            build_demo_forensics_agent(),
            build_demo_threat_intelligence_agent(),
        )
    try:
        triage_agent = TriageAgent(CrewAITriageProvider())
    except (TriageError, ImportError, RuntimeError):
        triage_agent = build_demo_triage_agent()

    try:
        forensics_agent = ForensicsAgent(CrewAIForensicsProvider())
    except (ForensicsError, ImportError, RuntimeError):
        forensics_agent = build_demo_forensics_agent()

    return (
        triage_agent,
        forensics_agent,
        ThreatIntelligenceAgent(_build_providers()),
    )


def runtime_mode() -> RuntimeMode:
    if settings.agent_mode == "demo":
        return RuntimeMode(
            mode="demo", label="DEMO MODE — Mock providers", provider="deterministic mock agents"
        )
    return RuntimeMode(
        mode="live",
        label="LIVE MODE — VirusTotal where configured; deterministic analyst fallback",
        provider=(
            "VirusTotal plus deterministic Triage/Forensics fallback; "
            "CrewAI when SHERLOCK_LLM_MODEL is configured"
        ),
    )


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/runtime/mode", response_model=RuntimeMode)
def get_runtime_mode() -> RuntimeMode:
    return runtime_mode()


@app.post("/api/v1/auth/login", response_model=AuthenticatedUser)
def login(credentials: LoginRequest, request: Request, response: Response) -> AuthenticatedUser:
    if not settings.auth_enabled:
        raise HTTPException(status_code=404, detail="Authentication is disabled.")
    client_ip = request.client.host if request.client else "unknown"
    client_key = f"{client_ip}:{credentials.username.strip().lower()}"
    check_login_rate_limit(client_key)
    with SessionLocal() as session:
        user = authenticate(session, credentials.username, credentials.password)
    if user is None:
        record_failed_login(client_key)
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    reset_login_rate_limit(client_key)
    with SessionLocal() as session:
        user_record = session.get(UserRecord, user.username)
        if user_record is not None:
            user_record.last_login_at = datetime.now(timezone.utc)
            session.commit()
    token = create_session(user.username)
    set_session_cookie(response, token)
    return AuthenticatedUser(username=user.username, role=user.role)


@app.get("/api/v1/auth/me", response_model=AuthenticatedUser)
def auth_me(user: AuthenticatedUser | None = Depends(require_analyst)) -> AuthenticatedUser:
    return user


@app.post("/api/v1/auth/logout", status_code=204)
def logout(request: Request, response: Response) -> Response:
    revoke_session(request)
    clear_session_cookie(response)
    response.status_code = 204
    return response


@app.get("/api/v1/admin/users", response_model=list[ManagedUser])
def list_users(_: AuthenticatedUser = Depends(require_admin)) -> list[ManagedUser]:
    with SessionLocal() as session:
        users = session.query(UserRecord).order_by(UserRecord.username).all()
        return [
            ManagedUser(
                username=user.username,
                email=user.email,
                role=user.role,
                active=user.active,
                created_at=user.created_at,
                last_login_at=user.last_login_at,
            )
            for user in users
        ]


@app.post("/api/v1/admin/users", response_model=ManagedUser, status_code=201)
def create_user(payload: CreateUserRequest, _: AuthenticatedUser = Depends(require_admin)) -> ManagedUser:
    with SessionLocal() as session:
        if session.get(UserRecord, payload.username) is not None:
            raise HTTPException(status_code=409, detail="Username already exists.")
        user = UserRecord(
            id=payload.username,
            username=payload.username,
            email=payload.email,
            password_hash=auth._password_hash(payload.password),
            role=payload.role,
            active=True,
            created_at=datetime.now(timezone.utc),
        )
        session.add(user)
        session.commit()
        return         ManagedUser(
            username=user.username,
            email=user.email,
            role=user.role,
            active=True,
            created_at=user.created_at,
        )


@app.patch("/api/v1/admin/users/{username}", response_model=ManagedUser)
def update_user(
    username: str,
    payload: UpdateUserRequest,
    admin: AuthenticatedUser = Depends(require_admin),
) -> ManagedUser:
    if username == admin.username and (payload.role != "admin" or not payload.active):
        raise HTTPException(status_code=400, detail="The current administrator cannot be demoted or disabled.")
    with SessionLocal() as session:
        user = session.get(UserRecord, username)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")
        user.email = payload.email
        user.role = payload.role
        user.active = payload.active
        if not payload.active:
            session.execute(delete(SessionRecord).where(SessionRecord.username == username))
        session.commit()
        return ManagedUser(
            username=user.username,
            email=user.email,
            role=user.role,
            active=user.active,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        )


@app.post("/api/v1/admin/users/{username}/password", status_code=204)
def reset_user_password(
    username: str,
    payload: ChangePasswordRequest,
    _: AuthenticatedUser = Depends(require_admin),
) -> Response:
    with SessionLocal() as session:
        user = session.get(UserRecord, username)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")
        user.password_hash = auth._password_hash(payload.password)
        session.execute(delete(SessionRecord).where(SessionRecord.username == username))
        session.commit()
    return Response(status_code=204)


@app.post("/api/v1/events/import", response_model=EventImportResult)
async def import_events(
    request: Request, _: AuthenticatedUser = Depends(require_analyst)
) -> EventImportResult:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as error:
            raise HTTPException(
                status_code=400, detail="Invalid Content-Length header."
            ) from error
        if declared_length > settings.max_import_bytes:
            raise HTTPException(status_code=413, detail="Event import is too large.")
    body = await request.body()
    if len(body) > settings.max_import_bytes:
        raise HTTPException(status_code=413, detail="Event import is too large.")
    try:
        result = ingest_json_document(body)
    except EventIngestionError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    with SessionLocal() as session:
        new_events = repository.save_events(session, result.events)
        repository.save_alerts(session, detect_behavioural_alerts(new_events))
    return result


@app.get("/api/v1/events", response_model=list[SecurityEvent])
def list_events(request: Request) -> list[SecurityEvent]:
    with session_factory_for_request(request)() as session:
        return repository.list_events(session)


@app.get("/api/v1/alerts", response_model=list[Alert])
def list_alerts(request: Request) -> list[Alert]:
    with session_factory_for_request(request)() as session:
        return repository.list_alerts(session)


@app.get("/api/v1/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: str, request: Request) -> Alert:
    with session_factory_for_request(request)() as session:
        alert = repository.get_alert(session, alert_id)
    if alert is not None:
        return alert
    raise HTTPException(status_code=404, detail="Alert not found.")


ALERT_STATUS_TRANSITIONS = {
    "New": {"Acknowledged", "Investigating", "False Positive", "Closed"},
    "Acknowledged": {"Investigating", "Escalated", "Resolved", "False Positive", "Closed"},
    "Investigating": {"Escalated", "Resolved", "False Positive", "Closed"},
    "Escalated": {"Investigating", "Resolved", "Closed"},
    "Resolved": {"Closed", "False Positive"},
    "Closed": set(),
    "False Positive": {"Closed"},
}


@app.patch("/api/v1/alerts/{alert_id}/status", response_model=Alert)
def update_alert_status(
    alert_id: str, update: AlertStatusUpdate, request: Request
) -> Alert:
    target = update.status.strip()
    supported_statuses = {
        "New", "Acknowledged", "Investigating", "Escalated",
        "Resolved", "Closed", "False Positive",
    }
    if target not in supported_statuses:
        raise HTTPException(status_code=422, detail="Unsupported alert status.")
    with session_factory_for_request(request)() as session:
        from app.persistence.models import AlertRecord
        record = session.get(AlertRecord, alert_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        previous = record.status
        if target != previous and target not in ALERT_STATUS_TRANSITIONS.get(previous, set()):
            raise HTTPException(status_code=409, detail=f"Invalid transition from {previous} to {target}.")
        if target != previous:
            record.status = target
            session.add(AlertLifecycleRecord(
                alert_id=alert_id, event_type="status", previous_value=previous,
                new_value=target, timestamp=datetime.now(timezone.utc), details=update.note,
            ))
        session.commit()
        return repository.get_alert(session, alert_id)


@app.patch("/api/v1/alerts/{alert_id}/assignment", response_model=Alert)
def update_alert_assignment(
    alert_id: str, update: AlertAssignmentUpdate, request: Request
) -> Alert:
    from app.persistence.models import AlertRecord
    with session_factory_for_request(request)() as session:
        record = session.get(AlertRecord, alert_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        previous = record.owner
        owner = update.owner.strip() if update.owner and update.owner.strip() else None
        if owner != previous:
            record.owner = owner
            record.assigned_at = datetime.now(timezone.utc) if owner else None
            session.add(AlertLifecycleRecord(
                alert_id=alert_id, event_type="assignment", previous_value=previous,
                new_value=owner, timestamp=datetime.now(timezone.utc),
            ))
        session.commit()
        return repository.get_alert(session, alert_id)


@app.patch("/api/v1/alerts/{alert_id}/priority", response_model=Alert)
def update_alert_priority(alert_id: str, update: AlertPriorityUpdate, request: Request) -> Alert:
    from app.persistence.models import AlertRecord
    if update.priority.upper() not in {"P1", "P2", "P3", "P4"}:
        raise HTTPException(status_code=422, detail="Priority must be P1, P2, P3, or P4.")
    with session_factory_for_request(request)() as session:
        record = session.get(AlertRecord, alert_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        previous = record.priority
        record.priority = update.priority.upper()
        if previous != record.priority:
            session.add(AlertLifecycleRecord(
                alert_id=alert_id, event_type="priority", previous_value=previous,
                new_value=record.priority, timestamp=datetime.now(timezone.utc),
            ))
        session.commit()
        return repository.get_alert(session, alert_id)


@app.post("/api/v1/alerts/{alert_id}/notes", response_model=AlertNote)
def add_alert_note(alert_id: str, update: AlertNoteCreate, request: Request) -> AlertNote:
    from app.persistence.models import AlertRecord
    with session_factory_for_request(request)() as session:
        if session.get(AlertRecord, alert_id) is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        record = AlertNoteRecord(
            alert_id=alert_id, investigation_id=update.investigation_id, note=update.note.strip(),
            created_at=datetime.now(timezone.utc),
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        return AlertNote(
            id=record.id, alert_id=record.alert_id, investigation_id=record.investigation_id,
            author=record.author, note=record.note, created_at=record.created_at,
        )


@app.get("/api/v1/alerts/{alert_id}/history", response_model=list[AlertLifecycleEvent])
def alert_history(alert_id: str, request: Request) -> list[AlertLifecycleEvent]:
    with session_factory_for_request(request)() as session:
        records = session.scalars(
            select(AlertLifecycleRecord).where(AlertLifecycleRecord.alert_id == alert_id)
            .order_by(AlertLifecycleRecord.timestamp.desc())
        ).all()
        return [AlertLifecycleEvent.model_validate(record) for record in records]


@app.get("/api/v1/alerts/{alert_id}/notes", response_model=list[AlertNote])
def list_alert_notes(alert_id: str, request: Request) -> list[AlertNote]:
    with session_factory_for_request(request)() as session:
        records = session.scalars(
            select(AlertNoteRecord).where(AlertNoteRecord.alert_id == alert_id)
            .order_by(AlertNoteRecord.created_at.desc())
        ).all()
        return [AlertNote.model_validate(record) for record in records]


@app.post("/api/v1/alerts/{alert_id}/triage", response_model=TriageResult)
def triage_alert(
    alert_id: str, _: AuthenticatedUser = Depends(require_analyst)
) -> TriageResult:
    with SessionLocal() as session:
        alert = repository.get_alert(session, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        events = repository.get_events_for_alert(session, alert_id)
        try:
            triage_agent, _, _ = build_agents()
            result = triage_agent.evaluate(alert, events)
        except TriageError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error
        repository.save_triage_result(session, result)
        return result


@app.get("/api/v1/alerts/{alert_id}/triage", response_model=TriageResult)
def get_triage(alert_id: str, request: Request) -> TriageResult:
    with session_factory_for_request(request)() as session:
        if repository.get_alert(session, alert_id) is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        result = repository.get_triage_result(session, alert_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Triage result not found.")
    return result


@app.post(
    "/api/v1/alerts/{alert_id}/forensics",
    response_model=ForensicAnalysis,
)
def forensics_alert(
    alert_id: str, _: AuthenticatedUser = Depends(require_analyst)
) -> ForensicAnalysis:
    with SessionLocal() as session:
        alert = repository.get_alert(session, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        events = repository.get_events_for_alert(session, alert_id)
        if not events:
            raise HTTPException(status_code=422, detail="Alert has no evidence.")
        try:
            _, forensics_agent, _ = build_agents()
            result = forensics_agent.evaluate(alert, events)
        except ForensicsError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error
        repository.save_forensic_analysis(session, result)
        return result


@app.post(
    "/api/v1/alerts/{alert_id}/threat-intelligence",
    response_model=ThreatIntelligenceResult,
)
def threat_intelligence_alert(
    alert_id: str, _: AuthenticatedUser = Depends(require_analyst)
) -> ThreatIntelligenceResult:
    with SessionLocal() as session:
        alert = repository.get_alert(session, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        events = repository.get_events_for_alert(session, alert_id)
        indicators = extract_indicators(events)
        if not indicators:
            raise HTTPException(status_code=422, detail="Alert has no indicators.")
        try:
            _, _, threat_intelligence_agent = build_agents()
            result = threat_intelligence_agent.evaluate(
                alert, indicators, events
            )
        except ThreatIntelError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error
        repository.save_threat_intelligence(session, result)
        return result


@app.get(
    "/api/v1/alerts/{alert_id}/threat-intelligence",
    response_model=ThreatIntelligenceResult,
)
def get_threat_intelligence(
    alert_id: str, request: Request
) -> ThreatIntelligenceResult:
    with session_factory_for_request(request)() as session:
        if repository.get_alert(session, alert_id) is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        result = repository.get_threat_intelligence(session, alert_id)
    if result is None:
        raise HTTPException(
            status_code=404, detail="Threat intelligence result not found."
        )
    return result


@app.post(
    "/api/v1/threat-intelligence/lookup",
    response_model=list[ThreatIntelIndicatorResult],
)
def manual_threat_intelligence_lookup(
    request: ManualIOCRequest, _: AuthenticatedUser = Depends(require_analyst)
) -> list[ThreatIntelIndicatorResult]:
    if settings.agent_mode != "live":
        raise HTTPException(status_code=409, detail="Manual VirusTotal enrichment requires LIVE mode.")

    try:
        indicator = normalize_manual_indicator(request.value, request.indicator_type)
    except ThreatIntelError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    applicable = {
        "virustotal": {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"},
        "abuseipdb": {"ipv4", "ipv6"},
        "alienvault_otx": {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"},
        "greynoise": {"ipv4", "ipv6"},
        "urlhaus": {"url"},
    }
    providers = [
        VirusTotalProvider(),
        AbuseIPDBProvider(),
        AlienVaultOTXProvider(),
        GreyNoiseProvider(),
        URLhausProvider(),
    ]
    results: list[ThreatIntelIndicatorResult] = []
    for provider in providers:
        if indicator.indicator_type not in applicable[provider.name]:
            continue
        cached = ti_cache.get_cached(provider.name, indicator.indicator_type, indicator.normalized_value)
        lookup = cached
        if lookup is None:
            lookup = provider.lookup(indicator)
            ti_cache.set_cached(provider.name, indicator.indicator_type, indicator.normalized_value, lookup)
        result = ThreatIntelIndicatorResult(
            indicator_type=indicator.indicator_type,
            normalized_value=indicator.normalized_value,
            original_value=indicator.original_value,
            source_event_ids=indicator.source_event_ids,
            source_fields=indicator.source_fields,
            provider_name=lookup.provider_name,
            verdict=lookup.verdict,
            reputation_score=lookup.reputation_score,
            confidence=lookup.confidence,
            analysis_stats=lookup.analysis_stats,
            evidence_summary=lookup.evidence_summary,
            source_reference=lookup.source_reference,
            lookup_timestamp=lookup.lookup_timestamp,
            lookup_status=lookup.lookup_status,
            cached=cached is not None,
        )
        if lookup.lookup_status == "available":
            result_id = f"manual-{uuid.uuid4()}"
            persisted = ThreatIntelligenceResult(
                alert_id=result_id,
                investigation_summary="Manual multi-provider IOC enrichment result.",
                indicators=[result],
                evidence_references=[{"event_id": "manual-enrichment", "fields": ["manual_ioc"]}],
            )
            with SessionLocal() as session:
                repository.save_threat_intelligence(session, persisted)
        results.append(result)
    return results


@app.get(
    "/api/v1/threat-intelligence/manual",
    response_model=list[ThreatIntelIndicatorResult],
)
def list_manual_threat_intelligence(
    request: Request, _: AuthenticatedUser = Depends(require_analyst)
) -> list[ThreatIntelIndicatorResult]:
    del request
    with SessionLocal() as session:
        results = repository.list_manual_threat_intelligence(session)
    return [indicator for result in results for indicator in result.indicators]


@app.get("/api/v1/threat-intelligence/status")
def threat_intelligence_status(_: AuthenticatedUser = Depends(require_analyst)) -> dict:
    provider_specs = [
        ("virustotal", "VirusTotal", bool(settings.virustotal_api_key), "IP, domain, URL, MD5, SHA1, SHA256"),
        ("abuseipdb", "AbuseIPDB", bool(settings.abuseipdb_api_key), "IPv4 and IPv6"),
        ("alienvault_otx", "AlienVault OTX", bool(settings.otx_api_key), "IP, domain, URL, MD5, SHA1, SHA256"),
        ("greynoise", "GreyNoise Community", True, "IP only"),
        ("urlhaus", "URLhaus", bool(settings.urlhaus_auth_key), "URL only"),
    ]
    with SessionLocal() as session:
        records = repository.list_threat_intelligence_records(session)
    successful = {}
    for lookup, _ in records:
        if lookup.lookup_status == "available" and lookup.provider_name not in successful:
            successful[lookup.provider_name] = lookup.lookup_timestamp.isoformat()
    providers = []
    for provider_id, name, configured, supported in provider_specs:
        providers.append({
            "id": provider_id,
            "name": name,
            "configured": configured,
            "configuration_status": "configured" if configured else ("community" if provider_id == "greynoise" else "unconfigured"),
            "connectivity": "available" if provider_id in successful else "not-tested",
            "supported": supported,
            "last_successful_lookup": successful.get(provider_id),
        })
    live = [(lookup, indicator) for lookup, indicator in records if lookup.provider_name not in {"mock", "demo-mock"}]
    indicators = {(lookup.indicator_type, lookup.normalized_value) for lookup, _ in live}
    return {
        "providers": providers,
        "overview": {
            "configured": sum(1 for provider in providers if provider["configured"]),
            "available": sum(1 for provider in providers if provider["connectivity"] == "available"),
            "unavailable": sum(1 for provider in providers if provider["connectivity"] == "not-tested" and provider["configured"]),
            "persisted_lookups": len(live),
            "malicious_findings": sum(1 for lookup, _ in live if lookup.verdict == "malicious"),
            "indicators_enriched": len(indicators),
        },
    }


@app.get("/api/v1/threat-intelligence/console")
def threat_intelligence_console(_: AuthenticatedUser = Depends(require_analyst)) -> dict:
    with SessionLocal() as session:
        records = repository.list_threat_intelligence_records(session)
    items = []
    for lookup, indicator in records:
        items.append({
            "indicator_type": lookup.indicator_type,
            "normalized_value": lookup.normalized_value,
            "original_value": indicator.original_value if indicator else lookup.normalized_value,
            "provider_name": lookup.provider_name,
            "verdict": lookup.verdict,
            "lookup_status": lookup.lookup_status,
            "source_reference": lookup.source_reference,
            "lookup_timestamp": lookup.lookup_timestamp.isoformat(),
            "cached": lookup.cached,
            "historical_demo": lookup.provider_name in {"mock", "demo-mock"},
            "evidence_summary": lookup.evidence_summary,
            "analysis_stats": safe_json_object(lookup.analysis_stats_json),
            "associated_alert_id": None if lookup.alert_id.startswith("manual-") else lookup.alert_id,
            "source_event_ids": safe_json_list(indicator.source_event_ids_json) if indicator else [],
        })
    return {"records": items}


def build_coordinator() -> InvestigationCoordinator:
    triage_agent, forensics_agent, threat_intelligence_agent = build_agents()
    return InvestigationCoordinator(
        triage_agent,
        forensics_agent,
        threat_intelligence_agent,
    )


@app.post(
    "/api/v1/alerts/{alert_id}/investigate",
    response_model=InvestigationReport,
)
def investigate_alert(
    alert_id: str, _: AuthenticatedUser = Depends(require_analyst)
) -> InvestigationReport:
    investigation_id = f"investigation-{alert_id}"
    with SessionLocal() as session:
        alert = repository.get_alert(session, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        events = repository.get_events_for_alert(session, alert_id)
        if not events:
            raise HTTPException(status_code=422, detail="Alert has no evidence.")
        previous_report = repository.get_investigation(
            session, investigation_id
        )
        try:
            report = build_coordinator().investigate(
                investigation_id,
                alert,
                events,
                previous_report,
                settings.agent_mode,
            )
        except InvestigationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except (TriageError, ForensicsError, ThreatIntelError) as error:
            raise HTTPException(status_code=502, detail=str(error)) from error
        if report.triage_analysis is not None:
            repository.save_triage_result(session, report.triage_analysis)
        if report.forensic_analysis is not None:
            repository.save_forensic_analysis(session, report.forensic_analysis)
        if report.threat_intelligence_analysis is not None:
            repository.save_threat_intelligence(
                session, report.threat_intelligence_analysis
            )
        repository.save_investigation(session, report)
        from app.persistence.models import InvestigationAlertRecord
        linked = session.scalar(
            select(InvestigationAlertRecord).where(
                InvestigationAlertRecord.investigation_id == investigation_id,
                InvestigationAlertRecord.alert_id == alert_id,
            )
        )
        if linked is None:
            session.add(InvestigationAlertRecord(
                investigation_id=investigation_id, alert_id=alert_id
            ))
        session.commit()
        return report


@app.get(
    "/api/v1/investigations",
    response_model=InvestigationListResponse,
)
def list_investigations(
    request: Request,
    limit: int = 50,
    offset: int = 0,
) -> InvestigationListResponse:
    bounded_limit = max(1, min(limit, 100))
    bounded_offset = max(0, offset)
    with session_factory_for_request(request)() as session:
        items, total = repository.list_all_investigations(
            session, limit=bounded_limit, offset=bounded_offset
        )
    return InvestigationListResponse(
        items=items,
        total=total,
        limit=bounded_limit,
        offset=bounded_offset,
    )


@app.get(
    "/api/v1/investigations/summary",
    response_model=InvestigationSummary,
)
def get_investigation_summary(request: Request) -> InvestigationSummary:
    with session_factory_for_request(request)() as session:
        return repository.investigation_summary(session)


@app.get(
    "/api/v1/investigations/{investigation_id}",
    response_model=InvestigationReport,
)
def get_investigation(
    investigation_id: str, request: Request
) -> InvestigationReport:
    with session_factory_for_request(request)() as session:
        report = repository.get_investigation(session, investigation_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return report


@app.get(
    "/api/v1/alerts/{alert_id}/investigations",
    response_model=list[InvestigationReport],
)
def list_alert_investigations(
    alert_id: str, request: Request
) -> list[InvestigationReport]:
    with session_factory_for_request(request)() as session:
        if repository.get_alert(session, alert_id) is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        return repository.list_investigations(session, alert_id)


@app.post("/api/v1/alerts/{alert_id}/investigations/{investigation_id}")
def link_alert_investigation(
    alert_id: str,
    investigation_id: str,
    _: AuthenticatedUser = Depends(require_analyst),
) -> dict[str, str]:
    from app.persistence.models import InvestigationAlertRecord, InvestigationRecord, AlertRecord
    with SessionLocal() as session:
        if session.get(AlertRecord, alert_id) is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        if session.get(InvestigationRecord, investigation_id) is None:
            raise HTTPException(status_code=404, detail="Investigation not found.")
        existing = session.scalar(
            select(InvestigationAlertRecord).where(
                InvestigationAlertRecord.alert_id == alert_id,
                InvestigationAlertRecord.investigation_id == investigation_id,
            )
        )
        if existing is None:
            session.add(InvestigationAlertRecord(
                alert_id=alert_id, investigation_id=investigation_id
            ))
            session.commit()
        return {"alert_id": alert_id, "investigation_id": investigation_id, "status": "linked"}


@app.get("/api/v1/validation/rules", response_model=list[ValidationRule])
def validation_rules(_: AuthenticatedUser = Depends(require_analyst)) -> list[ValidationRule]:
    return rules()


@app.get("/api/v1/validation/datasets", response_model=list[ValidationDataset])
def validation_datasets(_: AuthenticatedUser = Depends(require_analyst)) -> list[ValidationDataset]:
    return [dataset_metadata()]


@app.post("/api/v1/validation/runs", response_model=ValidationRun)
def create_validation_run(_: AuthenticatedUser = Depends(require_analyst)) -> ValidationRun:
    run = run_validation()
    with SessionLocal() as session:
        repository.save_validation_run(session, run)
    return run


@app.get("/api/v1/validation/runs", response_model=list[ValidationRun])
def list_validation_runs(_: AuthenticatedUser = Depends(require_analyst)) -> list[ValidationRun]:
    with SessionLocal() as session:
        return repository.list_validation_runs(session)


@app.get("/api/v1/validation/runs/{run_id}", response_model=ValidationRun)
def get_validation_run(run_id: str, _: AuthenticatedUser = Depends(require_analyst)) -> ValidationRun:
    with SessionLocal() as session:
        run = repository.get_validation_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Validation run not found.")
    return run


@app.get("/api/v1/validation/runs/{run_id}/report")
def export_validation_report(run_id: str, format: str = "json", _: AuthenticatedUser = Depends(require_analyst)):
    with SessionLocal() as session:
        run = repository.get_validation_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Validation run not found.")
    if format == "json":
        return run
    if format != "markdown":
        raise HTTPException(status_code=400, detail="Report format must be json or markdown.")
    m = run.metrics
    lines = [
        f"# Detection Validation Report: {run.run_id}", "",
        f"- Rule: {run.rule.rule_id} {run.rule.name} ({run.rule.version})",
        f"- Dataset: {run.dataset.dataset_id} ({run.dataset.version})",
        f"- Executed: {run.executed_at.isoformat()}", "",
        "## Metrics", "",
        f"| Metric | Value |", "|---|---:|",
        *[f"| {name.upper()} | {value if value is not None else 'N/A'} |" for name, value in [("precision", m.precision), ("recall", m.recall), ("f1", m.f1), ("specificity", m.specificity), ("accuracy", m.accuracy)]],
        "", "## Confusion matrix", "",
        f"TP={m.tp}, FP={m.fp}, FN={m.fn}, TN={m.tn}", "",
        "Metrics describe this versioned synthetic dataset only; they do not prove real-world detection accuracy.",
    ]
    return PlainTextResponse("\n".join(lines), media_type="text/markdown")


@app.get("/api/v1/mitre/overview")
def mitre_overview_endpoint(_: AuthenticatedUser = Depends(require_analyst)):
    return mitre_overview()


@app.get("/api/v1/mitre/matrix")
def mitre_matrix_endpoint(_: AuthenticatedUser = Depends(require_analyst)):
    return mitre_matrix()


@app.get("/api/v1/mitre/techniques")
def mitre_techniques_endpoint(search: str = "", _: AuthenticatedUser = Depends(require_analyst)):
    return list_mitre_techniques(search)


@app.get("/api/v1/mitre/techniques/{technique_id}")
def mitre_technique_endpoint(technique_id: str, _: AuthenticatedUser = Depends(require_analyst)):
    technique = get_mitre_technique(technique_id)
    if technique is None:
        raise HTTPException(status_code=404, detail="MITRE technique not found.")
    return technique


@app.get("/api/v1/detection/coverage")
def detection_coverage_endpoint(request: Request, _: AuthenticatedUser = Depends(require_analyst)):
    with session_factory_for_request(request)() as session:
        return detection_coverage(session)


@app.get("/api/v1/detection/rules")
def detection_rules_endpoint(_: AuthenticatedUser = Depends(require_analyst)):
    return detection_rule_catalog()


@app.get("/api/v1/investigations/{investigation_id}/evidence-graph")
def investigation_evidence_graph(investigation_id: str, request: Request, _: AuthenticatedUser = Depends(require_analyst)):
    with session_factory_for_request(request)() as session:
        return evidence_graph(session, investigation_id)


@app.get("/api/v1/investigations/{investigation_id}/storyline")
def investigation_storyline(investigation_id: str, request: Request, _: AuthenticatedUser = Depends(require_analyst)):
    with session_factory_for_request(request)() as session:
        return attack_storyline(session, investigation_id)


@app.get("/api/v1/investigations/{investigation_id}/copilot")
def investigation_copilot(investigation_id: str, request: Request, _: AuthenticatedUser = Depends(require_analyst)):
    with session_factory_for_request(request)() as session:
        return soc_copilot(session, investigation_id)


@app.get("/api/v1/investigations/{investigation_id}/evidence-quality")
def investigation_evidence_quality(investigation_id: str, request: Request, _: AuthenticatedUser = Depends(require_analyst)):
    with session_factory_for_request(request)() as session:
        return evidence_quality(session, investigation_id)


@app.put("/api/v1/investigations/{investigation_id}/assessment", response_model=InvestigationReport)
def save_investigation_assessment(
    investigation_id: str,
    assessment: AnalystAssessment,
    request: Request,
    user: AuthenticatedUser = Depends(require_analyst),
):
    with session_factory_for_request(request)() as session:
        report = repository.get_investigation(session, investigation_id)
        if report is None:
            raise HTTPException(status_code=404, detail="Investigation not found.")
        assessment.assessor = user.username
        assessment.updated_at = datetime.now(timezone.utc)
        report.analyst_assessment = assessment
        repository.save_investigation(session, report)
        return report


@app.get("/api/v1/hunting/search")
def hunting_search(
    request: Request,
    indicator: str = "",
    host: str = "",
    process: str = "",
    _: AuthenticatedUser = Depends(require_analyst),
):
    with session_factory_for_request(request)() as session:
        return hunting_query(session, indicator, host, process)


@app.get("/api/v1/ioc/{indicator}/explorer")
def ioc_relationship_explorer(indicator: str, request: Request, _: AuthenticatedUser = Depends(require_analyst)):
    with session_factory_for_request(request)() as session:
        return ioc_explorer(session, indicator)
