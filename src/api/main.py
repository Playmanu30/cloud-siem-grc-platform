"""
FastAPI Application - Cloud SIEM & GRC Platform
Main REST API serving security dashboards, compliance reports, and threat intelligence
"""

import os
import secrets
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Literal, Optional

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Security
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from ..compliance import NIST80053Engine
from ..threat_intel.engine import ThreatIntelligenceEngine
from ..threat_intel.mitre_mapper import (
    AWS_EVENT_TECHNIQUE_MAP,
    TACTICS,
    MITREMapper,
)
from ..utils.config import get_settings
from ..utils.logging import get_logger, setup_logging
from ..utils.store import get_store

logger = get_logger(__name__)

IOCType = Literal["ip", "hash", "domain"]
Severity = Literal["critical", "high", "medium", "low", "info"]
AlertStatus = Literal["open", "acknowledged", "resolved"]
ControlStatus = Literal[
    "pass", "fail", "warning", "not_applicable", "error", "not_assessed"
]

TAGS_METADATA = [
    {"name": "Health", "description": "Liveness and integration status"},
    {"name": "Dashboard", "description": "Aggregated security posture"},
    {"name": "Events", "description": "Cloud log collection and event queries"},
    {"name": "Threat Intelligence", "description": "IOC enrichment (VirusTotal, Shodan, AbuseIPDB)"},
    {"name": "Compliance", "description": "NIST 800-53 Rev5 assessments"},
    {"name": "Alerts", "description": "Alerts generated from collected events"},
    {"name": "MITRE ATT&CK", "description": "Tactic/technique mapping and attack chains"},
]


# ── Pydantic Models ─────────────────────────────────────────────

class IOCRequest(BaseModel):
    """Request to enrich an IOC"""
    type: IOCType
    value: str = Field(min_length=1, max_length=2048)


class BatchIOCRequest(BaseModel):
    """Request to enrich multiple IOCs"""
    iocs: List[IOCRequest] = Field(min_length=1, max_length=50)


class ComplianceAssessmentRequest(BaseModel):
    """Request to run a compliance assessment"""
    framework: str = "NIST 800-53"
    control_ids: Optional[List[str]] = None
    aws_data: Optional[Dict[str, Any]] = None
    azure_data: Optional[Dict[str, Any]] = None


class EventModel(BaseModel):
    """Normalized security event"""
    id: int
    event_type: str
    severity: Severity
    source: str
    message: str
    timestamp: str
    details: Dict[str, Any]


class EventListResponse(BaseModel):
    total: int
    offset: int
    limit: int
    events: List[EventModel]


class AlertModel(BaseModel):
    """Alert generated from a high or critical event"""
    id: int
    rule: Optional[str] = None
    severity: Severity
    status: AlertStatus
    message: str
    event_id: Optional[int] = None
    created_at: str


class AlertListResponse(BaseModel):
    total: int
    alerts: List[AlertModel]


class AlertUpdate(BaseModel):
    status: AlertStatus


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    services: Dict[str, Any]
    timestamp: str


class CollectionResponse(BaseModel):
    status: str
    stored: int
    results: Dict[str, Any]
    timestamp: str


class ControlResult(BaseModel):
    control_id: str
    family: str
    title: str
    description: str
    priority: str
    baseline: str
    status: str
    last_checked: Optional[str] = None
    findings_count: int
    findings: List[str]


class ComplianceReportResponse(BaseModel):
    assessment_id: str
    framework: str
    assessment_date: str
    completed_date: str
    total_controls: int
    compliance_score: float
    status_summary: Dict[str, int]
    controls: List[ControlResult]
    data_sources: Dict[str, bool] = Field(default_factory=dict)


class ComplianceSummaryResponse(BaseModel):
    framework: Optional[str] = None
    assessment_date: Optional[str] = None
    compliance_score: Optional[float] = None
    total_controls: Optional[int] = None
    status_summary: Optional[Dict[str, int]] = None
    data_sources: Optional[Dict[str, bool]] = None
    message: Optional[str] = None
    action: Optional[str] = None


class TacticModel(BaseModel):
    id: str
    name: str
    description: str
    events_mapped: int


class TacticsResponse(BaseModel):
    tactics: List[TacticModel]


class TechniqueModel(BaseModel):
    id: str
    name: str


class TechniquesResponse(BaseModel):
    tactic_id: str
    techniques: List[TechniqueModel]


class TechniqueCount(BaseModel):
    id: str
    name: str
    count: int


class MitreReportResponse(BaseModel):
    report_id: str
    total_events_analyzed: int
    attack_chains_detected: int
    attack_chains: List[Dict[str, Any]]
    heatmap: Dict[str, Any]
    top_techniques: List[TechniqueCount]
    timestamp: str


class DashboardResponse(BaseModel):
    """Dashboard summary data"""
    total_events: int
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    compliance_score: float
    active_threats: int
    top_source_ips: List[Dict[str, Any]]
    recent_events: List[Dict[str, Any]]
    cloud_findings: Dict[str, int]
    timestamp: str


# ── Application lifecycle & middleware ──────────────────────────

@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    setup_logging(settings.log_level, json_output=not settings.debug)

    if settings.environment == "production" and not settings.api_key:
        raise RuntimeError("API_KEY must be set when ENV=production")
    if settings.environment == "production" and settings.debug:
        logger.warning("debug mode enabled in production")

    workers = int(os.getenv("WEB_CONCURRENCY", "1") or 1)
    if workers > 1:
        # shortcut: limits live in process memory, so each worker enforces its own
        logger.warning("multiple workers: rate limiting is per-process", workers=workers)

    store = get_store()
    logger.info(
        "platform started",
        environment=settings.environment,
        database=str(store.path),
        aws=settings.aws_configured,
        azure=settings.azure_configured,
        threat_intel=settings.threat_intel_configured,
        workers=workers,
    )
    yield


app = FastAPI(
    title="Cloud SIEM & GRC Platform",
    description=(
        "Unified cloud security monitoring and compliance management API. "
        "Aggregates logs from AWS and Azure, provides threat intelligence "
        "enrichment, and automates NIST 800-53 compliance assessments."
    ),
    version=get_settings().app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=TAGS_METADATA,
    lifespan=lifespan,
)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Request id, body-size cap and defensive response headers"""

    def __init__(self, app, max_body_bytes: int):
        super().__init__(app)
        self.max_body_bytes = max_body_bytes

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = request_id

        try:
            content_length = int(request.headers.get("content-length", "0"))
        except ValueError:
            content_length = 0
        if content_length > self.max_body_bytes:
            return JSONResponse(
                {"detail": "Request body too large", "request_id": request_id},
                status_code=413,
            )

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window per-client request limit (in-process)"""

    EXEMPT_PATHS = {"/", "/health", "/docs", "/redoc", "/openapi.json"}

    def __init__(self, app, limit: int, window_seconds: int = 60):
        super().__init__(app)
        self.limit = limit
        self.window = window_seconds
        self._hits: Dict[str, deque] = defaultdict(deque)
        self._lock = Lock()

    async def dispatch(self, request: Request, call_next):
        if self.limit <= 0 or request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        client = request.client.host if request.client else "unknown"
        now = time.monotonic()

        with self._lock:
            if len(self._hits) > 10_000:  # shortcut: unbounded client keys, prune when a real gateway is added
                self._hits.clear()
            hits = self._hits[client]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                retry_after = int(self.window - (now - hits[0])) + 1
                return JSONResponse(
                    {"detail": "Rate limit exceeded"},
                    status_code=429,
                    headers={"Retry-After": str(retry_after)},
                )
            hits.append(now)

        return await call_next(request)


app.add_middleware(RateLimitMiddleware, limit=get_settings().rate_limit_rpm)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    RequestContextMiddleware, max_body_bytes=get_settings().max_body_bytes
)

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/ui", StaticFiles(directory=STATIC_DIR), name="ui")


@app.get("/", include_in_schema=False)
async def root():
    """Serve the security workspace"""
    return FileResponse(STATIC_DIR / "index.html")


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, scheme_name="ApiKeyAuth")


def require_api_key(api_key: Optional[str] = Security(api_key_header)) -> None:
    """Validate the API key when one is configured (always required in production)"""
    settings = get_settings()
    if not settings.api_key:
        if settings.environment == "production":
            raise HTTPException(status_code=500, detail="API_KEY is not configured")
        return
    if not api_key or not secrets.compare_digest(api_key, settings.api_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])


# ── Service singletons ──────────────────────────────────────────

@lru_cache
def get_ti_engine() -> ThreatIntelligenceEngine:
    settings = get_settings()
    return ThreatIntelligenceEngine(
        virustotal_api_key=settings.vt_api_key,
        shodan_api_key=settings.shodan_api_key,
        abuseipdb_api_key=settings.abuseipdb_api_key,
    )


@lru_cache
def get_compliance_engine() -> NIST80053Engine:
    return NIST80053Engine()


# ── Health & Status ─────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    settings = get_settings()
    try:
        events = get_store().count_events()
        database = "up"
    except Exception as exc:  # pragma: no cover - only on a broken database file
        logger.error("database health check failed", error=str(exc))
        events, database = 0, "down"

    healthy = database == "up"
    return JSONResponse(
        {
            "status": "healthy" if healthy else "degraded",
            "version": settings.app_version,
            "environment": settings.environment,
            "services": {
                "database": database,
                "storage": "sqlite" if settings.database_url.startswith("sqlite:///") else "external",
                "events_stored": events,
                "aws_collector": "configured" if settings.aws_configured else "not_configured",
                "azure_collector": "configured" if settings.azure_configured else "not_configured",
                "threat_intel": "configured" if settings.threat_intel_configured else "not_configured",
                "compliance_engine": "ready",
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        status_code=200 if healthy else 503,
    )


# ── Dashboard ───────────────────────────────────────────────────

@router.get("/dashboard", response_model=DashboardResponse, tags=["Dashboard"])
async def get_dashboard():
    """Get unified security dashboard data"""
    store = get_store()
    alert_counts = store.alert_counts()
    status_counts = store.alert_status_counts()
    latest_report = store.latest_report()
    source_counts = store.source_counts()

    return DashboardResponse(
        total_events=store.count_events(),
        total_alerts=sum(status_counts.values()),
        open_alerts=status_counts.get("open", 0),
        critical_alerts=alert_counts.get("critical", 0),
        high_alerts=alert_counts.get("high", 0),
        medium_alerts=alert_counts.get("medium", 0),
        low_alerts=alert_counts.get("low", 0),
        compliance_score=float(latest_report.get("compliance_score", 0.0)) if latest_report else 0.0,
        active_threats=alert_counts.get("critical", 0) + alert_counts.get("high", 0),
        top_source_ips=store.top_source_ips(),
        recent_events=store.query_events(limit=20)[1],
        cloud_findings={
            "aws": sum(n for source, n in source_counts.items() if source.startswith("AWS")),
            "azure": sum(n for source, n in source_counts.items() if source.startswith("Azure") or source.startswith("Microsoft")),
        },
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ── Event Collection ────────────────────────────────────────────

def _collect_aws(hours: int) -> Dict[str, Any]:
    settings = get_settings()
    from ..collectors.aws_collector import AWSCollector

    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    collector = AWSCollector(
        region=settings.aws_region,
        access_key=settings.aws_access_key_id,
        secret_key=settings.aws_secret_access_key,
        session_token=settings.aws_session_token,
    )

    raw_cloudtrail = collector.collect_cloudtrail_events(start, datetime.now(timezone.utc))
    mapper = MITREMapper()
    events = []
    for raw in raw_cloudtrail:
        event = collector.parse_event_to_security_event(raw, "cloudtrail").to_dict()
        mapping = mapper.map_cloudtrail_event(raw)
        if mapping:
            event["details"]["mitre"] = {
                key: mapping[key]
                for key in ("technique_id", "technique_name", "tactic_id", "tactic_name")
            }
        events.append(event)

    events += [
        collector.parse_event_to_security_event(raw, "security_hub").to_dict()
        for raw in collector.get_security_hub_findings()
    ]
    events += [
        collector.parse_event_to_security_event(raw, "guardduty").to_dict()
        for raw in collector.get_guardduty_findings(settings.aws_guardduty_detector_id)
    ]
    return {"events": events, "status": "collected"}


def _collect_azure(hours: int) -> Dict[str, Any]:
    settings = get_settings()
    from ..collectors.azure_collector import AzureCollector

    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    collector = AzureCollector(
        tenant_id=settings.azure_tenant_id,
        client_id=settings.azure_client_id,
        client_secret=settings.azure_client_secret,
        subscription_id=settings.azure_subscription_id,
    )

    events = [
        collector.parse_event_to_security_event(raw, "activity_log").to_dict()
        for raw in collector.collect_activity_logs(start, datetime.now(timezone.utc))
    ]
    events += [
        collector.parse_event_to_security_event(raw, "security_alert").to_dict()
        for raw in collector.get_security_alerts()
    ]
    return {"events": events, "status": "collected"}


_COLLECTORS = {"aws": _collect_aws, "azure": _collect_azure}


def _run_collection(sources: List[str], hours: int, request_id: Optional[str] = None) -> Dict[str, Any]:
    settings = get_settings()
    store = get_store()
    results: Dict[str, Dict[str, Any]] = {}
    collected_events: List[Dict[str, Any]] = []

    for source in sources:
        if source not in _COLLECTORS:
            results[source] = {"events": 0, "status": "unsupported"}
            continue
        if source == "aws" and not settings.aws_configured:
            results[source] = {"events": 0, "status": "skipped", "reason": "AWS credentials not configured"}
            continue
        if source == "azure" and not settings.azure_configured:
            results[source] = {"events": 0, "status": "skipped", "reason": "Azure credentials not configured"}
            continue

        try:
            outcome = _COLLECTORS[source](hours)
        except Exception as exc:
            logger.error(
                "collection failed",
                source=source,
                error=str(exc),
                request_id=request_id,
            )
            # Do not leak credential/endpoint details to the client
            results[source] = {"events": 0, "status": "error", "reason": "Collection failed; see server logs"}
            continue

        events = outcome["events"]
        collected_events.extend(events)
        results[source] = {"events": len(events), "status": outcome["status"]}

    stored = store.add_events(collected_events)

    # One alert per high/critical event, deduplicated against open alerts from the last hour
    alerts = [
        {
            "message": event.get("message", "Security event"),
            "severity": event["severity"],
            "rule": "collected-event",
        }
        for event in collected_events
        if event.get("severity") in ("critical", "high")
    ]
    if alerts:
        store.add_alerts(alerts, dedupe_minutes=60)

    logger.info("collection complete", stored=stored, sources=results, request_id=request_id)
    return {
        "status": "collection_complete",
        "stored": stored,
        "results": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _iso_utc(value: Optional[datetime]) -> Optional[str]:
    """Normalize query datetimes to UTC ISO strings so they compare correctly in SQLite"""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


@router.post("/events/collect", response_model=CollectionResponse, tags=["Events"])
async def collect_events(
    request: Request,
    sources: List[str] = Query(default=["aws", "azure"]),
    hours: int = Query(default=1, ge=1, le=168),
):
    """Collect events from the configured cloud sources and persist them"""
    return await run_in_threadpool(
        _run_collection, sources, hours, getattr(request.state, "request_id", None)
    )


@router.get("/events", response_model=EventListResponse, tags=["Events"])
async def get_events(
    severity: Optional[Severity] = None,
    source: Optional[str] = Query(default=None, max_length=100),
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """Get collected security events with optional filters"""
    total, events = get_store().query_events(
        severity,
        source,
        limit,
        offset,
        _iso_utc(since),
        _iso_utc(until),
    )
    return {"total": total, "offset": offset, "limit": limit, "events": events}


# ── Threat Intelligence ────────────────────────────────────────

def _enrich(ioc: IOCRequest) -> Dict[str, Any]:
    engine = get_ti_engine()
    if ioc.type == "ip":
        return engine.enrich_ip(ioc.value)
    if ioc.type == "hash":
        return engine.lookup_hash_virustotal(ioc.value)
    return engine.lookup_domain_virustotal(ioc.value)


def _require_threat_intel_config() -> None:
    if not get_settings().threat_intel_configured:
        raise HTTPException(
            status_code=503,
            detail=(
                "No threat-intelligence API keys configured. "
                "Set VT_API_KEY, SHODAN_API_KEY or ABUSEIPDB_API_KEY."
            ),
        )


@router.post("/threat-intel/enrich", tags=["Threat Intelligence"])
async def enrich_ioc(request: IOCRequest):
    """
    Enrich a single IOC using VirusTotal, Shodan, and AbuseIPDB

    Supported types: ip, hash, domain
    """
    _require_threat_intel_config()
    return await run_in_threadpool(_enrich, request)


@router.post("/threat-intel/enrich/batch", tags=["Threat Intelligence"])
async def enrich_iocs_batch(request: BatchIOCRequest):
    """Enrich multiple IOCs in batch (max 50)"""
    _require_threat_intel_config()
    results = await run_in_threadpool(lambda: [_enrich(ioc) for ioc in request.iocs])
    return {
        "total": len(results),
        "results": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/threat-intel/ioc/{ioc_type}/{ioc_value}", tags=["Threat Intelligence"])
async def lookup_ioc(ioc_type: IOCType, ioc_value: str):
    """Look up a specific IOC by type and value"""
    _require_threat_intel_config()
    return await run_in_threadpool(_enrich, IOCRequest(type=ioc_type, value=ioc_value))


# ── Compliance ──────────────────────────────────────────────────

@router.post(
    "/compliance/assess",
    response_model=ComplianceReportResponse,
    tags=["Compliance"],
)
async def run_compliance_assessment(request: ComplianceAssessmentRequest):
    """Run a compliance assessment against NIST 800-53 controls"""
    engine = get_compliance_engine()
    report = await run_in_threadpool(
        engine.run_assessment,
        request.aws_data,
        request.azure_data,
        request.control_ids,
    )
    report["data_sources"] = {
        "aws": bool(request.aws_data),
        "azure": bool(request.azure_data),
    }
    get_store().add_report(report)
    return report


@router.get(
    "/compliance/summary",
    response_model=ComplianceSummaryResponse,
    tags=["Compliance"],
)
async def get_compliance_summary():
    """Get latest compliance summary"""
    latest = get_store().latest_report()
    if not latest:
        return {
            "message": "No assessments run yet",
            "action": "POST /api/v1/compliance/assess to run one",
        }
    return {
        "framework": latest.get("framework"),
        "assessment_date": latest.get("assessment_date"),
        "compliance_score": latest.get("compliance_score"),
        "total_controls": latest.get("total_controls"),
        "status_summary": latest.get("status_summary"),
        "data_sources": latest.get("data_sources"),
    }


@router.get("/compliance/controls", tags=["Compliance"])
async def list_controls(
    family: Optional[str] = None,
    status: Optional[ControlStatus] = None,
):
    """List compliance controls with optional filters"""
    controls = list(get_compliance_engine().controls.values())

    if family:
        controls = [c for c in controls if c.family.lower() == family.lower()]
    if status:
        controls = [c for c in controls if c.status.value == status.lower()]

    return {"total": len(controls), "controls": [c.to_dict() for c in controls]}


@router.get("/compliance/reports", tags=["Compliance"])
async def get_compliance_reports(limit: int = Query(default=10, ge=1, le=50)):
    """Get historical compliance reports"""
    total, reports = get_store().query_reports(limit)
    return {"total": total, "reports": reports}


@router.get(
    "/compliance/report/latest",
    response_model=ComplianceReportResponse,
    tags=["Compliance"],
)
async def get_latest_compliance_report():
    """Get the most recent full compliance report, including every control"""
    report = get_store().latest_report()
    if not report:
        raise HTTPException(status_code=404, detail="No compliance assessments stored")
    return report


# ── Alerts ──────────────────────────────────────────────────────

@router.get("/alerts", response_model=AlertListResponse, tags=["Alerts"])
async def get_alerts(
    severity: Optional[Severity] = None,
    status: Optional[AlertStatus] = None,
    limit: int = Query(default=50, ge=1, le=500),
):
    """Get security alerts generated from collected events"""
    total, alerts = get_store().query_alerts(severity, status, limit)
    return {"total": total, "alerts": alerts}


@router.patch("/alerts/{alert_id}", response_model=AlertModel, tags=["Alerts"])
async def update_alert(alert_id: int, update: AlertUpdate):
    """Acknowledge or resolve an alert"""
    alert = get_store().update_alert_status(alert_id, update.status)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert


# ── MITRE ATT&CK ───────────────────────────────────────────────

@router.get("/mitre/tactics", response_model=TacticsResponse, tags=["MITRE ATT&CK"])
async def get_mitre_tactics():
    """Get MITRE ATT&CK tactics with mapped-event counts"""
    counts = get_store().tactic_counts()
    return {
        "tactics": [
            {
                "id": tactic_id,
                "name": info["name"],
                "description": info["description"],
                "events_mapped": counts.get(tactic_id, 0),
            }
            for tactic_id, info in TACTICS.items()
        ]
    }


@router.get(
    "/mitre/techniques/{tactic_id}",
    response_model=TechniquesResponse,
    tags=["MITRE ATT&CK"],
)
async def get_techniques_for_tactic(tactic_id: str):
    """Get techniques mapped to a given MITRE ATT&CK tactic"""
    if tactic_id not in TACTICS:
        raise HTTPException(status_code=404, detail=f"Unknown tactic: {tactic_id}")

    techniques: Dict[str, Dict[str, Any]] = {}
    for info in AWS_EVENT_TECHNIQUE_MAP.values():
        if info["tactic_id"] != tactic_id:
            continue
        techniques.setdefault(
            info["technique_id"],
            {"id": info["technique_id"], "name": info["technique_name"]},
        )
    return {"tactic_id": tactic_id, "techniques": list(techniques.values())}


@router.get("/mitre/report", response_model=MitreReportResponse, tags=["MITRE ATT&CK"])
async def get_mitre_report():
    """Generate an ATT&CK report (heatmap, top techniques, attack chains) from stored CloudTrail events"""
    mapper = MITREMapper()
    mapper.map_events_batch(get_store().cloudtrail_events())
    return mapper.generate_report()


# ── Error handling & server ────────────────────────────────────

app.include_router(router)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", None)
    logger.error(
        "unhandled error",
        path=request.url.path,
        error=str(exc),
        request_id=request_id,
        exc_info=True,
    )
    content: Dict[str, Any] = {"detail": "Internal server error"}
    if request_id:
        content["request_id"] = request_id
    return JSONResponse(status_code=500, content=content)


def start_server(host: str = "0.0.0.0", port: int = 8000):
    """Start the API server"""
    uvicorn.run("src.api.main:app", host=host, port=port)


if __name__ == "__main__":
    start_server()
