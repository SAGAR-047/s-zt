"""
SentinelCloud Event Schema
==========================
Unified event schema used throughout the pipeline.
Every event gets a correlation ID, timestamps, and provenance metadata.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


# ── Enums ──

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TelemetrySource(str, Enum):
    TETRAGON = "tetragon"
    FALCO = "falco"
    EBPF_PROBE = "ebpf_probe"
    HTTP_INGESTION = "http"
    LAB_TEST = "lab_test"
    REPLAY = "replay"


class DataMode(str, Enum):
    LIVE = "live"
    REPLAY = "replay"
    LAB_TEST = "lab_test"


class ServiceStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    QUARANTINED = "quarantined"
    REDEPLOYING = "redeploying"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class ServiceCriticality(str, Enum):
    CRITICAL = "critical"
    IMPORTANT = "important"
    NON_CRITICAL = "non_critical"


class IncidentPhase(str, Enum):
    DETECTED = "detected"
    ANALYZING = "analyzing"
    DIAGNOSED = "diagnosed"
    MITIGATING = "mitigating"
    RECOVERING = "recovering"
    RECOVERED = "recovered"
    FAILED = "failed"
    MANUAL_REVIEW = "manual_review"


class ComponentHealth(str, Enum):
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


# ── Core Event Models ──

class TelemetryEvent(BaseModel):
    """Raw or normalized telemetry event from eBPF/Tetragon/Falco."""
    event_id: str = Field(default_factory=_new_id)
    correlation_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=_utcnow)
    source: TelemetrySource = TelemetrySource.HTTP_INGESTION
    data_mode: DataMode = DataMode.LIVE

    # Process context
    node: str = ""
    namespace: str = ""
    pod_name: str = ""
    container: str = ""
    pid: int = 0
    uid: int = 0
    comm: str = ""

    # Syscall / event
    syscall_name: str = ""
    binary: str = ""
    target: str = ""
    port: int = 0
    protocol: str = ""
    payload_size: int = 0

    # Enrichment (filled by pipeline)
    anomaly_score: Optional[float] = None
    hmm_log_prob: Optional[float] = None
    is_alert: bool = False
    explanation: str = ""
    feature_vector: Optional[dict[str, float]] = None

    # Extra params
    params: dict[str, Any] = Field(default_factory=dict)

    # Benchmark dataset provenance
    dataset_source: str = "ADFA-LD & MIMIC-III Benchmark"
    record_id: Optional[str] = None
    benchmark_ref: Optional[str] = None


class DetectionResult(BaseModel):
    """Output from the ML detection pipeline."""
    event_id: str
    correlation_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=_utcnow)

    # Anomaly detection
    anomaly_score: float
    anomaly_threshold: float
    is_anomaly: bool
    model_name: str = "HalfSpaceTrees"
    model_version: str = "1.0"

    # Sequence detection
    hmm_log_prob: Optional[float] = None
    hmm_threshold: Optional[float] = None
    is_sequence_anomaly: bool = False

    # Feature info
    feature_vector: dict[str, float] = Field(default_factory=dict)
    feature_contributions: dict[str, float] = Field(default_factory=dict)
    top_contributing_features: list[str] = Field(default_factory=list)

    # Explanation
    explanation: str = ""
    confidence: float = 0.0

    # Timing
    inference_latency_ms: float = 0.0
    events_processed: int = 0


class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str
    evidence: str
    confidence: float
    observed_at: datetime = Field(default_factory=_utcnow)


class DiagnosisResult(BaseModel):
    """Output from the diagnosis engine."""
    diagnosis_id: str = Field(default_factory=_new_id)
    correlation_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=_utcnow)

    pod_name: str
    namespace: str

    root_cause: str  # compromise, dependency_failure, network_partition, unknown
    confidence: float
    evidence: list[str] = Field(default_factory=list)
    conflicting_evidence: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)

    # MITRE ATT&CK
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)

    # Scores breakdown
    scores: dict[str, float] = Field(default_factory=dict)
    events_analyzed: int = 0
    recommended_action: str = "manual_investigation"


class MitigationAction(BaseModel):
    """A remediation action taken by MAPE-K."""
    action_id: str = Field(default_factory=_new_id)
    correlation_id: Optional[str] = None
    incident_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=_utcnow)

    # MAPE-K phase tracking
    phase: str = "plan"  # monitor, analyze, plan, execute, knowledge
    action_type: str  # quarantine, failover, redeploy, restart_dependency
    pod_name: str
    namespace: str = "medical"

    # Decision context
    root_cause: str
    is_critical_service: bool = False
    confidence: float = 0.0

    # Execution
    status: str = "pending"  # pending, executing, completed, failed, aborted
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    error: Optional[str] = None

    # What was done
    details: str = ""
    cilium_policy_applied: Optional[str] = None
    pod_deleted: bool = False
    pod_restarted: bool = False
    replicas_scaled: Optional[int] = None

    # Verification
    health_verified: bool = False
    service_restored: bool = False


class IncidentTimelineEntry(BaseModel):
    timestamp: datetime = Field(default_factory=_utcnow)
    phase: str
    title: str
    detail: str = ""
    source_service: str = ""
    target_service: str = ""
    duration_ms: Optional[float] = None
    evidence: Optional[str] = None
    correlation_id: Optional[str] = None


class Incident(BaseModel):
    """Full incident lifecycle tracking."""
    incident_id: str = Field(default_factory=lambda: f"SC-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:5].upper()}")
    correlation_id: str = Field(default_factory=_new_id)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    # Classification
    phase: IncidentPhase = IncidentPhase.DETECTED
    severity: Severity = Severity.MEDIUM
    title: str = ""
    description: str = ""

    # Affected
    affected_pod: str = ""
    affected_namespace: str = "medical"
    affected_service: str = ""

    # Timeline entries
    timeline: list[IncidentTimelineEntry] = Field(default_factory=list)

    # Linked data
    detection: Optional[DetectionResult] = None
    diagnosis: Optional[DiagnosisResult] = None
    actions: list[MitigationAction] = Field(default_factory=list)
    telemetry_events: list[str] = Field(default_factory=list)  # event_ids

    # Metrics
    detection_time: Optional[datetime] = None
    mitigation_start_time: Optional[datetime] = None
    mitigation_end_time: Optional[datetime] = None
    recovery_time: Optional[datetime] = None
    mttd_ms: Optional[float] = None  # detection_time - first_event_time
    mttr_ms: Optional[float] = None  # recovery_time - detection_time

    # Test session link
    test_session_id: Optional[str] = None

    # Final state
    resolved: bool = False
    resolution: str = ""


class AuditRecord(BaseModel):
    """Immutable audit trail entry."""
    audit_id: str = Field(default_factory=_new_id)
    timestamp: datetime = Field(default_factory=_utcnow)
    action: str  # login, policy_change, incident_created, alert, mitigation, etc.
    actor: str = "system"
    target: str = ""
    detail: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class TestSession(BaseModel):
    """Authorized lab test session."""
    session_id: str = Field(default_factory=lambda: f"TEST-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}")
    created_at: datetime = Field(default_factory=_utcnow)
    scenario: str
    target: str
    status: str = "pending"  # pending, running, completed, failed
    safety_profile: str = "standard"

    # Results
    incidents: list[str] = Field(default_factory=list)  # incident_ids
    detection_time_ms: Optional[float] = None
    mitigation_time_ms: Optional[float] = None
    recovery_time_ms: Optional[float] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class SystemHealthStatus(BaseModel):
    """Health status of the SentinelCloud platform itself."""
    timestamp: datetime = Field(default_factory=_utcnow)
    mode: str = "dev"

    backend: ComponentHealth = ComponentHealth.ONLINE
    kafka: ComponentHealth = ComponentHealth.UNKNOWN
    clickhouse: ComponentHealth = ComponentHealth.UNKNOWN
    tetragon: ComponentHealth = ComponentHealth.UNKNOWN
    falco: ComponentHealth = ComponentHealth.UNKNOWN
    cilium: ComponentHealth = ComponentHealth.UNKNOWN
    anomaly_detector: ComponentHealth = ComponentHealth.UNKNOWN
    diagnosis_service: ComponentHealth = ComponentHealth.UNKNOWN
    mape_k_controller: ComponentHealth = ComponentHealth.UNKNOWN
    kubernetes_api: ComponentHealth = ComponentHealth.UNKNOWN
    prometheus: ComponentHealth = ComponentHealth.UNKNOWN

    # Medical services
    vitals: ComponentHealth = ComponentHealth.UNKNOWN
    drug_dispenser: ComponentHealth = ComponentHealth.UNKNOWN
    ehr: ComponentHealth = ComponentHealth.UNKNOWN
    billing: ComponentHealth = ComponentHealth.UNKNOWN


class ServiceInfo(BaseModel):
    """Real service information — no fake data."""
    name: str
    display_name: str
    port: int
    status: ServiceStatus = ServiceStatus.UNKNOWN
    criticality: ServiceCriticality = ServiceCriticality.NON_CRITICAL
    health_checked_at: Optional[datetime] = None

    # Real metrics (None = not measured yet)
    uptime_seconds: Optional[float] = None
    request_count: Optional[int] = None
    error_count: Optional[int] = None
    avg_latency_ms: Optional[float] = None

    # K8s metadata
    pod_count: Optional[int] = None
    ready_pods: Optional[int] = None
    restart_count: Optional[int] = None
    image: Optional[str] = None
    namespace: str = "medical"

    # Live Kernel & Operational Execution Context
    last_syscall: Optional[str] = None
    last_binary: Optional[str] = None
    last_target: Optional[str] = None
    last_anomaly_score: Optional[float] = None
    last_activity_type: Optional[str] = None
    last_activity_desc: Optional[str] = None
    active_threat: Optional[str] = None
    mapek_phase: Optional[str] = None
    last_event_time: Optional[datetime] = None
