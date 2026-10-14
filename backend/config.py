"""
SentinelCloud-Advanced Backend Configuration
=============================================
All configuration from environment variables with sensible defaults.
Supports three operating modes: LIVE, LAB, DEV.
"""

import os
from enum import Enum
from pydantic_settings import BaseSettings
from pydantic import Field


class OperatingMode(str, Enum):
    LIVE = "live"    # Full K8s cluster with all infrastructure
    LAB = "lab"      # Docker Compose local lab
    DEV = "dev"      # Single machine development


class Settings(BaseSettings):
    """Central configuration loaded from environment variables."""

    # ── Operating Mode ──
    mode: OperatingMode = Field(
        default=OperatingMode.DEV,
        description="Operating mode: live (K8s), lab (Docker Compose), dev (local)"
    )

    # ── Server ──
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=5050)
    debug: bool = Field(default=False)
    secret_key: str = Field(
        default="CHANGE-ME-IN-PRODUCTION-use-openssl-rand-hex-32",
        description="JWT signing secret. MUST be changed in production."
    )
    jwt_algorithm: str = Field(default="HS256")
    jwt_expiry_hours: int = Field(default=24)

    # ── CORS ──
    cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:5050",
        description="Comma-separated list of allowed CORS origins"
    )

    # ── Kafka ──
    kafka_bootstrap: str = Field(default="localhost:9092")
    kafka_topic_raw: str = Field(default="sentinel.telemetry.raw")
    kafka_topic_normalized: str = Field(default="sentinel.telemetry.normalized")
    kafka_topic_detections: str = Field(default="sentinel.detections")
    kafka_topic_diagnoses: str = Field(default="sentinel.diagnoses")
    kafka_topic_actions: str = Field(default="sentinel.actions")
    kafka_topic_audit: str = Field(default="sentinel.audit")
    kafka_group_id: str = Field(default="sentinel-backend")
    kafka_enabled: bool = Field(default=False)

    # ── ClickHouse ──
    clickhouse_host: str = Field(default="localhost")
    clickhouse_port: int = Field(default=9000)
    clickhouse_db: str = Field(default="sentinel")
    clickhouse_enabled: bool = Field(default=False)

    # ── Kubernetes ──
    kubernetes_enabled: bool = Field(default=False)
    kubernetes_namespace_medical: str = Field(default="medical")
    kubernetes_namespace_sentinel: str = Field(default="sentinel")

    # ── Medical Services ──
    vitals_url: str = Field(default="http://localhost:5000")
    drug_dispenser_url: str = Field(default="http://localhost:5001")
    ehr_url: str = Field(default="http://localhost:5002")
    billing_url: str = Field(default="http://localhost:5003")

    # ── Intelligence Services ──
    anomaly_detector_url: str = Field(default="http://localhost:8080")
    diagnosis_service_url: str = Field(default="http://localhost:8081")
    detector_enabled: bool = Field(default=True, description="Use external detector service")
    diagnosis_enabled: bool = Field(default=True, description="Use external diagnosis service")

    # ── MAPE-K Controller ──
    mape_k_controller_url: str = Field(default="http://localhost:8083")
    mape_k_enabled: bool = Field(default=False, description="Use external MAPE-K controller")

    # ── ML Thresholds ──
    anomaly_threshold: float = Field(default=0.72)
    hmm_threshold: float = Field(default=-5.0)
    hmm_window_size: int = Field(default=10)

    # ── Persistence ──
    sqlite_path: str = Field(default="./data/sentinel.db")

    # ── Tetragon ──
    tetragon_enabled: bool = Field(default=False)

    # ── Prometheus ──
    prometheus_enabled: bool = Field(default=True)

    model_config = {"env_prefix": "SENTINEL_", "env_file": ".env", "extra": "ignore"}

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_live(self) -> bool:
        return self.mode == OperatingMode.LIVE

    @property
    def is_lab(self) -> bool:
        return self.mode == OperatingMode.LAB

    @property
    def is_dev(self) -> bool:
        return self.mode == OperatingMode.DEV


settings = Settings()
