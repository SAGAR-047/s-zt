"""
SentinelCloud ClickHouse Client
================================
Read/write wrapper for ClickHouse event storage.
Only active when SENTINEL_CLICKHOUSE_ENABLED=true.
"""

import json
import logging
from typing import Optional

from backend.config import settings

logger = logging.getLogger("sentinel.integrations.clickhouse")


class ClickHouseClient:
    """Lazy-initialized ClickHouse client."""

    def __init__(self):
        self._client = None
        self._initialized = False

    def _init(self):
        if self._initialized or not settings.clickhouse_enabled:
            return
        try:
            from clickhouse_driver import Client
            self._client = Client(
                host=settings.clickhouse_host,
                port=settings.clickhouse_port,
                database=settings.clickhouse_db,
            )
            # Verify connection
            self._client.execute("SELECT 1")
            self._initialized = True
            self._ensure_tables()
            logger.info("ClickHouse connected at %s:%d/%s",
                        settings.clickhouse_host, settings.clickhouse_port, settings.clickhouse_db)
        except ImportError:
            logger.warning("clickhouse-driver not installed")
        except Exception as e:
            logger.warning("ClickHouse connection failed: %s", e)

    def _ensure_tables(self):
        """Create ClickHouse tables if they don't exist."""
        if not self._client:
            return
        try:
            self._client.execute("""
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    event_id String,
                    correlation_id Nullable(String),
                    timestamp DateTime64(3),
                    source String,
                    data_mode String,
                    pod_name String,
                    namespace String,
                    syscall_name String,
                    binary String,
                    target String,
                    port UInt16,
                    protocol String,
                    payload_size UInt32,
                    anomaly_score Nullable(Float64),
                    is_alert UInt8
                ) ENGINE = MergeTree()
                ORDER BY (timestamp, pod_name)
                TTL timestamp + INTERVAL 30 DAY
            """)

            self._client.execute("""
                CREATE TABLE IF NOT EXISTS detection_results (
                    event_id String,
                    timestamp DateTime64(3),
                    anomaly_score Float64,
                    anomaly_threshold Float64,
                    is_anomaly UInt8,
                    model_name String,
                    explanation String,
                    confidence Float64,
                    inference_latency_ms Float64
                ) ENGINE = MergeTree()
                ORDER BY (timestamp, is_anomaly)
                TTL timestamp + INTERVAL 30 DAY
            """)
            logger.info("ClickHouse tables ensured")
        except Exception as e:
            logger.error("Failed to create ClickHouse tables: %s", e)

    @property
    def available(self) -> bool:
        if not settings.clickhouse_enabled:
            return False
        self._init()
        return self._initialized

    def health_check(self) -> bool:
        """Check ClickHouse connectivity."""
        self._init()
        if not self._client:
            return False
        try:
            self._client.execute("SELECT 1")
            return True
        except Exception:
            return False

    def insert_event(self, event) -> bool:
        """Insert a telemetry event into ClickHouse."""
        self._init()
        if not self._client:
            return False
        try:
            self._client.execute(
                "INSERT INTO telemetry_events VALUES",
                [{
                    "event_id": event.event_id,
                    "correlation_id": event.correlation_id,
                    "timestamp": event.timestamp,
                    "source": event.source.value if hasattr(event.source, 'value') else str(event.source),
                    "data_mode": event.data_mode.value if hasattr(event.data_mode, 'value') else str(event.data_mode),
                    "pod_name": event.pod_name,
                    "namespace": event.namespace,
                    "syscall_name": event.syscall_name,
                    "binary": event.binary,
                    "target": event.target,
                    "port": event.port,
                    "protocol": event.protocol,
                    "payload_size": event.payload_size,
                    "anomaly_score": event.anomaly_score,
                    "is_alert": 1 if event.is_alert else 0,
                }]
            )
            return True
        except Exception as e:
            logger.error("ClickHouse insert failed: %s", e)
            return False

    def insert_detection(self, detection) -> bool:
        """Insert a detection result into ClickHouse."""
        self._init()
        if not self._client:
            return False
        try:
            self._client.execute(
                "INSERT INTO detection_results VALUES",
                [{
                    "event_id": detection.event_id,
                    "timestamp": detection.timestamp,
                    "anomaly_score": detection.anomaly_score,
                    "anomaly_threshold": detection.anomaly_threshold,
                    "is_anomaly": 1 if detection.is_anomaly else 0,
                    "model_name": detection.model_name,
                    "explanation": detection.explanation,
                    "confidence": detection.confidence,
                    "inference_latency_ms": detection.inference_latency_ms,
                }]
            )
            return True
        except Exception as e:
            logger.error("ClickHouse detection insert failed: %s", e)
            return False

    def query_recent_events(self, pod_name: Optional[str] = None,
                            limit: int = 50) -> list[dict]:
        """Query recent events from ClickHouse."""
        self._init()
        if not self._client:
            return []
        try:
            if pod_name:
                rows = self._client.execute(
                    "SELECT * FROM telemetry_events WHERE pod_name = %(pod)s "
                    "ORDER BY timestamp DESC LIMIT %(limit)s",
                    {"pod": pod_name, "limit": limit}
                )
            else:
                rows = self._client.execute(
                    "SELECT * FROM telemetry_events ORDER BY timestamp DESC LIMIT %(limit)s",
                    {"limit": limit}
                )
            return rows
        except Exception as e:
            logger.error("ClickHouse query failed: %s", e)
            return []

    def close(self):
        if self._client:
            self._client.disconnect()
            self._client = None
            self._initialized = False


# Singleton
clickhouse_client = ClickHouseClient()
