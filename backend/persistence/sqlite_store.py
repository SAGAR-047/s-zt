"""
SentinelCloud SQLite Persistence Store
=======================================
Persists events, detections, incidents, and audit records to SQLite.
Used in DEV and LAB modes so data survives restarts.

Tables:
    - events: raw telemetry events
    - detections: ML detection results
    - incidents: incident lifecycle records
    - audit_log: immutable audit trail
"""

import json
import sqlite3
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.config import settings

logger = logging.getLogger("sentinel.persistence.sqlite")


class SQLiteStore:
    """Thread-safe SQLite persistence for SentinelCloud state."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.sqlite_path
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self):
        """Create tables if they don't exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                correlation_id TEXT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'http',
                data_mode TEXT NOT NULL DEFAULT 'live',
                pod_name TEXT NOT NULL DEFAULT '',
                namespace TEXT NOT NULL DEFAULT '',
                syscall_name TEXT NOT NULL DEFAULT '',
                binary TEXT NOT NULL DEFAULT '',
                target TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL DEFAULT 0,
                protocol TEXT NOT NULL DEFAULT '',
                payload_size INTEGER NOT NULL DEFAULT 0,
                anomaly_score REAL,
                hmm_log_prob REAL,
                is_alert INTEGER NOT NULL DEFAULT 0,
                explanation TEXT NOT NULL DEFAULT '',
                feature_vector TEXT,
                params TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS detections (
                event_id TEXT PRIMARY KEY,
                correlation_id TEXT,
                timestamp TEXT NOT NULL,
                anomaly_score REAL NOT NULL,
                anomaly_threshold REAL NOT NULL,
                is_anomaly INTEGER NOT NULL DEFAULT 0,
                model_name TEXT NOT NULL DEFAULT 'HalfSpaceTrees',
                model_version TEXT NOT NULL DEFAULT '1.0',
                hmm_log_prob REAL,
                hmm_threshold REAL,
                is_sequence_anomaly INTEGER NOT NULL DEFAULT 0,
                feature_vector TEXT,
                feature_contributions TEXT,
                top_contributing_features TEXT,
                explanation TEXT NOT NULL DEFAULT '',
                confidence REAL NOT NULL DEFAULT 0.0,
                inference_latency_ms REAL NOT NULL DEFAULT 0.0,
                events_processed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                correlation_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                phase TEXT NOT NULL DEFAULT 'detected',
                severity TEXT NOT NULL DEFAULT 'MEDIUM',
                title TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                affected_pod TEXT NOT NULL DEFAULT '',
                affected_namespace TEXT NOT NULL DEFAULT 'medical',
                affected_service TEXT NOT NULL DEFAULT '',
                detection_json TEXT,
                diagnosis_json TEXT,
                actions_json TEXT,
                timeline_json TEXT,
                telemetry_events TEXT,
                detection_time TEXT,
                mitigation_start_time TEXT,
                mitigation_end_time TEXT,
                recovery_time TEXT,
                mttd_ms REAL,
                mttr_ms REAL,
                test_session_id TEXT,
                resolved INTEGER NOT NULL DEFAULT 0,
                resolution TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                audit_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT 'system',
                target TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS test_sessions (
                session_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                scenario TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                safety_profile TEXT NOT NULL DEFAULT 'standard',
                incidents TEXT,
                detection_time_ms REAL,
                details TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_events_pod ON events(pod_name);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_detections_anomaly ON detections(is_anomaly);
            CREATE INDEX IF NOT EXISTS idx_incidents_phase ON incidents(phase);
            CREATE INDEX IF NOT EXISTS idx_incidents_resolved ON incidents(resolved);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_test_sessions_status ON test_sessions(status);
        """)
        conn.commit()
        logger.info("SQLite database initialized at %s", self.db_path)

    # ── Events ──

    def save_event(self, event) -> None:
        """Persist a TelemetryEvent."""
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO events
            (event_id, correlation_id, timestamp, source, data_mode, pod_name,
             namespace, syscall_name, binary, target, port, protocol,
             payload_size, anomaly_score, hmm_log_prob, is_alert, explanation,
             feature_vector, params)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.event_id,
            event.correlation_id,
            event.timestamp.isoformat(),
            event.source.value if hasattr(event.source, 'value') else str(event.source),
            event.data_mode.value if hasattr(event.data_mode, 'value') else str(event.data_mode),
            event.pod_name,
            event.namespace,
            event.syscall_name,
            event.binary,
            event.target,
            event.port,
            event.protocol,
            event.payload_size,
            event.anomaly_score,
            event.hmm_log_prob,
            1 if event.is_alert else 0,
            event.explanation,
            json.dumps(event.feature_vector) if event.feature_vector else None,
            json.dumps(event.params) if event.params else None,
        ))
        conn.commit()

    def get_recent_events(self, limit: int = 50, pod_name: Optional[str] = None) -> list[dict]:
        """Retrieve recent events from SQLite."""
        conn = self._get_conn()
        if pod_name:
            rows = conn.execute(
                "SELECT * FROM events WHERE pod_name = ? ORDER BY timestamp DESC LIMIT ?",
                (pod_name, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_event_count(self) -> int:
        """Total event count."""
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return row[0] if row else 0

    # ── Detections ──

    def save_detection(self, detection) -> None:
        """Persist a DetectionResult."""
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO detections
            (event_id, correlation_id, timestamp, anomaly_score, anomaly_threshold,
             is_anomaly, model_name, model_version, hmm_log_prob, hmm_threshold,
             is_sequence_anomaly, feature_vector, feature_contributions,
             top_contributing_features, explanation, confidence,
             inference_latency_ms, events_processed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            detection.event_id,
            detection.correlation_id,
            detection.timestamp.isoformat(),
            detection.anomaly_score,
            detection.anomaly_threshold,
            1 if detection.is_anomaly else 0,
            detection.model_name,
            detection.model_version,
            detection.hmm_log_prob,
            detection.hmm_threshold,
            1 if detection.is_sequence_anomaly else 0,
            json.dumps(detection.feature_vector) if detection.feature_vector else None,
            json.dumps(detection.feature_contributions) if detection.feature_contributions else None,
            json.dumps(detection.top_contributing_features) if detection.top_contributing_features else None,
            detection.explanation,
            detection.confidence,
            detection.inference_latency_ms,
            detection.events_processed,
        ))
        conn.commit()

    def get_recent_detections(self, limit: int = 20, anomalies_only: bool = False) -> list[dict]:
        """Retrieve recent detections."""
        conn = self._get_conn()
        if anomalies_only:
            rows = conn.execute(
                "SELECT * FROM detections WHERE is_anomaly = 1 ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM detections ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Incidents ──

    def save_incident(self, incident) -> None:
        """Persist an Incident (full JSON serialization for complex fields)."""
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO incidents
            (incident_id, correlation_id, created_at, updated_at, phase, severity,
             title, description, affected_pod, affected_namespace, affected_service,
             detection_json, diagnosis_json, actions_json, timeline_json,
             telemetry_events, detection_time, mitigation_start_time,
             mitigation_end_time, recovery_time, mttd_ms, mttr_ms,
             test_session_id, resolved, resolution)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident.incident_id,
            incident.correlation_id,
            incident.created_at.isoformat(),
            incident.updated_at.isoformat(),
            incident.phase.value if hasattr(incident.phase, 'value') else str(incident.phase),
            incident.severity.value if hasattr(incident.severity, 'value') else str(incident.severity),
            incident.title,
            incident.description,
            incident.affected_pod,
            incident.affected_namespace,
            incident.affected_service,
            incident.detection.model_dump_json() if incident.detection else None,
            incident.diagnosis.model_dump_json() if incident.diagnosis else None,
            json.dumps([a.model_dump(mode="json") for a in incident.actions]) if incident.actions else "[]",
            json.dumps([t.model_dump(mode="json") for t in incident.timeline]) if incident.timeline else "[]",
            json.dumps(incident.telemetry_events),
            incident.detection_time.isoformat() if incident.detection_time else None,
            incident.mitigation_start_time.isoformat() if incident.mitigation_start_time else None,
            incident.mitigation_end_time.isoformat() if incident.mitigation_end_time else None,
            incident.recovery_time.isoformat() if incident.recovery_time else None,
            incident.mttd_ms,
            incident.mttr_ms,
            incident.test_session_id,
            1 if incident.resolved else 0,
            incident.resolution,
        ))
        conn.commit()

    def get_all_incidents(self, limit: int = 50, resolved: Optional[bool] = None) -> list[dict]:
        """Retrieve incidents."""
        conn = self._get_conn()
        if resolved is not None:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE resolved = ? ORDER BY created_at DESC LIMIT ?",
                (1 if resolved else 0, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_incident(self, incident_id: str) -> Optional[dict]:
        """Get a single incident."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        return dict(row) if row else None

    # ── Audit ──

    def save_audit_record(self, record) -> None:
        """Persist an AuditRecord."""
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO audit_log
            (audit_id, timestamp, action, actor, target, detail, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            record.audit_id,
            record.timestamp.isoformat(),
            record.action,
            record.actor,
            record.target,
            record.detail,
            json.dumps(record.metadata) if record.metadata else None,
        ))
        conn.commit()

    def get_audit_trail(self, limit: int = 100) -> list[dict]:
        """Retrieve audit trail."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Test Sessions / Experiments ──

    def save_test_session(self, session) -> None:
        """Persist a TestSession."""
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO test_sessions
            (session_id, created_at, scenario, target, status, safety_profile,
             incidents, detection_time_ms, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session.session_id,
            session.created_at.isoformat() if hasattr(session.created_at, 'isoformat') else str(session.created_at),
            session.scenario,
            session.target,
            session.status,
            session.safety_profile,
            json.dumps(session.incidents) if session.incidents else None,
            session.detection_time_ms,
            json.dumps(getattr(session, 'details', {})) if getattr(session, 'details', None) else None,
        ))
        conn.commit()

    def update_test_session(self, session_id: str, status: str, details: Optional[dict] = None) -> None:
        """Update test session status and details."""
        conn = self._get_conn()
        conn.execute("""
            UPDATE test_sessions
            SET status = ?, details = coalesce(?, details)
            WHERE session_id = ?
        """, (
            status,
            json.dumps(details) if details else None,
            session_id,
        ))
        conn.commit()

    def get_test_sessions(self, limit: int = 50) -> list[dict]:
        """Retrieve recent test sessions."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM test_sessions ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("incidents"):
                try:
                    d["incidents"] = json.loads(d["incidents"])
                except Exception:
                    pass
            if d.get("details"):
                try:
                    d["details"] = json.loads(d["details"])
                except Exception:
                    pass
            result.append(d)
        return result

    # ── Statistics ──

    def get_stats(self) -> dict:
        """Get aggregate statistics from the database."""
        conn = self._get_conn()
        return {
            "total_events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "total_detections": conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0],
            "total_anomalies": conn.execute("SELECT COUNT(*) FROM detections WHERE is_anomaly = 1").fetchone()[0],
            "total_incidents": conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
            "resolved_incidents": conn.execute("SELECT COUNT(*) FROM incidents WHERE resolved = 1").fetchone()[0],
            "total_audit_records": conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
        }

    def close(self):
        """Close the thread-local connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Singleton
sqlite_store = SQLiteStore()
