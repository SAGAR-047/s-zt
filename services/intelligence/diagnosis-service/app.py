"""
SentinelCloud-Advanced: Diagnosis Service
-------------------------------------------
Causal root-cause diagnosis REST API.
Adds MITRE ATT&CK mapping and in-memory fallback for ClickHouse.
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from collections import deque
from flask import Flask, jsonify, request
from clickhouse_driver import Client as CHClient

# Configuration
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse.sentinel.svc.cluster.local")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "9000"))
CLICKHOUSE_DB = os.environ.get("CLICKHOUSE_DB", "sentinel")
PORT = int(os.environ.get("PORT", "8081"))
LOOKBACK_SECONDS = int(os.environ.get("LOOKBACK_SECONDS", "60"))
ENABLE_IN_MEMORY_FALLBACK = os.environ.get("ENABLE_IN_MEMORY_FALLBACK", "true").lower() == "true"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("diagnosis-service")
app = Flask(__name__)

# In-memory buffer for fallback (stores recent events)
memory_events = deque(maxlen=1000)

# ---------------------------------------------------------------------------
# Event Querier with fallback
# ---------------------------------------------------------------------------
class EventQuerier:
    def __init__(self):
        self._client = None

    def _connect(self):
        try:
            self._client = CHClient(host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, database=CLICKHOUSE_DB)
        except Exception as e:
            logger.error("ClickHouse connection failed: %s", e)
            self._client = None

    def is_available(self):
        if not self._client:
            self._connect()
        return self._client is not None

    def get_recent_events(self, pod_name, namespace, seconds=60):
        # Try ClickHouse first
        if self._client is None:
            self._connect()
        if self._client:
            since = datetime.now(timezone.utc) - timedelta(seconds=seconds)
            try:
                rows = self._client.execute(
                    """
                    SELECT timestamp, syscall_name, params, anomaly_score
                    FROM events
                    WHERE pod_name = %(pod)s AND namespace = %(ns)s AND timestamp >= %(since)s
                    ORDER BY timestamp DESC LIMIT 500
                    """,
                    {"pod": pod_name, "ns": namespace, "since": since}
                )
                return [{"timestamp": str(r[0]), "syscall_name": r[1],
                         "params": json.loads(r[2]) if r[2] else {}, "anomaly_score": float(r[3])} for r in rows]
            except Exception as e:
                logger.error("ClickHouse query failed: %s", e)

        # Fallback to in-memory
        if ENABLE_IN_MEMORY_FALLBACK:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
            results = []
            for e in list(memory_events):
                if e.get("pod_name") == pod_name and e.get("namespace") == namespace:
                    try:
                        ts = datetime.fromisoformat(e.get("timestamp", ""))
                        if ts >= cutoff:
                            results.append(e)
                    except Exception:
                        results.append(e)
            return results
        return []

    def get_dependency_events(self, namespace, seconds=60):
        if self._client is None:
            self._connect()
        if self._client:
            since = datetime.now(timezone.utc) - timedelta(seconds=seconds)
            try:
                rows = self._client.execute(
                    """
                    SELECT pod_name, syscall_name, params, anomaly_score
                    FROM events WHERE namespace = %(ns)s AND timestamp >= %(since)s
                    ORDER BY timestamp DESC LIMIT 200
                    """,
                    {"ns": namespace, "since": since}
                )
                return [{"pod_name": r[0], "syscall_name": r[1],
                         "params": json.loads(r[2]) if r[2] else {}, "anomaly_score": float(r[3])} for r in rows]
            except Exception as e:
                logger.error("ClickHouse dependency query failed: %s", e)

        if ENABLE_IN_MEMORY_FALLBACK:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
            results = []
            for e in list(memory_events):
                if e.get("namespace") == namespace:
                    try:
                        ts = datetime.fromisoformat(e.get("timestamp", ""))
                        if ts >= cutoff:
                            results.append(e)
                    except Exception:
                        results.append(e)
            return results
        return []

querier = EventQuerier()

# ---------------------------------------------------------------------------
# MITRE ATT&CK Mapping
# ---------------------------------------------------------------------------
MITRE_MAP = {
    "shell_exec": {"technique_id": "T1059.004", "technique_name": "Command and Scripting Interpreter: Unix Shell"},
    "smb_lateral": {"technique_id": "T1021.002", "technique_name": "Remote Services: SMB/Windows Admin Shares"},
    "file_encrypt": {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"},
    "dns_exfil": {"technique_id": "T1071.004", "technique_name": "Application Layer Protocol: DNS"},
    "network_recon": {"technique_id": "T1046", "technique_name": "Network Service Discovery"},
    "behavioral_anomaly": {"technique_id": "T1204", "technique_name": "User Execution: Malicious Process"},
}

def diagnose_root_cause(pod_name, namespace, passed_events=None):
    if passed_events:
        events = passed_events
    else:
        events = querier.get_recent_events(pod_name, namespace, LOOKBACK_SECONDS)
    dep_events = querier.get_dependency_events(namespace, LOOKBACK_SECONDS)
    evidence = []
    scores = {"compromise": 0.0, "dependency_failure": 0.0, "network_partition": 0.0}
    mitre_techniques = []

    if not events:
        logger.warning("No events found for pod %s/%s", namespace, pod_name)
        return {
            "root_cause": "unknown",
            "confidence": 0.0,
            "evidence": ["No recent events found"],
            "recommended_action": "manual_investigation",
            "mitre_techniques": [],
            "scores": {},
            "events_analysed": 0,
        }

    for event in events:
        syscall = event.get("syscall_name", "")
        params = event.get("params", {})
        binary = event.get("binary", params.get("binary", params.get("path", "")))
        target = event.get("target", params.get("target", ""))
        port = int(event.get("port") or params.get("port", 0))
        anomaly_score = float(event.get("anomaly_score", 0.0))

        # Network Reconnaissance
        if ("nmap" in str(binary).lower() or "scan" in str(target).lower() or
            (syscall in ("sys_connect", "sys_socket") and port in (5000, 5001, 5002, 5003, 80, 443, 8080, 22, 21, 23)) or
            (syscall == "sys_connect" and anomaly_score >= 0.72)):
            scores["compromise"] += 4.0
            evidence.append(f"Network service reconnaissance scan targeting port {port}")
            mitre_techniques.append({**MITRE_MAP["network_recon"], "confidence": 0.88})

        # Shell execution
        if syscall == "sys_execve":
            if any(shell in str(binary) for shell in ["/bin/sh", "/bin/bash", "sh", "bash"]):
                scores["compromise"] += 3.0
                evidence.append(f"Shell execution detected: {binary}")
                mitre_techniques.append({**MITRE_MAP["shell_exec"], "confidence": 0.8})

        # Ransomware file rename
        if syscall == "sys_rename":
            for ext in [".locked", ".encrypted", ".crypto", ".ransom"]:
                if str(target).endswith(ext):
                    scores["compromise"] += 5.0
                    evidence.append(f"Suspicious file rename: {target}")
                    mitre_techniques.append({**MITRE_MAP["file_encrypt"], "confidence": 0.9})
                    break

        # SMB Lateral
        if syscall == "sys_connect":
            if port == 445:
                scores["compromise"] += 4.0
                evidence.append("Connection to SMB port 445")
                mitre_techniques.append({**MITRE_MAP["smb_lateral"], "confidence": 0.85})
            errno = params.get("errno", "")
            if "ECONNREFUSED" in str(errno) or "ETIMEDOUT" in str(errno):
                scores["network_partition"] += 2.0
                evidence.append(f"Connection failed: {errno}")

        # ML Anomaly fallback
        if anomaly_score >= 0.72 and not mitre_techniques:
            scores["compromise"] += 2.5
            evidence.append(f"Statistical anomaly score {anomaly_score:.3f} on {syscall}")
            mitre_techniques.append({**MITRE_MAP["behavioral_anomaly"], "confidence": min(0.9, anomaly_score)})

    other_pod_anomalies = [e for e in dep_events if e.get("pod_name") != pod_name and e.get("anomaly_score", 0.0) > 0.5]
    if other_pod_anomalies:
        scores["dependency_failure"] += len(other_pod_anomalies) * 0.5
        evidence.append(f"{len(other_pod_anomalies)} anomalous events from dependency pods")

    max_cause = max(scores, key=scores.get)
    max_score = scores[max_cause]
    total = sum(scores.values()) or 1.0
    if max_score == 0:
        return {
            "root_cause": "unknown",
            "confidence": 0.0,
            "evidence": evidence or ["No clear indicators"],
            "recommended_action": "manual_investigation",
            "mitre_techniques": [],
            "scores": {k: round(v, 2) for k, v in scores.items()},
            "events_analysed": len(events),
        }

    confidence = min(max_score / total, 1.0)
    # Qualification for low confidence
    if confidence < 0.3:
        evidence.append("Low confidence: insufficient corroborating evidence")

    action_map = {
        "compromise": "quarantine_and_redeploy",
        "dependency_failure": "restart_dependency",
        "network_partition": "check_network_policies",
    }
    return {
        "root_cause": max_cause,
        "confidence": round(confidence, 3),
        "evidence": list(set(evidence)),
        "recommended_action": action_map.get(max_cause, "manual_investigation"),
        "scores": {k: round(v, 2) for k, v in scores.items()},
        "events_analysed": len(events),
        "mitre_techniques": mitre_techniques,
    }

# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    ch_available = querier.is_available()
    return jsonify({
        "service": "diagnosis-service",
        "status": "healthy",
        "clickhouse_host": CLICKHOUSE_HOST,
        "clickhouse_connected": ch_available,
        "lookback_seconds": LOOKBACK_SECONDS,
        "in_memory_fallback": ENABLE_IN_MEMORY_FALLBACK,
    }), 200

@app.route("/diagnose", methods=["POST"])
def diagnose():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400
    pod_name = data.get("pod_name")
    namespace = data.get("namespace", "default")
    passed_events = data.get("events")
    if not pod_name:
        return jsonify({"error": "pod_name is required"}), 400
    logger.info("Diagnosing pod %s/%s with %d direct events", namespace, pod_name, len(passed_events) if passed_events else 0)
    result = diagnose_root_cause(pod_name, namespace, passed_events=passed_events)
    logger.info("Diagnosis result: %s (confidence=%.3f)", result["root_cause"], result["confidence"])
    return jsonify(result), 200

@app.route("/ingest", methods=["POST"])
def ingest_event():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    event = {
        "pod_name": data.get("pod_name", "unknown"),
        "namespace": data.get("namespace", "default"),
        "syscall_name": data.get("syscall_name", ""),
        "params": data.get("params", {}),
        "anomaly_score": float(data.get("anomaly_score", 0.0)),
        "timestamp": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
    }
    memory_events.append(event)
    return jsonify({"status": "accepted", "buffer_size": len(memory_events)}), 202

if __name__ == "__main__":
    logger.info("Starting Diagnosis Service on port %d", PORT)
    app.run(host="0.0.0.0", port=PORT)
