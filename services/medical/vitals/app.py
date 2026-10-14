"""
SentinelCloud-Advanced: Vitals Medical Microservice (Enhanced)
Monitors patient vital signs. Labeled as critical: true.
Endpoints: GET /health, POST /beat, GET /vitals, GET /metrics, GET /readiness
"""
import os
import json
import time
import logging
import urllib.request
from datetime import datetime, timezone

from flask import Flask, jsonify, request, g
from prometheus_client import Counter, Histogram, generate_latest

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Structured JSON Logging
# ---------------------------------------------------------------------------
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)
        return json.dumps(log_data)

handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger("vitals-service")

# ---------------------------------------------------------------------------
# Prometheus Metrics
# ---------------------------------------------------------------------------
REQUEST_COUNT = Counter(
    "vitals_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"]
)
REQUEST_LATENCY = Histogram(
    "vitals_request_latency_seconds",
    "HTTP request latency",
    ["method", "endpoint"]
)

# ---------------------------------------------------------------------------
# Service Configuration
# ---------------------------------------------------------------------------
SERVICE_NAME = "vitals"
SERVICE_VERSION = "1.1.0"
START_TIME = time.time()

# Dependencies (readiness check) – comma-separated URLs in env var
DEPENDENCY_URLS = os.environ.get("VITALS_DEPENDS_ON", "").split(",") if os.environ.get("VITALS_DEPENDS_ON") else []

# In-memory store for vitals
vitals_store = []

# ---------------------------------------------------------------------------
# Request Tracking Middleware
# ---------------------------------------------------------------------------
@app.before_request
def start_timer():
    g.start_time = time.time()

@app.after_request
def record_metrics(response):
    latency = time.time() - g.start_time
    endpoint = request.path
    REQUEST_COUNT.labels(method=request.method, endpoint=endpoint, status=response.status_code).inc()
    REQUEST_LATENCY.labels(method=request.method, endpoint=endpoint).observe(latency)
    logger.info("Request completed",
                extra={"extra_fields": {"method": request.method, "path": endpoint,
                                        "status": response.status_code, "latency_ms": round(latency * 1000, 2)}})
    return response

# ---------------------------------------------------------------------------
# Health & Readiness
# ---------------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    uptime = time.time() - START_TIME
    return jsonify({
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "status": "healthy",
        "uptime_seconds": round(uptime, 2),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200

@app.route("/readiness", methods=["GET"])
def readiness():
    """Check if service is ready to accept traffic, including dependencies."""
    for dep_url in DEPENDENCY_URLS:
        try:
            urllib.request.urlopen(dep_url + "/health", timeout=2)
        except Exception:
            return jsonify({
                "status": "not_ready",
                "dependency": dep_url,
                "reason": "unreachable"
            }), 503
    return jsonify({"status": "ready"}), 200

# ---------------------------------------------------------------------------
# Metrics Endpoint
# ---------------------------------------------------------------------------
@app.route("/metrics", methods=["GET"])
def metrics():
    return generate_latest(), 200, {"Content-Type": "text/plain; charset=utf-8"}

# ---------------------------------------------------------------------------
# Core Domain Endpoints
# ---------------------------------------------------------------------------
@app.route("/beat", methods=["POST"])
def beat():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400
    record = {
        "patient_id": data.get("patient_id", "unknown"),
        "heart_rate": data.get("heart_rate"),
        "bp_systolic": data.get("bp_systolic"),
        "bp_diastolic": data.get("bp_diastolic"),
        "spo2": data.get("spo2"),
        "received_at": datetime.now(timezone.utc).isoformat()
    }
    vitals_store.append(record)
    logger.info("Vital signs recorded", extra={"extra_fields": {"patient_id": record["patient_id"]}})

    # Simple alerting logic
    alerts = []
    if record["heart_rate"] and (record["heart_rate"] < 40 or record["heart_rate"] > 180):
        alerts.append({"type": "heart_rate_critical", "value": record["heart_rate"]})
    if record["spo2"] and record["spo2"] < 90.0:
        alerts.append({"type": "spo2_low", "value": record["spo2"]})
    return jsonify({
        "status": "recorded",
        "record": record,
        "alerts": alerts,
        "total_records": len(vitals_store)
    }), 201

@app.route("/vitals", methods=["GET"])
def get_vitals():
    return jsonify({
        "count": len(vitals_store),
        "records": vitals_store[-50:]
    }), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting Vitals service", extra={"extra_fields": {"port": port}})
    app.run(host="0.0.0.0", port=port)
