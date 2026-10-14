"""
SentinelCloud-Advanced: EHR Medical Microservice (Enhanced)
Manages patient health records.
Endpoints: GET /health, GET /record, POST /record, GET /records, GET /metrics, GET /readiness
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
logger = logging.getLogger("ehr-service")

# ---------------------------------------------------------------------------
# Prometheus Metrics
# ---------------------------------------------------------------------------
REQUEST_COUNT = Counter(
    "ehr_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"]
)
REQUEST_LATENCY = Histogram(
    "ehr_request_latency_seconds",
    "HTTP request latency",
    ["method", "endpoint"]
)

# ---------------------------------------------------------------------------
# Service Configuration
# ---------------------------------------------------------------------------
SERVICE_NAME = "ehr"
SERVICE_VERSION = "1.1.0"
START_TIME = time.time()

# Dependencies (readiness check) – comma-separated URLs in env var
DEPENDENCY_URLS = os.environ.get("EHR_DEPENDS_ON", "").split(",") if os.environ.get("EHR_DEPENDS_ON") else []

# In-memory EHR store
ehr_store = {}

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
    for dep_url in DEPENDENCY_URLS:
        try:
            urllib.request.urlopen(dep_url + "/health", timeout=2)
        except Exception:
            return jsonify({"status": "not_ready", "dependency": dep_url, "reason": "unreachable"}), 503
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
@app.route("/record", methods=["GET"])
def get_record():
    patient_id = request.args.get("patient_id")
    if not patient_id:
        return jsonify({"error": "patient_id query parameter required"}), 400
    record = ehr_store.get(patient_id)
    if not record:
        return jsonify({"error": f"No record found for patient {patient_id}"}), 404
    return jsonify({"patient_id": patient_id, "record": record}), 200

@app.route("/record", methods=["POST"])
def create_record():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400
    patient_id = data.get("patient_id")
    if not patient_id:
        return jsonify({"error": "patient_id is required"}), 400
    record = {
        "name": data.get("name", ""),
        "diagnosis": data.get("diagnosis", ""),
        "medications": data.get("medications", []),
        "notes": data.get("notes", ""),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    is_update = patient_id in ehr_store
    ehr_store[patient_id] = record
    action = "updated" if is_update else "created"
    logger.info(f"EHR record {action}", extra={"extra_fields": {"patient_id": patient_id}})
    return jsonify({"status": action, "patient_id": patient_id, "record": record}), 201 if not is_update else 200

@app.route("/records", methods=["GET"])
def list_records():
    return jsonify({"count": len(ehr_store), "patient_ids": list(ehr_store.keys())}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    logger.info("Starting EHR service", extra={"extra_fields": {"port": port}})
    app.run(host="0.0.0.0", port=port)
