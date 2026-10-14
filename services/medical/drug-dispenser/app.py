"""
SentinelCloud-Advanced: Drug Dispenser Medical Microservice (Enhanced)
Handles drug dispensing operations. Labeled as critical: true.
Endpoints: GET /health, POST /dispense, GET /inventory, GET /metrics, GET /readiness
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
logger = logging.getLogger("drug-dispenser-service")

# ---------------------------------------------------------------------------
# Prometheus Metrics
# ---------------------------------------------------------------------------
REQUEST_COUNT = Counter(
    "drugdispenser_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"]
)
REQUEST_LATENCY = Histogram(
    "drugdispenser_request_latency_seconds",
    "HTTP request latency",
    ["method", "endpoint"]
)

# ---------------------------------------------------------------------------
# Service Configuration
# ---------------------------------------------------------------------------
SERVICE_NAME = "drug-dispenser"
SERVICE_VERSION = "1.1.0"
START_TIME = time.time()

# Dependencies (readiness check) – comma-separated URLs in env var
DEPENDENCY_URLS = os.environ.get("DRUG_DISPENSER_DEPENDS_ON", "").split(",") if os.environ.get("DRUG_DISPENSER_DEPENDS_ON") else []

# In-memory drug dispensing log and inventory
dispense_log = []
drug_inventory = {
    "aspirin": 500,
    "morphine": 100,
    "insulin": 300,
    "amoxicillin": 200,
    "metformin": 400,
}

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
@app.route("/dispense", methods=["POST"])
def dispense():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400
    drug = data.get("drug_name", "").lower()
    quantity = data.get("quantity", 0)
    patient_id = data.get("patient_id", "unknown")
    prescriber_id = data.get("prescriber_id", "unknown")
    if drug not in drug_inventory:
        return jsonify({"error": f"Drug '{drug}' not found in inventory"}), 404
    if drug_inventory[drug] < quantity:
        return jsonify({"error": f"Insufficient stock for '{drug}'. Available: {drug_inventory[drug]}"}), 409
    drug_inventory[drug] -= quantity
    record = {
        "patient_id": patient_id,
        "drug_name": drug,
        "quantity": quantity,
        "prescriber_id": prescriber_id,
        "remaining_stock": drug_inventory[drug],
        "dispensed_at": datetime.now(timezone.utc).isoformat()
    }
    dispense_log.append(record)
    logger.info("Drug dispensed", extra={"extra_fields": {"drug": drug, "quantity": quantity, "patient_id": patient_id}})
    return jsonify({"status": "dispensed", "record": record}), 201

@app.route("/inventory", methods=["GET"])
def inventory():
    return jsonify({"inventory": drug_inventory}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    logger.info("Starting Drug Dispenser service", extra={"extra_fields": {"port": port}})
    app.run(host="0.0.0.0", port=port)
