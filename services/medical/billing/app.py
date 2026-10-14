"""
SentinelCloud-Advanced: Billing Medical Microservice (Enhanced)
Handles invoicing and billing operations.
Endpoints: GET /health, GET /invoice, GET /invoices, GET /metrics, GET /readiness
"""
import os
import json
import time
import logging
import urllib.request
import random
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
logger = logging.getLogger("billing-service")

# ---------------------------------------------------------------------------
# Prometheus Metrics
# ---------------------------------------------------------------------------
REQUEST_COUNT = Counter(
    "billing_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"]
)
REQUEST_LATENCY = Histogram(
    "billing_request_latency_seconds",
    "HTTP request latency",
    ["method", "endpoint"]
)

# ---------------------------------------------------------------------------
# Service Configuration
# ---------------------------------------------------------------------------
SERVICE_NAME = "billing"
SERVICE_VERSION = "1.1.0"
START_TIME = time.time()

# Dependencies (readiness check) – comma-separated URLs in env var
DEPENDENCY_URLS = os.environ.get("BILLING_DEPENDS_ON", "").split(",") if os.environ.get("BILLING_DEPENDS_ON") else []

# In-memory invoices
invoices_store = []

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
@app.route("/invoice", methods=["GET"])
def get_invoice():
    patient_id = request.args.get("patient_id")
    if not patient_id:
        return jsonify({"error": "patient_id query parameter required"}), 400
    patient_invoices = [inv for inv in invoices_store if inv["patient_id"] == patient_id]
    if not patient_invoices:
        invoice = {
            "invoice_id": f"INV-{random.randint(10000, 99999)}",
            "patient_id": patient_id,
            "items": [
                {"description": "Consultation", "amount": 150.00},
                {"description": "Lab Tests", "amount": 75.50},
                {"description": "Medication", "amount": 45.00}
            ],
            "total": 270.50,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        invoices_store.append(invoice)
        logger.info("Invoice generated", extra={"extra_fields": {"patient_id": patient_id, "invoice_id": invoice["invoice_id"]}})
        return jsonify({"invoice": invoice}), 201
    return jsonify({"patient_id": patient_id, "invoices": patient_invoices, "count": len(patient_invoices)}), 200

@app.route("/invoices", methods=["GET"])
def list_invoices():
    return jsonify({"count": len(invoices_store), "invoices": invoices_store[-50:]}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5003))
    logger.info("Starting Billing service", extra={"extra_fields": {"port": port}})
    app.run(host="0.0.0.0", port=port)
