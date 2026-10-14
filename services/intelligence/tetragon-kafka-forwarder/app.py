"""
SentinelCloud-Advanced: Tetragon Kafka Forwarder
--------------------------------------------------
Observability Plane – Event collector daemon.

Reads Tetragon events via:
  1. gRPC streaming API (primary), or
  2. JSON log file export (fallback)

Normalises events into a common JSON schema and publishes
them to a Kafka topic ('syscalls').

Also optionally consumes Falco alert JSON logs and publishes
to the 'falco_alerts' topic.
"""

import os
import io
import sys
import json
import time
import glob
import logging
import threading
from datetime import datetime, timezone

from kafka import KafkaProducer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "kafka.sentinel.svc.cluster.local:9092")
KAFKA_TOPIC_SYSCALLS = os.environ.get("KAFKA_TOPIC_SYSCALLS", "syscalls")
KAFKA_TOPIC_FALCO = os.environ.get("KAFKA_TOPIC_FALCO", "falco_alerts")
KAFKA_TOPIC_DNS = os.environ.get("KAFKA_TOPIC_DNS", "dns_blocks")

# Tetragon export path (JSON lines file)
TETRAGON_EXPORT_PATH = os.environ.get(
    "TETRAGON_EXPORT_PATH", "/var/run/cilium/tetragon/tetragon.log"
)

# Falco alert log path
FALCO_ALERT_PATH = os.environ.get(
    "FALCO_ALERT_PATH", "/var/log/falco/events.json"
)

# gRPC endpoint (Tetragon sensor)
TETRAGON_GRPC_ADDRESS = os.environ.get(
    "TETRAGON_GRPC_ADDRESS", "localhost:54321"
)

MODE = os.environ.get("FORWARDER_MODE", "file")  # "file" or "grpc"

PORT = int(os.environ.get("PORT", "8082"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("tetragon-kafka-forwarder")


# ---------------------------------------------------------------------------
# Kafka Producer
# ---------------------------------------------------------------------------
class EventPublisher:
    """Thread-safe Kafka producer wrapper."""

    def __init__(self):
        self._producer = None
        self._connect()

    def _connect(self):
        while True:
            try:
                self._producer = KafkaProducer(
                    bootstrap_servers=KAFKA_BOOTSTRAP,
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    acks="all",
                    retries=3,
                    linger_ms=10,
                    batch_size=16384,
                )
                logger.info("Kafka producer connected to %s", KAFKA_BOOTSTRAP)
                return
            except Exception as e:
                logger.error("Kafka connection failed: %s – retrying in 5s", e)
                time.sleep(5)

    def publish(self, topic: str, event: dict):
        try:
            self._producer.send(topic, value=event)
        except Exception as e:
            logger.error("Kafka send error: %s", e)
            self._connect()
            try:
                self._producer.send(topic, value=event)
            except Exception:
                pass

    def flush(self):
        if self._producer:
            self._producer.flush()


publisher = EventPublisher()


# ---------------------------------------------------------------------------
# Tetragon Event Normaliser
# ---------------------------------------------------------------------------
def normalise_tetragon_event(raw: dict) -> dict:
    """
    Convert a raw Tetragon JSON event into the SentinelCloud common schema.
    
    Tetragon emits several event types: process_exec, process_exit,
    process_kprobe, etc.  We extract the relevant fields.
    """
    process_exec = raw.get("process_exec", {})
    process_kprobe = raw.get("process_kprobe", {})

    # Determine event type
    if process_exec:
        proc = process_exec.get("process", {})
        syscall_name = "sys_execve"
        params = {
            "binary": proc.get("binary", ""),
            "arguments": " ".join(proc.get("arguments", [])),
            "pid": proc.get("pid", 0),
            "uid": proc.get("uid", 0),
        }
        pod_info = proc.get("pod", {})
    elif process_kprobe:
        proc = process_kprobe.get("process", {})
        func = process_kprobe.get("function_name", "")
        args = process_kprobe.get("args", [])

        # Map kprobe function names to syscall names
        func_map = {
            "__x64_sys_connect": "sys_connect",
            "__x64_sys_write": "sys_write",
            "__x64_sys_rename": "sys_rename",
            "__x64_sys_read": "sys_read",
            "__x64_sys_open": "sys_open",
            "__x64_sys_sendto": "sys_sendto",
            "__x64_sys_recvfrom": "sys_recvfrom",
            "__x64_sys_unlink": "sys_unlink",
        }
        syscall_name = func_map.get(func, func)

        # Extract args
        params = {"binary": proc.get("binary", "")}
        for arg in args:
            if "sock_arg" in arg:
                sock = arg["sock_arg"]
                params["port"] = sock.get("dport", 0)
                params["address"] = sock.get("daddr", "")
                params["protocol"] = sock.get("protocol", "")
            elif "string_arg" in arg:
                params["target"] = arg["string_arg"]
            elif "int_arg" in arg:
                params["size"] = arg["int_arg"]

        pod_info = proc.get("pod", {})
    else:
        # Unknown event type – still forward it
        syscall_name = "unknown"
        params = {}
        pod_info = {}

    normalised = {
        "timestamp": raw.get("time", datetime.now(timezone.utc).isoformat()),
        "node": raw.get("node_name", os.environ.get("NODE_NAME", "")),
        "pod_name": pod_info.get("name", ""),
        "namespace": pod_info.get("namespace", ""),
        "syscall_name": syscall_name,
        "params": params,
        "source": "tetragon",
    }
    return normalised


def normalise_falco_event(raw: dict) -> dict:
    """Convert a raw Falco alert JSON into the common schema."""
    output_fields = raw.get("output_fields", {})
    return {
        "timestamp": raw.get("time", datetime.now(timezone.utc).isoformat()),
        "node": output_fields.get("k8s.node.name", ""),
        "pod_name": output_fields.get("k8s.pod.name", ""),
        "namespace": output_fields.get("k8s.ns.name", ""),
        "syscall_name": output_fields.get("evt.type", raw.get("rule", "")),
        "params": {
            "rule": raw.get("rule", ""),
            "priority": raw.get("priority", ""),
            "output": raw.get("output", ""),
            "binary": output_fields.get("proc.name", ""),
        },
        "source": "falco",
    }


# ---------------------------------------------------------------------------
# File Tail Reader
# ---------------------------------------------------------------------------
def tail_file(filepath: str, callback, label: str = ""):
    """
    Tail a JSON-lines file and call `callback(line_dict)` for each new line.
    """
    logger.info("Tailing %s [%s]", filepath, label)
    while not os.path.exists(filepath):
        logger.info("Waiting for %s to appear…", filepath)
        time.sleep(5)

    with open(filepath, "r") as f:
        # Seek to end
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            try:
                data = json.loads(line.strip())
                callback(data)
            except json.JSONDecodeError:
                pass


# ---------------------------------------------------------------------------
# gRPC Reader (optional, requires tetragon protobuf stubs)
# ---------------------------------------------------------------------------
def grpc_stream(callback):
    """
    Stream Tetragon events via gRPC.
    Requires 'tetragon' protobuf stubs to be generated.
    Falls back to file mode if not available.
    """
    try:
        import grpc
        # tetragon gRPC stubs – generated from tetragon.proto
        # For now we fall back to file mode if stubs aren't available
        logger.warning("gRPC stubs not yet generated – falling back to file mode")
        tail_file(TETRAGON_EXPORT_PATH, callback, "tetragon-grpc-fallback")
    except ImportError:
        logger.warning("grpc not installed – falling back to file mode")
        tail_file(TETRAGON_EXPORT_PATH, callback, "tetragon-file-fallback")


# ---------------------------------------------------------------------------
# Processing Callbacks
# ---------------------------------------------------------------------------
events_forwarded = 0


def on_tetragon_event(raw: dict):
    global events_forwarded
    normalised = normalise_tetragon_event(raw)
    publisher.publish(KAFKA_TOPIC_SYSCALLS, normalised)
    events_forwarded += 1
    if events_forwarded % 1000 == 0:
        logger.info("Forwarded %d Tetragon events", events_forwarded)


def on_falco_event(raw: dict):
    normalised = normalise_falco_event(raw)
    publisher.publish(KAFKA_TOPIC_FALCO, normalised)


# ---------------------------------------------------------------------------
# Health API
# ---------------------------------------------------------------------------
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "tetragon-kafka-forwarder",
        "status": "healthy",
        "mode": MODE,
        "events_forwarded": events_forwarded,
        "kafka_bootstrap": KAFKA_BOOTSTRAP,
    }), 200


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Start Tetragon reader thread
    if MODE == "grpc":
        t_thread = threading.Thread(target=grpc_stream, args=(on_tetragon_event,), daemon=True)
    else:
        t_thread = threading.Thread(
            target=tail_file,
            args=(TETRAGON_EXPORT_PATH, on_tetragon_event, "tetragon"),
            daemon=True,
        )
    t_thread.start()

    # Start Falco reader thread
    f_thread = threading.Thread(
        target=tail_file,
        args=(FALCO_ALERT_PATH, on_falco_event, "falco"),
        daemon=True,
    )
    f_thread.start()

    logger.info("Tetragon Kafka Forwarder started (mode=%s)", MODE)
    app.run(host="0.0.0.0", port=PORT)
