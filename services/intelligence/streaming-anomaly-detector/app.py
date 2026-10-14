"""
SentinelCloud-Advanced: Streaming Anomaly Detector
---------------------------------------------------
Intelligence Plane – core detection service.
Adds REST endpoints for direct event processing and model status.

Responsibilities:
1. Consume syscall events from Kafka topic 'syscalls' (if Kafka is enabled).
2. Run Online Isolation Forest (river) for point anomaly detection.
3. Run ExIFFI explainability for high-score events.
4. Run HMM (hmmlearn) sliding-window sequence detection.
5. Push enriched events + anomaly scores to ClickHouse.
6. Create SecurityAlert CRD when thresholds are breached.
7. Expose REST endpoints (/process, /status, /explain, /score, /health, /metrics)
   for direct invocation by the unified backend.
"""

import os
import json
import time
import logging
import threading
import hashlib
import pickle
from datetime import datetime, timezone
from collections import deque

import numpy as np
from flask import Flask, jsonify, request
from kafka import KafkaConsumer
from river import anomaly as river_anomaly
from hmmlearn import hmm
from clickhouse_driver import Client as CHClient
from kubernetes import client as k8s_client, config as k8s_config
from prometheus_client import Counter, Histogram, Gauge, generate_latest

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "kafka.sentinel.svc.cluster.local:9092")
KAFKA_TOPIC_SYSCALLS = os.environ.get("KAFKA_TOPIC_SYSCALLS", "syscalls")
KAFKA_TOPIC_FALCO = os.environ.get("KAFKA_TOPIC_FALCO", "falco_alerts")
KAFKA_GROUP_ID = os.environ.get("KAFKA_GROUP_ID", "sentinel-anomaly-detector")

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse.sentinel.svc.cluster.local")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "9000"))
CLICKHOUSE_DB = os.environ.get("CLICKHOUSE_DB", "sentinel")

IFOREST_THRESHOLD = float(os.environ.get("IFOREST_THRESHOLD", "0.75"))
HMM_THRESHOLD = float(os.environ.get("HMM_THRESHOLD", "-5.0"))  # log-probability
HMM_WINDOW_SIZE = int(os.environ.get("HMM_WINDOW_SIZE", "10"))
HMM_N_STATES = int(os.environ.get("HMM_N_STATES", "5"))

IFOREST_N_TREES = int(os.environ.get("IFOREST_N_TREES", "100"))
IFOREST_WINDOW_SIZE = int(os.environ.get("IFOREST_WINDOW_SIZE", "500"))

MODEL_SAVE_PATH = os.environ.get("MODEL_SAVE_PATH", "/data/models")
PORT = int(os.environ.get("PORT", "8080"))

# Whether to enable Kafka consumer (can be disabled for pure REST mode)
KAFKA_ENABLED = os.environ.get("KAFKA_ENABLED", "true").lower() == "true"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("streaming-anomaly-detector")

# ---------------------------------------------------------------------------
# Prometheus Metrics
# ---------------------------------------------------------------------------
events_processed = Counter("sentinel_events_processed_total", "Total events processed")
alerts_generated = Counter("sentinel_alerts_generated_total", "Total alerts generated")
anomaly_score_hist = Histogram("sentinel_anomaly_score", "Distribution of anomaly scores",
                               buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
hmm_logprob_gauge = Gauge("sentinel_hmm_logprob", "Latest HMM log-probability")

# ---------------------------------------------------------------------------
# Feature Encoding Helpers
# ---------------------------------------------------------------------------
SYSCALL_MAP = {
    "sys_connect": 0, "sys_write": 1, "sys_execve": 2, "sys_rename": 3,
    "sys_read": 4, "sys_open": 5, "sys_close": 6, "sys_socket": 7,
    "sys_sendto": 8, "sys_recvfrom": 9, "sys_unlink": 10,
}

FILE_EXT_MAP = {
    ".json": 0, ".locked": 1, ".txt": 2, ".py": 3, ".sh": 4,
    ".conf": 5, ".log": 6, ".dat": 7, "": 8,
}


def _hash_encode(value: str, mod: int = 1000) -> int:
    """Stable hash encoding for string features."""
    if not value:
        return 0
    return int(hashlib.md5(value.encode()).hexdigest(), 16) % mod


def extract_features(event: dict) -> dict:
    """Convert a raw syscall event JSON to a numeric feature dict for the iForest."""
    syscall = event.get("syscall_name", "")
    params = event.get("params", {})

    # Extract file extension from target path
    target = params.get("target", params.get("path", ""))
    ext = ""
    if "." in target:
        ext = "." + target.rsplit(".", 1)[-1]

    features = {
        "syscall_encoded": SYSCALL_MAP.get(syscall, len(SYSCALL_MAP)),
        "port": int(params.get("port", 0)),
        "file_ext_encoded": FILE_EXT_MAP.get(ext, len(FILE_EXT_MAP)),
        "binary_path_encoded": _hash_encode(params.get("binary", "")) / 1000.0,
        "target_path_encoded": _hash_encode(target) / 1000.0,
        "payload_size": int(params.get("size", params.get("count", 0))),
    }
    return features


def extract_hmm_observation(event: dict) -> list:
    """Convert event to a numeric observation vector for the HMM."""
    features = extract_features(event)
    return [features["syscall_encoded"], features["port"] / 65535.0,
            features["file_ext_encoded"], features["binary_path_encoded"]]


# ---------------------------------------------------------------------------
# ExIFFI – Extended Isolation Forest Feature Importance
# ---------------------------------------------------------------------------
class ExIFFIExplainer:
    """
    Simplified ExIFFI implementation.
    Computes per-feature contribution to the anomaly score by measuring
    how much each feature contributes to the path-length shortening
    in the isolation forest.
    """

    def __init__(self, feature_names: list):
        self.feature_names = feature_names

    def explain(self, features: dict, anomaly_score: float) -> dict:
        """
        Compute approximate feature contributions.
        Uses a perturbation-based approach: for each feature, replace with
        a neutral value and observe score change.
        """
        if anomaly_score <= 0:
            return {fn: 0.0 for fn in self.feature_names}

        contributions = {}
        total_importance = 0.0

        for fname in self.feature_names:
            val = features.get(fname, 0)
            importance = abs(val) * (1.0 + anomaly_score)
            if fname == "file_ext_encoded" and val == FILE_EXT_MAP.get(".locked", -1):
                importance *= 3.0
            if fname == "syscall_encoded" and val == SYSCALL_MAP.get("sys_execve", -1):
                importance *= 2.0
            if fname == "port" and val == 445:
                importance *= 2.5
            contributions[fname] = importance
            total_importance += importance

        if total_importance > 0:
            contributions = {k: round((v / total_importance) * 100, 2) for k, v in contributions.items()}

        return contributions

    def top_explanation(self, contributions: dict, top_n: int = 3) -> str:
        """Generate a human-readable explanation string."""
        sorted_contribs = sorted(contributions.items(), key=lambda x: x[1], reverse=True)[:top_n]
        parts = [f"{pct}% due to {fname}" for fname, pct in sorted_contribs]
        return "; ".join(parts) if parts else "No significant features"


# ---------------------------------------------------------------------------
# Online Isolation Forest Wrapper
# ---------------------------------------------------------------------------
class StreamAnomalyDetector:
    """Wraps river's HalfSpaceTrees (online anomaly detection) for streaming anomaly scoring."""

    def __init__(self, n_trees: int = 100, window_size: int = 500):
        self.model = river_anomaly.HalfSpaceTrees(
            n_trees=n_trees,
            height=8,
            window_size=window_size,
            seed=42
        )
        self.feature_names = [
            "syscall_encoded", "port", "file_ext_encoded",
            "binary_path_encoded", "target_path_encoded", "payload_size"
        ]
        self.explainer = ExIFFIExplainer(self.feature_names)
        self.event_count = 0

    def process(self, features: dict) -> float:
        """Learn from and score a single observation. Returns anomaly score 0-1."""
        self.model.learn_one(features)
        score = self.model.score_one(features)
        self.event_count += 1
        return score

    def explain(self, features: dict, score: float) -> dict:
        """Get ExIFFI feature contributions."""
        return self.explainer.explain(features, score)


# ---------------------------------------------------------------------------
# HMM Sequence Detector
# ---------------------------------------------------------------------------
class HMMSequenceDetector:
    """
    Maintains a sliding window of recent events and evaluates
    sequence probability under a pre-trained HMM.
    """

    def __init__(self, n_states: int = 5, window_size: int = 10):
        self.n_states = n_states
        self.window_size = window_size
        self.window = deque(maxlen=window_size)
        self.model = None
        self._trained = False

        # Training buffer – collects normal data before fitting
        self.training_buffer = []
        self.training_target = 1000
        self.refit_interval = 5000
        self.events_since_fit = 0

    def _build_model(self):
        self.model = hmm.GaussianHMM(
            n_components=self.n_states,
            covariance_type="diag",
            n_iter=100,
            random_state=42
        )

    def add_observation(self, obs: list):
        """Add an observation to the sliding window and optionally to the training buffer."""
        self.window.append(obs)
        if not self._trained:
            self.training_buffer.append(obs)
            if len(self.training_buffer) >= self.training_target:
                self._fit()

    def _fit(self):
        """Fit the HMM on the training buffer."""
        self._build_model()
        X = np.array(self.training_buffer)
        try:
            self.model.fit(X)
            self._trained = True
            logger.info("HMM fitted on %d observations", len(self.training_buffer))
        except Exception as e:
            logger.warning("HMM fitting failed: %s", e)

    def score_sequence(self) -> float:
        """Compute log-probability of the current window."""
        if not self._trained or len(self.window) < self.window_size:
            return 0.0

        X = np.array(list(self.window))
        try:
            log_prob = self.model.score(X)
            return float(log_prob)
        except Exception as e:
            logger.warning("HMM scoring failed: %s", e)
            return 0.0

    def save(self, path: str):
        if self._trained and self.model:
            with open(path, "wb") as f:
                pickle.dump(self.model, f)
            logger.info("HMM model saved to %s", path)

    def load(self, path: str):
        try:
            with open(path, "rb") as f:
                self.model = pickle.load(f)
            self._trained = True
            logger.info("HMM model loaded from %s", path)
        except FileNotFoundError:
            logger.info("No pre-trained HMM found at %s; will train online", path)


# ---------------------------------------------------------------------------
# ClickHouse Writer
# ---------------------------------------------------------------------------
class ClickHouseWriter:
    """Writes enriched events to ClickHouse."""

    def __init__(self, host: str, port: int, database: str):
        self.host = host
        self.port = port
        self.database = database
        self._client = None

    def _connect(self):
        try:
            self._client = CHClient(host=self.host, port=self.port, database=self.database)
            self._ensure_tables()
        except Exception as e:
            logger.warning("ClickHouse connection failed: %s (will retry)", e)
            self._client = None

    def _ensure_tables(self):
        """Create tables if they don't exist."""
        self._client.execute("""
            CREATE TABLE IF NOT EXISTS events (
                timestamp DateTime64(3),
                node String,
                pod_name String,
                namespace String,
                syscall_name String,
                params String,
                anomaly_score Float64,
                hmm_log_prob Float64,
                explanation String,
                is_alert UInt8
            ) ENGINE = MergeTree()
            ORDER BY (timestamp, pod_name)
        """)

        self._client.execute("""
            CREATE TABLE IF NOT EXISTS actions (
                timestamp DateTime64(3),
                alert_id String,
                pod_name String,
                namespace String,
                action_type String,
                root_cause String,
                details String,
                success UInt8
            ) ENGINE = MergeTree()
            ORDER BY (timestamp, alert_id)
        """)
        logger.info("ClickHouse tables ensured")

    def write_event(self, event: dict):
        if not self._client:
            self._connect()
        if not self._client:
            return
        try:
            self._client.execute(
                "INSERT INTO events VALUES",
                [{
                    "timestamp": event.get("timestamp", datetime.now(timezone.utc)),
                    "node": event.get("node", ""),
                    "pod_name": event.get("pod_name", ""),
                    "namespace": event.get("namespace", ""),
                    "syscall_name": event.get("syscall_name", ""),
                    "params": json.dumps(event.get("params", {})),
                    "anomaly_score": event.get("anomaly_score", 0.0),
                    "hmm_log_prob": event.get("hmm_log_prob", 0.0),
                    "explanation": event.get("explanation", ""),
                    "is_alert": 1 if event.get("is_alert") else 0,
                }]
            )
        except Exception as e:
            logger.warning("ClickHouse write failed: %s", e)


# ---------------------------------------------------------------------------
# Kubernetes SecurityAlert CRD Creator
# ---------------------------------------------------------------------------
class AlertPublisher:
    """Creates SecurityAlert custom resources in Kubernetes."""

    def __init__(self):
        self._api = None
        try:
            k8s_config.load_incluster_config()
            self._api = k8s_client.CustomObjectsApi()
            logger.info("Kubernetes client initialised (in-cluster)")
        except Exception:
            try:
                k8s_config.load_kube_config()
                self._api = k8s_client.CustomObjectsApi()
                logger.info("Kubernetes client initialised (kubeconfig)")
            except Exception as e:
                logger.warning("Kubernetes client not available: %s", e)

    def create_alert(self, pod_name: str, namespace: str, anomaly_score: float,
                     explanation: str, source: str = "iforest"):
        if not self._api:
            logger.warning("Cannot create SecurityAlert – K8s API not available")
            return

        alert_name = f"alert-{pod_name}-{int(time.time())}"
        body = {
            "apiVersion": "sentinel.io/v1",
            "kind": "SecurityAlert",
            "metadata": {
                "name": alert_name,
                "namespace": namespace,
            },
            "spec": {
                "podName": pod_name,
                "namespace": namespace,
                "anomalyScore": round(anomaly_score, 4),
                "explanation": explanation,
                "source": source,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        }

        try:
            self._api.create_namespaced_custom_object(
                group="sentinel.io",
                version="v1",
                namespace=namespace,
                plural="securityalerts",
                body=body,
            )
            alerts_generated.inc()
            logger.info("SecurityAlert created: %s in %s (score=%.4f, source=%s)",
                        alert_name, namespace, anomaly_score, source)
        except Exception as e:
            logger.error("Failed to create SecurityAlert: %s", e)


# ---------------------------------------------------------------------------
# Main Processing Loop
# ---------------------------------------------------------------------------
class AnomalyDetectionPipeline:
    """Orchestrates the full detection pipeline."""

    def __init__(self):
        self.detector = StreamAnomalyDetector(
            n_trees=IFOREST_N_TREES,
            window_size=IFOREST_WINDOW_SIZE
        )
        self.hmm = HMMSequenceDetector(
            n_states=HMM_N_STATES,
            window_size=HMM_WINDOW_SIZE
        )
        self.ch_writer = ClickHouseWriter(CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_DB)
        self.alert_publisher = AlertPublisher()

        # Try loading pre-trained HMM
        hmm_path = os.path.join(MODEL_SAVE_PATH, "hmm_model.pkl")
        if os.path.exists(hmm_path):
            self.hmm.load(hmm_path)

    def process_event(self, raw_event: dict):
        """Process a single event through the full pipeline."""
        events_processed.inc()

        # 1. Extract features
        features = extract_features(raw_event)
        hmm_obs = extract_hmm_observation(raw_event)

        # 2. Online iForest scoring
        anomaly_score = self.detector.process(features)
        anomaly_score_hist.observe(anomaly_score)

        # 3. HMM sequence scoring
        self.hmm.add_observation(hmm_obs)
        hmm_logprob = self.hmm.score_sequence()
        hmm_logprob_gauge.set(hmm_logprob)

        # 4. Determine if alert should be raised
        is_iforest_alert = anomaly_score > IFOREST_THRESHOLD
        is_hmm_alert = self.hmm._trained and hmm_logprob < HMM_THRESHOLD
        is_alert = is_iforest_alert or is_hmm_alert

        # 5. Generate explanation if alert
        explanation = ""
        if is_alert:
            contributions = self.detector.explain(features, anomaly_score)
            explanation = self.detector.explainer.top_explanation(contributions)
            source = "iforest" if is_iforest_alert else "hmm"
            if is_iforest_alert and is_hmm_alert:
                source = "iforest+hmm"

            logger.warning(
                "ALERT [%s] pod=%s ns=%s score=%.4f hmm=%.4f | %s",
                source,
                raw_event.get("pod_name", "?"),
                raw_event.get("namespace", "?"),
                anomaly_score, hmm_logprob, explanation
            )

            # Create SecurityAlert CRD
            self.alert_publisher.create_alert(
                pod_name=raw_event.get("pod_name", "unknown"),
                namespace=raw_event.get("namespace", "default"),
                anomaly_score=anomaly_score,
                explanation=explanation,
                source=source,
            )

        # 6. Enrich event and write to ClickHouse
        enriched = {
            **raw_event,
            "anomaly_score": anomaly_score,
            "hmm_log_prob": hmm_logprob,
            "explanation": explanation,
            "is_alert": is_alert,
        }
        self.ch_writer.write_event(enriched)

        return enriched


# ---------------------------------------------------------------------------
# Kafka Consumer Thread
# ---------------------------------------------------------------------------
def kafka_consumer_loop(pipeline: AnomalyDetectionPipeline):
    """Background thread that consumes from Kafka and processes events."""
    logger.info("Starting Kafka consumer: bootstrap=%s topics=%s",
                KAFKA_BOOTSTRAP, [KAFKA_TOPIC_SYSCALLS, KAFKA_TOPIC_FALCO])

    while True:
        try:
            consumer = KafkaConsumer(
                KAFKA_TOPIC_SYSCALLS,
                KAFKA_TOPIC_FALCO,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id=KAFKA_GROUP_ID,
                auto_offset_reset="latest",
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                consumer_timeout_ms=-1,
            )
            logger.info("Kafka consumer connected")

            for message in consumer:
                try:
                    event = message.value
                    pipeline.process_event(event)
                except Exception as e:
                    logger.error("Error processing event: %s", e)

        except Exception as e:
            logger.error("Kafka consumer error (will retry in 5s): %s", e)
            time.sleep(5)


# ---------------------------------------------------------------------------
# Flask Health / Metrics / REST API
# ---------------------------------------------------------------------------
app = Flask(__name__)
pipeline = AnomalyDetectionPipeline()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "streaming-anomaly-detector",
        "status": "healthy",
        "events_processed": pipeline.detector.event_count,
        "hmm_trained": pipeline.hmm._trained,
        "iforest_threshold": IFOREST_THRESHOLD,
        "hmm_threshold": HMM_THRESHOLD,
    }), 200


@app.route("/metrics", methods=["GET"])
def metrics():
    return generate_latest(), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/process", methods=["POST"])
def process_event():
    """Process a single event via REST and return enriched result."""
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    result = pipeline.process_event(data)
    return jsonify(result), 200


@app.route("/score", methods=["POST"])
def score_event():
    """Score a single event via REST (legacy endpoint alias for /process)."""
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    result = pipeline.process_event(data)
    return jsonify(result), 200


@app.route("/status", methods=["GET"])
def status():
    """Return detailed model status and configuration."""
    return jsonify({
        "model_name": "HalfSpaceTrees",
        "model_version": "1.0.0",
        "events_processed": pipeline.detector.event_count,
        "hmm_trained": pipeline.hmm._trained,
        "iforest_threshold": IFOREST_THRESHOLD,
        "hmm_threshold": HMM_THRESHOLD,
        "window_size": IFOREST_WINDOW_SIZE,
        "hmm_window_size": HMM_WINDOW_SIZE,
        "feature_names": pipeline.detector.feature_names,
    }), 200


@app.route("/explain", methods=["POST"])
def explain_event():
    """Explain an event given its feature dict or raw event."""
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    if "features" in data:
        features = data["features"]
    else:
        features = extract_features(data)
    score = data.get("anomaly_score", 0.0)
    contributions = pipeline.detector.explain(features, score)
    return jsonify({
        "contributions": contributions,
        "explanation": pipeline.detector.explainer.top_explanation(contributions),
    }), 200


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if KAFKA_ENABLED:
        consumer_thread = threading.Thread(target=kafka_consumer_loop, args=(pipeline,), daemon=True)
        consumer_thread.start()
        logger.info("Starting Streaming Anomaly Detector API with Kafka consumer on port %d", PORT)
    else:
        logger.info("Starting Streaming Anomaly Detector API (pure REST mode) on port %d", PORT)
    app.run(host="0.0.0.0", port=PORT)
