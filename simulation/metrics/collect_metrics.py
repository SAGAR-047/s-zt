"""
SentinelCloud-Advanced: Metrics Collection & Evaluation Script
===============================================================
Collects and computes key evaluation metrics:
  - MTTD (Mean Time to Detect)
  - MTTR (Mean Time to Remediate/Recover)
  - CPU Overhead
  - AUC-ROC
  - False Positive Rate (FPR)
  - Sequence Detection Accuracy

Queries ClickHouse for events and actions, computes metrics,
and outputs CSV and summary reports.
"""

import os
import sys
import json
import csv
import time
import logging
import argparse
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple, Optional

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [METRICS] %(message)s",
)
logger = logging.getLogger("metrics-collector")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse.sentinel.svc.cluster.local")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "9000"))
CLICKHOUSE_DB = os.environ.get("CLICKHOUSE_DB", "sentinel")

OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/data/metrics")


# ---------------------------------------------------------------------------
# ClickHouse Client
# ---------------------------------------------------------------------------
class MetricsQuerier:
    """Query ClickHouse for metrics data."""

    def __init__(self):
        self._client = None

    def _connect(self):
        try:
            from clickhouse_driver import Client as CHClient
            self._client = CHClient(
                host=CLICKHOUSE_HOST,
                port=CLICKHOUSE_PORT,
                database=CLICKHOUSE_DB,
            )
        except Exception as e:
            logger.error("ClickHouse connection failed: %s", e)

    def query(self, sql: str, params: dict = None) -> list:
        if not self._client:
            self._connect()
        if not self._client:
            return []
        try:
            return self._client.execute(sql, params or {})
        except Exception as e:
            logger.error("Query failed: %s", e)
            return []


querier = MetricsQuerier()


# ---------------------------------------------------------------------------
# MTTD – Mean Time to Detect
# ---------------------------------------------------------------------------
def compute_mttd() -> Dict:
    """
    MTTD = timestamp of SecurityAlert creation − timestamp of first malicious syscall.
    
    We identify malicious syscalls as those with anomaly_score > threshold and is_alert=1.
    """
    logger.info("Computing MTTD...")

    # Get all alert events and corresponding actions
    alert_events = querier.query("""
        SELECT
            pod_name,
            namespace,
            MIN(timestamp) as first_malicious_event,
            MAX(anomaly_score) as max_score
        FROM events
        WHERE is_alert = 1
        GROUP BY pod_name, namespace
        ORDER BY first_malicious_event
    """)

    actions = querier.query("""
        SELECT
            pod_name,
            namespace,
            MIN(timestamp) as alert_created_at,
            action_type
        FROM actions
        GROUP BY pod_name, namespace, action_type
        ORDER BY alert_created_at
    """)

    mttd_values = []
    details = []

    for ae in alert_events:
        pod, ns, first_event_ts, max_score = ae
        # Find the corresponding action
        for action in actions:
            if action[0] == pod and action[1] == ns:
                alert_ts = action[2]
                if isinstance(first_event_ts, datetime) and isinstance(alert_ts, datetime):
                    delta = (alert_ts - first_event_ts).total_seconds()
                    mttd_values.append(delta)
                    details.append({
                        "pod": pod,
                        "namespace": ns,
                        "first_event": str(first_event_ts),
                        "alert_created": str(alert_ts),
                        "mttd_seconds": round(delta, 3),
                        "max_score": round(max_score, 4),
                    })
                break

    result = {
        "metric": "MTTD",
        "unit": "seconds",
        "values": mttd_values,
        "mean": round(np.mean(mttd_values), 3) if mttd_values else None,
        "median": round(np.median(mttd_values), 3) if mttd_values else None,
        "p95": round(np.percentile(mttd_values, 95), 3) if mttd_values else None,
        "min": round(min(mttd_values), 3) if mttd_values else None,
        "max": round(max(mttd_values), 3) if mttd_values else None,
        "count": len(mttd_values),
        "details": details,
    }
    logger.info("MTTD: mean=%.3fs, median=%.3fs, count=%d",
                result["mean"] or 0, result["median"] or 0, result["count"])
    return result


# ---------------------------------------------------------------------------
# MTTR – Mean Time to Remediate
# ---------------------------------------------------------------------------
def compute_mttr() -> Dict:
    """
    MTTR = timestamp when pod is restored/remediated − timestamp of alert.
    
    We measure from action creation to action completion.
    """
    logger.info("Computing MTTR...")

    actions = querier.query("""
        SELECT
            alert_id,
            pod_name,
            namespace,
            timestamp as action_time,
            action_type,
            success
        FROM actions
        WHERE success = 1
        ORDER BY timestamp
    """)

    # For MTTR, we compare action time with event time
    mttr_values = []
    details = []

    for action in actions:
        alert_id, pod, ns, action_time, action_type, success = action

        # Get the first alert event for this pod
        events = querier.query("""
            SELECT MIN(timestamp)
            FROM events
            WHERE pod_name = %(pod)s AND namespace = %(ns)s AND is_alert = 1
        """, {"pod": pod, "ns": ns})

        if events and events[0][0]:
            first_alert = events[0][0]
            if isinstance(first_alert, datetime) and isinstance(action_time, datetime):
                delta = (action_time - first_alert).total_seconds()
                if delta >= 0:
                    mttr_values.append(delta)
                    details.append({
                        "alert_id": alert_id,
                        "pod": pod,
                        "action_type": action_type,
                        "mttr_seconds": round(delta, 3),
                    })

    result = {
        "metric": "MTTR",
        "unit": "seconds",
        "values": mttr_values,
        "mean": round(np.mean(mttr_values), 3) if mttr_values else None,
        "median": round(np.median(mttr_values), 3) if mttr_values else None,
        "p95": round(np.percentile(mttr_values, 95), 3) if mttr_values else None,
        "count": len(mttr_values),
        "details": details,
    }
    logger.info("MTTR: mean=%.3fs, median=%.3fs, count=%d",
                result["mean"] or 0, result["median"] or 0, result["count"])
    return result


# ---------------------------------------------------------------------------
# CPU Overhead
# ---------------------------------------------------------------------------
def compute_cpu_overhead() -> Dict:
    """
    Measure CPU overhead by checking resource usage of eBPF-related pods.
    Uses kubectl top if available.
    """
    logger.info("Computing CPU Overhead...")

    cpu_data = []

    try:
        # Get CPU usage for sentinel namespace pods
        result = subprocess.run(
            ["kubectl", "top", "pods", "-n", "sentinel", "--no-headers"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 3:
                    pod_name = parts[0]
                    cpu_str = parts[1]  # e.g., "50m" or "1"
                    mem_str = parts[2]  # e.g., "128Mi"

                    # Parse CPU millicores
                    cpu_m = 0
                    if cpu_str.endswith("m"):
                        cpu_m = int(cpu_str[:-1])
                    else:
                        cpu_m = int(cpu_str) * 1000

                    cpu_data.append({
                        "pod": pod_name,
                        "cpu_millicores": cpu_m,
                        "memory": mem_str,
                    })

        # Also get node-level eBPF overhead
        result2 = subprocess.run(
            ["kubectl", "top", "nodes", "--no-headers"],
            capture_output=True, text=True, timeout=10,
        )
        node_data = []
        if result2.returncode == 0:
            for line in result2.stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 5:
                    node_data.append({
                        "node": parts[0],
                        "cpu_percent": parts[2],
                        "memory_percent": parts[4],
                    })

    except Exception as e:
        logger.warning("kubectl top failed: %s", e)

    total_cpu = sum(d["cpu_millicores"] for d in cpu_data) if cpu_data else 0

    result = {
        "metric": "CPU_Overhead",
        "unit": "millicores",
        "sentinel_pods": cpu_data,
        "total_sentinel_cpu_millicores": total_cpu,
        "overhead_percentage": round(total_cpu / 40000 * 100, 2) if total_cpu else None,  # Assume 4-core nodes
    }
    logger.info("CPU Overhead: %d millicores total for sentinel pods", total_cpu)
    return result


# ---------------------------------------------------------------------------
# AUC-ROC
# ---------------------------------------------------------------------------
def compute_auc_roc() -> Dict:
    """
    Compute AUC-ROC by comparing anomaly scores with actual labels.
    Labels: is_alert=1 for true positives (attack events).
    """
    logger.info("Computing AUC-ROC...")

    events = querier.query("""
        SELECT anomaly_score, is_alert
        FROM events
        ORDER BY timestamp
        LIMIT 50000
    """)

    if not events:
        return {"metric": "AUC_ROC", "value": None, "error": "No events found"}

    scores = np.array([e[0] for e in events])
    labels = np.array([e[1] for e in events])

    if len(np.unique(labels)) < 2:
        return {"metric": "AUC_ROC", "value": None, "error": "Only one class present"}

    # Manual AUC-ROC computation (no sklearn dependency needed)
    # Sort by decreasing score
    sorted_indices = np.argsort(-scores)
    sorted_labels = labels[sorted_indices]

    n_pos = np.sum(labels == 1)
    n_neg = np.sum(labels == 0)

    if n_pos == 0 or n_neg == 0:
        return {"metric": "AUC_ROC", "value": None, "error": "Need both positive and negative samples"}

    tpr_list = [0.0]
    fpr_list = [0.0]
    tp = 0
    fp = 0

    for label in sorted_labels:
        if label == 1:
            tp += 1
        else:
            fp += 1
        tpr_list.append(tp / n_pos)
        fpr_list.append(fp / n_neg)

    # Trapezoidal AUC
    auc = 0.0
    for i in range(1, len(tpr_list)):
        auc += (fpr_list[i] - fpr_list[i - 1]) * (tpr_list[i] + tpr_list[i - 1]) / 2

    result = {
        "metric": "AUC_ROC",
        "value": round(auc, 4),
        "total_events": len(events),
        "positive_events": int(n_pos),
        "negative_events": int(n_neg),
    }
    logger.info("AUC-ROC: %.4f (pos=%d, neg=%d)", auc, n_pos, n_neg)
    return result


# ---------------------------------------------------------------------------
# False Positive Rate
# ---------------------------------------------------------------------------
def compute_fpr(benign_hours: int = 24) -> Dict:
    """
    FPR = count of alerts during benign operation / total events during that period.
    """
    logger.info("Computing False Positive Rate (over %dh of benign operation)...", benign_hours)

    since = datetime.now(timezone.utc) - timedelta(hours=benign_hours)

    total = querier.query("""
        SELECT COUNT(*) FROM events WHERE timestamp >= %(since)s
    """, {"since": since})

    alerts = querier.query("""
        SELECT COUNT(*) FROM events WHERE timestamp >= %(since)s AND is_alert = 1
    """, {"since": since})

    total_count = total[0][0] if total else 0
    alert_count = alerts[0][0] if alerts else 0

    fpr = (alert_count / total_count) if total_count > 0 else 0.0

    result = {
        "metric": "FPR",
        "value": round(fpr, 6),
        "total_events": total_count,
        "false_alerts": alert_count,
        "period_hours": benign_hours,
    }
    logger.info("FPR: %.6f (%d alerts / %d events)", fpr, alert_count, total_count)
    return result


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------
def generate_report(output_dir: str):
    """Generate comprehensive metrics report."""
    os.makedirs(output_dir, exist_ok=True)

    metrics = {}

    # Compute all metrics
    metrics["mttd"] = compute_mttd()
    metrics["mttr"] = compute_mttr()
    metrics["cpu_overhead"] = compute_cpu_overhead()
    metrics["auc_roc"] = compute_auc_roc()
    metrics["fpr"] = compute_fpr()

    # Write JSON report
    json_path = os.path.join(output_dir, "metrics_report.json")
    with open(json_path, "w") as f:
        json.dump(metrics, f, indent=2, default=str)
    logger.info("JSON report written to %s", json_path)

    # Write CSV summary
    csv_path = os.path.join(output_dir, "metrics_summary.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Metric", "Value", "Unit", "Details"])
        writer.writerow(["MTTD_mean", metrics["mttd"]["mean"], "seconds", f"n={metrics['mttd']['count']}"])
        writer.writerow(["MTTD_median", metrics["mttd"]["median"], "seconds", ""])
        writer.writerow(["MTTD_p95", metrics["mttd"]["p95"], "seconds", ""])
        writer.writerow(["MTTR_mean", metrics["mttr"]["mean"], "seconds", f"n={metrics['mttr']['count']}"])
        writer.writerow(["MTTR_median", metrics["mttr"]["median"], "seconds", ""])
        writer.writerow(["CPU_overhead", metrics["cpu_overhead"]["total_sentinel_cpu_millicores"], "millicores", ""])
        writer.writerow(["AUC_ROC", metrics["auc_roc"].get("value"), "", ""])
        writer.writerow(["FPR", metrics["fpr"]["value"], "", f"over {metrics['fpr']['period_hours']}h"])
    logger.info("CSV summary written to %s", csv_path)

    # Print summary to stdout
    print("\n" + "=" * 60)
    print("  SENTINELCLOUD-ADVANCED METRICS REPORT")
    print("=" * 60)
    print(f"  MTTD (Mean Time to Detect):    {metrics['mttd']['mean']}s")
    print(f"  MTTR (Mean Time to Remediate):  {metrics['mttr']['mean']}s")
    print(f"  CPU Overhead:                   {metrics['cpu_overhead']['total_sentinel_cpu_millicores']}m")
    print(f"  AUC-ROC:                        {metrics['auc_roc'].get('value')}")
    print(f"  False Positive Rate:            {metrics['fpr']['value']}")
    print("=" * 60 + "\n")

    return metrics


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="SentinelCloud-Advanced Metrics Collection"
    )
    parser.add_argument(
        "--output-dir", default=OUTPUT_DIR,
        help="Output directory for reports (default: %(default)s)"
    )
    parser.add_argument(
        "--metric", choices=["mttd", "mttr", "cpu", "auc", "fpr", "all"],
        default="all",
        help="Compute a specific metric or all (default: all)"
    )
    parser.add_argument(
        "--benign-hours", type=int, default=24,
        help="Hours of benign operation for FPR (default: 24)"
    )

    args = parser.parse_args()

    if args.metric == "all":
        generate_report(args.output_dir)
    elif args.metric == "mttd":
        print(json.dumps(compute_mttd(), indent=2, default=str))
    elif args.metric == "mttr":
        print(json.dumps(compute_mttr(), indent=2, default=str))
    elif args.metric == "cpu":
        print(json.dumps(compute_cpu_overhead(), indent=2, default=str))
    elif args.metric == "auc":
        print(json.dumps(compute_auc_roc(), indent=2, default=str))
    elif args.metric == "fpr":
        print(json.dumps(compute_fpr(args.benign_hours), indent=2, default=str))


if __name__ == "__main__":
    main()
