"""
SentinelCloud Prometheus Metrics Client
========================================
Exposes Prometheus-compatible metrics at /metrics for the backend.
"""

import time
import logging
from typing import Optional

from backend.config import settings

logger = logging.getLogger("sentinel.integrations.prometheus")


class PrometheusMetrics:
    """Simple Prometheus-style metrics collector for the backend."""

    def __init__(self):
        self._counters: dict[str, float] = {}
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = {}
        self._start_time = time.time()

    def inc(self, name: str, value: float = 1.0, labels: Optional[dict] = None):
        """Increment a counter."""
        key = self._make_key(name, labels)
        self._counters[key] = self._counters.get(key, 0) + value

    def set_gauge(self, name: str, value: float, labels: Optional[dict] = None):
        """Set a gauge value."""
        key = self._make_key(name, labels)
        self._gauges[key] = value

    def observe(self, name: str, value: float, labels: Optional[dict] = None):
        """Record a histogram observation."""
        key = self._make_key(name, labels)
        if key not in self._histograms:
            self._histograms[key] = []
        self._histograms[key].append(value)

    def _make_key(self, name: str, labels: Optional[dict] = None) -> str:
        if labels:
            label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
            return f"{name}{{{label_str}}}"
        return name

    def generate_text(self) -> str:
        """Generate Prometheus text exposition format."""
        lines = []
        lines.append(f"# HELP sentinel_uptime_seconds Backend uptime in seconds")
        lines.append(f"# TYPE sentinel_uptime_seconds gauge")
        lines.append(f"sentinel_uptime_seconds {time.time() - self._start_time:.1f}")

        for key, value in sorted(self._counters.items()):
            lines.append(f"{key} {value}")

        for key, value in sorted(self._gauges.items()):
            lines.append(f"{key} {value}")

        for key, values in sorted(self._histograms.items()):
            if values:
                avg = sum(values) / len(values)
                lines.append(f"{key}_count {len(values)}")
                lines.append(f"{key}_sum {sum(values):.4f}")
                lines.append(f"{key}_avg {avg:.4f}")

        return "\n".join(lines) + "\n"

    def get_summary(self) -> dict:
        """Get metrics as a dict for API consumption."""
        return {
            "uptime_seconds": round(time.time() - self._start_time, 1),
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
        }


# Singleton
prometheus_metrics = PrometheusMetrics()
