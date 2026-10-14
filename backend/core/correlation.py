"""
SentinelCloud Correlation Engine
=================================
Groups related events into incident correlation chains.
Events sharing a correlation_id are part of the same attack sequence.
"""

import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional

from backend.core.event_schema import _new_id

logger = logging.getLogger("sentinel.core.correlation")


class CorrelationEngine:
    """
    Correlates events by pod, time window, and attack chain.
    Assigns correlation IDs to link related events into a single incident.
    """

    def __init__(self, window_seconds: int = 60):
        self.window = timedelta(seconds=window_seconds)
        # pod_name -> {correlation_id, last_event_time, event_count}
        self._active_chains: dict[str, dict] = {}

    def get_or_create_correlation_id(
        self,
        pod_name: str,
        namespace: str = "medical",
        existing_correlation_id: Optional[str] = None,
    ) -> str:
        """
        Get existing correlation ID for a pod's active chain,
        or create a new one if the time window has expired.
        """
        now = datetime.now(timezone.utc)

        # If an explicit correlation_id is provided, use it
        if existing_correlation_id:
            self._active_chains[pod_name] = {
                "correlation_id": existing_correlation_id,
                "last_event_time": now,
                "event_count": self._active_chains.get(pod_name, {}).get("event_count", 0) + 1,
                "namespace": namespace,
            }
            return existing_correlation_id

        # Check for active chain
        chain = self._active_chains.get(pod_name)
        if chain:
            time_since_last = now - chain["last_event_time"]
            if time_since_last <= self.window:
                # Still within the correlation window
                chain["last_event_time"] = now
                chain["event_count"] += 1
                return chain["correlation_id"]

        # Start a new chain
        corr_id = _new_id()
        self._active_chains[pod_name] = {
            "correlation_id": corr_id,
            "last_event_time": now,
            "event_count": 1,
            "namespace": namespace,
        }
        return corr_id

    def get_chain_info(self, pod_name: str) -> Optional[dict]:
        """Get info about the active correlation chain for a pod."""
        return self._active_chains.get(pod_name)

    def get_all_active_chains(self) -> dict[str, dict]:
        """Get all active correlation chains."""
        now = datetime.now(timezone.utc)
        # Prune expired chains
        expired = [
            pod for pod, chain in self._active_chains.items()
            if now - chain["last_event_time"] > self.window
        ]
        for pod in expired:
            del self._active_chains[pod]
        return dict(self._active_chains)

    def close_chain(self, pod_name: str):
        """Explicitly close a correlation chain (e.g., when incident is resolved)."""
        self._active_chains.pop(pod_name, None)


# Singleton
correlation_engine = CorrelationEngine(window_seconds=60)
