"""
SentinelCloud Tetragon Client
==============================
Status checker for the Tetragon eBPF runtime.
"""

import logging

from backend.config import settings

logger = logging.getLogger("sentinel.integrations.tetragon")


class TetragonClient:
    """Check Tetragon status in the cluster."""

    def __init__(self):
        self._available = False

    @property
    def available(self) -> bool:
        return settings.tetragon_enabled and self._available

    def check_status(self) -> dict:
        """Check if Tetragon is running."""
        if not settings.tetragon_enabled:
            return {"status": "disabled", "reason": "SENTINEL_TETRAGON_ENABLED=false"}

        if not settings.kubernetes_enabled:
            return {"status": "unavailable", "reason": "Kubernetes not enabled"}

        try:
            from backend.integrations.kubernetes_client import k8s_client
            if not k8s_client.available:
                return {"status": "unavailable", "reason": "Kubernetes not reachable"}

            # Check for tetragon DaemonSet in sentinel namespace
            pods = k8s_client.list_pods(namespace=settings.kubernetes_namespace_sentinel)
            tetragon_pods = [p for p in pods if "tetragon" in p.get("name", "").lower()]

            if tetragon_pods:
                ready = all(p.get("ready", False) for p in tetragon_pods)
                self._available = ready
                return {
                    "status": "online" if ready else "degraded",
                    "pods": len(tetragon_pods),
                    "all_ready": ready,
                }
            else:
                return {"status": "not_deployed", "reason": "No Tetragon pods found"}

        except Exception as e:
            logger.error("Tetragon status check failed: %s", e)
            return {"status": "error", "reason": str(e)}


# Singleton
tetragon_client = TetragonClient()
