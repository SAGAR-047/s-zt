"""
SentinelCloud Cilium CNI Client
================================
Manages Cilium NetworkPolicies for pod quarantine.
Only active when Kubernetes is available.
"""

import logging
from typing import Optional

from backend.config import settings

logger = logging.getLogger("sentinel.integrations.cilium")


class CiliumClient:
    """Cilium NetworkPolicy management via Kubernetes CustomObjects API."""

    def __init__(self):
        self._custom_api = None
        self._initialized = False

    def _init(self):
        if self._initialized or not settings.kubernetes_enabled:
            return
        try:
            from kubernetes import client as k8s_client, config as k8s_config
            try:
                k8s_config.load_incluster_config()
            except Exception:
                k8s_config.load_kube_config()
            self._custom_api = k8s_client.CustomObjectsApi()
            self._initialized = True
        except Exception as e:
            logger.warning("Cilium client initialization failed: %s", e)

    @property
    def available(self) -> bool:
        if not settings.kubernetes_enabled:
            return False
        self._init()
        return self._initialized

    def apply_quarantine(self, pod_name: str, namespace: str = "medical") -> bool:
        """Apply a deny-all Cilium NetworkPolicy to quarantine a pod."""
        self._init()
        if not self._custom_api:
            return False

        policy = {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {
                "name": f"quarantine-{pod_name}",
                "namespace": namespace,
            },
            "spec": {
                "endpointSelector": {"matchLabels": {"suspect": "true"}},
                "ingressDeny": [{}],
                "egressDeny": [{}],
            },
        }

        try:
            self._custom_api.create_namespaced_custom_object(
                group="cilium.io",
                version="v2",
                namespace=namespace,
                plural="ciliumnetworkpolicies",
                body=policy,
            )
            logger.info("Cilium quarantine policy applied for %s/%s", namespace, pod_name)
            return True
        except Exception as e:
            if "already exists" in str(e).lower():
                logger.info("Quarantine policy already exists for %s", pod_name)
                return True
            logger.error("Failed to apply Cilium quarantine: %s", e)
            return False

    def remove_quarantine(self, pod_name: str, namespace: str = "medical") -> bool:
        """Remove a quarantine policy."""
        self._init()
        if not self._custom_api:
            return False

        try:
            self._custom_api.delete_namespaced_custom_object(
                group="cilium.io",
                version="v2",
                namespace=namespace,
                plural="ciliumnetworkpolicies",
                name=f"quarantine-{pod_name}",
            )
            logger.info("Cilium quarantine removed for %s/%s", namespace, pod_name)
            return True
        except Exception as e:
            logger.error("Failed to remove Cilium quarantine: %s", e)
            return False

    def list_policies(self, namespace: str = "medical") -> list[dict]:
        """List all Cilium NetworkPolicies in a namespace."""
        self._init()
        if not self._custom_api:
            return []

        try:
            result = self._custom_api.list_namespaced_custom_object(
                group="cilium.io",
                version="v2",
                namespace=namespace,
                plural="ciliumnetworkpolicies",
            )
            return [
                {
                    "name": p["metadata"]["name"],
                    "namespace": p["metadata"]["namespace"],
                    "spec": p.get("spec", {}),
                }
                for p in result.get("items", [])
            ]
        except Exception as e:
            logger.error("Failed to list Cilium policies: %s", e)
            return []


# Singleton
cilium_client = CiliumClient()
