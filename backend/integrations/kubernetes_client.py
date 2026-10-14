"""
SentinelCloud Kubernetes Client
================================
Wraps the Kubernetes Python client for pod management, policy operations,
and cluster status queries. Only active when SENTINEL_KUBERNETES_ENABLED=true.
"""

import logging
from typing import Optional

from backend.config import settings

logger = logging.getLogger("sentinel.integrations.kubernetes")


class KubernetesClient:
    """Lazy-initialized Kubernetes API client."""

    def __init__(self):
        self._core_v1 = None
        self._apps_v1 = None
        self._custom_api = None
        self._initialized = False

    def _init(self):
        """Load Kubernetes configuration and create API clients."""
        if self._initialized or not settings.kubernetes_enabled:
            return

        try:
            from kubernetes import client as k8s_client, config as k8s_config

            try:
                k8s_config.load_incluster_config()
                logger.info("Loaded in-cluster K8s config")
            except Exception:
                k8s_config.load_kube_config()
                logger.info("Loaded kubeconfig")

            self._core_v1 = k8s_client.CoreV1Api()
            self._apps_v1 = k8s_client.AppsV1Api()
            self._custom_api = k8s_client.CustomObjectsApi()
            self._initialized = True
            logger.info("Kubernetes client initialized")
        except ImportError:
            logger.warning("kubernetes package not installed")
        except Exception as e:
            logger.warning("Failed to initialize Kubernetes client: %s", e)

    @property
    def available(self) -> bool:
        """Check if Kubernetes is configured and reachable."""
        if not settings.kubernetes_enabled:
            return False
        self._init()
        return self._initialized

    def list_pods(self, namespace: str = "medical") -> list[dict]:
        """List pods in a namespace."""
        self._init()
        if not self._core_v1:
            return []
        try:
            pods = self._core_v1.list_namespaced_pod(namespace=namespace)
            return [
                {
                    "name": p.metadata.name,
                    "namespace": p.metadata.namespace,
                    "status": p.status.phase,
                    "ip": p.status.pod_ip,
                    "node": p.spec.node_name,
                    "ready": all(
                        c.ready for c in (p.status.container_statuses or [])
                    ),
                    "restarts": sum(
                        c.restart_count for c in (p.status.container_statuses or [])
                    ),
                    "labels": dict(p.metadata.labels or {}),
                }
                for p in pods.items
            ]
        except Exception as e:
            logger.error("Failed to list pods: %s", e)
            return []

    def label_pod(self, pod_name: str, namespace: str, labels: dict) -> bool:
        """Add labels to a pod."""
        self._init()
        if not self._core_v1:
            return False
        try:
            self._core_v1.patch_namespaced_pod(
                name=pod_name,
                namespace=namespace,
                body={"metadata": {"labels": labels}},
            )
            return True
        except Exception as e:
            logger.error("Failed to label pod %s: %s", pod_name, e)
            return False

    def delete_pod(self, pod_name: str, namespace: str, grace_period: int = 0) -> bool:
        """Delete a pod (to trigger redeployment)."""
        self._init()
        if not self._core_v1:
            return False
        try:
            self._core_v1.delete_namespaced_pod(
                name=pod_name,
                namespace=namespace,
                grace_period_seconds=grace_period,
            )
            return True
        except Exception as e:
            logger.error("Failed to delete pod %s: %s", pod_name, e)
            return False

    def get_deployment_status(self, name: str, namespace: str = "medical") -> Optional[dict]:
        """Get deployment status."""
        self._init()
        if not self._apps_v1:
            return None
        try:
            dep = self._apps_v1.read_namespaced_deployment(name=name, namespace=namespace)
            return {
                "name": dep.metadata.name,
                "replicas": dep.spec.replicas,
                "ready_replicas": dep.status.ready_replicas or 0,
                "available_replicas": dep.status.available_replicas or 0,
                "image": dep.spec.template.spec.containers[0].image if dep.spec.template.spec.containers else "",
            }
        except Exception as e:
            logger.error("Failed to get deployment %s: %s", name, e)
            return None

    def check_api_health(self) -> bool:
        """Check if the Kubernetes API is reachable."""
        self._init()
        if not self._core_v1:
            return False
        try:
            self._core_v1.list_namespace(limit=1)
            return True
        except Exception:
            return False


# Singleton
k8s_client = KubernetesClient()
