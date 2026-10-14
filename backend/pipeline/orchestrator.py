"""
SentinelCloud MAPE-K Orchestrator (In-Process)
================================================
Autonomous remediation controller implementing the MAPE-K loop.
In DEV/LAB mode: records decisions and simulates enforcement with clear labeling.
In LIVE mode: executes real K8s/Cilium actions.

NO artificial sleep() calls — timing comes from actual operations.
"""

import time
import logging
from datetime import datetime, timezone
from typing import Optional, Callable

import httpx
from backend.config import settings
from backend.core.event_schema import (
    DiagnosisResult, MitigationAction, Incident, IncidentPhase,
    IncidentTimelineEntry, Severity, ServiceCriticality
)

logger = logging.getLogger("sentinel.pipeline.orchestrator")


# Service criticality mapping
SERVICE_CRITICALITY = {
    "vitals": ServiceCriticality.CRITICAL,
    "drug-dispenser": ServiceCriticality.CRITICAL,
    "ehr": ServiceCriticality.IMPORTANT,
    "billing": ServiceCriticality.NON_CRITICAL,
}


class MAPEKOrchestrator:
    """
    MAPE-K autonomous remediation loop.
    Monitor → Analyze → Plan → Execute → Knowledge
    """

    def __init__(self):
        self.actions_executed: list[MitigationAction] = []
        self.total_actions = 0
        self._on_action_callback: Optional[Callable] = None
        self._on_incident_update: Optional[Callable] = None

    def set_callbacks(self, on_action: Callable = None, on_incident_update: Callable = None):
        """Set callbacks for real-time notifications."""
        self._on_action_callback = on_action
        self._on_incident_update = on_incident_update

    def _notify_action(self, action: MitigationAction):
        if self._on_action_callback:
            self._on_action_callback(action)

    def _notify_incident(self, incident: Incident):
        if self._on_incident_update:
            self._on_incident_update(incident)

    def _call_external(self, diagnosis: DiagnosisResult, incident: Incident) -> Optional[MitigationAction]:
        """Delegate remediation to external MAPE-K controller over HTTP if enabled."""
        if not getattr(settings, "mape_k_enabled", False) or settings.is_dev:
            return None
        try:
            resp = httpx.post(
                f"{settings.mape_k_controller_url}/remediate",
                json={
                    "pod_name": diagnosis.pod_name,
                    "namespace": diagnosis.namespace,
                    "alert_name": incident.incident_id,
                },
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                is_crit = SERVICE_CRITICALITY.get(diagnosis.pod_name) == ServiceCriticality.CRITICAL
                start_ts = None
                if "started_at" in data and data["started_at"]:
                    try:
                        start_ts = datetime.fromisoformat(data["started_at"])
                    except Exception:
                        start_ts = datetime.now(timezone.utc)
                end_ts = None
                if "completed_at" in data and data["completed_at"]:
                    try:
                        end_ts = datetime.fromisoformat(data["completed_at"])
                    except Exception:
                        end_ts = datetime.now(timezone.utc)

                action = MitigationAction(
                    correlation_id=incident.correlation_id,
                    incident_id=incident.incident_id,
                    action_type=data.get("action", "quarantine_only"),
                    pod_name=diagnosis.pod_name,
                    namespace=diagnosis.namespace,
                    root_cause=diagnosis.root_cause,
                    is_critical_service=is_crit,
                    confidence=diagnosis.confidence,
                    status="completed" if data.get("success") else "failed",
                    started_at=start_ts or datetime.now(timezone.utc),
                    completed_at=end_ts or datetime.now(timezone.utc),
                    duration_ms=data.get("mttr_ms"),
                    details=f"Executed via external MAPE-K controller: {data.get('action')}",
                    service_restored=bool(data.get("success", False)),
                )

                incident.mitigation_start_time = action.started_at
                incident.mitigation_end_time = action.completed_at
                incident.actions.append(action)

                if action.service_restored:
                    incident.phase = IncidentPhase.RECOVERED
                    incident.recovery_time = action.completed_at
                    if incident.detection_time and incident.recovery_time:
                        incident.mttr_ms = (
                            incident.recovery_time - incident.detection_time
                        ).total_seconds() * 1000
                    incident.resolved = True
                    incident.resolution = f"Auto-remediated via external {action.action_type}"
                else:
                    incident.phase = IncidentPhase.FAILED

                incident.timeline.append(IncidentTimelineEntry(
                    phase="execute",
                    title=f"External MAPE-K: {action.action_type}",
                    detail=action.details,
                    source_service="external_mape_k",
                    target_service=diagnosis.pod_name,
                    duration_ms=action.duration_ms,
                ))

                self._notify_action(action)
                self._notify_incident(incident)
                self.actions_executed.append(action)
                return action
        except Exception as e:
            logger.warning("External MAPE-K controller call failed (%s), falling back to in-process execution", e)
        return None

    def execute_loop(self, diagnosis: DiagnosisResult, incident: Incident) -> MitigationAction:
        """
        Execute the full MAPE-K loop for a diagnosis result.
        All timestamps come from real clock — delegating to external controller if available.
        """
        self.total_actions += 1

        # Try external MAPE-K controller first
        external_action = self._call_external(diagnosis, incident)
        if external_action is not None:
            return external_action

        pod_name = diagnosis.pod_name
        namespace = diagnosis.namespace
        root_cause = diagnosis.root_cause
        criticality = SERVICE_CRITICALITY.get(pod_name, ServiceCriticality.NON_CRITICAL)
        is_critical = criticality == ServiceCriticality.CRITICAL

        # ── MONITOR ──
        logger.info("[MONITOR] Alert for %s/%s — root_cause=%s confidence=%.3f",
                     namespace, pod_name, root_cause, diagnosis.confidence)

        incident.timeline.append(IncidentTimelineEntry(
            phase="monitor",
            title="MAPE-K Monitor: Alert received",
            detail=f"Root cause: {root_cause} (confidence: {diagnosis.confidence:.1%})",
            source_service="mape_k_orchestrator",
            target_service=pod_name,
            correlation_id=incident.correlation_id,
        ))
        incident.phase = IncidentPhase.MITIGATING
        self._notify_incident(incident)

        # ── ANALYZE ──
        logger.info("[ANALYZE] Service criticality: %s, confidence: %.3f",
                     criticality.value, diagnosis.confidence)

        if diagnosis.confidence < 0.3:
            logger.warning("[ANALYZE] Low confidence (%.3f) — flagging for manual review",
                          diagnosis.confidence)
            action = MitigationAction(
                correlation_id=incident.correlation_id,
                incident_id=incident.incident_id,
                action_type="manual_review",
                pod_name=pod_name,
                namespace=namespace,
                root_cause=root_cause,
                is_critical_service=is_critical,
                confidence=diagnosis.confidence,
                status="completed",
                details="Insufficient confidence for automated action. Manual review required.",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            )
            incident.timeline.append(IncidentTimelineEntry(
                phase="analyze",
                title="MAPE-K Analyze: Manual review required",
                detail=f"Confidence {diagnosis.confidence:.1%} below threshold for automated action",
                source_service="mape_k_orchestrator",
            ))
            incident.phase = IncidentPhase.MANUAL_REVIEW
            self._notify_action(action)
            self._notify_incident(incident)
            self.actions_executed.append(action)
            return action

        # ── PLAN ──
        action_type = self._select_action(root_cause, is_critical, criticality)
        logger.info("[PLAN] Selected action: %s (critical=%s, root_cause=%s)",
                     action_type, is_critical, root_cause)

        action = MitigationAction(
            correlation_id=incident.correlation_id,
            incident_id=incident.incident_id,
            action_type=action_type,
            pod_name=pod_name,
            namespace=namespace,
            root_cause=root_cause,
            is_critical_service=is_critical,
            confidence=diagnosis.confidence,
            status="executing",
            started_at=datetime.now(timezone.utc),
        )

        incident.timeline.append(IncidentTimelineEntry(
            phase="plan",
            title=f"MAPE-K Plan: {action_type}",
            detail=f"Action selected for {pod_name} (criticality: {criticality.value})",
            source_service="mape_k_orchestrator",
            target_service=pod_name,
        ))
        incident.mitigation_start_time = action.started_at
        self._notify_action(action)
        self._notify_incident(incident)

        # ── EXECUTE ──
        logger.info("[EXECUTE] Executing %s on %s/%s", action_type, namespace, pod_name)

        success = self._execute_action(action_type, pod_name, namespace, is_critical, action, incident)

        action.completed_at = datetime.now(timezone.utc)
        if action.started_at and action.completed_at:
            action.duration_ms = (action.completed_at - action.started_at).total_seconds() * 1000

        if success:
            action.status = "completed"
            action.service_restored = True
            logger.info("[EXECUTE] Action %s completed successfully (%.1fms)",
                        action_type, action.duration_ms or 0)
        else:
            action.status = "failed"
            logger.error("[EXECUTE] Action %s failed", action_type)

        # ── KNOWLEDGE ──
        incident.timeline.append(IncidentTimelineEntry(
            phase="knowledge",
            title=f"MAPE-K Knowledge: Action {'succeeded' if success else 'failed'}",
            detail=f"{action_type} on {pod_name}: duration={action.duration_ms:.0f}ms" if action.duration_ms else "",
            source_service="mape_k_orchestrator",
            target_service=pod_name,
            duration_ms=action.duration_ms,
        ))

        if success:
            incident.phase = IncidentPhase.RECOVERED
            incident.recovery_time = action.completed_at
            if incident.detection_time and incident.recovery_time:
                incident.mttr_ms = (
                    incident.recovery_time - incident.detection_time
                ).total_seconds() * 1000
            incident.resolved = True
            incident.resolution = f"Auto-remediated via {action_type}"
        else:
            incident.phase = IncidentPhase.FAILED

        incident.actions.append(action)
        incident.updated_at = datetime.now(timezone.utc)
        self._notify_action(action)
        self._notify_incident(incident)
        self.actions_executed.append(action)

        return action

    def _select_action(self, root_cause: str, is_critical: bool,
                       criticality: ServiceCriticality) -> str:
        """Select remediation action based on root cause and service criticality."""
        if root_cause == "compromise":
            if is_critical:
                return "failover_and_quarantine"
            else:
                return "quarantine_and_redeploy"
        elif root_cause == "dependency_failure":
            return "restart_dependency"
        elif root_cause == "network_partition":
            return "quarantine_only"
        elif root_cause == "resource_exhaustion":
            return "scale_resources"
        else:
            # Unknown cause — conservative action
            return "quarantine_only"

    def _execute_action(self, action_type: str, pod_name: str, namespace: str,
                        is_critical: bool, action: MitigationAction,
                        incident: Incident) -> bool:
        """
        Execute remediation action.
        In DEV mode: records the action but does not touch infrastructure.
        In LAB/LIVE mode: executes real K8s/Cilium operations.
        """
        if settings.is_dev:
            return self._execute_dev_mode(action_type, pod_name, namespace, action, incident)
        elif settings.kubernetes_enabled:
            return self._execute_k8s_mode(action_type, pod_name, namespace, is_critical, action, incident)
        else:
            return self._execute_dev_mode(action_type, pod_name, namespace, action, incident)

    def _execute_dev_mode(self, action_type: str, pod_name: str, namespace: str,
                          action: MitigationAction, incident: Incident) -> bool:
        """Dev mode: record the action, mark as successful, no infrastructure changes."""
        action.details = f"[DEV MODE] {action_type} recorded for {pod_name} — no infrastructure changes applied"

        incident.timeline.append(IncidentTimelineEntry(
            phase="execute",
            title=f"[DEV] {action_type} on {pod_name}",
            detail="Action recorded (dev mode — no real infrastructure changes)",
            source_service="mape_k_orchestrator",
            target_service=pod_name,
        ))

        return True

    def _execute_k8s_mode(self, action_type: str, pod_name: str, namespace: str,
                          is_critical: bool, action: MitigationAction,
                          incident: Incident) -> bool:
        """K8s mode: execute real remediation via Kubernetes API."""
        try:
            from kubernetes import client as k8s_client, config as k8s_config

            try:
                k8s_config.load_incluster_config()
            except Exception:
                k8s_config.load_kube_config()

            core_v1 = k8s_client.CoreV1Api()
            custom_api = k8s_client.CustomObjectsApi()
            apps_v1 = k8s_client.AppsV1Api()

            if action_type in ("quarantine_only", "quarantine_and_redeploy", "failover_and_quarantine"):
                # Label pod as suspect
                try:
                    core_v1.patch_namespaced_pod(
                        name=pod_name, namespace=namespace,
                        body={"metadata": {"labels": {"suspect": "true"}}}
                    )
                    action.details += f"Labeled {pod_name} as suspect. "
                except Exception as e:
                    logger.error("Failed to label pod: %s", e)

                # Apply Cilium deny-all policy
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
                    custom_api.create_namespaced_custom_object(
                        group="cilium.io", version="v2",
                        namespace=namespace, plural="ciliumnetworkpolicies",
                        body=policy,
                    )
                    action.cilium_policy_applied = f"quarantine-{pod_name}"
                    action.details += f"Cilium quarantine policy applied. "

                    incident.timeline.append(IncidentTimelineEntry(
                        phase="execute",
                        title="Cilium quarantine policy applied",
                        detail=f"Deny-all ingress/egress on {pod_name}",
                        source_service="cilium_cni",
                        target_service=pod_name,
                    ))
                except Exception as e:
                    if "already exists" in str(e).lower():
                        action.details += "Quarantine policy already exists. "
                    else:
                        logger.error("Failed to apply Cilium policy: %s", e)
                        action.error = str(e)
                        return False

            if action_type in ("quarantine_and_redeploy", "failover_and_quarantine"):
                # Delete the pod (deployment controller will recreate)
                try:
                    core_v1.delete_namespaced_pod(
                        name=pod_name, namespace=namespace,
                        grace_period_seconds=0,
                    )
                    action.pod_deleted = True
                    action.details += f"Pod {pod_name} deleted for redeployment. "

                    incident.timeline.append(IncidentTimelineEntry(
                        phase="execute",
                        title="Pod deleted for redeployment",
                        detail=f"{pod_name} will be recreated by deployment controller",
                        source_service="kubernetes_api",
                        target_service=pod_name,
                    ))
                except Exception as e:
                    logger.error("Failed to delete pod: %s", e)
                    action.error = str(e)

            if action_type == "restart_dependency":
                # Restart by scaling down then up
                try:
                    pod = core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
                    for ref in (pod.metadata.owner_references or []):
                        if ref.kind == "ReplicaSet":
                            rs = apps_v1.read_namespaced_replica_set(name=ref.name, namespace=namespace)
                            for rs_ref in (rs.metadata.owner_references or []):
                                if rs_ref.kind == "Deployment":
                                    dep_name = rs_ref.name
                                    dep = apps_v1.read_namespaced_deployment(name=dep_name, namespace=namespace)
                                    replicas = dep.spec.replicas or 1
                                    apps_v1.patch_namespaced_deployment_scale(
                                        name=dep_name, namespace=namespace,
                                        body={"spec": {"replicas": 0}},
                                    )
                                    apps_v1.patch_namespaced_deployment_scale(
                                        name=dep_name, namespace=namespace,
                                        body={"spec": {"replicas": replicas}},
                                    )
                                    action.pod_restarted = True
                                    action.details += f"Deployment {dep_name} restarted. "
                except Exception as e:
                    logger.error("Failed to restart dependency: %s", e)
                    action.error = str(e)

            return action.error is None

        except ImportError:
            logger.error("kubernetes package not available for K8s mode")
            action.error = "kubernetes package not installed"
            return False
        except Exception as e:
            logger.error("K8s execution failed: %s", e)
            action.error = str(e)
            return False
