import pytest
from unittest.mock import patch
from backend.config import Settings
from backend.pipeline.orchestrator import MAPEKOrchestrator, SERVICE_CRITICALITY
from backend.core.event_schema import (
    DiagnosisResult, Incident, Severity, IncidentPhase, MitigationAction
)


def test_select_action_compromise_critical():
    orch = MAPEKOrchestrator()
    action = orch._select_action("compromise", True, SERVICE_CRITICALITY["vitals"])
    assert action == "failover_and_quarantine"


def test_select_action_compromise_noncritical():
    orch = MAPEKOrchestrator()
    action = orch._select_action("compromise", False, SERVICE_CRITICALITY["billing"])
    assert action == "quarantine_and_redeploy"


def test_select_action_dependency():
    orch = MAPEKOrchestrator()
    action = orch._select_action("dependency_failure", False, SERVICE_CRITICALITY["ehr"])
    assert action == "restart_dependency"


def test_execute_dev_mode_records_without_infra():
    orch = MAPEKOrchestrator()
    with patch.object(Settings, "is_dev", property(lambda self: True)):
        action = MitigationAction(
            action_type="quarantine_only",
            pod_name="ehr",
            namespace="medical",
            root_cause="compromise",
        )
        incident = Incident(
            incident_id="test-incident",
            correlation_id="corr-test",
            severity=Severity.HIGH,
            title="Test incident",
            affected_pod="ehr",
            phase=IncidentPhase.MITIGATING,
        )
        success = orch._execute_dev_mode(
            action_type=action.action_type,
            pod_name=action.pod_name,
            namespace=action.namespace,
            action=action,
            incident=incident,
        )
        assert success is True
        assert "[DEV MODE]" in action.details
        assert incident.phase == IncidentPhase.MITIGATING
