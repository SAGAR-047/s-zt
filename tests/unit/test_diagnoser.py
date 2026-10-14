import pytest
from backend.pipeline.diagnoser import DiagnosisEngine
from backend.core.event_schema import TelemetryEvent, TelemetrySource, DataMode, DetectionResult


def create_event(pod_name, syscall, binary="", target="", port=0, is_alert=False):
    return TelemetryEvent(
        source=TelemetrySource.LAB_TEST,
        data_mode=DataMode.LAB_TEST,
        pod_name=pod_name,
        namespace="medical",
        syscall_name=syscall,
        binary=binary,
        target=target,
        port=port,
        is_alert=is_alert,
    )


def test_diagnosis_no_events_returns_unknown():
    engine = DiagnosisEngine(lookback_size=10)
    result = engine.diagnose("ehr", "medical")
    assert result.root_cause == "unknown"
    assert result.confidence == 0.0
    assert result.events_analyzed == 0


def test_diagnosis_shell_exec_detected():
    engine = DiagnosisEngine(lookback_size=10)
    engine.add_event(create_event("ehr", "sys_execve", binary="/bin/bash", is_alert=True))
    engine.add_event(create_event("ehr", "sys_connect", target="refused", port=80))
    result = engine.diagnose("ehr", "medical")
    assert result.root_cause == "compromise"
    assert result.confidence > 0.5
    assert any("Shell execution" in e for e in result.evidence)
    assert len(result.mitre_techniques) > 0
    assert any(t.technique_id == "T1059.004" for t in result.mitre_techniques)


def test_diagnosis_ransomware_rename():
    engine = DiagnosisEngine(lookback_size=10)
    engine.add_event(create_event("ehr", "sys_rename", target="/data/records.db.locked", is_alert=True))
    result = engine.diagnose("ehr", "medical")
    assert result.root_cause == "compromise"
    assert result.confidence > 0.8
    assert any("Suspicious file rename" in e for e in result.evidence)


def test_diagnosis_dependency_failure():
    engine = DiagnosisEngine(lookback_size=10)
    engine.add_event(create_event("vitals", "sys_connect", target="timeout", port=5000))
    engine.add_event(create_event("ehr", "sys_connect", target="refused", port=5002, is_alert=True))
    engine.add_event(create_event("billing", "sys_connect", target="refused", port=5003, is_alert=True))
    result = engine.diagnose("vitals", "medical")
    # The presence of anomalies in other pods may indicate dependency failure
    assert result.root_cause in ["compromise", "dependency_failure", "network_partition"]
