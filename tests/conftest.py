try:
    import pytest
except ImportError:
    class _MockPytest:
        @staticmethod
        def fixture(func):
            return func
    pytest = _MockPytest()


@pytest.fixture
def sample_telemetry_event():
    from backend.core.event_schema import TelemetryEvent, TelemetrySource, DataMode
    return TelemetryEvent(
        source=TelemetrySource.LAB_TEST,
        data_mode=DataMode.LAB_TEST,
        pod_name="ehr",
        namespace="medical",
        syscall_name="sys_connect",
        binary="/usr/bin/curl",
        target="ehr:445",
        port=445,
        protocol="tcp",
        payload_size=128,
    )


@pytest.fixture
def sample_detection():
    from backend.core.event_schema import DetectionResult
    return DetectionResult(
        event_id="test-event-123",
        anomaly_score=0.85,
        anomaly_threshold=0.72,
        is_anomaly=True,
        model_name="HalfSpaceTrees",
        explanation="Test anomaly",
        confidence=0.9,
        feature_vector={"port": 445, "syscall_encoded": 0},
    )


@pytest.fixture
def sample_incident():
    from backend.core.event_schema import Incident, Severity, IncidentPhase
    return Incident(
        incident_id="SC-TEST-0001",
        correlation_id="corr-test-123",
        severity=Severity.HIGH,
        title="Test incident",
        description="Unit test incident",
        affected_pod="ehr",
        affected_namespace="medical",
        phase=IncidentPhase.DETECTED,
    )
