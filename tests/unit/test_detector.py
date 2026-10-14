import pytest
from backend.pipeline.detector import (
    StreamingAnomalyDetector,
    extract_features,
    extract_hmm_observation,
    ExIFFIExplainer,
    HMMSequenceDetector,
    SYSCALL_MAP,
    FILE_EXT_MAP,
)
from backend.core.event_schema import TelemetryEvent, TelemetrySource, DataMode


def test_extract_features_basic():
    event = TelemetryEvent(
        source=TelemetrySource.LAB_TEST,
        data_mode=DataMode.LAB_TEST,
        pod_name="vitals",
        syscall_name="sys_open",
        binary="/usr/bin/touch",
        target="/tmp/test.txt",
        port=0,
        payload_size=10,
    )
    features = extract_features(event)
    assert "syscall_encoded" in features
    assert "port" in features
    assert "file_ext_encoded" in features
    assert features["file_ext_encoded"] == FILE_EXT_MAP[".txt"]
    assert features["syscall_encoded"] == SYSCALL_MAP["sys_open"]


def test_extract_hmm_observation():
    event = TelemetryEvent(
        source=TelemetrySource.LAB_TEST,
        data_mode=DataMode.LAB_TEST,
        pod_name="ehr",
        syscall_name="sys_execve",
        binary="/bin/bash",
        port=0,
        payload_size=0,
    )
    obs = extract_hmm_observation(extract_features(event))
    assert len(obs) == 4
    assert obs[0] == SYSCALL_MAP["sys_execve"]


def test_detector_process_returns_result(sample_telemetry_event):
    detector = StreamingAnomalyDetector(n_trees=10, window_size=20, threshold=0.72)
    result = detector.process(sample_telemetry_event)
    assert result.event_id == sample_telemetry_event.event_id
    assert 0.0 <= result.anomaly_score <= 1.0
    assert result.model_name == "HalfSpaceTrees"
    assert result.events_processed == 1
    assert detector.events_processed == 1


def test_detector_status():
    detector = StreamingAnomalyDetector(n_trees=10, window_size=20, threshold=0.72)
    status = detector.status
    assert status["model_name"] == "HalfSpaceTrees"
    assert status["events_processed"] == 0
    assert "hmm" in status


def test_hmm_sequence_detector_initial_state():
    hmm = HMMSequenceDetector(n_states=3, window_size=5)
    assert hmm.is_trained is False
    assert hmm.status["trained"] is False
    assert hmm.status["window_fill"] == 0


def test_exiffi_explainer_zero_score():
    explainer = ExIFFIExplainer(["a", "b", "c"])
    contrib = explainer.explain({"a": 1.0, "b": 2.0, "c": 0.0}, 0.0)
    assert contrib == {"a": 0.0, "b": 0.0, "c": 0.0}
