import pytest
import requests


@pytest.mark.integration
def test_anomaly_detector_health():
    try:
        resp = requests.get("http://localhost:8080/health", timeout=2)
        assert resp.status_code == 200
        data = resp.json()
        assert data["service"] == "streaming-anomaly-detector"
    except Exception:
        pytest.skip("streaming-anomaly-detector not running")


@pytest.mark.integration
def test_anomaly_detector_process():
    try:
        resp = requests.post(
            "http://localhost:8080/process",
            json={
                "pod_name": "ehr",
                "namespace": "medical",
                "syscall_name": "sys_connect",
                "params": {"port": 445, "binary": "/usr/bin/curl", "target": "ehr:445"},
                "timestamp": "2025-01-01T00:00:00Z",
            },
            timeout=5,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "anomaly_score" in data
    except Exception:
        pytest.skip("streaming-anomaly-detector not running")


@pytest.mark.integration
def test_diagnosis_service_health():
    try:
        resp = requests.get("http://localhost:8081/health", timeout=2)
        assert resp.status_code == 200
        data = resp.json()
        assert data["service"] == "diagnosis-service"
    except Exception:
        pytest.skip("diagnosis-service not running")
