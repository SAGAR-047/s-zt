import pytest
from fastapi.testclient import TestClient
from backend.main import fastapi_app

client = TestClient(fastapi_app)


def get_token():
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "sentinel-admin-2026"})
    return resp.json()["token"]


def test_ingest_event_and_recent():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "pod_name": "ehr",
        "namespace": "medical",
        "syscall_name": "sys_connect",
        "binary": "/usr/bin/curl",
        "target": "ehr:445",
        "port": 445,
        "protocol": "tcp",
        "source": "lab_test",
    }
    resp = client.post("/api/telemetry/ingest", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "event_id" in data
    assert "anomaly_score" in data

    # Fetch recent events
    resp2 = client.get("/api/telemetry/recent?limit=10", headers=headers)
    assert resp2.status_code == 200
    events = resp2.json()["events"]
    assert any(e["pod_name"] == "ehr" for e in events)


def test_get_recent_events_empty():
    token = get_token()
    resp = client.get("/api/telemetry/recent?limit=5", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert "events" in resp.json()
