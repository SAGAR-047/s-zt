import pytest
from fastapi.testclient import TestClient
from backend.main import fastapi_app

client = TestClient(fastapi_app)


def get_token():
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "sentinel-admin-2026"})
    return resp.json()["token"]


def test_trigger_incident_and_list():
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

    resp2 = client.get("/api/incidents/", headers=headers)
    assert resp2.status_code == 200
    data = resp2.json()
    assert "incidents" in data
