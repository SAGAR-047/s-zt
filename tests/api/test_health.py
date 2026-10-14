import pytest
from fastapi.testclient import TestClient
from backend.main import fastapi_app

client = TestClient(fastapi_app)


def get_token():
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "sentinel-admin-2026"})
    return resp.json()["token"]


def test_health_unauthenticated():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "sentinel-backend"
    assert data["status"] == "healthy"
    assert "mode" in data


def test_system_health_authenticated():
    token = get_token()
    resp = client.get("/api/system-health", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert "backend" in data
    assert data["backend"] == "online"
