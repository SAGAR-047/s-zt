import pytest
from fastapi.testclient import TestClient
from backend.main import fastapi_app

client = TestClient(fastapi_app)


def test_login_success():
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "sentinel-admin-2026"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["authenticated"] is True
    assert "token" in data
    assert data["role"] == "admin"


def test_login_failure():
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_verify_token():
    login = client.post("/api/auth/login", json={"username": "admin", "password": "sentinel-admin-2026"})
    token = login.json()["token"]
    resp = client.get("/api/auth/verify", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["authenticated"] is True
    assert data["username"] == "admin"


def test_missing_auth():
    resp = client.get("/api/system-health")
    assert resp.status_code == 401
