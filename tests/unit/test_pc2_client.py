import pytest
from unittest.mock import MagicMock, patch
from testing.pc2_client import PC2Client, SCENARIO_CATALOG, load_config
from testing.safety import validate_target, is_ip_allowed


def test_scenario_catalog_completeness():
    expected_scenarios = {"shell_exec", "ransomware", "recon", "lateral_movement", "file_encryption", "dns_exfil"}
    for sc in expected_scenarios:
        assert sc in SCENARIO_CATALOG
        assert "expected_syscall" in SCENARIO_CATALOG[sc]
        assert "min_score" in SCENARIO_CATALOG[sc]


def test_safety_validation():
    assert validate_target("ehr") is True
    assert validate_target("vitals") is True
    assert validate_target("drug-dispenser") is True
    assert validate_target("billing") is True
    assert validate_target("localhost") is True
    assert validate_target("127.0.0.1") is True
    assert validate_target("unknown_evil_target.com") is False


def test_is_ip_allowed():
    assert is_ip_allowed("127.0.0.1") is True
    assert is_ip_allowed("192.168.1.50") is True
    assert is_ip_allowed("10.0.0.5") is True
    assert is_ip_allowed("8.8.8.8") is False


def test_pc2_client_reachability_mock():
    client = PC2Client(base_url="http://mock-pc1:5050")
    with patch.object(client.session, "get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "service": "sentinel-backend",
            "status": "healthy",
            "mode": "dev",
            "timestamp": "2026-10-14T00:00:00Z",
        }
        mock_get.return_value = mock_resp

        status = client.check_reachability()
        assert status["reachable"] is True
        assert status["mode"] == "dev"
        assert status["service"] == "sentinel-backend"


def test_pc2_client_login_mock():
    client = PC2Client(base_url="http://mock-pc1:5050")
    with patch.object(client.session, "post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "authenticated": True,
            "token": "mock-jwt-token",
            "role": "admin",
        }
        mock_post.return_value = mock_resp

        success = client.login()
        assert success is True
        assert client.token == "mock-jwt-token"
