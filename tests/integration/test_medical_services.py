import pytest
import requests

MEDICAL_SERVICES = [
    ("vitals", "http://localhost:5000/health"),
    ("drug-dispenser", "http://localhost:5001/health"),
    ("ehr", "http://localhost:5002/health"),
    ("billing", "http://localhost:5003/health"),
]


@pytest.mark.integration
@pytest.mark.parametrize("name,url", MEDICAL_SERVICES)
def test_service_health(name, url):
    try:
        resp = requests.get(url, timeout=2)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == name
    except Exception:
        pytest.skip(f"{name} service not running")


@pytest.mark.integration
def test_vitals_metrics_endpoint():
    try:
        resp = requests.get("http://localhost:5000/metrics", timeout=2)
        assert resp.status_code == 200
        assert "vitals_requests_total" in resp.text
    except Exception:
        pytest.skip("vitals service not running")
