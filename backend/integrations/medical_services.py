"""
SentinelCloud Medical Services Health Client
=============================================
Centralized health checker for the 4 medical microservices.
"""

import logging
from typing import Optional

import httpx

from backend.config import settings

logger = logging.getLogger("sentinel.integrations.medical")

SERVICE_URLS = {
    "vitals": lambda: settings.vitals_url,
    "drug-dispenser": lambda: settings.drug_dispenser_url,
    "ehr": lambda: settings.ehr_url,
    "billing": lambda: settings.billing_url,
}


async def check_service_health(service_name: str) -> dict:
    """Check health of a single medical service."""
    url_fn = SERVICE_URLS.get(service_name)
    if not url_fn:
        return {"name": service_name, "status": "unknown", "error": "Unknown service"}

    url = url_fn()
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{url}/health")
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "name": service_name,
                    "status": "healthy",
                    "uptime_seconds": data.get("uptime_seconds"),
                    "data": data,
                }
            else:
                return {"name": service_name, "status": "degraded", "status_code": resp.status_code}
    except Exception as e:
        return {"name": service_name, "status": "offline", "error": str(e)}


async def check_all_services() -> dict[str, dict]:
    """Check health of all medical services."""
    results = {}
    for name in SERVICE_URLS:
        results[name] = await check_service_health(name)
    return results


async def get_service_metrics(service_name: str) -> Optional[dict]:
    """Fetch /metrics from a medical service."""
    url_fn = SERVICE_URLS.get(service_name)
    if not url_fn:
        return None

    url = url_fn()
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{url}/metrics")
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return None


async def get_service_readiness(service_name: str) -> Optional[dict]:
    """Fetch /readiness from a medical service."""
    url_fn = SERVICE_URLS.get(service_name)
    if not url_fn:
        return None

    url = url_fn()
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{url}/readiness")
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return None
