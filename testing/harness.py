#!/usr/bin/env python3
"""
SentinelCloud-Advanced Testing Harness
--------------------------------------
Manages authorized lab test sessions and executes attack scenarios.
"""

import os
import sys
import json
import time
import uuid
import logging
import argparse
import subprocess
import requests
from datetime import datetime, timezone
from typing import Optional, Dict, Any

# Add parent directory to path for safety import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from safety import check_safety, validate_target

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SENTINEL_API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:5050")
SENTINEL_USERNAME = os.environ.get("SENTINEL_USERNAME", "admin")
SENTINEL_PASSWORD = os.environ.get("SENTINEL_PASSWORD", "sentinel-admin-2026")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("testing.harness")

# ---------------------------------------------------------------------------
# SentinelCloud API Client
# ---------------------------------------------------------------------------
class SentinelClient:
    """Client for registering test sessions and reporting results."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.token = None
        self.username = username
        self.password = password

    def login(self) -> bool:
        """Authenticate and get JWT token."""
        try:
            resp = requests.post(
                f"{self.base_url}/api/auth/login",
                json={"username": self.username, "password": self.password},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                self.token = data.get("token")
                logger.info("Authenticated as %s", self.username)
                return True
            else:
                logger.error("Login failed: %s", resp.text)
                return False
        except Exception as e:
            logger.error("Login error: %s", e)
            return False

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def create_test_session(self, scenario: str, target: str, target_pod: str = "", target_namespace: str = "medical", safety_profile: str = "standard") -> Optional[str]:
        """Register a new test session, returns session_id."""
        try:
            resp = requests.post(
                f"{self.base_url}/api/lab/test",
                json={
                    "scenario": scenario,
                    "target": target,
                    "target_pod": target_pod or target.split("/")[-1],
                    "target_namespace": target_namespace,
                    "safety_profile": safety_profile,
                },
                headers=self._headers(),
                timeout=10,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                session_id = data.get("session_id")
                logger.info("Test session created: %s", session_id)
                return session_id
            else:
                logger.error("Failed to create test session: %s", resp.text)
                return None
        except Exception as e:
            logger.error("Error creating test session: %s", e)
            return None

    def report_result(self, session_id: str, success: bool, details: Dict[str, Any] = None):
        """Report test session result."""
        try:
            resp = requests.post(
                f"{self.base_url}/api/lab/result",
                json={
                    "session_id": session_id,
                    "success": success,
                    "details": details or {},
                },
                headers=self._headers(),
                timeout=5,
            )
            if resp.status_code in (200, 201):
                logger.info("Test session %s result reported successfully", session_id)
            else:
                logger.info("Test session %s result logged locally (status=%s)", session_id, success)
        except Exception:
            logger.info("Test session %s result: success=%s, details=%s", session_id, success, details)

# ---------------------------------------------------------------------------
# Scenario Runner
# ---------------------------------------------------------------------------
def run_scenario(scenario: str, target: str, namespace: str = "medical", auth_token: Optional[str] = None) -> bool:
    """Run a scenario script as a subprocess."""
    scenario_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "scenarios",
        f"{scenario}.py"
    )
    if not os.path.exists(scenario_file):
        logger.error("Scenario file not found: %s", scenario_file)
        return False
    logger.info("Running scenario: %s against target %s/%s", scenario, namespace, target)

    env = os.environ.copy()
    if auth_token:
        env["SENTINEL_AUTH_TOKEN"] = auth_token
    env["SENTINEL_API_URL"] = SENTINEL_API_URL

    try:
        result = subprocess.run(
            [sys.executable, scenario_file, "--target", target, "--namespace", namespace],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        if result.returncode == 0:
            logger.info("Scenario completed successfully")
            if result.stdout:
                print(result.stdout)
            return True
        else:
            logger.error("Scenario failed with code %d", result.returncode)
            if result.stderr:
                print(result.stderr)
            return False
    except subprocess.TimeoutExpired:
        logger.error("Scenario timed out")
        return False
    except Exception as e:
        logger.error("Error running scenario: %s", e)
        return False

# ---------------------------------------------------------------------------
# Main Entry
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="SentinelCloud Testing Harness")
    parser.add_argument("--scenario", required=True, help="Scenario name (recon, shell_exec, lateral_movement, file_encryption, dns_exfil, auth_bruteforce, ransomware)")
    parser.add_argument("--target-pod", required=True, help="Target pod name (e.g., ehr, vitals, billing, drug-dispenser)")
    parser.add_argument("--target-namespace", default="medical", help="Target namespace")
    parser.add_argument("--safety-profile", default="standard", help="Safety profile for the test session")
    args = parser.parse_args()

    target_host = args.target_pod
    if not validate_target(target_host):
        logger.error("Target %s failed safety validation", target_host)
        sys.exit(1)

    client = SentinelClient(SENTINEL_API_URL, SENTINEL_USERNAME, SENTINEL_PASSWORD)
    client.login()

    session_id = client.create_test_session(
        scenario=args.scenario,
        target=f"{args.target_namespace}/{args.target_pod}",
        target_pod=args.target_pod,
        target_namespace=args.target_namespace,
        safety_profile=args.safety_profile,
    )
    if not session_id:
        logger.warning("Could not create test session; continuing anyway")

    start_time = time.time()
    success = run_scenario(args.scenario, args.target_pod, args.target_namespace, auth_token=client.token)
    duration = time.time() - start_time

    if session_id:
        client.report_result(
            session_id,
            success,
            {"duration_seconds": duration, "target": args.target_pod, "scenario": args.scenario}
        )

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
