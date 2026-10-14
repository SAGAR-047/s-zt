#!/usr/bin/env python3
"""
Authentication brute-force scenario: simulates multiple failed login attempts.
"""

import os
import sys
import argparse
import logging
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from safety import check_safety

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scenario.auth_bruteforce")

SENTINEL_API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:5050")


def send_telemetry(event: dict):
    try:
        headers = {}
        token = os.environ.get("SENTINEL_AUTH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        requests.post(
            f"{SENTINEL_API_URL}/api/telemetry/ingest",
            json=event,
            headers=headers,
            timeout=5
        )
    except Exception as e:
        logger.warning("Telemetry error: %s", e)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--namespace", default="medical")
    args = parser.parse_args()

    if not check_safety(args.target):
        sys.exit(1)

    logger.info("Simulating auth brute-force against %s", args.target)
    for i in range(5):
        send_telemetry({
            "pod_name": args.target,
            "namespace": args.namespace,
            "syscall_name": "sys_execve",
            "binary": "/usr/bin/curl",
            "target": f"http://{args.target}:5000/login",
            "port": 5000,
            "protocol": "tcp",
            "source": "lab_test",
            "params": {"username": "admin", "password": f"wrong{i}", "attempt": i + 1},
        })
    logger.info("Auth brute-force simulation complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
