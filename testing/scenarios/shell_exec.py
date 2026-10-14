#!/usr/bin/env python3
"""
Suspicious shell execution scenario: simulates spawning a shell inside the target pod.
"""

import os
import sys
import argparse
import logging
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from safety import check_safety

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scenario.shell_exec")

SENTINEL_API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:5050")


def send_telemetry(event: dict):
    try:
        headers = {}
        token = os.environ.get("SENTINEL_AUTH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        resp = requests.post(
            f"{SENTINEL_API_URL}/api/telemetry/ingest",
            json=event,
            headers=headers,
            timeout=5
        )
        if resp.status_code != 200:
            logger.warning("Telemetry response status %d: %s", resp.status_code, resp.text)
    except Exception as e:
        logger.warning("Telemetry error: %s", e)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--namespace", default="medical")
    args = parser.parse_args()

    if not check_safety(args.target):
        sys.exit(1)

    logger.info("Simulating shell execution on %s", args.target)
    # Send sys_execve event for /bin/sh
    send_telemetry({
        "pod_name": args.target,
        "namespace": args.namespace,
        "syscall_name": "sys_execve",
        "binary": "/bin/sh",
        "target": "",
        "port": 0,
        "protocol": "",
        "source": "lab_test",
        "params": {"argv": ["/bin/sh", "-c", "whoami"]},
    })
    # Send a second exec for a suspicious command
    send_telemetry({
        "pod_name": args.target,
        "namespace": args.namespace,
        "syscall_name": "sys_execve",
        "binary": "/bin/bash",
        "target": "",
        "port": 0,
        "protocol": "",
        "source": "lab_test",
        "params": {"argv": ["/bin/bash", "-c", "curl http://malicious.example.com"]},
    })
    logger.info("Shell execution simulation complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
