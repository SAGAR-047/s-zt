#!/usr/bin/env python3
"""
File encryption scenario: simulates ransomware-like file rename on target.
"""

import os
import sys
import argparse
import logging
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from safety import check_safety

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scenario.file_encryption")

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

    logger.info("Simulating file encryption on %s", args.target)
    # Send sys_rename event for a file renamed to .locked
    send_telemetry({
        "pod_name": args.target,
        "namespace": args.namespace,
        "syscall_name": "sys_rename",
        "binary": "/bin/mv",
        "target": "/data/patient_records.db.locked",
        "port": 0,
        "protocol": "",
        "source": "lab_test",
        "params": {"old_path": "/data/patient_records.db", "new_path": "/data/patient_records.db.locked"},
    })
    logger.info("File encryption simulation complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
