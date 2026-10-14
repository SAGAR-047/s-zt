#!/usr/bin/env python3
"""
DNS exfiltration scenario: simulates suspicious DNS query from target pod.
"""

import os
import sys
import argparse
import logging
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from safety import check_safety

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scenario.dns_exfil")

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

    logger.info("Simulating DNS exfiltration from %s", args.target)
    # Suspicious DNS query with long subdomain
    suspicious_domain = "a" * 50 + ".exfil.example.com"
    send_telemetry({
        "pod_name": args.target,
        "namespace": args.namespace,
        "syscall_name": "sys_sendto",
        "binary": "/usr/bin/dig",
        "target": suspicious_domain,
        "port": 53,
        "protocol": "udp",
        "source": "lab_test",
        "params": {"query": suspicious_domain},
    })
    logger.info("DNS exfiltration simulation complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
