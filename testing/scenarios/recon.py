#!/usr/bin/env python3
"""
Reconnaissance scenario: performs TCP connect scan on common ports of the target service.
"""

import os
import sys
import socket
import argparse
import logging
import requests
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from safety import check_safety

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scenario.recon")

SENTINEL_API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:5050")


def send_telemetry(event: dict):
    """Send a telemetry event to SentinelCloud backend."""
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
        if resp.status_code == 200:
            logger.debug("Telemetry sent: %s", event)
        else:
            logger.warning("Telemetry response status %d: %s", resp.status_code, resp.text)
    except Exception as e:
        logger.warning("Telemetry send error: %s", e)


def scan_port(target: str, port: int, namespace: str) -> bool:
    """Attempt TCP connection to target:port and return True if open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    open_port = False
    try:
        result = sock.connect_ex((target, port))
        open_port = (result == 0)
    except Exception as e:
        logger.debug("Connect check on %s:%d: %s", target, port, e)
    finally:
        sock.close()

    # Emit telemetry event
    send_telemetry({
        "pod_name": target,
        "namespace": namespace,
        "syscall_name": "sys_connect",
        "binary": "/usr/bin/nmap",
        "target": f"{target}:{port}",
        "port": port,
        "protocol": "tcp",
        "source": "lab_test",
        "params": {"scan": "recon", "port": port, "open": open_port},
    })
    return open_port


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--namespace", default="medical")
    args = parser.parse_args()

    if not check_safety(args.target):
        sys.exit(1)

    logger.info("Starting reconnaissance against %s", args.target)
    common_ports = [22, 80, 443, 5000, 5001, 5002, 5003, 8080, 8081, 9092, 9000]
    open_ports = []
    for port in common_ports:
        if scan_port(args.target, port, args.namespace):
            open_ports.append(port)
            logger.info("Port %d is open", port)
    logger.info("Recon complete. Open ports detected: %s", open_ports)
    return 0


if __name__ == "__main__":
    sys.exit(main())
