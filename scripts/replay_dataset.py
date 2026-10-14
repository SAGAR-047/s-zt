#!/usr/bin/env python3
"""
SentinelCloud-Advanced: Dataset Replay Ingestion Client
-------------------------------------------------------
Streams preprocessed JSON telemetry events into the SentinelCloud backend.
"""

import os
import sys
import json
import time
import argparse
import requests
from datetime import datetime

API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:5050")
USERNAME = os.environ.get("SENTINEL_USERNAME", "admin")
PASSWORD = os.environ.get("SENTINEL_PASSWORD", "sentinel-admin-2026")


def login() -> str:
    """Authenticate and obtain JWT token."""
    try:
        resp = requests.post(
            f"{API_URL}/api/auth/login",
            json={"username": USERNAME, "password": PASSWORD},
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"Login failed: {resp.status_code} {resp.text}")
            sys.exit(1)
        token = resp.json().get("token")
        print(f"Authenticated successfully as '{USERNAME}'")
        return token
    except Exception as e:
        print(f"Failed to connect to backend at {API_URL}: {e}")
        sys.exit(1)


def send_event(token: str, event: dict) -> tuple[bool, float]:
    """Send event to telemetry ingest endpoint, returns (success, anomaly_score)."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    event.setdefault("source", "replay")
    try:
        resp = requests.post(
            f"{API_URL}/api/telemetry/ingest",
            json=event,
            headers=headers,
            timeout=5,
        )
        if resp.status_code == 200:
            score = resp.json().get("anomaly_score", 0.0)
            return True, score
        return False, 0.0
    except Exception:
        return False, 0.0


def main():
    parser = argparse.ArgumentParser(description="Replay telemetry events into SentinelCloud")
    parser.add_argument("events_file", help="Path to JSON file containing events list")
    parser.add_argument("--rate", type=float, default=50.0, help="Events per second to send (default: 50)")
    parser.add_argument("--max-events", type=int, default=0, help="Max events to send (0 = all)")
    args = parser.parse_args()

    if not os.path.exists(args.events_file):
        print(f"File not found: {args.events_file}")
        sys.exit(1)

    with open(args.events_file, "r") as f:
        events = json.load(f)

    if not isinstance(events, list):
        print("Invalid format: expected JSON array of event objects")
        sys.exit(1)

    if args.max_events > 0:
        events = events[:args.max_events]

    token = login()
    print(f"Loaded {len(events)} events from {args.events_file}")
    print(f"Streaming at up to {args.rate} events/sec into {API_URL}...")

    interval = 1.0 / args.rate if args.rate > 0 else 0
    success = 0
    anomalies = 0
    start_time = time.time()

    for i, ev in enumerate(events):
        t0 = time.time()
        ok, score = send_event(token, ev)
        if ok:
            success += 1
            if score > 0.72:
                anomalies += 1
        else:
            print(f"  [WARN] Failed to send event #{i}")

        if (i + 1) % 50 == 0 or (i + 1) == len(events):
            elapsed = time.time() - start_time
            current_rate = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"  Progress: {i + 1}/{len(events)} events sent | "
                  f"Rate: {current_rate:.1f} ev/s | "
                  f"Anomalies flagged: {anomalies}")

        elapsed_event = time.time() - t0
        sleep_time = interval - elapsed_event
        if sleep_time > 0:
            time.sleep(sleep_time)

    total_time = time.time() - start_time
    print("\n════════════════════════════════════════════════════════")
    print(f"  Replay Summary:")
    print(f"  Total sent:      {success}/{len(events)}")
    print(f"  Anomalies:       {anomalies}")
    print(f"  Elapsed time:    {total_time:.2f}s ({success / total_time:.1f} ev/s)")
    print("════════════════════════════════════════════════════════")


if __name__ == "__main__":
    main()
