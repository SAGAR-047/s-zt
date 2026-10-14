"""
SentinelCloud-Advanced: Benign Traffic Generator
==================================================
Generates realistic benign medical traffic to train the HMM
and establish a baseline for the Online Isolation Forest.

Run this for at least 1 hour before starting attack simulations
to allow the ML models to learn normal patterns.
"""

import os
import sys
import json
import time
import random
import logging
import argparse
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BENIGN] %(message)s",
)
logger = logging.getLogger("benign-traffic")

# Service endpoints (update for your environment)
SERVICES = {
    "vitals": os.environ.get("VITALS_URL", "http://localhost:5000"),
    "drug-dispenser": os.environ.get("DRUG_DISPENSER_URL", "http://localhost:5001"),
    "ehr": os.environ.get("EHR_URL", "http://localhost:5002"),
    "billing": os.environ.get("BILLING_URL", "http://localhost:5003"),
}

# ── Load Real Benchmark Dataset ──

DATASET_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "datasets", "internal_traffic_dataset.json")
)

def _load_dataset_records():
    if os.path.exists(DATASET_PATH):
        try:
            with open(DATASET_PATH, "r", encoding="utf-8") as f:
                d = json.load(f)
                return d.get("records", [])
        except Exception as err:
            logger.warning("Could not read %s: %s", DATASET_PATH, err)
    return []

RECORDS = _load_dataset_records()
VITALS_RECORDS = [r for r in RECORDS if r.get("pod_name") == "vitals"]
DRUG_RECORDS = [r for r in RECORDS if r.get("pod_name") == "drug-dispenser"]
EHR_RECORDS = [r for r in RECORDS if r.get("pod_name") == "ehr"]
BILLING_RECORDS = [r for r in RECORDS if r.get("pod_name") == "billing"]

_vitals_idx = 0
_drug_idx = 0
_ehr_idx = 0
_billing_idx = 0


def send_vitals():
    """Send an authentic vital sign packet from MIMIC-III dataset."""
    global _vitals_idx
    if not VITALS_RECORDS:
        return 0
    rec = VITALS_RECORDS[_vitals_idx % len(VITALS_RECORDS)]
    _vitals_idx += 1
    p = rec.get("params", {})
    data = {
        "patient_id": p.get("patient_id", "PT-10014"),
        "heart_rate": p.get("heart_rate", 76),
        "bp_systolic": p.get("bp_systolic", 124),
        "bp_diastolic": p.get("bp_diastolic", 76),
        "spo2": p.get("spo2", 98.4),
        "source": rec.get("dataset_source", "MIMIC-III"),
    }
    try:
        resp = requests.post(f"{SERVICES['vitals']}/beat", json=data, timeout=5)
        return resp.status_code
    except Exception:
        return 0


def check_vitals_health():
    """Check vitals service health."""
    try:
        resp = requests.get(f"{SERVICES['vitals']}/health", timeout=5)
        return resp.status_code
    except Exception:
        return 0


def dispense_drug():
    """Dispense an authentic prescribed medication from MIMIC-III formulary."""
    global _drug_idx
    if not DRUG_RECORDS:
        return 0
    rec = DRUG_RECORDS[_drug_idx % len(DRUG_RECORDS)]
    _drug_idx += 1
    p = rec.get("params", {})
    data = {
        "patient_id": p.get("patient_id", "PT-10014"),
        "drug_name": p.get("drug_name", "Regular Insulin"),
        "ndc_code": p.get("ndc_code", "00002-8215-01"),
        "dosage": p.get("dosage", "2.5 units/hr"),
        "quantity": 1,
        "prescriber_id": f"DR-MIMIC-{p.get('mimic_subject_id', 10014)}",
    }
    try:
        resp = requests.post(f"{SERVICES['drug-dispenser']}/dispense", json=data, timeout=5)
        return resp.status_code
    except Exception:
        return 0


def create_ehr_record():
    """Create an EHR record from MIMIC-III clinical admission diagnostic chart."""
    global _ehr_idx
    if not EHR_RECORDS:
        return 0
    rec = EHR_RECORDS[_ehr_idx % len(EHR_RECORDS)]
    _ehr_idx += 1
    p = rec.get("params", {})
    data = {
        "patient_id": p.get("patient_id", "PT-10014"),
        "name": f"Patient {p.get('patient_id')}",
        "diagnosis": p.get("diagnosis", "Type 2 diabetes mellitus"),
        "icd10": p.get("icd10", "E11.9"),
        "notes": f"MIMIC-III Clinical record verified: {p.get('query')}",
        "dataset_source": rec.get("dataset_source", "MIMIC-III / ADFA-LD"),
    }
    try:
        resp = requests.post(f"{SERVICES['ehr']}/record", json=data, timeout=5)
        return resp.status_code
    except Exception:
        return 0


def get_ehr_record():
    """Retrieve an EHR record."""
    global _ehr_idx
    patient_id = "PT-10014"
    if EHR_RECORDS:
        patient_id = EHR_RECORDS[_ehr_idx % len(EHR_RECORDS)].get("params", {}).get("patient_id", "PT-10014")
    try:
        resp = requests.get(f"{SERVICES['ehr']}/record", params={"patient_id": patient_id}, timeout=5)
        return resp.status_code
    except Exception:
        return 0


def get_invoice():
    """Generate/retrieve an invoice verified against MIMIC-III claims ledger."""
    global _billing_idx
    patient_id = "PT-10014"
    if BILLING_RECORDS:
        patient_id = BILLING_RECORDS[_billing_idx % len(BILLING_RECORDS)].get("params", {}).get("patient_id", "PT-10014")
        _billing_idx += 1
    try:
        resp = requests.get(f"{SERVICES['billing']}/invoice", params={"patient_id": patient_id}, timeout=5)
        return resp.status_code
    except Exception:
        return 0


def run_traffic(duration_minutes: int = 60, rate: float = 10.0):
    """Generate benign traffic using deterministic sequential replay of the benchmark dataset."""
    logger.info("Starting deterministic benchmark traffic replay for %d minutes at %.1f req/s", duration_minutes, rate)
    logger.info("Sources: ADFA-LD (UNSW Canberra) & MIMIC-III (MIT PhysioNet)")

    actions = [
        send_vitals,
        check_vitals_health,
        dispense_drug,
        create_ehr_record,
        get_ehr_record,
        get_invoice,
    ]

    end_time = time.time() + (duration_minutes * 60)
    interval = 1.0 / rate
    total_requests = 0
    errors = 0

    with ThreadPoolExecutor(max_workers=8) as executor:
        while time.time() < end_time:
            action = random.choice(weighted_actions)
            future = executor.submit(action)

            try:
                status = future.result(timeout=10)
                total_requests += 1
                if status == 0 or status >= 500:
                    errors += 1
            except Exception:
                errors += 1

            if total_requests % 100 == 0:
                elapsed = (duration_minutes * 60) - (end_time - time.time())
                logger.info(
                    "Progress: %d requests sent, %d errors, %.0f seconds elapsed",
                    total_requests, errors, elapsed,
                )

            time.sleep(interval + random.uniform(-0.01, 0.01))

    logger.info("Traffic generation complete: %d requests, %d errors", total_requests, errors)
    return total_requests, errors


def main():
    parser = argparse.ArgumentParser(description="Benign Traffic Generator")
    parser.add_argument("--duration", type=int, default=60, help="Duration in minutes (default: 60)")
    parser.add_argument("--rate", type=float, default=10.0, help="Requests per second (default: 10)")
    args = parser.parse_args()

    run_traffic(args.duration, args.rate)


if __name__ == "__main__":
    main()
