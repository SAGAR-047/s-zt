"""
SentinelCloud Diagnosis Engine (In-Process)
============================================
Evidence-driven root cause analysis.
In LAB/DEV mode, runs analysis on in-memory event buffer.
In LIVE mode, delegates to the diagnosis-service over HTTP.
"""

import logging
from collections import deque
from typing import Optional

import httpx
from backend.config import settings
from backend.core.event_schema import (
    TelemetryEvent, DiagnosisResult, MitreTechnique, DetectionResult
)

logger = logging.getLogger("sentinel.pipeline.diagnoser")


SHELL_BINARIES = {"sh", "bash", "zsh", "/bin/sh", "/bin/bash", "/usr/bin/sh",
                  "/usr/bin/bash", "/bin/zsh", "/usr/bin/zsh"}
RANSOMWARE_EXTENSIONS = {".locked", ".encrypted", ".crypto", ".ransom", ".crypt"}
SMB_PORT = 445
DNS_PORT = 53

# MITRE ATT&CK mapping
MITRE_MAP = {
    "shell_exec": MitreTechnique(
        technique_id="T1059.004",
        technique_name="Command and Scripting Interpreter: Unix Shell",
        evidence="Shell execution detected",
        confidence=0.0,
    ),
    "smb_lateral": MitreTechnique(
        technique_id="T1021.002",
        technique_name="Remote Services: SMB/Windows Admin Shares",
        evidence="SMB port 445 connection attempt",
        confidence=0.0,
    ),
    "file_encrypt": MitreTechnique(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        evidence="Mass file rename to ransomware extension",
        confidence=0.0,
    ),
    "dns_exfil": MitreTechnique(
        technique_id="T1071.004",
        technique_name="Application Layer Protocol: DNS",
        evidence="Suspicious DNS query pattern",
        confidence=0.0,
    ),
    "priv_escalation": MitreTechnique(
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        evidence="Privilege escalation attempt",
        confidence=0.0,
    ),
    "network_recon": MitreTechnique(
        technique_id="T1046",
        technique_name="Network Service Discovery",
        evidence="Port scanning or service discovery detected",
        confidence=0.0,
    ),
    "behavioral_anomaly": MitreTechnique(
        technique_id="T1204",
        technique_name="User Execution: Malicious Process",
        evidence="Statistical system call distribution anomaly",
        confidence=0.0,
    ),
}


class DiagnosisEngine:
    """In-process diagnosis engine that correlates recent events."""

    def __init__(self, lookback_size: int = 200):
        self.event_buffer: deque[TelemetryEvent] = deque(maxlen=lookback_size)
        self.detection_buffer: deque[DetectionResult] = deque(maxlen=100)
        self.diagnoses_count = 0

    def add_event(self, event: TelemetryEvent):
        """Buffer events for correlation."""
        self.event_buffer.append(event)

    def add_detection(self, detection: DetectionResult):
        """Buffer detections for correlation."""
        self.detection_buffer.append(detection)

    def _call_external(self, pod_name: str, namespace: str = "medical",
                       correlation_id: Optional[str] = None,
                       events: Optional[list[TelemetryEvent]] = None) -> Optional[DiagnosisResult]:
        """Call external diagnosis service if configured and available."""
        if not getattr(settings, "diagnosis_enabled", True) or not settings.diagnosis_service_url:
            return None
        try:
            payload = {"pod_name": pod_name, "namespace": namespace}
            if events:
                payload["events"] = [e.model_dump(mode="json") for e in events]

            resp = httpx.post(
                f"{settings.diagnosis_service_url}/diagnose",
                json=payload,
                timeout=5.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                root_cause = data.get("root_cause", "unknown")
                confidence = float(data.get("confidence", 0.0))
                # Only accept external result if it actually diagnosed a root cause
                if root_cause == "unknown" or confidence <= 0.0:
                    return None

                mitre_techniques = []
                for t in data.get("mitre_techniques", []):
                    try:
                        mitre_techniques.append(MitreTechnique(
                            technique_id=t.get("technique_id", ""),
                            technique_name=t.get("technique_name", ""),
                            evidence=t.get("evidence", ""),
                            confidence=float(t.get("confidence", 0.0)),
                        ))
                    except Exception:
                        pass

                return DiagnosisResult(
                    correlation_id=correlation_id,
                    pod_name=pod_name,
                    namespace=namespace,
                    root_cause=root_cause,
                    confidence=confidence,
                    evidence=data.get("evidence", []),
                    conflicting_evidence=[],
                    affected_assets=[pod_name],
                    mitre_techniques=mitre_techniques,
                    scores=data.get("scores", {}),
                    events_analyzed=int(data.get("events_analysed", 0)),
                    recommended_action=data.get("recommended_action", "manual_investigation"),
                )
        except Exception as e:
            logger.debug("External diagnosis service unreachable (%s), using in-process engine", e)
        return None

    def diagnose(self, pod_name: str, namespace: str = "medical",
                 correlation_id: Optional[str] = None) -> DiagnosisResult:
        """
        Analyze recent events for a pod and determine root cause.
        Returns real evidence-based diagnosis — delegating to external service if available.
        """
        self.diagnoses_count += 1

        # Get recent events for this pod
        pod_events = [e for e in self.event_buffer if e.pod_name == pod_name]
        all_events = list(self.event_buffer)

        # Try external diagnosis service first, passing buffered events
        external_result = self._call_external(pod_name, namespace, correlation_id, events=pod_events[-30:] if pod_events else None)
        if external_result is not None:
            return external_result

        evidence: list[str] = []
        conflicting: list[str] = []
        affected: list[str] = [pod_name]
        mitre: list[MitreTechnique] = []
        scores = {"compromise": 0.0, "dependency_failure": 0.0,
                  "network_partition": 0.0, "resource_exhaustion": 0.0}

        if not pod_events:
            return DiagnosisResult(
                correlation_id=correlation_id,
                pod_name=pod_name,
                namespace=namespace,
                root_cause="unknown",
                confidence=0.0,
                evidence=["No recent events found for this pod"],
                recommended_action="manual_investigation",
                events_analyzed=0,
            )

        for event in pod_events:
            sc = event.syscall_name
            binary = event.binary
            target = event.target
            port = event.port

            # Network reconnaissance / port scan
            if ("nmap" in binary.lower() or "scan" in str(target).lower() or
                (sc in ("sys_connect", "sys_socket") and port in (5000, 5001, 5002, 5003, 80, 443, 8080, 22, 21, 23)) or
                (sc == "sys_connect" and event.anomaly_score is not None and event.anomaly_score >= 0.72)):
                scores["compromise"] += 4.0
                evidence.append(f"Network reconnaissance / port scan detected: {binary or sc} on port {port}")
                tech = MITRE_MAP["network_recon"].model_copy()
                tech.evidence = f"Target: {target or pod_name}:{port} via {binary or sc}"
                tech.confidence = 0.88
                tech.observed_at = event.timestamp
                mitre.append(tech)

            # Shell execution
            if sc == "sys_execve":
                binary_base = binary.split("/")[-1].split(" ")[0] if binary else ""
                if binary_base in SHELL_BINARIES or any(s in binary for s in SHELL_BINARIES):
                    scores["compromise"] += 3.0
                    evidence.append(f"Shell execution detected: {binary}")
                    tech = MITRE_MAP["shell_exec"].model_copy()
                    tech.evidence = f"Binary: {binary}"
                    tech.confidence = 0.8
                    tech.observed_at = event.timestamp
                    mitre.append(tech)

            # Ransomware file rename
            if sc == "sys_rename":
                for ext in RANSOMWARE_EXTENSIONS:
                    if target.endswith(ext):
                        scores["compromise"] += 5.0
                        evidence.append(f"Suspicious file rename: {target}")
                        tech = MITRE_MAP["file_encrypt"].model_copy()
                        tech.evidence = f"Target: {target}"
                        tech.confidence = 0.9
                        tech.observed_at = event.timestamp
                        mitre.append(tech)
                        break

            # SMB lateral movement
            if sc in ("sys_connect", "sys_socket") and port == SMB_PORT:
                scores["compromise"] += 4.0
                evidence.append(f"SMB port 445 connection from {pod_name}")
                tech = MITRE_MAP["smb_lateral"].model_copy()
                tech.confidence = 0.85
                tech.observed_at = event.timestamp
                mitre.append(tech)

            # DNS exfiltration
            if sc == "sys_sendto" and port == DNS_PORT:
                if target and len(target) > 30:
                    scores["compromise"] += 3.0
                    evidence.append(f"Suspicious DNS query: {target[:50]}...")
                    tech = MITRE_MAP["dns_exfil"].model_copy()
                    tech.evidence = f"Domain: {target[:60]}"
                    tech.confidence = 0.7
                    tech.observed_at = event.timestamp
                    mitre.append(tech)

            # Connection failures (network partition indicators)
            if "refused" in target.lower() or "timeout" in target.lower():
                scores["network_partition"] += 2.0
                evidence.append(f"Connection issue: {target}")

            if "denied" in target.lower():
                scores["network_partition"] += 2.5
                evidence.append(f"Network policy deny: {target}")

            # High ML anomaly fallback if no specific rule matched yet
            if event.anomaly_score is not None and event.anomaly_score >= 0.72 and not mitre:
                scores["compromise"] += 2.5
                evidence.append(f"Statistical anomaly score {event.anomaly_score:.3f} on {sc} ({binary})")
                tech = MITRE_MAP["behavioral_anomaly"].model_copy()
                tech.evidence = f"Syscall: {sc}, Binary: {binary}, Score: {event.anomaly_score:.3f}"
                tech.confidence = min(0.9, event.anomaly_score)
                tech.observed_at = event.timestamp
                mitre.append(tech)

        # Check other pods for dependency issues
        other_pod_anomalies = [
            e for e in all_events
            if e.pod_name != pod_name and e.is_alert
        ]
        if other_pod_anomalies:
            unique_pods = set(e.pod_name for e in other_pod_anomalies)
            scores["dependency_failure"] += len(unique_pods) * 1.5
            evidence.append(
                f"Anomalies detected in dependency pods: {', '.join(unique_pods)}"
            )
            affected.extend(unique_pods)

        # Determine root cause
        max_cause = max(scores, key=scores.get)
        max_score = scores[max_cause]
        total = sum(scores.values())

        if max_score == 0:
            return DiagnosisResult(
                correlation_id=correlation_id,
                pod_name=pod_name,
                namespace=namespace,
                root_cause="unknown",
                confidence=0.0,
                evidence=evidence or ["Insufficient evidence for diagnosis"],
                recommended_action="manual_investigation",
                scores={k: round(v, 2) for k, v in scores.items()},
                events_analyzed=len(pod_events),
            )

        confidence = round(min(max_score / max(total, 1.0), 1.0), 3)

        # Qualifying language for low confidence
        if confidence < 0.3:
            conflicting.append("Low confidence — insufficient corroborating evidence")

        # Action mapping
        action_map = {
            "compromise": "quarantine_and_redeploy",
            "dependency_failure": "restart_dependency",
            "network_partition": "check_network_policies",
            "resource_exhaustion": "scale_resources",
        }

        return DiagnosisResult(
            correlation_id=correlation_id,
            pod_name=pod_name,
            namespace=namespace,
            root_cause=max_cause,
            confidence=confidence,
            evidence=list(set(evidence)),
            conflicting_evidence=conflicting,
            affected_assets=list(set(affected)),
            mitre_techniques=mitre,
            scores={k: round(v, 2) for k, v in scores.items()},
            events_analyzed=len(pod_events),
            recommended_action=action_map.get(max_cause, "manual_investigation"),
        )
