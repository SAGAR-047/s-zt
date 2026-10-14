"""
SentinelCloud Event Normalizer
================================
Standardizes raw telemetry events from various sources
into the canonical TelemetryEvent format.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from backend.core.event_schema import TelemetryEvent, TelemetrySource, DataMode

logger = logging.getLogger("sentinel.pipeline.normalizer")


# Known syscall name normalizations
SYSCALL_ALIASES = {
    "connect": "sys_connect",
    "write": "sys_write",
    "execve": "sys_execve",
    "rename": "sys_rename",
    "read": "sys_read",
    "open": "sys_open",
    "close": "sys_close",
    "socket": "sys_socket",
    "sendto": "sys_sendto",
    "recvfrom": "sys_recvfrom",
    "unlink": "sys_unlink",
    "openat": "sys_openat",
    "ioctl": "sys_ioctl",
    "mmap": "sys_mmap",
    "clone": "sys_clone",
    "fork": "sys_fork",
}


def normalize_syscall_name(name: str) -> str:
    """Normalize syscall name to canonical sys_ prefix form."""
    if not name:
        return ""
    name = name.strip().lower()
    if name in SYSCALL_ALIASES:
        return SYSCALL_ALIASES[name]
    if not name.startswith("sys_"):
        return f"sys_{name}"
    return name


def normalize_event(event: TelemetryEvent) -> TelemetryEvent:
    """
    Normalize a TelemetryEvent in-place.
    Standardizes syscall names, trims whitespace, ensures valid types.
    """
    # Normalize syscall name
    if event.syscall_name:
        event.syscall_name = normalize_syscall_name(event.syscall_name)

    # Trim whitespace
    event.pod_name = event.pod_name.strip()
    event.namespace = event.namespace.strip() or "medical"
    event.binary = event.binary.strip()
    event.target = event.target.strip()
    event.protocol = event.protocol.strip().lower()

    # Ensure valid port range
    event.port = max(0, min(65535, event.port))

    # Ensure non-negative payload size
    event.payload_size = max(0, event.payload_size)

    return event


def normalize_raw_dict(raw: dict, source: TelemetrySource = TelemetrySource.HTTP_INGESTION) -> Optional[TelemetryEvent]:
    """Convert a raw dict (from Kafka, HTTP, etc.) into a normalized TelemetryEvent."""
    try:
        event = TelemetryEvent(
            source=source,
            pod_name=raw.get("pod_name", raw.get("pod", "")),
            namespace=raw.get("namespace", "medical"),
            syscall_name=raw.get("syscall_name", raw.get("event_type", "")),
            binary=raw.get("binary", raw.get("process", {}).get("binary", "")),
            target=raw.get("target", ""),
            port=int(raw.get("port", 0)),
            protocol=raw.get("protocol", ""),
            payload_size=int(raw.get("payload_size", raw.get("size", 0))),
            params=raw.get("params", {}),
        )
        return normalize_event(event)
    except Exception as e:
        logger.error("Failed to normalize raw event: %s", e)
        return None
