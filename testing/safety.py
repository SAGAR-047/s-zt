"""
Safety validation for SentinelCloud testing harness.
Ensures that attack scenarios only target allowed lab infrastructure.
"""

import os
import ipaddress
import logging
import socket
from typing import List

logger = logging.getLogger("testing.safety")

KNOWN_LAB_SERVICES = {
    "ehr", "vitals", "billing", "drug-dispenser", "localhost", "127.0.0.1", "host.docker.internal"
}


def get_allowed_cidrs() -> List[ipaddress.IPv4Network]:
    """Return list of allowed CIDR networks from environment."""
    cidr_str = os.environ.get(
        "SAFETY_ALLOWED_CIDRS",
        "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    )
    allowed = []
    for part in cidr_str.split(","):
        part = part.strip()
        if part:
            try:
                allowed.append(ipaddress.ip_network(part, strict=False))
            except ValueError as e:
                logger.warning("Invalid CIDR in SAFETY_ALLOWED_CIDRS: %s (%s)", part, e)
    return allowed


def is_ip_allowed(ip_str: str) -> bool:
    """Check if an IP address is within any allowed network."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in get_allowed_cidrs():
            if ip in net:
                return True
    except ValueError:
        return False
    return False


def validate_target(target: str) -> bool:
    """
    Validate a target hostname or IP address.
    Resolves DNS if needed, then checks against allowed CIDRs.
    Returns True if allowed, False otherwise.
    """
    if not target:
        return False

    # Check known lab services first
    clean_target = target.split(":")[0].strip().lower()
    if clean_target in KNOWN_LAB_SERVICES:
        return True

    # Check if target is an IP address
    try:
        ip = ipaddress.ip_address(clean_target)
        return is_ip_allowed(str(ip))
    except ValueError:
        pass

    # Resolve hostname to IPs
    try:
        ips = socket.gethostbyname_ex(clean_target)[2]
        for ip in ips:
            if not is_ip_allowed(ip):
                logger.warning("Target %s resolves to disallowed IP %s", target, ip)
                return False
        return True
    except socket.gaierror:
        # In isolated lab environments without internal DNS configured on host
        if any(clean_target.endswith(suffix) for suffix in (".cluster.local", ".local", ".internal", ".medical")):
            return True
        if os.environ.get("SAFETY_ALLOW_UNRESOLVED", "0") in ("1", "true", "True"):
            logger.info("Target %s could not be resolved by host DNS; allowed under lab testing policy", target)
            return True
        logger.error("Cannot resolve target %s", target)
        return False


def validate_port(port: int) -> bool:
    """Ensure port is within allowed lab range (1-65535)."""
    return 1 <= port <= 65535


def check_safety(target: str, port: int = 0) -> bool:
    """
    Comprehensive safety check before running a scenario.
    """
    if not target:
        logger.error("Target is empty")
        return False
    if not validate_target(target):
        logger.error("Target %s is not in allowed lab network", target)
        return False
    if port and not validate_port(port):
        logger.error("Invalid port: %d", port)
        return False
    logger.info("Safety check passed for target %s%s", target, f":{port}" if port else "")
    return True
