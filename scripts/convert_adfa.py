#!/usr/bin/env python3
"""
Convert ADFA-LD dataset traces into SentinelCloud TelemetryEvent JSON format.
Handles both syscall names and Linux x86 system call numbers.
"""

import os
import json
import sys
from pathlib import Path

# Mapping of common ADFA-LD syscall abbreviations & names
SYSCALL_NAME_MAP = {
    "open": "sys_open",
    "read": "sys_read",
    "write": "sys_write",
    "close": "sys_close",
    "execve": "sys_execve",
    "fork": "sys_fork",
    "clone": "sys_clone",
    "connect": "sys_connect",
    "socket": "sys_socket",
    "sendto": "sys_sendto",
    "recvfrom": "sys_recvfrom",
    "rename": "sys_rename",
    "unlink": "sys_unlink",
    "openat": "sys_openat",
    "mmap": "sys_mmap",
    "ioctl": "sys_ioctl",
}

# Mapping of Linux x86 system call numbers (common in raw ADFA-LD traces)
SYSCALL_NUM_MAP = {
    "3": "sys_read",
    "4": "sys_write",
    "5": "sys_open",
    "6": "sys_close",
    "11": "sys_execve",
    "12": "sys_chdir",
    "13": "sys_time",
    "33": "sys_access",
    "38": "sys_rename",
    "39": "sys_mkdir",
    "40": "sys_rmdir",
    "42": "sys_connect",
    "45": "sys_brk",
    "54": "sys_ioctl",
    "102": "sys_socket",
    "120": "sys_clone",
    "122": "sys_uname",
    "125": "sys_mprotect",
    "140": "sys_read",
    "168": "sys_read",
    "192": "sys_mmap",
    "195": "sys_read",
    "197": "sys_read",
    "220": "sys_read",
    "221": "sys_read",
    "252": "sys_close",
}


def resolve_syscall(token: str) -> str:
    """Resolve token (numeric or name) to standard sys_* name."""
    clean = token.strip().lower()
    if clean.isdigit():
        return SYSCALL_NUM_MAP.get(clean, f"sys_call_{clean}")
    if clean in SYSCALL_NAME_MAP:
        return SYSCALL_NAME_MAP[clean]
    if clean.startswith("sys_"):
        return clean
    return f"sys_{clean}"


def convert_adfa_dir(base_dir: str, output_file: str, pod_prefix: str = "adfa-normal"):
    base_path = Path(base_dir)
    if not base_path.exists():
        print(f"Error: input path '{base_dir}' does not exist.")
        sys.exit(1)

    events = []
    txt_files = list(base_path.rglob("*.txt"))
    if not txt_files:
        print(f"Warning: No .txt files found under {base_dir}")

    for txt_file in txt_files:
        try:
            with open(txt_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            print(f"Skipping {txt_file}: {e}")
            continue

        # Split across whitespace (handles both multi-line and space-separated single-line files)
        tokens = content.split()
        for token in tokens:
            token = token.strip()
            if not token or token.startswith("#"):
                continue

            syscall_full = resolve_syscall(token)

            # Plausible binary, target, and port based on syscall
            binary = "/usr/bin/python3" if "read" in syscall_full or "write" in syscall_full else "/bin/sh"
            target = "/data/patient_records.json"
            port = 0

            if syscall_full in ("sys_connect", "sys_sendto", "sys_recvfrom", "sys_socket"):
                port = 5002
                target = f"{pod_prefix}:5002"
                binary = "/usr/bin/curl"
            elif syscall_full == "sys_execve":
                binary = "/bin/bash"
                target = "/bin/ls"
            elif syscall_full == "sys_rename":
                target = "/data/patient_records.json.locked"

            event = {
                "pod_name": pod_prefix,
                "namespace": "medical",
                "syscall_name": syscall_full,
                "binary": binary,
                "target": target,
                "port": port,
                "protocol": "tcp" if port else "",
                "source": "replay",
                "params": {"raw_token": token, "source_file": txt_file.name},
            }
            events.append(event)

    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(events, f, indent=2)

    print(f"Successfully converted {len(events)} events from {len(txt_files)} files to {output_file}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Convert ADFA-LD syscall traces to SentinelCloud events")
    parser.add_argument("--input", required=True, help="Path to ADFA-LD directory (e.g. Training_Data_Master)")
    parser.add_argument("--output", required=True, help="Output JSON file path")
    parser.add_argument("--pod-prefix", default="adfa-normal", help="Prefix for pod names (default: adfa-normal)")
    args = parser.parse_args()
    convert_adfa_dir(args.input, args.output, args.pod_prefix)
