# SentinelCloud-Advanced Testing Harness

Authorized lab testing framework for generating controlled attack scenarios against the SentinelCloud stack.

## Overview

This harness provides a safe and auditable way to run attack simulations against the medical microservices protected by SentinelCloud. Each scenario is a self-contained Python script that can be executed individually or orchestrated via `harness.py`.

## Safety

- All scenarios validate the target environment before executing any action.
- Targets must be in an allowed lab network range (configurable via `SAFETY_ALLOWED_CIDRS` environment variable).
- The harness registers a test session with the SentinelCloud backend before running, and reports results when finished.
- A valid SentinelCloud JWT token is required to authenticate the session.

## Usage

1. Ensure the SentinelCloud backend is running (`python -m backend.main`).
2. Set environment variables:
   - `SENTINEL_API_URL` (default `http://localhost:5050`)
   - `SENTINEL_USERNAME` (default `admin`)
   - `SENTINEL_PASSWORD` (default `sentinel-admin-2026`)
   - `SAFETY_ALLOWED_CIDRS` (comma-separated, default `127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`)
3. Run a scenario:
   ```bash
   python testing/harness.py --scenario recon --target-pod ehr --target-namespace medical
   ```
   or run a scenario directly:
   ```bash
   python testing/scenarios/recon.py --target ehr
   ```

## Scenarios

- **recon** – Network reconnaissance (port scanning of target service).
- **shell_exec** – Suspicious process execution (simulated shell spawn on target).
- **lateral_movement** – SMB/port probing from target pod.
- **file_encryption** – Canary file rename to .locked on target.
- **dns_exfil** – DNS tunneling queries from target.
- **auth_bruteforce** – Authentication failure testing against target service.
- **ransomware** – Full multi-stage ransomware attack simulation (stages 1-4).

All scenarios send real telemetry events to the SentinelCloud backend, which are then processed by the detection pipeline.
