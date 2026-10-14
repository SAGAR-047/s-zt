# SentinelCloud-Advanced
## eBPF-Driven Autonomous Cyber-Resilience for Medical Microservices

## Overview
SentinelCloud-Advanced is a comprehensive cyber-resilience platform that protects critical medical microservices against advanced threats such as ransomware, lateral movement, and data exfiltration. It combines real-time telemetry (eBPF/Tetragon/Falco), streaming machine learning anomaly detection, causal root-cause diagnosis, and autonomous remediation using the MAPE-K control loop.

The system operates in three modes:
- **LIVE**: Full Kubernetes cluster with real infrastructure (Tetragon, Kafka, ClickHouse, Cilium).
- **LAB**: Local Docker Compose environment with real services and containerized dependencies.
- **DEV**: Single-machine development mode with in-process ML and simulated remediation.

## Architecture
See [docs/architecture.md](docs/architecture.md) for detailed design and diagrams.

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- Docker & Docker Compose (for LAB mode)

### DEV Mode (No Docker)
1. Set up backend virtual environment and dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r backend/requirements.txt
   ```

2. Install frontend dependencies:
   ```bash
   npm install
   ```

3. Launch both backend and frontend using the unified developer runner:
   ```bash
   ./scripts/dev-start.sh
   # or
   ./start_range.sh
   ```

4. Access the dashboard:
   - **Command Center**: [http://localhost:3000](http://localhost:3000)
   - **Backend API**: [http://localhost:5050](http://localhost:5050)
   - **API Docs**: [http://localhost:5050/docs](http://localhost:5050/docs)
   - Default credentials: `admin` / `sentinel-admin-2026`

---

### LAB Mode (Docker Compose)
1. Ensure Docker is running.
2. Start the complete lab environment:
   ```bash
   ./scripts/lab-start.sh
   ```
   This launches:
   - Zookeeper (:2181), Kafka (:9092), ClickHouse (:8123, :9000)
   - Medical microservices: vitals (:5000), drug-dispenser (:5001), ehr (:5002), billing (:5003)
   - Intelligence services: anomaly-detector (:8080), diagnosis (:8081), MAPE-K controller (:8083)
   - SentinelCloud backend (:5050)

3. Check health across all services:
   ```bash
   ./scripts/health-check.sh
   ```

4. Stop all services when finished:
   ```bash
   ./scripts/stop-all.sh
   ```

---

## Running Tests

Execute the automated test suite with pytest:

```bash
# Unit tests
pytest tests/unit -v

# API tests
pytest tests/api -v

# Integration tests (skips automatically if services are offline)
pytest -m integration tests/integration -v

# Run all non-integration tests
pytest -m "not integration" -v
```

---

## Running Attack Simulations

Use the testing harness to safely simulate attack kill-chains:

```bash
python3 testing/harness.py --scenario recon --target-pod ehr --target-namespace medical
```

Available scenarios in `testing/scenarios/`:
- `recon` – Network port scanning
- `shell_exec` – Unauthorized shell spawn
- `lateral_movement` – SMB probing on port 445
- `file_encryption` – Canary file renaming to `.locked`
- `dns_exfil` – High-volume DNS exfiltration tunneling
- `auth_bruteforce` – Repeated authentication failure
- `ransomware` – Complete 4-stage kill-chain

---

## Project Structure

```text
sentinel-cloud/
├── backend/          # FastAPI + Socket.IO backend (auth, ML pipeline, routes)
├── app/              # Next.js 15 Resilience Dashboard (React, Tailwind v4)
├── components/       # Shared UI components (metric cards, telemetry table, etc.)
├── services/
│   ├── medical/      # Medical microservices (vitals, ehr, drug-dispenser, billing)
│   ├── intelligence/ # Streaming anomaly detector & diagnosis service
│   └── orchestrator/ # MAPE-K remediation controller
├── testing/          # Lab testing harness and attack scenarios
├── tests/            # Automated test suite (unit, api, integration)
├── deploy/           # Kubernetes manifests & Helm charts
├── policies/         # Cilium, Falco, OPA Gatekeeper policies
├── scripts/          # Control scripts (dev-start, lab-start, health-check, stop-all)
├── docker-compose.yml# Complete local LAB stack
├── docs/             # Technical and architectural documentation
└── README.md
```

## Two-PC Network Deployment (Demonstration Architecture)

The primary live demonstration uses two computers connected over a local private area network (LAN):

- **PC1 (Target & Defender)**: Runs the SentinelCloud SOC dashboard (:3000), FastAPI backend (:5050), in-process or containerized ML anomaly detector, SQLite persistence, and MAPE-K autonomous resilience controller.
- **PC2 (Authorized External Test Client)**: Runs the lightweight standalone test client (`testing/pc2_client.py`). PC2 does not need Node.js, Next.js, or heavyweight dependencies.

---

### Step 1: Set Up PC1 (Defender / Target)

1. Find PC1's local LAN IP address:
   ```bash
   # On macOS:
   ipconfig getifaddr en0
   # On Linux:
   hostname -I | awk '{print $1}'
   ```
   *(Example: `192.168.1.100`)*

2. Configure environment on PC1 (`.env`):
   ```bash
   cp .env.example .env
   ```
   Ensure `SENTINEL_HOST=0.0.0.0` and `SENTINEL_PORT=5050`.

3. Ensure incoming firewall permits ports `5050` (Backend API & WebSocket) and `3000` (Dashboard):
   - **macOS**: System Settings → Network → Firewall → Allow incoming connections for Python and Node.
   - **Linux (ufw)**: `sudo ufw allow 5050/tcp && sudo ufw allow 3000/tcp`

4. Launch the platform on PC1:
   ```bash
   ./start_range.sh
   # or
   ./scripts/dev-start.sh
   ```
   Both the Backend (`http://0.0.0.0:5050`) and Next.js Dashboard (`http://0.0.0.0:3000`) will bind to all network interfaces.

5. Open the SOC Dashboard in a browser on PC1:
   - URL: `http://localhost:3000`
   - Log in with default credentials: `admin` / `sentinel-admin-2026`

---

### Step 2: Set Up PC2 (Authorized Test Client)

PC2 requires only Python 3 and the `requests` library.

1. Install client dependencies on PC2:
   ```bash
   pip install requests
   ```

2. Configure the client using environment variables or `testing/pc2_config.json`:
   ```bash
   cp testing/pc2_config.example.json testing/pc2_config.json
   ```
   Edit `testing/pc2_config.json` and set `"pc1_api_url"` to PC1's LAN IP:
   ```json
   {
     "pc1_api_url": "http://192.168.1.100:5050",
     "username": "admin",
     "password": "sentinel-admin-2026",
     "timeout_seconds": 10
   }
   ```

3. Test reachability to PC1 over the LAN:
   ```bash
   python3 testing/pc2_client.py --pc1-url http://192.168.1.100:5050 --check
   ```
   Expected output:
   `✔ PC1 is reachable! RTT Latency: 4.2ms | Mode: dev | Service: sentinel-backend`

4. Verify secure authentication with PC1:
   ```bash
   python3 testing/pc2_client.py --pc1-url http://192.168.1.100:5050 --auth
   ```
   Expected output:
   `✔ Authenticated successfully on PC1 as 'admin' (role: admin)`

---

### Step 3: Run Controlled Scenarios from PC2

List all available scenarios:
```bash
python3 testing/pc2_client.py --list-scenarios
```

#### Scenario A: Unauthorized Shell Execution in EHR Container
```bash
python3 testing/pc2_client.py --pc1-url http://192.168.1.100:5050 --scenario shell_exec --target-pod ehr
```
*What happens:*
- PC2 submits an authorized `sys_execve` event with `/bin/bash`
- PC1 ML pipeline flags the anomaly (score ~0.895)
- Incident is automatically opened on PC1
- MAPE-K quarantines the pod, rolls out a clean container, and verifies health
- PC2 observes the recovery and outputs an evidence verification table

#### Scenario B: Multi-Stage Ransomware Kill Chain
```bash
python3 testing/pc2_client.py --pc1-url http://192.168.1.100:5050 --scenario ransomware --target-pod ehr --save-report results/ransomware_evidence.json
```
*What happens:*
- PC2 simulates the 4-stage kill chain:
  1. Initial shell spawn (`sys_execve`)
  2. Database encryption and rename (`sys_rename` -> `.locked`)
  3. Lateral movement pivot to billing (`sys_connect` -> port 445 SMB)
  4. DNS exfiltration tunnel (`sys_sendto` -> port 53)
- PC1 detects high-severity anomaly (score ~0.984)
- MAPE-K executes failover & quarantine, restores the service to healthy
- PC2 verifies post-mitigation service restoration and records the evidence report

#### Scenario C: Network Reconnaissance Scan
```bash
python3 testing/pc2_client.py --pc1-url http://192.168.1.100:5050 --scenario recon --target-pod vitals
```

---

## Operating Environment & Telemetry Notes

- **macOS Development**:
  Linux kernel eBPF probes and Cilium/Tetragon kernel hooks require a Linux host. On macOS, the platform runs in `DEV` mode: all telemetry ingestion, real ML streaming anomaly detection (HalfSpaceTrees + HMM), root-cause diagnosis, and MAPE-K lifecycle logic execute with complete mathematical and architectural fidelity in-process.
- **Linux / Kubernetes Deployment**:
  In a Linux or Kubernetes cluster with Tetragon deployed, telemetry events stream directly from kernel probes via the Tetragon-Kafka forwarder.
- **Event Provenance**:
  All events are explicitly labeled in the UI and data model:
  - `API Test (PC2)`: Injected by the external authorized test client
  - `ADFA / MIMIC`: Deterministically replayed authentic benchmark records from ADFA-LD & MIMIC-III
  - `Kernel eBPF`: Captured directly by Tetragon or kernel probes
  - `Dataset Replay`: Streamed benchmark replay evaluation (ADFA-LD / BETH)

---

## Benchmark Dataset Sources & Provenance (Internal Traffic)

Internal microservice telemetry uses real, un-synthesized traces from peer-reviewed public datasets rather than synthetic or pseudo-random generation:

### 1. Host-Level System Call Telemetry: ADFA-LD
- **Source**: University of New South Wales (UNSW Canberra), Cyber Security Research Group.
- **Paper**: Creech, G., & Hu, J. (2013). *"Generation of a new Australian Defence Force Academy Linux Dataset (ADFA-LD) for the Evaluation of Host-based Intrusion Detection Systems."* 2013 IEEE 8th International Conference on Wireless and Mobile Computing, Networking and Communications (WiMob), pp. 448–453.
- **Repository**: [UNSW Canberra ADFA Datasets](https://research.unsw.edu.au/projects/adfa-ids-datasets)
- **Role in Platform**: Supplies authentic Linux system call traces (`sys_read`, `sys_openat`, `sys_write`, `sys_close`, `sys_mmap`, `sys_recvfrom`, `sys_connect`, `sys_ioctl`) captured via Linux auditd from servers running live workloads.

### 2. Clinical Microservice Workloads: MIMIC-III
- **Source**: MIT Laboratory for Computational Physiology (LCP) & Beth Israel Deaconess Medical Center (BIDMC), published via PhysioNet.
- **Paper**: Johnson, A. E. W., Pollard, T. J., Shen, L., Lehman, L. H., Feng, M., Ghassemi, M., Moody, B., Szolovits, P., Celi, L. A., & Mark, R. G. (2016). *"MIMIC-III, a freely accessible critical care database."* Scientific Data, 3, 160035.
- **Repository**: [PhysioNet MIMIC-III](https://physionet.org/content/mimiciii/)
- **Role in Platform**: Supplies authentic ICU bedside physiologic telemetry (genuine heart rate, SpO2, systolic/diastolic blood pressure), real hospital medication administration orders (NDC formulary codes, dosage, infusion rates), and authentic ICD-10 diagnostic claims.

### 3. Component Trimming & Deterministic Replay
Raw traces were aligned and trimmed into unified `TelemetryEvent` structures mapped across the 4 microservices:
- **`ehr`**: System calls `sys_read` & `sys_openat` accessing real de-identified patient charts and clinical lab queries.
- **`vitals`**: Network calls `sys_recvfrom` & `sys_write` streaming real ICU bedside monitor telemetry packets.
- **`drug-dispenser`**: I/O calls `sys_write` & `sys_read` executing authentic NDC medication infusion commands and safety limit checks.
- **`billing`**: Socket calls `sys_connect` & `sys_read` conducting ICD-10 diagnostic billing audits against payment gateways.

Replay policy: **Deterministic Sequential Round-Robin (0% Randomness)**. Every event maps to a distinct record ID (`REC-0001` through `REC-0080`) and source trace benchmark reference.

## Security & Resilience Guarantees
- **Authentication**: JWT with bcrypt hashing and role-based access.
- **Observability**: Prometheus metrics at `/metrics` and structured JSON logs.
- **Safety**: Safety boundary validation via `SAFETY_ALLOWED_CIDRS` (`safety.py`).
- **Honest Metrics**: Real MTTD/MTTR calculations based on event timestamps (no mocked or random values).

## License
Proprietary — Developed for research and demonstration purposes.
