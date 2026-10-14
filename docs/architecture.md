# SentinelCloud-Advanced Architecture

## Overview
SentinelCloud-Advanced is an eBPF-driven autonomous cyber-resilience platform designed to protect medical microservices. It integrates real-time telemetry ingestion, streaming machine learning anomaly detection, causal root-cause diagnosis, and automated remediation using the MAPE-K control loop.

The system operates in three modes:
- **LIVE** – Full Kubernetes cluster with Tetragon/Falco eBPF probes, Kafka, ClickHouse, Cilium, and the MAPE-K controller watching SecurityAlert CRDs.
- **LAB** – Local Docker Compose environment with simplified service mesh but real detection and diagnosis services.
- **DEV** – Single-machine development mode with in-process ML pipeline and simulated remediation (clearly labeled).

## High-Level Components

```
┌────────────────────┐          ┌─────────────────────┐
│  Medical Services  │          │ Intelligence Plane  │
│  vitals, ehr,      │          │  streaming-anomaly- │
│  drug-dispenser,   │◄─────────┤  detector           │
│  billing           │          │  diagnosis-service  │
└─────────┬──────────┘          └─────────┬───────────┘
          │                               │
          │         REST / Socket.IO      │
          │                               │
┌─────────▼───────────────────────────────▼───────────┐
│              SentinelCloud Backend                  │
│             FastAPI + Socket.IO                     │
│    Auth, Pipeline, Orchestrator, API Gateway        │
└─────────────────────┬───────────────────────────────┘
                      │
          ┌───────────▼────────────┐
          │   Enforcement Plane    │
          │   mape-k-controller    │
          │ Cilium NetworkPolicies │
          │   Kubernetes API       │
          └────────────────────────┘
```

## Backend
The backend (`backend/`) is a modular FastAPI application with Socket.IO for real-time push. It exposes REST endpoints under `/api` and manages the central pipeline:
- **Ingestion** – Receives telemetry from eBPF probes, lab tests, or HTTP.
- **Detection** – Uses River HalfSpaceTrees and HMM for streaming anomaly detection. Can delegate to external `streaming-anomaly-detector` service.
- **Diagnosis** – Correlates events to determine root cause. Can use external `diagnosis-service` or internal engine.
- **Mitigation** – Executes MAPE-K loop: selects and applies remediation actions (quarantine, redeploy, failover). In DEV mode, actions are simulated; in LIVE mode, they call Kubernetes/Cilium.
- **Persistence** – SQLite for dev/lab, ClickHouse for production.

## Frontend
The frontend is a Next.js application (App Router) with multiple pages:
- Login with JWT.
- Dashboard overview.
- Live threat operations, telemetry stream, detection pipeline view, diagnosis, response (MAPE-K), network topology, Kubernetes, incidents, analytics, policies, health, settings.
- Real-time updates via Socket.IO.
- Persistent mode banner indicating LIVE/LAB/DEV.

## Security
- **Authentication**: JWT with bcrypt-hashed passwords.
- **Authorization**: Role-based access (admin, analyst).
- **No hardcoded credentials**; initial admin configured from environment variables.
- **CORS** restricted to configured origins.
- **Audit trail** of security-relevant actions.

## Deployment
- **Docker Compose** for local lab: `docker-compose.yml` starts Kafka, ClickHouse, medical services, intelligence services, and backend.
- **Kubernetes** manifests in `deploy/manifests/` for full production (LIVE mode).
- **Helm chart** available in `deploy/sentinel-chart/`.

## Testing
- **Unit tests**: `pytest tests/unit`
- **API tests**: `pytest tests/api`
- **Integration tests**: `pytest -m integration tests/integration`
- **Manual test harness**: `testing/harness.py` for authorized attack simulations.

## Metrics & Observability
- All services expose Prometheus metrics at `/metrics`.
- Backend computes real MTTD/MTTR from timestamps (no seeded values).
- Structured JSON logging for medical services.
