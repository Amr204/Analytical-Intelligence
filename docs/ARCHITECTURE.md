# 🏗️ System Architecture

> System design, data flow, Docker structure, and repository map

---

## Table of Contents

- [Overview](#overview)
- [Architecture Diagram](#architecture-diagram)
- [Data Flow](#data-flow)
- [Docker Structure](#docker-structure)
- [Repository Map](#repository-map)
- [Entrypoints](#entrypoints)
- [Networks and Volumes](#networks-and-volumes)

---

## Overview

Analytical-Intelligence is a mini-SIEM system that detects security threats in real-time using machine learning.

### Components

| Component | Purpose |
|-----------|---------|
| **Backend** | FastAPI server with ML detection + UI |
| **PostgreSQL** | Event and detection storage |
| **Auth Collector** | Monitors `/var/log/auth.log` for SSH events |
| **Suricata Collector** | Captures network threats using Suricata IDS |

### Models

| Model | File Location | Detects |
|-------|---------------|---------|
| SSH LSTM | `models/ssh/ssh_lstm.joblib` | SSH brute force |


---

## Architecture Diagram

```
                         ┌─────────────────────────────────────────────────┐
                         │            ANALYSIS SERVER                      │
                         │                                                 │
 ┌──────────────────┐    │  ┌─────────────────┐    ┌─────────────────┐    │
 │  SENSOR SERVER   │    │  │    backend      │    │   postgres      │    │
 │                  │    │  │  (FastAPI + ML) │◄──►│  (PostgreSQL)   │    │
 │  ┌────────────┐  │    │  │                 │    │                 │    │
 │  │   auth     │  │────┼─►│  Port 8000      │    │  Port 5432      │    │
 │  │ collector  │  │    │  │                 │    │  (internal)     │    │
 │  └────────────┘  │    │  │  ┌───────────┐  │    └─────────────────┘    │
 │                  │    │  │  │ SSH LSTM  │  │                           │
 │  ┌────────────┐  │    │  │  │ Network RF│  │                           │
 │  │   flow     │  │────┼─►│  └───────────┘  │                           │
 │  │ collector  │  │    │  └─────────────────┘                           │
 │  └────────────┘  │    │                                                 │
 │                  │    └─────────────────────────────────────────────────┘
 │  network_mode:   │                          │
 │     host         │                          │
 └──────────────────┘                          ▼
                                     ┌─────────────────┐
                                     │  Windows/Browser│
                                     │  Dashboard UI   │
                                     └─────────────────┘
```

---

## Data Flow

### 1. SSH Event Processing

```
/var/log/auth.log
       │
       ▼
┌──────────────────┐
│  auth_collector  │  Reads auth.log lines
│  (tail -F)       │
└────────┬─────────┘
         │
         │  POST /api/v1/ingest/auth
         │  Headers: INGEST_API_KEY
         ▼
┌──────────────────┐
│     backend      │
│                  │
│  1. Verify API key
│  2. Register device
│  3. Store raw event
│  4. Run SSH detector
│     - Count failed attempts
│     - If threshold exceeded → alert
│  5. Store detection
└──────────────────┘
```

### 2. Suricata Event Processing

```
Network Interface (ens33)
         │
         ▼
┌──────────────────┐
│suricata_collector│  Suricata IDS detects threats
│  (host network)  │
└────────┬─────────┘
         │
         │  POST /api/v1/ingest/suricata
         │  Headers: INGEST_API_KEY
         ▼
┌──────────────────┐
│     backend      │
│                  │
│  1. Verify API key
│  2. Register device
│  3. Store detection
└──────────────────┘
```

---

## Docker Structure

### Analysis Server (docker-compose.analysis.yml)

```yaml
services:
  postgres:
    image: postgres:15-alpine
    container_name: ai_db-postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init_db.sql:/docker-entrypoint-initdb.d/

  backend:
    build: ./services/backend
    container_name: ai_db-backend
    ports:
      - "8000:8000"
    volumes:
      - ./models/ssh:/app/models/ssh:ro
    depends_on:
      postgres: { condition: service_healthy }

networks:
  ai-network: { driver: bridge }

volumes:
  postgres_data:
```

### Sensor Server (docker-compose.sensor.yml)

```yaml
services:
  auth_collector:
    build: ./agents/auth_collector
    container_name: ai_db-auth-collector
    network_mode: host
    volumes:
      - /var/log/auth.log:/var/log/auth.log:ro

  suricata_collector:
    build: ./agents/suricata_collector
    container_name: ai_db-suricata-collector
    network_mode: host
    cap_add: [NET_ADMIN, NET_RAW, SYS_NICE]
```

---

## Repository Map

```
Analytical-Intelligence/
│
├── docker-compose.analysis.yml  ◄── Analysis server entrypoint
├── docker-compose.sensor.yml    ◄── Sensor server entrypoint
├── .env.example                 ◄── Environment template
│
├── services/
│   └── backend/
│       ├── Dockerfile
│       ├── requirements.txt
│       └── app/
│           ├── main.py          ◄── FastAPI entrypoint
│           ├── config.py        ◄── Settings
│           ├── db.py            ◄── Database operations
│           ├── models_loader.py ◄── ML model loading
│           ├── security.py      ◄── API key verification
│           ├── schemas.py       ◄── Pydantic models
│           │
│           ├── ingest/          ◄── Ingestion endpoints
│           │   ├── auth_ingest.py
│           │   └── suricata_ingest.py
│           │
│           ├── detectors/       ◄── ML detectors
│           │   └── ssh_lstm_detector.py
│           │
│           ├── ui/              ◄── Web UI routes
│           │   └── routes.py
│           │
│           ├── templates/       ◄── Jinja2 HTML templates
│           └── static/          ◄── CSS, JS
│
├── agents/
│   ├── auth_collector/
│   │   ├── Dockerfile
│   │   └── agent.py             ◄── Auth collector entrypoint
│   │
│   ├── suricata_collector/
│   │   ├── Dockerfile
│   │   └── agent.py             ◄── Suricata collector entrypoint
│   │
│   └── common/                  ◄── Shared utilities
│
├── models/
│   ├── ssh/
│   │   └── ssh_lstm.joblib      ◄── SSH detection model
│   │

│
├── scripts/
│   ├── analysis_up.sh           ◄── Start analysis stack
│   ├── sensor_up.sh             ◄── Start sensor stack
│   ├── docker_doctor.sh         ◄── Preflight health check
│   └── init_db.sql              ◄── Database initialization
│
└── docs/                        ◄── Documentation
```

---

## Entrypoints

| File | Triggered By | Purpose |
|------|--------------|---------|
| `docker-compose.analysis.yml` | User / `analysis_up.sh` | Start Analysis stack |
| `docker-compose.sensor.yml` | User / `sensor_up.sh` | Start Sensor stack |
| `scripts/init_db.sql` | PostgreSQL on first start | Create database tables |
| `services/backend/app/main.py` | Uvicorn in container | FastAPI application |
| `agents/auth_collector/agent.py` | Docker container | Auth log monitoring |
| `agents/suricata_collector/agent.py` | Docker container | Suricata evasion detection |

---

## Networks and Volumes

### Networks

| Network | Type | Purpose |
|---------|------|---------|
| `ai-network` | Bridge | Internal communication (backend ↔ postgres) |
| Host mode | N/A | Sensors use host networking for packet capture |

### Volumes

| Volume | Purpose | Persistence |
|--------|---------|-------------|
| `postgres_data` | Database storage | Survives container restarts |
| `./models/ssh` | SSH model (read-only bind) | Host filesystem |


### Port Mapping

| Port | Service | Exposed To |
|------|---------|------------|
| 8000 | Backend API + UI | External (LAN) |
| 5432 | PostgreSQL | Internal only |

---

## Build Caching

The project uses Docker BuildKit for efficient rebuilds:

```bash
# Enabled in startup scripts
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1
```

**Caching behavior:**
- If only code changes (not `requirements.txt`) → Fast rebuild (~30s)
- If `requirements.txt` changes → pip install runs, but uses pip cache
- `--no-cache` flag → Full rebuild (slow, rarely needed)

---

**For daily operations, see [OPERATIONS.md](OPERATIONS.md)**
