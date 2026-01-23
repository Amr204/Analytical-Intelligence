# 📚 Analytical-Intelligence Documentation Index

> Quick navigation to all project documentation

---

## Table of Contents

- [Quick Start](#quick-start)
- [Documentation Map](#documentation-map)
- [Document Purposes](#document-purposes)

---

## Quick Start

```
New Installation?     → INSTALLATION.md
System not working?   → TROUBLESHOOTING.md
Daily operations?     → OPERATIONS.md
Updating the system?  → UPGRADES.md
```

---

## Documentation Map

| Document | Purpose | Audience |
|----------|---------|----------|
| [INSTALLATION.md](INSTALLATION.md) | Setup guide for Analysis + Sensor servers | New users |
| [OPERATIONS.md](OPERATIONS.md) | Daily operations, start/stop, add sensors | Operators |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design, data flow, Docker structure | Developers |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Comprehensive problem-solving runbook | All users |
| [UPGRADES.md](UPGRADES.md) | How to update the system safely | Operators |
| [ML.md](ML.md) | ML models, thresholds, allowlist policy | Developers |
| [SECURITY.md](SECURITY.md) | Firewall modes, API keys, hardening | Security admins |
| [GIT_WORKFLOW.md](GIT_WORKFLOW.md) | Git best practices & standard workflow | Developers |
| [TESTING.md](TESTING.md) | Network RF pipeline validation guide | Developers |

---

## Document Purposes


### [INSTALLATION.md](INSTALLATION.md)
Step-by-step setup for:
- Analysis server (backend + database)
- Sensor server(s) (auth_collector + flow_collector)
- Post-install verification

### [OPERATIONS.md](OPERATIONS.md)
- Start/stop/restart commands
- Recovery after reboot
- Adding new sensors
- Monitoring logs and status

### [ARCHITECTURE.md](ARCHITECTURE.md)
- System architecture diagram
- Data flow from sensor to database
- Docker container structure
- Repository file map

### [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
Comprehensive runbook covering:
- Reboot recovery
- IP changes
- Docker issues
- ML model problems
- Database issues
- Network/firewall problems

### [UPGRADES.md](UPGRADES.md)
- Pre-upgrade checklist
- Safe update procedure
- When to rebuild containers
- Rollback procedure

### [ML.md](ML.md)
- SSH LSTM model (brute force)
- Network RF model (DoS, DDoS, Port Scanning, Brute Force)
- Threshold tuning
- Allowlist configuration

### [SECURITY.md](SECURITY.md)
- UFW firewall configurations
- API key management
- Exposure matrix
- Production hardening

### [GIT_WORKFLOW.md](GIT_WORKFLOW.md)
- Branching strategy (`main` / `develop`)
- Commit message standards
- Handling large model files (`.joblib`)
- Safe deployment practices


---

## Getting Started Flowchart

```
                    ┌─────────────────────┐
                    │   New Installation? │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  INSTALLATION.md    │
                    │  (Setup both        │
                    │   servers)          │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  System Working?    │
                    └──────────┬──────────┘
                        │             │
                       YES           NO
                        │             │
                        ▼             ▼
              ┌─────────────┐  ┌─────────────────┐
              │ OPERATIONS  │  │ TROUBLESHOOTING │
              │    .md      │  │      .md        │
              └─────────────┘  └─────────────────┘
```

---

**Need help?** Start with [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
