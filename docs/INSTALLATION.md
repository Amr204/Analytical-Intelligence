# 🚀 Installation Guide

> Complete setup instructions for Analysis and Sensor servers

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Analysis Server Setup](#analysis-server-setup)
- [Sensor Server Setup](#sensor-server-setup)
- [Post-Installation Verification](#post-installation-verification)
- [Multi-Sensor Deployment](#multi-sensor-deployment)
- [Next Steps](#next-steps)

---

## Prerequisites

### Hardware Requirements

| Server | RAM | Disk | Purpose |
|--------|-----|------|---------|
| Analysis | 4GB+ | 20GB+ | Backend, Database, ML |
| Sensor | 2GB+ | 10GB+ | Collectors |

### Software Requirements

- Ubuntu 22.04 LTS (both servers)
- Docker (installed during setup)
- Network connectivity between servers

### Network Requirements

- Both servers on same network (e.g., `192.168.1.0/24`)
- Port 8000 open on Analysis server
- Port 22 open for SSH access

---

## Analysis Server Setup

### Step 1: Update System

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Docker

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
```

**Log out and back in** to apply group changes:
```bash
exit
# Reconnect via SSH
```

### Step 3: Verify Docker

```bash
docker --version
docker compose version
```

### Step 4: Clone Repository

```bash
cd ~
git clone https://github.com/Amr204/Analytical-Intelligence.git
cd Analytical-Intelligence
```

### Step 5: Configure Environment

```bash
cp .env.example .env
nano .env
```

**Minimum required settings for Analysis server:**
```bash
# Change this to a secure key!
INGEST_API_KEY=<YOUR_SECURE_API_KEY>
```

Save: `Ctrl+X` → `Y` → `Enter`

### Step 6: Verify Models

```bash
ls -la models/ssh/
# Expected: ssh_lstm.joblib

ls -la models/RF/
# Expected: random_forest.joblib, feature_list.json, label_map.json
```

### Step 7: Start Analysis Stack

```bash
bash scripts/analysis_up.sh
```

**First run takes 5-10 minutes** (building images).

Expected output:
```
==============================================
Analytical-Intelligence Analysis Stack Startup
==============================================
✓ BuildKit enabled (faster rebuilds with pip cache)

Checking ML models...
  ✓ SSH LSTM model found
  ✓ Network RF model found

Starting Analysis Stack...
[+] Running 2/2
 ✔ Container ai_db-postgres  Started
 ✔ Container ai_db-backend   Started

==============================================
Analysis Stack Ready!
==============================================
Dashboard: http://localhost:8000
```

### Step 8: Verify Health

```bash
curl -s http://localhost:8000/api/v1/health | jq
```

Expected:
```json
{"status": "ok", "timestamp": "...", "version": "1.0.0"}
```

---

## Sensor Server Setup

### Step 1: Install Docker

```bash
sudo apt update && sudo apt upgrade -y
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
exit
# Reconnect via SSH
```

### Step 2: Test Connectivity to Analysis Server

```bash
# Replace <ANALYZER_IP> with your Analysis server IP
ping -c 4 <ANALYZER_IP>
curl -s http://<ANALYZER_IP>:8000/api/v1/health
```

If curl fails, check Analysis server firewall (see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)).

### Step 3: Clone Repository

```bash
cd ~
git clone https://github.com/Amr204/Analytical-Intelligence.git
cd Analytical-Intelligence
```

### Step 4: Find Network Interface

```bash
ip link show
```

Look for your main interface (usually `ens33`, `eth0`, or `enp0s3`).

### Step 5: Configure Environment

```bash
cp .env.example .env
nano .env
```

**Required settings for Sensor server:**
```bash
# Analysis server IP (NO http://, NO port)
ANALYZER_HOST=<ANALYZER_IP>

# Must match Analysis server's key!
INGEST_API_KEY=<YOUR_SECURE_API_KEY>

# MUST BE UNIQUE for each sensor!
DEVICE_ID=sensor-01

# Human-readable name
HOSTNAME=sensor-server

# Your network interface
NET_IFACE=ens33
```

Save: `Ctrl+X` → `Y` → `Enter`

### Step 6: Start Sensor Stack

```bash
bash scripts/sensor_up.sh
```

Expected output:
```
==============================================
Analytical-Intelligence Sensor Stack Startup
==============================================
✓ BuildKit enabled (faster rebuilds with pip cache)

Starting Sensor Stack...
[+] Running 2/2
 ✔ Container ai_db-auth-collector  Started
 ✔ Container ai_db-flow-collector  Started

==============================================
Sensor Stack Started!
==============================================
Device ID: sensor-01
Hostname:  sensor-server
Sending to: <ANALYZER_IP>
```

---

## Post-Installation Verification

### 1. Check Devices Page

Open in browser:
```
http://<ANALYZER_IP>:8000/devices
```

Your sensor should appear with:
- Device ID: `sensor-01`
- Status: Online
- Last seen: Recent timestamp

### 2. Check Container Status

**On Analysis server:**
```bash
docker ps
```
Expected: `ai_db-postgres` and `ai_db-backend` both "Up"

**On Sensor server:**
```bash
docker ps
```
Expected: `ai_db-auth-collector` and `ai_db-flow-collector` both "Up"

### 3. Check Logs

**Analysis server:**
```bash
docker compose -f docker-compose.analysis.yml logs -f backend
```

**Sensor server:**
```bash
docker compose -f docker-compose.sensor.yml logs -f
```

---

## Multi-Sensor Deployment

To add additional sensors:

> [!IMPORTANT]
> **Each sensor MUST have a unique `DEVICE_ID`**

### On Each New Sensor:

1. Follow [Sensor Server Setup](#sensor-server-setup)
2. In `.env`, set a unique `DEVICE_ID`:
   ```bash
   DEVICE_ID=sensor-02   # Different from other sensors!
   HOSTNAME=datacenter-sensor
   ```
3. Start the sensor stack

### Verify All Sensors

Check the devices page:
```
http://<ANALYZER_IP>:8000/devices
```

All sensors should appear with their unique IDs.

---

## Next Steps

| Task | Document |
|------|----------|
| Daily operations | [OPERATIONS.md](OPERATIONS.md) |
| Test with attacks | [README.md](../README.md#-اختبار-النظام-بهجمات-حقيقية) |
| Troubleshooting | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |
| Security hardening | [SECURITY.md](SECURITY.md) |

---

## Quick Reference

| Server | Start Command | Stop Command |
|--------|---------------|--------------|
| Analysis | `bash scripts/analysis_up.sh` | `docker compose -f docker-compose.analysis.yml down` |
| Sensor | `bash scripts/sensor_up.sh` | `docker compose -f docker-compose.sensor.yml down` |
