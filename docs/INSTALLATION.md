# 🚀 Installation Guide

> Complete setup instructions for Analysis and Sensor servers

---

## 📋 Table of Contents

- [Requirements](#requirements)
- [Ubuntu Server Installation](#ubuntu-server-installation)
- [Disk Expansion](#disk-expansion)
- [Analysis Server Setup](#analysis-server-setup)
- [Sensor Server Setup](#sensor-server-setup)
- [Post-Installation Verification](#post-installation-verification)
- [Multi-Sensor Deployment](#multi-sensor-deployment)
- [Troubleshooting: Network Issues](#troubleshooting-network-issues-during-installation)

---

## Requirements

### Hardware Requirements

| Server | OS | RAM | CPU | Disk |
|--------|-----|-----|-----|------|
| **Analysis Server** | Ubuntu Server 22.04 | 4 GB | 4 cores | 40 GB |
| **Sensor Server** | Ubuntu Server 22.04 | 4 GB | 4 cores | 40 GB |

### Network Requirements

- Both servers on the same network (e.g., `192.168.1.0/24`)
- Port 8000 open on Analysis server
- Port 22 open for SSH access

### Software Requirements (Windows)

| Software | Description | Link |
|----------|-------------|------|
| **VMware Workstation** | Run virtual machines | [Download VMware](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html) |
| **MobaXterm** | SSH client for Windows | [Download MobaXterm](https://mobaxterm.mobatek.net/download.html) |
| **Ubuntu Server 22.04** | Server operating system | [Download Ubuntu Server](https://ubuntu.com/download/server) |

---

## Ubuntu Server Installation

### Create Virtual Machine in VMware

1. **New Virtual Machine** → **Typical**
2. **Installer disc image file (iso)** → Select Ubuntu Server ISO
3. **Specifications:**
   - Memory: **4096 MB** (4 GB)
   - Processors: **4**
   - Hard Disk: **40 GB**

### Installation Settings

**For Analyzer (Analysis Server):**

| Field | Value |
|-------|-------|
| Your name | `analyzer` |
| Your server's name | `ubuntu-analyzer` |
| Pick a username | `analyzer` |
| Choose a password | `analyzer` |

**For Sensor (Sensor Server):**

| Field | Value |
|-------|-------|
| Your name | `server` |
| Your server's name | `ubuntu-server` |
| Pick a username | `server` |
| Choose a password | `server` |

> [!IMPORTANT]
> Make sure to enable **Install OpenSSH server** ✓

---

## Disk Expansion

> [!WARNING]
> **This step is required** - Ubuntu Server uses only part of the disk by default

**Run these commands on both servers:**

```bash
# Show partitions
lsblk

# Check current space
df -h /

# Expand partition
sudo growpart /dev/sda 3

# Expand Physical Volume
sudo pvresize /dev/sda3

# Expand Logical Volume
sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv

# Expand filesystem
sudo resize2fs /dev/ubuntu-vg/ubuntu-lv

# Verify expansion
df -h /
```

**Expected result:**
```
Filesystem                         Size  Used Avail Use% Mounted on
/dev/mapper/ubuntu--vg-ubuntu--lv   39G  3.5G   34G   9% /
```

---

## Analysis Server Setup

### 1. Update System

```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Install Docker

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
```

**Log out and reconnect:**
```bash
exit
# Reconnect via MobaXterm
```

### 3. Verify Docker

```bash
docker --version
docker compose version
```

### 4. Clone Repository

```bash
cd ~
git clone https://github.com/Amr204/Analytical-Intelligence.git
cd Analytical-Intelligence
```

### 5. Configure Environment

```bash
cp .env.example .env
nano .env
```

**Edit:**
```bash
INGEST_API_KEY=<YOUR_SECURE_API_KEY>
```

### 6. Verify Models

```bash
ls -la models/ssh/

```

### 7. Start Analysis Stack

```bash
bash scripts/analysis_up.sh
```

**First run takes 5-10 minutes**

### 8. Verify Startup

```bash
docker ps
curl -s http://localhost:8000/api/v1/health | jq
```

### 9. Verify pgAdmin (Database UI)

Open `http://<ANALYZER_IP>:5050` in your browser.
- **Email:** `admin@local.com` (or value in .env)
- **Password:** `change_me` (or value in .env)

---

## Sensor Server Setup

### 1. Install Docker

```bash
sudo apt update && sudo apt upgrade -y
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
exit
# Reconnect via MobaXterm
```

### 2. Test Connectivity to Analysis Server

```bash
# Replace <ANALYZER_IP> with Analysis server IP
ping -c 4 <ANALYZER_IP>
curl -s http://<ANALYZER_IP>:8000/api/v1/health
```

### 3. Clone Repository

```bash
cd ~
git clone https://github.com/Amr204/Analytical-Intelligence.git
cd Analytical-Intelligence
```

### 4. Find Network Interface

```bash
ip link show
```

**Usually: `ens33`, `eth0`, or `enp0s3`**

### 5. Configure Environment

```bash
cp .env.example .env
nano .env
```

**Edit:**
```bash
ANALYZER_HOST=<ANALYZER_IP>
INGEST_API_KEY=<YOUR_SECURE_API_KEY>
DEVICE_ID=sensor-01
HOSTNAME=sensor-server
NET_IFACE=ens33
```

### 6. Start Sensor Stack

```bash
bash scripts/sensor_up.sh
```

### 7. Verify Startup

```bash
docker ps
```

**Expected:**
- `ai_db-auth-collector` ... Up
- `ai_db-suricata-collector` ... Up (Health: healthy)
- `ai_db-suricata` ... Up (Health: healthy)
- `ai_db-suricata-collector` ... Up

---

## Post-Installation Verification

### 1. Devices Page

```
http://<ANALYZER_IP>:8000/devices
```

Sensor should appear with Online status.

### 2. Container Status

**On Analysis server:**
```bash
docker ps
# Expected: ai_db-postgres and ai_db-backend
```

**On Sensor server:**
```bash
docker ps
# Expected: ai_db-auth-collector and ai_db-suricata-collector
```

### 3. Logs

```bash
# Analysis server
docker compose -f docker-compose.analysis.yml logs -f backend

# Sensor server
docker compose -f docker-compose.sensor.yml logs -f
```

---

## Multi-Sensor Deployment

> [!IMPORTANT]
> **Each sensor MUST have a unique `DEVICE_ID`**

### On Each New Sensor:

1. Follow [Sensor Server Setup](#sensor-server-setup)
2. In `.env`, use a unique `DEVICE_ID`:
   ```bash
   DEVICE_ID=sensor-02
   HOSTNAME=datacenter-sensor
   ```
3. Run `bash scripts/sensor_up.sh`

### Verify

```
http://<ANALYZER_IP>:8000/devices
```

All sensors should appear.

---

## Troubleshooting: Network Issues During Installation

> [!NOTE]
> **VPN is OPTIONAL** — only use if you encounter network/DNS issues during installation or updates.

### When do I need the VPN?

| Error Message | Cause |
|---------------|-------|
| `Temporary failure resolving` | DNS resolution failed |
| `Could not resolve host: github.com` | Cannot reach GitHub |
| `Could not resolve host: pypi.org` | Cannot reach Python packages |
| Docker build fails with "resolving" errors | Container DNS issues |
| Corporate/ISP network restrictions | Blocked external access |

### VPN Commands

| Action | Command |
|--------|---------|
| **Start VPN** | `sudo ./scripts/ai-vpn.sh start` |
| **Stop VPN** | `sudo ./scripts/ai-vpn.sh stop` |
| **Check Status** | `sudo ./scripts/ai-vpn.sh status` |
| **View Logs** | `sudo ./scripts/ai-vpn.sh logs` |

### VPN Files

| File | Description |
|------|-------------|
| `scripts/ai-vpn.sh` | VPN management script |
| `scripts/ai-vpn.ovpn` | OpenVPN configuration file |

### Safe Usage Notes

> [!IMPORTANT]
> - **Verify internet first:** Run `ping 8.8.8.8` before starting VPN
> - **Endpoint offline?** If VPN endpoint is unreachable, use a different `.ovpn` file
> - **Do NOT edit `/etc/resolv.conf` manually** on Ubuntu Server — the script uses systemd-resolved integration

### Example: Install with VPN

```bash
# 1. Start VPN if DNS is failing
sudo ./scripts/ai-vpn.sh start

# 2. Proceed with installation
sudo apt update && sudo apt upgrade -y
curl -fsSL https://get.docker.com | sudo sh
git clone https://github.com/Amr204/Analytical-Intelligence.git

# 3. Stop VPN when done (optional)
sudo ./scripts/ai-vpn.sh stop
```

---

## Quick Reference

| Server | Start Command | Stop Command |
|--------|---------------|--------------|
| Analysis | `bash scripts/analysis_up.sh` | `docker compose -f docker-compose.analysis.yml down` |
| Sensor | `bash scripts/sensor_up.sh` | `docker compose -f docker-compose.sensor.yml down` |

---

## Next Steps

| Task | Document |
|------|----------|
| Daily operations | [OPERATIONS.md](OPERATIONS.md) |
| Test with attacks | [README.md](../README.md#-testing-with-real-attacks) |
| Troubleshooting | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |
| Security hardening | [SECURITY.md](SECURITY.md) |
