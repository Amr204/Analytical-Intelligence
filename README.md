#  Analytical-Intelligence v1 - Security Event Management System

> A lightweight SIEM for real-time attack detection using Machine Learning

---

## 📋 Table of Contents

1. [Overview](#-overview)
2. [Requirements](#-requirements)
3. [Ubuntu Server Installation](#-ubuntu-server-installation)
4. [MobaXterm Connection](#-mobaxterm-connection)
5. [Analysis Server Setup](#-analysis-server-setup)
6. [Sensor Server Setup](#-sensor-server-setup)
7. [Testing with Real Attacks](#-testing-with-real-attacks)
8. [Verification](#-verification)
9. [Operation Scenarios](#-operation-scenarios)
10. [Advanced Settings](#-advanced-settings)
11. [Troubleshooting](#-troubleshooting)

---

## 📖 Overview

### What is Analytical-Intelligence?

A real-time security threat detection system using:

| Component | Function | Accuracy |
|-----------|----------|----------|
| **SSH LSTM** | SSH Brute Force detection | High |
| **Suricata IDS** | Network Signature Detection (DoS, Scan, Malware) | High |


### 🎯 Detected Attack Types

| Attack Type | Description |
|-------------|-------------|
| **DoS** | Denial of Service - flooding server with requests |
| **DDoS** | Distributed DoS - distributed attack |
| **Port Scanning** | Scanning open ports |
| **Brute Force** | Password guessing |
| **SSH Authentication** | SSH authentication attacks |

### 📚 Full Documentation

| Document | Description |
|----------|-------------|
| [Documentation Index](docs/INDEX.md) | Quick navigation to all docs |
| [Installation Guide](docs/INSTALLATION.md) | Analysis + Sensor setup |
| [Operations Guide](docs/OPERATIONS.md) | Start/stop + add sensors |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Comprehensive problem-solving |
| [Upgrades Guide](docs/UPGRADES.md) | Safe system updates |
| [Architecture](docs/ARCHITECTURE.md) | Design and data flow |
| [ML Models](docs/ML.md) | Model tuning and thresholds |
| [Security](docs/SECURITY.md) | Firewall and hardening |

---

## 📦 Requirements

### Hardware Requirements

| Server | OS | RAM | CPU | Disk |
|--------|-----|-----|-----|------|
| **Analysis Server** | Ubuntu Server 22.04 | 4 GB | 4 cores | 40 GB |
| **Sensor Server** | Ubuntu Server 22.04 | 4 GB | 4 cores | 40 GB |

> **Note:** Both servers must be on the same network (e.g., `192.168.1.0/24`)

### Software Requirements (Windows)

| Software | Description | Link |
|----------|-------------|------|
| **VMware Workstation** | Run virtual machines | [Download VMware](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html) |
| **MobaXterm** | SSH client for Windows | [Download MobaXterm](https://mobaxterm.mobatek.net/download.html) |
| **Ubuntu Server 22.04** | Server operating system | [Download Ubuntu Server](https://ubuntu.com/download/server) |

---

## 💿 Ubuntu Server Installation

### Installation Steps in VMware

1. **Create a new virtual machine** in VMware:
   - Memory: **4 GB**
   - Processors: **4 cores**
   - Hard Disk: **40 GB**

2. **Set names during installation:**

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

3. **Enable OpenSSH** during installation ✓
4. **Complete installation and restart**

---

## 🖥️ MobaXterm Connection

### Step 1: Download MobaXterm

1. Open browser and visit: https://mobaxterm.mobatek.net/download.html
2. Choose **MobaXterm Home Edition (Installer edition)**
3. Download and run the installer
4. Click Next → Next → Install → Finish

### Step 2: Find Server IPs

**On each server:**

```bash
ip addr show
```

**Record the IPs:**

| Server | Hostname | IP (example) |
|--------|----------|--------------|
| Analyzer | ubuntu-analyzer | 192.168.1.20 |
| Sensor | ubuntu-server | 192.168.1.21 |

### Step 3: Connect to Servers

1. **Open MobaXterm**
2. Click **Session** → **SSH**

**Analyzer connection settings:**
```
Remote host: 192.168.1.20
Username:    analyzer
Port:        22
Password:    analyzer
```

**Sensor connection settings:**
```
Remote host: 192.168.1.21
Username:    server
Port:        22
Password:    server
```

**Expected result:**

Two tabs in MobaXterm:
- ubuntu-analyzer (Analysis Server)
- ubuntu-server (Sensor Server)

---

## 📊 Analysis Server Setup

> **Open ubuntu-analyzer tab in MobaXterm**

### Step 0: Disk Expansion (Required!)

> ⚠️ **This step is required** to use full disk space (40 GB)

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

### Step 1: Update System

```bash
# Update package list
sudo apt update

# Upgrade installed packages
sudo apt upgrade -y
```

**Wait until complete (may take 2-5 minutes)**

### Step 2: Install Docker

```bash
# Download and install Docker
curl -fsSL https://get.docker.com | sudo sh
```

**Wait until complete (may take 1-3 minutes)**

```bash
# Add user to Docker group
sudo usermod -aG docker $USER
```

### Step 3: Activate Permissions (Important!)

```bash
# Log out and back in to activate permissions
exit
```

**Now in MobaXterm:**
- Reconnect to the server (click on the tab again)
- Or click **Reconnect** button

### Step 4: Verify Docker

```bash
# Check Docker version
docker --version
```

**Expected result:**
```
Docker version 24.0.7, build afdd53b
```

```bash
# Check Docker Compose
docker compose version
```

**Expected result:**
```
Docker Compose version v2.21.0
```

### Step 5: Clone Repository

```bash
# Go to home directory
cd ~

# Clone project from GitHub
git clone https://github.com/Amr204/Analytical-Intelligence.git

# Enter project folder
cd Analytical-Intelligence

# Verify files
ls -la
```

**Expected result:**
```
drwxrwxr-x  8 user user 4096 Jan 16 10:00 .
drwxr-xr-x 15 user user 4096 Jan 16 10:00 ..
-rw-rw-r--  1 user user  XXX Jan 16 10:00 docker-compose.analysis.yml
-rw-rw-r--  1 user user  XXX Jan 16 10:00 docker-compose.sensor.yml
drwxrwxr-x  3 user user 4096 Jan 16 10:00 models
drwxrwxr-x  2 user user 4096 Jan 16 10:00 scripts
drwxrwxr-x  3 user user 4096 Jan 16 10:00 services
...
```

### Step 6: Verify Models

```bash
# Check SSH model
ls -la models/ssh/
```

**Expected result:**
```
-rw-rw-r-- 1 user user XXXXX Jan 16 10:00 ssh_lstm.joblib
```



### Step 7: Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Open file for editing
nano .env
```

**File contents (change API Key for security):**

```bash
# API Key - change in production!
INGEST_API_KEY=MySecureKey12345

# Database
POSTGRES_USER=ai
POSTGRES_PASSWORD=ai2025
POSTGRES_DB=ai_db
```

**To save and exit nano:**
1. Press `Ctrl + X`
2. Press `Y`
3. Press `Enter`

### Step 8: Start System

```bash
# Start Analysis Stack (enables BuildKit automatically)
bash scripts/analysis_up.sh
```

**Wait! This step takes time (5-10 minutes on first run)**

**You will see something like:**
```
==============================================
Analytical-Intelligence Analysis Stack Startup
==============================================
✓ BuildKit enabled (dependency caching active)

Checking ML models...
  ✓ SSH LSTM model found


Starting Analysis Stack...
[+] Running 2/2
 ✔ Container ai_db-postgres  Started
 ✔ Container ai_db-backend   Started

==============================================
Analysis Stack Ready!
==============================================
Dashboard: http://localhost:8000
```

<details>
<summary>📌 Manual startup (for advanced users)</summary>

```bash
# Enable BuildKit manually
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# Build and start
docker compose -f docker-compose.analysis.yml up -d --build

# Watch logs
docker compose -f docker-compose.analysis.yml logs -f backend
```
</details>

### Step 9: Verify Startup

```bash
# Check container status
docker ps
```

**Expected result:**
```
CONTAINER ID   IMAGE              COMMAND                  STATUS          PORTS                    NAMES
xxx            ai_db-backend     "uvicorn app.main:…"     Up 25 seconds   0.0.0.0:8000->8000/tcp   ai_db-backend
xxx            postgres:15       "docker-entrypoint.…"    Up 30 seconds   5432/tcp                 ai_db-postgres
```

**Important:** STATUS must be "Up" for both containers!

### Step 10: Check API Health

```bash
# Check Health endpoint
curl -s http://localhost:8000/api/v1/health | jq
```

**Expected result:**
```json
{
  "status": "ok",
  "timestamp": "2026-01-16T10:30:00.000000Z",
  "version": "1.0.0"
}
```

**If `jq` is not installed:**
```bash
sudo apt install -y jq
```

### Step 11: Open Dashboard in Browser

**On your Windows machine:**

1. Open browser (Chrome/Firefox/Edge)
2. Enter in address bar:
   ```
   http://192.168.1.20:8000
   ```
   (Replace with your Analysis server IP)

**Expected result:**
- Dashboard page appears
- Shows statistics (may be zero initially)

### Step 12: Open Firewall (if dashboard doesn't open)

```bash
# Allow SSH first (important!)
sudo ufw allow 22/tcp
```

**⚠️ Recommended security setup (port 8000 restrictions):**

```bash
# Allow only Sensor to access API
sudo ufw allow from <SENSOR_IP> to any port 8000 proto tcp

# Allow Windows machine to access dashboard
sudo ufw allow from <YOUR_WINDOWS_IP> to any port 8000 proto tcp

# Deny others from accessing 8000
sudo ufw deny 8000/tcp

# Enable UFW
sudo ufw enable

# Verify rules
sudo ufw status numbered
```

**Real example:**
```bash
# Allow Sensor with IP 192.168.1.21
sudo ufw allow from 192.168.1.21 to any port 8000 proto tcp

# Allow Windows machine with IP 192.168.1.100
sudo ufw allow from 192.168.1.100 to any port 8000 proto tcp

# Deny others
sudo ufw deny 8000/tcp
sudo ufw enable
```

**Expected result:**
```
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8000/tcp                   ALLOW IN    192.168.1.21
[ 3] 8000/tcp                   ALLOW IN    192.168.1.100
[ 4] 8000/tcp                   DENY IN     Anywhere
```

**🔓 Simple setup (for testing only):**
```bash
# Open 8000 for any device (not secure in production!)
sudo ufw allow 8000
sudo ufw enable
```

---

## 🔍 Sensor Server Setup

> **Open Sensor Server tab in MobaXterm**

### Step 1: Update and Install Docker

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sudo sh

# Add user to Docker group
sudo usermod -aG docker $USER

# Log out to activate permissions
exit
```

**Reconnect to server in MobaXterm**

### Step 2: Verify Docker

```bash
docker --version
docker compose version
```

### Step 3: Test Connection to Analysis Server

```bash
# Test ping (replace with Analysis server IP)
ping -c 4 192.168.1.20
```

**Expected result:**
```
PING 192.168.1.20 (192.168.1.20) 56(84) bytes of data.
64 bytes from 192.168.1.20: icmp_seq=1 ttl=64 time=0.345 ms
64 bytes from 192.168.1.20: icmp_seq=2 ttl=64 time=0.289 ms
...
```

```bash
# Test API
curl -s http://192.168.1.20:8000/api/v1/health
```

**Expected result:**
```json
{"status":"ok","timestamp":"...","version":"1.0.0"}
```

**If connection fails:**
- Make sure Analysis Server is running
- Check firewall (ufw allow 8000)
- Make sure both servers are on the same network

### Step 4: Clone Repository

```bash
cd ~
git clone https://github.com/Amr204/Analytical-Intelligence.git
cd Analytical-Intelligence
```

### Step 5: Find Network Interface Name

```bash
# Show network interfaces
ip link show
```

**Expected result:**
```
1: lo: <LOOPBACK,UP,LOWER_UP> ...
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> ...  ← this one
```

**Note the interface name (usually: ens33, eth0, or enp0s3)**

### Step 6: Configure Environment

```bash
cp .env.example .env
nano .env
```

**Edit these variables:**

```bash
# Analysis server address (change it!)
ANALYZER_HOST=192.168.1.20

# API key (same key as Analysis!)
INGEST_API_KEY=MySecureKey12345

# Network interface (change as needed!)
NET_IFACE=ens33

# Device ID
DEVICE_ID=sensor-01
HOSTNAME=sensor-server
```

**To save:** `Ctrl + X` → `Y` → `Enter`

### Step 7: Start Sensor Stack

```bash
# Start Sensor Stack (enables BuildKit automatically)
bash scripts/sensor_up.sh
```

**Wait (3-5 minutes on first run)**

<details>
<summary>📌 Manual startup (for advanced users)</summary>

```bash
# Enable BuildKit manually
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# Build and start
docker compose -f docker-compose.sensor.yml up -d --build

# Watch logs
docker compose -f docker-compose.sensor.yml logs -f
```
</details>

### Step 8: Verify Startup

```bash
docker ps
```

**Expected result:**
```
CONTAINER ID   IMAGE                     STATUS         NAMES
xxx            ai_db-auth-collector     Up 1 minute    ai_db-auth-collector
xxx            ai_db-suricata           Up 1 minute    ai_db-suricata
xxx            ai_db-suricata-collector Up 1 minute    ai_db-suricata-collector
```

### Step 9: Watch Logs

```bash
# Watch logs directly
docker compose -f docker-compose.sensor.yml logs -f
```

**Press `Ctrl + C` to exit**

---

## ⚔️ Testing with Real Attacks

> **Open Kali (Attacker) tab in MobaXterm**

### 🎯 Attack 1: SSH Brute Force

**Goal:** Test SSH password guessing attack detection

```bash
# Install hydra if not present
sudo apt install -y hydra

# Create test password file
echo -e "admin\n123456\npassword\nroot\ntest\nuser\nletmein\nqwerty" > passwords.txt

# Execute Brute Force attack on Sensor Server
hydra -l root -P passwords.txt ssh://192.168.1.21 -t 4 -V
```

**Replace `192.168.1.21` with Sensor server IP**

**You will see:**
```
[DATA] attacking ssh://192.168.1.21:22/
[22][ssh] host: 192.168.1.21   login: root   password: (failed)
[22][ssh] host: 192.168.1.21   login: root   password: (failed)
...
```

### 🎯 Attack 2: Port Scanning (Nmap)

**Goal:** Test port scanning detection

```bash
# Quick scan of common ports
nmap -sS -F 192.168.1.21

# Full port scan
nmap -sS -p- 192.168.1.21 --min-rate 1000
```

**You will see:**
```
Starting Nmap
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
...
```

### 🎯 Attack 3: SYN Flood (DoS)

**Goal:** Test DoS attack detection

```bash
# Install hping3
sudo apt install -y hping3

# SYN Flood attack on port 80
sudo hping3 -S --flood -V -p 80 192.168.1.21
```

**Press `Ctrl + C` after 10 seconds to stop the attack**

### 🎯 Attack 4: Simulating Failed SSH Logins

```bash
# Repeated failed login attempts
for i in {1..10}; do
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 wronguser@192.168.1.21
    echo "Attempt $i"
done
```

**Each attempt will fail and be logged in the system**

---

## ✅ Verification

### 1. Check Dashboard

**In browser:**
```
http://192.168.1.20:8000
```

**You should see:**
- Event count increasing
- New alerts appearing
- Graph updating

### 2. Check Alerts Page

**In browser:**
```
http://192.168.1.20:8000/alerts
```

**You should see:**
- Alerts with different colors (by severity)
- Different types: Port Scanning, Brute Force, DoS

### 3. Check API

**On Analysis server:**

```bash
# Event count in database
docker exec -it ai_db-postgres psql -U ai -d ai_db -c "
SELECT event_type, COUNT(*) as count 
FROM raw_events 
GROUP BY event_type;
"
```

**Expected result:**
```
 event_type | count
------------+-------
 auth       |   45
 flow       |  120
```

```bash
# Alert count by type
docker exec -it ai_db-postgres psql -U ai -d ai_db -c "
SELECT model_name, label, severity, COUNT(*) as count
FROM detections 
GROUP BY model_name, label, severity
ORDER BY count DESC;
"
```

**Expected result:**
```
 model_name | label          | severity | count
------------+----------------+----------+-------

 ssh_lstm   | Brute Force    | CRITICAL |     5
```

### 4. Watch Logs Directly

**On Analysis server:**
```bash
# Watch Backend logs directly
docker logs -f ai_db-backend
```

**You will see messages like:**
```
INFO:     suricata_ingest: Alert received: ET SCAN Potential SSH Scan
INFO:     SSH detection: Brute Force attempt detected
```

---

## 🔄 Operation Scenarios

### Scenario 1: Start System After Server Restart

**On Analysis server:**
```bash
cd ~/Analytical-Intelligence
docker compose -f docker-compose.analysis.yml up -d
```

**On Sensor server:**
```bash
cd ~/Analytical-Intelligence
docker compose -f docker-compose.sensor.yml up -d
```

### Scenario 2: Update Code After git pull

```bash
cd ~/Analytical-Intelligence
git pull

# Rebuild (fast thanks to cache)
docker compose -f docker-compose.analysis.yml up -d --build
```

> **Tip:** If you encounter DNS errors during `git pull` or `docker build`, see [Optional VPN for Updates](#-optional-vpn-for-updates).

### Scenario 3: Stop System

**On Analysis server:**
```bash
docker compose -f docker-compose.analysis.yml down
```

**On Sensor server:**
```bash
docker compose -f docker-compose.sensor.yml down
```

### Scenario 4: Full Reset (Delete All Data)

```bash
# ⚠️ Deletes all data!
docker compose -f docker-compose.analysis.yml down -v
docker compose -f docker-compose.analysis.yml up -d --build
```

---

## 📡 Multi-Device Setup

### How Does the System Work with Multiple Sensors?

The system supports multiple sensors sending data to one analysis server:

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   Sensor 1 (sensor-dc1)  ──┐                                    │
│                            │                                    │
│   Sensor 2 (sensor-dc2)  ──┼──► Analysis Server ──► Dashboard   │
│                            │      :8000                         │
│   Sensor 3 (sensor-dmz)  ──┘                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Steps to Add New Sensor

**On the new Sensor:**

```bash
# 1. Clone repository
git clone https://github.com/Amr204/Analytical-Intelligence.git
cd Analytical-Intelligence

# 2. Create .env with unique DEVICE_ID!
cp .env.example .env
nano .env
```

**.env contents (important!):**
```bash
ANALYZER_HOST=192.168.1.20        # Analysis server IP
INGEST_API_KEY=MySecureKey12345   # Same key as Analysis!

# ⚠️ DEVICE_ID must be unique for each Sensor!
DEVICE_ID=sensor-datacenter-02    # Unique!
HOSTNAME=datacenter-sensor-02
NET_IFACE=ens33
```

```bash
# 3. Start Sensor
bash scripts/sensor_up.sh
```

### View Devices in Dashboard

**In browser:**
```
http://<ANALYZER_IP>:8000/devices
```

**You will see:**
- Device cards for each sensor
- Online/Offline status for each device
- Alert count in last 24 hours
- "View Details" button for device details

### Filter Alerts by Device

**On Alerts page:**
```
http://<ANALYZER_IP>:8000/alerts?device_id=sensor-01
```

Or use the "Device" dropdown in page filters.

---

## ⚙️ Advanced Settings



### Adjust Detection Sensitivity

```bash
# Suricata Noise Profile (balanced, low-noise, aggressive)
SURICATA_PROFILE=balanced

# Failed attempts to trigger SSH alert
SSH_BRUTEFORCE_THRESHOLD=5

# Time window for aggregating attempts (seconds)
SSH_BRUTEFORCE_WINDOW_SECONDS=300
```

---

## 🔧 Troubleshooting

For comprehensive troubleshooting guide, see:

📖 **[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)** - Full troubleshooting guide

Includes:
- System recovery after restart
- IP address change issues
- Docker and build issues
- ML model issues
- Database issues
- Network and firewall issues

### Quick Fixes

| Problem | Quick Fix |
|---------|-----------|
| Dashboard doesn't open | `sudo ufw allow 8000` |
| Sensor doesn't connect | Check `ANALYZER_HOST` in `.env` |
| No alerts | Check `SURICATA_PROFILE` in `.env` |
| Container doesn't start | `docker compose logs backend` |
| DNS fails during build | `bash scripts/docker_doctor.sh` or [use VPN](#-optional-vpn-for-updates) |

---

### 🔐 Optional VPN for Updates

> **This step is OPTIONAL** — only use when you encounter network/DNS issues during updates or installations.

#### When do I need the VPN?

Use the VPN if you see any of these errors:

| Error Message | Cause |
|---------------|-------|
| `Temporary failure resolving` | DNS resolution failed |
| `Could not resolve host: github.com` | Cannot reach GitHub |
| `Could not resolve host: pypi.org` | Cannot reach Python packages |
| Docker build fails with "resolving" errors | Container DNS issues |
| Corporate/ISP network restrictions | Blocked external access |

#### VPN Commands

| Action | Command |
|--------|---------|
| **Permissions** | `sudo chmod +x scripts/ai-vpn.sh` |
| **Start VPN** | `sudo ./scripts/ai-vpn.sh start` |
| **Stop VPN** | `sudo ./scripts/ai-vpn.sh stop` |
| **Check Status** | `sudo ./scripts/ai-vpn.sh status` |
| **View Logs** | `sudo ./scripts/ai-vpn.sh logs` |

#### VPN Files

| File | Description |
|------|-------------|
| `scripts/ai-vpn.sh` | VPN management script |
| `scripts/ai-vpn.ovpn` | OpenVPN configuration file |

#### Safe Usage Notes

> [!IMPORTANT]
> - **Verify internet first:** Run `ping 8.8.8.8` before starting VPN
> - **Endpoint offline?** If VPN endpoint is unreachable, use a different `.ovpn` file
> - **Do NOT edit `/etc/resolv.conf` manually** on Ubuntu Server — the script uses systemd-resolved integration

#### Example: Update with VPN

```bash
# 1. Start VPN if DNS is failing
sudo ./scripts/ai-vpn.sh start

# 2. Proceed with update
cd ~/Analytical-Intelligence
git pull
docker compose -f docker-compose.analysis.yml up -d --build

# 3. Stop VPN when done (optional)
sudo ./scripts/ai-vpn.sh stop
```

---

## 📊 System Summary

```
┌─────────────────────────────────────────────────────────────┐
│                    Analytical-Intelligence                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Models:                                                    │
│   ├── SSH LSTM (Brute Force Detection)                      │
│   └── Suricata IDS (Signature-based Network Detection)      │
│                                                              │
│   Sensors:                                                   │
│   ├── auth_collector (SSH logs)                             │
│   ├── suricata (Network IDS)                                │
│   └── suricata_collector (Alert shipper)                    │
│                                                              │
│   UI: http://<ANALYZER_IP>:8000                             │
│   ├── /           → Dashboard                               │
│   ├── /alerts     → Security Alerts                         │
│   ├── /devices    → Device Inventory                        │
│   ├── /events     → Raw Events                              │
│   └── /models     → Models Status                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 📄 License

MIT License - Use freely with attribution.
