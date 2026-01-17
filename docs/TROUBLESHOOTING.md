# 🔧 Troubleshooting Guide

> Comprehensive runbook for diagnosing and fixing common issues

---

## Table of Contents

- [Quick Diagnosis](#quick-diagnosis)
- [A. Power Loss / Reboot Recovery](#a-power-loss--reboot-recovery)
- [B. IP Changes](#b-ip-changes)
- [C. Multi-Sensor Issues](#c-multi-sensor-issues)
- [D. Docker Issues](#d-docker-issues)
- [E. ML Model Issues](#e-ml-model-issues)
- [F. Database Issues](#f-database-issues)
- [G. Network / Firewall Issues](#g-network--firewall-issues)
- [H. Sensor Issues](#h-sensor-issues)
- [Common Mistakes](#common-mistakes)

---

## Quick Diagnosis

Run these commands to understand system state:

```bash
# 1. Check Docker is running
sudo systemctl status docker

# 2. Check containers
docker ps
docker compose -f docker-compose.analysis.yml ps  # or sensor.yml

# 3. Check logs for errors
docker compose -f docker-compose.analysis.yml logs --tail=50 backend

# 4. Check health endpoint
curl -s http://localhost:8000/api/v1/health | jq

# 5. Check listening ports
ss -lntp | grep 8000

# 6. Check firewall
sudo ufw status numbered
```

---

## A. Power Loss / Reboot Recovery

### Symptoms
- Dashboard not accessible after reboot
- Sensors not sending data
- `docker ps` shows no containers

### Recovery Steps

#### On Analysis Server

```bash
# 1. Start Docker service
sudo systemctl start docker

# 2. Navigate to project
cd ~/Analytical-Intelligence

# 3. Start analysis stack
bash scripts/analysis_up.sh

# 4. Verify health
curl -s http://localhost:8000/api/v1/health | jq
# Expected: {"status": "ok", ...}

# 5. Check containers
docker ps
# Expected: ai_db-postgres, ai_db-backend both "Up"
```

#### On Each Sensor Server

```bash
# 1. Start Docker service
sudo systemctl start docker

# 2. Navigate to project
cd ~/Analytical-Intelligence

# 3. Start sensor stack
bash scripts/sensor_up.sh

# 4. Verify containers
docker ps
# Expected: ai_db-auth-collector, ai_db-flow-collector both "Up"
```

### Verification

```bash
# On Analysis server - check device heartbeat
docker exec -it ai_db-postgres psql -U ai -d ai_db -c "
SELECT device_id, last_seen_at 
FROM devices 
ORDER BY last_seen_at DESC;
"
```

### Prevention

Enable Docker auto-start:
```bash
sudo systemctl enable docker
```

---

## B. IP Changes

### B1. Analyzer IP Changed

#### Symptoms
- Sensors show "connection refused" in logs
- No new events arriving
- Devices page shows old data

#### Fix Steps

**1. Find new Analyzer IP:**
```bash
# On Analysis server
ip a | grep inet
# or
hostname -I
```

**2. Update each sensor's `.env`:**
```bash
# On each sensor server
cd ~/Analytical-Intelligence
nano .env
```

Change:
```bash
ANALYZER_HOST=<NEW_ANALYZER_IP>
```

**3. Restart sensors:**
```bash
docker compose -f docker-compose.sensor.yml down
docker compose -f docker-compose.sensor.yml up -d
```

**4. If using strict firewall, update UFW on Analyzer:**
```bash
# On Analysis server
sudo ufw status numbered
# Delete old sensor IP rule (note the number)
sudo ufw delete <RULE_NUMBER>
# Add new sensor IP if it also changed
sudo ufw allow from <SENSOR_IP> to any port 8000 proto tcp
```

#### Verification
```bash
# From sensor
curl -s http://<NEW_ANALYZER_IP>:8000/api/v1/health
```

### B2. Sensor IP Changed

#### Symptoms
- Usually none (sensors make outgoing connections)
- If strict firewall: sensors blocked

#### Fix Steps

**Only if using strict firewall on Analyzer:**
```bash
# On Analysis server
sudo ufw status numbered
# Delete old sensor IP rule
sudo ufw delete <RULE_NUMBER>
# Add new sensor IP
sudo ufw allow from <NEW_SENSOR_IP> to any port 8000 proto tcp
```

#### Verification
```bash
# Check device heartbeat
docker exec -it ai_db-postgres psql -U ai -d ai_db -c "
SELECT device_id, device_ip, last_seen_at FROM devices;
"
```

---

## C. Multi-Sensor Issues

### C1. Sensors Not Appearing in Devices Page

#### Symptoms
- `/devices` page doesn't show expected sensors
- Only some sensors visible

#### Likely Causes

| Cause | Check |
|-------|-------|
| Sensor not running | `docker ps` on sensor |
| Wrong ANALYZER_HOST | Check sensor `.env` |
| Firewall blocking | `sudo ufw status` on analyzer |
| API key mismatch | Compare `INGEST_API_KEY` |

#### Fix Steps

**1. Check sensor containers:**
```bash
# On sensor
docker ps
docker compose -f docker-compose.sensor.yml logs
```

**2. Test connectivity:**
```bash
# On sensor
curl -s http://<ANALYZER_IP>:8000/api/v1/health
```

### C2. Duplicate DEVICE_ID

#### Symptoms
- Events mixed between sensors
- Confusion in device tracking

#### Fix Steps

**Ensure unique DEVICE_ID for each sensor:**

```bash
# Sensor 1
DEVICE_ID=sensor-01

# Sensor 2
DEVICE_ID=sensor-02

# Sensor 3
DEVICE_ID=sensor-datacenter
```

After fixing, restart the sensor:
```bash
docker compose -f docker-compose.sensor.yml down
docker compose -f docker-compose.sensor.yml up -d
```

### C3. List All Registered Devices

```bash
docker exec -it ai_db-postgres psql -U ai -d ai_db -c "
SELECT 
  device_id, 
  hostname, 
  device_ip, 
  last_seen_at,
  CASE WHEN last_seen_at > NOW() - INTERVAL '5 minutes' 
       THEN 'ONLINE' ELSE 'OFFLINE' END as status
FROM devices 
ORDER BY last_seen_at DESC;
"
```

---

## D. Docker Issues

### D1. Docker Service Not Running

#### Symptoms
```
Cannot connect to the Docker daemon
```

#### Fix
```bash
sudo systemctl start docker
sudo systemctl status docker
```

### D2. Invalid daemon.json

#### Symptoms
```
Error starting daemon: error initializing graphdriver
```
or Docker fails to start.

#### Fix Steps

**1. Validate JSON:**
```bash
sudo python3 -m json.tool /etc/docker/daemon.json
```

**2. If invalid, fix or reset:**
```bash
# Backup
sudo cp /etc/docker/daemon.json /etc/docker/daemon.json.bak

# Edit
sudo nano /etc/docker/daemon.json
```

Common fix (minimal valid daemon.json):
```json
{}
```

**3. Restart Docker:**
```bash
sudo systemctl restart docker
```

### D3. DNS Failures During Build

#### Symptoms
```
Temporary failure resolving 'deb.debian.org'
```

#### Fix Steps

**1. Add DNS to Docker:**
```bash
sudo nano /etc/docker/daemon.json
```

Add:
```json
{
  "dns": ["8.8.8.8", "8.8.4.4"]
}
```

**2. Restart Docker:**
```bash
sudo systemctl restart docker
```

**3. Test DNS:**
```bash
docker run --rm alpine nslookup google.com
```

### D4. Build Caching Behavior

> [!NOTE]
> **`docker compose logs` does NOT install packages.**
> Dependencies are only installed during `docker build`.

**When cache is used:**
- Code changes only → pip cache used → fast (~30s)

**When rebuild occurs:**
- `requirements.txt` changes → pip install runs
- Dockerfile changes → full layer rebuild

**Force fresh build (rarely needed):**
```bash
docker compose -f docker-compose.analysis.yml build --no-cache
docker compose -f docker-compose.analysis.yml up -d
```

> [!WARNING]
> **Avoid `docker system prune -a`** - this deletes pip cache and slows future builds.

---

## E. ML Model Issues

### E1. Model Files Not Found

#### Symptoms
```
Network RF model not loaded
SSH LSTM model not loaded
```

#### Fix Steps

**1. Verify files exist on host:**
```bash
ls -la models/ssh/
# Expected: ssh_lstm.joblib

ls -la models/RF/
# Expected: random_forest.joblib, feature_list.json, label_map.json
```

**2. Check volume mounts:**
```bash
docker exec ai_db-backend ls -la /app/models/ssh/
docker exec ai_db-backend ls -la /app/models/RF/
```

**3. Restart backend:**
```bash
docker compose -f docker-compose.analysis.yml restart backend
```

### E2. scikit-learn Version Mismatch

#### Symptoms
```
InconsistentVersionWarning
UserWarning: Trying to unpickle estimator
```
or predictions fail.

#### Cause
Model was trained with different scikit-learn/numpy version than container has.

#### Fix Steps

**1. Check versions in logs:**
```bash
docker compose -f docker-compose.analysis.yml logs backend | grep -i "version\|warning"
```

**2. Pin versions in requirements.txt and rebuild:**
```bash
# Edit services/backend/requirements.txt
# Add specific versions like:
# scikit-learn==1.3.0
# numpy==1.24.0

# Then rebuild
docker compose -f docker-compose.analysis.yml build --no-cache backend
docker compose -f docker-compose.analysis.yml up -d
```

### E3. Quick Python Model Test

```bash
docker exec -it ai_db-backend python3 -c "
import joblib
model = joblib.load('/app/models/RF/random_forest.joblib')
print('Model loaded successfully')
print(f'Model type: {type(model).__name__}')
"
```

### E4. Too Many False Positives

#### Cause
Network ML threshold too low.

#### Fix
```bash
# Edit .env on Analysis server
NETWORK_ML_THRESHOLD=0.70   # Increase from 0.60

# Restart backend
docker compose -f docker-compose.analysis.yml restart backend
```

### E5. Missing Detections

#### Cause
Threshold too high or gating layer filtering.

#### Fix

**Lower threshold:**
```bash
NETWORK_ML_THRESHOLD=0.50
```

**Check gating layer settings:**
```bash
ML_MIN_FLOW_RATE_PPS=50    # Lower from 100
```

---

## F. Database Issues

### F1. Postgres Not Healthy

#### Symptoms
```
Dependency failed: postgres is not healthy
```

#### Fix Steps

**1. Check postgres container:**
```bash
docker compose -f docker-compose.analysis.yml logs postgres
```

**2. Common issues:**
- Wrong credentials → Check `.env` matches compose
- Corrupted data → Try restart first

**3. Restart postgres:**
```bash
docker compose -f docker-compose.analysis.yml restart postgres
```

### F2. Connection Refused

#### Symptoms
```
connection refused to postgres:5432
```

#### Fix
```bash
# Ensure postgres is running
docker ps | grep postgres

# Check database URL in backend logs
docker compose -f docker-compose.analysis.yml logs backend | grep DATABASE
```

### F3. Database Size / Disk Full

**Check size:**
```bash
docker exec ai_db-postgres psql -U ai -d ai_db -c "
SELECT pg_size_pretty(pg_database_size('ai_db'));
"
```

**Safe cleanup (delete old data):**
```bash
docker exec ai_db-postgres psql -U ai -d ai_db -c "
DELETE FROM raw_events WHERE ts < NOW() - INTERVAL '30 days';
DELETE FROM detections WHERE ts < NOW() - INTERVAL '30 days';
VACUUM ANALYZE;
"
```

### F4. Backup Database

```bash
docker exec ai_db-postgres pg_dump -U ai ai_db > backup_$(date +%Y%m%d).sql
```

### F5. Restore Database

```bash
docker exec -i ai_db-postgres psql -U ai -d ai_db < backup_20260117.sql
```

### F6. Full Reset

> [!CAUTION]
> **This deletes ALL data!**

```bash
docker compose -f docker-compose.analysis.yml down -v
docker compose -f docker-compose.analysis.yml up -d --build
```

---

## G. Network / Firewall Issues

### G1. UFW Modes

| Mode | Command | Security | Use Case |
|------|---------|----------|----------|
| **Strict Allowlist** | Allow specific IPs only | High | Production |
| **Subnet Allow** | Allow entire subnet | Medium | Lab with dynamic IPs |
| **Open Port** | Allow anyone | Low | Testing only |

### G2. Strict Allowlist (Recommended for Production)

```bash
# Allow SSH first (important!)
sudo ufw allow 22/tcp

# Allow each sensor IP
sudo ufw allow from <SENSOR_IP> to any port 8000 proto tcp

# Allow your Windows machine
sudo ufw allow from <WINDOWS_IP> to any port 8000 proto tcp

# Deny everyone else
sudo ufw deny 8000/tcp

# Enable firewall
sudo ufw enable
```

### G3. Subnet Allow (Recommended for Lab)

```bash
# Allow entire subnet
sudo ufw allow from 192.168.1.0/24 to any port 8000 proto tcp
sudo ufw allow 22/tcp
sudo ufw enable
```

### G4. Open Port (Testing Only)

> [!WARNING]
> **Not secure for production!**

```bash
sudo ufw allow 8000
sudo ufw allow 22/tcp
sudo ufw enable
```

### G5. Firewall Verification

```bash
# Check rules
sudo ufw status numbered

# Test from sensor
curl -s http://<ANALYZER_IP>:8000/api/v1/health

# Check port is listening
ss -lntp | grep 8000
```

### G6. Delete Firewall Rule

```bash
sudo ufw status numbered
sudo ufw delete <RULE_NUMBER>
```

---

## H. Sensor Issues

### H1. auth.log Not Found / Permission Denied

#### Symptoms
```
FileNotFoundError: /var/log/auth.log
PermissionError: /var/log/auth.log
```

#### Fix Steps

**1. Verify file exists:**
```bash
ls -la /var/log/auth.log
```

**2. Some systems use journald instead:**
```bash
# Check if rsyslog is installed
dpkg -l | grep rsyslog

# Install if missing
sudo apt install rsyslog
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

**3. Check permissions:**
```bash
# Add read permission
sudo chmod 644 /var/log/auth.log
```

### H2. Wrong Network Interface

#### Symptoms
```
No packets captured
Interface not found
```

#### Fix Steps

**1. Find correct interface:**
```bash
ip link show
```

Look for your active interface (has `state UP`).

**2. Update `.env`:**
```bash
NET_IFACE=eth0   # or ens33, enp0s3, etc.
```

**3. Restart sensor:**
```bash
docker compose -f docker-compose.sensor.yml down
docker compose -f docker-compose.sensor.yml up -d
```

### H3. Host Network Mode Issues

Flow collector uses `network_mode: host` for packet capture.

**Implications:**
- Container shares host's network namespace
- No port mapping needed
- May conflict with host services on same ports

**Verify capture works:**
```bash
docker compose -f docker-compose.sensor.yml logs flow_collector
# Should show "Capturing on ens33..." or similar
```

### H4. Time Sync Issues

#### Symptoms
- Events have wrong timestamps
- Events appear in future/past

#### Fix
```bash
# Sync time
sudo timedatectl set-ntp true
sudo systemctl restart systemd-timesyncd

# Verify
timedatectl status
```

---

## Common Mistakes

| Mistake | Symptom | Fix |
|---------|---------|-----|
| Forgot to create `.env` | Container fails to start | `cp .env.example .env` |
| Using `http://` in ANALYZER_HOST | Connection fails | Use IP only: `192.168.1.20` |
| Same DEVICE_ID on multiple sensors | Events mixed up | Unique ID per sensor |
| API key mismatch | 401 Unauthorized | Ensure same key on both |
| Running sensor before analyzer | Connection refused | Start analyzer first |
| Using wrong network interface | No flows captured | Run `ip link show` |
| Forgetting to open firewall | Timeout | `sudo ufw allow 8000` |
| Using `down -v` accidentally | Data lost | Use `down` without `-v` |
| Running `docker system prune -a` | Slow rebuilds | Avoid; deletes cache |
| Changing requirements.txt often | Slow builds | Pin versions, rebuild once |

---

**For upgrade procedures, see [UPGRADES.md](UPGRADES.md)**
