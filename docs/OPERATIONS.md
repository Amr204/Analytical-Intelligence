# 🔧 Operations Guide

> Daily operations, start/stop commands, and sensor management

---

## Table of Contents

- [Quick Reference](#quick-reference)
- [Starting the System](#starting-the-system)
- [Stopping the System](#stopping-the-system)
- [Reboot Recovery](#reboot-recovery)
- [Monitoring](#monitoring)
- [Adding New Sensors](#adding-new-sensors)
- [Common Tasks](#common-tasks)

---

## Quick Reference

| Task | Analysis Server | Sensor Server |
|------|-----------------|---------------|
| Start | `bash scripts/analysis_up.sh` | `bash scripts/sensor_up.sh` |
| Stop | `docker compose -f docker-compose.analysis.yml down` | `docker compose -f docker-compose.sensor.yml down` |
| Restart | `docker compose -f docker-compose.analysis.yml restart` | `docker compose -f docker-compose.sensor.yml restart` |
| Logs | `docker compose -f docker-compose.analysis.yml logs -f` | `docker compose -f docker-compose.sensor.yml logs -f` |
| Status | `docker ps` | `docker ps` |

---

## Starting the System

### Order: Analysis First, Then Sensors

> [!IMPORTANT]
> Always start the Analysis server before Sensor servers. Sensors need the backend to be available.

### 1. Start Analysis Server

```bash
cd ~/Analytical-Intelligence
bash scripts/analysis_up.sh
```

Wait for:
```
Analysis Stack Ready!
Dashboard: http://localhost:8000
```

### 2. Start Sensor Server(s)

On each sensor:
```bash
cd ~/Analytical-Intelligence
bash scripts/sensor_up.sh
```

### 3. Verify All Systems

```bash
# On Analysis server - check containers
docker ps

# Expected output:
# ai_db-postgres   ... Up ...
# ai_db-backend    ... Up ...
```

Open browser:
```
http://<ANALYZER_IP>:8000/devices
```
All sensors should show as Online.

---

## Stopping the System

### Stop Analysis Server

```bash
cd ~/Analytical-Intelligence
docker compose -f docker-compose.analysis.yml down
```

### Stop Sensor Server

```bash
cd ~/Analytical-Intelligence
docker compose -f docker-compose.sensor.yml down
```

> [!WARNING]
> **Destructive command (deletes data):**
> ```bash
> docker compose -f docker-compose.analysis.yml down -v
> ```
> The `-v` flag deletes database volumes. Only use for complete reset.

> [!caution]
> **Delete Everything**
>
> ⚠️ **تحذير:** هذه الأوامر ستحذف *كل شيء* متعلق بـ Docker  
> (الحاويات، الصور، الشبكات، الـ volumes، والـ cache).
>
> ```bash
> docker compose -f docker-compose.analysis.yml down -v --remove-orphans || true
> docker rm -f $(docker ps -aq) 2>/dev/null || true
> docker volume rm $(docker volume ls -q) 2>/dev/null || true
> docker network prune -f
> docker image prune -a -f
> docker builder prune -a -f
> docker system prune -a -f
> ```


## Reboot Recovery

After a server reboot, Docker containers don't auto-start by default.

### Analysis Server Recovery

```bash
# 1. Ensure Docker is running
sudo systemctl start docker

# 2. Navigate to project
cd ~/Analytical-Intelligence

# 3. Start stack
bash scripts/analysis_up.sh

# 4. Verify
curl -s http://localhost:8000/api/v1/health | jq
```

### Sensor Server Recovery

```bash
# 1. Ensure Docker is running
sudo systemctl start docker

# 2. Navigate to project
cd ~/Analytical-Intelligence

# 3. Start stack
bash scripts/sensor_up.sh

# 4. Verify containers
docker ps
```

### Recovery Order

```
1. Start Analysis server first
2. Wait for health check to pass
3. Then start all sensor servers
```

---

## Monitoring

### View Container Status

```bash
docker ps
docker stats  # Live resource usage
```

### View Logs

**Analysis backend logs:**
```bash
docker compose -f docker-compose.analysis.yml logs -f backend
```

**Sensor collector logs:**
```bash
docker compose -f docker-compose.sensor.yml logs -f
```

**Last 50 lines only:**
```bash
docker compose -f docker-compose.analysis.yml logs --tail=50 backend
```

### Health Check

```bash
curl -s http://localhost:8000/api/v1/health | jq
```

### Database Statistics

```bash
docker exec -it ai_db-postgres psql -U ai -d ai_db -c "
SELECT 
  (SELECT COUNT(*) FROM raw_events) as total_events,
  (SELECT COUNT(*) FROM detections) as total_detections,
  (SELECT COUNT(*) FROM devices) as total_devices;
"
```

---

## Adding New Sensors

### Step 1: Set Up New Sensor Server

Follow [INSTALLATION.md](INSTALLATION.md#sensor-server-setup).

### Step 2: Configure Unique Device ID

> [!IMPORTANT]
> **DEVICE_ID must be unique for each sensor!**

In `.env` on the new sensor:
```bash
DEVICE_ID=sensor-02   # Must be different from existing sensors
HOSTNAME=new-sensor
ANALYZER_HOST=<ANALYZER_IP>
INGEST_API_KEY=<SAME_KEY_AS_OTHER_SENSORS>
NET_IFACE=ens33
```

### Step 3: Start and Verify

```bash
bash scripts/sensor_up.sh
```

Check devices page:
```
http://<ANALYZER_IP>:8000/devices
```

### List All Registered Devices

```bash
docker exec -it ai_db-postgres psql -U ai -d ai_db -c "
SELECT device_id, hostname, device_ip, last_seen_at 
FROM devices 
ORDER BY last_seen_at DESC;
"
```

---

## Common Tasks

### Restart a Single Container

```bash
# Restart backend only
docker compose -f docker-compose.analysis.yml restart backend

# Restart auth collector only
docker compose -f docker-compose.sensor.yml restart auth_collector
```

### View Events Count by Type

```bash
docker exec -it ai_db-postgres psql -U ai -d ai_db -c "
SELECT event_type, COUNT(*) as count 
FROM raw_events 
GROUP BY event_type;
"
```

### View Recent Detections

```bash
docker exec -it ai_db-postgres psql -U ai -d ai_db -c "
SELECT model_name, label, severity, COUNT(*) as count
FROM detections 
WHERE ts > NOW() - INTERVAL '24 hours'
GROUP BY model_name, label, severity
ORDER BY count DESC;
"
```

### Check Disk Usage

```bash
docker system df
```

### Clean Old Events (Safe)

```bash
docker exec -it ai_db-postgres psql -U ai -d ai_db -c "
DELETE FROM raw_events WHERE ts < NOW() - INTERVAL '30 days';
DELETE FROM detections WHERE ts < NOW() - INTERVAL '30 days';
VACUUM ANALYZE;
"
```

---

## UI Pages Reference

| Page | URL | Purpose |
|------|-----|---------|
| Dashboard | `http://<ANALYZER_IP>:8000/` | Overview and stats |
| Alerts | `http://<ANALYZER_IP>:8000/alerts` | All detections |
| Devices | `http://<ANALYZER_IP>:8000/devices` | Sensor inventory |
| Models | `http://<ANALYZER_IP>:8000/models` | ML model status |
| Auth Events | `http://<ANALYZER_IP>:8000/events/auth` | Raw SSH events |
| Flow Events | `http://<ANALYZER_IP>:8000/events/flows` | Raw network flows |

---

**For troubleshooting, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)**
