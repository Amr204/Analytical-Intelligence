# 🔄 Upgrade Guide

> Safe procedures for updating Analytical-Intelligence

---

## Table of Contents

- [Pre-Upgrade Checklist](#pre-upgrade-checklist)
- [Standard Upgrade](#standard-upgrade)
- [When to Rebuild](#when-to-rebuild)
- [Applying .env Changes](#applying-env-changes)
- [Rollback Procedure](#rollback-procedure)
- [Post-Upgrade Verification](#post-upgrade-verification)

---

## Pre-Upgrade Checklist

Before any upgrade:

- [ ] Note current commit: `git log --oneline -1`
- [ ] Check for local changes: `git status`
- [ ] Backup database (if important data):
  ```bash
  docker exec ai_db-postgres pg_dump -U ai ai_db > backup_$(date +%Y%m%d).sql
  ```
- [ ] Check `.env.example` for new variables (after pull)

---

## Standard Upgrade

### Step 1: Pull Updates

```bash
cd ~/Analytical-Intelligence

# Check for local changes
git status

# If you have local changes, stash them
git stash

# Pull latest code
git pull origin main

# Restore local changes (if stashed)
git stash pop
```

### Step 2: Check for .env Changes

```bash
diff .env .env.example
```

If new variables exist, add them to your `.env`.

### Step 3: Rebuild and Restart

**Analysis Server:**
```bash
bash scripts/analysis_up.sh
```

**Sensor Server:**
```bash
bash scripts/sensor_up.sh
```

---

## When to Rebuild

| Change Type | Command | Rebuild Time |
|-------------|---------|--------------|
| Code only (`app/*.py`) | `up -d --build` | Fast (~30s) |
| `requirements.txt` | `up -d --build` | Medium (~2min) |
| Dockerfile | `build --no-cache` | Slow (~5min) |
| `docker-compose.yml` | `down` then `up -d --build` | Medium |

### Code Changes Only (Fast)

```bash
docker compose -f docker-compose.analysis.yml up -d --build
```

### Requirements Changed (Medium)

```bash
docker compose -f docker-compose.analysis.yml up -d --build
# pip cache makes this faster than full rebuild
```

### Dockerfile Changed (Slow)

```bash
docker compose -f docker-compose.analysis.yml build --no-cache
docker compose -f docker-compose.analysis.yml up -d
```

### Docker Compose Changed

```bash
docker compose -f docker-compose.analysis.yml down
docker compose -f docker-compose.analysis.yml up -d --build
```

---

## Applying .env Changes

### Step 1: Compare Files

```bash
diff .env .env.example
```

### Step 2: Add New Variables

```bash
nano .env
# Add any new required variables
```

### Step 3: Restart to Apply

```bash
# Analysis
docker compose -f docker-compose.analysis.yml down
docker compose -f docker-compose.analysis.yml up -d

# Sensor
docker compose -f docker-compose.sensor.yml down
docker compose -f docker-compose.sensor.yml up -d
```

> [!NOTE]
> Environment changes require container restart, not rebuild.

---

## Rollback Procedure

### View Recent Commits

```bash
git log --oneline -10
```

### Rollback to Previous Commit

```bash
# Checkout specific commit
git checkout <COMMIT_HASH>

# Or go back one commit
git checkout HEAD~1
```

### Rebuild After Rollback

```bash
docker compose -f docker-compose.analysis.yml up -d --build
```

### Return to Latest Version

```bash
git checkout main
docker compose -f docker-compose.analysis.yml up -d --build
```

### Restore Database from Backup

```bash
docker exec -i ai_db-postgres psql -U ai -d ai_db < backup_20260117.sql
```

---

## Post-Upgrade Verification

### 1. Health Check

```bash
curl -s http://localhost:8000/api/v1/health | jq
```

Expected:
```json
{"status": "ok", "timestamp": "...", "version": "1.0.0"}
```

### 2. Container Status

```bash
docker ps
# All containers should show "Up"
```

### 3. Check Logs for Errors

```bash
docker compose -f docker-compose.analysis.yml logs --tail=50 backend
```

### 4. Model Status

```bash
curl http://localhost:8000/models
# Or check in browser
```

### 5. Device Connectivity

Check devices page:
```
http://<ANALYZER_IP>:8000/devices
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Pull updates | `git pull origin main` |
| Stash local changes | `git stash` |
| Restore stash | `git stash pop` |
| View commits | `git log --oneline -5` |
| Rollback | `git checkout <HASH>` |
| Return to latest | `git checkout main` |
| Backup DB | `docker exec ai_db-postgres pg_dump -U ai ai_db > backup.sql` |
| Restore DB | `docker exec -i ai_db-postgres psql -U ai -d ai_db < backup.sql` |

---

**For troubleshooting upgrade issues, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)**
