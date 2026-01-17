# 🔒 Security Guide

> Firewall configuration, API key management, and hardening

---

## Table of Contents

- [Security Overview](#security-overview)
- [API Key Management](#api-key-management)
- [Firewall Configuration](#firewall-configuration)
- [Exposure Matrix](#exposure-matrix)
- [Production Hardening](#production-hardening)
- [Security Checklist](#security-checklist)

---

## Security Overview

### Attack Surface

| Component | Exposed Port | Access Required |
|-----------|-------------|-----------------|
| Backend API | 8000 | Sensors + Admin UI |
| PostgreSQL | 5432 | Internal only |
| SSH | 22 | Admin access |

### Authentication

| Endpoint | Authentication |
|----------|----------------|
| `/api/v1/ingest/*` | `INGEST_API_KEY` header |
| `/api/v1/health` | None (public) |
| UI pages (`/`, `/alerts`, etc.) | None (protect with firewall) |

---

## API Key Management

### Setting API Key

**On Analysis server:**
```bash
# In .env
INGEST_API_KEY=<YOUR_SECURE_KEY>
```

**On each Sensor:**
```bash
# In .env (must match!)
INGEST_API_KEY=<YOUR_SECURE_KEY>
```

### Generating Secure Key

```bash
# Generate random 32-character key
openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32
```

### Rotating API Key

1. **Generate new key:**
   ```bash
   NEW_KEY=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)
   echo "New key: $NEW_KEY"
   ```

2. **Update Analysis server:**
   ```bash
   # On Analysis server
   nano .env
   # Change INGEST_API_KEY to new value
   docker compose -f docker-compose.analysis.yml restart backend
   ```

3. **Update all Sensors:**
   ```bash
   # On each sensor
   nano .env
   # Change INGEST_API_KEY to match
   docker compose -f docker-compose.sensor.yml restart
   ```

> [!IMPORTANT]
> Update sensors quickly to minimize downtime. Events won't be ingested until keys match.

---

## Firewall Configuration

### UFW Modes Comparison

| Mode | Security | Maintenance | Use Case |
|------|----------|-------------|----------|
| **Strict Allowlist** | High | High (update on IP change) | Production |
| **Subnet Allow** | Medium | Low | Lab, DHCP environments |
| **Open Port** | Low | None | Testing only |

### Mode 1: Strict Allowlist (Recommended for Production)

```bash
# Allow SSH first (always!)
sudo ufw allow 22/tcp

# Allow specific sensor IPs
sudo ufw allow from 192.168.1.21 to any port 8000 proto tcp
sudo ufw allow from 192.168.1.22 to any port 8000 proto tcp

# Allow admin machine(s)
sudo ufw allow from 192.168.1.100 to any port 8000 proto tcp

# Deny everyone else
sudo ufw deny 8000/tcp

# Enable firewall
sudo ufw enable

# Verify
sudo ufw status numbered
```

**Pros:** Maximum security, explicit access  
**Cons:** Must update when IPs change

---

### Mode 2: Subnet Allow (Recommended for Lab)

```bash
# Allow SSH
sudo ufw allow 22/tcp

# Allow entire subnet
sudo ufw allow from 192.168.1.0/24 to any port 8000 proto tcp

# Enable
sudo ufw enable
```

**Pros:** Works with DHCP, low maintenance  
**Cons:** Any device on subnet can access

---

### Mode 3: Open Port (Testing Only)

> [!CAUTION]
> **Not secure!** Only use in isolated test environments.

```bash
sudo ufw allow 22/tcp
sudo ufw allow 8000/tcp
sudo ufw enable
```

**Pros:** Simple setup  
**Cons:** Anyone with network access can view dashboard

---

### Managing Firewall Rules

**View rules:**
```bash
sudo ufw status numbered
```

**Delete rule:**
```bash
sudo ufw delete <RULE_NUMBER>
```

**Reset all rules:**
```bash
sudo ufw reset
```

---

## Exposure Matrix

### What's Exposed?

| Resource | Default | Recommended Production |
|----------|---------|----------------------|
| Backend API (:8000) | All interfaces | Allowlist only |
| PostgreSQL (:5432) | Internal only | Keep internal |
| Dashboard UI | Via :8000 | Allowlist only |
| Health endpoint | Public | OK (no sensitive data) |

### Port Binding

Backend binds to `0.0.0.0:8000` by default, meaning all interfaces.

To restrict (advanced):
```yaml
# In docker-compose.analysis.yml
ports:
  - "127.0.0.1:8000:8000"  # localhost only
```

Then use SSH tunnel for access:
```bash
ssh -L 8000:localhost:8000 user@analyzer
```

---

## Production Hardening

### 1. Use Strong API Key

```bash
# Generate 32+ character random key
INGEST_API_KEY=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)
```

### 2. Enable Strict Firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow from <SENSOR_IP> to any port 8000 proto tcp
sudo ufw enable
```

### 3. Change Database Password

In `.env`:
```bash
POSTGRES_PASSWORD=<STRONG_RANDOM_PASSWORD>
```

Then reset containers:
```bash
docker compose -f docker-compose.analysis.yml down -v
docker compose -f docker-compose.analysis.yml up -d --build
```

> [!WARNING]
> Using `down -v` deletes all data. Backup first if needed.

### 4. Limit SSH Access

```bash
# Allow SSH only from admin IPs
sudo ufw delete allow 22/tcp
sudo ufw allow from <ADMIN_IP> to any port 22 proto tcp
```

### 5. Keep System Updated

```bash
sudo apt update && sudo apt upgrade -y
```

### 6. Monitor Logs

```bash
# Check for unauthorized access attempts
docker compose -f docker-compose.analysis.yml logs backend | grep -i "401\|403\|unauthorized"
```

---

## Security Checklist

### Initial Setup

- [ ] Changed default `INGEST_API_KEY`
- [ ] Same key on all sensors and analyzer
- [ ] UFW enabled with appropriate rules
- [ ] SSH allowed before enabling UFW

### Production Deployment

- [ ] Using strict allowlist firewall
- [ ] Strong database password
- [ ] Limited SSH access
- [ ] System packages updated
- [ ] Log monitoring configured

### Ongoing Maintenance

- [ ] Rotate API key periodically
- [ ] Update firewall when IPs change
- [ ] Monitor logs for anomalies
- [ ] Keep Docker and system updated

---

## Quick Reference

| Task | Command |
|------|---------|
| Generate API key | `openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32` |
| Enable firewall | `sudo ufw enable` |
| Allow IP | `sudo ufw allow from <IP> to any port 8000 proto tcp` |
| View rules | `sudo ufw status numbered` |
| Delete rule | `sudo ufw delete <NUM>` |
| Check logs | `docker compose logs backend | grep -i error` |

---

**For firewall issues, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md#g-network--firewall-issues)**
