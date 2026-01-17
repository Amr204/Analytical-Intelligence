# 🧠 ML Models Documentation

> Machine learning models, thresholds, and detection tuning

---

## Table of Contents

- [Overview](#overview)
- [SSH LSTM Model](#ssh-lstm-model)
- [Network Random Forest Model](#network-random-forest-model)
- [Threshold Tuning](#threshold-tuning)
- [Allowlist Policy](#allowlist-policy)
- [Gating Layer](#gating-layer)
- [Deduplication and Cooldown](#deduplication-and-cooldown)
- [Model Files](#model-files)

---

## Overview

Analytical-Intelligence uses two ML models:

| Model | Type | Purpose | Location |
|-------|------|---------|----------|
| SSH LSTM | RNN/LSTM | Brute force detection | `models/ssh/` |
| Network RF | Random Forest | Attack classification | `models/RF/` |

---

## SSH LSTM Model

### Purpose
Detects SSH brute force attacks by tracking failed login attempts.

### Detection Logic

1. **Parse auth.log lines** for:
   - `Failed password`
   - `Invalid user`
   - `authentication failure`

2. **Count failures per source IP** within time window

3. **Alert when threshold exceeded**

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_BRUTEFORCE_THRESHOLD` | `5` | Failed attempts to trigger alert |
| `SSH_BRUTEFORCE_WINDOW_SECONDS` | `300` | Time window (5 min) |

### Example

```
Source IP: 192.168.1.100
Window: 5 minutes

Attempt 1: Failed password (count = 1)
Attempt 2: Invalid user (count = 2)
Attempt 3: Failed password (count = 3)
Attempt 4: Failed password (count = 4)
Attempt 5: Failed password (count = 5) → ALERT: Brute Force
```

### Tuning

**Too many alerts?** Increase threshold:
```bash
SSH_BRUTEFORCE_THRESHOLD=10
```

**Missing attacks?** Decrease threshold:
```bash
SSH_BRUTEFORCE_THRESHOLD=3
```

---

## Network Random Forest Model

### Purpose
Classifies network flows into attack categories using Random Forest.

### Detected Attacks

| Label | Description |
|-------|-------------|
| **DoS** | Denial of Service |
| **DDoS** | Distributed Denial of Service |
| **Port Scanning** | Port enumeration |
| **Brute Force** | Network-based password guessing |

### Processing Pipeline

```
NFStream Flow
     │
     ▼
Feature Extraction (41 features)
     │
     ▼
Random Forest Prediction
     │
     ▼
Gating Layer (volume check)
     │
     ▼
Allowlist Filter
     │
     ▼
Deduplication
     │
     ▼
Store Detection
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `NETWORK_ML_THRESHOLD` | `0.60` | Confidence threshold (0.0-1.0) |
| `NETWORK_LABEL_ALLOWLIST` | `DoS,DDoS,Port Scanning,Brute Force` | Allowed labels |
| `NETWORK_NON_ALLOW_ACTION` | `ignore` | What to do with non-allowed labels |

---

## Threshold Tuning

### Understanding Thresholds

- **Higher threshold** (0.80+) = Fewer alerts, may miss attacks
- **Lower threshold** (0.50) = More alerts, more false positives
- **Recommended range** = 0.60 - 0.80

### Adjusting Network Threshold

```bash
# In .env on Analysis server
NETWORK_ML_THRESHOLD=0.70

# Restart to apply
docker compose -f docker-compose.analysis.yml restart backend
```

### Symptoms and Fixes

| Symptom | Current State | Fix |
|---------|---------------|-----|
| Too many false positives | Threshold too low | Increase to 0.70-0.80 |
| Missing real attacks | Threshold too high | Decrease to 0.50-0.60 |
| DoS alerts on light traffic | Gating layer too permissive | Increase `ML_MIN_FLOW_RATE_PPS` |

---

## Allowlist Policy

### Why Allowlist?

The RF model can output 15+ labels from training data, but only 4 are relevant attacks:

- ✅ DoS
- ✅ DDoS
- ✅ Port Scanning
- ✅ Brute Force

### Configuration

```bash
# Only create detections for these labels
NETWORK_LABEL_ALLOWLIST=DoS,DDoS,Port Scanning,Brute Force

# What to do with other labels: "ignore" or "map_to_normal"
NETWORK_NON_ALLOW_ACTION=ignore
```

### Behavior

| Model Output | Allowlist Contains | Action |
|--------------|-------------------|--------|
| DoS | DoS | Create detection |
| Benign | (not in list) | Ignore |
| Reconnaissance | (not in list) | Ignore |

---

## Gating Layer

### Purpose

Prevents false positives by requiring minimum traffic volume for volume-based attacks.

### Logic

```
If label is "DoS" or "DDoS":
  - Check PPS (packets per second) >= ML_MIN_FLOW_RATE_PPS
  - Check BPS (bytes per second) >= ML_MIN_BYTES_PER_SECOND
  - If either fails → discard as false positive
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ML_MIN_FLOW_RATE_PPS` | `100` | Minimum packets/second |
| `ML_MIN_BYTES_PER_SECOND` | `1000` | Minimum bytes/second |

### Example

```
Flow classified as "DDoS" with confidence 0.95

Metrics:
  - PPS: 50 (below 100)
  - BPS: 2000

Result: DISCARDED (not enough packet volume for DDoS)
```

### Tuning

**Too much filtering (missing real attacks)?**
```bash
ML_MIN_FLOW_RATE_PPS=50
```

**Too many false positives?**
```bash
ML_MIN_FLOW_RATE_PPS=200
```

---

## Deduplication and Cooldown

### Deduplication

Same attack from same source within window → Update existing alert instead of creating new one.

| Variable | Default | Description |
|----------|---------|-------------|
| `ML_DEDUP_WINDOW_SECONDS` | `300` | 5-minute window |

**Key:** `(Label, SrcIP, DstIP, Port)`

```
Alert 1: DoS from 10.0.0.5 → port 80 (count=1)
[2 min later]
Alert 2: DoS from 10.0.0.5 → port 80 → UPDATE existing (count=2)
```

### Cooldown

After an IP triggers an alert, suppress new alerts from that IP.

| Variable | Default | Description |
|----------|---------|-------------|
| `ML_COOLDOWN_SECONDS_PER_SRC` | `3600` | 1-hour cooldown |

**Purpose:** Prevent log flooding during active scanning.

---

## Model Files

### SSH Model

```
models/ssh/
└── ssh_lstm.joblib    # Trained LSTM model
```

### Network Model

```
models/RF/
├── random_forest.joblib     # Trained classifier
├── feature_list.json        # Expected input features
├── label_map.json           # Label ID → name mapping
└── preprocess_config.json   # Optional preprocessing config
```

### Verify Models

```bash
# On Analysis server
ls -la models/ssh/
ls -la models/RF/

# Check inside container
docker exec ai_db-backend ls -la /app/models/ssh/
docker exec ai_db-backend ls -la /app/models/RF/
```

### Check Model Status

Visit: `http://<ANALYZER_IP>:8000/models`

Or via API:
```bash
curl http://localhost:8000/models
```

---

## Model Version Compatibility

> [!IMPORTANT]
> Models are tied to scikit-learn/numpy versions.

If you see version warnings:
1. Check container's scikit-learn version
2. Pin versions in `requirements.txt`
3. Rebuild backend

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md#e2-scikit-learn-version-mismatch).

---

**For detection tuning issues, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md#e-ml-model-issues)**
