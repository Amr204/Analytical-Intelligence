# SSH & Network ML Hardening Guidelines

> Detection tuning settings for SSH brute force and Network ML models

---

## Table of Contents

- [Overview](#overview)
- [SSH Detection (Brute Force)](#1-ssh-detection-brute-force)
- [Network ML Detection (Flows)](#2-network-ml-detection-flows)

---

## Overview


This document details the hardening measures implemented for SSH and Network ML detection pipelines to improve accuracy, reduce false positives, and prevent alert storms.

## 1. SSH Detection (Brute Force)

### Logic Improvement
The SSH detector now implements a configurable "Aggregation Window" to track failed login attempts.
- **Old Behavior**: Alerted on every failed line (generic model output).
- **New Behavior**: 
    - Counts failed attempts (`Failed password`, `Invalid user`, `authentication failure`) per Source IP.
    - Alerts ONLY when the count exceeds `SSH_BRUTEFORCE_THRESHOLD` within `SSH_BRUTEFORCE_WINDOW_SECONDS`.
    - Captures generic "authentication failure" logs (e.g., from PAM) that were previously missed.

### Configuration
| Variable | Default | Description |
|---|---|---|
| `SSH_BRUTEFORCE_WINDOW_SECONDS` | `300` | Time window (seconds) to count failures (e.g., 5 mins). |
| `SSH_BRUTEFORCE_THRESHOLD` | `5` | Number of failures required to trigger an alert. |

## 2. Network ML Detection (Flows)

### Gating Layer (Sanity Checks)
To reduce false positives (especially for DoS/DDoS labels), we implemented a "Gating Layer" **before** the ML result is accepted.
- **Rationale**: An ML model might classify a single packet flow as "DDoS" based on feature patterns, which is technically impossible (DDoS implies volume).
- **Check**:
    - **PPS (Packets Per Second)**: Must be > `ML_MIN_FLOW_RATE_PPS` (Default: 100).
    - **BPS (Bytes Per Second)**: Must be > `ML_MIN_BYTES_PER_SECOND` (Default: 1000).
    - If a flow is labeled "DDOS" or "DOS" but has low volume, it is **discarded** as a false positive.

### Deduplication & Cooldown
- **Deduplication**: If the *same* attack (Label + SrcIP + DstIP + Port) is detected within `ML_DEDUP_WINDOW_SECONDS` (5 mins), it updates the existing alert (increments `occurrences`) instead of creating a new one.
- **Cooldown**: If a Source IP triggers an alert, new (different) alerts from the *same IP* are suppressed for `ML_COOLDOWN_SECONDS_PER_SRC` (1 hour) to prevent log flooding during active scanning.

### Configuration
| Variable | Default | Description |
|---|---|---|
| `ML_DEDUP_WINDOW_SECONDS` | `300` | Window to group identical flows. |
| `ML_COOLDOWN_SECONDS_PER_SRC` | `3600` | Time to suppress new alerts from a known attacker IP. |
| `ML_MIN_FLOW_RATE_PPS` | `100` | Minimum packets/sec for Volume-based attacks. |
| `ML_MIN_BYTES_PER_SECOND` | `1000` | Minimum bytes/sec for Volume-based attacks. |

