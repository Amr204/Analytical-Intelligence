# Network RF Pipeline Testing Guide

This document describes how to validate that the Network RF pipeline fixes are working correctly.

## Prerequisites

- Backend container is running with the RF model loaded
- Sensor container is running with `flow_collector` agent
- Debug mode enabled: `NETWORK_ML_DEBUG=1`

## Test 1: Verify Port Scanning is Detected

### What was fixed
- `FLOW_MIN_PKTS` default changed from 2 to 1, allowing single-packet scan flows
- Missing IAT fields added to `flow_to_dict()` for complete feature mapping  
- Per-label cooldown prevents false DDoS from suppressing Port Scanning

### How to verify

1. **Enable debug logging on backend:**
   ```bash
   docker exec -it backend sh -c "export NETWORK_ML_DEBUG=1"
   # Or set in docker-compose.yml environment
   ```

2. **Generate port scan traffic from sensor network:**
   - Use any scanning tool that generates SYN packets to multiple ports
   - Target a host visible to the sensor's network interface

3. **Check backend logs for Port Scanning predictions:**
   ```bash
   docker logs backend 2>&1 | grep -E "\[DEBUG\].*Port Scanning|detection.*Port Scanning"
   ```
   
4. **Expected result:**
   - Logs should show `[DEBUG] ... top3=[..., Port Scanning:X.XXX, ...]`
   - If score >= 0.60 and flow passes gating, you should see:
     `Network RF detection: Port Scanning (HIGH|CRITICAL)`
   - UI should display Port Scanning alerts

### Troubleshooting if Port Scanning still not detected

1. **Check if flows are reaching backend:**
   ```bash
   docker logs flow_collector 2>&1 | grep "Sent.*flows"
   ```

2. **Check FLOW_MIN_PKTS setting:**
   ```bash
   docker exec flow_collector env | grep FLOW_MIN_PKTS
   # Should be 1 or unset (defaults to 1)
   ```

3. **Check cooldown suppression:**
   ```bash
   docker logs backend 2>&1 | grep "SUPPRESSED.*Port Scanning"
   ```
   If you see suppression, wait for cooldown to expire (default 3600s) or reduce `ML_COOLDOWN_SECONDS_PER_SRC`.

---

## Test 2: Verify False DDoS Stops on Idle Traffic

### What was fixed
- Rate features (Flow Bytes/s, Packets/s) now return 0 when `duration_ms < 50`
- Volume attack gating requires minimum: duration >= 100ms, packets >= 10, bytes >= 1000
- sklearn `model.classes_` ordering now correctly maps probability indices to labels

### How to verify

1. **Leave sensor running on idle network (little to no traffic)**

2. **Monitor for DDoS detections over 10-15 minutes:**
   ```bash
   docker logs backend 2>&1 | grep -c "detection.*DDoS"
   # Should be 0 or very few, not continuous
   ```

3. **Enable debug mode to see why DDoS is filtered:**
   ```bash
   docker logs backend 2>&1 | grep -E "GATING_DURATION|GATING_PACKETS|GATING_BYTES"
   ```
   
4. **Expected result:**
   - No periodic DDoS alerts on genuinely idle traffic
   - Debug logs show flows being filtered by gating layer:
     `-> GATING_DURATION (DDoS, 10ms < 100ms)`
     `-> GATING_PACKETS (DDoS, 3 < 10)`

### Adjusting thresholds

If you still see false positives, increase gating thresholds via environment variables:

```yaml
environment:
  MIN_VOLUME_ATTACK_DURATION_MS: "200"   # Require 200ms minimum
  MIN_VOLUME_ATTACK_PACKETS: "20"        # Require 20 packets minimum
  MIN_VOLUME_ATTACK_BYTES: "5000"        # Require 5KB minimum
```

---

## Test 3: Verify Debug Mode Output

### Enable debug sampling
```yaml
environment:
  NETWORK_ML_DEBUG: "1"
  NETWORK_ML_DEBUG_SAMPLE_RATE: "10"  # Log 1 out of every 10 flows
```

### Expected log format
```
[DEBUG] src=192.168.1.100 dst=10.0.0.1:443 proto=6 dur=1500ms pkts=25 bytes=5000 
        mapped=38 fallback=14 top3=[Normal Traffic:0.85, DDoS:0.08, DoS:0.04] -> BENIGN
```

### Fields explained
- `mapped=38` - 38 features filled from real NFStream fields
- `fallback=14` - 14 features using fallback (0 or median)
- `top3=[...]` - Top 3 predicted labels with probabilities
- `-> REASON` - Why detection was created or rejected:
  - `BENIGN` - Predicted as Normal Traffic
  - `DETECTION` - Attack detected, stored in database
  - `THRESHOLD` - Score below 0.60 threshold
  - `ALLOWLIST_FILTERED` - Label not in allowlist (Bots, Web Attacks)
  - `GATING_*` - Failed volume attack sanity checks

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `FLOW_MIN_PKTS` | `1` | Minimum packets per flow to forward (agent) |
| `MIN_FLOW_DURATION_MS` | `50` | Below this, rate features are 0 (mapper) |
| `MIN_VOLUME_ATTACK_DURATION_MS` | `100` | Volume attack minimum duration (gating) |
| `MIN_VOLUME_ATTACK_PACKETS` | `10` | Volume attack minimum packets (gating) |
| `MIN_VOLUME_ATTACK_BYTES` | `1000` | Volume attack minimum bytes (gating) |
| `NETWORK_ML_DEBUG` | `0` | Enable debug logging (1=on) |
| `NETWORK_ML_DEBUG_SAMPLE_RATE` | `50` | Log 1 out of every N flows |
| `ML_COOLDOWN_SECONDS_PER_SRC` | `3600` | Per (IP, label) cooldown window |

---

## Running Unit Tests

```bash
cd services/backend
pytest tests/test_network_ml_model.py -v
```

### Test coverage includes:
- `TestClassesMapping` - Verifies sklearn classes_ ordering fix
- `TestFeatureMapperDurationHandling` - Verifies duration_ms==0 produces rate=0
- `TestIATUnitConversion` - Verifies ms→µs conversion
- `TestAllowlistFiltering` - Verifies 4-label allowlist

---

## Summary of Fixes Applied

| Issue | Root Cause | Fix |
|-------|-----------|-----|
| Port Scanning not detected | `bidirectional_packets < 2` filter dropped scans | Changed to `FLOW_MIN_PKTS=1` |
| Port Scanning not detected | Missing IAT fields caused bad features | Added 6 missing piat fields |
| Port Scanning not detected | Per-IP cooldown suppressed all labels | Changed to per-(IP, label) cooldown |
| False DDoS on idle traffic | `duration_ms=0` inflated rate features | Rate features = 0 when duration < 50ms |
| False DDoS on idle traffic | argmax used directly as label_id | Now uses `model.classes_[argmax]` |
| False DDoS on idle traffic | Gating only checked PPS/BPS | Added absolute min duration/packets/bytes |
| IAT features wrong scale | ms not converted to µs | All IAT features now × 1000 |
