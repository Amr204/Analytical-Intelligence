# 🧪 System Testing & Verification

> Guide to validating the Analytical-Intelligence SIEM detection capabilities.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Test 1: SSH Brute Force (LSTM)](#test-1-ssh-brute-force-lstm)
- [Test 2: Network Attacks (Suricata)](#test-2-network-attacks-suricata)
- [Test 3: System Health](#test-3-system-health)

---

## Prerequisites

1.  **Kali Linux** or another attacker machine on the same network.
2.  **Analytical-Intelligence** running:
    - Analysis Server (Backend + DB)
    - Sensor Server (Auth + Suricata)

---

## Test 1: SSH Brute Force (LSTM)

**Objective:** Verify that the LSTM model detects a sequence of failed login attempts.

### 1. Prepare Attack
On the attacker machine, create a password list:
```bash
echo -e "admin\n123456\npassword\nroot\ntest\nuser\nletmein\nqwerty" > passwords.txt
```

### 2. Launch Attack
Use `hydra` to simulate a rapid brute force attack against the **Sensor Server**:
```bash
hydra -l root -P passwords.txt ssh://<SENSOR_IP> -t 4 -V
```

### 3. Verify Detection
1.  **Check Dashboard:** `http://<ANALYZER_IP>:8000/alerts`
2.  **Look for:**
    - **Model:** `ssh_lstm`
    - **Label:** `Brute Force`
    - **Severity:** `CRITICAL` or `HIGH`

### 4. Troubleshooting
If no alert appears:
- Check `auth_collector` logs: `docker logs ai_db-auth-collector`
- Ensure `INGEST_API_KEY` matches.
- Check if `SSH_BRUTEFORCE_THRESHOLD` in `.env` is too high (default 5).

---

## Test 2: Network Attacks (Suricata)

**Objective:** Verify that Suricata IDS detects network signatures.

### Scenario A: Port Scanning (Nmap)

**Command (Attacker):**
```bash
nmap -sS -F <SENSOR_IP>
```

**Expected Result:**
- **Alert:** `ET SCAN Potential SSH Scan` or similar.
- **Severity:** `MEDIUM` or `HIGH`.

### Scenario B: DoS / DDoS Simulation (hping3)

**Command (Attacker):**
```bash
# Send SYN flood to port 80
sudo hping3 -S --flood -V -p 80 <SENSOR_IP>
```
*Stop after 10-15 seconds.*

**Expected Result:**
- **Alert:** `ET DOS Possible SYN Flood` or similar.
- **Model:** `suricata`.

### Scenario C: Connectivity Check (Test Rule)

If real attacks don't trigger, test with a custom rule.

1.  **Add Rule on Sensor:**
    Edit `services/suricata/etc/local.rules`:
    ```
    alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)
    ```

2.  **Restart Suricata:**
    ```bash
    docker compose -f docker-compose.sensor.yml restart suricata
    ```

3.  **Ping Sensor:**
    ```bash
    ping -c 4 <SENSOR_IP>
    ```

4.  **Verify Alert:** Dashboard should show "ICMP Ping Detected".

---

## Test 3: System Health

### 1. API Health Check
```bash
curl -s http://<ANALYZER_IP>:8000/api/v1/health | jq
```
**Expected:** `"status": "ok"`

### 2. Device Status
Check `http://<ANALYZER_IP>:8000/devices`.
- Sensor status should be **ONLINE**.
- Last Seen should be "Just now" or extremely recent.

### 3. Log Verification
Check backend logs for successful ingestion:
```bash
docker logs --tail 20 ai_db-backend
```
Look for: `POST /api/v1/ingest/suricata 201 Created` or `POST /api/v1/ingest/auth 201 Created`.
