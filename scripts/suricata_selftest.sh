#!/bin/bash
# ==============================================================================
# Suricata End-to-End Self-Test Script
# ==============================================================================
# Tests the complete Suricata pipeline: startup, rule loading, alert generation,
# collector forwarding, and backend display.
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "============================================================"
echo "  Suricata End-to-End Self-Test"
echo "============================================================"

# Configuration
COMPOSE_FILE="${1:-docker-compose.sensor.yml}"
EVE_FILE="./services/suricata/log/eve.json"
FAST_LOG="./services/suricata/log/fast.log"
BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
TEST_TARGET="${TEST_TARGET:-8.8.8.8}"

# ------------------------------------------------------------------------------
# Step 1: Check if Suricata container is running
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[1/5] Checking Suricata container status...${NC}"
if docker ps --format '{{.Names}}' | grep -q "ai_db-suricata"; then
    echo -e "${GREEN}[+] Suricata container is running${NC}"
else
    echo -e "${RED}[!] Suricata container not running. Starting...${NC}"
    docker-compose -f "$COMPOSE_FILE" up -d suricata
    sleep 10
fi

# ------------------------------------------------------------------------------
# Step 2: Generate test traffic to trigger local.rules
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[2/5] Generating test traffic (Nmap XMAS Scan)...${NC}"
# Ping doesn't trigger alerts, use Nmap XMAS scan which triggers sid:1000013
if command -v nmap &> /dev/null; then
    nmap -sX -p 80 "$TEST_TARGET" > /dev/null 2>&1 || true
    echo -e "${GREEN}[+] Nmap XMAS scan sent to $TEST_TARGET${NC}"
else
    echo -e "${YELLOW}[!] Nmap not found, sending HTTP User-Agent scan...${NC}"
    curl -s -A "Nmap Scripting Engine" "$TEST_TARGET" > /dev/null 2>&1 || true
fi

# Optional: send HTTP request with Nmap user-agent
if command -v curl &> /dev/null; then
    echo -e "${YELLOW}[*] Sending HTTP request with Nmap User-Agent...${NC}"
    curl -s -A "Nmap" "$TEST_TARGET" > /dev/null 2>&1 || true
fi

# ------------------------------------------------------------------------------
# Step 3: Check eve.json for alerts
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[3/5] Checking eve.json for alerts...${NC}"
sleep 5  # Give Suricata time to write

if [ -f "$EVE_FILE" ]; then
    ALERT_COUNT=$(grep -c '"event_type":"alert"' "$EVE_FILE" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] eve.json exists with $ALERT_COUNT alert(s)${NC}"
    
    if [ "$ALERT_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}[*] Last 3 alerts:${NC}"
        grep '"event_type":"alert"' "$EVE_FILE" | tail -3 | jq -r '.alert.signature // "unknown"' 2>/dev/null || head -3
    fi
else
    echo -e "${RED}[!] eve.json not found at $EVE_FILE${NC}"
fi

# ------------------------------------------------------------------------------
# Step 4: Check Suricata Collector
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[4/5] Checking Suricata Collector...${NC}"
if docker ps --format '{{.Names}}' | grep -q "ai_db-suricata-collector"; then
    echo -e "${GREEN}[+] Suricata Collector is running${NC}"
    
    # Check collector logs for recent activity
    COLLECTOR_LOGS=$(docker logs ai_db-suricata-collector --tail 10 2>&1)
    COLLECTOR_LOGS=$(docker logs ai_db-suricata-collector --tail 20 2>&1)
    if echo "$COLLECTOR_LOGS" | grep -iE "sent|forwarded|processed|Alerts seen"; then
        echo -e "${GREEN}[+] Collector appears to be forwarding alerts${NC}"
    else
        echo -e "${YELLOW}[*] Collector running but no recent forwards detected${NC}"
    fi
else
    echo -e "${RED}[!] Suricata Collector not running${NC}"
fi

# ------------------------------------------------------------------------------
# Step 5: Check Backend for Suricata alerts
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[5/5] Checking Backend for Suricata alerts...${NC}"
if curl -s "$BACKEND_URL/api/v1/health" > /dev/null 2>&1; then
    echo -e "${GREEN}[+] Backend is reachable${NC}"
    
    # Try to fetch alerts with model_name=suricata
    SURICATA_ALERTS=$(curl -s "$BACKEND_URL/api/v1/alerts?model_name=suricata&limit=5" 2>/dev/null || echo "{}")
    if echo "$SURICATA_ALERTS" | grep -q "suricata"; then
        echo -e "${GREEN}[+] Suricata alerts found in backend!${NC}"
    else
        echo -e "${YELLOW}[*] No Suricata alerts in backend yet (may take time)${NC}"
    fi
else
    echo -e "${YELLOW}[*] Backend not reachable at $BACKEND_URL (might be on different host)${NC}"
fi

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Self-Test Complete"
echo "============================================================"
echo ""
echo "Manual verification steps:"
echo "  1. Check eve.json: tail -f $EVE_FILE"
echo "  2. Check fast.log: tail -f $FAST_LOG"
echo "  3. View container logs: docker logs ai_db-suricata -f"
echo "  4. Check UI Alerts page for model_name='suricata'"
echo ""
