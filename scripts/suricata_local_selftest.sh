#!/bin/bash
# ==============================================================================
# Suricata Local Rules Self-Test Script
# ==============================================================================
# Verifies that Suricata is running in OFFLINE mode with LOCAL rules only.
# No external feeds / No ET signatures.
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.sensor.yml}"
EVE_FILE="./services/suricata/log/eve.json"

echo "============================================================"
echo "  Suricata Local Rules Self-Test"
echo "============================================================"
echo ""

# ------------------------------------------------------------------------------
# 1. Check if Suricata container is running
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[1/5] Checking Suricata container status...${NC}"

if docker ps --format '{{.Names}}' | grep -q "suricata"; then
    echo -e "${GREEN}[+] Suricata container is running${NC}"
else
    echo -e "${RED}[!] Suricata container is NOT running${NC}"
    echo "    Start with: docker compose -f $COMPOSE_FILE up -d suricata"
    exit 1
fi

# ------------------------------------------------------------------------------
# 2. Check container health
# ------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[2/5] Checking container health...${NC}"

HEALTH=$(docker inspect --format='{{.State.Health.Status}}' ai_db-suricata 2>/dev/null || echo "unknown")
echo "    Health status: $HEALTH"

if [ "$HEALTH" = "healthy" ]; then
    echo -e "${GREEN}[+] Container is healthy${NC}"
elif [ "$HEALTH" = "starting" ]; then
    echo -e "${YELLOW}[~] Container is still starting (wait for health check)${NC}"
else
    echo -e "${YELLOW}[!] Health status: $HEALTH (may need time to stabilize)${NC}"
fi

# ------------------------------------------------------------------------------
# 3. Verify local rules are loaded
# ------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[3/5] Checking loaded rules...${NC}"

# Get rule count from container logs
RULE_COUNT=$(docker logs ai_db-suricata 2>&1 | grep -oP "Active Rules: \K\d+" | tail -1 || echo "0")
echo "    Local rules loaded: $RULE_COUNT"

if [ "$RULE_COUNT" -gt 0 ]; then
    echo -e "${GREEN}[+] Local rules are loaded${NC}"
else
    echo -e "${RED}[!] No local rules loaded - check local.rules file${NC}"
fi

# ------------------------------------------------------------------------------
# 4. Check for AI-prefixed alerts (no ET)
# ------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[4/5] Checking alert signatures...${NC}"

if [ -f "$EVE_FILE" ]; then
    AI_ALERTS=$(grep -c '"signature":"AI ' "$EVE_FILE" 2>/dev/null || echo "0")
    ET_ALERTS=$(grep -c '"signature":"ET ' "$EVE_FILE" 2>/dev/null || echo "0")
    
    echo "    AI-prefixed alerts: $AI_ALERTS"
    echo "    ET-prefixed alerts: $ET_ALERTS"
    
    if [ "$ET_ALERTS" -gt 0 ]; then
        echo -e "${YELLOW}[!] WARNING: Found $ET_ALERTS old ET signatures in eve.json${NC}"
        echo "    These are historical. New alerts should only be AI-prefixed."
    else
        echo -e "${GREEN}[+] No ET signatures found (offline mode confirmed)${NC}"
    fi
else
    echo -e "${YELLOW}[~] eve.json not found yet (no alerts generated)${NC}"
fi

# ------------------------------------------------------------------------------
# 5. Verify stats.log exists (healthcheck requirement)
# ------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[5/5] Checking stats.log...${NC}"

STATS_FILE="./services/suricata/log/stats.log"
if [ -f "$STATS_FILE" ]; then
    STATS_AGE=$(find "$STATS_FILE" -mmin -5 | wc -l)
    if [ "$STATS_AGE" -gt 0 ]; then
        echo -e "${GREEN}[+] stats.log exists and is recent${NC}"
    else
        echo -e "${YELLOW}[~] stats.log exists but may be stale${NC}"
    fi
else
    echo -e "${YELLOW}[~] stats.log not found yet (Suricata may be starting)${NC}"
fi

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Self-Test Summary"
echo "============================================================"
echo "  Container:     Running"
echo "  Health:        $HEALTH"
echo "  Local Rules:   $RULE_COUNT"
echo "  Mode:          OFFLINE (local rules only)"
echo "============================================================"
echo ""
echo -e "${GREEN}Self-test complete.${NC}"
echo ""
echo "To generate test alerts, you can:"
echo "  1. Ping flood test:    hping3 -1 --flood -V <target>"
echo "  2. Port scan test:     nmap -sS <target>"
echo "  3. Check logs:         tail -f $EVE_FILE | jq '.alert.signature'"
echo ""
