#!/bin/bash
# =============================================================================
# Analytical-Intelligencel-Intelligence v1 - Configuration Printer
# Prints detected IP and configuration for debugging
# =============================================================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "=============================================="
echo "Analytical-Intelligence Configuration Check"
echo "=============================================="

# Detect interface
NET_IFACE="${NET_IFACE:-ens33}"
echo -e "NET_IFACE:      ${GREEN}${NET_IFACE}${NC}"

# Check if interface exists
if ! ip link show "$NET_IFACE" &>/dev/null; then
    echo -e "${RED}ERROR: Interface $NET_IFACE not found!${NC}"
    echo ""
    echo "Available interfaces:"
    ip -o link show | awk -F': ' '{print "  - " $2}'
    echo ""
    echo "Set NET_IFACE in your .env file to one of the above."
    exit 1
fi

# Get IP from interface
DETECTED_IP=$(ip -j addr show dev "$NET_IFACE" 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for addr in data[0].get('addr_info', []):
        if addr.get('family') == 'inet':
            print(addr.get('local', ''))
            break
except:
    pass
" 2>/dev/null || echo "")

if [ -z "$DETECTED_IP" ]; then
    echo -e "DETECTED_IP:    ${RED}Could not detect${NC}"
    echo ""
    echo "This interface has no IPv4 address assigned."
    echo "Check your network configuration."
else
    echo -e "DETECTED_IP:    ${GREEN}${DETECTED_IP}${NC} (auto-detected)"
fi

# Check for manual override
if [ -n "$DEVICE_IP" ]; then
    echo -e "DEVICE_IP:      ${YELLOW}${DEVICE_IP}${NC} (manual override)"
fi

# Check ANALYZER_HOST
if [ -n "$ANALYZER_HOST" ]; then
    echo -e "ANALYZER_HOST:  ${GREEN}${ANALYZER_HOST}${NC}"
    
    # Try to ping analyzer
    if ping -c 1 -W 2 "$ANALYZER_HOST" &>/dev/null; then
        echo -e "                ${GREEN}✓ Reachable${NC}"
    else
        echo -e "                ${YELLOW}⚠ Not reachable (might be OK if on different network)${NC}"
    fi
elif [ -n "$ANALYZER_URL" ]; then
    echo -e "ANALYZER_URL:   ${GREEN}${ANALYZER_URL}${NC}"
else
    echo -e "ANALYZER_HOST:  ${RED}NOT SET${NC}"
    echo ""
    echo "You must set ANALYZER_HOST in your .env file!"
    echo "Example: ANALYZER_HOST=192.168.1.20"
fi

# Check other required vars
echo ""
echo "Required variables:"
[ -n "$DEVICE_ID" ] && echo -e "  DEVICE_ID:      ${GREEN}${DEVICE_ID}${NC}" || echo -e "  DEVICE_ID:      ${RED}NOT SET${NC}"
[ -n "$HOSTNAME" ] && echo -e "  HOSTNAME:       ${GREEN}${HOSTNAME}${NC}" || echo -e "  HOSTNAME:       ${RED}NOT SET${NC}"
[ -n "$INGEST_API_KEY" ] && echo -e "  INGEST_API_KEY: ${GREEN}[set]${NC}" || echo -e "  INGEST_API_KEY: ${RED}NOT SET${NC}"

echo "=============================================="
