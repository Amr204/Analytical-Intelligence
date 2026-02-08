#!/bin/bash
# ==============================================================================
# Suricata IDS Entrypoint Script - OFFLINE MODE
# ==============================================================================
# Uses LOCAL RULES ONLY - No external rule downloads or ET feeds
# ==============================================================================

set -e

# Configuration from environment
SURICATA_IFACE="${SURICATA_IFACE:-}"
MAX_EVE_MB="${MAX_EVE_MB:-200}"

# Paths
RULES_DIR="/var/lib/suricata/rules"
LOG_DIR="/var/log/suricata"
EVE_FILE="$LOG_DIR/eve.json"
LOCAL_RULES="$RULES_DIR/local.rules"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ------------------------------------------------------------------------------
# Auto-detect network interface if not set or invalid
# ------------------------------------------------------------------------------
detect_interface() {
    if [ -z "$SURICATA_IFACE" ]; then
        SURICATA_IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
        if [ -z "$SURICATA_IFACE" ]; then
            SURICATA_IFACE=$(ip link show 2>/dev/null | awk -F: '/^[0-9]+: e/{print $2; exit}' | tr -d ' ')
        fi
        if [ -z "$SURICATA_IFACE" ]; then
            SURICATA_IFACE="eth0"
        fi
        echo -e "${YELLOW}[*] Auto-detected interface: $SURICATA_IFACE${NC}"
    fi
    
    # Validate interface exists
    if ! ip link show "$SURICATA_IFACE" &>/dev/null; then
        echo -e "${RED}[!] Interface $SURICATA_IFACE not found, trying to find alternative...${NC}"
        SURICATA_IFACE=$(ip link show 2>/dev/null | awk -F: '/^[0-9]+: e/{print $2; exit}' | tr -d ' ')
        if [ -z "$SURICATA_IFACE" ]; then
            echo -e "${RED}[!] No valid interface found, using eth0 as fallback${NC}"
            SURICATA_IFACE="eth0"
        fi
    fi
}

detect_interface

echo "============================================================"
echo "  Suricata IDS Service - OFFLINE MODE"
echo "============================================================"
echo "  Interface:   $SURICATA_IFACE"
echo "  Rules Dir:   $RULES_DIR"
echo "  Log Dir:     $LOG_DIR"
echo "  Max EVE MB:  $MAX_EVE_MB"
echo "============================================================"

# Ensure directories exist
mkdir -p "$LOG_DIR" "$RULES_DIR"

# ------------------------------------------------------------------------------
# Verify local.rules exists
# ------------------------------------------------------------------------------
if [ ! -f "$LOCAL_RULES" ]; then
    echo -e "${RED}[!] ERROR: local.rules not found at $LOCAL_RULES${NC}"
    echo -e "${RED}[!] Suricata requires rules to function. Exiting.${NC}"
    exit 1
fi

# Count active rules
count_rules() {
    grep -cE "^alert|^drop|^reject|^pass" "$LOCAL_RULES" 2>/dev/null || echo 0
}

RULE_COUNT=$(count_rules)
RULES_SIZE=$(du -h "$LOCAL_RULES" 2>/dev/null | cut -f1 || echo "0")

echo -e "${GREEN}[+] Local Rules Status:${NC}"
echo "    Path: $LOCAL_RULES"
echo "    Size: $RULES_SIZE"
echo "    Active Rules: $RULE_COUNT"

if [ "$RULE_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}[!] WARNING: No active rules found in local.rules${NC}"
fi

# ------------------------------------------------------------------------------
# Log rotation (simple: rotate if >MAX_MB)
# ------------------------------------------------------------------------------
rotate_logs() {
    if [ -f "$EVE_FILE" ]; then
        local size_mb
        size_mb=$(du -m "$EVE_FILE" 2>/dev/null | cut -f1 || echo 0)
        
        if [ "$size_mb" -gt "$MAX_EVE_MB" ]; then
            echo -e "${YELLOW}[*] Rotating eve.json (${size_mb}MB > ${MAX_EVE_MB}MB)${NC}"
            mv "$EVE_FILE" "${EVE_FILE}.1"
        fi
    fi
}

rotate_logs

# ------------------------------------------------------------------------------
# Validate configuration
# ------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Validating Suricata configuration...${NC}"
if suricata -T -c /etc/suricata/suricata.yaml 2>&1 | tail -10; then
    echo -e "${GREEN}[+] Configuration valid${NC}"
else
    echo -e "${RED}[!] Configuration validation failed, attempting to start anyway${NC}"
fi

# ------------------------------------------------------------------------------
# Start Suricata
# ------------------------------------------------------------------------------
echo ""
echo "============================================================"
echo -e "  ${GREEN}Starting Suricata on interface $SURICATA_IFACE${NC}"
echo -e "  ${GREEN}Loaded $RULE_COUNT local rules (NO ET feeds)${NC}"
echo "============================================================"

exec suricata -c /etc/suricata/suricata.yaml \
    -i "$SURICATA_IFACE" \
    --set "outputs.0.eve-log.filetype=regular" \
    -v
