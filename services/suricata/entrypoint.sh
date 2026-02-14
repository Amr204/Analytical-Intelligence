#!/bin/bash
# ==============================================================================
# Suricata IDS Entrypoint - Analytical-Intelligence
# ==============================================================================
# LOCAL RULES ONLY — no external feeds or ET downloads.
# Key design:
#   • Interface passed via --af-packet= (NOT -i which uses pcap)
#   • classification.config symlinked from base image if missing
#   • Validation runs before start (fail-fast)
# ==============================================================================

set -e

# ── Configuration ────────────────────────────────────────────────────────────
SURICATA_IFACE="${SURICATA_IFACE:-}"
MAX_EVE_MB="${MAX_EVE_MB:-200}"

RULES_DIR="/var/lib/suricata/rules"
LOG_DIR="/var/log/suricata"
EVE_FILE="$LOG_DIR/eve.json"
LOCAL_RULES="$RULES_DIR/local.rules"
SURICATA_CONF="/etc/suricata/suricata.yaml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Interface Detection ──────────────────────────────────────────────────────
detect_interface() {
    if [ -z "$SURICATA_IFACE" ]; then
        # Try default route first
        SURICATA_IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
        # Fallback: first ethernet-like interface
        if [ -z "$SURICATA_IFACE" ]; then
            SURICATA_IFACE=$(ip -o link show 2>/dev/null \
                | awk -F': ' '!/lo/{print $2; exit}' \
                | sed 's/@.*//')
        fi
        if [ -z "$SURICATA_IFACE" ]; then
            SURICATA_IFACE="eth0"
        fi
        echo -e "${YELLOW}[*] Auto-detected interface: $SURICATA_IFACE${NC}"
    fi

    # Validate
    if ! ip link show "$SURICATA_IFACE" &>/dev/null; then
        echo -e "${RED}[!] Interface '$SURICATA_IFACE' not found!${NC}"
        echo -e "${YELLOW}[*] Available interfaces:${NC}"
        ip -o link show 2>/dev/null | awk -F': ' '{print "    " $2}'
        # Try fallback
        SURICATA_IFACE=$(ip -o link show 2>/dev/null \
            | awk -F': ' '!/lo/{print $2; exit}' \
            | sed 's/@.*//')
        if [ -z "$SURICATA_IFACE" ]; then
            echo -e "${RED}[!] FATAL: No usable interface found. Exiting.${NC}"
            exit 1
        fi
        echo -e "${YELLOW}[*] Using fallback: $SURICATA_IFACE${NC}"
    fi
    
    # Enable PROMISCUOUS MODE (Critical for IDS)
    echo -e "${YELLOW}[*] Enabling promiscuous mode on $SURICATA_IFACE...${NC}"
    ip link set "$SURICATA_IFACE" promisc on || echo -e "${RED}[!] Failed to set promisc mode (need NET_ADMIN capability)${NC}"
}

detect_interface

# ── Ensure Directories ───────────────────────────────────────────────────────
mkdir -p "$LOG_DIR" "$RULES_DIR"

# ── Ensure classification.config exists ──────────────────────────────────────
# The base image (jasonish/suricata) ships classification.config at various
# paths. Our custom YAML doesn't reference it, but Suricata may look for it
# by default. Ensure it exists at the standard path.
if [ ! -f /etc/suricata/classification.config ]; then
    # Search common locations in the base image
    for src in /usr/share/suricata/classification.config \
               /etc/suricata/classification.config \
               /var/lib/suricata/classification.config; do
        if [ -f "$src" ]; then
            cp "$src" /etc/suricata/classification.config
            echo -e "${GREEN}[+] Copied classification.config from $src${NC}"
            break
        fi
    done
    # If still missing, create a minimal one
    if [ ! -f /etc/suricata/classification.config ]; then
        cat > /etc/suricata/classification.config << 'CLASSEOF'
config classification: attempted-recon,Attempted Information Leak,2
config classification: attempted-dos,Attempted Denial of Service,2
config classification: trojan-activity,A Network Trojan was Detected,1
config classification: web-application-attack,Web Application Attack,1
config classification: attempted-admin,Attempted Administrator Privilege Gain,1
config classification: system-call-detect,A System Call was Detected,2
config classification: policy-violation,Potential Corporate Privacy Violation,1
config classification: misc-attack,Misc Attack,2
config classification: not-suspicious,Not Suspicious Traffic,3
CLASSEOF
        echo -e "${YELLOW}[*] Created minimal classification.config${NC}"
    fi
fi

# Same for reference.config
if [ ! -f /etc/suricata/reference.config ]; then
    for src in /usr/share/suricata/reference.config \
               /var/lib/suricata/reference.config; do
        if [ -f "$src" ]; then
            cp "$src" /etc/suricata/reference.config
            echo -e "${GREEN}[+] Copied reference.config from $src${NC}"
            break
        fi
    done
    if [ ! -f /etc/suricata/reference.config ]; then
        touch /etc/suricata/reference.config
        echo -e "${YELLOW}[*] Created empty reference.config${NC}"
    fi
fi

# ── Banner ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  Suricata IDS - Analytical-Intelligence (OFFLINE MODE)${NC}"
echo -e "${CYAN}============================================================${NC}"
echo "  Interface:   $SURICATA_IFACE"
echo "  Rules Dir:   $RULES_DIR"
echo "  Log Dir:     $LOG_DIR"
echo "  Max EVE MB:  $MAX_EVE_MB"
echo -e "${CYAN}============================================================${NC}"

# ── Verify Rules ─────────────────────────────────────────────────────────────
if [ ! -f "$LOCAL_RULES" ]; then
    echo -e "${RED}[!] FATAL: local.rules not found at $LOCAL_RULES${NC}"
    exit 1
fi

RULE_COUNT=$(grep -cE "^alert|^drop|^reject|^pass" "$LOCAL_RULES" 2>/dev/null || echo 0)
echo -e "${GREEN}[+] Rules: $RULE_COUNT active rules in local.rules${NC}"

if [ "$RULE_COUNT" -eq 0 ]; then
    echo -e "${RED}[!] FATAL: No active rules found!${NC}"
    exit 1
fi

# ── Log Rotation ─────────────────────────────────────────────────────────────
if [ -f "$EVE_FILE" ]; then
    size_mb=$(du -m "$EVE_FILE" 2>/dev/null | cut -f1 || echo 0)
    if [ "$size_mb" -gt "$MAX_EVE_MB" ]; then
        echo -e "${YELLOW}[*] Rotating eve.json (${size_mb}MB > ${MAX_EVE_MB}MB)${NC}"
        mv "$EVE_FILE" "${EVE_FILE}.1"
    fi
fi

# ── Validate Config ──────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[*] Validating Suricata configuration...${NC}"

VALIDATION_OUTPUT=$(suricata -T \
    -c "$SURICATA_CONF" \
    --af-packet="$SURICATA_IFACE" \
    2>&1)
VALIDATION_RESULT=$?

# Show key lines from validation
echo "$VALIDATION_OUTPUT" | grep -iE "(rule|load|fail|error|warn|invalid)" | head -20
echo ""

LOADED_RULES=$(echo "$VALIDATION_OUTPUT" | grep -oP '\d+(?= rules loaded)' | head -1 || echo "?")
FAILED_RULES=$(echo "$VALIDATION_OUTPUT" | grep -oP '\d+(?= rules failed)' | head -1 || echo "0")

echo -e "${CYAN}────────────────────────────────────────────────────${NC}"
echo "  Rules in file:    $RULE_COUNT"
echo "  Rules loaded:     ${LOADED_RULES}"
echo "  Rules failed:     ${FAILED_RULES}"
echo -e "${CYAN}────────────────────────────────────────────────────${NC}"

if [ "$VALIDATION_RESULT" -ne 0 ]; then
    echo -e "${RED}[!] FATAL: Suricata validation failed (exit=$VALIDATION_RESULT)${NC}"
    echo "$VALIDATION_OUTPUT" | tail -25
    exit 1
fi

echo -e "${GREEN}[+] Validation passed ✓${NC}"

# ── Start Suricata ───────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}[+] Starting Suricata on $SURICATA_IFACE (af-packet mode)${NC}"
echo -e "${GREEN}[+] $RULE_COUNT local rules loaded (NO ET feeds)${NC}"
echo ""

exec suricata \
    -c "$SURICATA_CONF" \
    --af-packet="$SURICATA_IFACE" \
    -v
