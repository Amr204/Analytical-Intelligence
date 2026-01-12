#!/bin/bash
# =====================================================
# Mini-SIEM v1 - Sensor Server Startup Script
# =====================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "========================================"
echo "Mini-SIEM v1 - Sensor Server"
echo "========================================"

# Check Docker
echo "[1/3] Checking Docker..."
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed. Please install Docker first."
    exit 1
fi

if ! docker info &> /dev/null; then
    echo "ERROR: Docker daemon is not running. Please start Docker first."
    exit 1
fi
echo "[✓] Docker is running"

# Check Docker Compose
echo "[2/3] Checking Docker Compose..."
if ! docker compose version &> /dev/null; then
    echo "ERROR: Docker Compose v2 is required. Please install it."
    exit 1
fi
echo "[✓] Docker Compose is available"

# Create data directories
echo "[3/3] Preparing data directories..."
mkdir -p "$PROJECT_ROOT/data/suricata"
chmod 755 "$PROJECT_ROOT/data/suricata"
echo "[✓] Data directories ready"

# Check network interface
NET_IFACE="${NET_IFACE:-ens33}"
echo ""
echo "Network interface: $NET_IFACE"
if ip link show "$NET_IFACE" &> /dev/null; then
    echo "[✓] Interface $NET_IFACE exists"
else
    echo "[!] Warning: Interface $NET_IFACE not found!"
    echo "    Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk -F: '{print "    - " $2}' | tr -d ' '
    echo ""
    echo "    Set correct interface: export NET_IFACE=<interface_name>"
fi

# Start the stack
echo ""
echo "Starting Sensor stack..."
cd "$PROJECT_ROOT"
docker compose -f docker-compose.sensor.yml up -d --build

echo ""
echo "========================================"
echo "Mini-SIEM Sensor Server Started!"
echo "========================================"
echo ""
echo "Suricata eve.json: $PROJECT_ROOT/data/suricata/eve.json"
echo ""
echo "View logs:"
echo "  docker compose -f docker-compose.sensor.yml logs -f"
echo ""
echo "View Suricata alerts:"
echo "  tail -f $PROJECT_ROOT/data/suricata/eve.json | jq '.'"
echo ""
echo "Check container status:"
echo "  docker compose -f docker-compose.sensor.yml ps"
echo ""
echo "Stop:"
echo "  docker compose -f docker-compose.sensor.yml down"
echo ""
