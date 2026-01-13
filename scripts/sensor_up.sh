#!/bin/bash
# =============================================================================
# Analytical-Intelligence v1 - Sensor Stack Startup Script
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=============================================="
echo "Analytical-Intelligence Sensor Stack Startup"
echo "=============================================="

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "ERROR: .env file not found!"
    echo ""
    echo "Create .env from example:"
    echo "  cp .env.example .env"
    echo "  nano .env"
    echo ""
    echo "Required variables:"
    echo "  ANALYZER_HOST=<analysis-server-ip>"
    echo "  INGEST_API_KEY=ONuMcisin3paJYkPDaf0tt9n2deEBeaN"
    echo "  DEVICE_ID=sensor-01"
    echo "  HOSTNAME=my-sensor"
    echo "  NET_IFACE=ens33"
    exit 1
fi

# Load .env
set -a
source .env
set +a

# Print configuration
echo ""
bash "$SCRIPT_DIR/print_config.sh"
echo ""

# Check required variables
MISSING=""
[ -z "$ANALYZER_HOST" ] && [ -z "$ANALYZER_URL" ] && MISSING="$MISSING ANALYZER_HOST"
[ -z "$INGEST_API_KEY" ] && MISSING="$MISSING INGEST_API_KEY"
[ -z "$DEVICE_ID" ] && MISSING="$MISSING DEVICE_ID"
[ -z "$HOSTNAME" ] && MISSING="$MISSING HOSTNAME"

if [ -n "$MISSING" ]; then
    echo "ERROR: Missing required variables:$MISSING"
    echo "Please set them in .env file."
    exit 1
fi

# Create data directories
echo "Creating data directories..."
mkdir -p data/suricata

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed!"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "ERROR: Docker Compose is not available!"
    exit 1
fi

# Start the stack
echo ""
echo "Starting Sensor Stack..."
docker compose -f docker-compose.sensor.yml up -d --build

echo ""
echo "=============================================="
echo "Sensor Stack Started!"
echo "=============================================="
echo ""
echo "Monitor logs with:"
echo "  docker compose -f docker-compose.sensor.yml logs -f"
echo ""
echo "Stop with:"
echo "  docker compose -f docker-compose.sensor.yml down"
echo ""
