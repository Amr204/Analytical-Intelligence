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

# Enable BuildKit for faster builds with pip caching
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1
echo "✓ BuildKit enabled (faster rebuilds with pip cache)"
echo ""

# Run Docker Doctor preflight checks
if ! bash "$SCRIPT_DIR/docker_doctor.sh"; then
    echo ""
    echo "Fix the above issues and re-run."
    exit 1
fi
echo ""

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
    echo "  INGEST_API_KEY=<same-key-as-analysis-server>"
    echo "  DEVICE_ID=sensor-01   (must be unique per sensor!)"
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
echo "Device ID: $DEVICE_ID"
echo "Hostname:  $HOSTNAME"
echo "Sending to: ${ANALYZER_HOST:-$ANALYZER_URL}"
echo ""
echo "This sensor will appear at:"
echo "  http://<ANALYZER_IP>:8000/devices"
echo ""
echo "Monitor logs with:"
echo "  docker compose -f docker-compose.sensor.yml logs -f"
echo ""
echo "Stop with:"
echo "  docker compose -f docker-compose.sensor.yml down"
echo ""
