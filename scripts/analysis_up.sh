#!/bin/bash
# =============================================================================
# Analytical-Intelligence v1 - Analysis Stack Startup Script
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=============================================="
echo "Analytical-Intelligence Analysis Stack Startup"
echo "=============================================="

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed!"
    echo "Install with: curl -fsSL https://get.docker.com | sudo sh"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "ERROR: Docker Compose is not available!"
    exit 1
fi

# Check if .env exists (optional for analysis server)
if [ -f ".env" ]; then
    echo "Loading .env..."
    set -a
    source .env
    set +a
fi

# Check models
echo ""
echo "Checking ML models..."

SSH_MODEL="models/ssh/ssh_lstm.joblib"
if [ -f "$SSH_MODEL" ]; then
    echo "  ✓ SSH LSTM model found"
else
    echo "  ⚠ SSH LSTM model not found at $SSH_MODEL"
    echo "    Copy from: models/Host-Model/ssh_lstm.joblib"
fi

NETWORK_MODEL="models/network/model.joblib"
if [ -f "$NETWORK_MODEL" ]; then
    echo "  ✓ Network ML model found"
else
    echo "  ⚠ Network ML model not found at $NETWORK_MODEL"
    echo "    Copy from: models/Network-Model/"
fi

# Print configuration
echo ""
echo "Configuration:"
echo "  INGEST_API_KEY: ${INGEST_API_KEY:+[set]}${INGEST_API_KEY:-[using default]}"
echo "  POSTGRES_USER:  ${POSTGRES_USER:-ai}"
echo "  POSTGRES_DB:    ${POSTGRES_DB:-ai_db}"
echo ""

# Start the stack
echo "Starting Analysis Stack..."
docker compose -f docker-compose.analysis.yml up -d --build

# Wait for backend to be healthy
echo ""
echo "Waiting for backend to be ready..."
MAX_WAIT=60
WAIT=0
while [ $WAIT -lt $MAX_WAIT ]; do
    if curl -s http://localhost:8000/api/v1/health > /dev/null 2>&1; then
        echo ""
        echo "=============================================="
        echo "Analysis Stack Ready!"
        echo "=============================================="
        echo ""
        echo "Dashboard: http://localhost:8000"
        echo ""
        echo "From other machines, use your LAN IP:"
        # Try to detect LAN IP
        LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")
        if [ -n "$LAN_IP" ]; then
            echo "  http://${LAN_IP}:8000"
        fi
        echo ""
        echo "Monitor logs with:"
        echo "  docker compose -f docker-compose.analysis.yml logs -f backend"
        echo ""
        exit 0
    fi
    sleep 2
    WAIT=$((WAIT + 2))
    echo -n "."
done

echo ""
echo "WARNING: Backend health check timed out."
echo "Check logs: docker compose -f docker-compose.analysis.yml logs backend"
