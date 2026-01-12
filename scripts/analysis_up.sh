#!/bin/bash
# =====================================================
# Mini-SIEM v1 - Analysis Server Startup Script
# =====================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "========================================"
echo "Mini-SIEM v1 - Analysis Server"
echo "========================================"

# Check Docker
echo "[1/4] Checking Docker..."
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
echo "[2/4] Checking Docker Compose..."
if ! docker compose version &> /dev/null; then
    echo "ERROR: Docker Compose v2 is required. Please install it."
    exit 1
fi
echo "[✓] Docker Compose is available"

# Extract models if needed
echo "[3/4] Checking models..."
if [ -f "$SCRIPT_DIR/extract_models.sh" ]; then
    bash "$SCRIPT_DIR/extract_models.sh"
fi

# Start the stack
echo "[4/4] Starting Analysis stack..."
cd "$PROJECT_ROOT"
docker compose -f docker-compose.analysis.yml up -d --build

echo ""
echo "========================================"
echo "Waiting for services to be ready..."
echo "========================================"

# Wait for backend to be healthy
MAX_WAIT=60
COUNTER=0
while [ $COUNTER -lt $MAX_WAIT ]; do
    if curl -s http://localhost:8000/api/v1/health > /dev/null 2>&1; then
        echo "[✓] Backend is healthy!"
        break
    fi
    echo "Waiting for backend... ($COUNTER/$MAX_WAIT)"
    sleep 2
    COUNTER=$((COUNTER + 2))
done

if [ $COUNTER -ge $MAX_WAIT ]; then
    echo "[!] Warning: Backend did not become healthy in time."
    echo "    Check logs with: docker compose -f docker-compose.analysis.yml logs backend"
fi

echo ""
echo "========================================"
echo "Mini-SIEM Analysis Server Started!"
echo "========================================"
echo ""
echo "Dashboard:  http://localhost:8000"
echo "Health:     http://localhost:8000/api/v1/health"
echo ""
echo "View logs:"
echo "  docker compose -f docker-compose.analysis.yml logs -f backend"
echo ""
echo "Stop:"
echo "  docker compose -f docker-compose.analysis.yml down"
echo ""
