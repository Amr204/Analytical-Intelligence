#!/bin/bash
# =============================================================================
# Docker Doctor - Preflight checks for Docker health
# =============================================================================
# Run this script before docker compose to detect common issues early.
# Usage: bash scripts/docker_doctor.sh
# =============================================================================

set -e

PASSED=0
FAILED=0

print_header() {
    echo "=============================================="
    echo "Docker Doctor - Preflight Health Check"
    echo "=============================================="
    echo ""
}

print_ok() {
    echo "  ✓ $1"
    PASSED=$((PASSED + 1))
}

print_fail() {
    echo "  ✗ $1"
    FAILED=$((FAILED + 1))
}

print_info() {
    echo "    → $1"
}

# =============================================================================
# CHECK A: Docker Daemon Status
# =============================================================================
check_docker_daemon() {
    echo "[A] Checking Docker daemon status..."
    
    # Check if docker command exists
    if ! command -v docker &> /dev/null; then
        print_fail "Docker is not installed"
        print_info "Install with: curl -fsSL https://get.docker.com | sudo sh"
        return 1
    fi
    
    # Check if systemctl is available (systemd)
    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet docker; then
            print_ok "Docker daemon is running"
            return 0
        else
            print_fail "Docker daemon is not running"
            echo ""
            echo "    To fix, run:"
            echo "      sudo systemctl start docker"
            echo ""
            echo "    To see why it failed:"
            echo "      sudo journalctl -xeu docker.service --no-pager | tail -n 80"
            echo ""
            return 1
        fi
    else
        # Fallback: try docker info
        if docker info &> /dev/null; then
            print_ok "Docker daemon is running"
            return 0
        else
            print_fail "Docker daemon is not running or not accessible"
            print_info "Try: sudo systemctl start docker"
            return 1
        fi
    fi
}

# =============================================================================
# CHECK B: Validate /etc/docker/daemon.json
# =============================================================================
check_daemon_json() {
    echo ""
    echo "[B] Validating /etc/docker/daemon.json..."
    
    DAEMON_JSON="/etc/docker/daemon.json"
    
    if [ ! -f "$DAEMON_JSON" ]; then
        print_ok "daemon.json does not exist (using defaults - OK)"
        return 0
    fi
    
    # Validate JSON using python3
    if python3 -m json.tool "$DAEMON_JSON" > /dev/null 2>&1; then
        print_ok "daemon.json is valid JSON"
        return 0
    else
        print_fail "daemon.json contains invalid JSON!"
        echo ""
        echo "    Error details:"
        python3 -m json.tool "$DAEMON_JSON" 2>&1 | sed 's/^/      /'
        echo ""
        echo "    To fix, backup the broken file and create a new one:"
        echo ""
        echo "      sudo mv /etc/docker/daemon.json /etc/docker/daemon.json.bad"
        echo "      sudo systemctl restart docker"
        echo ""
        echo "    Or create a minimal valid config with DNS:"
        echo ""
        echo "      sudo tee /etc/docker/daemon.json >/dev/null <<'JSON'"
        echo '      { "dns": ["1.1.1.1","8.8.8.8"] }'
        echo "      JSON"
        echo "      sudo systemctl restart docker"
        echo ""
        return 1
    fi
}

# =============================================================================
# CHECK C: Test DNS Inside Container
# =============================================================================
check_container_dns() {
    echo ""
    echo "[C] Testing DNS resolution inside container..."
    
    # First check if we can run docker
    if ! docker info &> /dev/null; then
        print_fail "Cannot run docker (skipping DNS test)"
        return 1
    fi
    
    # Run nslookup inside alpine container
    if docker run --rm alpine:3.19 nslookup deb.debian.org > /dev/null 2>&1; then
        print_ok "Container DNS is working"
        return 0
    else
        print_fail "Container cannot resolve DNS!"
        echo ""
        echo "    This causes 'Temporary failure resolving' during docker build."
        echo ""
        echo "    To fix, add DNS servers to daemon.json:"
        echo ""
        echo "      sudo tee /etc/docker/daemon.json >/dev/null <<'JSON'"
        echo '      { "dns": ["1.1.1.1","8.8.8.8"] }'
        echo "      JSON"
        echo "      sudo systemctl restart docker"
        echo ""
        return 1
    fi
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    print_header
    
    check_docker_daemon || true
    check_daemon_json || true
    check_container_dns || true
    
    echo ""
    echo "=============================================="
    if [ $FAILED -eq 0 ]; then
        echo "Docker Doctor: All checks passed! ($PASSED/$PASSED)"
        echo "=============================================="
        exit 0
    else
        echo "Docker Doctor: $FAILED issue(s) found"
        echo "=============================================="
        echo ""
        echo "Please fix the issues above before running docker compose."
        exit 1
    fi
}

main
