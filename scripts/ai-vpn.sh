#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="ai-vpn"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# We expect the OpenVPN config next to this script
CONF_SRC_1="${SCRIPT_DIR}/ai-vpn.ovpn"
CONF_SRC_2="${SCRIPT_DIR}/vpn.ovpn"

if [[ -f "$CONF_SRC_1" ]]; then
  CONF_SRC="$CONF_SRC_1"
elif [[ -f "$CONF_SRC_2" ]]; then
  CONF_SRC="$CONF_SRC_2"
else
  echo "❌ Could not find OpenVPN config file."
  echo "Place your config next to this script as: ai-vpn.ovpn"
  echo "Or as an alternative: vpn.ovpn"
  exit 1
fi

CONF_DST="/etc/openvpn/client/${SERVICE_NAME}.conf"
UNIT="openvpn-client@${SERVICE_NAME}.service"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "❌ You need to run this script as root:"
    echo "   sudo ${SCRIPT_DIR}/ai-vpn start"
    exit 1
  fi
}

is_installed() {
  dpkg -s "$1" >/dev/null 2>&1
}

install_if_missing() {
  local pkg="$1"
  if ! is_installed "$pkg"; then
    echo "📦 Installing: $pkg"
    apt-get update -y
    apt-get install -y "$pkg"
  else
    echo "✅ Already installed: $pkg"
  fi
}

get_remote_host_port() {
  # Parse first non-comment "remote host port" from config
  # Output: host port
  local line
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^[[:space:]]*remote[[:space:]]+ ]] || continue
    # split by spaces
    # shellcheck disable=SC2206
    local parts=($line)
    local host="${parts[1]:-}"
    local port="${parts[2]:-443}"
    if [[ -n "$host" ]]; then
      echo "$host $port"
      return 0
    fi
  done < "$CONF_SRC"
  return 1
}

append_if_missing() {
  local file="$1"
  local needle="$2"
  local line="$3"
  if ! grep -Fqx "$needle" "$file" 2>/dev/null; then
    echo "$line" >> "$file"
  fi
}

prepare_runtime_config() {
  echo "🧩 Preparing runtime config -> ${CONF_DST}"
  install -m 600 "$CONF_SRC" "$CONF_DST"

  # Add DNS integration for Ubuntu (systemd-resolved)
  # These are safe to add even if server doesn't push DNS.
  append_if_missing "$CONF_DST" "script-security 2" "script-security 2"
  append_if_missing "$CONF_DST" "up /etc/openvpn/update-systemd-resolved" "up /etc/openvpn/update-systemd-resolved"
  append_if_missing "$CONF_DST" "down /etc/openvpn/update-systemd-resolved" "down /etc/openvpn/update-systemd-resolved"
  append_if_missing "$CONF_DST" "down-pre" "down-pre"
  append_if_missing "$CONF_DST" "dhcp-option DOMAIN-ROUTE ." "dhcp-option DOMAIN-ROUTE ."

  # Improve cipher negotiation on newer OpenVPN clients (keeps modern ciphers + AES-128-CBC fallback)
  if ! grep -Eiq '^[[:space:]]*data-ciphers[[:space:]]+' "$CONF_DST"; then
    echo "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC" >> "$CONF_DST"
  fi
  if ! grep -Eiq '^[[:space:]]*data-ciphers-fallback[[:space:]]+' "$CONF_DST"; then
    echo "data-ciphers-fallback AES-128-CBC" >> "$CONF_DST"
  fi
}

start_vpn() {
  echo "🚀 Starting VPN service: ${UNIT}"

  # Make sure systemd-resolved is running
  systemctl enable --now systemd-resolved >/dev/null 2>&1 || true
  systemctl restart systemd-resolved >/dev/null 2>&1 || true

  systemctl daemon-reload
  systemctl enable "${UNIT}" >/dev/null 2>&1 || true
  systemctl restart "${UNIT}"

  echo "✅ Started. Status:"
  systemctl --no-pager --full status "${UNIT}" || true

  echo
  echo "🔎 DNS / routes quick check:"
  command -v resolvectl >/dev/null 2>&1 && resolvectl status | sed -n '1,120p' || true
  echo
  echo "🧪 Test:"
  echo "  nslookup pypi.org"
  echo "  curl -I https://pypi.org"
}

stop_vpn() {
  echo "🛑 Stopping VPN service: ${UNIT}"
  systemctl stop "${UNIT}" >/dev/null 2>&1 || true
  systemctl disable "${UNIT}" >/dev/null 2>&1 || true

  # Optional: keep config installed. If you want remove it:
  # rm -f "${CONF_DST}"

  systemctl restart systemd-resolved >/dev/null 2>&1 || true
  command -v resolvectl >/dev/null 2>&1 && resolvectl flush-caches || true

  echo "✅ Stopped."
}

show_status() {
  systemctl --no-pager --full status "${UNIT}" || true
  echo
  command -v resolvectl >/dev/null 2>&1 && resolvectl status | sed -n '1,120p' || true
}

show_logs() {
  journalctl -u "${UNIT}" -n 200 --no-pager
}

check_connectivity() {
  echo "🌐 Checking basic connectivity (without forcing VPN)..."
  if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
    echo "✅ Internet ping OK (8.8.8.8)"
  else
    echo "⚠️  Ping to 8.8.8.8 failed. VPN may not connect."
  fi

  if remote_info="$(get_remote_host_port)"; then
    local host port
    host="$(awk '{print $1}' <<<"$remote_info")"
    port="$(awk '{print $2}' <<<"$remote_info")"
    echo "🔗 Testing VPN endpoint: ${host}:${port}"
    if nc -vz -w 3 "$host" "$port" >/dev/null 2>&1; then
      echo "✅ Endpoint reachable"
    else
      echo "⚠️  Endpoint not reachable now (may be blocked/offline)."
    fi
  else
    echo "⚠️  Could not parse 'remote' from config."
  fi
}

main() {
  local cmd="${1:-start}"

  case "$cmd" in
    start|restart|stop|status|logs|install)
      ;;
    *)
      echo "Usage: sudo ${SCRIPT_DIR}/ai-vpn {start|stop|restart|status|logs}"
      exit 1
      ;;
  esac

  require_root

  # Dependencies
  install_if_missing "openvpn"
  install_if_missing "openvpn-systemd-resolved"
  install_if_missing "netcat-openbsd"

  # Verify update-systemd-resolved exists
  if [[ ! -x /etc/openvpn/update-systemd-resolved ]]; then
    echo "❌ Could not find /etc/openvpn/update-systemd-resolved"
    echo "Make sure openvpn-systemd-resolved is installed."
    exit 1
  fi

  prepare_runtime_config
  check_connectivity

  case "$cmd" in
    start) start_vpn ;;
    restart) stop_vpn; start_vpn ;;
    stop) stop_vpn ;;
    status) show_status ;;
    logs) show_logs ;;
    install) echo "✅ Installed config at ${CONF_DST}" ;;
  esac

  echo
  echo "🧰 Commands:"
  echo "  🛑 sudo ./ai-vpn.sh stop"
  echo "  🔄 sudo ./ai-vpn.sh restart"
  echo "  📊 sudo ./ai-vpn.sh status"
  echo "  🧾 sudo ./ai-vpn.sh logs"
}

main "$@"
