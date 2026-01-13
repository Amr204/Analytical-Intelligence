#!/bin/bash
# Analytical-Intelligence v1 - Suricata Entrypoint

set -e

NET_IFACE="${NET_IFACE:-ens33}"

echo "=========================================="
echo "Analytical-Intelligence Suricata IDS"
echo "=========================================="
echo "Interface: ${NET_IFACE}"
echo "=========================================="

# Update rules
echo "Updating Suricata rules..."
suricata-update --no-test --no-reload 2>/dev/null || echo "suricata-update completed (some sources may have failed)"

echo "Rules updated."

# Create log directory if needed
mkdir -p /var/log/suricata

# Start Suricata
echo "Starting Suricata on ${NET_IFACE}..."
exec suricata -c /etc/suricata/suricata.yaml --af-packet="${NET_IFACE}" -v

# exec suricata -c /etc/suricata/suricata.yaml -i "${NET_IFACE}" --af-packet="${NET_IFACE}" -v
