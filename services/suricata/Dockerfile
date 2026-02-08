# ==============================================================================
# Suricata IDS Service - OFFLINE MODE
# ==============================================================================
# Rule-based Intrusion Detection System for network traffic analysis
# Runs on sensor servers with network_mode: host to see real traffic
#
# Features:
# - LOCAL RULES ONLY (no external feeds/ET)
# - DDoS, DoS, PortScan, Botnet detection
# - EVE JSON logging for collector agent
# - Simple log rotation
# ==============================================================================

FROM jasonish/suricata:latest

# Note: bash and coreutils-single are already installed in the base image
USER root

# Create directories
RUN mkdir -p /var/log/suricata /var/lib/suricata/rules /etc/suricata

# Copy configuration files (LOCAL RULES ONLY - no ET)
COPY etc/suricata.yaml /etc/suricata/suricata.yaml

# Copy local rules (shipped with project)
COPY rules/local.rules /var/lib/suricata/rules/local.rules

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Ensure directories are writable
RUN chmod 777 /var/log/suricata /var/lib/suricata/rules

ENTRYPOINT ["/entrypoint.sh"]
