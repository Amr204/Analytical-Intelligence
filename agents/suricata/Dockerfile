FROM jasonish/suricata:7.0.3

# Install suricata-update
RUN suricata-update update-sources || true

# Copy configuration
COPY suricata.yaml /etc/suricata/suricata.yaml
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

# Create log directory
RUN mkdir -p /var/log/suricata

ENTRYPOINT ["/entrypoint.sh"]
