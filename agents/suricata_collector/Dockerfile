# ==============================================================================
# Suricata Collector Agent
# ==============================================================================
# Tails Suricata eve.json and sends alerts to the analysis backend
# ==============================================================================

FROM python:3.11-slim

# Install system dependencies for IP detection
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .

# Create spool directory for offline queuing
RUN mkdir -p /app/spool

# Note: common/ is mounted via docker-compose volume at /app/common
CMD ["python", "-u", "agent.py"]
