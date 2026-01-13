FROM python:3.11-slim

# Install system dependencies for NFStream and IP detection
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .

# Note: common/ is mounted via docker-compose volume at /app/common
# The agent imports from common.ip_utils

CMD ["python", "-u", "agent.py"]
