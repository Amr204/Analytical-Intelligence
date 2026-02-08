# syntax=docker/dockerfile:1.6
# ==============================================
# Analytical-Intelligence Backend
# Optimized for layer caching
# ==============================================

FROM python:3.11-slim AS base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq-dev \
    gcc \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# ==============================================
# Layer 1: Heavy dependencies (cached long-term)
# These rarely change: tensorflow, numpy
# ==============================================
COPY requirements-heavy.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && \
    pip install -r requirements-heavy.txt

# ==============================================
# Layer 2: Light dependencies (changes more often)
# Web, database, utilities
# ==============================================
COPY requirements-light.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements-light.txt

# ==============================================
# Layer 3: Application code (changes most often)
# ==============================================
COPY app/ ./app/

# Create models directory (will be mounted)
RUN mkdir -p /app/models/ssh

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
