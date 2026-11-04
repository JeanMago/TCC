# ============================================
# DeployDock Backend - Multi-stage Dockerfile
# ============================================

# --- Stage: Development ---
FROM python:3.12-slim AS development

WORKDIR /app

# Install system dependencies (git for GitPython)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create repos directory
RUN mkdir -p /app/repos

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# --- Stage: Production ---
FROM python:3.12-slim AS production

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r deploydock && useradd -r -g deploydock -d /app deploydock

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create repos directory with proper permissions
RUN mkdir -p /app/repos && chown -R deploydock:deploydock /app

# Note: We run as root because Docker socket access typically requires root
# In production, consider using Docker socket proxy for enhanced security
# USER deploydock

EXPOSE 8000

# 1 worker: WAF/rate-limit, WebSocket manager e uptime monitor mantem estado em memoria do processo.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
