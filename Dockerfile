# Multi-stage build for security and smaller image size
FROM python:3.11-slim-bookworm AS builder

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install only necessary build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .

# Upgrade pip to latest version for security
RUN pip install --no-cache-dir --upgrade pip

# Install dependencies (make sure requirements.txt uses pinned versions, e.g., fastapi==0.109.1)
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim-bookworm AS production

# Install security updates and clean up
RUN apt-get update && apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/* && apt-get clean

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# Copy Python packages from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=appuser:appuser main.py .

# Security hardening
RUN chmod 755 /app && \
    chmod 644 /app/main.py

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health', timeout=10)" || exit 1

# Expose port
EXPOSE 8000

# Run the application with security settings
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
