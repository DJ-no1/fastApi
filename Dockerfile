# Multi-stage build for security and smaller image size
FROM python:3.12-slim-bookworm AS builder

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install build dependencies and system packages needed for URL analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libxml2-dev \
    libxslt-dev \
    pkg-config \
    build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .

# Upgrade pip to latest version for security
RUN pip install --no-cache-dir --upgrade pip

# Install dependencies for URL Intelligence API
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.12-slim-bookworm AS production

# Install runtime dependencies for URL analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2 \
    libxslt1.1 \
    ca-certificates \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# Copy Python packages from builder stage
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application files
COPY --chown=appuser:appuser main.py .
COPY --chown=appuser:appuser test_api.py .

# Security hardening
RUN chmod 755 /app && \
    chmod 644 /app/main.py && \
    chmod 644 /app/test_api.py

# Switch to non-root user
USER appuser

# Health check for URL Intelligence API
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health', timeout=10)" || exit 1

# Expose port
EXPOSE 8000

# Run the URL Intelligence API with optimized settings
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--access-log"]
