# Multi-stage production Dockerfile for PatchForge AI Backend Engine
# ====================================================================

FROM python:3.12-slim AS builder

WORKDIR /app

# Install system compilation tools for tree-sitter C bindings
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final minimal runtime container
FROM python:3.12-slim AS runner

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Create non-root user
RUN useradd -u 10001 -m -s /bin/bash appuser && \
    chown -R appuser:appuser /app

COPY --chown=appuser:appuser backend/ /app/backend/
COPY --chown=appuser:appuser fixtures/ /app/fixtures/

ENV PYTHONPATH=/app/backend

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
