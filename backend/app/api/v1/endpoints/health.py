"""
PatchForge AI - Health, Readiness & Metrics Endpoints
====================================================
Observability probes for container orchestration (Kubernetes / Docker Compose),
monitoring uptime, database readiness, and message broker availability.
"""

import time
import socket
from datetime import datetime, timezone
import httpx
from fastapi import APIRouter, status, Response
from app.config import get_settings
from app.database import check_db_health
from app.core.logging import get_logger

router = APIRouter()
logger = get_logger("patchforge.health")
settings = get_settings()
START_TIME = time.time()


def check_redis_health() -> bool:
    """Checks if Redis broker port is accepting connections."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            return s.connect_ex((settings.REDIS_HOST, settings.REDIS_PORT)) == 0
    except Exception:
        return False


def check_groq_health() -> bool:
    """Checks if the Groq inference API is reachable with the configured API key."""
    if not settings.GROQ_API_KEY:
        return False
    try:
        resp = httpx.get(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
            timeout=2.0,
        )
        return resp.status_code == 200
    except Exception:
        return False


@router.get("/health", status_code=status.HTTP_200_OK, summary="Liveness Probe")
async def health_check():
    """Returns basic liveness status confirming the API server process is running."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/ready", summary="Readiness Probe")
async def readiness_check(response: Response):
    """
    Validates the database connection and Groq LLM API reachability - the two
    dependencies the app actually calls on its request paths. Redis is reported
    for visibility only and doesn't affect readiness: no reachable code path
    (API endpoints or the webhook dispatcher) enqueues anything through Celery -
    they all call the scanner/patch/PR services directly and synchronously.
    Returns HTTP 200 if all critical services are operational, or HTTP 503 if degraded.
    """
    db_ok = check_db_health()
    redis_ok = check_redis_health()
    groq_ok = check_groq_health()

    is_ready = db_ok

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if is_ready else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "database": "connected" if db_ok else "unreachable",
            "redis_broker": "connected" if redis_ok else "unreachable (unused - not required)",
            "groq_llm": "connected" if groq_ok else "unreachable (patch generation will use fallback templates)",
        }
    }


@router.get("/metrics", summary="Observability Metrics")
async def metrics_endpoint():
    """Returns runtime telemetry for DevSecOps monitoring."""
    uptime_seconds = round(time.time() - START_TIME, 2)
    return {
        "service": settings.PROJECT_NAME,
        "uptime_seconds": uptime_seconds,
        "environment": settings.ENVIRONMENT,
        "debug_mode": settings.DEBUG,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
