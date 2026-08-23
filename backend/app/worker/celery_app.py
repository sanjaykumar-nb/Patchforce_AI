"""
PatchForge AI - Celery Asynchronous Task Application
====================================================
Configures distributed worker queues backed by Redis for long-running
AST static scans, dynamic exploit verifications, and multi-stage patch validation.
"""

from celery import Celery
from app.config import get_settings
from app.core.logging import get_logger

logger = get_logger("patchforge.worker.celery")
settings = get_settings()

celery_app = Celery(
    "patchforge_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=600,  # 10 minutes max per task
    task_soft_time_limit=540,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_routes={
        "app.worker.tasks.task_run_security_scan": {"queue": "scans"},
        "app.worker.tasks.task_verify_vulnerability": {"queue": "verification"},
        "app.worker.tasks.task_generate_and_validate_patch": {"queue": "remediation"},
    },
)

# Auto-discover tasks in worker module
celery_app.autodiscover_tasks(["app.worker"])
