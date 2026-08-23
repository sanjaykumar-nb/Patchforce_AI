"""
PatchForge AI - FastAPI Application Gateway & Orchestrator Entrypoint
=====================================================================
Initializes middleware, correlation context tracking, error handlers,
API routes, and OpenAPI Swagger documentation.
"""

import time
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from app.config import get_settings
from app.core.logging import setup_logging, get_logger, request_id_ctx
from app.core.exceptions import (
    PatchForgeException,
    patchforge_exception_handler,
    generic_exception_handler,
)
from app.api.v1.api import api_router

settings = get_settings()
setup_logging(log_level=settings.LOG_LEVEL, json_format=not settings.DEBUG)
logger = get_logger("patchforge.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    logger.info(f"Initializing {settings.PROJECT_NAME} v{settings.VERSION} [{settings.ENVIRONMENT}]...")
    logger.info(f"Database URL configured: {settings.DATABASE_URL.split('@')[-1]}")
    logger.info(f"Groq Cloud LLM inference (Model: {settings.GROQ_MODEL}, API key configured: {bool(settings.GROQ_API_KEY)})")
    yield
    logger.info(f"Gracefully shutting down {settings.PROJECT_NAME}...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Autonomous AST-Driven Vulnerability Remediation & Self-Healing CI/CD Pipeline",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/api/v1/openapi.json",
    lifespan=lifespan,
)

# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Request Correlation Middleware ---
@app.middleware("http")
async def correlation_middleware(request: Request, call_next):
    """
    Assigns a unique X-Request-ID to every incoming HTTP request,
    attaches it to context variables for logging, and returns it in headers.
    """
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    token = request_id_ctx.set(request_id)
    start_time = time.time()

    try:
        response: Response = await call_next(request)
        process_time = round((time.time() - start_time) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time-Ms"] = str(process_time)
        return response
    finally:
        request_id_ctx.reset(token)


# --- Exception Handlers ---
app.add_exception_handler(PatchForgeException, patchforge_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# --- Include API v1 Router ---
app.include_router(api_router, prefix="/api/v1")


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint welcoming clients and directing to API documentation."""
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "operational",
        "documentation": "/docs",
        "health_check": "/api/v1/health",
        "readiness_check": "/api/v1/ready",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
