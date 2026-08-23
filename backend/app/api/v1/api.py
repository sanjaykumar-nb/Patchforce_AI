"""
PatchForge AI - API v1 Router Aggregator
=======================================
Aggregates all version 1 modular endpoints into a central APIRouter.
"""

from fastapi import APIRouter
from app.api.v1.endpoints import (
    health,
    auth,
    organizations,
    repositories,
    scans,
    vulnerabilities,
    patches,
    pull_requests,
    webhooks,
    stream,
)

api_router = APIRouter()

# Observability & System Health
api_router.include_router(health.router, tags=["Observability & Health"])

# Authentication & RBAC
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication & RBAC"])

# Tenant Workspace
api_router.include_router(organizations.router, prefix="/organizations", tags=["Organizations"])

# Repository Management
api_router.include_router(repositories.router, prefix="/repositories", tags=["Repositories"])

# Security Scanning & AST Analysis
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])

# Vulnerability Findings & Verification
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["Vulnerabilities"])

# Autonomous Patch Remediation
api_router.include_router(patches.router, prefix="/patches", tags=["Patches"])

# Git & GitHub Pull Requests
api_router.include_router(pull_requests.router, prefix="/pull-requests", tags=["Pull Requests"])

# Cryptographic Webhooks
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])

# Real-Time Telemetry & Log Streaming (SSE / WebSocket)
api_router.include_router(stream.router, prefix="/stream", tags=["Streaming Logs"])
