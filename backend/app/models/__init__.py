"""
PatchForge AI - Database Models Package
======================================
Consolidates all SQLAlchemy database entities for Alembic discovery and ORM relations.
"""

from app.database import Base
from app.models.user import User, UserRole
from app.models.repository import Repository
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability, SeverityLevel, VulnerabilityStatus
from app.models.ast_node import ASTNode
from app.models.exploit_verification import ExploitVerification
from app.models.patch import Patch, PatchStatus
from app.models.test_run import TestRun
from app.models.pull_request import PullRequest, PRStatus
from app.models.pipeline_run import PipelineRun, PipelineState
from app.models.audit_log import AuditLog

__all__ = [
    "Base",
    "User",
    "UserRole",
    "Repository",
    "Scan",
    "ScanStatus",
    "Vulnerability",
    "SeverityLevel",
    "VulnerabilityStatus",
    "ASTNode",
    "ExploitVerification",
    "Patch",
    "PatchStatus",
    "TestRun",
    "PullRequest",
    "PRStatus",
    "PipelineRun",
    "PipelineState",
    "AuditLog",
]
