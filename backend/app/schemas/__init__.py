"""
PatchForge AI - Schemas Package
===============================
Pydantic data validation and serialization models.
"""

from app.schemas.repository import RepositoryCreate, RepositoryResponse, RepositoryListResponse
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse
from app.schemas.vulnerability import (
    ASTNodeResponse,
    ExploitVerificationResponse,
    VulnerabilityResponse,
    VulnerabilityDetailResponse,
    VulnerabilityListResponse,
)
from app.schemas.patch import (
    PatchGenerateRequest,
    PatchResponse,
    PatchListResponse,
    ValidationReportResponse,
)
from app.schemas.pull_request import (
    PullRequestCreateRequest,
    PullRequestResponse,
    PullRequestListResponse,
)
from app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    TokenResponse,
)

__all__ = [
    "RepositoryCreate",
    "RepositoryResponse",
    "RepositoryListResponse",
    "ScanCreate",
    "ScanResponse",
    "ScanListResponse",
    "ASTNodeResponse",
    "ExploitVerificationResponse",
    "VulnerabilityResponse",
    "VulnerabilityDetailResponse",
    "VulnerabilityListResponse",
    "PatchGenerateRequest",
    "PatchResponse",
    "PatchListResponse",
    "ValidationReportResponse",
    "PullRequestCreateRequest",
    "PullRequestResponse",
    "PullRequestListResponse",
    "UserRegisterRequest",
    "UserLoginRequest",
    "UserResponse",
    "TokenResponse",
]
