"""
PatchForge AI - Patches API Endpoints
=====================================
REST endpoints for triggering AST patch generation, multi-stage validation,
inspecting diffs, and tracking patch lifecycle.
"""

from typing import Optional
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Patch, Vulnerability, PatchStatus, Repository
from app.models.user import User, UserRole
from app.schemas.patch import (
    PatchGenerateRequest,
    PatchResponse,
    PatchListResponse,
    ValidationReportResponse,
)
from app.remediation.patch_generator import patch_generator
from app.validation.validator import patch_validator
from app.core.exceptions import EntityNotFoundException
from app.core.deps import get_current_user, require_roles

router = APIRouter()


def _get_org_scoped_vulnerability(db: Session, vuln_id: str, organization_id: Optional[str]) -> Vulnerability:
    vuln = (
        db.query(Vulnerability)
        .join(Repository, Vulnerability.repository_id == Repository.id)
        .filter(Vulnerability.id == vuln_id, Repository.organization_id == organization_id)
        .first()
    )
    if not vuln:
        raise EntityNotFoundException("Vulnerability", vuln_id)
    return vuln


def _get_org_scoped_patch(db: Session, patch_id: str, organization_id: Optional[str]) -> Patch:
    patch = (
        db.query(Patch)
        .join(Vulnerability, Patch.vulnerability_id == Vulnerability.id)
        .join(Repository, Vulnerability.repository_id == Repository.id)
        .filter(Patch.id == patch_id, Repository.organization_id == organization_id)
        .first()
    )
    if not patch:
        raise EntityNotFoundException("Patch", patch_id)
    return patch


@router.post("/generate", response_model=PatchResponse, status_code=status.HTTP_201_CREATED, summary="Generate AST Remediation Patch")
def generate_patch(payload: PatchGenerateRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Triggers autonomous AST-targeted minimal patch generation for a vulnerability finding.
    Uses local Code LLM with prompt injection guardrails and produces unified git diffs.
    Scoped to the caller's own tenant.
    """
    vuln = _get_org_scoped_vulnerability(db, payload.vulnerability_id, current_user.organization_id)

    patch = patch_generator.generate_patch_for_vulnerability(db=db, vulnerability=vuln)
    return patch


@router.post("/{patch_id}/validate", response_model=ValidationReportResponse, status_code=status.HTTP_200_OK, summary="Execute 4-Stage Patch Validation")
def validate_patch(
    patch_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.SECURITY_ENGINEER, UserRole.DEVELOPER)),
):
    """
    Executes the comprehensive 4-stage validation pipeline on a candidate patch:
    1. Syntax parse
    2. AST structural integrity
    3. Dynamic test / PoC neutralization in sandbox
    4. Security re-scan
    Computes composite score (0-100) and marks patch as VALIDATED or REJECTED.
    """
    patch = _get_org_scoped_patch(db, patch_id, current_user.organization_id)

    report = patch_validator.validate_patch(db=db, patch=patch)
    db.refresh(patch)
    return ValidationReportResponse(
        patch_id=patch.id,
        id=patch.id,
        syntax_valid=report.syntax_valid,
        ast_valid=report.ast_valid,
        test_pass_rate=report.test_pass_rate,
        rescan_clean=report.rescan_clean,
        composite_score=report.composite_score,
        patch_score=report.composite_score,
        diff_content=patch.diff_content,
        explanation=patch.explanation,
        security_reason=patch.security_reason,
        status=report.status,
        stage_logs=report.stage_logs,
    )


@router.get("", response_model=PatchListResponse, summary="List Candidate Patches")
def list_patches(
    vulnerability_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    status: Optional[PatchStatus] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves a paginated list of candidate patches with filtering, scoped to the caller's own tenant."""
    query = (
        db.query(Patch)
        .join(Vulnerability, Patch.vulnerability_id == Vulnerability.id)
        .join(Repository, Vulnerability.repository_id == Repository.id)
        .filter(Repository.organization_id == current_user.organization_id)
    )

    # filter_by() after a join binds to the last-joined entity (Repository), not
    # Patch - these must name the column explicitly via filter().
    if vulnerability_id:
        query = query.filter(Patch.vulnerability_id == vulnerability_id)
    if scan_id:
        query = query.filter(Patch.scan_id == scan_id)
    if status:
        query = query.filter(Patch.status == status)

    total = query.count()
    items = query.order_by(Patch.created_at.desc()).offset(skip).limit(limit).all()
    return PatchListResponse(total=total, items=items)


@router.get("/{patch_id}", response_model=PatchResponse, summary="Get Patch Details & Unified Diff")
def get_patch(patch_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Retrieves full details for a candidate patch including its unified git diff and validation scores, scoped to the caller's own tenant."""
    return _get_org_scoped_patch(db, patch_id, current_user.organization_id)
