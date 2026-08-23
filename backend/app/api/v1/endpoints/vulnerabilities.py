"""
PatchForge AI - Vulnerabilities API Endpoints
=============================================
REST endpoints for querying detected vulnerabilities, inspecting AST evidence,
and triggering safe dynamic PoC verification.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Vulnerability, SeverityLevel, VulnerabilityStatus
from app.models.user import User, UserRole
from app.schemas.vulnerability import (
    VulnerabilityResponse,
    VulnerabilityDetailResponse,
    VulnerabilityListResponse,
    ExploitVerificationResponse,
)
from app.verification.verifier import exploit_verifier
from app.core.exceptions import EntityNotFoundException
from app.core.deps import get_current_user, require_roles

router = APIRouter()


@router.get("", response_model=VulnerabilityListResponse, summary="List Vulnerabilities")
def list_vulnerabilities(
    repository_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    severity: Optional[SeverityLevel] = None,
    status: Optional[VulnerabilityStatus] = None,
    cwe: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves a paginated list of vulnerabilities with flexible filtering
    by severity, CWE, status, repository, or scan session.
    """
    query = db.query(Vulnerability)

    if repository_id:
        query = query.filter_by(repository_id=repository_id)
    if scan_id:
        query = query.filter_by(scan_id=scan_id)
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    if cwe:
        query = query.filter_by(cwe=cwe)

    total = query.count()
    items = query.order_by(Vulnerability.created_at.desc()).offset(skip).limit(limit).all()
    return VulnerabilityListResponse(total=total, items=items)


@router.get("/{vuln_id}", response_model=VulnerabilityDetailResponse, summary="Get Vulnerability Details")
def get_vulnerability(vuln_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Retrieves full details for a vulnerability including associated AST nodes and evidence."""
    vuln = db.query(Vulnerability).filter_by(id=vuln_id).first()
    if not vuln:
        raise EntityNotFoundException("Vulnerability", vuln_id)
    return vuln


@router.post("/{vuln_id}/verify", response_model=ExploitVerificationResponse, status_code=status.HTTP_200_OK, summary="Verify Exploitability via Dynamic PoC")
def verify_vulnerability(
    vuln_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.SECURITY_ENGINEER, UserRole.DEVELOPER)),
):
    """
    Executes a safe, non-destructive dynamic PoC harness inside the Docker sandbox
    to verify exploitability and rule out false positives.
    """
    vuln = db.query(Vulnerability).filter_by(id=vuln_id).first()
    if not vuln:
        raise EntityNotFoundException("Vulnerability", vuln_id)

    verification = exploit_verifier.verify_vulnerability(db=db, vulnerability=vuln)
    return verification
