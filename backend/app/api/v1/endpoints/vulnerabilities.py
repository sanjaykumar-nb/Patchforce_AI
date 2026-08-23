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
from app.models import Vulnerability, SeverityLevel, VulnerabilityStatus, Repository
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
    query = db.query(Vulnerability).join(Repository, Vulnerability.repository_id == Repository.id).filter(
        Repository.organization_id == current_user.organization_id
    )

    # filter_by() after a join binds to the last-joined entity (Repository), not
    # Vulnerability - these must name the column explicitly via filter().
    if repository_id:
        query = query.filter(Vulnerability.repository_id == repository_id)
    if scan_id:
        query = query.filter(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if status:
        query = query.filter(Vulnerability.status == status)
    if cwe:
        query = query.filter(Vulnerability.cwe == cwe)

    total = query.count()
    items = query.order_by(Vulnerability.created_at.desc()).offset(skip).limit(limit).all()
    return VulnerabilityListResponse(total=total, items=items)


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


@router.get("/{vuln_id}", response_model=VulnerabilityDetailResponse, summary="Get Vulnerability Details")
def get_vulnerability(vuln_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Retrieves full details for a vulnerability including associated AST nodes and evidence, scoped to the caller's own tenant."""
    return _get_org_scoped_vulnerability(db, vuln_id, current_user.organization_id)


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
    vuln = _get_org_scoped_vulnerability(db, vuln_id, current_user.organization_id)

    verification = exploit_verifier.verify_vulnerability(db=db, vulnerability=vuln)
    return verification
