"""
PatchForge AI - Pull Requests API Endpoints
===========================================
REST endpoints for opening automated GitHub Pull Requests, inspecting PR status,
and listing remediation history.
"""

from typing import Optional
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import PullRequest, Patch, PRStatus
from app.models.user import User, UserRole
from app.schemas.pull_request import (
    PullRequestCreateRequest,
    PullRequestResponse,
    PullRequestListResponse,
)
from app.git.github_client import github_client
from app.core.exceptions import EntityNotFoundException
from app.core.deps import get_current_user, require_roles

router = APIRouter()


@router.post("/create", response_model=PullRequestResponse, status_code=status.HTTP_201_CREATED, summary="Create GitHub Pull Request")
def create_pull_request(
    payload: PullRequestCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.SECURITY_ENGINEER)),
):
    """
    Creates an isolated remediation branch, commits the verified code diff,
    and opens a comprehensive Pull Request with security verification scorecards.
    """
    patch = db.query(Patch).filter_by(id=payload.patch_id).first()
    if not patch:
        raise EntityNotFoundException("Patch", payload.patch_id)

    pr = github_client.create_remediation_pr(
        db=db,
        patch=patch,
        base_branch=payload.base_branch or "main",
        requesting_user=current_user,
    )
    return pr


@router.get("", response_model=PullRequestListResponse, summary="List Pull Requests")
def list_pull_requests(
    repository_id: Optional[str] = None,
    status: Optional[PRStatus] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves a paginated list of automated pull requests."""
    query = db.query(PullRequest)

    if repository_id:
        query = query.filter_by(repository_id=repository_id)
    if status:
        query = query.filter_by(status=status)

    total = query.count()
    items = query.order_by(PullRequest.created_at.desc()).offset(skip).limit(limit).all()
    return PullRequestListResponse(total=total, items=items)


@router.get("/{pr_id}", response_model=PullRequestResponse, summary="Get Pull Request Details")
def get_pull_request(pr_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Retrieves detailed information for a specific pull request."""
    pr = db.query(PullRequest).filter_by(id=pr_id).first()
    if not pr:
        raise EntityNotFoundException("PullRequest", pr_id)
    return pr
