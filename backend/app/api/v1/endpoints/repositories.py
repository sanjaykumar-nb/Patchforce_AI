"""
PatchForge AI - Repositories API Endpoints
==========================================
REST endpoints for repository registration, listing, and configuration.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Repository
from app.models.user import User, UserRole
from app.schemas.repository import RepositoryCreate, RepositoryResponse, RepositoryListResponse
from app.core.exceptions import EntityNotFoundException, PatchForgeException
from app.core.deps import get_current_user, require_roles

router = APIRouter()


def _sanitize_github_url(raw: str, suffix: str = "") -> str:
    """Removes duplicate github.com prefixes and normalises the URL."""
    raw = raw.strip()
    # Strip any leading https://github.com// or github.com/https:// duplicates
    while "github.com/https://" in raw or "github.com/http://" in raw:
        raw = raw.split("github.com/")[-1]  # keep only the path portion
        raw = f"https://github.com/{raw}"
    # Ensure the URL starts with https://
    if not raw.startswith("https://") and not raw.startswith("git@"):
        raw = f"https://github.com/{raw}"
    # Remove duplicate .git suffixes
    while raw.endswith(".git.git"):
        raw = raw[:-4]
    # Remove .git before adding correct suffix
    raw = raw.removesuffix(".git")
    return raw + suffix


@router.post("", response_model=RepositoryResponse, status_code=status.HTTP_201_CREATED, summary="Register Repository")
def create_repository(payload: RepositoryCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Registers a new code repository for continuous AST scanning and automated remediation."""
    # Normalize full_name and name if user entered full GitHub URL
    raw_full_name = payload.full_name.strip()
    if "github.com/" in raw_full_name:
        clean_full_name = raw_full_name.split("github.com/")[-1].strip("/").removesuffix(".git")
    else:
        clean_full_name = raw_full_name.strip("/").removesuffix(".git")

    raw_name = payload.name.strip()
    if "github.com/" in raw_name:
        clean_name = raw_name.split("github.com/")[-1].strip("/").split("/")[-1].removesuffix(".git")
    elif "/" in raw_name:
        clean_name = raw_name.split("/")[-1].removesuffix(".git")
    else:
        clean_name = raw_name

    existing = db.query(Repository).filter_by(
        full_name=clean_full_name, organization_id=current_user.organization_id
    ).first()
    if existing:
        raise PatchForgeException(
            message=f"Repository with full_name '{clean_full_name}' is already registered.",
            status_code=status.HTTP_409_CONFLICT,
        )

    raw_url = payload.url.strip() or f"https://github.com/{clean_full_name}"
    raw_clone = payload.clone_url.strip() or f"https://github.com/{clean_full_name}.git"

    clean_url = _sanitize_github_url(raw_url, suffix="")
    clean_clone = _sanitize_github_url(raw_clone, suffix=".git")

    repo = Repository(
        organization_id=current_user.organization_id,
        name=clean_name,
        full_name=clean_full_name,
        url=clean_url,
        clone_url=clean_clone,
        default_branch=payload.default_branch or "main",
        language=payload.language,
        webhook_secret=payload.webhook_secret,
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)
    return repo


@router.get("", response_model=RepositoryListResponse, summary="List Repositories")
def list_repositories(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves all repositories registered under the caller's own tenant workspace, with pagination."""
    query = db.query(Repository).filter_by(organization_id=current_user.organization_id)
    total = query.count()
    items = query.order_by(Repository.created_at.desc()).offset(skip).limit(limit).all()
    return RepositoryListResponse(total=total, items=items)


@router.get("/{repo_id}", response_model=RepositoryResponse, summary="Get Repository Details")
def get_repository(repo_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Retrieves a single repository by its unique identifier, scoped to the caller's own tenant."""
    repo = db.query(Repository).filter_by(id=repo_id, organization_id=current_user.organization_id).first()
    if not repo:
        raise EntityNotFoundException("Repository", repo_id)
    return repo


@router.delete("/{repo_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete Repository")
def delete_repository(
    repo_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.SECURITY_ENGINEER)),
):
    """Removes a repository and all associated scans, findings, and patches. Scoped to the caller's own tenant."""
    repo = db.query(Repository).filter_by(id=repo_id, organization_id=current_user.organization_id).first()
    if not repo:
        raise EntityNotFoundException("Repository", repo_id)
    db.delete(repo)
    db.commit()
    return None
