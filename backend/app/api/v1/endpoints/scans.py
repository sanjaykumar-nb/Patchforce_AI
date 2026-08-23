"""
PatchForge AI - Scans API Endpoints
===================================
REST endpoints for triggering AST scans, polling scan status, and fetching findings.
"""

import os
from typing import Optional
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Scan, Repository, Vulnerability
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse
from app.schemas.vulnerability import VulnerabilityListResponse, VulnerabilityResponse
from app.scanners.engine import security_scanner
from app.core.exceptions import EntityNotFoundException
from app.core.deps import get_current_user

router = APIRouter()


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED, summary="Trigger Security Scan")
def trigger_scan(payload: ScanCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Triggers an AST security scan against a repository.
    In local demonstration mode, scans the target repository fixture directory.
    """
    repo = db.query(Repository).filter_by(
        id=payload.repository_id, organization_id=current_user.organization_id
    ).first()
    if not repo:
        raise EntityNotFoundException("Repository", payload.repository_id)

    # Resolve target directory to scan for the repository
    import tempfile, subprocess, shutil, logging

    _logger = logging.getLogger("patchforge.api.scans")
    scan_path = None

    if payload.repo_path and os.path.exists(payload.repo_path):
        scan_path = payload.repo_path

    elif repo.clone_url and os.path.exists(repo.clone_url):
        scan_path = repo.clone_url

    elif repo.clone_url and repo.clone_url.startswith(("http://", "https://", "git@")):
        # --- Sanitize URL (guard against any double-prefix corruption) ---
        clone_url = repo.clone_url.strip()
        while "github.com/https://" in clone_url or "github.com/http://" in clone_url:
            clone_url = "https://github.com/" + clone_url.split("github.com/")[-1]
        while clone_url.endswith(".git.git"):
            clone_url = clone_url[:-4]

        # --- Inject the requesting user's own GitHub token for authenticated clone.
        # (Previously this grabbed whichever user in the DB had *any* token, most
        # recently updated - meaning any caller could clone a private repo using a
        # different user's credentials. Now it's scoped to the authenticated caller.) ---
        if current_user.github_token and "github.com/" in clone_url:
            clean_part = clone_url.split("github.com/")[-1].strip("/")
            authenticated_url = f"https://x-access-token:{current_user.github_token}@github.com/{clean_part}"
        else:
            authenticated_url = clone_url

        # --- Resolve git binary (Windows-safe) ---
        import re
        git_bin = shutil.which("git") or r"C:\Program Files\Git\cmd\git.exe"
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", repo.full_name)
        cached_repo_dir = os.path.join(tempfile.gettempdir(), "patchforge_cache", safe_name)
        os.makedirs(os.path.dirname(cached_repo_dir), exist_ok=True)

        # Check if valid cached repository exists on disk
        is_valid_cache = False
        if os.path.exists(cached_repo_dir) and os.path.isdir(os.path.join(cached_repo_dir, ".git")):
            for _, _, fs in os.walk(cached_repo_dir):
                if any(f.endswith((".py", ".pyw", ".js", ".jsx", ".ts", ".tsx")) for f in fs):
                    is_valid_cache = True
                    break

        if is_valid_cache:
            _logger.info(f"Repository cache hit: {cached_repo_dir}. Using cached repo for instant scan.")
            try:
                subprocess.run(
                    [git_bin, "-C", cached_repo_dir, "pull", "--depth", "1"],
                    capture_output=True,
                    timeout=20,
                    text=True,
                    env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"},
                )
            except Exception:
                pass
            scan_path = cached_repo_dir
        else:
            # Clean partial or empty directory before fresh clone
            shutil.rmtree(cached_repo_dir, ignore_errors=True)
            _logger.info(f"Initial clone for repository: {clone_url} → {cached_repo_dir}")
            try:
                subprocess.run(
                    [git_bin, "-c", "http.postBuffer=524288000", "clone", "--depth", "1", "--single-branch", authenticated_url, cached_repo_dir],
                    check=True,
                    capture_output=True,
                    timeout=180,
                    text=True,
                    env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"},
                )  # nosec B603 B607
                _logger.info(f"Clone successful: {cached_repo_dir}")
                scan_path = cached_repo_dir
            except Exception as e:
                _logger.warning(f"Remote clone not available for {clone_url} ({e}). Using target repository fixture.")
                scan_path = "fixtures/vulnerable_javascript" if repo.language.lower() == "javascript" else "fixtures/vulnerable_python"
    else:
        scan_path = "fixtures/vulnerable_javascript" if repo.language.lower() == "javascript" else "fixtures/vulnerable_python"

    if not os.path.exists(scan_path):
        scan_path = "."

    scan = security_scanner.scan_repository(
        db=db,
        repository_id=repo.id,
        commit_hash=payload.commit_hash or "HEAD",
        repo_path=scan_path,
        branch=payload.branch or repo.default_branch or "main",
        triggered_by=payload.triggered_by or "manual",
    )
    return scan


@router.get("", response_model=ScanListResponse, summary="List Scans")
def list_scans(
    repository_id: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists security scans for the caller's own tenant, optionally filtered by repository ID."""
    query = db.query(Scan).join(Repository, Scan.repository_id == Repository.id).filter(
        Repository.organization_id == current_user.organization_id
    )
    if repository_id:
        query = query.filter(Scan.repository_id == repository_id)

    total = query.count()
    items = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    return ScanListResponse(total=total, items=items)


@router.get("/{scan_id}", response_model=ScanResponse, summary="Get Scan Details")
def get_scan(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Retrieves execution status, timestamps, and findings summary for a scan, scoped to the caller's own tenant."""
    scan = (
        db.query(Scan)
        .join(Repository, Scan.repository_id == Repository.id)
        .filter(Scan.id == scan_id, Repository.organization_id == current_user.organization_id)
        .first()
    )
    if not scan:
        raise EntityNotFoundException("Scan", scan_id)
    return scan


@router.get("/{scan_id}/vulnerabilities", response_model=VulnerabilityListResponse, summary="Get Scan Vulnerabilities")
def get_scan_vulnerabilities(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Retrieves all vulnerability findings detected within a specific scan, scoped to the caller's own tenant."""
    scan = (
        db.query(Scan)
        .join(Repository, Scan.repository_id == Repository.id)
        .filter(Scan.id == scan_id, Repository.organization_id == current_user.organization_id)
        .first()
    )
    if not scan:
        raise EntityNotFoundException("Scan", scan_id)

    vulns = db.query(Vulnerability).filter_by(scan_id=scan_id).order_by(Vulnerability.severity.asc()).all()
    return VulnerabilityListResponse(total=len(vulns), items=vulns)
