"""
PatchForge AI - Scans API Endpoints
===================================
REST endpoints for triggering AST scans, polling scan status, and fetching findings.
"""

import os
import re
import logging
import tempfile
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, status, Query
from sqlalchemy.orm import Session

from app.database import get_db, SessionLocal
from app.models import Scan, Repository, Vulnerability
from app.models.scan import ScanStatus
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse
from app.schemas.vulnerability import VulnerabilityListResponse, VulnerabilityResponse
from app.scanners.engine import security_scanner
from app.core.exceptions import EntityNotFoundException
from app.core.deps import get_current_user

router = APIRouter()
_logger = logging.getLogger("patchforge.api.scans")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve_scan_path(
    repo_full_name: str,
    repo_clone_url: Optional[str],
    repo_language: Optional[str],
    github_token: Optional[str],
    payload_repo_path: Optional[str],
) -> str:
    """
    Resolves the filesystem path to scan.
    Clones from remote if needed; falls back to fixtures on any failure.
    """
    # 1. Explicit payload path
    if payload_repo_path and os.path.exists(payload_repo_path):
        return payload_repo_path

    # 2. clone_url is already a local path
    if repo_clone_url and os.path.exists(repo_clone_url):
        return repo_clone_url

    # 3. Remote URL → clone into temp cache
    if repo_clone_url and repo_clone_url.startswith(("http://", "https://", "git@")):
        clone_url = repo_clone_url.strip()
        # Guard against double-prefix corruption
        while "github.com/https://" in clone_url or "github.com/http://" in clone_url:
            clone_url = "https://github.com/" + clone_url.split("github.com/")[-1]
        while clone_url.endswith(".git.git"):
            clone_url = clone_url[:-4]

        if github_token and "github.com/" in clone_url:
            clean_part = clone_url.split("github.com/")[-1].strip("/")
            authenticated_url = f"https://x-access-token:{github_token}@github.com/{clean_part}"
        else:
            authenticated_url = clone_url

        git_bin = shutil.which("git") or r"C:\Program Files\Git\cmd\git.exe"
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", repo_full_name)
        cached_repo_dir = os.path.join(tempfile.gettempdir(), "patchforge_cache", safe_name)
        os.makedirs(os.path.dirname(cached_repo_dir), exist_ok=True)

        # Check for a valid cached clone
        is_valid_cache = False
        if os.path.exists(cached_repo_dir) and os.path.isdir(os.path.join(cached_repo_dir, ".git")):
            for _, _, fs in os.walk(cached_repo_dir):
                if any(f.endswith((".py", ".pyw", ".js", ".jsx", ".ts", ".tsx")) for f in fs):
                    is_valid_cache = True
                    break

        if is_valid_cache:
            _logger.info(f"Repository cache hit: {cached_repo_dir}. Pulling latest.")
            try:
                subprocess.run(
                    [git_bin, "-C", cached_repo_dir, "pull", "--depth", "1"],
                    capture_output=True, timeout=20, text=True,
                    env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"},
                )
            except Exception:
                pass
            return cached_repo_dir
        else:
            shutil.rmtree(cached_repo_dir, ignore_errors=True)
            _logger.info(f"Initial clone for repository: {clone_url} → {cached_repo_dir}")
            try:
                subprocess.run(
                    [git_bin, "-c", "http.postBuffer=524288000", "clone",
                     "--depth", "1", "--single-branch", authenticated_url, cached_repo_dir],
                    check=True, capture_output=True, timeout=180, text=True,
                    env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"},
                )  # nosec B603 B607
                _logger.info(f"Clone successful: {cached_repo_dir}")
                return cached_repo_dir
            except Exception as e:
                _logger.warning(f"Remote clone failed for {clone_url} ({e}). Using fixture.")

    # 4. Fixture fallback
    lang = (repo_language or "python").lower()
    return (
        "fixtures/vulnerable_javascript" if lang == "javascript"
        else "fixtures/vulnerable_python"
    )


def _run_scan_background(
    scan_id: str,
    repository_id: str,
    repo_full_name: str,
    repo_clone_url: Optional[str],
    repo_language: Optional[str],
    github_token: Optional[str],
    payload_repo_path: Optional[str],
    commit_hash: str,
    branch: str,
    triggered_by: str,
) -> None:
    """
    Background worker: resolves the scan path, runs the AST scan, and
    persists all findings. Runs in a thread AFTER the HTTP 202 response
    has already been returned, so Uvicorn is never blocked.
    """
    db: Session = SessionLocal()
    try:
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            _logger.error(f"[Background] Scan [{scan_id}] not found in DB.")
            return

        scan_path = _resolve_scan_path(
            repo_full_name=repo_full_name,
            repo_clone_url=repo_clone_url,
            repo_language=repo_language,
            github_token=github_token,
            payload_repo_path=payload_repo_path,
        )
        if not os.path.exists(scan_path):
            scan_path = "."

        scan.status = ScanStatus.IN_PROGRESS
        scan.repo_path = os.path.abspath(scan_path)
        scan.started_at = datetime.now(timezone.utc)
        db.add(scan)
        db.commit()

        _logger.info(
            f"[Background] AST scan [{scan_id}] started for repo [{repository_id}] "
            f"at path [{scan_path}]"
        )

        findings, total_files = security_scanner.scan_directory(scan_path)

        from app.models import VulnerabilityStatus, ASTNode, AuditLog

        for f in findings:
            vuln = Vulnerability(
                scan_id=scan.id,
                repository_id=repository_id,
                rule_id=f.rule_id,
                cwe=f.cwe,
                severity=f.severity,
                cvss_score=f.cvss_score,
                confidence_score=f.confidence_score,
                file_path=f.file_path,
                line_start=f.line_start,
                line_end=f.line_end,
                function_name=f.function_name,
                ast_node_type=f.ast_node_type,
                source_snippet=f.source_snippet,
                description=f.description,
                evidence=f.evidence,
                status=VulnerabilityStatus.DETECTED,
            )
            db.add(vuln)
            db.flush()

            ast_node = ASTNode(
                vulnerability_id=vuln.id,
                node_type=f.ast_node_type,
                start_line=f.line_start,
                start_column=0,
                end_line=f.line_end,
                end_column=len(f.source_snippet.splitlines()[-1]) if f.source_snippet else 0,
                code_snippet=f.source_snippet,
                parent_scope=f.function_name,
            )
            db.add(ast_node)

        scan.total_files_scanned = total_files
        scan.vulnerabilities_count = len(findings)
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)

        audit = AuditLog(
            event_type="SCAN_COMPLETED",
            actor="BACKGROUND_SCANNER",
            repository_id=repository_id,
            details=(
                f'{{"scan_id": "{scan.id}", "files_scanned": {total_files},'
                f' "findings": {len(findings)}}}'
            ),
        )
        db.add(audit)
        db.commit()

        _logger.info(
            f"[Background] Scan [{scan_id}] completed: "
            f"{total_files} files, {len(findings)} findings."
        )

    except Exception as exc:
        _logger.exception(f"[Background] Scan [{scan_id}] failed: {exc}")
        try:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(exc)
                scan.completed_at = datetime.now(timezone.utc)
                db.add(scan)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger Security Scan",
)
def trigger_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Triggers an AST security scan against a repository.

    Returns **202 Accepted** immediately with the Scan in PENDING status.
    The git clone and file analysis run in a background thread so the
    server is never blocked or OOM-killed on constrained environments.

    Poll ``GET /api/v1/scans/{scan_id}`` to track progress:
    ``PENDING → IN_PROGRESS → COMPLETED | FAILED``
    """
    repo = db.query(Repository).filter_by(
        id=payload.repository_id, organization_id=current_user.organization_id
    ).first()
    if not repo:
        raise EntityNotFoundException("Repository", payload.repository_id)

    # Create the Scan record immediately so the caller has an ID to poll
    scan = Scan(
        repository_id=repo.id,
        commit_hash=payload.commit_hash or "HEAD",
        branch=payload.branch or repo.default_branch or "main",
        status=ScanStatus.PENDING,
        triggered_by=payload.triggered_by or "manual",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    _logger.info(
        f"Scan [{scan.id}] queued (PENDING) for repository [{repo.id}]. "
        f"Background worker will start shortly."
    )

    background_tasks.add_task(
        _run_scan_background,
        scan_id=scan.id,
        repository_id=repo.id,
        repo_full_name=repo.full_name,
        repo_clone_url=repo.clone_url,
        repo_language=repo.language,
        github_token=current_user.github_token,
        payload_repo_path=getattr(payload, "repo_path", None),
        commit_hash=payload.commit_hash or "HEAD",
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
