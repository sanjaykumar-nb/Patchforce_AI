"""
PatchForge AI - Phase 12 Celery Background Worker Tasks Unit Tests
==================================================================
Validates Celery app configuration, task routing, asynchronous job execution,
background AST scanning, sandbox PoC verification, and automated patch remediation.
"""

import uuid
import pytest
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import (
    Repository,
    Scan,
    ScanStatus,
    Vulnerability,
    VulnerabilityStatus,
    Patch,
    PatchStatus,
)
from app.worker.celery_app import celery_app
from app.worker.tasks import (
    task_run_security_scan,
    task_verify_vulnerability,
    task_generate_and_validate_patch,
)


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    yield db
    db.close()


def test_celery_app_configuration():
    assert celery_app.main == "patchforge_worker"
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.result_serializer == "json"
    assert celery_app.conf.timezone == "UTC"
    assert celery_app.conf.task_acks_late is True

    routes = celery_app.conf.task_routes
    assert "app.worker.tasks.task_run_security_scan" in routes
    assert routes["app.worker.tasks.task_run_security_scan"]["queue"] == "scans"
    assert routes["app.worker.tasks.task_verify_vulnerability"]["queue"] == "verification"
    assert routes["app.worker.tasks.task_generate_and_validate_patch"]["queue"] == "remediation"


def test_task_run_security_scan(db_session: Session):
    repo = Repository(
        name="worker-scan-repo",
        full_name=f"test-org/worker-scan-{uuid.uuid4().hex[:6]}",
        url="https://github.com/test-org/worker-scan",
        clone_url="https://github.com/test-org/worker-scan.git",
        language="python",
    )
    db_session.add(repo)
    db_session.commit()

    scan = Scan(
        repository_id=repo.id,
        commit_hash="wkr123",
        status=ScanStatus.PENDING,
    )
    db_session.add(scan)
    db_session.commit()

    # Execute task synchronously
    result = task_run_security_scan.apply(args=[scan.id]).get()

    assert result["status"] == "COMPLETED"
    assert result["scan_id"] == scan.id
    assert result["summary"]["vulnerabilities_detected"] >= 4

    db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED


def test_task_verify_vulnerability(db_session: Session):
    repo = Repository(
        name="worker-verify-repo",
        full_name=f"test-org/worker-verify-{uuid.uuid4().hex[:6]}",
        url="https://github.com/test-org/worker-verify",
        clone_url="https://github.com/test-org/worker-verify.git",
        language="python",
    )
    db_session.add(repo)
    db_session.commit()

    scan = Scan(
        repository_id=repo.id,
        commit_hash="wkr456",
        status=ScanStatus.COMPLETED,
    )
    db_session.add(scan)
    db_session.commit()

    vuln = Vulnerability(
        scan_id=scan.id,
        repository_id=repo.id,
        rule_id="PY-SQLI-001",
        cwe="CWE-89",
        file_path="fixtures/vulnerable_python/app.py",
        line_start=20,
        line_end=21,
        function_name="get_user_profile",
        source_snippet='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        description="SQL injection in get_user_profile",
        status=VulnerabilityStatus.DETECTED,
    )
    db_session.add(vuln)
    db_session.commit()
    db_session.refresh(vuln)

    # Execute verification task
    result = task_verify_vulnerability.apply(args=[vuln.id]).get()

    assert result["status"] == "COMPLETED"
    assert result["verified"] is True
    assert result["vuln_status"] == "VERIFIED"


def test_task_generate_and_validate_patch(db_session: Session):
    repo = Repository(
        name="worker-patch-repo",
        full_name=f"test-org/worker-patch-{uuid.uuid4().hex[:6]}",
        url="https://github.com/test-org/worker-patch",
        clone_url="https://github.com/test-org/worker-patch.git",
        language="python",
    )
    db_session.add(repo)
    db_session.commit()

    scan = Scan(
        repository_id=repo.id,
        commit_hash="wkr789",
        status=ScanStatus.COMPLETED,
    )
    db_session.add(scan)
    db_session.commit()

    vuln = Vulnerability(
        scan_id=scan.id,
        repository_id=repo.id,
        rule_id="PY-SQLI-001",
        cwe="CWE-89",
        file_path="fixtures/vulnerable_python/app.py",
        line_start=20,
        line_end=21,
        function_name="get_user_profile",
        source_snippet='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        description="SQL injection in get_user_profile",
        status=VulnerabilityStatus.VERIFIED,
    )
    db_session.add(vuln)
    db_session.commit()
    db_session.refresh(vuln)

    # Execute full background remediation pipeline task
    result = task_generate_and_validate_patch.apply(args=[vuln.id]).get()

    assert result["status"] == "COMPLETED"
    assert result["vulnerability_id"] == vuln.id
    assert "patch_id" in result
    assert result["composite_score"] >= 80.0
    assert result["patch_status"] == "VALIDATED"
    assert result["syntax_valid"] is True
    assert result["ast_valid"] is True
    assert result["rescan_clean"] is True
