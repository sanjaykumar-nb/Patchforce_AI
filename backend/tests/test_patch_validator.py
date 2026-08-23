"""
PatchForge AI - Phase 11 Multi-Stage Patch Validator Unit Tests
===============================================================
Validates the 4-stage patch validation pipeline: syntax checks, AST scope preservation,
sandbox PoC neutralization, static security re-scan, composite scoring, and REST validation API.
"""

import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.database import SessionLocal
from app.models import (
    Repository,
    Scan,
    ScanStatus,
    Vulnerability,
    VulnerabilityStatus,
    Patch,
    PatchStatus,
    TestRun,
)
from app.validation import patch_validator
from app.remediation import patch_generator

client = TestClient(app)


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    yield db
    db.close()


def test_validator_stage1_syntax():
    valid_code = "def add(a, b):\n    return a + b\n"
    ok, log = patch_validator.validate_stage1_syntax(valid_code, "python")
    assert ok is True

    broken_code = "def broken(a, b\n    return a"
    bad, log = patch_validator.validate_stage1_syntax(broken_code, "python")
    assert bad is False
    assert "SyntaxError" in log


def test_validator_stage2_ast_integrity():
    orig_code = "def fn1():\n    pass\n\ndef fn2():\n    pass\n"
    good_patched = "def fn1():\n    return 42\n\ndef fn2():\n    pass\n"
    ok, log = patch_validator.validate_stage2_ast_integrity(orig_code, good_patched, "python")
    assert ok is True

    bad_patched = "def fn1():\n    return 42\n"  # Deleted fn2!
    bad, log = patch_validator.validate_stage2_ast_integrity(orig_code, bad_patched, "python")
    assert bad is False
    assert "Missing functions" in log


def test_validator_stage4_security_rescan():
    vuln = Vulnerability(
        cwe="CWE-89",
        rule_id="PY-SQLI-001",
        file_path="fixtures/vulnerable_python/app.py",
    )
    # Parameterized safe code
    safe_code = """
import sqlite3
def get_user_profile(user_id):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()
"""
    clean_ok, log = patch_validator.validate_stage4_security_rescan(vuln, safe_code)
    assert clean_ok is True

    # Still vulnerable code
    vuln_code = """
import sqlite3
def get_user_profile(user_id):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()
"""
    dirty_ok, log = patch_validator.validate_stage4_security_rescan(vuln, vuln_code)
    assert dirty_ok is False


def test_end_to_end_patch_validation(db_session: Session):
    repo = Repository(
        name="val-repo",
        full_name=f"test-org/val-repo-{uuid.uuid4().hex[:6]}",
        url="https://github.com/test-org/val-repo",
        clone_url="https://github.com/test-org/val-repo.git",
        language="python",
    )
    db_session.add(repo)
    db_session.commit()

    scan = Scan(
        repository_id=repo.id,
        commit_hash="val123",
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

    # 1. Generate Patch
    patch = patch_generator.generate_patch_for_vulnerability(db=db_session, vulnerability=vuln)
    assert patch.status == PatchStatus.PENDING_VALIDATION

    # 2. Execute 4-Stage Validation
    report = patch_validator.validate_patch(db=db_session, patch=patch)

    assert report.syntax_valid is True
    assert report.ast_valid is True
    assert report.rescan_clean is True
    assert report.composite_score >= 80.0
    assert report.status == PatchStatus.VALIDATED
    assert patch.status == PatchStatus.VALIDATED

    # Verify TestRun records were created
    test_runs = db_session.query(TestRun).filter_by(patch_id=patch.id).all()
    assert len(test_runs) == 4


def test_api_patch_validation_endpoint(admin_auth_headers):
    # 1. Register repo
    repo_name = f"test-org/api-val-{uuid.uuid4().hex[:6]}"
    repo_resp = client.post(
        "/api/v1/repositories",
        json={
            "name": "api-val",
            "full_name": repo_name,
            "url": f"https://github.com/{repo_name}",
            "clone_url": f"https://github.com/{repo_name}.git",
            "language": "python",
        },
        headers=admin_auth_headers,
    )
    assert repo_resp.status_code == 201
    repo_id = repo_resp.json()["id"]

    # 2. Trigger scan
    scan_resp = client.post(
        "/api/v1/scans",
        json={"repository_id": repo_id, "commit_hash": "val999"},
        headers=admin_auth_headers,
    )
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    # 3. Get first vulnerability
    vulns = client.get(f"/api/v1/scans/{scan_id}/vulnerabilities", headers=admin_auth_headers).json()["items"]
    target_vuln_id = vulns[0]["id"]

    # 4. Generate patch
    gen_resp = client.post("/api/v1/patches/generate", json={"vulnerability_id": target_vuln_id}, headers=admin_auth_headers)
    assert gen_resp.status_code == 201
    patch_id = gen_resp.json()["id"]

    # 5. Validate patch via API
    val_resp = client.post(f"/api/v1/patches/{patch_id}/validate", headers=admin_auth_headers)
    assert val_resp.status_code == 200
    report_data = val_resp.json()

    assert report_data["patch_id"] == patch_id
    assert report_data["syntax_valid"] is True
    assert report_data["composite_score"] >= 80.0
    assert report_data["status"] == "VALIDATED"
