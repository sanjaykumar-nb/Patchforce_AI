"""
PatchForge AI - Phase 8 Dynamic PoC Verification Unit Tests
===========================================================
Validates safe PoC generation, sandbox execution, true-positive confirmation
on vulnerable fixtures, false-positive rejection on safe fixtures, and REST verification APIs.
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
    ExploitVerification,
)
from app.verification import poc_generator, exploit_verifier

client = TestClient(app)


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    yield db
    db.close()


def test_poc_generator_cwe_templates():
    # CWE-89 SQLi
    py_sqli = poc_generator.generate_python_poc("CWE-89", "app.py", "get_user_profile")
    assert "run_poc.py" in py_sqli
    assert "999 OR 1=1" in py_sqli["run_poc.py"]

    # CWE-78 CMDi
    py_cmdi = poc_generator.generate_python_poc("CWE-78", "app.py", "ping_server")
    assert "run_poc.py" in py_cmdi
    assert "PATCHFORGE_POC_CONFIRMED_CMDI_78" in py_cmdi["run_poc.py"]

    # CWE-22 Path Traversal
    py_path = poc_generator.generate_python_poc("CWE-22", "app.py", "read_user_file")
    assert "run_poc.py" in py_path
    assert "SECRET_BOUNDARY_TOKEN_CWE_22" in py_path["run_poc.py"]

    # CWE-502 Deserialization
    py_deser = poc_generator.generate_python_poc("CWE-502", "app.py", "load_cached_session")
    assert "run_poc.py" in py_deser
    assert "PATCHFORGE_DESERIALIZATION_TRIGGERED" in py_deser["run_poc.py"]


def test_exploit_verifier_confirms_vulnerable_python_fixture(db_session: Session):
    # 1. Create dummy repository & scan
    repo = Repository(
        name="test-vuln-app",
        full_name=f"test-org/vuln-app-{uuid.uuid4().hex[:6]}",
        url="https://github.com/test-org/vuln-app",
        clone_url="https://github.com/test-org/vuln-app.git",
        language="python",
    )
    db_session.add(repo)
    db_session.commit()

    scan = Scan(
        repository_id=repo.id,
        commit_hash="abc1234",
        status=ScanStatus.COMPLETED,
    )
    db_session.add(scan)
    db_session.commit()

    # 2. Add CWE-89 vulnerability pointing to vulnerable fixture
    vuln = Vulnerability(
        scan_id=scan.id,
        repository_id=repo.id,
        rule_id="PY-SQLI-001",
        cwe="CWE-89",
        file_path="fixtures/vulnerable_python/app.py",
        line_start=13,
        line_end=15,
        function_name="get_user_profile",
        source_snippet='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        description="SQL injection in get_user_profile",
        status=VulnerabilityStatus.DETECTED,
    )
    db_session.add(vuln)
    db_session.commit()
    db_session.refresh(vuln)

    # 3. Run verification
    verification = exploit_verifier.verify_vulnerability(db=db_session, vulnerability=vuln)

    assert verification.verified is True
    assert verification.exit_code == 0
    assert "[PATCHFORGE_POC_CONFIRMED]" in verification.stdout
    assert vuln.status == VulnerabilityStatus.VERIFIED


def test_exploit_verifier_rejects_safe_python_fixture(db_session: Session):
    repo = Repository(
        name="test-safe-app",
        full_name=f"test-org/safe-app-{uuid.uuid4().hex[:6]}",
        url="https://github.com/test-org/safe-app",
        clone_url="https://github.com/test-org/safe-app.git",
        language="python",
    )
    db_session.add(repo)
    db_session.commit()

    scan = Scan(
        repository_id=repo.id,
        commit_hash="safe1234",
        status=ScanStatus.COMPLETED,
    )
    db_session.add(scan)
    db_session.commit()

    vuln = Vulnerability(
        scan_id=scan.id,
        repository_id=repo.id,
        rule_id="PY-SQLI-001",
        cwe="CWE-89",
        file_path="fixtures/vulnerable_python/safe_app.py",
        line_start=13,
        line_end=15,
        function_name="get_user_profile",
        source_snippet='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        description="Parameterized SQL",
        status=VulnerabilityStatus.DETECTED,
    )
    db_session.add(vuln)
    db_session.commit()
    db_session.refresh(vuln)

    # Run verification against safe code
    with open("fixtures/vulnerable_python/safe_app.py", "r", encoding="utf-8") as f:
        safe_code = f.read()

    verification = exploit_verifier.verify_vulnerability(
        db=db_session,
        vulnerability=vuln,
        source_code_override=safe_code,
    )

    # Parameterized query should NOT return records for "999 OR 1=1"
    assert verification.verified is False
    assert "[PATCHFORGE_POC_CONFIRMED]" not in verification.stdout


def test_api_verify_vulnerability_endpoint(admin_auth_headers):
    # 1. Register repository
    repo_name = f"test-org/api-verify-{uuid.uuid4().hex[:6]}"
    repo_resp = client.post(
        "/api/v1/repositories",
        json={
            "name": "api-verify",
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
        json={
            "repository_id": repo_id,
            "commit_hash": "c0ffee",
        },
        headers=admin_auth_headers,
    )
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    # 3. Get vulnerabilities
    vulns_resp = client.get(f"/api/v1/scans/{scan_id}/vulnerabilities", headers=admin_auth_headers)
    assert vulns_resp.status_code == 200
    vulns = vulns_resp.json()["items"]
    assert len(vulns) >= 1
    target_vuln_id = vulns[0]["id"]

    # 4. Trigger dynamic PoC verification via API
    verify_resp = client.post(f"/api/v1/vulnerabilities/{target_vuln_id}/verify", headers=admin_auth_headers)
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert "verified" in verify_data
    assert verify_data["vulnerability_id"] == target_vuln_id
    assert verify_data["execution_time_ms"] > 0
