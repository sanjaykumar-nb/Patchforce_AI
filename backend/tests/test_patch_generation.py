"""
PatchForge AI - Phase 10 AST Patch Generator Unit Tests
=======================================================
Validates precision AST function splicing, import deduplication, unified diff creation,
autonomous patch generation via Code LLM, and REST patch endpoints.
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
)
from app.remediation import (
    generate_unified_diff,
    merge_imports,
    splice_function_replacement,
    patch_generator,
)

client = TestClient(app)


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    yield db
    db.close()


def test_diff_utils_unified_diff():
    orig = "def foo():\n    return 'bad'\n"
    patched = "def foo():\n    return 'safe'\n"
    diff = generate_unified_diff(orig, patched, "foo.py")

    assert "--- a/foo.py" in diff
    assert "+++ b/foo.py" in diff
    assert "-    return 'bad'" in diff
    assert "+    return 'safe'" in diff


def test_diff_utils_merge_imports():
    code = "import os\n\ndef run():\n    pass\n"
    merged = merge_imports(code, ["import subprocess", "import os"], language="python")

    assert "import subprocess" in merged
    assert merged.count("import os") == 1  # No duplicate


def test_diff_utils_splice_function():
    full_source = """import os

def helper():
    return 1

def vulnerable_fn(x):
    query = "SELECT " + x
    return query

def other():
    return 2
"""
    old_fn = """def vulnerable_fn(x):
    query = "SELECT " + x
    return query"""

    new_fn = """def vulnerable_fn(x):
    return execute_safe(x)"""

    spliced = splice_function_replacement(full_source, old_fn, new_fn)

    assert "execute_safe(x)" in spliced
    assert "SELECT " not in spliced
    assert "def other():" in spliced
    assert "def helper():" in spliced


def test_patch_generator_for_sqli(db_session: Session):
    repo = Repository(
        name="patch-repo",
        full_name=f"test-org/patch-repo-{uuid.uuid4().hex[:6]}",
        url="https://github.com/test-org/patch-repo",
        clone_url="https://github.com/test-org/patch-repo.git",
        language="python",
    )
    db_session.add(repo)
    db_session.commit()

    scan = Scan(
        repository_id=repo.id,
        commit_hash="abc999",
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

    # Generate patch
    patch = patch_generator.generate_patch_for_vulnerability(db=db_session, vulnerability=vuln)

    assert patch.id is not None
    assert patch.vulnerability_id == vuln.id
    assert patch.diff_content != ""
    assert "--- a/fixtures/vulnerable_python/app.py" in patch.diff_content
    assert patch.status == PatchStatus.PENDING_VALIDATION
    assert vuln.status == VulnerabilityStatus.PATCH_GENERATED


def test_api_patch_lifecycle(admin_auth_headers):
    # 1. Register repository
    repo_name = f"test-org/api-patch-{uuid.uuid4().hex[:6]}"
    repo_resp = client.post(
        "/api/v1/repositories",
        json={
            "name": "api-patch",
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
            "commit_hash": "f00baa",
        },
        headers=admin_auth_headers,
    )
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    # 3. Get first vulnerability
    vulns_resp = client.get(f"/api/v1/scans/{scan_id}/vulnerabilities", headers=admin_auth_headers)
    assert vulns_resp.status_code == 200
    vulns = vulns_resp.json()["items"]
    assert len(vulns) >= 1
    target_vuln_id = vulns[0]["id"]

    # 4. Request patch generation via API
    gen_resp = client.post(
        "/api/v1/patches/generate",
        json={"vulnerability_id": target_vuln_id},
        headers=admin_auth_headers,
    )
    assert gen_resp.status_code == 201
    patch_data = gen_resp.json()
    patch_id = patch_data["id"]
    assert patch_data["vulnerability_id"] == target_vuln_id
    assert "diff_content" in patch_data
    assert patch_data["status"] == "PENDING_VALIDATION"

    # 5. Retrieve patch details
    get_patch_resp = client.get(f"/api/v1/patches/{patch_id}", headers=admin_auth_headers)
    assert get_patch_resp.status_code == 200
    assert get_patch_resp.json()["id"] == patch_id

    # 6. List patches
    list_patches_resp = client.get(f"/api/v1/patches?vulnerability_id={target_vuln_id}", headers=admin_auth_headers)
    assert list_patches_resp.status_code == 200
    assert list_patches_resp.json()["total"] >= 1
