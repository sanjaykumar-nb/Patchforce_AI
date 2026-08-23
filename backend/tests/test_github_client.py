"""
PatchForge AI - Phase 13 Git & GitHub Pull Request Provider Unit Tests
======================================================================
Validates branch name sanitization, conventional commit formatting,
PR markdown scorecard generation, PR persistence in PostgreSQL, and REST PR endpoints.
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
    PullRequest,
    PRStatus,
)
from app.git.formatter import generate_pr_markdown_description
from app.git.github_client import github_client
from app.remediation import patch_generator
from app.validation import patch_validator

client = TestClient(app)


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    yield db
    db.close()


def test_pr_markdown_description_formatting():
    vuln = Vulnerability(
        cwe="CWE-89",
        rule_id="PY-SQLI-001",
        file_path="app.py",
        function_name="get_user",
        line_start=10,
        line_end=15,
        cvss_score=8.5,
        description="SQL injection vulnerability in user lookup.",
    )
    patch = Patch(
        explanation="Parameterized query.",
        security_reason="Eliminates SQL injection risk.",
        syntax_valid=True,
        ast_valid=True,
        test_pass_rate=1.0,
        rescan_clean=True,
        patch_score=100.0,
        diff_content="--- a/app.py\n+++ b/app.py\n@@ -10,3 +10,3 @@",
    )

    markdown = generate_pr_markdown_description(vuln, patch)

    assert "## 🛡️ PatchForge AI Autonomous Remediation" in markdown
    assert "CWE-89" in markdown
    assert "PY-SQLI-001" in markdown
    assert "100.0 / 100.0" in markdown
    assert "--- a/app.py" in markdown
    assert "Parameterized query." in markdown


def test_github_client_branch_and_commit_formatting():
    branch = github_client.format_branch_name("CWE-89", "get_user_profile", "12345678-abcd")
    assert branch == "patchforge/fix-cwe-89-get-user-profile-12345678"

    commit_msg = github_client.format_commit_message("CWE-89", "app.py", "get_user_profile")
    assert "fix(security): remediate CWE-89 in get_user_profile" in commit_msg

    pr_title = github_client.format_pr_title("CWE-89", "get_user_profile")
    assert "fix(security): remediate CWE-89 vulnerability in `get_user_profile()`" in pr_title


def test_create_remediation_pr_lifecycle(db_session: Session):
    repo = Repository(
        name="pr-repo",
        full_name=f"test-org/pr-repo-{uuid.uuid4().hex[:6]}",
        url="https://github.com/test-org/pr-repo",
        clone_url="https://github.com/test-org/pr-repo.git",
        language="python",
    )
    db_session.add(repo)
    db_session.commit()

    scan = Scan(
        repository_id=repo.id,
        commit_hash="pr123",
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

    # 1. Generate & validate patch
    patch = patch_generator.generate_patch_for_vulnerability(db=db_session, vulnerability=vuln)
    patch_validator.validate_patch(db=db_session, patch=patch)

    # 2. Create PR
    pr = github_client.create_remediation_pr(db=db_session, patch=patch)

    assert pr.id is not None
    assert pr.patch_id == patch.id
    assert pr.repository_id == repo.id
    assert pr.pr_number is not None
    assert "github.com" in pr.pr_url
    assert pr.status == PRStatus.OPEN
    assert patch.status == PatchStatus.PR_CREATED


def test_api_pull_request_endpoints(admin_auth_headers):
    # 1. Register repo
    repo_name = f"test-org/api-pr-{uuid.uuid4().hex[:6]}"
    repo_resp = client.post(
        "/api/v1/repositories",
        json={
            "name": "api-pr",
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
        json={"repository_id": repo_id, "commit_hash": "pr999"},
        headers=admin_auth_headers,
    )
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    # 3. Get first vulnerability
    vulns = client.get(f"/api/v1/scans/{scan_id}/vulnerabilities", headers=admin_auth_headers).json()["items"]
    target_vuln_id = vulns[0]["id"]

    # 4. Generate & validate patch
    gen_resp = client.post("/api/v1/patches/generate", json={"vulnerability_id": target_vuln_id}, headers=admin_auth_headers)
    patch_id = gen_resp.json()["id"]
    client.post(f"/api/v1/patches/{patch_id}/validate", headers=admin_auth_headers)

    # 5. Open Pull Request via API
    pr_resp = client.post(
        "/api/v1/pull-requests/create",
        json={"patch_id": patch_id, "base_branch": "main"},
        headers=admin_auth_headers,
    )
    assert pr_resp.status_code == 201
    pr_data = pr_resp.json()
    pr_id = pr_data["id"]
    assert pr_data["patch_id"] == patch_id
    assert pr_data["status"] == "OPEN"
    assert "patchforge/fix-" in pr_data["branch_name"]

    # 6. Retrieve PR
    get_pr_resp = client.get(f"/api/v1/pull-requests/{pr_id}", headers=admin_auth_headers)
    assert get_pr_resp.status_code == 200
    assert get_pr_resp.json()["id"] == pr_id

    # 7. List PRs
    list_pr_resp = client.get(f"/api/v1/pull-requests?repository_id={repo_id}", headers=admin_auth_headers)
    assert list_pr_resp.status_code == 200
    assert list_pr_resp.json()["total"] >= 1
