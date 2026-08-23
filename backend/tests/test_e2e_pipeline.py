"""
PatchForge AI - Phase 18 Full End-to-End Pipeline Integration Test Suite
========================================================================
Validates the complete autonomous DevSecOps pipeline lifecycle:
1. User Authentication (JWT + RBAC)
2. Repository Registration
3. Tree-sitter AST Static Security Scan
4. Isolated Docker Sandbox Dynamic PoC Verification
5. AST-Targeted LLM Patch Generation & 4-Stage Validation
6. GitHub Remediation Pull Request Generation with Scorecard Matrix
"""

import os
import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.vulnerability import VulnerabilityStatus
from app.models.patch import PatchStatus

client = TestClient(app)


def test_complete_autonomous_devsecops_pipeline_e2e(admin_auth_headers):
    """
    Executes an end-to-end integration test across all 6 core subsystems.
    """
    # -------------------------------------------------------------
    # STAGE 1: Authentication & RBAC Access Token
    # -------------------------------------------------------------
    # Elevated roles (needed later for /verify, /validate, /pull-requests/create)
    # are no longer obtainable via public self-registration - registering with
    # role="ADMIN" is now silently ignored and the account lands as DEVELOPER
    # (see test_auth_rbac.py::test_user_registration_and_login_lifecycle). This
    # uses the shared admin_auth_headers fixture, which seeds an ADMIN user
    # directly, the same way a real admin-promotion flow would.
    auth_headers = admin_auth_headers

    # Verify Profile
    me_resp = client.get("/api/v1/auth/me", headers=auth_headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["role"] == "ADMIN"

    # -------------------------------------------------------------
    # STAGE 2: Connect Target Repository
    # -------------------------------------------------------------
    repo_name = f"e2e-payment-service-{uuid.uuid4().hex[:6]}"
    repo_resp = client.post(
        "/api/v1/repositories",
        json={
            "name": repo_name,
            "full_name": f"acme-corp/{repo_name}",
            "url": f"https://github.com/acme-corp/{repo_name}",
            "clone_url": f"https://github.com/acme-corp/{repo_name}.git",
            "language": "python",
        },
        headers=auth_headers,
    )
    assert repo_resp.status_code == 201
    repo_id = repo_resp.json()["id"]

    # -------------------------------------------------------------
    # STAGE 3: Execute AST Security Scan
    # -------------------------------------------------------------
    scan_resp = client.post(
        "/api/v1/scans",
        json={"repository_id": repo_id},
        headers=auth_headers,
    )
    assert scan_resp.status_code == 201
    scan_data = scan_resp.json()
    scan_id = scan_data["id"]
    assert scan_data["status"] == "COMPLETED"

    # Fetch detected vulnerability findings
    vulns_resp = client.get(f"/api/v1/vulnerabilities?scan_id={scan_id}", headers=auth_headers)
    assert vulns_resp.status_code == 200
    vulns_list = vulns_resp.json()["items"]
    assert len(vulns_list) > 0

    # Pick the SQL injection vulnerability (CWE-89)
    sqli_vuln = next((v for v in vulns_list if v["cwe"] == "CWE-89"), vulns_list[0])
    vuln_id = sqli_vuln["id"]

    # -------------------------------------------------------------
    # STAGE 4: Dynamic PoC Exploit Verification in Isolated Sandbox
    # -------------------------------------------------------------
    verify_resp = client.post(
        f"/api/v1/vulnerabilities/{vuln_id}/verify",
        headers=auth_headers,
    )
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["verified"] is True
    assert verify_data["vulnerability_id"] == vuln_id

    # -------------------------------------------------------------
    # STAGE 5: AST-Targeted Patch Generation & Multi-Stage Validation
    # -------------------------------------------------------------
    patch_gen_resp = client.post(
        "/api/v1/patches/generate",
        json={"vulnerability_id": vuln_id},
        headers=auth_headers,
    )
    assert patch_gen_resp.status_code == 201
    patch_data = patch_gen_resp.json()
    patch_id = patch_data["id"]
    assert len(patch_data["diff_content"]) > 0

    # Validate Patch across 4 stages
    val_resp = client.post(
        f"/api/v1/patches/{patch_id}/validate",
        headers=auth_headers,
    )
    assert val_resp.status_code == 200
    validated_patch = val_resp.json()
    assert validated_patch["status"] == PatchStatus.VALIDATED.value
    assert validated_patch["composite_score"] >= 70.0
    assert validated_patch["syntax_valid"] is True
    assert validated_patch["ast_valid"] is True

    # -------------------------------------------------------------
    # STAGE 6: GitHub Remediation Pull Request Generation
    # -------------------------------------------------------------
    pr_resp = client.post(
        "/api/v1/pull-requests/create",
        json={"patch_id": patch_id},
        headers=auth_headers,
    )
    assert pr_resp.status_code == 201
    pr_data = pr_resp.json()
    assert pr_data["status"] == "OPEN"
    assert "patchforge/fix-" in pr_data["branch_name"]
    assert "github.com" in pr_data["pr_url"]
    assert pr_data["pr_number"] > 0
