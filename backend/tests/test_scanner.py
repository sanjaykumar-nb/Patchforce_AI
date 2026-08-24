"""
PatchForge AI - Phase 6 Security Scanner & API Integration Tests
================================================================
Validates file scanning, directory scanning, repository scanning persistence,
and all OpenAPI REST endpoints for repositories, scans, and vulnerabilities.
"""

import os
import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.scanners.engine import SecurityScanner

client = TestClient(app)


def test_scanner_python_vulnerable_file():
    scanner = SecurityScanner()
    findings = scanner.scan_file("fixtures/vulnerable_python/app.py")
    assert len(findings) == 4

    rule_ids = [f.rule_id for f in findings]
    assert "PY-SQLI-001" in rule_ids
    assert "PY-CMDI-001" in rule_ids
    assert "PY-PATH-001" in rule_ids
    assert "PY-DESER-001" in rule_ids


def test_scanner_python_safe_file_zero_false_positives():
    scanner = SecurityScanner()
    findings = scanner.scan_file("fixtures/vulnerable_python/safe_app.py")
    assert len(findings) == 0


def test_scanner_javascript_vulnerable_file():
    scanner = SecurityScanner()
    findings = scanner.scan_file("fixtures/vulnerable_javascript/app.js")
    assert len(findings) == 3

    rule_ids = [f.rule_id for f in findings]
    assert "JS-SQLI-001" in rule_ids
    assert "JS-CMDI-001" in rule_ids
    assert "JS-PATH-001" in rule_ids


def test_scanner_directory_scan():
    scanner = SecurityScanner()
    findings, total_files = scanner.scan_directory("fixtures/vulnerable_python")
    assert total_files >= 2
    assert len(findings) == 4  # 4 from app.py, 0 from safe_app.py


def test_e2e_api_repository_and_scan_lifecycle(admin_auth_headers):
    # 1. Register repository
    repo_name = f"test-org/api-scan-repo-{uuid.uuid4().hex[:6]}"
    create_repo_resp = client.post(
        "/api/v1/repositories",
        json={
            "name": "api-scan-repo",
            "full_name": repo_name,
            "url": f"https://github.com/{repo_name}",
            "clone_url": f"https://github.com/{repo_name}.git",
            "default_branch": "main",
            "language": "python",
        },
        headers=admin_auth_headers,
    )
    assert create_repo_resp.status_code == 201
    repo_data = create_repo_resp.json()
    repo_id = repo_data["id"]

    # 2. List repositories
    list_repos_resp = client.get("/api/v1/repositories", headers=admin_auth_headers)
    assert list_repos_resp.status_code == 200
    assert list_repos_resp.json()["total"] >= 1

    # 3. Trigger AST Security Scan
    scan_resp = client.post(
        "/api/v1/scans",
        json={
            "repository_id": repo_id,
            "commit_hash": "e1f2a3b4c5d6",
            "branch": "main",
            "triggered_by": "api_test",
        },
        headers=admin_auth_headers,
    )
    assert scan_resp.status_code == 202
    scan_id = scan_resp.json()["id"]
    # Scans run in a background task now (202 PENDING returned immediately) -
    # TestClient waits out the whole ASGI cycle including background tasks,
    # so a fresh GET already reflects the finished scan.
    scan_data = client.get(f"/api/v1/scans/{scan_id}", headers=admin_auth_headers).json()
    assert scan_data["status"] == "COMPLETED"
    assert scan_data["vulnerabilities_count"] >= 1

    # 4. Get scan details
    get_scan_resp = client.get(f"/api/v1/scans/{scan_id}", headers=admin_auth_headers)
    assert get_scan_resp.status_code == 200
    assert get_scan_resp.json()["id"] == scan_id

    # 5. Get scan vulnerabilities
    scan_vulns_resp = client.get(f"/api/v1/scans/{scan_id}/vulnerabilities", headers=admin_auth_headers)
    assert scan_vulns_resp.status_code == 200
    vulns_data = scan_vulns_resp.json()
    assert vulns_data["total"] >= 1
    first_vuln_id = vulns_data["items"][0]["id"]

    # 6. Get single vulnerability with AST node details
    get_vuln_resp = client.get(f"/api/v1/vulnerabilities/{first_vuln_id}", headers=admin_auth_headers)
    assert get_vuln_resp.status_code == 200
    vuln_detail = get_vuln_resp.json()
    assert vuln_detail["id"] == first_vuln_id
    assert len(vuln_detail["ast_nodes"]) >= 1

    # 7. Filter vulnerabilities endpoint
    filter_vulns_resp = client.get(f"/api/v1/vulnerabilities?repository_id={repo_id}&cwe=CWE-89", headers=admin_auth_headers)
    assert filter_vulns_resp.status_code == 200
    for item in filter_vulns_resp.json()["items"]:
        assert item["cwe"] == "CWE-89"
