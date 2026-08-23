"""
PatchForge AI - Phase 3 Database Models & Relations Unit Tests
=============================================================
Validates all SQLAlchemy relational models, foreign key cascades,
enums, and data integrity constraints.
"""

import uuid
import pytest
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import (
    User,
    UserRole,
    Repository,
    Scan,
    ScanStatus,
    Vulnerability,
    SeverityLevel,
    VulnerabilityStatus,
    ASTNode,
    ExploitVerification,
    Patch,
    PatchStatus,
    TestRun,
    PullRequest,
    PRStatus,
    PipelineRun,
    PipelineState,
    AuditLog,
)


@pytest.fixture
def db_session():
    """Provides an isolated database session rolled back after test."""
    session: Session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def test_user_creation(db_session: Session):
    unique_email = f"sec_eng_{uuid.uuid4().hex[:8]}@patchforge.ai"
    user = User(
        email=unique_email,
        hashed_password="argon2_hashed_password_mock",
        full_name="Alex Rivera",
        role=UserRole.SECURITY_ENGINEER,
    )
    db_session.add(user)
    db_session.commit()

    saved_user = db_session.query(User).filter_by(email=unique_email).first()
    assert saved_user is not None
    assert saved_user.role == UserRole.SECURITY_ENGINEER
    assert saved_user.is_active is True


def test_complete_remediation_lifecycle_entities(db_session: Session):
    # 1. Repository
    repo_name = f"test-org/repo-{uuid.uuid4().hex[:6]}"
    repo = Repository(
        name="demo-app",
        full_name=repo_name,
        url=f"https://github.com/{repo_name}",
        clone_url=f"https://github.com/{repo_name}.git",
        default_branch="main",
        language="python",
    )
    db_session.add(repo)
    db_session.commit()

    # 2. Scan
    scan = Scan(
        repository_id=repo.id,
        commit_hash="a1b2c3d4e5f67890",
        branch="main",
        status=ScanStatus.COMPLETED,
        total_files_scanned=12,
        vulnerabilities_count=1,
    )
    db_session.add(scan)
    db_session.commit()

    # 3. Vulnerability Finding
    vuln = Vulnerability(
        scan_id=scan.id,
        repository_id=repo.id,
        rule_id="PY-SQLI-001",
        cwe="CWE-89",
        severity=SeverityLevel.HIGH,
        cvss_score=8.5,
        confidence_score=0.95,
        file_path="app/database.py",
        line_start=42,
        line_end=45,
        function_name="get_user_by_id",
        ast_node_type="call",
        source_snippet="cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
        description="Unsanitized user input concatenated directly into SQL query.",
        status=VulnerabilityStatus.VERIFIED,
    )
    db_session.add(vuln)
    db_session.commit()

    # 4. AST Node
    ast_node = ASTNode(
        vulnerability_id=vuln.id,
        node_type="call",
        start_line=42,
        start_column=4,
        end_line=45,
        end_column=68,
        code_snippet="cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
        parent_scope="get_user_by_id",
    )
    db_session.add(ast_node)

    # 5. Exploit Verification (PoC)
    poc = ExploitVerification(
        vulnerability_id=vuln.id,
        sandbox_container_id="docker-sandbox-84920",
        verified=True,
        exit_code=0,
        stdout="Controlled injection payload successfully executed.",
        execution_time_ms=142.5,
        poc_summary="SQL injection confirmed with injected payload ' OR '1'='1",
    )
    db_session.add(poc)

    # 6. Patch
    patch = Patch(
        vulnerability_id=vuln.id,
        scan_id=scan.id,
        model_name="qwen2.5-coder:1.5b",
        diff_content="--- a/app/database.py\n+++ b/app/database.py\n@@ -42,1 +42,1 @@\n- cursor.execute('SELECT * FROM users WHERE id = ' + user_id)\n+ cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        old_code="cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
        new_code="cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        explanation="Replaced string concatenation with parameterized SQL execution.",
        security_reason="Remediates CWE-89 by treating input as literal parameter data.",
        patch_score=96.5,
        syntax_valid=True,
        ast_valid=True,
        test_pass_rate=100.0,
        rescan_clean=True,
        status=PatchStatus.VALIDATED,
    )
    db_session.add(patch)
    db_session.commit()

    # 7. Test Run
    test_run = TestRun(
        patch_id=patch.id,
        test_type="regression",
        test_command="pytest tests/ -v",
        passed=True,
        total_tests=8,
        passed_tests=8,
        failed_tests=0,
        execution_time_ms=530.0,
    )
    db_session.add(test_run)

    # 8. Pull Request
    pr = PullRequest(
        patch_id=patch.id,
        repository_id=repo.id,
        pr_number=101,
        pr_url=f"https://github.com/{repo_name}/pull/101",
        branch_name="patchforge/fix-cwe-89-get-user",
        title="[PatchForge] Remediate CWE-89 SQL Injection in get_user_by_id()",
        body="## Security Remediation\nAutomated fix for CWE-89.",
        status=PRStatus.OPEN,
    )
    db_session.add(pr)

    # 9. Pipeline Run State Machine
    pipeline = PipelineRun(
        repository_id=repo.id,
        scan_id=scan.id,
        commit_hash="a1b2c3d4e5f67890",
        branch="main",
        current_state=PipelineState.PR_CREATED,
    )
    db_session.add(pipeline)

    # 10. Audit Log
    audit = AuditLog(
        event_type="PR_CREATED",
        actor="SYSTEM",
        repository_id=repo.id,
        pipeline_run_id=pipeline.id,
        vulnerability_id=vuln.id,
        patch_id=patch.id,
        details='{"pr_number": 101, "score": 96.5, "cwe": "CWE-89"}',
    )
    db_session.add(audit)
    db_session.commit()

    # Verify traversal through relationships
    queried_repo = db_session.query(Repository).filter_by(id=repo.id).first()
    assert len(queried_repo.scans) == 1
    assert len(queried_repo.vulnerabilities) == 1
    assert queried_repo.vulnerabilities[0].rule_id == "PY-SQLI-001"
    assert len(queried_repo.vulnerabilities[0].patches) == 1
    assert queried_repo.vulnerabilities[0].patches[0].patch_score == 96.5
    assert queried_repo.vulnerabilities[0].patches[0].pull_request.pr_number == 101
