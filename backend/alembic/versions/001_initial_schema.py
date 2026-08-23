"""Initial schema migration for PatchForge AI

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-08-20 23:08:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Users
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=True),
        sa.Column('role', sa.Enum('ADMIN', 'SECURITY_ENGINEER', 'DEVELOPER', 'VIEWER', name='userrole'), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_role'), 'users', ['role'], unique=False)
    op.create_index(op.f('ix_users_created_at'), 'users', ['created_at'], unique=False)

    # 2. Repositories
    op.create_table(
        'repositories',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=False),
        sa.Column('url', sa.String(length=512), nullable=False),
        sa.Column('clone_url', sa.String(length=512), nullable=False),
        sa.Column('default_branch', sa.String(length=64), nullable=False),
        sa.Column('language', sa.String(length=64), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('webhook_secret', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_repositories_full_name'), 'repositories', ['full_name'], unique=True)
    op.create_index(op.f('ix_repositories_created_at'), 'repositories', ['created_at'], unique=False)

    # 3. Scans
    op.create_table(
        'scans',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('repository_id', sa.String(length=36), nullable=False),
        sa.Column('commit_hash', sa.String(length=64), nullable=False),
        sa.Column('branch', sa.String(length=64), nullable=False),
        sa.Column('status', sa.Enum('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', name='scanstatus'), nullable=False),
        sa.Column('triggered_by', sa.String(length=64), nullable=False),
        sa.Column('total_files_scanned', sa.Integer(), nullable=False),
        sa.Column('vulnerabilities_count', sa.Integer(), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scans_repository_id'), 'scans', ['repository_id'], unique=False)
    op.create_index(op.f('ix_scans_commit_hash'), 'scans', ['commit_hash'], unique=False)
    op.create_index(op.f('ix_scans_status'), 'scans', ['status'], unique=False)
    op.create_index(op.f('ix_scans_created_at'), 'scans', ['created_at'], unique=False)

    # 4. Vulnerabilities
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('repository_id', sa.String(length=36), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('cwe', sa.String(length=32), nullable=False),
        sa.Column('severity', sa.Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', name='severitylevel'), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('file_path', sa.String(length=512), nullable=False),
        sa.Column('line_start', sa.Integer(), nullable=False),
        sa.Column('line_end', sa.Integer(), nullable=False),
        sa.Column('function_name', sa.String(length=255), nullable=True),
        sa.Column('ast_node_type', sa.String(length=64), nullable=True),
        sa.Column('source_snippet', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('status', sa.Enum('DETECTED', 'VERIFIED', 'PATCH_GENERATING', 'PATCH_GENERATED', 'PATCH_APPROVED', 'REMEDIATED', 'FALSE_POSITIVE', 'IGNORED', name='vulnerabilitystatus'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_vulnerabilities_scan_id'), 'vulnerabilities', ['scan_id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_repository_id'), 'vulnerabilities', ['repository_id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_rule_id'), 'vulnerabilities', ['rule_id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_cwe'), 'vulnerabilities', ['cwe'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_severity'), 'vulnerabilities', ['severity'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_status'), 'vulnerabilities', ['status'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_created_at'), 'vulnerabilities', ['created_at'], unique=False)

    # 5. AST Nodes
    op.create_table(
        'ast_nodes',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('vulnerability_id', sa.String(length=36), nullable=False),
        sa.Column('node_type', sa.String(length=64), nullable=False),
        sa.Column('start_line', sa.Integer(), nullable=False),
        sa.Column('start_column', sa.Integer(), nullable=False),
        sa.Column('end_line', sa.Integer(), nullable=False),
        sa.Column('end_column', sa.Integer(), nullable=False),
        sa.Column('code_snippet', sa.Text(), nullable=False),
        sa.Column('parent_scope', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ast_nodes_vulnerability_id'), 'ast_nodes', ['vulnerability_id'], unique=False)

    # 6. Exploit Verifications
    op.create_table(
        'exploit_verifications',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('vulnerability_id', sa.String(length=36), nullable=False),
        sa.Column('sandbox_container_id', sa.String(length=64), nullable=True),
        sa.Column('verified', sa.Boolean(), nullable=False),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('stdout', sa.Text(), nullable=True),
        sa.Column('stderr', sa.Text(), nullable=True),
        sa.Column('execution_time_ms', sa.Float(), nullable=False),
        sa.Column('poc_summary', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_exploit_verifications_vulnerability_id'), 'exploit_verifications', ['vulnerability_id'], unique=False)
    op.create_index(op.f('ix_exploit_verifications_verified'), 'exploit_verifications', ['verified'], unique=False)

    # 7. Patches
    op.create_table(
        'patches',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('vulnerability_id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('model_name', sa.String(length=64), nullable=False),
        sa.Column('model_version', sa.String(length=64), nullable=True),
        sa.Column('diff_content', sa.Text(), nullable=False),
        sa.Column('old_code', sa.Text(), nullable=False),
        sa.Column('new_code', sa.Text(), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('security_reason', sa.Text(), nullable=False),
        sa.Column('patch_score', sa.Float(), nullable=False),
        sa.Column('syntax_valid', sa.Boolean(), nullable=False),
        sa.Column('ast_valid', sa.Boolean(), nullable=False),
        sa.Column('test_pass_rate', sa.Float(), nullable=False),
        sa.Column('rescan_clean', sa.Boolean(), nullable=False),
        sa.Column('status', sa.Enum('PENDING_VALIDATION', 'VALIDATED', 'REJECTED', 'APPLIED', 'PR_CREATED', name='patchstatus'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_patches_vulnerability_id'), 'patches', ['vulnerability_id'], unique=False)
    op.create_index(op.f('ix_patches_scan_id'), 'patches', ['scan_id'], unique=False)
    op.create_index(op.f('ix_patches_status'), 'patches', ['status'], unique=False)
    op.create_index(op.f('ix_patches_created_at'), 'patches', ['created_at'], unique=False)

    # 8. Test Runs
    op.create_table(
        'test_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('patch_id', sa.String(length=36), nullable=False),
        sa.Column('test_type', sa.String(length=64), nullable=False),
        sa.Column('test_command', sa.String(length=255), nullable=False),
        sa.Column('passed', sa.Boolean(), nullable=False),
        sa.Column('total_tests', sa.Integer(), nullable=False),
        sa.Column('passed_tests', sa.Integer(), nullable=False),
        sa.Column('failed_tests', sa.Integer(), nullable=False),
        sa.Column('stdout', sa.Text(), nullable=True),
        sa.Column('stderr', sa.Text(), nullable=True),
        sa.Column('execution_time_ms', sa.Float(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['patch_id'], ['patches.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_test_runs_patch_id'), 'test_runs', ['patch_id'], unique=False)
    op.create_index(op.f('ix_test_runs_test_type'), 'test_runs', ['test_type'], unique=False)
    op.create_index(op.f('ix_test_runs_passed'), 'test_runs', ['passed'], unique=False)

    # 9. Pull Requests
    op.create_table(
        'pull_requests',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('patch_id', sa.String(length=36), nullable=False),
        sa.Column('repository_id', sa.String(length=36), nullable=False),
        sa.Column('pr_number', sa.Integer(), nullable=True),
        sa.Column('pr_url', sa.String(length=512), nullable=True),
        sa.Column('branch_name', sa.String(length=255), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('status', sa.Enum('OPEN', 'MERGED', 'CLOSED', 'REJECTED', name='prstatus'), nullable=False),
        sa.Column('merged_by', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['patch_id'], ['patches.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('patch_id')
    )
    op.create_index(op.f('ix_pull_requests_repository_id'), 'pull_requests', ['repository_id'], unique=False)
    op.create_index(op.f('ix_pull_requests_pr_number'), 'pull_requests', ['pr_number'], unique=False)
    op.create_index(op.f('ix_pull_requests_status'), 'pull_requests', ['status'], unique=False)

    # 10. Pipeline Runs
    op.create_table(
        'pipeline_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('repository_id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=True),
        sa.Column('commit_hash', sa.String(length=64), nullable=False),
        sa.Column('branch', sa.String(length=64), nullable=False),
        sa.Column('current_state', sa.Enum('RECEIVED', 'CLONING', 'SCANNING', 'VULNERABILITY_FOUND', 'VERIFYING', 'VERIFIED', 'PATCH_GENERATING', 'PATCH_GENERATED', 'VALIDATING', 'TESTING', 'SECURITY_RESCAN', 'PATCH_APPROVED', 'PR_CREATING', 'PR_CREATED', 'COMPLETED', 'FAILED', 'REJECTED', name='pipelinestate'), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_pipeline_runs_repository_id'), 'pipeline_runs', ['repository_id'], unique=False)
    op.create_index(op.f('ix_pipeline_runs_scan_id'), 'pipeline_runs', ['scan_id'], unique=False)
    op.create_index(op.f('ix_pipeline_runs_commit_hash'), 'pipeline_runs', ['commit_hash'], unique=False)
    op.create_index(op.f('ix_pipeline_runs_current_state'), 'pipeline_runs', ['current_state'], unique=False)

    # 11. Audit Logs
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('actor', sa.String(length=255), nullable=False),
        sa.Column('repository_id', sa.String(length=36), nullable=True),
        sa.Column('pipeline_run_id', sa.String(length=36), nullable=True),
        sa.Column('vulnerability_id', sa.String(length=36), nullable=True),
        sa.Column('patch_id', sa.String(length=36), nullable=True),
        sa.Column('details', sa.Text(), nullable=False),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['patch_id'], ['patches.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['pipeline_run_id'], ['pipeline_runs.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_event_type'), 'audit_logs', ['event_type'], unique=False)
    op.create_index(op.f('ix_audit_logs_actor'), 'audit_logs', ['actor'], unique=False)
    op.create_index(op.f('ix_audit_logs_repository_id'), 'audit_logs', ['repository_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_created_at'), 'audit_logs', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('pipeline_runs')
    op.drop_table('pull_requests')
    op.drop_table('test_runs')
    op.drop_table('patches')
    op.drop_table('exploit_verifications')
    op.drop_table('ast_nodes')
    op.drop_table('vulnerabilities')
    op.drop_table('scans')
    op.drop_table('repositories')
    op.drop_table('users')
