"""Add missing User columns (github_token, github_username, github_avatar_url,
otp_code, otp_expires_at) and relax hashed_password to nullable

The User ORM model has always had these columns, but the initial migration
never created them - so GitHub-login and OTP-login users could never be
persisted, and any query selecting a full User row against a migrated
database would fail with "column does not exist". hashed_password must also
be nullable: GitHub/OTP-only users never set a password.

Revision ID: 003_user_oauth_otp_columns
Revises: 002_scan_repo_path
Create Date: 2026-08-23 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '003_user_oauth_otp_columns'
down_revision: Union[str, None] = '002_scan_repo_path'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column('users', 'hashed_password', existing_type=sa.String(length=255), nullable=True)
    op.add_column('users', sa.Column('github_token', sa.String(length=512), nullable=True))
    op.add_column('users', sa.Column('github_username', sa.String(length=255), nullable=True))
    op.add_column('users', sa.Column('github_avatar_url', sa.String(length=1024), nullable=True))
    op.add_column('users', sa.Column('otp_code', sa.String(length=16), nullable=True))
    op.add_column('users', sa.Column('otp_expires_at', sa.DateTime(timezone=True), nullable=True))
    op.create_index(op.f('ix_users_github_username'), 'users', ['github_username'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_users_github_username'), table_name='users')
    op.drop_column('users', 'otp_expires_at')
    op.drop_column('users', 'otp_code')
    op.drop_column('users', 'github_avatar_url')
    op.drop_column('users', 'github_username')
    op.drop_column('users', 'github_token')
    op.alter_column('users', 'hashed_password', existing_type=sa.String(length=255), nullable=False)
