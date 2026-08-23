"""Add scans.repo_path so patch generation/validation can re-locate scanned source files

Revision ID: 002_scan_repo_path
Revises: 001_initial_schema
Create Date: 2026-08-23 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '002_scan_repo_path'
down_revision: Union[str, None] = '001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('repo_path', sa.String(length=1024), nullable=True))


def downgrade() -> None:
    op.drop_column('scans', 'repo_path')
