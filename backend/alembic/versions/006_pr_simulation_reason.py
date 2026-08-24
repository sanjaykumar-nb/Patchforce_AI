"""Add pull_requests.simulation_reason

Captures WHY a PR fell back to simulation (no GitHub token linked, no push
access, a specific GitHub API error, etc.) instead of silently returning a
non-functional compare-link PR that looks identical to a real one. This was
reported live: the app showed "PR created" with a link, but no PR existed on
GitHub - the fallback path was firing and nothing surfaced why.

Revision ID: 006_pr_simulation_reason
Revises: 005_multi_tenancy
Create Date: 2026-08-24 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '006_pr_simulation_reason'
down_revision: Union[str, None] = '005_multi_tenancy'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('pull_requests', sa.Column('simulation_reason', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('pull_requests', 'simulation_reason')
