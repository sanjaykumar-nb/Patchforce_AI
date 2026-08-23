"""Add missing pull_requests.is_simulated column

Same class of bug as 003_user_oauth_otp_columns: the ORM model has always had
this column, but the initial migration never created it - any SELECT against
pull_requests (even on an empty table) fails because Postgres rejects a query
referencing a column that doesn't exist in the actual table.

Revision ID: 004_pull_request_is_simulated
Revises: 003_user_oauth_otp_columns
Create Date: 2026-08-23 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '004_pull_request_is_simulated'
down_revision: Union[str, None] = '003_user_oauth_otp_columns'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'pull_requests',
        sa.Column('is_simulated', sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    # Drop the server_default after backfilling existing rows - the model's
    # default=False is application-side only, matching every other column here.
    op.alter_column('pull_requests', 'is_simulated', server_default=None)


def downgrade() -> None:
    op.drop_column('pull_requests', 'is_simulated')
