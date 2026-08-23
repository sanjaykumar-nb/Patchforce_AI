"""Add multi-tenancy: organizations table + organization_id on users/repositories

Introduces the Organization entity as the tenant-isolation boundary. Existing
rows are left with organization_id = NULL (they predate multi-tenancy and are
only ever reachable directly by primary key, e.g. via Alembic/DBA tooling -
every user-facing query path is scoped through the authenticated caller's own
organization_id from here on). repositories.full_name's uniqueness moves from
global to per-organization, since two tenants may legitimately track the same
upstream repo.

Revision ID: 005_multi_tenancy
Revises: 004_pull_request_is_simulated
Create Date: 2026-08-23 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '005_multi_tenancy'
down_revision: Union[str, None] = '004_pull_request_is_simulated'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'organizations',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f('ix_organizations_slug'), 'organizations', ['slug'], unique=True)
    op.create_index(op.f('ix_organizations_created_at'), 'organizations', ['created_at'], unique=False)

    op.add_column('users', sa.Column('organization_id', sa.String(length=36), nullable=True))
    op.create_index(op.f('ix_users_organization_id'), 'users', ['organization_id'], unique=False)
    op.create_foreign_key(
        'fk_users_organization_id', 'users', 'organizations',
        ['organization_id'], ['id'], ondelete='SET NULL',
    )

    op.add_column('repositories', sa.Column('organization_id', sa.String(length=36), nullable=True))
    op.create_index(op.f('ix_repositories_organization_id'), 'repositories', ['organization_id'], unique=False)
    op.create_foreign_key(
        'fk_repositories_organization_id', 'repositories', 'organizations',
        ['organization_id'], ['id'], ondelete='CASCADE',
    )

    # full_name uniqueness becomes per-tenant instead of global.
    op.drop_index('ix_repositories_full_name', table_name='repositories')
    op.create_index(op.f('ix_repositories_full_name'), 'repositories', ['full_name'], unique=False)
    op.create_unique_constraint(
        'uq_repository_org_full_name', 'repositories', ['organization_id', 'full_name'],
    )


def downgrade() -> None:
    op.drop_constraint('uq_repository_org_full_name', 'repositories', type_='unique')
    op.drop_index(op.f('ix_repositories_full_name'), table_name='repositories')
    op.create_index('ix_repositories_full_name', 'repositories', ['full_name'], unique=True)

    op.drop_constraint('fk_repositories_organization_id', 'repositories', type_='foreignkey')
    op.drop_index(op.f('ix_repositories_organization_id'), table_name='repositories')
    op.drop_column('repositories', 'organization_id')

    op.drop_constraint('fk_users_organization_id', 'users', type_='foreignkey')
    op.drop_index(op.f('ix_users_organization_id'), table_name='users')
    op.drop_column('users', 'organization_id')

    op.drop_index(op.f('ix_organizations_created_at'), table_name='organizations')
    op.drop_index(op.f('ix_organizations_slug'), table_name='organizations')
    op.drop_table('organizations')
