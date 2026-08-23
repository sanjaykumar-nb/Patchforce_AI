"""
PatchForge AI - Organization (Tenant) API Endpoints
=====================================================
Read-only endpoint for the authenticated caller's own tenant workspace.
There is no cross-tenant listing endpoint by design - a user can only ever
see the one organization they belong to.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.repository import Repository
from app.core.deps import get_current_user
from app.core.exceptions import EntityNotFoundException
from app.schemas.organization import OrganizationResponse

router = APIRouter()


@router.get("/me", response_model=OrganizationResponse, summary="Get Current Workspace")
def get_current_organization(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves the authenticated caller's own tenant workspace, with member/repo counts."""
    org = current_user.organization
    if not org:
        raise EntityNotFoundException("Organization", "current-user")

    member_count = len(org.users)
    repository_count = db.query(Repository).filter_by(organization_id=org.id).count()

    return OrganizationResponse(
        id=org.id,
        name=org.name,
        slug=org.slug,
        created_at=org.created_at,
        member_count=member_count,
        repository_count=repository_count,
    )
