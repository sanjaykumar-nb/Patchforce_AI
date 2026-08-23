"""
PatchForge AI - Organization (Tenant) Schemas
==============================================
Pydantic schemas for tenant workspace responses.
"""

from datetime import datetime
from pydantic import BaseModel, ConfigDict


class OrganizationBrief(BaseModel):
    id: str
    name: str
    slug: str

    model_config = ConfigDict(from_attributes=True)


class OrganizationResponse(OrganizationBrief):
    created_at: datetime
    member_count: int
    repository_count: int
