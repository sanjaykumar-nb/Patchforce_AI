"""
PatchForge AI - Pull Request Schemas
====================================
Pydantic schemas for requesting automated pull request generation and retrieving PR details.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field
from app.models.pull_request import PRStatus


class PullRequestCreateRequest(BaseModel):
    patch_id: str = Field(..., json_schema_extra={"example": "patch-uuid-12345"})
    base_branch: Optional[str] = Field("main", json_schema_extra={"example": "main"})


class PullRequestResponse(BaseModel):
    id: str
    patch_id: str
    repository_id: str
    pr_number: Optional[int]
    pr_url: Optional[str]
    branch_name: str
    title: str
    body: str
    status: PRStatus
    is_simulated: bool = False
    merged_by: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PullRequestListResponse(BaseModel):
    total: int
    items: List[PullRequestResponse]
