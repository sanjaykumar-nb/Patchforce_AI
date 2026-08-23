"""
PatchForge AI - Repository Schemas
==================================
Pydantic schemas for repository registration, retrieval, and updates.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field


class RepositoryCreate(BaseModel):
    name: str = Field(..., json_schema_extra={"example": "demo-app"})
    full_name: str = Field(..., json_schema_extra={"example": "org/demo-app"})
    url: str = Field(..., json_schema_extra={"example": "https://github.com/org/demo-app"})
    clone_url: str = Field(..., json_schema_extra={"example": "https://github.com/org/demo-app.git"})
    default_branch: str = Field(default="main", json_schema_extra={"example": "main"})
    language: str = Field(default="python", json_schema_extra={"example": "python"})
    webhook_secret: Optional[str] = Field(default=None)


class RepositoryResponse(BaseModel):
    id: str
    name: str
    full_name: str
    url: str
    clone_url: str
    default_branch: str
    language: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RepositoryListResponse(BaseModel):
    total: int
    items: List[RepositoryResponse]
