"""
PatchForge AI - Scan Schemas
============================
Pydantic schemas for scan requests, progress tracking, and scan results.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field
from app.models.scan import ScanStatus


class ScanCreate(BaseModel):
    repository_id: str = Field(..., json_schema_extra={"example": "repo-uuid-12345"})
    commit_hash: str = Field(default="HEAD", json_schema_extra={"example": "a1b2c3d4e5f6"})
    branch: str = Field(default="main", json_schema_extra={"example": "main"})
    triggered_by: str = Field(default="api", json_schema_extra={"example": "api"})
    repo_path: Optional[str] = Field(default=None, json_schema_extra={"example": "C:/path/to/my-repo"})


class ScanResponse(BaseModel):
    id: str
    repository_id: str
    commit_hash: str
    branch: str
    status: ScanStatus
    triggered_by: str
    total_files_scanned: int
    vulnerabilities_count: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanListResponse(BaseModel):
    total: int
    items: List[ScanResponse]
