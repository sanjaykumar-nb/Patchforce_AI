"""
PatchForge AI - Patch Schemas
=============================
Pydantic schemas for patch requests, unified diff responses, and validation metrics.
"""

from datetime import datetime
from typing import Optional, List, Dict
from pydantic import BaseModel, ConfigDict, Field
from app.models.patch import PatchStatus


class PatchGenerateRequest(BaseModel):
    vulnerability_id: str = Field(..., json_schema_extra={"example": "vuln-uuid-12345"})


class ValidationReportResponse(BaseModel):
    patch_id: str
    id: Optional[str] = None
    syntax_valid: bool
    ast_valid: bool
    test_pass_rate: float
    rescan_clean: bool
    composite_score: float
    patch_score: Optional[float] = None
    diff_content: Optional[str] = None
    explanation: Optional[str] = None
    security_reason: Optional[str] = None
    status: PatchStatus
    stage_logs: Dict[str, str] = {}


class PatchResponse(BaseModel):
    id: str
    vulnerability_id: str
    scan_id: str
    model_name: str
    model_version: Optional[str]
    diff_content: str
    old_code: str
    new_code: str
    explanation: str
    security_reason: str
    patch_score: float
    syntax_valid: bool
    ast_valid: bool
    test_pass_rate: float
    rescan_clean: bool
    status: PatchStatus
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PatchListResponse(BaseModel):
    total: int
    items: List[PatchResponse]
