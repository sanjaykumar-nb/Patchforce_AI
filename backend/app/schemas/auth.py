"""
PatchForge AI - Authentication & User Schemas
=============================================
Pydantic validation models for registration, login, token responses, and user profiles.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, ConfigDict, Field
from app.models.user import UserRole


class UserRegisterRequest(BaseModel):
    email: str = Field(..., json_schema_extra={"example": "secops@patchforge.ai"})
    password: str = Field(..., min_length=8, json_schema_extra={"example": "P@ssw0rdSecure!2026"})
    full_name: Optional[str] = Field(None, json_schema_extra={"example": "Alex Rivers"})
    role: Optional[UserRole] = Field(UserRole.DEVELOPER, json_schema_extra={"example": "SECURITY_ENGINEER"})


class UserLoginRequest(BaseModel):
    email: str = Field(..., json_schema_extra={"example": "secops@patchforge.ai"})
    password: str = Field(..., json_schema_extra={"example": "P@ssw0rdSecure!2026"})


class GitHubTokenLoginRequest(BaseModel):
    token: str = Field(..., json_schema_extra={"example": "ghp_xxxxxxxxxxxxxxxxxxxx"})


class OTPRequest(BaseModel):
    email: str = Field(..., json_schema_extra={"example": "developer@patchforge.ai"})


class OTPVerifyRequest(BaseModel):
    email: str = Field(..., json_schema_extra={"example": "developer@patchforge.ai"})
    otp: str = Field(..., min_length=6, max_length=6, json_schema_extra={"example": "123456"})


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str]
    role: UserRole
    github_username: Optional[str] = None
    github_avatar_url: Optional[str] = None
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    user: UserResponse
