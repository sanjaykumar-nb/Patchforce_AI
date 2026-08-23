"""
PatchForge AI - User & RBAC Database Model
=========================================
Represents platform users with Role-Based Access Control (RBAC).
"""

import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Enum
from app.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    SECURITY_ENGINEER = "SECURITY_ENGINEER"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=True)
    full_name = Column(String(255), nullable=True)
    role = Column(Enum(UserRole), default=UserRole.DEVELOPER, nullable=False, index=True)
    github_token = Column(String(512), nullable=True)
    github_username = Column(String(255), nullable=True, index=True)
    github_avatar_url = Column(String(1024), nullable=True)
    otp_code = Column(String(16), nullable=True)
    otp_expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} github={self.github_username} role={self.role}>"
