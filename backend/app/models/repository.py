"""
PatchForge AI - Repository Database Model
========================================
Tracks registered Git repositories monitored by PatchForge AI.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from app.database import Base


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    full_name = Column(String(255), unique=True, index=True, nullable=False)  # e.g. "org/repo"
    url = Column(String(512), nullable=False)
    clone_url = Column(String(512), nullable=False)
    default_branch = Column(String(64), default="main", nullable=False)
    language = Column(String(64), default="python", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    webhook_secret = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="repository", cascade="all, delete-orphan")
    pipeline_runs = relationship("PipelineRun", back_populates="repository", cascade="all, delete-orphan")
    pull_requests = relationship("PullRequest", back_populates="repository", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Repository id={self.id} full_name={self.full_name}>"
