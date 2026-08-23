"""
PatchForge AI - Repository Database Model
========================================
Tracks registered Git repositories monitored by PatchForge AI.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from app.database import Base


class Repository(Base):
    __tablename__ = "repositories"
    __table_args__ = (
        # full_name only needs to be unique within a tenant - two different
        # organizations can each independently register "org/demo-app" as a
        # repo they track. Nullable organization_id rows (pre-multi-tenancy)
        # are excluded from this constraint by Postgres/SQLite NULL semantics.
        UniqueConstraint("organization_id", "full_name", name="uq_repository_org_full_name"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # Tenant this repository belongs to. Nullable only for rows created before
    # multi-tenancy shipped (see migration 005).
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    full_name = Column(String(255), index=True, nullable=False)  # e.g. "org/repo"
    url = Column(String(512), nullable=False)
    clone_url = Column(String(512), nullable=False)
    default_branch = Column(String(64), default="main", nullable=False)
    language = Column(String(64), default="python", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    webhook_secret = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="repositories")
    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="repository", cascade="all, delete-orphan")
    pipeline_runs = relationship("PipelineRun", back_populates="repository", cascade="all, delete-orphan")
    pull_requests = relationship("PullRequest", back_populates="repository", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Repository id={self.id} full_name={self.full_name}>"
