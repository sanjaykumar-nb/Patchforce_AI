"""
PatchForge AI - Pull Request Database Model
===========================================
Tracks automated Git pull requests opened for human review and merge approval.
"""

import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Text, DateTime, Enum, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.database import Base


class PRStatus(str, enum.Enum):
    OPEN = "OPEN"
    MERGED = "MERGED"
    CLOSED = "CLOSED"
    REJECTED = "REJECTED"


class PullRequest(Base):
    __tablename__ = "pull_requests"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    patch_id = Column(String(36), ForeignKey("patches.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    repository_id = Column(String(36), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    pr_number = Column(Integer, nullable=True, index=True)
    pr_url = Column(String(512), nullable=True)
    branch_name = Column(String(255), nullable=False)
    title = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    status = Column(Enum(PRStatus), default=PRStatus.OPEN, nullable=False, index=True)
    is_simulated = Column(Boolean, default=False, nullable=False)
    # Why the real GitHub API push was skipped/failed and this fell back to a
    # simulated (non-functional) PR link - e.g. "no GitHub token linked",
    # "no push access", "branch creation failed: 422 ...". NULL for real PRs.
    simulation_reason = Column(Text, nullable=True)
    merged_by = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    patch = relationship("Patch", back_populates="pull_request")
    repository = relationship("Repository", back_populates="pull_requests")

    def __repr__(self) -> str:
        return f"<PullRequest id={self.id} pr_number={self.pr_number} status={self.status}>"
