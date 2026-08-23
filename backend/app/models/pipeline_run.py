"""
PatchForge AI - Pipeline Run Database Model
===========================================
Tracks state transitions of the end-to-end autonomous remediation pipeline.
"""

import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, Enum, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class PipelineState(str, enum.Enum):
    RECEIVED = "RECEIVED"
    CLONING = "CLONING"
    SCANNING = "SCANNING"
    VULNERABILITY_FOUND = "VULNERABILITY_FOUND"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    PATCH_GENERATING = "PATCH_GENERATING"
    PATCH_GENERATED = "PATCH_GENERATED"
    VALIDATING = "VALIDATING"
    TESTING = "TESTING"
    SECURITY_RESCAN = "SECURITY_RESCAN"
    PATCH_APPROVED = "PATCH_APPROVED"
    PR_CREATING = "PR_CREATING"
    PR_CREATED = "PR_CREATED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    repository_id = Column(String(36), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    commit_hash = Column(String(64), nullable=False, index=True)
    branch = Column(String(64), default="main", nullable=False)
    current_state = Column(Enum(PipelineState), default=PipelineState.RECEIVED, nullable=False, index=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    repository = relationship("Repository", back_populates="pipeline_runs")
    scan = relationship("Scan", back_populates="pipeline_runs")
    audit_logs = relationship("AuditLog", back_populates="pipeline_run", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<PipelineRun id={self.id} state={self.current_state} commit={self.commit_hash[:7]}>"
