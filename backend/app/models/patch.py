"""
PatchForge AI - Patch Database Model
====================================
Stores generated AST-minimal code diffs, LLM rationale, and multi-stage scoring metrics.
"""

import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, Boolean, Text, DateTime, Enum, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class PatchStatus(str, enum.Enum):
    PENDING_VALIDATION = "PENDING_VALIDATION"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    APPLIED = "APPLIED"
    PR_CREATED = "PR_CREATED"


class Patch(Base):
    __tablename__ = "patches"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vulnerability_id = Column(String(36), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    model_name = Column(String(64), nullable=False)
    model_version = Column(String(64), nullable=True)
    diff_content = Column(Text, nullable=False)
    old_code = Column(Text, nullable=False)
    new_code = Column(Text, nullable=False)
    explanation = Column(Text, nullable=False)
    security_reason = Column(Text, nullable=False)
    patch_score = Column(Float, default=0.0, nullable=False)  # 0 to 100 composite score
    syntax_valid = Column(Boolean, default=False, nullable=False)
    ast_valid = Column(Boolean, default=False, nullable=False)
    test_pass_rate = Column(Float, default=0.0, nullable=False)
    rescan_clean = Column(Boolean, default=False, nullable=False)
    status = Column(Enum(PatchStatus), default=PatchStatus.PENDING_VALIDATION, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="patches")
    test_runs = relationship("TestRun", back_populates="patch", cascade="all, delete-orphan")
    pull_request = relationship("PullRequest", back_populates="patch", uselist=False, cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="patch", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Patch id={self.id} vuln={self.vulnerability_id} score={self.patch_score} status={self.status}>"
