"""
PatchForge AI - Enterprise Security Audit Log Database Model
===========================================================
Provides an immutable audit log trail of all automated remediation decisions,
sandbox outcomes, model inferences, and human approvals.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String(64), nullable=False, index=True)  # e.g., "PATCH_APPROVED", "VULN_DETECTED"
    actor = Column(String(255), default="SYSTEM", nullable=False, index=True)
    repository_id = Column(String(36), ForeignKey("repositories.id", ondelete="SET NULL"), nullable=True, index=True)
    pipeline_run_id = Column(String(36), ForeignKey("pipeline_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    vulnerability_id = Column(String(36), ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True, index=True)
    patch_id = Column(String(36), ForeignKey("patches.id", ondelete="SET NULL"), nullable=True, index=True)
    details = Column(Text, nullable=False)  # JSON-encoded payload
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    repository = relationship("Repository")
    pipeline_run = relationship("PipelineRun", back_populates="audit_logs")
    vulnerability = relationship("Vulnerability", back_populates="audit_logs")
    patch = relationship("Patch", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} event={self.event_type} actor={self.actor}>"
