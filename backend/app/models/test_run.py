"""
PatchForge AI - Test Run Database Model
======================================
Tracks test executions, unit tests, regression suites, and static analysis checks on patches.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class TestRun(Base):
    __tablename__ = "test_runs"
    __test__ = False

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    patch_id = Column(String(36), ForeignKey("patches.id", ondelete="CASCADE"), nullable=False, index=True)
    test_type = Column(String(64), nullable=False, index=True)  # "syntax", "unit", "regression", "security_rescan"
    test_command = Column(String(255), nullable=False)
    passed = Column(Boolean, default=False, nullable=False, index=True)
    total_tests = Column(Integer, default=0, nullable=False)
    passed_tests = Column(Integer, default=0, nullable=False)
    failed_tests = Column(Integer, default=0, nullable=False)
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)
    execution_time_ms = Column(Float, default=0.0, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    patch = relationship("Patch", back_populates="test_runs")

    def __repr__(self) -> str:
        return f"<TestRun id={self.id} type={self.test_type} passed={self.passed}>"
