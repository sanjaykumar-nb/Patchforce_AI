"""
PatchForge AI - AST Node Database Model
======================================
Stores exact Tree-sitter AST syntax subtrees and byte ranges for vulnerability findings.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class ASTNode(Base):
    __tablename__ = "ast_nodes"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vulnerability_id = Column(String(36), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    node_type = Column(String(64), nullable=False)  # e.g., "call", "binary_operator", "function_definition"
    start_line = Column(Integer, nullable=False)
    start_column = Column(Integer, nullable=False)
    end_line = Column(Integer, nullable=False)
    end_column = Column(Integer, nullable=False)
    code_snippet = Column(Text, nullable=False)
    parent_scope = Column(String(255), nullable=True)  # enclosing class/function
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="ast_nodes")

    def __repr__(self) -> str:
        return f"<ASTNode id={self.id} type={self.node_type} lines={self.start_line}-{self.end_line}>"
