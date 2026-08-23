"""
PatchForge AI - Vulnerability Rule Engine Base Contract
======================================================
Defines the abstract vulnerability rule class and finding representation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from app.ast_engine.base import BaseASTParser
from app.models.vulnerability import SeverityLevel


@dataclass
class Finding:
    """Represents an AST-verified security finding detected by a rule."""
    rule_id: str
    cwe: str
    severity: SeverityLevel
    cvss_score: float
    confidence_score: float
    file_path: str
    line_start: int
    line_end: int
    function_name: Optional[str]
    ast_node_type: str
    source_snippet: str
    description: str
    evidence: str


class BaseRule(ABC):
    """Abstract base class for deterministic AST vulnerability rules."""

    def __init__(
        self,
        rule_id: str,
        cwe: str,
        severity: SeverityLevel,
        cvss_score: float,
        description: str,
        language: str,
    ):
        self.rule_id = rule_id
        self.cwe = cwe
        self.severity = severity
        self.cvss_score = cvss_score
        self.description = description
        self.language = language

    @abstractmethod
    def analyze(self, source_code: str, file_path: str, parser: BaseASTParser) -> List[Finding]:
        """Analyzes source code via Tree-sitter AST and returns detected findings."""
        pass

    def calculate_confidence(self, match_context: Dict[str, Any]) -> float:
        """
        Calculates an objective confidence score (0.0 - 1.0) based on
        direct AST node certainty vs data-flow heuristic certainty.
        """
        base_confidence = 0.85
        if match_context.get("direct_call_match"):
            base_confidence += 0.05
        if match_context.get("string_concatenation"):
            base_confidence += 0.05
        if match_context.get("enclosing_function_found"):
            base_confidence += 0.04
        return min(round(base_confidence, 2), 0.99)
