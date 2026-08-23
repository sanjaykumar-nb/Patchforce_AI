"""
PatchForge AI - AST Engine Base Interface
=========================================
Defines the universal AST node data structures and abstract parser contract
for Tree-sitter and multi-language syntactic analysis.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Dict


@dataclass
class ASTNodeData:
    """Universal normalized AST node representation across languages."""
    node_type: str
    start_line: int          # 1-indexed
    start_column: int        # 0-indexed
    end_line: int            # 1-indexed
    end_column: int          # 0-indexed
    text: str
    parent_scope: Optional[str] = None
    identifier: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    children: List["ASTNodeData"] = field(default_factory=list)

    @property
    def line_range(self) -> str:
        return f"{self.start_line}:{self.start_column}-{self.end_line}:{self.end_column}"


class BaseASTParser(ABC):
    """Abstract base class for language-specific Tree-sitter parsers."""

    def __init__(self, language_name: str):
        self.language_name = language_name

    @abstractmethod
    def parse(self, source_code: str) -> Any:
        """Parses source string into an AST tree."""
        pass

    @abstractmethod
    def get_functions(self, source_code: str) -> List[ASTNodeData]:
        """Extracts all function and method declarations."""
        pass

    @abstractmethod
    def get_classes(self, source_code: str) -> List[ASTNodeData]:
        """Extracts all class declarations."""
        pass

    @abstractmethod
    def get_imports(self, source_code: str) -> List[ASTNodeData]:
        """Extracts all import statements."""
        pass

    @abstractmethod
    def get_calls(self, source_code: str, target_name: Optional[str] = None) -> List[ASTNodeData]:
        """Extracts function/method call sites, optionally filtered by target name."""
        pass

    @abstractmethod
    def get_assignments(self, source_code: str) -> List[ASTNodeData]:
        """Extracts variable assignment statements."""
        pass

    @abstractmethod
    def find_enclosing_function(self, source_code: str, line_number: int) -> Optional[ASTNodeData]:
        """Finds the function node enclosing a given 1-indexed line number."""
        pass
