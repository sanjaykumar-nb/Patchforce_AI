"""
PatchForge AI - Robust Native Python AST Parser
================================================
Implements memory-safe, crash-resilient AST analysis for Python:
functions, classes, calls, arguments, variable assignments, and scope resolution.
"""

import ast
from typing import Any, List, Optional
from app.ast_engine.base import BaseASTParser, ASTNodeData


class PythonASTParser(BaseASTParser):
    """Production AST parser for Python using native, memory-safe ast engine."""

    def __init__(self):
        super().__init__(language_name="python")

    def parse(self, source_code: str) -> Optional[ast.AST]:
        """Parses Python source code string into an AST tree."""
        try:
            return ast.parse(source_code)
        except Exception:
            return None

    def _get_node_text(self, node: ast.AST, lines: List[str]) -> str:
        """Extracts source text for an AST node safely across Python versions."""
        try:
            start_line = getattr(node, "lineno", 1) - 1
            end_line = getattr(node, "end_lineno", start_line + 1)
            return "\n".join(lines[start_line:end_line])
        except Exception:
            return ""

    def get_functions(self, source_code: str) -> List[ASTNodeData]:
        """Extracts all function and async function declarations with hierarchical parent scope."""
        tree = self.parse(source_code)
        if not tree:
            return []

        lines = source_code.splitlines()
        functions = []

        def _traverse(node: ast.AST, scope_stack: List[str]):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    _traverse(child, scope_stack + [child.name])
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    text = self._get_node_text(child, lines)
                    start_l = getattr(child, "lineno", 1)
                    end_l = getattr(child, "end_lineno", start_l)
                    start_c = getattr(child, "col_offset", 0)
                    end_c = getattr(child, "end_col_offset", 0)
                    parent_scope = ".".join(scope_stack) if scope_stack else None

                    functions.append(
                        ASTNodeData(
                            node_type="function_definition" if isinstance(child, ast.FunctionDef) else "async_function_definition",
                            start_line=start_l,
                            start_column=start_c,
                            end_line=end_l,
                            end_column=end_c,
                            text=text,
                            identifier=child.name,
                            parent_scope=parent_scope,
                        )
                    )
                    _traverse(child, scope_stack + [child.name])
                else:
                    _traverse(child, scope_stack)

        _traverse(tree, [])
        return functions

    def get_classes(self, source_code: str) -> List[ASTNodeData]:
        """Extracts all class declarations."""
        tree = self.parse(source_code)
        if not tree:
            return []

        lines = source_code.splitlines()
        classes = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                text = self._get_node_text(node, lines)
                classes.append(
                    ASTNodeData(
                        node_type="class_definition",
                        start_line=getattr(node, "lineno", 1),
                        start_column=getattr(node, "col_offset", 0),
                        end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                        end_column=getattr(node, "end_col_offset", 0),
                        text=text,
                        identifier=node.name,
                    )
                )

        return classes

    def get_imports(self, source_code: str) -> List[ASTNodeData]:
        """Extracts all import statements."""
        tree = self.parse(source_code)
        if not tree:
            return []

        lines = source_code.splitlines()
        imports = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                text = self._get_node_text(node, lines)
                imports.append(
                    ASTNodeData(
                        node_type="import_statement" if isinstance(node, ast.Import) else "import_from_statement",
                        start_line=getattr(node, "lineno", 1),
                        start_column=getattr(node, "col_offset", 0),
                        end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                        end_column=getattr(node, "end_col_offset", 0),
                        text=text,
                    )
                )

        return imports

    def get_calls(self, source_code: str, target_name: Optional[str] = None) -> List[ASTNodeData]:
        """Extracts all function/method call sites."""
        tree = self.parse(source_code)
        if not tree:
            return []

        lines = source_code.splitlines()
        calls = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = None
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr
                    # Include object.method format (e.g. cursor.execute, db.execute)
                    val = node.func.value
                    if isinstance(val, ast.Name):
                        call_name = f"{val.id}.{call_name}"

                if target_name is None or (call_name and target_name in call_name):
                    text = self._get_node_text(node, lines)
                    calls.append(
                        ASTNodeData(
                            node_type="call",
                            start_line=getattr(node, "lineno", 1),
                            start_column=getattr(node, "col_offset", 0),
                            end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                            end_column=getattr(node, "end_col_offset", 0),
                            text=text,
                            identifier=call_name,
                        )
                    )

        return calls

    def get_assignments(self, source_code: str) -> List[ASTNodeData]:
        """Extracts variable assignment expressions."""
        tree = self.parse(source_code)
        if not tree:
            return []

        lines = source_code.splitlines()
        assignments = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                text = self._get_node_text(node, lines)
                assignments.append(
                    ASTNodeData(
                        node_type="assignment",
                        start_line=getattr(node, "lineno", 1),
                        start_column=getattr(node, "col_offset", 0),
                        end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                        end_column=getattr(node, "end_col_offset", 0),
                        text=text,
                    )
                )

        return assignments

    def find_enclosing_function(
        self,
        source_code: str,
        line_number: int,
        line_end: Optional[int] = None,
    ) -> Optional[ASTNodeData]:
        """Locates the tightest function node enclosing or overlapping the given line range."""
        functions = self.get_functions(source_code)
        candidate = None
        end_num = line_end or line_number

        for func in functions:
            if not (end_num < func.start_line or line_number > func.end_line):
                if candidate is None:
                    candidate = func
                else:
                    if (func.end_line - func.start_line) < (candidate.end_line - candidate.start_line):
                        candidate = func

        return candidate
