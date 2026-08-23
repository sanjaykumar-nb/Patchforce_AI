"""
PatchForge AI - Targeted AST Context Slicer & Prompt Payload Builder
===================================================================
Extracts minimal, high-precision syntactic context around vulnerability
findings for local LLM inference without leaking entire repositories.
"""

import os
from typing import Any, Dict, List, Optional
from app.ast_engine.base import BaseASTParser, ASTNodeData
from app.ast_engine.python_parser import PythonASTParser
from app.ast_engine.javascript_parser import JavaScriptASTParser
from app.core.logging import get_logger

logger = get_logger("patchforge.ast.extractor")


class ASTContextExtractor:
    """Extracts isolated syntactic contexts and constraints for LLM patch generation."""

    def __init__(self):
        self.python_parser = PythonASTParser()
        self.javascript_parser = JavaScriptASTParser()

    def get_parser_for_file(self, file_path: str) -> Optional[BaseASTParser]:
        """Resolves the appropriate AST parser based on file extension."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in (".py", ".pyw"):
            return self.python_parser
        elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            return self.javascript_parser
        return None

    def extract_context(
        self,
        source_code: str,
        file_path: str,
        line_start: int,
        line_end: int,
        rule_id: str,
        cwe: str,
        severity: str,
        description: str,
    ) -> Dict[str, Any]:
        """
        Constructs a structured, injection-resistant LLM context payload
        containing only the relevant enclosing function, imports, and constraints.
        """
        parser = self.get_parser_for_file(file_path)
        language = parser.language_name if parser else "text"

        imports_list: List[str] = []
        enclosing_func: Optional[ASTNodeData] = None
        target_code = source_code
        func_start = 1
        func_end = len(source_code.splitlines())
        func_name = "module_level"
        parent_scope = None

        if parser:
            # 1. Extract imports
            raw_imports = parser.get_imports(source_code)
            imports_list = [imp.text.strip() for imp in raw_imports]

            # 2. Extract enclosing function node
            enclosing_func = parser.find_enclosing_function(source_code, line_start, line_end)
            if enclosing_func:
                target_code = enclosing_func.text
                func_start = enclosing_func.start_line
                func_end = enclosing_func.end_line
                func_name = enclosing_func.identifier or "anonymous_function"
                parent_scope = enclosing_func.parent_scope
            else:
                # Fallback: slice 10 lines above and below
                lines = source_code.splitlines()
                slice_start = max(0, line_start - 10)
                slice_end = min(len(lines), line_end + 10)
                target_code = "\n".join(lines[slice_start:slice_end])
                func_start = slice_start + 1
                func_end = slice_end

        # Slice the specific vulnerable code lines
        lines = source_code.splitlines()
        vuln_lines = lines[max(0, line_start - 1):min(len(lines), line_end)]
        source_snippet = "\n".join(vuln_lines)

        return {
            "language": language,
            "file_path": file_path,
            "function_name": func_name,
            "enclosing_scope": f"{parent_scope}.{func_name}" if parent_scope else func_name,
            "function_line_start": func_start,
            "function_line_end": func_end,
            "vulnerability": {
                "rule_id": rule_id,
                "cwe": cwe,
                "severity": severity,
                "line_start": line_start,
                "line_end": line_end,
                "description": description,
                "source_snippet": source_snippet,
            },
            "imports": imports_list,
            "target_code_to_patch": target_code,
            "security_constraints": [
                "Generate a minimal patch modifying ONLY the vulnerable logic",
                "Preserve public API function signatures, arguments, and return types",
                "Do NOT modify unrelated code or introduce breaking refactorings",
                "Use secure parameterized APIs and robust input validation",
                "Output strictly valid JSON matching the requested schema",
            ]
        }
