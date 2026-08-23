"""
PatchForge AI - Rule: PY-EVAL-001 (Dynamic Code Execution / Code Injection)
===========================================================================
CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code.
Detects dangerous eval() or exec() usage with dynamic input.
"""

from typing import List
from app.ast_engine.base import BaseASTParser
from app.models.vulnerability import SeverityLevel
from app.scanners.rules.base_rule import BaseRule, Finding


class PythonEvalCodeInjectionRule(BaseRule):
    """Detects dangerous eval() and exec() execution in Python source code."""

    def __init__(self):
        super().__init__(
            rule_id="PY-EVAL-001",
            cwe="CWE-95",
            severity=SeverityLevel.CRITICAL,
            cvss_score=9.6,
            description="Use of dangerous eval() or exec() allows arbitrary code execution.",
            language="python",
        )

    def analyze(self, source_code: str, file_path: str, parser: BaseASTParser) -> List[Finding]:
        findings: List[Finding] = []
        calls = parser.get_calls(source_code)

        for call in calls:
            identifier = (call.identifier or "").strip()
            if identifier in ("eval", "exec", "__import__", "builtins.eval", "builtins.exec"):
                text = call.text.strip()
                enclosing = parser.find_enclosing_function(source_code, call.start_line)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        cwe=self.cwe,
                        severity=self.severity,
                        cvss_score=self.cvss_score,
                        confidence_score=0.96,
                        file_path=file_path,
                        line_start=call.start_line,
                        line_end=call.end_line,
                        function_name=enclosing.identifier if enclosing else None,
                        ast_node_type=call.node_type,
                        source_snippet=text.splitlines()[0],
                        description=self.description,
                        evidence=f"Direct invocation of '{identifier}' at line {call.start_line} allows remote code execution.",
                    )
                )

        return findings
