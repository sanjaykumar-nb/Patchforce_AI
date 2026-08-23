"""
PatchForge AI - Rule: PY-YAML-001 (Unsafe YAML Deserialization)
===============================================================
CWE-20: Improper Input Validation / Unsafe YAML Loading.
Detects use of yaml.load() without explicit SafeLoader, leading to Arbitrary Object Execution.
"""

from typing import List
from app.ast_engine.base import BaseASTParser
from app.models.vulnerability import SeverityLevel
from app.scanners.rules.base_rule import BaseRule, Finding


class PythonUnsafeYAMLRule(BaseRule):
    """Detects unsafe yaml.load() calls vulnerable to arbitrary code execution."""

    def __init__(self):
        super().__init__(
            rule_id="PY-YAML-001",
            cwe="CWE-20",
            severity=SeverityLevel.HIGH,
            cvss_score=8.1,
            description="Use of unsafe yaml.load() without SafeLoader allows arbitrary code execution.",
            language="python",
        )

    def analyze(self, source_code: str, file_path: str, parser: BaseASTParser) -> List[Finding]:
        findings: List[Finding] = []
        calls = parser.get_calls(source_code)

        for call in calls:
            identifier = (call.identifier or "").strip()
            if identifier in ("yaml.load", "load") and "yaml." in call.text:
                if "Loader=SafeLoader" not in call.text and "Loader=yaml.SafeLoader" not in call.text:
                    enclosing = parser.find_enclosing_function(source_code, call.start_line)
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            cwe=self.cwe,
                            severity=self.severity,
                            cvss_score=self.cvss_score,
                            confidence_score=0.94,
                            file_path=file_path,
                            line_start=call.start_line,
                            line_end=call.end_line,
                            function_name=enclosing.identifier if enclosing else None,
                            ast_node_type=call.node_type,
                            source_snippet=call.text.splitlines()[0],
                            description=self.description,
                            evidence=f"Call to unsafe '{identifier}' at line {call.start_line}. Replace with yaml.safe_load().",
                        )
                    )

        return findings
