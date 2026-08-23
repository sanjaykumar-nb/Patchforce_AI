"""
PatchForge AI - Rule: JS-CMDI-001 (JavaScript Command Injection)
================================================================
CWE-78: Improper Neutralization of Special Elements used in an OS Command.
Detects dangerous shell command execution using child_process.exec, execSync, or eval.
"""

from typing import List
from app.ast_engine.base import BaseASTParser
from app.models.vulnerability import SeverityLevel
from app.scanners.rules.base_rule import BaseRule, Finding


class JavaScriptCommandInjectionRule(BaseRule):
    """Detects command injection vulnerabilities in Node.js child_process."""

    def __init__(self):
        super().__init__(
            rule_id="JS-CMDI-001",
            cwe="CWE-78",
            severity=SeverityLevel.CRITICAL,
            cvss_score=9.8,
            description="Dangerous shell execution via child_process.exec or eval with dynamic input.",
            language="javascript",
        )

    def analyze(self, source_code: str, file_path: str, parser: BaseASTParser) -> List[Finding]:
        findings: List[Finding] = []
        calls = parser.get_calls(source_code)

        for call in calls:
            identifier = call.identifier or ""
            call_text = call.text
            is_unsafe = False
            evidence = ""

            if any(target in identifier for target in ("exec", "execSync", "child_process.exec", "eval")):
                if "+" in call_text or "${" in call_text:
                    is_unsafe = True
                    evidence = f"Dangerous dynamic execution via {identifier}(): {call_text.splitlines()[0]}"

            if is_unsafe:
                enclosing = parser.find_enclosing_function(source_code, call.start_line)
                confidence = self.calculate_confidence({
                    "direct_call_match": True,
                    "string_concatenation": True,
                    "enclosing_function_found": enclosing is not None,
                })

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        cwe=self.cwe,
                        severity=self.severity,
                        cvss_score=self.cvss_score,
                        confidence_score=confidence,
                        file_path=file_path,
                        line_start=call.start_line,
                        line_end=call.end_line,
                        function_name=enclosing.identifier if enclosing else None,
                        ast_node_type=call.node_type,
                        source_snippet=call_text,
                        description=self.description,
                        evidence=evidence,
                    )
                )

        return findings
