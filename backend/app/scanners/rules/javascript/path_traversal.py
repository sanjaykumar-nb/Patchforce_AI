"""
PatchForge AI - Rule: JS-PATH-001 (JavaScript Path Traversal)
============================================================
CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal').
Detects unvalidated filesystem path operations in fs.readFile, fs.createReadStream, etc.
"""

from typing import List
from app.ast_engine.base import BaseASTParser
from app.models.vulnerability import SeverityLevel
from app.scanners.rules.base_rule import BaseRule, Finding


class JavaScriptPathTraversalRule(BaseRule):
    """Detects path traversal vulnerabilities in Node.js fs operations."""

    def __init__(self):
        super().__init__(
            rule_id="JS-PATH-001",
            cwe="CWE-22",
            severity=SeverityLevel.HIGH,
            cvss_score=7.5,
            description="Unvalidated filesystem path concatenation in fs API.",
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

            if any(target in identifier for target in ("readFile", "readFileSync", "createReadStream", "unlink", "fs.readFile")):
                if ("+" in call_text or "${" in call_text) and ("/" in call_text or "\\" in call_text):
                    if "path.basename" not in call_text and "path.resolve" not in call_text:
                        is_unsafe = True
                        evidence = f"Unvalidated path string concatenation in {identifier}(): {call_text.splitlines()[0]}"

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
