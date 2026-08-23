"""
PatchForge AI - Rule: PY-TLS-001 (Disabled TLS/SSL Certificate Verification)
===========================================================================
CWE-295: Improper Certificate Validation.
Detects requests/httpx/urllib calls with verify=False, allowing Man-in-the-Middle attacks.
"""

from typing import List
from app.ast_engine.base import BaseASTParser
from app.models.vulnerability import SeverityLevel
from app.scanners.rules.base_rule import BaseRule, Finding


class PythonInsecureTLSRule(BaseRule):
    """Detects disabled SSL/TLS certificate validation in network clients."""

    def __init__(self):
        super().__init__(
            rule_id="PY-TLS-001",
            cwe="CWE-295",
            severity=SeverityLevel.HIGH,
            cvss_score=7.5,
            description="TLS/SSL certificate validation is explicitly disabled (verify=False).",
            language="python",
        )

    def analyze(self, source_code: str, file_path: str, parser: BaseASTParser) -> List[Finding]:
        findings: List[Finding] = []
        calls = parser.get_calls(source_code)

        for call in calls:
            text = call.text
            if "verify=False" in text or "verify = False" in text or "ssl_verify=False" in text:
                identifier = call.identifier or ""
                if any(kw in identifier for kw in ("get", "post", "put", "delete", "request", "Client", "Session", "urlopen")):
                    enclosing = parser.find_enclosing_function(source_code, call.start_line)
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            cwe=self.cwe,
                            severity=self.severity,
                            cvss_score=self.cvss_score,
                            confidence_score=0.95,
                            file_path=file_path,
                            line_start=call.start_line,
                            line_end=call.end_line,
                            function_name=enclosing.identifier if enclosing else None,
                            ast_node_type=call.node_type,
                            source_snippet=text.splitlines()[0],
                            description=self.description,
                            evidence=f"Call to '{identifier}' at line {call.start_line} disables TLS certificate verification (verify=False).",
                        )
                    )

        return findings
