"""
PatchForge AI - Rule: PY-HASH-001 (Broken / Insecure Cryptographic Hash)
========================================================================
CWE-328: Use of Weak Hash.
Detects use of broken MD5 or SHA1 hash functions vulnerable to collision attacks.
"""

from typing import List
from app.ast_engine.base import BaseASTParser
from app.models.vulnerability import SeverityLevel
from app.scanners.rules.base_rule import BaseRule, Finding


class PythonWeakCryptoHashRule(BaseRule):
    """Detects use of broken hash algorithms (MD5, SHA1) in hashlib calls."""

    def __init__(self):
        super().__init__(
            rule_id="PY-HASH-001",
            cwe="CWE-328",
            severity=SeverityLevel.MEDIUM,
            cvss_score=5.3,
            description="Use of weak cryptographic hash (MD5 or SHA-1) vulnerable to collision attacks.",
            language="python",
        )

    def analyze(self, source_code: str, file_path: str, parser: BaseASTParser) -> List[Finding]:
        findings: List[Finding] = []
        calls = parser.get_calls(source_code)

        for call in calls:
            identifier = (call.identifier or "").strip()
            if any(kw in identifier for kw in ("hashlib.md5", "hashlib.sha1", "md5", "sha1", "Crypto.Hash.MD5", "Crypto.Hash.SHA1")):
                enclosing = parser.find_enclosing_function(source_code, call.start_line)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        cwe=self.cwe,
                        severity=self.severity,
                        cvss_score=self.cvss_score,
                        confidence_score=0.90,
                        file_path=file_path,
                        line_start=call.start_line,
                        line_end=call.end_line,
                        function_name=enclosing.identifier if enclosing else None,
                        ast_node_type=call.node_type,
                        source_snippet=call.text.splitlines()[0],
                        description=self.description,
                        evidence=f"Call to broken hash function '{identifier}' at line {call.start_line}. Upgrade to SHA-256 or SHA-3.",
                    )
                )

        return findings
