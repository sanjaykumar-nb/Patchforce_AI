"""
PatchForge AI - Rule: PY-SECRET-001 (Hardcoded Secrets & API Keys)
=================================================================
CWE-798: Use of Hard-coded Credentials.
Detects hardcoded API keys, JWT tokens, AWS/GCP keys, and database passwords in source code.
"""

import re
from typing import List
from app.ast_engine.base import BaseASTParser
from app.models.vulnerability import SeverityLevel
from app.scanners.rules.base_rule import BaseRule, Finding


class PythonHardcodedSecretRule(BaseRule):
    """Detects hardcoded API keys, credentials, and access tokens in AST assignments."""

    SECRET_KEYWORDS = (
        "api_key", "apikey", "secret_key", "secret", "password", "passwd",
        "access_token", "auth_token", "private_key", "jwt_secret", "aws_secret",
        "client_secret", "database_password", "db_password"
    )

    def __init__(self):
        super().__init__(
            rule_id="PY-SECRET-001",
            cwe="CWE-798",
            severity=SeverityLevel.HIGH,
            cvss_score=7.8,
            description="Hardcoded API key, secret token, or credential detected in source code.",
            language="python",
        )

    def analyze(self, source_code: str, file_path: str, parser: BaseASTParser) -> List[Finding]:
        findings: List[Finding] = []
        assignments = parser.get_assignments(source_code)

        for assign in assignments:
            text = assign.text.strip()
            if "=" not in text:
                continue

            left, *right_parts = text.split("=", 1)
            var_name = left.strip().lower()
            val_str = right_parts[0].strip()

            # Check if variable name matches secret pattern
            if any(kw in var_name for kw in self.SECRET_KEYWORDS):
                # Ignore empty strings, env lookups, or None
                if val_str in ('""', "''", "None", "os.getenv", "os.environ"):
                    continue
                if "os.getenv(" in val_str or "os.environ.get(" in val_str or "config(" in val_str:
                    continue

                # Check if value is a string literal >= 8 characters
                if (val_str.startswith(('"', "'")) and val_str.endswith(('"', "'")) and len(val_str) >= 10):
                    raw_val = val_str[1:-1]
                    # Filter out placeholders
                    if raw_val.lower() in ("your_key_here", "placeholder", "changeme", "test", "example"):
                        continue

                    enclosing = parser.find_enclosing_function(source_code, assign.start_line)
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            cwe=self.cwe,
                            severity=self.severity,
                            cvss_score=self.cvss_score,
                            confidence_score=0.92,
                            file_path=file_path,
                            line_start=assign.start_line,
                            line_end=assign.end_line,
                            function_name=enclosing.identifier if enclosing else None,
                            ast_node_type=assign.node_type,
                            source_snippet=f"{left.strip()} = '***REDACTED***'",
                            description=self.description,
                            evidence=f"Hardcoded credential assigned to variable '{left.strip()}' at line {assign.start_line}.",
                        )
                    )

        return findings
