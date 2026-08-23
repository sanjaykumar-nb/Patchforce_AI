"""
PatchForge AI - Rule: JS-SQLI-001 (JavaScript SQL Injection)
============================================================
CWE-89: Improper Neutralization of Special Elements used in an SQL Command.
Detects unparameterized database query execution via string concatenation or template literals.
"""

from typing import List
from app.ast_engine.base import BaseASTParser
from app.models.vulnerability import SeverityLevel
from app.scanners.rules.base_rule import BaseRule, Finding


class JavaScriptSQLInjectionRule(BaseRule):
    """Detects SQL injection vulnerabilities in Node.js / JavaScript database clients."""

    def __init__(self):
        super().__init__(
            rule_id="JS-SQLI-001",
            cwe="CWE-89",
            severity=SeverityLevel.HIGH,
            cvss_score=8.5,
            description="Unsanitized string concatenation or template interpolation in database query() call.",
            language="javascript",
        )

    def analyze(self, source_code: str, file_path: str, parser: BaseASTParser) -> List[Finding]:
        findings: List[Finding] = []
        calls = parser.get_calls(source_code)
        assignments = parser.get_assignments(source_code)

        unsafe_vars = {}
        for assign in assignments:
            assign_text = assign.text
            if ("+" in assign_text or "${" in assign_text):
                if any(sql_kw in assign_text.upper() for sql_kw in ("SELECT", "INSERT", "UPDATE", "DELETE", "WHERE")):
                    var_name = assign_text.split("=")[0].replace("const", "").replace("let", "").replace("var", "").strip()
                    unsafe_vars[var_name] = assign

        for call in calls:
            identifier = call.identifier or ""
            call_text = call.text
            is_unsafe = False
            evidence = ""

            if any(target in identifier for target in ("query", "raw", "db.query", "client.query", "pool.query", "sequelize.query")):
                if ("+" in call_text or "${" in call_text) and any(sql_kw in call_text.upper() for sql_kw in ("SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE")):
                    is_unsafe = True
                    evidence = f"Direct concatenation/template string in {identifier}() query call."

                if not is_unsafe:
                    for var_name, assign_node in unsafe_vars.items():
                        if f"({var_name})" in call_text or f"({var_name}," in call_text:
                            is_unsafe = True
                            evidence = f"Query variable '{var_name}' built unsafely at line {assign_node.start_line} and executed."
                            break

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
