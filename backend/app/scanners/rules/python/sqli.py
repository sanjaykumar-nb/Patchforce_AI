"""
PatchForge AI - Rule: PY-SQLI-001 (Python SQL Injection)
========================================================
CWE-89: Improper Neutralization of Special Elements used in an SQL Command.
Detects unparameterized SQL query execution via string concatenation or f-strings.
"""

from typing import List
from app.ast_engine.base import BaseASTParser
from app.models.vulnerability import SeverityLevel
from app.scanners.rules.base_rule import BaseRule, Finding


class PythonSQLInjectionRule(BaseRule):
    """Detects SQL injection vulnerabilities in Python database adapters."""

    def __init__(self):
        super().__init__(
            rule_id="PY-SQLI-001",
            cwe="CWE-89",
            severity=SeverityLevel.HIGH,
            cvss_score=8.5,
            description="Unsanitized string concatenation or formatting detected in SQL execute() call.",
            language="python",
        )

    def analyze(self, source_code: str, file_path: str, parser: BaseASTParser) -> List[Finding]:
        findings: List[Finding] = []
        calls = parser.get_calls(source_code)
        assignments = parser.get_assignments(source_code)

        # Map variable assignments in scope: var_name -> node
        unsafe_vars = {}
        for assign in assignments:
            assign_text = assign.text
            # Detect string concatenation or formatting in variable assignment
            if ("+" in assign_text or "f\"" in assign_text or "f'" in assign_text or " % " in assign_text or ".format(" in assign_text):
                if any(sql_kw in assign_text.upper() for sql_kw in ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE")):
                    var_name = assign_text.split("=")[0].strip()
                    unsafe_vars[var_name] = assign

        for call in calls:
            identifier = call.identifier or ""
            if any(target in identifier for target in ("execute", "executemany", "raw", "cursor.execute", "db.execute")):
                call_text = call.text.strip()

                # Extract arguments within parentheses
                open_paren = call_text.find("(")
                close_paren = call_text.rfind(")")
                if open_paren == -1 or close_paren == -1:
                    continue

                args_raw = call_text[open_paren + 1 : close_paren].strip()
                
                # Check if multiple arguments are passed (e.g. query, (params,))
                # A parameterized execute(sql, params) call will have a comma outside quotes
                is_parameterized = False
                if "," in args_raw:
                    # Check if comma separates the SQL query string from parameter collection
                    parts = [p.strip() for p in args_raw.split(",") if p.strip()]
                    if len(parts) >= 2 and not ("+" in parts[0] or "f\"" in parts[0] or "f'" in parts[0] or " % " in parts[0]):
                        is_parameterized = True

                if is_parameterized:
                    continue

                is_unsafe = False
                evidence = ""

                # Direct concatenation or f-string inside execute argument
                if "+" in args_raw or "f\"" in args_raw or "f'" in args_raw or " % " in args_raw or ".format(" in args_raw:
                    if any(kw in args_raw.upper() for kw in ("SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE")):
                        is_unsafe = True
                        evidence = f"Direct string concatenation/formatting in execute call: {call_text.splitlines()[0]}"

                # Indirect usage via previously concatenated variable
                if not is_unsafe:
                    for var_name, assign_node in unsafe_vars.items():
                        if args_raw == var_name or args_raw.startswith(f"{var_name},"):
                            is_unsafe = True
                            evidence = f"Query variable '{var_name}' built unsafely at line {assign_node.start_line} and passed without parameters."
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
