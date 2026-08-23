"""
PatchForge AI - Rule: PY-CMDI-001 (Python Command Injection)
============================================================
CWE-78: Improper Neutralization of Special Elements used in an OS Command.
Detects unsafe shell execution using os.system, os.popen, or subprocess with shell=True.
"""

from typing import List
from app.ast_engine.base import BaseASTParser
from app.models.vulnerability import SeverityLevel
from app.scanners.rules.base_rule import BaseRule, Finding


class PythonCommandInjectionRule(BaseRule):
    """Detects command injection vulnerabilities in Python OS and subprocess execution."""

    def __init__(self):
        super().__init__(
            rule_id="PY-CMDI-001",
            cwe="CWE-78",
            severity=SeverityLevel.CRITICAL,
            cvss_score=9.8,
            description="Dangerous shell command execution with dynamic string parameters.",
            language="python",
        )

    def analyze(self, source_code: str, file_path: str, parser: BaseASTParser) -> List[Finding]:
        findings: List[Finding] = []
        calls = parser.get_calls(source_code)
        assignments = parser.get_assignments(source_code)

        # Track dynamically concatenated command variables
        dynamic_vars = {}
        for assign in assignments:
            assign_text = assign.text
            if "+" in assign_text or "f\"" in assign_text or "f'" in assign_text or "%" in assign_text:
                var_name = assign_text.split("=")[0].strip()
                dynamic_vars[var_name] = assign

        for call in calls:
            identifier = call.identifier or ""
            call_text = call.text
            is_unsafe = False
            evidence = ""

            # Check os.system and os.popen
            if any(target in identifier for target in ("os.system", "system", "os.popen", "popen")):
                # Check for dynamic argument
                if "+" in call_text or "f\"" in call_text or "f'" in call_text or "%" in call_text:
                    is_unsafe = True
                    evidence = f"Dynamic string concatenation in {identifier}() execution: {call_text.splitlines()[0]}"
                else:
                    for var_name, assign_node in dynamic_vars.items():
                        if f"({var_name})" in call_text:
                            is_unsafe = True
                            evidence = f"Dynamic variable '{var_name}' from line {assign_node.start_line} passed into {identifier}()."
                            break

            # Check subprocess calls with shell=True
            elif "subprocess" in identifier or any(sub in identifier for sub in ("Popen", "run", "call", "check_output")):
                if "shell=True" in call_text or "shell = True" in call_text:
                    if "+" in call_text or any(var in call_text for var in dynamic_vars.keys()):
                        is_unsafe = True
                        evidence = f"subprocess execution with shell=True and dynamic input: {call_text.splitlines()[0]}"

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
