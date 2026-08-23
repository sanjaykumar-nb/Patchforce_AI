"""
PatchForge AI - Rule: PY-PATH-001 (Python Path Traversal)
=========================================================
CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal').
Detects unvalidated filesystem path construction in open(), os.remove(), etc.
"""

from typing import List
from app.ast_engine.base import BaseASTParser
from app.models.vulnerability import SeverityLevel
from app.scanners.rules.base_rule import BaseRule, Finding


class PythonPathTraversalRule(BaseRule):
    """Detects path traversal vulnerabilities in Python filesystem operations."""

    def __init__(self):
        super().__init__(
            rule_id="PY-PATH-001",
            cwe="CWE-22",
            severity=SeverityLevel.HIGH,
            cvss_score=7.5,
            description="Unvalidated filesystem path concatenation allows directory traversal attacks.",
            language="python",
        )

    def analyze(self, source_code: str, file_path: str, parser: BaseASTParser) -> List[Finding]:
        findings: List[Finding] = []
        calls = parser.get_calls(source_code)
        assignments = parser.get_assignments(source_code)

        path_vars = {}
        for assign in assignments:
            assign_text = assign.text
            if ("/" in assign_text or "\\" in assign_text) and ("+" in assign_text or "f\"" in assign_text or "f'" in assign_text):
                if not any(safe_fn in assign_text for safe_fn in ("os.path.basename", "Path.resolve", "os.path.abspath")):
                    var_name = assign_text.split("=")[0].strip()
                    path_vars[var_name] = assign

        for call in calls:
            identifier = call.identifier or ""
            call_text = call.text
            is_unsafe = False
            evidence = ""

            if identifier in ("open", "io.open", "os.remove", "os.unlink", "shutil.rmtree"):
                # Check for direct concatenation in open("/data/" + filename)
                if ("+" in call_text or "f\"" in call_text or "f'" in call_text) and ("/" in call_text or "\\" in call_text):
                    if not any(safe_fn in call_text for safe_fn in ("os.path.basename", "Path.resolve", "os.path.abspath")):
                        is_unsafe = True
                        evidence = f"Direct unvalidated path concatenation in {identifier}(): {call_text.splitlines()[0]}"

                if not is_unsafe:
                    for var_name, assign_node in path_vars.items():
                        if f"({var_name}" in call_text:
                            is_unsafe = True
                            evidence = f"Path variable '{var_name}' constructed without boundary validation at line {assign_node.start_line}."
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
