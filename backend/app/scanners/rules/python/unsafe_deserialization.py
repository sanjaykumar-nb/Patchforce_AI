"""
PatchForge AI - Rule: PY-DESER-001 (Python Unsafe Deserialization)
=================================================================
CWE-502: Deserialization of Untrusted Data.
Detects dangerous deserialization via pickle.loads or unsafe yaml.load.
"""

from typing import List
from app.ast_engine.base import BaseASTParser
from app.models.vulnerability import SeverityLevel
from app.scanners.rules.base_rule import BaseRule, Finding


class PythonUnsafeDeserializationRule(BaseRule):
    """Detects unsafe object deserialization in Python."""

    def __init__(self):
        super().__init__(
            rule_id="PY-DESER-001",
            cwe="CWE-502",
            severity=SeverityLevel.CRITICAL,
            cvss_score=9.8,
            description="Deserialization of untrusted data using unsafe serialization engines (e.g. pickle, unsafe YAML).",
            language="python",
        )

    def analyze(self, source_code: str, file_path: str, parser: BaseASTParser) -> List[Finding]:
        findings: List[Finding] = []
        calls = parser.get_calls(source_code)

        for call in calls:
            identifier = call.identifier or ""
            call_text = call.text
            is_unsafe = False
            evidence = ""

            # Check pickle.loads / pickle.load
            if any(target in identifier for target in ("pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load")):
                is_unsafe = True
                evidence = f"Unsafe object deserialization call {identifier}() detected."

            # Check yaml.load without SafeLoader
            elif "yaml.load" in identifier and "SafeLoader" not in call_text:
                is_unsafe = True
                evidence = f"yaml.load() invoked without SafeLoader: {call_text.splitlines()[0]}"

            # Check marshal / shelve
            elif any(target in identifier for target in ("marshal.loads", "shelve.open")):
                is_unsafe = True
                evidence = f"Dangerous native Python deserializer {identifier}() detected."

            if is_unsafe:
                enclosing = parser.find_enclosing_function(source_code, call.start_line)
                confidence = self.calculate_confidence({
                    "direct_call_match": True,
                    "string_concatenation": False,
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
