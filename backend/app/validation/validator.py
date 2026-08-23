"""
PatchForge AI - Multi-Stage Patch Validator Engine
==================================================
Implements 4-stage automated patch verification:
1. Syntax Validation (ast.parse / node -c)
2. AST Structural Integrity (preservation of surrounding AST nodes)
3. Sandboxed Dynamic Verification & Unit Tests
4. Security Re-Scan (confirming 0 remaining CWE findings)
Computes an objective composite confidence score (0-100) and updates patch status.
"""

import ast
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models import (
    Patch,
    PatchStatus,
    Vulnerability,
    TestRun,
    AuditLog,
)
from app.ast_engine import PythonASTParser, JavaScriptASTParser
from app.scanners.engine import security_scanner
from app.sandbox import docker_sandbox_runner
from app.verification import poc_generator
from app.remediation.diff_utils import merge_imports, splice_function_replacement
from app.core.source_resolver import read_source_for_vulnerability
from app.core.logging import get_logger

logger = get_logger("patchforge.validation.validator")


@dataclass
class ValidationReport:
    """Consolidated summary of 4-stage validation pipeline."""
    patch_id: str
    syntax_valid: bool
    ast_valid: bool
    test_pass_rate: float
    rescan_clean: bool
    composite_score: float
    status: PatchStatus
    stage_logs: Dict[str, str] = field(default_factory=dict)


class PatchValidator:
    """Executes multi-stage validation on candidate remediation patches."""

    def __init__(self):
        self.py_parser = PythonASTParser()
        self.js_parser = JavaScriptASTParser()

    def _reconstruct_full_patched_file(
        self,
        vulnerability: Vulnerability,
        patch: Patch,
    ) -> Tuple[str, str]:
        """
        Reconstructs the full original source and full patched source.
        Returns (full_original, full_patched).
        """
        full_original = read_source_for_vulnerability(vulnerability)

        # Apply patch replacement
        replace_target = patch.old_code if patch.old_code.strip() in full_original else vulnerability.source_snippet
        patched = splice_function_replacement(
            full_source=full_original,
            old_function_code=replace_target,
            new_function_code=patch.new_code,
        )

        ext = os.path.splitext(vulnerability.file_path)[1].lower()
        lang = "python" if ext in (".py", ".pyw") or not ext else "javascript"

        # Check diff for new imports
        new_imports = []
        for line in patch.diff_content.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                l_strip = line[1:].strip()
                if l_strip.startswith("import ") or l_strip.startswith("from ") or "require(" in l_strip:
                    new_imports.append(l_strip)

        full_patched = merge_imports(patched, new_imports, language=lang)
        return full_original, full_patched

    def validate_stage1_syntax(self, patched_code: str, language: str) -> Tuple[bool, str]:
        """Stage 1: Validates language syntax."""
        if language == "python":
            try:
                ast.parse(patched_code)
                return True, "Python AST syntax parse succeeded."
            except SyntaxError as e:
                return False, f"SyntaxError on line {e.lineno}: {e.msg}"
        else:  # JavaScript
            tree = self.js_parser.parse(patched_code)
            if tree.root_node.has_error:
                return False, "JavaScript syntax contains parsing errors."
            return True, "JavaScript AST syntax check succeeded."

    def validate_stage2_ast_integrity(
        self,
        original_code: str,
        patched_code: str,
        language: str,
    ) -> Tuple[bool, str]:
        """Stage 2: Checks that surrounding functions and classes are intact."""
        parser = self.py_parser if language == "python" else self.js_parser

        orig_funcs = {f.identifier for f in parser.get_functions(original_code) if f.identifier}
        patched_funcs = {f.identifier for f in parser.get_functions(patched_code) if f.identifier}

        missing_funcs = orig_funcs - patched_funcs
        if missing_funcs:
            return False, f"AST structural mutation detected! Missing functions: {missing_funcs}"

        return True, "AST structural integrity confirmed. All surrounding scopes preserved."

    def validate_stage3_dynamic_tests(
        self,
        vulnerability: Vulnerability,
        patched_code: str,
        language: str,
    ) -> Tuple[float, str]:
        """
        Stage 3: Runs dynamic tests inside sandbox.
        For vulnerability PoC, the vulnerability should now be BLOCKED / safe.
        """
        base_name = os.path.basename(vulnerability.file_path)
        if not base_name.endswith(".py") and not base_name.endswith(".js"):
            base_name += ".py" if language == "python" else ".js"

        sandbox_files = {base_name: patched_code}

        if language == "python":
            poc_files = poc_generator.generate_python_poc(
                cwe=vulnerability.cwe,
                file_path=base_name,
                function_name=vulnerability.function_name,
            )
            sandbox_files.update(poc_files)
            command = "python run_poc.py"
        else:
            poc_files = poc_generator.generate_javascript_poc(
                cwe=vulnerability.cwe,
                file_path=base_name,
                function_name=vulnerability.function_name,
            )
            sandbox_files.update(poc_files)
            command = "node run_poc.js"

        res = docker_sandbox_runner.run_code(
            language=language,
            files=sandbox_files,
            command=command,
            timeout=10,
        )

        # Stage 3 must fail closed: absence of "[PATCHFORGE_POC_CONFIRMED]" is NOT
        # by itself evidence the patch is safe. A crashed/broken patched file also
        # fails to reproduce the exploit, so each PoC outcome marker is classified
        # explicitly instead of treating "not confirmed" as "neutralized".
        stdout = res.stdout

        if "[PATCHFORGE_POC_CONFIRMED]" in stdout:
            return 0.0, f"Dynamic PoC still succeeded against patched code. Flaw not resolved. (Output: {stdout.strip()})"

        if "[PATCHFORGE_POC_IMPORT_ERROR]" in stdout:
            return 0.0, f"Patched file failed to import/execute - the patch produced broken code, not a security fix. (Output: {stdout.strip()})"

        if "[POC_ERROR]" in stdout:
            return 0.0, f"Target function could not be located in the patched file - the patch likely removed or renamed it. (Output: {stdout.strip()})"

        if "[PATCHFORGE_POC_BLOCKED]" in stdout:
            return 1.0, f"Dynamic verification confirmed vulnerability is neutralized. (Output: {stdout.strip()})"

        if "[PATCHFORGE_POC_FAILED]" in stdout:
            # The payload ran without raising, but had no observable effect. This is
            # weaker evidence than an explicit BLOCKED signal - a silently broken
            # function (wrong return value, no-op) can look identical - so it earns
            # partial credit rather than a full pass.
            return 0.5, f"Exploit payload had no effect but no explicit security block was observed - inconclusive. (Output: {stdout.strip()})"

        # No recognizable marker at all: sandbox crash/timeout, unsupported CWE
        # ([PATCHFORGE_POC_SKIPPED]), or unexpected output. Treat as unresolved.
        return 0.0, f"Dynamic verification produced no conclusive signal - treating as unresolved. (Exit: {res.exit_code}, Timed out: {res.timed_out}, Output: {stdout.strip()[:300]})"

    def validate_stage4_security_rescan(
        self,
        vulnerability: Vulnerability,
        patched_code: str,
    ) -> Tuple[bool, str]:
        """Stage 4: Runs static scanner rules on patched source to ensure target flaw is resolved."""
        findings = security_scanner.scan_file(vulnerability.file_path, source_code=patched_code)

        # Target vulnerability finding in the remediated function
        target_fn_findings = [
            f for f in findings
            if (f.rule_id == vulnerability.rule_id or f.cwe == vulnerability.cwe)
            and (
                not vulnerability.function_name
                or f.function_name == vulnerability.function_name
            )
        ]

        if target_fn_findings:
            return False, f"Security re-scan failed: {len(target_fn_findings)} finding(s) of {vulnerability.cwe} still present in {vulnerability.function_name or 'file'}."

        return True, f"Security re-scan clean. Target vulnerability {vulnerability.cwe} successfully resolved."

    def validate_patch(
        self,
        db: Session,
        patch: Patch,
    ) -> ValidationReport:
        """
        Executes the full 4-stage validation pipeline on a candidate patch,
        persists test run records, updates patch status, and returns a ValidationReport.
        """
        vuln = db.query(Vulnerability).filter_by(id=patch.vulnerability_id).first()
        if not vuln:
            raise ValueError(f"Vulnerability {patch.vulnerability_id} not found for Patch {patch.id}")

        logger.info(f"Starting 4-stage validation pipeline for Patch [{patch.id}]...")

        ext = os.path.splitext(vuln.file_path)[1].lower()
        language = "python" if ext in (".py", ".pyw") or not ext else "javascript"

        # Reconstruct full files
        orig_code, patched_code = self._reconstruct_full_patched_file(vuln, patch)

        stage_logs = {}

        # -------------------------------------------------------------
        # Stage 1: Syntax Validation
        # -------------------------------------------------------------
        syntax_ok, syntax_log = self.validate_stage1_syntax(patched_code, language)
        stage_logs["stage1_syntax"] = syntax_log
        db.add(TestRun(
            patch_id=patch.id,
            test_type="syntax",
            test_command=f"syntax_check_{language}",
            passed=syntax_ok,
            total_tests=1,
            passed_tests=1 if syntax_ok else 0,
            failed_tests=0 if syntax_ok else 1,
            stdout=syntax_log,
        ))

        # -------------------------------------------------------------
        # Stage 2: AST Structural Integrity
        # -------------------------------------------------------------
        ast_ok, ast_log = self.validate_stage2_ast_integrity(orig_code, patched_code, language)
        stage_logs["stage2_ast"] = ast_log
        db.add(TestRun(
            patch_id=patch.id,
            test_type="ast_integrity",
            test_command="ast_scope_check",
            passed=ast_ok,
            total_tests=1,
            passed_tests=1 if ast_ok else 0,
            failed_tests=0 if ast_ok else 1,
            stdout=ast_log,
        ))

        # -------------------------------------------------------------
        # Stage 3: Dynamic Tests / PoC Neutralization
        # -------------------------------------------------------------
        test_rate, test_log = self.validate_stage3_dynamic_tests(vuln, patched_code, language)
        stage_logs["stage3_tests"] = test_log
        tests_passed = test_rate >= 1.0
        db.add(TestRun(
            patch_id=patch.id,
            test_type="dynamic_verification",
            test_command="sandbox_poc_neutralization",
            passed=tests_passed,
            total_tests=1,
            passed_tests=1 if tests_passed else 0,
            failed_tests=0 if tests_passed else 1,
            stdout=test_log,
        ))

        # -------------------------------------------------------------
        # Stage 4: Security Re-Scan
        # -------------------------------------------------------------
        rescan_ok, rescan_log = self.validate_stage4_security_rescan(vuln, patched_code)
        stage_logs["stage4_rescan"] = rescan_log
        db.add(TestRun(
            patch_id=patch.id,
            test_type="security_rescan",
            test_command="static_ast_rescan",
            passed=rescan_ok,
            total_tests=1,
            passed_tests=1 if rescan_ok else 0,
            failed_tests=0 if rescan_ok else 1,
            stdout=rescan_log,
        ))

        # -------------------------------------------------------------
        # Composite Score Calculation (0 - 100)
        # -------------------------------------------------------------
        syntax_score = 20.0 if syntax_ok else 0.0
        ast_score = 20.0 if ast_ok else 0.0
        test_score = 30.0 * test_rate
        rescan_score = 30.0 if rescan_ok else 0.0

        composite_score = round(syntax_score + ast_score + test_score + rescan_score, 2)
        is_validated = (composite_score >= 70.0) and syntax_ok and rescan_ok

        # Update Patch record
        patch.syntax_valid = syntax_ok
        patch.ast_valid = ast_ok
        patch.test_pass_rate = test_rate
        patch.rescan_clean = rescan_ok
        patch.patch_score = composite_score
        patch.status = PatchStatus.VALIDATED if is_validated else PatchStatus.REJECTED
        db.add(patch)

        # Record Audit Log
        audit = AuditLog(
            event_type="PATCH_VALIDATED" if is_validated else "PATCH_REJECTED",
            actor="PATCH_VALIDATOR",
            repository_id=vuln.repository_id,
            vulnerability_id=vuln.id,
            patch_id=patch.id,
            details=f'{{"composite_score": {composite_score}, "syntax_valid": {str(syntax_ok).lower()}, "rescan_clean": {str(rescan_ok).lower()}}}',
        )
        db.add(audit)
        db.commit()
        db.refresh(patch)

        logger.info(f"Validation for Patch [{patch.id}] complete. Score: {composite_score}/100. Status: {patch.status}")

        return ValidationReport(
            patch_id=patch.id,
            syntax_valid=syntax_ok,
            ast_valid=ast_ok,
            test_pass_rate=test_rate,
            rescan_clean=rescan_ok,
            composite_score=composite_score,
            status=patch.status,
            stage_logs=stage_logs,
        )


# Global singleton instance
patch_validator = PatchValidator()
