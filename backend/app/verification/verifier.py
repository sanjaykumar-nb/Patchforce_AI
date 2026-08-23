"""
PatchForge AI - Safe Dynamic Exploit Verification Service
========================================================
Orchestrates isolated dynamic PoC execution in Docker sandboxes
to confirm exploitability and eliminate false positives.
"""

import os
from typing import Dict, Optional
from sqlalchemy.orm import Session

from app.models import (
    Vulnerability,
    VulnerabilityStatus,
    ExploitVerification,
    AuditLog,
)
from app.sandbox import docker_sandbox_runner
from app.verification.poc_generator import poc_generator
from app.core.logging import get_logger

logger = get_logger("patchforge.verification.verifier")


class ExploitVerifier:
    """Safely executes controlled PoC harnesses to verify vulnerability findings."""

    def verify_vulnerability(
        self,
        db: Session,
        vulnerability: Vulnerability,
        source_code_override: Optional[str] = None,
        additional_files: Optional[Dict[str, str]] = None,
    ) -> ExploitVerification:
        """
        Executes dynamic PoC against the target file in the sandbox and records results.
        """
        logger.info(f"Initiating dynamic PoC verification for Vulnerability [{vulnerability.id}] ({vulnerability.cwe})...")

        # Determine language
        ext = os.path.splitext(vulnerability.file_path)[1].lower()
        is_python = ext in (".py", ".pyw") or not ext

        # Read target source code
        target_basename = os.path.basename(vulnerability.file_path)
        if not target_basename.endswith(".py") and not target_basename.endswith(".js"):
            target_basename += ".py" if is_python else ".js"

        if source_code_override:
            source_content = source_code_override
        else:
            try:
                # Resolve full path on disk
                target_disk_path = vulnerability.file_path
                if not os.path.exists(target_disk_path):
                    # Check in fixtures folder
                    alt_path = os.path.join("fixtures", "vulnerable_python", target_basename)
                    if os.path.exists(alt_path):
                        target_disk_path = alt_path
                    else:
                        alt_path_js = os.path.join("fixtures", "vulnerable_javascript", target_basename)
                        if os.path.exists(alt_path_js):
                            target_disk_path = alt_path_js

                if os.path.exists(target_disk_path):
                    with open(target_disk_path, "r", encoding="utf-8", errors="replace") as f:
                        source_content = f.read()
                else:
                    source_content = vulnerability.source_snippet
            except Exception as e:
                logger.error(f"Failed to read source file for verification: {str(e)}")
                source_content = vulnerability.source_snippet

        # Generate PoC harness files
        sandbox_files: Dict[str, str] = {
            target_basename: source_content,
        }
        if additional_files:
            sandbox_files.update(additional_files)

        if is_python:
            poc_files = poc_generator.generate_python_poc(
                cwe=vulnerability.cwe,
                file_path=target_basename,
                function_name=vulnerability.function_name,
            )
            sandbox_files.update(poc_files)
            command = "python run_poc.py"
            lang = "python"
        else:
            poc_files = poc_generator.generate_javascript_poc(
                cwe=vulnerability.cwe,
                file_path=target_basename,
                function_name=vulnerability.function_name,
            )
            sandbox_files.update(poc_files)
            command = "node run_poc.js"
            lang = "javascript"

        # Execute inside ephemeral Docker sandbox
        result = docker_sandbox_runner.run_code(
            language=lang,
            files=sandbox_files,
            command=command,
            timeout=15,
        )

        is_verified = (result.exit_code == 0) and ("[PATCHFORGE_POC_CONFIRMED]" in result.stdout)

        poc_summary = (
            f"Dynamic PoC {'CONFIRMED' if is_verified else 'FAILED'} for {vulnerability.cwe} "
            f"in {vulnerability.file_path}:{vulnerability.line_start}. (Exit code: {result.exit_code})"
        )

        # Create ExploitVerification record
        verification = ExploitVerification(
            vulnerability_id=vulnerability.id,
            sandbox_container_id=result.container_id,
            verified=is_verified,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            execution_time_ms=result.execution_time_ms,
            poc_summary=poc_summary,
        )
        db.add(verification)

        # Update vulnerability status if verified
        if is_verified:
            vulnerability.status = VulnerabilityStatus.VERIFIED
            db.add(vulnerability)

        # Audit log
        audit = AuditLog(
            event_type="POC_VERIFICATION",
            actor="EXPLOIT_VERIFIER",
            repository_id=vulnerability.repository_id,
            vulnerability_id=vulnerability.id,
            details=f'{{"verified": {str(is_verified).lower()}, "cwe": "{vulnerability.cwe}", "execution_time_ms": {result.execution_time_ms}}}',
        )
        db.add(audit)
        db.commit()
        db.refresh(verification)

        logger.info(f"Verification completed for Vulnerability [{vulnerability.id}]: Verified={is_verified}")
        return verification


# Global singleton instance
exploit_verifier = ExploitVerifier()
