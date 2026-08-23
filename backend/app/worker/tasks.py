"""
PatchForge AI - Celery Distributed Task Definitions
===================================================
Asynchronous background tasks for static security scanning, dynamic sandbox PoC
exploit verification, and autonomous multi-stage patch generation & validation.
"""

from typing import Any, Dict
from celery import shared_task
from app.database import SessionLocal
from app.models import Scan, Vulnerability, ScanStatus
from app.scanners.engine import security_scanner
from app.verification.verifier import exploit_verifier
from app.remediation.patch_generator import patch_generator
from app.validation.validator import patch_validator
from app.core.logging import get_logger

logger = get_logger("patchforge.worker.tasks")


@shared_task(name="app.worker.tasks.task_run_security_scan", bind=True)
def task_run_security_scan(self, scan_id: str) -> Dict[str, Any]:
    """
    Executes a comprehensive AST static security scan in the background.
    """
    logger.info(f"[Task {self.request.id}] Starting security scan for Scan ID [{scan_id}]...")
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            logger.error(f"Scan ID [{scan_id}] not found in database.")
            return {"status": "FAILED", "error": f"Scan {scan_id} not found"}

        repo = scan.repository
        if not repo:
            logger.error(f"Repository for Scan [{scan_id}] not found.")
            return {"status": "FAILED", "error": "Repository not found"}

        summary = security_scanner.scan_existing_scan(db=db, scan=scan)
        logger.info(f"[Task {self.request.id}] Scan [{scan_id}] finished. Vulns detected: {summary.get('vulnerabilities_detected', 0)}")
        return {
            "status": "COMPLETED",
            "scan_id": scan_id,
            "summary": summary,
        }
    except Exception as exc:
        logger.exception(f"[Task {self.request.id}] Scan execution failed: {str(exc)}")
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)
            db.add(scan)
            db.commit()
        return {"status": "FAILED", "error": str(exc)}
    finally:
        db.close()


@shared_task(name="app.worker.tasks.task_verify_vulnerability", bind=True)
def task_verify_vulnerability(self, vulnerability_id: str) -> Dict[str, Any]:
    """
    Executes dynamic exploit verification inside an isolated ephemeral Docker sandbox.
    """
    logger.info(f"[Task {self.request.id}] Verifying exploitability for Vulnerability ID [{vulnerability_id}]...")
    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter_by(id=vulnerability_id).first()
        if not vuln:
            return {"status": "FAILED", "error": f"Vulnerability {vulnerability_id} not found"}

        verification = exploit_verifier.verify_vulnerability(db=db, vulnerability=vuln)
        return {
            "status": "COMPLETED",
            "vulnerability_id": vulnerability_id,
            "verified": verification.verified,
            "vuln_status": vuln.status.value,
        }
    except Exception as exc:
        logger.exception(f"[Task {self.request.id}] Verification failed: {str(exc)}")
        return {"status": "FAILED", "error": str(exc)}
    finally:
        db.close()


@shared_task(name="app.worker.tasks.task_generate_and_validate_patch", bind=True)
def task_generate_and_validate_patch(self, vulnerability_id: str) -> Dict[str, Any]:
    """
    Orchestrates full autonomous remediation pipeline:
    1. Generates AST-targeted patch with Code LLM
    2. Runs 4-stage validation pipeline
    3. Scores and updates Patch status
    """
    logger.info(f"[Task {self.request.id}] Generating and validating patch for Vulnerability [{vulnerability_id}]...")
    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter_by(id=vulnerability_id).first()
        if not vuln:
            return {"status": "FAILED", "error": f"Vulnerability {vulnerability_id} not found"}

        # 1. Generate patch
        patch = patch_generator.generate_patch_for_vulnerability(db=db, vulnerability=vuln)

        # 2. Validate patch
        report = patch_validator.validate_patch(db=db, patch=patch)

        return {
            "status": "COMPLETED",
            "vulnerability_id": vulnerability_id,
            "patch_id": patch.id,
            "composite_score": report.composite_score,
            "patch_status": report.status.value,
            "syntax_valid": report.syntax_valid,
            "ast_valid": report.ast_valid,
            "rescan_clean": report.rescan_clean,
        }
    except Exception as exc:
        logger.exception(f"[Task {self.request.id}] Remediation pipeline failed: {str(exc)}")
        return {"status": "FAILED", "error": str(exc)}
    finally:
        db.close()
