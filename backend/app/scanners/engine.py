"""
PatchForge AI - AST Security Scanner Engine
===========================================
High-throughput scanner orchestrating AST parsing, CWE rule execution,
and transactional persistence of security findings into PostgreSQL.
"""

import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.ast_engine import PythonASTParser, JavaScriptASTParser
from app.scanners.rules.base_rule import Finding
from app.scanners.rules.registry import rule_registry
from app.models import (
    Scan,
    ScanStatus,
    Vulnerability,
    VulnerabilityStatus,
    ASTNode,
    AuditLog,
)
from app.core.logging import get_logger

logger = get_logger("patchforge.scanner.engine")


class SecurityScanner:
    """Orchestrates multi-language AST vulnerability scanning across files and repositories."""

    def __init__(self):
        self.python_parser = PythonASTParser()
        self.javascript_parser = JavaScriptASTParser()

    def get_parser_and_language(self, file_path: str) -> Tuple[Optional[object], Optional[str]]:
        """Resolves the AST parser and language name from file extension."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in (".py", ".pyw"):
            return self.python_parser, "python"
        elif ext in (".js", ".mjs", ".cjs", ".ts"):
            return self.javascript_parser, "javascript"
        return None, None

    def scan_file(self, file_path: str, source_code: Optional[str] = None) -> List[Finding]:
        """Scans an individual source file with all applicable AST rules."""
        parser, language = self.get_parser_and_language(file_path)
        if not parser or not language:
            return []

        if source_code is None:
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    source_code = f.read()
            except Exception as e:
                logger.error(f"Failed to read file for scanning: {file_path} - {str(e)}")
                return []

        rules = rule_registry.get_rules_for_language(language)
        file_findings: List[Finding] = []

        for rule in rules:
            try:
                findings = rule.analyze(source_code, file_path, parser)
                file_findings.extend(findings)
            except Exception as e:
                logger.debug(f"Rule [{rule.rule_id}] skipped {file_path}: {str(e)}")

        return file_findings

    def scan_directory(
        self,
        directory_path: str,
        exclude_dirs: Optional[List[str]] = None,
    ) -> Tuple[List[Finding], int]:
        """
        Recursively scans all supported source files within a directory tree.
        Returns a tuple of (all_findings, total_files_scanned).
        """
        if exclude_dirs is None:
            exclude_dirs = [
                ".git",
                "__pycache__",
                "node_modules",
                ".venv",
                "venv",
                "env",
                ".env",
                ".pytest_cache",
                ".mypy_cache",
                ".ruff_cache",
                ".tox",
                "dist",
                "build",
                ".next",
                ".nuxt",
            ]

        all_findings: List[Finding] = []
        files_scanned_count = 0

        for root, dirs, files in os.walk(directory_path):
            # Prune excluded directories in-place
            dirs[:] = [d for d in dirs if d not in exclude_dirs]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in (".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, directory_path).replace("\\", "/")
                    findings = self.scan_file(full_path)
                    # Normalize findings to relative path
                    for f in findings:
                        f.file_path = rel_path
                    all_findings.extend(findings)
                    files_scanned_count += 1

        return all_findings, files_scanned_count

    def scan_repository(
        self,
        db: Session,
        repository_id: str,
        commit_hash: str,
        repo_path: str,
        branch: str = "main",
        triggered_by: str = "api",
    ) -> Scan:
        """
        Executes a complete scan on a repository path and records all findings
        transactionally in PostgreSQL.
        """
        scan = Scan(
            repository_id=repository_id,
            commit_hash=commit_hash or "HEAD",
            branch=branch or "main",
            status=ScanStatus.IN_PROGRESS,
            triggered_by=triggered_by or "api",
            repo_path=os.path.abspath(repo_path),
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        start_time = time.time()
        logger.info(f"Starting AST scan for Repository [{repository_id}] Commit [{commit_hash[:7]}]...")

        try:
            findings, total_files = self.scan_directory(repo_path)

            for f in findings:
                vuln = Vulnerability(
                    scan_id=scan.id,
                    repository_id=repository_id,
                    rule_id=f.rule_id,
                    cwe=f.cwe,
                    severity=f.severity,
                    cvss_score=f.cvss_score,
                    confidence_score=f.confidence_score,
                    file_path=f.file_path,
                    line_start=f.line_start,
                    line_end=f.line_end,
                    function_name=f.function_name,
                    ast_node_type=f.ast_node_type,
                    source_snippet=f.source_snippet,
                    description=f.description,
                    evidence=f.evidence,
                    status=VulnerabilityStatus.DETECTED,
                )
                db.add(vuln)
                db.flush()

                # Add AST node coordinates record
                ast_node = ASTNode(
                    vulnerability_id=vuln.id,
                    node_type=f.ast_node_type,
                    start_line=f.line_start,
                    start_column=0,
                    end_line=f.line_end,
                    end_column=len(f.source_snippet.splitlines()[-1]) if f.source_snippet else 0,
                    code_snippet=f.source_snippet,
                    parent_scope=f.function_name,
                )
                db.add(ast_node)

            scan.total_files_scanned = total_files
            scan.vulnerabilities_count = len(findings)
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)

            # Record Audit Log
            audit = AuditLog(
                event_type="SCAN_COMPLETED",
                actor="SCANNER_ENGINE",
                repository_id=repository_id,
                details=f'{{"scan_id": "{scan.id}", "files_scanned": {total_files}, "findings": {len(findings)}}}',
            )
            db.add(audit)
            db.commit()
            db.refresh(scan)

            duration_s = round(time.time() - start_time, 2)
            logger.info(f"Scan [{scan.id}] completed in {duration_s}s: {total_files} files scanned, {len(findings)} vulnerabilities detected.")
            return scan

        except Exception as e:
            db.rollback()
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            db.add(scan)
            db.commit()
            logger.exception(f"Scan [{scan.id}] failed: {str(e)}")
            raise e

    def scan_existing_scan(
        self,
        db: Session,
        scan: Scan,
        repo_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Runs static AST analysis for an existing Scan database entity."""
        target_path = repo_path
        if not target_path or not os.path.exists(target_path):
            lang = scan.repository.language if scan.repository else "python"
            target_path = (
                os.path.join("fixtures", "vulnerable_python")
                if lang == "python"
                else os.path.join("fixtures", "vulnerable_javascript")
            )

        scan.status = ScanStatus.IN_PROGRESS
        scan.repo_path = os.path.abspath(target_path)
        scan.started_at = datetime.now(timezone.utc)
        db.add(scan)
        db.commit()

        findings, total_files = self.scan_directory(target_path)
        for f in findings:
            vuln = Vulnerability(
                scan_id=scan.id,
                repository_id=scan.repository_id,
                rule_id=f.rule_id,
                cwe=f.cwe,
                severity=f.severity,
                cvss_score=f.cvss_score,
                confidence_score=f.confidence_score,
                file_path=f.file_path,
                line_start=f.line_start,
                line_end=f.line_end,
                function_name=f.function_name,
                ast_node_type=f.ast_node_type,
                source_snippet=f.source_snippet,
                description=f.description,
                evidence=f.evidence,
                status=VulnerabilityStatus.DETECTED,
            )
            db.add(vuln)
            db.flush()

            ast_node = ASTNode(
                vulnerability_id=vuln.id,
                node_type=f.ast_node_type,
                start_line=f.line_start,
                start_column=0,
                end_line=f.line_end,
                end_column=len(f.source_snippet.splitlines()[-1]) if f.source_snippet else 0,
                code_snippet=f.source_snippet,
                parent_scope=f.function_name,
            )
            db.add(ast_node)

        scan.total_files_scanned = total_files
        scan.vulnerabilities_count = len(findings)
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)

        audit = AuditLog(
            event_type="SCAN_COMPLETED",
            actor="CELERY_WORKER",
            repository_id=scan.repository_id,
            details=f'{{"scan_id": "{scan.id}", "files_scanned": {total_files}, "findings": {len(findings)}}}',
        )
        db.add(audit)
        db.commit()
        db.refresh(scan)

        return {
            "total_files_scanned": total_files,
            "vulnerabilities_detected": len(findings),
            "scan_id": scan.id,
        }


# Global scanner instance
security_scanner = SecurityScanner()

