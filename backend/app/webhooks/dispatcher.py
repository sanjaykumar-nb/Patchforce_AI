"""
PatchForge AI - Webhook Event Dispatcher
========================================
Routes verified GitHub webhook payloads to automatic repository ingestion,
AST static scans, and continuous autonomous remediation pipelines.
"""

from typing import Dict, Any
from sqlalchemy.orm import Session

from app.models import Repository, Scan, ScanStatus, AuditLog
from app.scanners.engine import security_scanner
from app.core.logging import get_logger

logger = get_logger("patchforge.webhooks.dispatcher")


class WebhookDispatcher:
    """Dispatches verified inbound webhook events to scanning and remediation pipelines."""

    def handle_github_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        db: Session,
    ) -> Dict[str, Any]:
        """Processes GitHub webhook event payloads."""
        logger.info(f"Processing inbound GitHub webhook event [{event_type}]...")

        # 1. Ping Event
        if event_type == "ping":
            zen = payload.get("zen", "Security is priority.")
            logger.info(f"GitHub ping event received: '{zen}'")
            return {
                "status": "OK",
                "event": "ping",
                "message": "Webhook handshake verified successfully.",
                "zen": zen,
            }

        # 2. Push Event (Continuous Integration Security Trigger)
        if event_type == "push":
            repo_data = payload.get("repository", {})
            full_name = repo_data.get("full_name")
            name = repo_data.get("name") or "webhook-repo"
            url = repo_data.get("html_url") or f"https://github.com/{full_name}"
            clone_url = repo_data.get("clone_url") or f"https://github.com/{full_name}.git"
            language = (repo_data.get("language") or "python").lower()

            if not full_name:
                return {"status": "FAILED", "error": "Missing repository.full_name in payload"}

            # Upsert Repository entity
            repo = db.query(Repository).filter_by(full_name=full_name).first()
            if not repo:
                repo = Repository(
                    name=name,
                    full_name=full_name,
                    url=url,
                    clone_url=clone_url,
                    language=language,
                )
                db.add(repo)
                db.commit()
                db.refresh(repo)

            # Extract commit & branch details
            commit_hash = payload.get("after") or payload.get("head_commit", {}).get("id") or "HEAD"
            ref = payload.get("ref", "refs/heads/main")
            branch = ref.replace("refs/heads/", "")

            # Create and trigger AST security scan
            scan = Scan(
                repository_id=repo.id,
                commit_hash=commit_hash[:40],
                branch=branch,
                status=ScanStatus.PENDING,
                triggered_by="WEBHOOK_PUSH",
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)

            # Execute static AST scan
            summary = security_scanner.scan_existing_scan(db=db, scan=scan)

            # Record Audit Log
            audit = AuditLog(
                event_type="WEBHOOK_PUSH_PROCESSED",
                actor="WEBHOOK_DISPATCHER",
                repository_id=repo.id,
                details=f'{{"scan_id": "{scan.id}", "commit": "{commit_hash[:7]}", "vulns": {summary.get("vulnerabilities_detected", 0)}}}',
            )
            db.add(audit)
            db.commit()

            return {
                "status": "PROCESSED",
                "event": "push",
                "repository": repo.full_name,
                "scan_id": scan.id,
                "commit_hash": commit_hash[:7],
                "vulnerabilities_detected": summary.get("vulnerabilities_detected", 0),
            }

        # 3. Pull Request Event
        if event_type == "pull_request":
            action = payload.get("action", "opened")
            pr_data = payload.get("pull_request", {})
            pr_num = pr_data.get("number")
            logger.info(f"PR event received: #{pr_num} action={action}")
            return {
                "status": "PROCESSED",
                "event": "pull_request",
                "action": action,
                "pr_number": pr_num,
            }

        # Other events
        return {
            "status": "IGNORED",
            "event": event_type,
            "message": f"Event type '{event_type}' ignored.",
        }


# Global dispatcher singleton
webhook_dispatcher = WebhookDispatcher()
