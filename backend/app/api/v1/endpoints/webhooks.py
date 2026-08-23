"""
PatchForge AI - Webhooks API Endpoints
======================================
Secure webhook receiver endpoints protected with cryptographic HMAC-SHA256 signature
verification for continuous DevSecOps automation.
"""

import json
from fastapi import APIRouter, Request, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.webhooks.verifier import verify_github_signature
from app.webhooks.dispatcher import webhook_dispatcher
from app.core.logging import get_logger

logger = get_logger("patchforge.api.webhooks")
router = APIRouter()


@router.post("/github", status_code=status.HTTP_200_OK, summary="GitHub Webhook Receiver")
async def github_webhook_receiver(request: Request, db: Session = Depends(get_db)):
    """
    Receives and processes GitHub webhook events.
    Enforces HMAC-SHA256 signature validation on the raw request body.
    """
    # 1. Read raw body bytes
    payload_bytes = await request.body()

    # 2. Extract GitHub security headers
    signature_header = request.headers.get("X-Hub-Signature-256")
    event_type = request.headers.get("X-GitHub-Event", "push")

    # 3. Cryptographic HMAC-SHA256 verification
    if not verify_github_signature(payload_bytes, signature_header):
        logger.warning("Rejected unauthorized webhook request: Invalid HMAC signature.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid HMAC-SHA256 webhook signature",
        )

    # 4. Parse JSON payload
    try:
        payload = json.loads(payload_bytes.decode("utf-8")) if payload_bytes else {}
    except Exception as e:
        logger.error(f"Malformed JSON payload in webhook: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed JSON payload")

    # 5. Dispatch event to scanning & remediation pipeline
    result = webhook_dispatcher.handle_github_event(
        event_type=event_type,
        payload=payload,
        db=db,
    )
    return result
