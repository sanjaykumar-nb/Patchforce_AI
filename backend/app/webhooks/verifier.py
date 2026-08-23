"""
PatchForge AI - Cryptographic Webhook Verifier
==============================================
Validates HMAC-SHA256 signatures for inbound GitHub/GitLab webhook events
using constant-time comparisons to eliminate timing side-channel attacks.
"""

import hmac
import hashlib
from typing import Optional
from app.config import get_settings
from app.core.logging import get_logger

logger = get_logger("patchforge.webhooks.verifier")
settings = get_settings()


def compute_github_signature(payload_bytes: bytes, secret: Optional[str] = None) -> str:
    """Computes the expected GitHub X-Hub-Signature-256 header string."""
    key = (secret or settings.GITHUB_WEBHOOK_SECRET).encode("utf-8")
    mac = hmac.new(key, msg=payload_bytes, digestmod=hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def verify_github_signature(
    payload_bytes: bytes,
    signature_header: Optional[str],
    secret: Optional[str] = None,
) -> bool:
    """
    Verifies that the inbound request signature matches the calculated HMAC-SHA256
    using constant-time comparison (hmac.compare_digest).
    """
    if not signature_header or not signature_header.startswith("sha256="):
        logger.warning("Missing or malformed X-Hub-Signature-256 header.")
        return False

    expected_signature = compute_github_signature(payload_bytes, secret)
    is_valid = hmac.compare_digest(expected_signature, signature_header)

    if not is_valid:
        logger.warning("HMAC-SHA256 signature mismatch for webhook payload.")

    return is_valid
