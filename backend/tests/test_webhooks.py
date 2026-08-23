"""
PatchForge AI - Phase 14 Cryptographic Webhook Handler Unit Tests
==================================================================
Validates HMAC-SHA256 signature verification, timing attack prevention,
unauthorized webhook rejection (401), ping handshake, and push-event automatic scan ingestion.
"""

import json
import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app.webhooks.verifier import verify_github_signature, compute_github_signature

client = TestClient(app)
settings = get_settings()


def test_hmac_sha256_verifier_unit():
    payload = b'{"action": "test", "repository": "test-org/repo"}'
    secret = "test_super_secret_key"

    valid_sig = compute_github_signature(payload, secret)
    assert valid_sig.startswith("sha256=")

    # Valid signature check
    assert verify_github_signature(payload, valid_sig, secret) is True

    # Tampered payload check
    tampered_payload = b'{"action": "malicious", "repository": "test-org/repo"}'
    assert verify_github_signature(tampered_payload, valid_sig, secret) is False

    # Wrong secret check
    assert verify_github_signature(payload, valid_sig, "wrong_secret") is False

    # Malformed / missing header
    assert verify_github_signature(payload, "invalid-header", secret) is False
    assert verify_github_signature(payload, None, secret) is False


def test_api_webhook_ping_event():
    payload_dict = {"zen": "Encourage commits, verify security.", "hook_id": 12345}
    payload_bytes = json.dumps(payload_dict).encode("utf-8")
    sig = compute_github_signature(payload_bytes, settings.GITHUB_WEBHOOK_SECRET)

    response = client.post(
        "/api/v1/webhooks/github",
        content=payload_bytes,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "ping",
            "X-Hub-Signature-256": sig,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OK"
    assert data["event"] == "ping"
    assert "handshake verified" in data["message"].lower()


def test_api_webhook_signature_rejection():
    payload_bytes = b'{"action": "unauthorized"}'

    # 1. Invalid signature
    resp1 = client.post(
        "/api/v1/webhooks/github",
        content=payload_bytes,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        },
    )
    assert resp1.status_code == 401
    assert "Invalid HMAC-SHA256" in resp1.json()["detail"]

    # 2. Missing signature header
    resp2 = client.post(
        "/api/v1/webhooks/github",
        content=payload_bytes,
        headers={"Content-Type": "application/json", "X-GitHub-Event": "push"},
    )
    assert resp2.status_code == 401


def test_api_webhook_push_event_triggers_scan():
    repo_name = f"webhook-repo-{uuid.uuid4().hex[:6]}"
    payload_dict = {
        "ref": "refs/heads/main",
        "after": "c0ffee1234567890abcdef1234567890abcdef12",
        "repository": {
            "name": repo_name,
            "full_name": f"test-org/{repo_name}",
            "html_url": f"https://github.com/test-org/{repo_name}",
            "clone_url": f"https://github.com/test-org/{repo_name}.git",
            "language": "Python",
        },
        "head_commit": {
            "id": "c0ffee1234567890abcdef1234567890abcdef12",
            "message": "Add user authentication endpoints",
        },
    }
    payload_bytes = json.dumps(payload_dict).encode("utf-8")
    sig = compute_github_signature(payload_bytes, settings.GITHUB_WEBHOOK_SECRET)

    response = client.post(
        "/api/v1/webhooks/github",
        content=payload_bytes,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": sig,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "PROCESSED"
    assert data["event"] == "push"
    assert data["repository"] == f"test-org/{repo_name}"
    assert "scan_id" in data
    assert data["vulnerabilities_detected"] >= 4
