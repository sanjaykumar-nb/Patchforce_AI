"""
PatchForge AI - Phase 17 Authentication & RBAC Unit Tests
=========================================================
Validates bcrypt password hashing, JWT creation & decoding, registration/login lifecycle,
and Role-Based Access Control (RBAC) permission enforcement.
"""

import uuid
from datetime import timedelta
import pytest
from fastapi.testclient import TestClient
from fastapi import Depends, APIRouter

from app.main import app
from app.models.user import User, UserRole
from app.core.security import get_password_hash, verify_password, create_access_token, decode_access_token
from app.core.deps import get_current_user, require_roles

client = TestClient(app)

# Test router to verify RBAC protection
rbac_router = APIRouter(prefix="/test-rbac")


@rbac_router.get("/admin-only")
def admin_only_endpoint(current_user: User = Depends(require_roles(UserRole.ADMIN))):
    return {"message": "Admin clearance granted", "user": current_user.email}


@rbac_router.get("/engineer-or-admin")
def engineer_endpoint(
    current_user: User = Depends(require_roles(UserRole.SECURITY_ENGINEER, UserRole.ADMIN))
):
    return {"message": "Security clearance granted", "user": current_user.email}


app.include_router(rbac_router)


def test_bcrypt_hash_and_verify():
    password = "SuperSecretPassword123!"
    hashed = get_password_hash(password)
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_create_and_decode():
    payload = {"sub": "developer@patchforge.ai", "role": "DEVELOPER"}
    token = create_access_token(payload, expires_delta=timedelta(minutes=15))

    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded["sub"] == "developer@patchforge.ai"
    assert decoded["role"] == "DEVELOPER"

    # Expired token test
    expired_token = create_access_token(payload, expires_delta=timedelta(seconds=-1))
    assert decode_access_token(expired_token) is None


def test_user_registration_and_login_lifecycle():
    unique_email = f"secops-{uuid.uuid4().hex[:8]}@patchforge.ai"
    password = "SecOpsMasterPass#2026"

    # 1. Register User. A requested elevated role must be ignored - self-registration
    # always yields DEVELOPER, otherwise any caller could grant themselves ADMIN.
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": unique_email,
            "password": password,
            "full_name": "Security Officer",
            "role": "SECURITY_ENGINEER",
        },
    )
    assert reg_resp.status_code == 201
    user_data = reg_resp.json()
    assert user_data["email"] == unique_email
    assert user_data["role"] == "DEVELOPER"

    # 2. Duplicate Registration Rejection
    dup_resp = client.post(
        "/api/v1/auth/register",
        json={"email": unique_email, "password": password},
    )
    assert dup_resp.status_code == 400

    # 3. Login with Invalid Credentials
    bad_login = client.post(
        "/api/v1/auth/login",
        json={"email": unique_email, "password": "WrongPassword!"},
    )
    assert bad_login.status_code == 401

    # 4. Login with Valid Credentials
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": unique_email, "password": password},
    )
    assert login_resp.status_code == 200
    token_data = login_resp.json()
    assert "access_token" in token_data
    access_token = token_data["access_token"]

    # 5. Access /auth/me with Bearer Token
    me_resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == unique_email


def test_rbac_role_enforcement(admin_auth_headers):
    # Create Developer user via public self-registration (always lands as DEVELOPER)
    dev_email = f"dev-{uuid.uuid4().hex[:8]}@patchforge.ai"
    dev_pass = "DevPass12345!"
    client.post(
        "/api/v1/auth/register",
        json={"email": dev_email, "password": dev_pass},
    )
    dev_token = client.post(
        "/api/v1/auth/login",
        json={"email": dev_email, "password": dev_pass},
    ).json()["access_token"]

    # Admin user: elevated roles are no longer assignable through self-registration
    # (see test_user_registration_and_login_lifecycle), so this uses the shared
    # admin_auth_headers fixture, which seeds the user directly in the database -
    # the same way a real admin-promotion flow would, once one exists.
    admin_headers = admin_auth_headers

    # 1. Developer tries to access /test-rbac/admin-only -> 403 Forbidden
    dev_forbidden = client.get(
        "/test-rbac/admin-only",
        headers={"Authorization": f"Bearer {dev_token}"},
    )
    assert dev_forbidden.status_code == 403

    # 2. Admin accesses /test-rbac/admin-only -> 200 OK
    admin_ok = client.get(
        "/test-rbac/admin-only",
        headers=admin_headers,
    )
    assert admin_ok.status_code == 200
    assert admin_ok.json()["message"] == "Admin clearance granted"
