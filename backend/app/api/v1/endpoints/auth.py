"""
PatchForge AI - Authentication & Authorization REST Endpoints
=============================================================
Endpoints for user registration, JWT login authentication, and profile retrieval.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import get_settings
from app.models.user import User, UserRole
from app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    TokenResponse,
    GitHubTokenLoginRequest,
    OTPRequest,
    OTPVerifyRequest,
)
from app.core.security import get_password_hash, verify_password, create_access_token
from app.core.deps import get_current_user
from app.core.logging import get_logger

logger = get_logger("patchforge.api.auth")
settings = get_settings()
router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, summary="Register User")
def register_user(payload: UserRegisterRequest, db: Session = Depends(get_db)):
    """Registers a new platform user with bcrypt password hashing."""
    existing_user = db.query(User).filter_by(email=payload.email.lower().strip()).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists.",
        )

    # Role is never taken from client input - a self-registering caller could
    # otherwise request "ADMIN" and require_roles()'s ADMIN-bypass would grant
    # them access to every protected endpoint. Elevated roles must be assigned
    # by an existing admin through a separate, authenticated action.
    user = User(
        email=payload.email.lower().strip(),
        hashed_password=get_password_hash(payload.password),
        full_name=payload.full_name,
        role=UserRole.DEVELOPER,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info(f"User registered successfully: [{user.email}] (Role: {user.role.value})")
    return user


@router.post("/login", response_model=TokenResponse, summary="User Login")
def login_user(payload: UserLoginRequest, db: Session = Depends(get_db)):
    """Authenticates credentials and issues a signed HMAC-SHA256 JWT access token."""
    user = db.query(User).filter_by(email=payload.email.lower().strip()).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is inactive",
        )

    access_token = create_access_token(
        data={"sub": user.email, "role": user.role.value, "user_id": user.id}
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        user=user,
    )


import secrets
import httpx
from datetime import datetime, timezone, timedelta

@router.post("/github", response_model=TokenResponse, summary="GitHub Access Token Authentication")
def login_with_github_token(payload: GitHubTokenLoginRequest, db: Session = Depends(get_db)):
    """
    Validates a GitHub Personal Access Token directly against api.github.com,
    registers or updates the user, saves their token for automated PR creations,
    and returns a signed JWT session.
    """
    token = payload.token.strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="GitHub Token cannot be empty.")

    try:
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "PatchForge-AI-Auth",
        }
        with httpx.Client(timeout=10.0) as client:
            resp = client.get("https://api.github.com/user", headers=headers)
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid GitHub Access Token: {resp.text}",
                )
            gh_data = resp.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to connect to GitHub API: {str(e)}",
        )

    gh_login = gh_data.get("login")
    gh_name = gh_data.get("name") or gh_login
    gh_avatar = gh_data.get("avatar_url")
    gh_email = gh_data.get("email") or f"{gh_login.lower()}@github.users.patchforge.ai"

    # Find or create user
    user = db.query(User).filter((User.github_username == gh_login) | (User.email == gh_email.lower())).first()
    if not user:
        user = User(
            email=gh_email.lower(),
            full_name=gh_name,
            github_username=gh_login,
            github_avatar_url=gh_avatar,
            github_token=token,
            role=UserRole.DEVELOPER,
            is_active=True,
        )
        db.add(user)
    else:
        user.github_token = token
        user.github_username = gh_login
        user.github_avatar_url = gh_avatar
        db.add(user)

    db.commit()
    db.refresh(user)

    logger.info(f"User authenticated via GitHub Access Token: [{user.github_username}] ({user.email})")

    access_token = create_access_token(
        data={"sub": user.email, "role": user.role.value, "user_id": user.id}
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        user=user,
    )


@router.post("/otp/send", summary="Send Verification OTP")
def send_otp(payload: OTPRequest, db: Session = Depends(get_db)):
    """
    Generates a secure 6-digit OTP code with a 5-minute expiration window for 2FA/Passwordless authentication.
    """
    email = payload.email.lower().strip()
    otp_code = f"{secrets.randbelow(900000) + 100000}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

    user = db.query(User).filter_by(email=email).first()
    if not user:
        user = User(
            email=email,
            full_name=email.split("@")[0].capitalize(),
            otp_code=otp_code,
            otp_expires_at=expires_at,
            role=UserRole.DEVELOPER,
            is_active=True,
        )
        db.add(user)
    else:
        user.otp_code = otp_code
        user.otp_expires_at = expires_at
        db.add(user)

    db.commit()

    response = {
        "message": f"Verification OTP sent to {email}",
        "email": email,
        "expires_in_seconds": 300,
    }

    # The OTP is never logged or returned in the response outside local/dev use -
    # this environment has no real email/SMS delivery integration wired up, so
    # `demo_otp` exists purely so the flow is testable locally. Shipping this in
    # production would let anyone log in as anyone by reading their own response.
    if settings.DEBUG:
        logger.info(f"[OTP] Security OTP generated for [{email}]: {otp_code} (Valid for 5 minutes) [DEBUG mode only]")
        response["demo_otp"] = otp_code
    else:
        logger.info(f"[OTP] Security OTP generated for [{email}] (Valid for 5 minutes)")

    return response


@router.post("/otp/verify", response_model=TokenResponse, summary="Verify OTP and Login")
def verify_otp(payload: OTPVerifyRequest, db: Session = Depends(get_db)):
    """
    Validates the 6-digit OTP code and issues a signed JWT access token.
    """
    email = payload.email.lower().strip()
    user = db.query(User).filter_by(email=email).first()
    if not user or not user.otp_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active OTP found for this email. Please request a new code.",
        )

    if user.otp_expires_at and datetime.now(timezone.utc) > user.otp_expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP code has expired. Please request a new code.",
        )

    if user.otp_code != payload.otp.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 6-digit OTP verification code.",
        )

    # Clear OTP after successful verification
    user.otp_code = None
    user.otp_expires_at = None
    db.add(user)
    db.commit()
    db.refresh(user)

    access_token = create_access_token(
        data={"sub": user.email, "role": user.role.value, "user_id": user.id}
    )

    logger.info(f"User successfully verified OTP: [{user.email}]")

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        user=user,
    )


@router.get("/me", response_model=UserResponse, summary="Get Current Profile")
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Retrieves the profile and role privileges of the authenticated user."""
    return current_user
