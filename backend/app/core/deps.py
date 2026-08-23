"""
PatchForge AI - Dependency Injection & RBAC Authorization Engine
================================================================
FastAPI dependencies for JWT authentication, database session management,
and Role-Based Access Control (ADMIN, SECURITY_ENGINEER, DEVELOPER, VIEWER).
"""

from typing import List, Callable
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User, UserRole
from app.core.security import decode_access_token
from app.core.logging import get_logger

logger = get_logger("patchforge.core.deps")

# OAuth2 scheme extracting Bearer token from Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Validates the incoming JWT access token and retrieves the authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        raise credentials_exception

    payload = decode_access_token(token)
    if not payload:
        raise credentials_exception

    email: str = payload.get("sub")
    if not email:
        raise credentials_exception

    user = db.query(User).filter_by(email=email).first()
    if not user:
        logger.warning(f"User with email [{email}] not found.")
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account",
        )

    return user


def require_roles(*allowed_roles: UserRole) -> Callable:
    """
    Role-Based Access Control (RBAC) dependency factory.
    Enforces that the current authenticated user possesses one of the allowed roles.
    """
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles and current_user.role != UserRole.ADMIN:
            logger.warning(
                f"Access denied for user [{current_user.email}] (Role: {current_user.role}) to protected resource."
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Insufficient privileges. Required: {[r.value for r in allowed_roles]}",
            )
        return current_user

    return role_checker
