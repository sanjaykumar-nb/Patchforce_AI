"""
Test-session bootstrap: creates all ORM tables on the configured DATABASE_URL
before the suite runs. No test module in this package creates its own schema,
so without this the suite only works against a pre-migrated database.

Also provides shared auth-header fixtures for tests that exercise the API
directly via TestClient - most endpoints require authentication now.
"""

import uuid
import pytest

from app.database import Base, engine, SessionLocal
import app.models  # noqa: F401  (registers all model classes on Base.metadata)
from app.models.user import User, UserRole
from app.core.security import get_password_hash, create_access_token


def pytest_configure(config):
    Base.metadata.create_all(bind=engine)


def _make_auth_headers(role: UserRole) -> dict:
    """Seeds a throwaway user with the given role and returns Bearer auth headers for it."""
    db = SessionLocal()
    try:
        user = User(
            email=f"test-{role.value.lower()}-{uuid.uuid4().hex[:10]}@patchforge.test",
            hashed_password=get_password_hash("Test-Password-123!"),
            full_name=f"Test {role.value.title()}",
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        token = create_access_token(data={"sub": user.email, "role": user.role.value, "user_id": user.id})
        return {"Authorization": f"Bearer {token}"}
    finally:
        db.close()


@pytest.fixture
def auth_headers() -> dict:
    """Bearer auth headers for a DEVELOPER-role test user - covers most protected routes."""
    return _make_auth_headers(UserRole.DEVELOPER)


@pytest.fixture
def admin_auth_headers() -> dict:
    """Bearer auth headers for an ADMIN-role test user - satisfies every require_roles() check."""
    return _make_auth_headers(UserRole.ADMIN)
