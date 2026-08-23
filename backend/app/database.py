"""
PatchForge AI - Relational Database Layer
========================================
SQLAlchemy engine initialization, connection pooling, base declarative model,
and FastAPI database session dependency.
Supports both psycopg (v3) and psycopg2 drivers automatically.
"""

from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.config import get_settings
from app.core.logging import get_logger

logger = get_logger("patchforge.database")
settings = get_settings()

db_url = settings.DATABASE_URL

# Auto-normalize postgresql:// to postgresql+psycopg:// if using modern psycopg3
if db_url.startswith("postgresql://"):
    try:
        import psycopg  # noqa: F401
        db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)
    except ImportError:
        pass

# Engine creation parameters
engine_kwargs = {
    "pool_pre_ping": True,
}

# Connection pool tuning for PostgreSQL
if "sqlite" not in db_url:
    engine_kwargs.update({
        "pool_size": 10,
        "max_overflow": 20,
        "pool_recycle": 300,
    })

engine = create_engine(db_url, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a transactional database session per request,
    ensuring cleanup upon completion.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_health() -> bool:
    """Performs an active ping query against the database."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        return False
