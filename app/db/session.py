"""Engine / session factory. Services own transactions (commit at use-case boundary)."""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


def normalize_database_url(url: str) -> str:
    """Accept postgres:// and postgresql:// forms; always use the psycopg 3 driver."""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


def make_engine(url: str | None = None) -> Engine:
    settings = get_settings()
    db_url = normalize_database_url(url or settings.database_url)
    if not db_url:
        raise RuntimeError("DATABASE_URL is not configured")
    return create_engine(
        db_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_pre_ping=True,
        # Supabase pooler (pgbouncer transaction mode) does not support prepared statements.
        connect_args={"prepare_threshold": None},
    )


@lru_cache
def get_engine() -> Engine:
    return make_engine()


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, autoflush=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request; always closed, rolled back on error."""
    session = get_sessionmaker()()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
