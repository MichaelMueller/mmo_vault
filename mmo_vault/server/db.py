"""Engine and session factory.

Deliberately synchronous SQLAlchemy: the CLI and the request handlers would
otherwise need two code paths for the same queries. FastAPI runs synchronous
endpoints in a worker thread, which is more than enough for a service of this
size, and it keeps the model layer free of await noise.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from . import environment
from .models import Base

_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None


def create_db_engine(url: str) -> Engine:
    kwargs: dict = {"future": True}
    if url.startswith("sqlite"):
        # FastAPI hands requests to worker threads, and the connection would
        # otherwise refuse to be used there.
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        _enable_sqlite_pragmas(engine)
    return engine


def _enable_sqlite_pragmas(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_connection, _record):  # pragma: no cover - trivial
        cursor = dbapi_connection.cursor()
        # Foreign keys are off by default in SQLite, which would silently allow
        # orphaned rows. WAL keeps a reader from blocking the writer.
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


def init(url: str | None = None) -> Engine:
    """Binds the process to one database. Called by both the CLI and the app."""
    global _engine, _SessionFactory
    _engine = create_db_engine(url or environment.database_url())
    _SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def engine() -> Engine:
    if _engine is None:
        raise RuntimeError("database not initialised - call db.init() first")
    return _engine


def create_all(url: str | None = None) -> Engine:
    """Creates the schema without Alembic - for tests and tooling only.

    The regular path is `alembic upgrade head`, which also stamps the version.
    """
    eng = init(url)
    Base.metadata.create_all(eng)
    return eng


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transaction around a unit of work, committed or rolled back as a whole."""
    if _SessionFactory is None:
        raise RuntimeError("database not initialised - call db.init() first")
    session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

