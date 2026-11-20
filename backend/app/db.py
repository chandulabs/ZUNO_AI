"""Central Database Configuration for PhishGuard AI Server.

Single source of truth for SQLite (development) and PostgreSQL (production).
Enables WAL mode and busy timeouts for SQLite concurrency.
"""
import os
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool

_BACKEND_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DB_FILE = _BACKEND_DIR / "phishguard.db"

DB_URL = os.getenv("DATABASE_URL")
if not DB_URL:
    DB_URL = f"sqlite:///{DEFAULT_DB_FILE.as_posix()}"

is_sqlite = DB_URL.startswith("sqlite")

if is_sqlite:
    engine = create_engine(
        DB_URL,
        connect_args={"check_same_thread": False, "timeout": 30},
        poolclass=NullPool
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=10000")
            cursor.close()
        except Exception:
            pass
else:
    engine = create_engine(
        DB_URL,
        pool_pre_ping=True
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine)
Base = declarative_base()


def get_db():
    """Database session generator."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
