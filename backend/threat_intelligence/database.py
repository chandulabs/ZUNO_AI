"""Local Threat Intelligence Database Model and Session Management.

Uses the unified database engine and sessionmaker from app.db.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, JSON, Index
from app.db import Base, SessionLocal, engine


class ThreatRecord(Base):
    __tablename__ = "threat_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_type = Column(String(32), nullable=False)  # url, domain, sha256, md5
    indicator_value = Column(String(2048), nullable=False)
    threat_level = Column(String(32), nullable=False, default="MALICIOUS")  # MALICIOUS, SUSPICIOUS
    category = Column(String(64), nullable=False, default="phishing")  # phishing, malware, c2, etc.
    malware_family = Column(String(128), nullable=True)
    source = Column(String(128), nullable=False, default="Manual Import")
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_updated = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    details = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_threat_type_val", "indicator_type", "indicator_value"),
        Index("ix_threat_val", "indicator_value"),
    )


def get_session():
    return SessionLocal()


def init_db():
    Base.metadata.create_all(bind=engine)
