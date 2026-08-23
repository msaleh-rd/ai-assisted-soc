"""Database connection and models for PostgreSQL."""

from sqlalchemy import create_engine, Column, String, Integer, DateTime, Float, JSON, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from typing import Optional

# SQLAlchemy setup
Base = declarative_base()


class AlertRecord(Base):
    """PostgreSQL model for normalized alerts."""
    __tablename__ = "alerts"
    
    alert_id = Column(String(36), primary_key=True)
    investigation_id = Column(String(36), index=True)
    correlation_id = Column(String(36), index=True)
    source_system = Column(String(50), index=True)
    source_name = Column(String(100))
    alert_name = Column(String(255))
    alert_category = Column(String(100), index=True)
    severity = Column(String(20), index=True)
    confidence = Column(Float)
    status = Column(String(20), index=True)
    primary_entities = Column(JSON)
    alert_metadata = Column(JSON)
    occurrence_count = Column(Integer, default=1)
    timestamp_generated = Column(DateTime, index=True)
    timestamp_received = Column(DateTime, index=True, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class InvestigationRecord(Base):
    """PostgreSQL model for investigations."""
    __tablename__ = "investigations"
    
    investigation_id = Column(String(36), primary_key=True)
    primary_alert_id = Column(String(36), index=True)
    status = Column(String(50), index=True)
    severity = Column(String(20), index=True)
    entity_count = Column(Integer, default=0)
    relationship_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    compression_ratio = Column(Float)
    raw_events_count = Column(Integer)
    compressed_events_count = Column(Integer)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class EventRecord(Base):
    """PostgreSQL model for correlated events."""
    __tablename__ = "events"
    
    event_id = Column(String(36), primary_key=True)
    investigation_id = Column(String(36), index=True)
    event_type = Column(String(100), index=True)
    source_entity_id = Column(String(255))
    target_entity_id = Column(String(255))
    relationship_type = Column(String(100))
    timestamp = Column(DateTime, index=True)
    risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.85)
    is_suspicious = Column(Boolean, default=False)
    context = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)


class EntityRecord(Base):
    """PostgreSQL model for investigation entities."""
    __tablename__ = "entities"
    
    entity_id = Column(String(255), primary_key=True)
    entity_type = Column(String(50), index=True)
    entity_name = Column(String(255))
    attributes = Column(JSON)
    enrichment_data = Column(JSON)
    threat_intel = Column(JSON)
    risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.85)
    is_suspicious = Column(Boolean, default=False)
    is_known_malicious = Column(Boolean, default=False)
    source_alerts = Column(JSON)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditRecord(Base):
    """PostgreSQL model for audit trail."""
    __tablename__ = "audit"
    
    audit_id = Column(String(36), primary_key=True)
    investigation_id = Column(String(36), index=True)
    action = Column(String(100))
    actor = Column(String(100))
    details = Column(Text)
    timestamp = Column(DateTime, index=True, default=datetime.utcnow)


class RCAResultRecord(Base):
    """PostgreSQL model for Root Cause Analysis results."""
    __tablename__ = "rca_results"
    
    rca_id = Column(String(36), primary_key=True)
    investigation_id = Column(String(36), index=True)
    root_cause = Column(Text)
    attack_chain = Column(JSON)  # List of steps
    confidence = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)


def get_database_url(
    host: Optional[str] = None,
    port: Optional[int] = None,
    database: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None
) -> str:
    """Build database connection string with environment fallbacks."""
    import os
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return env_url
    h = host or os.getenv("POSTGRES_HOST", "127.0.0.1")
    p = port or int(os.getenv("POSTGRES_PORT", "5435"))
    db = database or os.getenv("POSTGRES_DB", "soc_platform")
    u = user or os.getenv("POSTGRES_USER", "soc_user")
    pwd = password or os.getenv("POSTGRES_PASSWORD", "soc_password")
    return f"postgresql://{u}:{pwd}@{h}:{p}/{db}"


def create_db_engine(database_url: str):
    """Create SQLAlchemy engine."""
    return create_engine(database_url, echo=False, pool_pre_ping=True)


def create_db_session(engine):
    """Create session factory."""
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)
