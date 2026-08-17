"""Centralized database connection management for Postgres and Neo4j."""

import os
import logging
from typing import Optional, Generator
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database.postgres import get_database_url
from backend.database.neo4j import Neo4jClient

logger = logging.getLogger("database-connection")

# Global instances
engine = None
SessionLocal = None
neo4j_client: Optional[Neo4jClient] = None

def init_db():
    """Initialize database connections (Postgres & Neo4j)."""
    global engine, SessionLocal, neo4j_client
    
    # Init Postgres
    db_url = os.getenv("DATABASE_URL", get_database_url())
    logger.info(f"Initializing PostgreSQL connection to {db_url}")
    engine = create_engine(db_url, echo=False, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # Auto-create tables if they don't exist
    from backend.database.postgres import Base
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("PostgreSQL tables verified/created.")
    except Exception as e:
        logger.error(f"Failed to create PostgreSQL tables: {e}")
    
    # Init Neo4j
    neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password = os.getenv("NEO4J_PASSWORD", "password")
    
    logger.info(f"Initializing Neo4j connection to {neo4j_uri}")
    try:
        neo4j_client = Neo4jClient(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)
    except Exception as e:
        logger.error(f"Failed to initialize Neo4j client: {e}")
        neo4j_client = None

async def close_db():
    """Close all database connections."""
    global engine, SessionLocal, neo4j_client
    
    if engine:
        engine.dispose()
        engine = None
        SessionLocal = None
        logger.info("PostgreSQL connection closed")
        
    if neo4j_client:
        await neo4j_client.close()
        neo4j_client = None
        logger.info("Neo4j connection closed")

def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency to get a DB session."""
    if not SessionLocal:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_neo4j() -> Optional[Neo4jClient]:
    """Get the global Neo4j client."""
    return neo4j_client
