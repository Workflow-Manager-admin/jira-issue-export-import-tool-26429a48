import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv
from .models import Base

# Load environment variables
load_dotenv()

# Database configuration from environment variables
MYSQL_USER = os.getenv("MYSQL_USER", "appuser")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "dbuser123")
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = os.getenv("MYSQL_PORT", "5000")
MYSQL_DB = os.getenv("MYSQL_DB", "myapp")

# Create database URL
DATABASE_URL = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"

# Create engine
engine = create_engine(DATABASE_URL, echo=False)

# Create SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# PUBLIC_INTERFACE
def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# PUBLIC_INTERFACE
def create_tables():
    """Create all tables in the database"""
    Base.metadata.create_all(bind=engine)

# PUBLIC_INTERFACE
def get_database_session() -> Session:
    """Get a database session for direct use"""
    return SessionLocal()
