"""
Database configuration and connection management
"""
import os
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from src.models.database import Base

# Database configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://deidentify_user:secure_password@localhost:5432/deidentify_db"
)

# Create async engine for better performance
ASYNC_DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")
async_engine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=os.getenv("DATABASE_ECHO", "false").lower() == "true",
    future=True,
    pool_pre_ping=True,
    pool_recycle=300,
)

# Create sync engine for migrations and initial setup
sync_engine = create_engine(
    DATABASE_URL,
    echo=os.getenv("DATABASE_ECHO", "false").lower() == "true",
    future=True,
    pool_pre_ping=True,
    pool_recycle=300,
)

# Session factories
AsyncSessionLocal = sessionmaker(
    async_engine, class_=AsyncSession, expire_on_commit=False
)

SessionLocal = sessionmaker(
    autocommit=False, 
    autoflush=False, 
    bind=sync_engine
)


async def get_async_db() -> Generator[AsyncSession, None, None]:
    """
    Dependency function for FastAPI to get async database session
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def get_db() -> Generator[Session, None, None]:
    """
    Dependency function for FastAPI to get sync database session
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


async def create_tables():
    """
    Create all database tables
    """
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def create_tables_sync():
    """
    Create all database tables synchronously
    """
    Base.metadata.create_all(bind=sync_engine)


async def drop_tables():
    """
    Drop all database tables (use with caution!)
    """
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


def drop_tables_sync():
    """
    Drop all database tables synchronously (use with caution!)
    """
    Base.metadata.drop_all(bind=sync_engine)


class DatabaseManager:
    """
    Database management utilities
    """
    
    @staticmethod
    async def initialize_database():
        """
        Initialize database with tables and default data
        """
        await create_tables()
        print("✅ Database tables created successfully")
    
    @staticmethod
    def initialize_database_sync():
        """
        Initialize database with tables and default data synchronously
        """
        create_tables_sync()
        print("✅ Database tables created successfully")
    
    @staticmethod
    async def health_check() -> bool:
        """
        Check database connectivity
        """
        try:
            async with AsyncSessionLocal() as session:
                await session.execute("SELECT 1")
                return True
        except Exception as e:
            print(f"❌ Database health check failed: {e}")
            return False
    
    @staticmethod
    def health_check_sync() -> bool:
        """
        Check database connectivity synchronously
        """
        try:
            with SessionLocal() as session:
                session.execute("SELECT 1")
                return True
        except Exception as e:
            print(f"❌ Database health check failed: {e}")
            return False