"""
Database Connection Management for PII De-identification System

Provides comprehensive database connection management with pooling, health monitoring,
and security features.
"""

import asyncio
import logging
import time
from contextlib import contextmanager, asynccontextmanager
from typing import Dict, Optional, Any, AsyncGenerator, Generator
from urllib.parse import urlparse

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError, DisconnectionError, TimeoutError
from sqlalchemy.pool import QueuePool, NullPool, StaticPool
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.engine.events import PoolEvents

from ..config.settings import get_settings
from .database_encryption import DatabaseEncryptionManager

logger = logging.getLogger(__name__)
settings = get_settings()


class DatabaseConnectionManager:
    """Manages database connections with pooling, health monitoring, and security."""
    
    def __init__(self, database_url: Optional[str] = None):
        self.database_url = database_url or settings.database_url
        self.encryption_manager = DatabaseEncryptionManager()
        self._engine: Optional[Engine] = None
        self._session_factory: Optional[sessionmaker] = None
        self._connection_pools: Dict[str, Any] = {}
        self._health_status = {"healthy": False, "last_check": 0}
        self._connection_stats = {
            "total_connections": 0,
            "active_connections": 0,
            "failed_connections": 0,
            "reconnection_attempts": 0
        }
        
    @property
    def engine(self) -> Engine:
        """Get the database engine, creating it if necessary."""
        if self._engine is None:
            self._engine = self._create_engine()
        return self._engine
    
    @property
    def session_factory(self) -> sessionmaker:
        """Get the session factory, creating it if necessary."""
        if self._session_factory is None:
            self._session_factory = sessionmaker(
                bind=self.engine,
                autocommit=False,
                autoflush=False,
                expire_on_commit=False
            )
        return self._session_factory
    
    def _create_engine(self) -> Engine:
        """Create and configure the database engine."""
        logger.info(f"Creating database engine for: {self._mask_database_url(self.database_url)}")
        
        # Parse database URL to determine configuration
        parsed_url = urlparse(self.database_url)
        db_type = parsed_url.scheme.split('+')[0]
        
        # Configure engine parameters based on database type
        engine_config = self._get_engine_config(db_type)
        
        # Create engine with security enhancements if available
        try:
            if settings.enable_pii_encryption and db_type != 'sqlite':
                secure_url = self.encryption_manager.create_encrypted_database_url(
                    self.database_url
                )
                engine = create_engine(secure_url, **engine_config)
            else:
                engine = create_engine(self.database_url, **engine_config)
            
            # Set up event listeners
            self._setup_engine_events(engine)
            
            # Validate engine configuration
            self._validate_engine(engine)
            
            logger.info(f"Database engine created successfully for {db_type}")
            return engine
            
        except Exception as e:
            logger.error(f"Failed to create database engine: {e}")
            raise
    
    def _get_engine_config(self, db_type: str) -> Dict[str, Any]:
        """Get database-specific engine configuration."""
        base_config = {
            'echo': settings.database_echo,
            'future': True,  # SQLAlchemy 2.0 style
            'connect_args': {},
            'pool_pre_ping': True,
            'pool_recycle': 3600,  # 1 hour
        }
        
        if db_type == 'postgresql':
            base_config.update({
                'poolclass': QueuePool,
                'pool_size': settings.database_pool_size,
                'max_overflow': settings.database_pool_size * 2,
                'pool_timeout': 30,
                'connect_args': {
                    'connect_timeout': 10,
                    'application_name': f"{settings.app_name}_v{settings.app_version}",
                    'options': '-c default_transaction_isolation=read_committed'
                }
            })
            
        elif db_type == 'mysql':
            base_config.update({
                'poolclass': QueuePool,
                'pool_size': settings.database_pool_size,
                'max_overflow': settings.database_pool_size * 2,
                'pool_timeout': 30,
                'connect_args': {
                    'connect_timeout': 10,
                    'charset': 'utf8mb4',
                    'autocommit': False,
                    'sql_mode': 'STRICT_TRANS_TABLES,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION'
                }
            })
            
        elif db_type == 'sqlite':
            base_config.update({
                'poolclass': StaticPool,
                'connect_args': {
                    'check_same_thread': False,
                    'timeout': 30,
                    'isolation_level': None,  # Autocommit mode
                    'pragma': {
                        'foreign_keys': 'ON',
                        'journal_mode': 'WAL',
                        'synchronous': 'NORMAL',
                        'cache_size': -64000,  # 64MB
                        'temp_store': 'memory'
                    }
                }
            })
        
        return base_config
    
    def _setup_engine_events(self, engine: Engine):
        """Set up SQLAlchemy engine event listeners."""
        
        @event.listens_for(engine, "connect")
        def on_connect(dbapi_connection, connection_record):
            """Handle new database connections."""
            self._connection_stats["total_connections"] += 1
            self._connection_stats["active_connections"] += 1
            
            # Set connection-specific configurations
            db_type = engine.url.drivername.split('+')[0]
            
            if db_type == 'sqlite':
                # Enable SQLite optimizations
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA cache_size=-64000")
                cursor.execute("PRAGMA temp_store=memory")
                cursor.close()
                
            elif db_type == 'postgresql':
                # Set PostgreSQL session parameters
                cursor = dbapi_connection.cursor()
                cursor.execute("SET statement_timeout = '300s'")
                cursor.execute("SET lock_timeout = '30s'")
                cursor.execute("SET idle_in_transaction_session_timeout = '600s'")
                cursor.close()
            
            logger.debug(f"New database connection established: {id(dbapi_connection)}")
        
        @event.listens_for(engine, "close")
        def on_close(dbapi_connection, connection_record):
            """Handle database connection closures."""
            self._connection_stats["active_connections"] -= 1
            logger.debug(f"Database connection closed: {id(dbapi_connection)}")
        
        @event.listens_for(engine, "invalid")
        def on_invalid(dbapi_connection, connection_record, exception):
            """Handle invalid database connections."""
            self._connection_stats["failed_connections"] += 1
            logger.warning(f"Database connection invalidated: {exception}")
        
        @event.listens_for(engine.pool, "connect", propagate=True)
        def on_pool_connect(dbapi_connection, connection_record):
            """Handle connection pool events."""
            connection_record.info['connect_time'] = time.time()
        
        @event.listens_for(engine.pool, "checkout", propagate=True)
        def on_pool_checkout(dbapi_connection, connection_record, connection_proxy):
            """Handle connection checkout from pool."""
            logger.debug(f"Connection checked out from pool: {id(dbapi_connection)}")
        
        @event.listens_for(engine.pool, "checkin", propagate=True)
        def on_pool_checkin(dbapi_connection, connection_record):
            """Handle connection checkin to pool."""
            logger.debug(f"Connection checked in to pool: {id(dbapi_connection)}")
    
    def _validate_engine(self, engine: Engine):
        """Validate the database engine configuration."""
        try:
            with engine.connect() as conn:
                # Test basic connectivity
                result = conn.execute(text("SELECT 1"))
                assert result.scalar() == 1
                
                # Validate security configuration if applicable
                if not self.database_url.startswith('sqlite'):
                    security_validation = self.encryption_manager.validate_database_security(engine)
                    if not security_validation.get("overall_security", False):
                        logger.warning("Database security validation failed")
                        for recommendation in security_validation.get("recommendations", []):
                            logger.warning(f"Security recommendation: {recommendation}")
                
                self._health_status["healthy"] = True
                self._health_status["last_check"] = time.time()
                logger.info("Database engine validation successful")
                
        except Exception as e:
            logger.error(f"Database engine validation failed: {e}")
            raise
    
    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """Get a database session with automatic cleanup."""
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    @contextmanager
    def get_connection(self):
        """Get a raw database connection with automatic cleanup."""
        connection = self.engine.connect()
        try:
            yield connection
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            connection.close()
    
    def health_check(self, timeout: int = 10) -> Dict[str, Any]:
        """Perform a comprehensive database health check."""
        health_info = {
            "healthy": False,
            "response_time_ms": None,
            "connection_stats": self._connection_stats.copy(),
            "pool_info": {},
            "database_info": {},
            "error": None
        }
        
        start_time = time.time()
        
        try:
            with self.engine.connect() as conn:
                # Test basic query
                conn.execute(text("SELECT 1"))
                
                # Get database-specific information
                db_type = self.engine.url.drivername.split('+')[0]
                
                if db_type == 'postgresql':
                    version_result = conn.execute(text("SELECT version()"))
                    health_info["database_info"]["version"] = version_result.scalar()
                    
                    # Check connection count
                    conn_count_result = conn.execute(text(
                        "SELECT count(*) FROM pg_stat_activity WHERE state = 'active'"
                    ))
                    health_info["database_info"]["active_connections"] = conn_count_result.scalar()
                    
                elif db_type == 'mysql':
                    version_result = conn.execute(text("SELECT VERSION()"))
                    health_info["database_info"]["version"] = version_result.scalar()
                    
                    conn_count_result = conn.execute(text("SHOW STATUS LIKE 'Threads_connected'"))
                    health_info["database_info"]["active_connections"] = conn_count_result.scalar()
                    
                elif db_type == 'sqlite':
                    pragma_result = conn.execute(text("PRAGMA user_version"))
                    health_info["database_info"]["user_version"] = pragma_result.scalar()
                
                # Get pool information
                pool = self.engine.pool
                if hasattr(pool, 'size'):
                    health_info["pool_info"] = {
                        "pool_size": pool.size(),
                        "checked_in": pool.checkedin(),
                        "checked_out": pool.checkedout(),
                        "invalid": pool.invalid(),
                        "overflow": pool.overflow() if hasattr(pool, 'overflow') else 0
                    }
                
                response_time = (time.time() - start_time) * 1000
                health_info["response_time_ms"] = round(response_time, 2)
                health_info["healthy"] = True
                
                self._health_status["healthy"] = True
                self._health_status["last_check"] = time.time()
                
        except Exception as e:
            health_info["error"] = str(e)
            health_info["healthy"] = False
            self._health_status["healthy"] = False
            logger.error(f"Database health check failed: {e}")
        
        return health_info
    
    def reconnect(self, max_retries: int = 3) -> bool:
        """Attempt to reconnect to the database."""
        logger.info("Attempting database reconnection...")
        
        for attempt in range(max_retries):
            try:
                self._connection_stats["reconnection_attempts"] += 1
                
                # Dispose existing engine
                if self._engine:
                    self._engine.dispose()
                
                # Create new engine
                self._engine = self._create_engine()
                self._session_factory = None  # Reset session factory
                
                # Test connection
                health = self.health_check()
                if health["healthy"]:
                    logger.info(f"Database reconnection successful on attempt {attempt + 1}")
                    return True
                    
            except Exception as e:
                logger.warning(f"Reconnection attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
        
        logger.error("All database reconnection attempts failed")
        return False
    
    def close(self):
        """Close all database connections and cleanup resources."""
        logger.info("Closing database connections...")
        
        try:
            if self._engine:
                self._engine.dispose()
                self._engine = None
            
            if self._session_factory:
                self._session_factory.close_all()
                self._session_factory = None
            
            self._connection_pools.clear()
            self._health_status["healthy"] = False
            
            logger.info("Database connections closed successfully")
            
        except Exception as e:
            logger.error(f"Error closing database connections: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive database connection statistics."""
        stats = {
            "connection_stats": self._connection_stats.copy(),
            "health_status": self._health_status.copy(),
            "engine_info": {},
            "pool_info": {}
        }
        
        if self._engine:
            stats["engine_info"] = {
                "url": self._mask_database_url(str(self._engine.url)),
                "driver": self._engine.url.drivername,
                "echo": self._engine.echo,
                "pool_class": self._engine.pool.__class__.__name__
            }
            
            if hasattr(self._engine.pool, 'size'):
                stats["pool_info"] = {
                    "pool_size": self._engine.pool.size(),
                    "checked_in": self._engine.pool.checkedin(),
                    "checked_out": self._engine.pool.checkedout(),
                    "invalid": self._engine.pool.invalid()
                }
        
        return stats
    
    @staticmethod
    def _mask_database_url(url: str) -> str:
        """Mask sensitive information in database URL for logging."""
        if '://' in url:
            scheme, rest = url.split('://', 1)
            if '@' in rest:
                auth, host_path = rest.split('@', 1)
                if ':' in auth:
                    user, password = auth.split(':', 1)
                    masked_auth = f"{user}:***"
                else:
                    masked_auth = f"{auth}:***"
                return f"{scheme}://{masked_auth}@{host_path}"
        return url


# Global database connection manager instance
_db_manager: Optional[DatabaseConnectionManager] = None


def get_database_manager() -> DatabaseConnectionManager:
    """Get the global database connection manager instance."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseConnectionManager()
    return _db_manager


def initialize_database() -> DatabaseConnectionManager:
    """Initialize the database connection manager."""
    global _db_manager
    _db_manager = DatabaseConnectionManager()
    
    # Perform initial health check
    health = _db_manager.health_check()
    if not health["healthy"]:
        raise Exception(f"Database initialization failed: {health.get('error', 'Unknown error')}")
    
    logger.info("Database connection manager initialized successfully")
    return _db_manager


def close_database():
    """Close the database connection manager."""
    global _db_manager
    if _db_manager:
        _db_manager.close()
        _db_manager = None
    logger.info("Database connection manager closed")


# Convenience functions
def get_engine() -> Engine:
    """Get the database engine."""
    return get_database_manager().engine


def get_session_factory() -> sessionmaker:
    """Get the session factory."""
    return get_database_manager().session_factory


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Get a database session context manager."""
    with get_database_manager().get_session() as session:
        yield session


@contextmanager
def get_db_connection():
    """Get a database connection context manager."""
    with get_database_manager().get_connection() as connection:
        yield connection