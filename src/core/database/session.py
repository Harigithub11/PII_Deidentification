"""
Database Session Management and Dependency Injection

Provides FastAPI-compatible session management with proper lifecycle handling,
transaction management, and dependency injection.
"""

import asyncio
import logging
from contextlib import asynccontextmanager, contextmanager
from typing import AsyncGenerator, Generator, Optional, Dict, Any
from functools import wraps

from fastapi import Depends, HTTPException, status
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.exc import SQLAlchemyError, DisconnectionError, IntegrityError

from .connection import get_database_manager, DatabaseConnectionManager
from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class SessionManager:
    """Manages database sessions with comprehensive lifecycle handling."""
    
    def __init__(self, db_manager: Optional[DatabaseConnectionManager] = None):
        self.db_manager = db_manager or get_database_manager()
        self._session_stats = {
            "total_sessions": 0,
            "active_sessions": 0,
            "committed_transactions": 0,
            "rolled_back_transactions": 0,
            "failed_sessions": 0
        }
        self._setup_session_events()
    
    def _setup_session_events(self):
        """Set up SQLAlchemy session event listeners."""
        
        @event.listens_for(sessionmaker, "after_configured")
        def configure_session_events():
            """Configure session-level events after session factory is created."""
            pass
        
        # We'll set up events on individual sessions in get_session()
    
    def _setup_individual_session_events(self, session: Session):
        """Set up events for individual session instances."""
        
        @event.listens_for(session, "after_transaction_create")
        def on_transaction_create(session, transaction):
            """Handle transaction creation."""
            logger.debug(f"Transaction created for session {id(session)}")
        
        @event.listens_for(session, "after_transaction_end")
        def on_transaction_end(session, transaction):
            """Handle transaction completion."""
            if transaction.is_active:
                logger.debug(f"Transaction ended for session {id(session)}")
        
        @event.listens_for(session, "after_commit")
        def on_commit(session):
            """Handle successful commits."""
            self._session_stats["committed_transactions"] += 1
            logger.debug(f"Session {id(session)} committed successfully")
        
        @event.listens_for(session, "after_rollback")
        def on_rollback(session):
            """Handle rollbacks."""
            self._session_stats["rolled_back_transactions"] += 1
            logger.debug(f"Session {id(session)} rolled back")
    
    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """
        Get a database session with automatic transaction management.
        
        Returns:
            Database session with automatic cleanup
        """
        session = self.db_manager.session_factory()
        self._setup_individual_session_events(session)
        
        self._session_stats["total_sessions"] += 1
        self._session_stats["active_sessions"] += 1
        
        try:
            logger.debug(f"Created database session {id(session)}")
            yield session
            
            # Commit if no exceptions occurred
            if session.in_transaction():
                session.commit()
                logger.debug(f"Session {id(session)} committed")
            
        except IntegrityError as e:
            session.rollback()
            self._session_stats["failed_sessions"] += 1
            logger.error(f"Database integrity error in session {id(session)}: {e}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Data integrity constraint violated"
            )
        
        except DisconnectionError as e:
            session.rollback()
            self._session_stats["failed_sessions"] += 1
            logger.error(f"Database disconnection in session {id(session)}: {e}")
            
            # Attempt reconnection
            if self.db_manager.reconnect():
                # Create new session with reconnected engine
                session.close()
                session = self.db_manager.session_factory()
                yield session
            else:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Database connection unavailable"
                )
        
        except SQLAlchemyError as e:
            session.rollback()
            self._session_stats["failed_sessions"] += 1
            logger.error(f"Database error in session {id(session)}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database operation failed"
            )
        
        except Exception as e:
            session.rollback()
            self._session_stats["failed_sessions"] += 1
            logger.error(f"Unexpected error in session {id(session)}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )
        
        finally:
            self._session_stats["active_sessions"] -= 1
            session.close()
            logger.debug(f"Closed database session {id(session)}")
    
    @contextmanager
    def get_read_only_session(self) -> Generator[Session, None, None]:
        """
        Get a read-only database session.
        
        Returns:
            Read-only database session
        """
        session = self.db_manager.session_factory()
        session.bind = session.bind.execution_options(isolation_level="READ_COMMITTED")
        
        self._session_stats["total_sessions"] += 1
        self._session_stats["active_sessions"] += 1
        
        try:
            logger.debug(f"Created read-only session {id(session)}")
            yield session
        
        except Exception as e:
            logger.error(f"Error in read-only session {id(session)}: {e}")
            raise
        
        finally:
            self._session_stats["active_sessions"] -= 1
            session.close()
            logger.debug(f"Closed read-only session {id(session)}")
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get session usage statistics."""
        return {
            **self._session_stats,
            "connection_stats": self.db_manager.get_statistics()["connection_stats"]
        }
    
    def health_check(self) -> Dict[str, Any]:
        """Perform session manager health check."""
        try:
            with self.get_session() as session:
                # Test basic query
                session.execute("SELECT 1")
                
            return {
                "healthy": True,
                "session_stats": self._session_stats,
                "database_health": self.db_manager.health_check()
            }
        
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e),
                "session_stats": self._session_stats
            }


# Global session manager instance
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get the global session manager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


def initialize_session_manager(db_manager: Optional[DatabaseConnectionManager] = None) -> SessionManager:
    """Initialize the session manager."""
    global _session_manager
    _session_manager = SessionManager(db_manager)
    logger.info("Session manager initialized successfully")
    return _session_manager


# FastAPI Dependencies
def get_db_session() -> Generator[Session, None, None]:
    """
    FastAPI dependency for getting a database session.
    
    Usage:
        @app.get("/users/")
        def get_users(db: Session = Depends(get_db_session)):
            return db.query(User).all()
    """
    session_manager = get_session_manager()
    with session_manager.get_session() as session:
        yield session


def get_read_only_db_session() -> Generator[Session, None, None]:
    """
    FastAPI dependency for getting a read-only database session.
    
    Usage:
        @app.get("/users/{user_id}")
        def get_user(user_id: int, db: Session = Depends(get_read_only_db_session)):
            return db.query(User).filter(User.id == user_id).first()
    """
    session_manager = get_session_manager()
    with session_manager.get_read_only_session() as session:
        yield session


# Transaction Decorators
def with_db_transaction(rollback_on_error: bool = True):
    """
    Decorator to wrap functions with database transaction management.
    
    Args:
        rollback_on_error: Whether to rollback on exceptions
    
    Usage:
        @with_db_transaction()
        def create_user(user_data: dict):
            with get_session_manager().get_session() as session:
                user = User(**user_data)
                session.add(user)
                # Transaction is automatically committed
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            session_manager = get_session_manager()
            
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if rollback_on_error:
                    logger.error(f"Transaction failed in {func.__name__}: {e}")
                raise
        
        return wrapper
    return decorator


# Session Context Managers for Advanced Use Cases
@contextmanager
def transaction_scope() -> Generator[Session, None, None]:
    """
    Create a database session with explicit transaction scope.
    
    Usage:
        with transaction_scope() as session:
            user = User(name="John")
            session.add(user)
            # Transaction commits automatically on success
            # or rolls back on exception
    """
    session_manager = get_session_manager()
    with session_manager.get_session() as session:
        yield session


@contextmanager
def nested_transaction_scope(session: Session) -> Generator[Session, None, None]:
    """
    Create a nested transaction (savepoint) within an existing session.
    
    Args:
        session: Existing database session
    
    Usage:
        with transaction_scope() as session:
            user = User(name="John")
            session.add(user)
            
            with nested_transaction_scope(session) as nested_session:
                # This will create a savepoint
                profile = UserProfile(user_id=user.id)
                nested_session.add(profile)
                # Nested transaction can rollback without affecting parent
    """
    savepoint = session.begin_nested()
    try:
        yield session
        savepoint.commit()
    except Exception:
        savepoint.rollback()
        raise


# Batch Operation Utilities
@contextmanager
def batch_session(batch_size: int = 1000, commit_interval: Optional[int] = None) -> Generator[Session, None, None]:
    """
    Create a session optimized for batch operations.
    
    Args:
        batch_size: Size of each batch
        commit_interval: How often to commit (defaults to batch_size)
    
    Usage:
        with batch_session(batch_size=1000) as session:
            for i, item in enumerate(large_dataset):
                session.add(Item(**item))
                if i % 1000 == 0:
                    session.commit()  # Periodic commits
    """
    commit_interval = commit_interval or batch_size
    session_manager = get_session_manager()
    
    # Configure session for batch operations
    session = session_manager.db_manager.session_factory()
    session.bind = session.bind.execution_options(
        autocommit=False,
        autoflush=False,
        compiled_cache={},  # Disable statement caching for batch operations
    )
    
    operation_count = 0
    
    try:
        yield session
        
        # Final commit
        if session.in_transaction():
            session.commit()
    
    except Exception as e:
        session.rollback()
        logger.error(f"Batch operation failed: {e}")
        raise
    
    finally:
        session.close()


# Health Check and Monitoring
def check_session_health() -> Dict[str, Any]:
    """Check the health of the session management system."""
    session_manager = get_session_manager()
    return session_manager.health_check()


def get_session_statistics() -> Dict[str, Any]:
    """Get comprehensive session usage statistics."""
    session_manager = get_session_manager()
    return session_manager.get_session_stats()


# Cleanup Functions
def close_session_manager():
    """Close the session manager and cleanup resources."""
    global _session_manager
    if _session_manager:
        # The session manager itself doesn't need explicit cleanup,
        # but we can trigger database connection cleanup
        _session_manager.db_manager.close()
        _session_manager = None
    logger.info("Session manager closed")