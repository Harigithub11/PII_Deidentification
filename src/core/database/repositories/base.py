"""
Base Repository Pattern Implementation
"""

import logging
from abc import ABC
from typing import Generic, TypeVar, Type, Optional, List, Dict, Any
from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, NoResultFound

logger = logging.getLogger(__name__)

# Generic type for model classes
ModelType = TypeVar('ModelType')


class BaseRepository(Generic[ModelType], ABC):
    """Base repository class with common CRUD operations."""
    
    def __init__(self, model_class: Type[ModelType], session: Optional[Session] = None):
        self.model_class = model_class
        self._session = session
    
    @property
    def session(self) -> Session:
        """Get the current session."""
        if self._session:
            return self._session
        # This would be injected in actual usage
        from ..session import get_db_session
        return get_db_session()
    
    def create(self, **kwargs) -> ModelType:
        """Create a new record."""
        try:
            instance = self.model_class(**kwargs)
            self.session.add(instance)
            self.session.flush()
            return instance
        except IntegrityError as e:
            logger.error(f"Failed to create {self.model_class.__name__}: {e}")
            raise
    
    def get_by_id(self, record_id: UUID) -> Optional[ModelType]:
        """Get record by ID."""
        try:
            return self.session.query(self.model_class).filter(
                self.model_class.id == record_id
            ).first()
        except Exception as e:
            logger.error(f"Failed to get {self.model_class.__name__} by ID {record_id}: {e}")
            return None
    
    def get_all(self, limit: int = 100, offset: int = 0) -> List[ModelType]:
        """Get all records with pagination."""
        try:
            return self.session.query(self.model_class).offset(offset).limit(limit).all()
        except Exception as e:
            logger.error(f"Failed to get all {self.model_class.__name__}: {e}")
            return []
    
    def update(self, record_id: UUID, **kwargs) -> Optional[ModelType]:
        """Update record by ID."""
        try:
            instance = self.get_by_id(record_id)
            if not instance:
                return None
            
            for key, value in kwargs.items():
                if hasattr(instance, key):
                    setattr(instance, key, value)
            
            self.session.flush()
            return instance
        except Exception as e:
            logger.error(f"Failed to update {self.model_class.__name__} {record_id}: {e}")
            return None
    
    def delete(self, record_id: UUID) -> bool:
        """Delete record by ID."""
        try:
            instance = self.get_by_id(record_id)
            if not instance:
                return False
            
            self.session.delete(instance)
            self.session.flush()
            return True
        except Exception as e:
            logger.error(f"Failed to delete {self.model_class.__name__} {record_id}: {e}")
            return False
    
    def count(self) -> int:
        """Get total count of records."""
        try:
            return self.session.query(self.model_class).count()
        except Exception as e:
            logger.error(f"Failed to count {self.model_class.__name__}: {e}")
            return 0