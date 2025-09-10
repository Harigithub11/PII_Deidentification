"""
Repository Pattern Implementation for PII De-identification System

Provides clean abstraction layer over database operations with comprehensive
CRUD operations, query building, and transaction management.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, TypeVar, Generic, Type
from uuid import UUID

from sqlalchemy import and_, or_, not_, func, desc, asc, text
from sqlalchemy.orm import Session, Query, joinedload, selectinload
from sqlalchemy.exc import IntegrityError, NoResultFound
from pydantic import BaseModel

from .models import (
    User, UserSession, APIKey, ComplianceStandard, PolicyTemplate, Policy,
    PolicyRule, PolicyExecution, AuditEvent, UserActivity, SystemEvent,
    SecurityEvent, DataProcessingLog, Document, DocumentVersion, FileStorage,
    RedactionMetadata, BatchJob, JobResult, JobSchedule, BatchWorker,
    ProcessingStep, WorkflowExecution
)
from .session import get_db_session, transaction_scope
from ..security.encryption import encryption_manager

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
        raise RuntimeError("No session available. Use with dependency injection.")
    
    def create(self, **kwargs) -> ModelType:
        """Create a new record."""
        instance = self.model_class(**kwargs)
        self.session.add(instance)
        self.session.flush()  # Get ID without committing
        return instance
    
    def get_by_id(self, record_id: Union[int, str, UUID]) -> Optional[ModelType]:
        """Get record by ID."""
        return self.session.query(self.model_class).filter(
            self.model_class.id == record_id
        ).first()
    
    def get_all(self, limit: int = 1000, offset: int = 0) -> List[ModelType]:
        """Get all records with pagination."""
        return self.session.query(self.model_class).limit(limit).offset(offset).all()
    
    def update(self, record_id: Union[int, str, UUID], **kwargs) -> Optional[ModelType]:
        """Update a record by ID."""
        instance = self.get_by_id(record_id)
        if instance:
            for key, value in kwargs.items():
                if hasattr(instance, key):
                    setattr(instance, key, value)
            self.session.flush()
        return instance
    
    def delete(self, record_id: Union[int, str, UUID]) -> bool:
        """Delete a record by ID."""
        instance = self.get_by_id(record_id)
        if instance:
            self.session.delete(instance)
            return True
        return False
    
    def exists(self, record_id: Union[int, str, UUID]) -> bool:
        """Check if record exists."""
        return self.session.query(self.model_class.id).filter(
            self.model_class.id == record_id
        ).first() is not None
    
    def count(self, **filters) -> int:
        """Count records with optional filters."""
        query = self.session.query(self.model_class)
        for key, value in filters.items():
            if hasattr(self.model_class, key):
                query = query.filter(getattr(self.model_class, key) == value)
        return query.count()
    
    def find(self, **filters) -> List[ModelType]:
        """Find records by filters."""
        query = self.session.query(self.model_class)
        for key, value in filters.items():
            if hasattr(self.model_class, key):
                query = query.filter(getattr(self.model_class, key) == value)
        return query.all()
    
    def find_one(self, **filters) -> Optional[ModelType]:
        """Find single record by filters."""
        results = self.find(**filters)
        return results[0] if results else None


class UserRepository(BaseRepository[User]):
    """Repository for user management operations."""
    
    def __init__(self, session: Optional[Session] = None):
        super().__init__(User, session)
    
    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email address."""
        return self.session.query(User).filter(User.email == email).first()
    
    def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        return self.session.query(User).filter(User.username == username).first()
    
    def create_user(self, username: str, email: str, password_hash: str, 
                   full_name: Optional[str] = None, role: str = "user") -> User:
        """Create a new user with validation."""
        # Check for existing user
        if self.get_by_email(email) or self.get_by_username(username):
            raise ValueError("User with this email or username already exists")
        
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            full_name=full_name,
            role=role,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        self.session.add(user)
        self.session.flush()
        return user
    
    def authenticate_user(self, username: str, password_hash: str) -> Optional[User]:
        """Authenticate user credentials."""
        user = self.get_by_username(username)
        if user and user.password_hash == password_hash and user.is_active:
            # Update last login
            user.last_login = datetime.utcnow()
            return user
        return None
    
    def get_active_users(self, limit: int = 100) -> List[User]:
        """Get all active users."""
        return self.session.query(User).filter(User.is_active == True).limit(limit).all()
    
    def deactivate_user(self, user_id: UUID) -> bool:
        """Deactivate a user account."""
        user = self.get_by_id(user_id)
        if user:
            user.is_active = False
            user.updated_at = datetime.utcnow()
            return True
        return False


class SessionRepository(BaseRepository[UserSession]):
    """Repository for user session management."""
    
    def __init__(self, session: Optional[Session] = None):
        super().__init__(UserSession, session)
    
    def create_session(self, user_id: UUID, session_token: str, 
                      expires_at: datetime, ip_address: str, user_agent: str) -> UserSession:
        """Create a new user session."""
        session_obj = UserSession(
            user_id=user_id,
            session_token=session_token,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        self.session.add(session_obj)
        self.session.flush()
        return session_obj
    
    def get_by_token(self, session_token: str) -> Optional[UserSession]:
        """Get session by token."""
        return self.session.query(UserSession).filter(
            UserSession.session_token == session_token,
            UserSession.is_active == True,
            UserSession.expires_at > datetime.utcnow()
        ).first()
    
    def get_user_sessions(self, user_id: UUID, active_only: bool = True) -> List[UserSession]:
        """Get all sessions for a user."""
        query = self.session.query(UserSession).filter(UserSession.user_id == user_id)
        if active_only:
            query = query.filter(
                UserSession.is_active == True,
                UserSession.expires_at > datetime.utcnow()
            )
        return query.all()
    
    def revoke_session(self, session_token: str) -> bool:
        """Revoke a session."""
        session_obj = self.get_by_token(session_token)
        if session_obj:
            session_obj.is_active = False
            session_obj.updated_at = datetime.utcnow()
            return True
        return False
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions."""
        count = self.session.query(UserSession).filter(
            UserSession.expires_at <= datetime.utcnow(),
            UserSession.is_active == True
        ).update({
            'is_active': False,
            'updated_at': datetime.utcnow()
        })
        return count


class PolicyRepository(BaseRepository[Policy]):
    """Repository for policy management operations."""
    
    def __init__(self, session: Optional[Session] = None):
        super().__init__(Policy, session)
    
    def get_by_name(self, name: str) -> Optional[Policy]:
        """Get policy by name."""
        return self.session.query(Policy).filter(Policy.name == name).first()
    
    def get_active_policies(self, compliance_standard: Optional[str] = None) -> List[Policy]:
        """Get all active policies, optionally filtered by compliance standard."""
        query = self.session.query(Policy).filter(Policy.is_active == True)
        if compliance_standard:
            query = query.filter(Policy.compliance_standard == compliance_standard)
        return query.all()
    
    def create_policy(self, name: str, description: str, compliance_standard: str,
                     rules: List[Dict[str, Any]], **kwargs) -> Policy:
        """Create a new policy with rules."""
        policy = Policy(
            name=name,
            description=description,
            compliance_standard=compliance_standard,
            is_active=True,
            created_at=datetime.utcnow(),
            **kwargs
        )
        
        self.session.add(policy)
        self.session.flush()
        
        # Add policy rules
        for rule_data in rules:
            rule = PolicyRule(
                policy_id=policy.id,
                **rule_data
            )
            self.session.add(rule)
        
        return policy
    
    def get_policy_with_rules(self, policy_id: UUID) -> Optional[Policy]:
        """Get policy with associated rules."""
        return self.session.query(Policy).options(
            joinedload(Policy.rules)
        ).filter(Policy.id == policy_id).first()


class DocumentRepository(BaseRepository[Document]):
    """Repository for document management operations."""
    
    def __init__(self, session: Optional[Session] = None):
        super().__init__(Document, session)
    
    def create_document(self, filename: str, file_type: str, file_size: int,
                       file_hash: str, original_path: str, user_id: UUID,
                       metadata: Optional[Dict[str, Any]] = None) -> Document:
        """Create a new document record."""
        document = Document(
            filename=filename,
            file_type=file_type,
            file_size=file_size,
            file_hash=file_hash,
            original_path=original_path,
            user_id=user_id,
            metadata=metadata or {},
            status="uploaded",
            created_at=datetime.utcnow()
        )
        
        self.session.add(document)
        self.session.flush()
        return document
    
    def get_by_hash(self, file_hash: str) -> Optional[Document]:
        """Get document by file hash."""
        return self.session.query(Document).filter(Document.file_hash == file_hash).first()
    
    def get_user_documents(self, user_id: UUID, status: Optional[str] = None) -> List[Document]:
        """Get documents for a specific user."""
        query = self.session.query(Document).filter(Document.user_id == user_id)
        if status:
            query = query.filter(Document.status == status)
        return query.order_by(desc(Document.created_at)).all()
    
    def update_status(self, document_id: UUID, status: str, 
                     processing_result: Optional[Dict[str, Any]] = None) -> bool:
        """Update document processing status."""
        document = self.get_by_id(document_id)
        if document:
            document.status = status
            document.updated_at = datetime.utcnow()
            if processing_result:
                document.processing_result = processing_result
            return True
        return False
    
    def get_documents_by_status(self, status: str, limit: int = 100) -> List[Document]:
        """Get documents by processing status."""
        return self.session.query(Document).filter(
            Document.status == status
        ).limit(limit).all()


class AuditRepository(BaseRepository[AuditEvent]):
    """Repository for audit log operations."""
    
    def __init__(self, session: Optional[Session] = None):
        super().__init__(AuditEvent, session)
    
    def create_audit_event(self, event_type: str, resource_type: str,
                          resource_id: str, action: str, user_id: Optional[UUID] = None,
                          metadata: Optional[Dict[str, Any]] = None,
                          ip_address: Optional[str] = None) -> AuditEvent:
        """Create a new audit event."""
        # Generate integrity hash based on previous event
        previous_event = self.session.query(AuditEvent).order_by(
            desc(AuditEvent.created_at)
        ).first()
        
        previous_hash = previous_event.integrity_hash if previous_event else "genesis"
        
        event = AuditEvent(
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            user_id=user_id,
            metadata=metadata or {},
            ip_address=ip_address,
            previous_hash=previous_hash,
            created_at=datetime.utcnow()
        )
        
        # Calculate integrity hash
        hash_data = f"{event.event_type}{event.resource_type}{event.resource_id}{event.action}{event.created_at.isoformat()}{previous_hash}"
        event.integrity_hash = encryption_manager.hash_data(hash_data.encode())
        
        self.session.add(event)
        self.session.flush()
        return event
    
    def get_events_by_user(self, user_id: UUID, limit: int = 100) -> List[AuditEvent]:
        """Get audit events for a specific user."""
        return self.session.query(AuditEvent).filter(
            AuditEvent.user_id == user_id
        ).order_by(desc(AuditEvent.created_at)).limit(limit).all()
    
    def get_events_by_resource(self, resource_type: str, resource_id: str) -> List[AuditEvent]:
        """Get audit events for a specific resource."""
        return self.session.query(AuditEvent).filter(
            AuditEvent.resource_type == resource_type,
            AuditEvent.resource_id == resource_id
        ).order_by(desc(AuditEvent.created_at)).all()
    
    def get_events_by_date_range(self, start_date: datetime, end_date: datetime) -> List[AuditEvent]:
        """Get audit events within a date range."""
        return self.session.query(AuditEvent).filter(
            AuditEvent.created_at >= start_date,
            AuditEvent.created_at <= end_date
        ).order_by(desc(AuditEvent.created_at)).all()
    
    def verify_integrity_chain(self, limit: int = 1000) -> Dict[str, Any]:
        """Verify the integrity of the audit chain."""
        events = self.session.query(AuditEvent).order_by(
            AuditEvent.created_at
        ).limit(limit).all()
        
        if not events:
            return {"valid": True, "message": "No events to verify"}
        
        for i, event in enumerate(events):
            expected_previous = events[i-1].integrity_hash if i > 0 else "genesis"
            if event.previous_hash != expected_previous:
                return {
                    "valid": False,
                    "message": f"Integrity chain broken at event {event.id}",
                    "event_id": event.id
                }
        
        return {"valid": True, "message": f"Verified {len(events)} events"}


class BatchJobRepository(BaseRepository[BatchJob]):
    """Repository for batch job management."""
    
    def __init__(self, session: Optional[Session] = None):
        super().__init__(BatchJob, session)
    
    def create_batch_job(self, job_type: str, parameters: Dict[str, Any],
                        user_id: Optional[UUID] = None) -> BatchJob:
        """Create a new batch job."""
        job = BatchJob(
            job_type=job_type,
            status="pending",
            parameters=parameters,
            user_id=user_id,
            created_at=datetime.utcnow()
        )
        
        self.session.add(job)
        self.session.flush()
        return job
    
    def update_job_status(self, job_id: UUID, status: str, 
                         progress: Optional[float] = None,
                         result: Optional[Dict[str, Any]] = None) -> bool:
        """Update batch job status and progress."""
        job = self.get_by_id(job_id)
        if job:
            job.status = status
            job.updated_at = datetime.utcnow()
            
            if progress is not None:
                job.progress = progress
            
            if result is not None:
                job.result = result
            
            if status in ["completed", "failed"]:
                job.completed_at = datetime.utcnow()
            
            return True
        return False
    
    def get_pending_jobs(self, limit: int = 100) -> List[BatchJob]:
        """Get pending batch jobs."""
        return self.session.query(BatchJob).filter(
            BatchJob.status == "pending"
        ).order_by(BatchJob.created_at).limit(limit).all()
    
    def get_user_jobs(self, user_id: UUID, limit: int = 100) -> List[BatchJob]:
        """Get batch jobs for a specific user."""
        return self.session.query(BatchJob).filter(
            BatchJob.user_id == user_id
        ).order_by(desc(BatchJob.created_at)).limit(limit).all()


# Repository Factory
class RepositoryFactory:
    """Factory for creating repository instances with proper session injection."""
    
    def __init__(self, session: Session):
        self.session = session
        self._repositories = {}
    
    def get_user_repository(self) -> UserRepository:
        """Get user repository instance."""
        if 'user' not in self._repositories:
            self._repositories['user'] = UserRepository(self.session)
        return self._repositories['user']
    
    def get_session_repository(self) -> SessionRepository:
        """Get session repository instance."""
        if 'session' not in self._repositories:
            self._repositories['session'] = SessionRepository(self.session)
        return self._repositories['session']
    
    def get_policy_repository(self) -> PolicyRepository:
        """Get policy repository instance."""
        if 'policy' not in self._repositories:
            self._repositories['policy'] = PolicyRepository(self.session)
        return self._repositories['policy']
    
    def get_document_repository(self) -> DocumentRepository:
        """Get document repository instance."""
        if 'document' not in self._repositories:
            self._repositories['document'] = DocumentRepository(self.session)
        return self._repositories['document']
    
    def get_audit_repository(self) -> AuditRepository:
        """Get audit repository instance."""
        if 'audit' not in self._repositories:
            self._repositories['audit'] = AuditRepository(self.session)
        return self._repositories['audit']
    
    def get_batch_job_repository(self):
        """Get batch job repository instance."""
        if 'batch_job' not in self._repositories:
            from .repositories.batch_job_repository import BatchJobRepository
            self._repositories['batch_job'] = BatchJobRepository(self.session)
        return self._repositories['batch_job']
    
    def get_job_result_repository(self):
        """Get job result repository instance."""
        if 'job_result' not in self._repositories:
            from .repositories.job_result_repository import JobResultRepository
            self._repositories['job_result'] = JobResultRepository(self.session)
        return self._repositories['job_result']
    
    def get_batch_worker_repository(self):
        """Get batch worker repository instance."""
        if 'batch_worker' not in self._repositories:
            from .repositories.batch_worker_repository import BatchWorkerRepository
            self._repositories['batch_worker'] = BatchWorkerRepository(self.session)
        return self._repositories['batch_worker']
    
    def get_job_schedule_repository(self):
        """Get job schedule repository instance."""
        if 'job_schedule' not in self._repositories:
            from .repositories.job_schedule_repository import JobScheduleRepository
            self._repositories['job_schedule'] = JobScheduleRepository(self.session)
        return self._repositories['job_schedule']


# FastAPI Dependencies for Repository Injection
def get_repository_factory(session: Session = get_db_session()) -> RepositoryFactory:
    """
    FastAPI dependency for getting repository factory.
    
    Usage:
        @app.get("/users/")
        def get_users(repos: RepositoryFactory = Depends(get_repository_factory)):
            return repos.get_user_repository().get_all()
    """
    return RepositoryFactory(session)


# Convenience Functions for Common Operations
def with_repositories(func):
    """Decorator to automatically inject repository factory."""
    from functools import wraps
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        with transaction_scope() as session:
            repos = RepositoryFactory(session)
            return func(repos, *args, **kwargs)
    
    return wrapper