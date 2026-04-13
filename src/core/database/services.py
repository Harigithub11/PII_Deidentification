"""
Database Service Layer

Provides high-level database operations and business logic integration
for the PII De-identification System.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from uuid import UUID, uuid4

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from .session import get_db_session, transaction_scope, with_db_transaction
from .repositories import RepositoryFactory
from .models import User, Document, Policy, AuditEvent, BatchJob
from ..config.settings import get_settings
from ..security.encryption import encryption_manager

logger = logging.getLogger(__name__)
settings = get_settings()


class DatabaseService:
    """High-level database service providing business logic operations."""
    
    def __init__(self, session: Optional[Session] = None):
        self._session = session
        self._repos = None
    
    @property
    def repos(self) -> RepositoryFactory:
        """Get repository factory instance."""
        if self._repos is None:
            if self._session:
                self._repos = RepositoryFactory(self._session)
            else:
                raise RuntimeError("No session available")
        return self._repos


class UserService(DatabaseService):
    """Service for user management operations."""
    
    @with_db_transaction()
    def create_user_account(self, username: str, email: str, password: str,
                          full_name: Optional[str] = None, role: str = "user") -> Dict[str, Any]:
        """
        Create a new user account with validation and audit logging.
        
        Args:
            username: Username for the account
            email: Email address
            password: Plain text password (will be hashed)
            full_name: Optional full name
            role: User role (default: user)
            
        Returns:
            Result dictionary with user information
        """
        result = {"success": False, "user_id": None, "errors": []}
        
        try:
            with transaction_scope() as session:
                repos = RepositoryFactory(session)
                
                # Hash password
                password_hash = encryption_manager.hash_password(password)
                
                # Create user
                user = repos.get_user_repository().create_user(
                    username=username,
                    email=email,
                    password_hash=password_hash,
                    full_name=full_name,
                    role=role
                )
                
                # Create audit event
                repos.get_audit_repository().create_audit_event(
                    event_type="user_management",
                    resource_type="user",
                    resource_id=str(user.id),
                    action="user_created",
                    metadata={
                        "username": username,
                        "email": email,
                        "role": role
                    }
                )
                
                result["success"] = True
                result["user_id"] = str(user.id)
                logger.info(f"User account created: {username} ({email})")
        
        except ValueError as e:
            result["errors"].append(str(e))
        except Exception as e:
            result["errors"].append(f"Failed to create user account: {e}")
            logger.error(f"User creation failed: {e}")
        
        return result
    
    def authenticate_user(self, username: str, password: str, ip_address: Optional[str] = None) -> Dict[str, Any]:
        """
        Authenticate user and create session.
        
        Args:
            username: Username or email
            password: Plain text password
            ip_address: Client IP address
            
        Returns:
            Authentication result with session token
        """
        result = {"success": False, "user_id": None, "session_token": None, "errors": []}
        
        try:
            with transaction_scope() as session:
                repos = RepositoryFactory(session)
                user_repo = repos.get_user_repository()
                session_repo = repos.get_session_repository()
                audit_repo = repos.get_audit_repository()
                
                # Find user by username or email
                user = user_repo.get_by_username(username) or user_repo.get_by_email(username)
                
                if not user:
                    result["errors"].append("Invalid credentials")
                    # Log failed attempt
                    audit_repo.create_audit_event(
                        event_type="authentication",
                        resource_type="user",
                        resource_id="unknown",
                        action="login_failed",
                        metadata={"username": username, "reason": "user_not_found"},
                        ip_address=ip_address
                    )
                    return result
                
                # Verify password
                if not encryption_manager.verify_password(password, user.password_hash):
                    result["errors"].append("Invalid credentials")
                    # Log failed attempt
                    audit_repo.create_audit_event(
                        event_type="authentication",
                        resource_type="user",
                        resource_id=str(user.id),
                        action="login_failed",
                        metadata={"username": username, "reason": "invalid_password"},
                        ip_address=ip_address
                    )
                    return result
                
                if not user.is_active:
                    result["errors"].append("Account is disabled")
                    return result
                
                # Create session
                session_token = str(uuid4())
                expires_at = datetime.utcnow() + timedelta(hours=24)
                
                user_session = session_repo.create_session(
                    user_id=user.id,
                    session_token=session_token,
                    expires_at=expires_at,
                    ip_address=ip_address or "unknown",
                    user_agent="api"
                )
                
                # Update user last login
                user.last_login = datetime.utcnow()
                
                # Log successful authentication
                audit_repo.create_audit_event(
                    event_type="authentication",
                    resource_type="user",
                    resource_id=str(user.id),
                    action="login_success",
                    metadata={
                        "username": username,
                        "session_id": str(user_session.id)
                    },
                    user_id=user.id,
                    ip_address=ip_address
                )
                
                result["success"] = True
                result["user_id"] = str(user.id)
                result["session_token"] = session_token
                result["expires_at"] = expires_at.isoformat()
                
                logger.info(f"User authenticated: {username}")
        
        except Exception as e:
            result["errors"].append(f"Authentication failed: {e}")
            logger.error(f"Authentication error: {e}")
        
        return result
    
    def validate_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """
        Validate a session token and return user information.
        
        Args:
            session_token: Session token to validate
            
        Returns:
            User information if session is valid, None otherwise
        """
        try:
            with transaction_scope() as session:
                repos = RepositoryFactory(session)
                session_repo = repos.get_session_repository()
                
                user_session = session_repo.get_by_token(session_token)
                if not user_session:
                    return None
                
                user = repos.get_user_repository().get_by_id(user_session.user_id)
                if not user or not user.is_active:
                    return None
                
                return {
                    "user_id": str(user.id),
                    "username": user.username,
                    "email": user.email,
                    "role": user.role,
                    "session_id": str(user_session.id)
                }
        
        except Exception as e:
            logger.error(f"Session validation failed: {e}")
            return None


class DocumentService(DatabaseService):
    """Service for document management operations."""
    
    def register_document(self, filename: str, file_type: str, file_size: int,
                         file_hash: str, original_path: str, user_id: UUID,
                         metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Register a new document for processing.
        
        Args:
            filename: Original filename
            file_type: File MIME type
            file_size: File size in bytes
            file_hash: SHA-256 hash of file content
            original_path: Original file path
            user_id: ID of user uploading the document
            metadata: Additional metadata
            
        Returns:
            Document registration result
        """
        result = {"success": False, "document_id": None, "errors": []}
        
        try:
            with transaction_scope() as session:
                repos = RepositoryFactory(session)
                doc_repo = repos.get_document_repository()
                audit_repo = repos.get_audit_repository()
                
                # Check for duplicate file
                existing_doc = doc_repo.get_by_hash(file_hash)
                if existing_doc:
                    result["errors"].append("Document with this content already exists")
                    result["existing_document_id"] = str(existing_doc.id)
                    return result
                
                # Create document record
                document = doc_repo.create_document(
                    filename=filename,
                    file_type=file_type,
                    file_size=file_size,
                    file_hash=file_hash,
                    original_path=original_path,
                    user_id=user_id,
                    metadata=metadata
                )
                
                # Create audit event
                audit_repo.create_audit_event(
                    event_type="document_management",
                    resource_type="document",
                    resource_id=str(document.id),
                    action="document_uploaded",
                    user_id=user_id,
                    metadata={
                        "filename": filename,
                        "file_type": file_type,
                        "file_size": file_size
                    }
                )
                
                result["success"] = True
                result["document_id"] = str(document.id)
                
                logger.info(f"Document registered: {filename} (ID: {document.id})")
        
        except Exception as e:
            result["errors"].append(f"Document registration failed: {e}")
            logger.error(f"Document registration error: {e}")
        
        return result
    
    def update_document_status(self, document_id: UUID, status: str, 
                              processing_result: Optional[Dict[str, Any]] = None,
                              user_id: Optional[UUID] = None) -> bool:
        """
        Update document processing status.
        
        Args:
            document_id: Document ID
            status: New status
            processing_result: Processing result data
            user_id: ID of user making the update
            
        Returns:
            Success status
        """
        try:
            with transaction_scope() as session:
                repos = RepositoryFactory(session)
                doc_repo = repos.get_document_repository()
                audit_repo = repos.get_audit_repository()
                
                success = doc_repo.update_status(document_id, status, processing_result)
                
                if success:
                    # Create audit event
                    audit_repo.create_audit_event(
                        event_type="document_processing",
                        resource_type="document",
                        resource_id=str(document_id),
                        action="status_updated",
                        user_id=user_id,
                        metadata={
                            "new_status": status,
                            "has_result": processing_result is not None
                        }
                    )
                    
                    logger.info(f"Document status updated: {document_id} -> {status}")
                
                return success
        
        except Exception as e:
            logger.error(f"Document status update failed: {e}")
            return False


class PolicyService(DatabaseService):
    """Service for policy management operations."""
    
    def create_policy(self, name: str, description: str, compliance_standard: str,
                     rules: List[Dict[str, Any]], user_id: Optional[UUID] = None,
                     **kwargs) -> Dict[str, Any]:
        """
        Create a new policy with validation.
        
        Args:
            name: Policy name
            description: Policy description
            compliance_standard: Compliance standard name
            rules: List of policy rules
            user_id: ID of user creating the policy
            **kwargs: Additional policy parameters
            
        Returns:
            Policy creation result
        """
        result = {"success": False, "policy_id": None, "errors": []}
        
        try:
            with transaction_scope() as session:
                repos = RepositoryFactory(session)
                policy_repo = repos.get_policy_repository()
                audit_repo = repos.get_audit_repository()
                
                # Check for existing policy with same name
                existing_policy = policy_repo.get_by_name(name)
                if existing_policy:
                    result["errors"].append("Policy with this name already exists")
                    return result
                
                # Create policy
                policy = policy_repo.create_policy(
                    name=name,
                    description=description,
                    compliance_standard=compliance_standard,
                    rules=rules,
                    **kwargs
                )
                
                # Create audit event
                audit_repo.create_audit_event(
                    event_type="policy_management",
                    resource_type="policy",
                    resource_id=str(policy.id),
                    action="policy_created",
                    user_id=user_id,
                    metadata={
                        "policy_name": name,
                        "compliance_standard": compliance_standard,
                        "rules_count": len(rules)
                    }
                )
                
                result["success"] = True
                result["policy_id"] = str(policy.id)
                
                logger.info(f"Policy created: {name} (ID: {policy.id})")
        
        except Exception as e:
            result["errors"].append(f"Policy creation failed: {e}")
            logger.error(f"Policy creation error: {e}")
        
        return result


class BatchJobService(DatabaseService):
    """Service for batch job management."""
    
    def create_batch_job(self, job_type: str, parameters: Dict[str, Any],
                        user_id: Optional[UUID] = None) -> Dict[str, Any]:
        """
        Create a new batch job.
        
        Args:
            job_type: Type of batch job
            parameters: Job parameters
            user_id: ID of user creating the job
            
        Returns:
            Job creation result
        """
        result = {"success": False, "job_id": None, "errors": []}
        
        try:
            with transaction_scope() as session:
                repos = RepositoryFactory(session)
                job_repo = repos.get_batch_job_repository()
                audit_repo = repos.get_audit_repository()
                
                # Create batch job
                job = job_repo.create_batch_job(job_type, parameters, user_id)
                
                # Create audit event
                audit_repo.create_audit_event(
                    event_type="batch_processing",
                    resource_type="batch_job",
                    resource_id=str(job.id),
                    action="job_created",
                    user_id=user_id,
                    metadata={
                        "job_type": job_type,
                        "parameters": parameters
                    }
                )
                
                result["success"] = True
                result["job_id"] = str(job.id)
                
                logger.info(f"Batch job created: {job_type} (ID: {job.id})")
        
        except Exception as e:
            result["errors"].append(f"Batch job creation failed: {e}")
            logger.error(f"Batch job creation error: {e}")
        
        return result
    
    def update_job_progress(self, job_id: UUID, status: str, progress: float,
                           result_data: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update batch job progress.
        
        Args:
            job_id: Job ID
            status: Job status
            progress: Progress percentage (0.0 to 1.0)
            result_data: Result data if job is completed
            
        Returns:
            Success status
        """
        try:
            with transaction_scope() as session:
                repos = RepositoryFactory(session)
                job_repo = repos.get_batch_job_repository()
                
                return job_repo.update_job_status(job_id, status, progress, result_data)
        
        except Exception as e:
            logger.error(f"Job progress update failed: {e}")
            return False


class AuditService(DatabaseService):
    """Service for audit and logging operations."""
    
    def log_user_activity(self, user_id: UUID, activity_type: str, description: str,
                         metadata: Optional[Dict[str, Any]] = None,
                         ip_address: Optional[str] = None) -> bool:
        """
        Log user activity.
        
        Args:
            user_id: User ID
            activity_type: Type of activity
            description: Activity description
            metadata: Additional metadata
            ip_address: User's IP address
            
        Returns:
            Success status
        """
        try:
            with transaction_scope() as session:
                repos = RepositoryFactory(session)
                audit_repo = repos.get_audit_repository()
                
                audit_repo.create_audit_event(
                    event_type="user_activity",
                    resource_type="user",
                    resource_id=str(user_id),
                    action=activity_type,
                    user_id=user_id,
                    metadata={"description": description, **(metadata or {})},
                    ip_address=ip_address
                )
                
                return True
        
        except Exception as e:
            logger.error(f"User activity logging failed: {e}")
            return False
    
    def get_audit_trail(self, resource_type: str, resource_id: str) -> List[Dict[str, Any]]:
        """
        Get audit trail for a resource.
        
        Args:
            resource_type: Type of resource
            resource_id: Resource ID
            
        Returns:
            List of audit events
        """
        try:
            with transaction_scope() as session:
                repos = RepositoryFactory(session)
                audit_repo = repos.get_audit_repository()
                
                events = audit_repo.get_events_by_resource(resource_type, resource_id)
                
                return [
                    {
                        "id": str(event.id),
                        "event_type": event.event_type,
                        "action": event.action,
                        "user_id": str(event.user_id) if event.user_id else None,
                        "created_at": event.created_at.isoformat(),
                        "metadata": event.metadata,
                        "ip_address": event.ip_address
                    }
                    for event in events
                ]
        
        except Exception as e:
            logger.error(f"Audit trail retrieval failed: {e}")
            return []


# Service Factory
class DatabaseServiceFactory:
    """Factory for creating database service instances."""
    
    def __init__(self, session: Optional[Session] = None):
        self.session = session
    
    def get_user_service(self) -> UserService:
        """Get user service instance."""
        return UserService(self.session)
    
    def get_document_service(self) -> DocumentService:
        """Get document service instance."""
        return DocumentService(self.session)
    
    def get_policy_service(self) -> PolicyService:
        """Get policy service instance."""
        return PolicyService(self.session)
    
    def get_batch_job_service(self) -> BatchJobService:
        """Get batch job service instance."""
        return BatchJobService(self.session)
    
    def get_audit_service(self) -> AuditService:
        """Get audit service instance."""
        return AuditService(self.session)


# FastAPI Dependencies
def get_database_services(session: Session = get_db_session()) -> DatabaseServiceFactory:
    """
    FastAPI dependency for getting database services.
    
    Usage:
        @app.post("/users/")
        def create_user(user_data: dict, services: DatabaseServiceFactory = Depends(get_database_services)):
            return services.get_user_service().create_user_account(**user_data)
    """
    return DatabaseServiceFactory(session)