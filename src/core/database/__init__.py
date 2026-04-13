"""
Database module for PII De-identification System

Provides comprehensive database management including encrypted fields, connection management,
ORM models, repositories, services, and CLI tools.
"""

# Core Database Components
from .encrypted_fields import EncryptedString, EncryptedText, EncryptedJSON
from .database_encryption import DatabaseEncryptionManager, db_encryption_manager
from .connection import (
    DatabaseConnectionManager, 
    get_database_manager, 
    initialize_database,
    close_database,
    get_engine,
    get_session_factory,
    get_db_session,
    get_db_connection
)

# Session Management
from .session import (
    SessionManager,
    get_session_manager,
    initialize_session_manager,
    get_db_session as get_session_dependency,
    get_read_only_db_session,
    transaction_scope,
    nested_transaction_scope,
    batch_session,
    with_db_transaction,
    check_session_health,
    get_session_statistics,
    close_session_manager
)

# ORM Models
from .models import (
    Base,
    User, UserSession, APIKey,
    ComplianceStandard, PolicyTemplate, Policy, PolicyRule, PolicyExecution,
    AuditEvent, UserActivity, SystemEvent, SecurityEvent, DataProcessingLog,
    Document, DocumentVersion, FileStorage, RedactionMetadata,
    BatchJob, ProcessingStep, WorkflowExecution
)

# Repository Layer
from .repositories import (
    BaseRepository, UserRepository, SessionRepository, PolicyRepository,
    DocumentRepository, AuditRepository, BatchJobRepository,
    RepositoryFactory, get_repository_factory, with_repositories
)

# Service Layer
from .services import (
    DatabaseService, UserService, DocumentService, PolicyService,
    BatchJobService, AuditService, DatabaseServiceFactory, get_database_services
)

# FastAPI Dependencies
from .dependencies import (
    DatabaseException, AuthenticationException, AuthorizationException,
    get_db, get_read_only_db, get_repositories, get_services,
    get_current_user_optional, get_current_user, get_admin_user,
    require_roles, get_client_ip, get_user_agent, audit_request,
    validate_uuid, validate_pagination, handle_database_errors,
    check_database_health,
    # Typed dependencies
    DatabaseSession, ReadOnlySession, Repositories, Services,
    CurrentUser, OptionalUser, AdminUser, ClientIP, UserAgent, Pagination
)

# Database Initialization
from .initialization import (
    DatabaseInitializer, get_database_initializer,
    initialize_database_system, run_database_migrations, create_database_migration
)

# CLI Commands
from .cli import database_cli, register_database_commands

__all__ = [
    # Encrypted Fields
    "EncryptedString",
    "EncryptedText", 
    "EncryptedJSON",
    "DatabaseEncryptionManager",
    "db_encryption_manager",
    
    # Connection Management
    "DatabaseConnectionManager",
    "get_database_manager",
    "initialize_database",
    "close_database",
    "get_engine",
    "get_session_factory",
    "get_db_session",
    "get_db_connection",
    
    # Session Management
    "SessionManager",
    "get_session_manager",
    "initialize_session_manager",
    "get_session_dependency",
    "get_read_only_db_session",
    "transaction_scope",
    "nested_transaction_scope",
    "batch_session",
    "with_db_transaction",
    "check_session_health",
    "get_session_statistics",
    "close_session_manager",
    
    # ORM Models
    "Base",
    "User", "UserSession", "APIKey",
    "ComplianceStandard", "PolicyTemplate", "Policy", "PolicyRule", "PolicyExecution",
    "AuditEvent", "UserActivity", "SystemEvent", "SecurityEvent", "DataProcessingLog",
    "Document", "DocumentVersion", "FileStorage", "RedactionMetadata",
    "BatchJob", "ProcessingStep", "WorkflowExecution",
    
    # Repository Layer
    "BaseRepository", "UserRepository", "SessionRepository", "PolicyRepository",
    "DocumentRepository", "AuditRepository", "BatchJobRepository",
    "RepositoryFactory", "get_repository_factory", "with_repositories",
    
    # Service Layer
    "DatabaseService", "UserService", "DocumentService", "PolicyService",
    "BatchJobService", "AuditService", "DatabaseServiceFactory", "get_database_services",
    
    # FastAPI Dependencies
    "DatabaseException", "AuthenticationException", "AuthorizationException",
    "get_db", "get_read_only_db", "get_repositories", "get_services",
    "get_current_user_optional", "get_current_user", "get_admin_user",
    "require_roles", "get_client_ip", "get_user_agent", "audit_request",
    "validate_uuid", "validate_pagination", "handle_database_errors",
    "check_database_health",
    # Typed dependencies
    "DatabaseSession", "ReadOnlySession", "Repositories", "Services",
    "CurrentUser", "OptionalUser", "AdminUser", "ClientIP", "UserAgent", "Pagination",
    
    # Database Initialization
    "DatabaseInitializer", "get_database_initializer",
    "initialize_database_system", "run_database_migrations", "create_database_migration",
    
    # CLI Commands
    "database_cli", "register_database_commands"
]