"""
Database Initialization and Migration Integration

Handles database setup, schema creation, migrations, and initial data seeding.
"""

import logging
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import SQLAlchemyError

from .connection import get_database_manager, DatabaseConnectionManager
from .models import Base
from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class DatabaseInitializer:
    """Handles database initialization and migration operations."""
    
    def __init__(self, db_manager: Optional[DatabaseConnectionManager] = None):
        self.db_manager = db_manager or get_database_manager()
        self.project_root = Path(__file__).parent.parent.parent.parent
        self.migrations_dir = self.project_root / "database" / "migrations"
        self.schema_dir = self.project_root / "database" / "schema"
        self.alembic_cfg_path = self.project_root / "alembic.ini"
    
    def initialize_database(self, force_recreate: bool = False) -> Dict[str, Any]:
        """
        Initialize the database with schema and initial data.
        
        Args:
            force_recreate: Whether to drop and recreate all tables
            
        Returns:
            Initialization result dictionary
        """
        result = {
            "success": False,
            "steps_completed": [],
            "errors": [],
            "database_info": {}
        }
        
        try:
            # Check database connectivity
            health_check = self.db_manager.health_check()
            if not health_check["healthy"]:
                result["errors"].append(f"Database connection failed: {health_check.get('error', 'Unknown error')}")
                return result
            
            result["steps_completed"].append("Database connectivity verified")
            result["database_info"] = health_check["database_info"]
            
            # Check if database needs initialization
            needs_init = self._needs_initialization()
            
            if force_recreate or needs_init:
                if force_recreate:
                    logger.warning("Force recreating database schema")
                    self._drop_all_tables()
                    result["steps_completed"].append("Existing tables dropped")
                
                # Create schema using SQLAlchemy models
                self._create_schema()
                result["steps_completed"].append("Database schema created")
                
                # Run initial migration if Alembic is set up
                if self._has_alembic_setup():
                    self._initialize_alembic()
                    result["steps_completed"].append("Alembic migration system initialized")
                
                # Seed initial data
                self._seed_initial_data()
                result["steps_completed"].append("Initial data seeded")
                
            else:
                # Run pending migrations
                migration_result = self.run_migrations()
                if migration_result["success"]:
                    result["steps_completed"].append(f"Migrations applied: {migration_result['migrations_applied']}")
                else:
                    result["errors"].extend(migration_result["errors"])
            
            # Validate final schema
            validation_result = self._validate_schema()
            if validation_result["valid"]:
                result["steps_completed"].append("Schema validation passed")
                result["success"] = True
            else:
                result["errors"].extend(validation_result["errors"])
            
            logger.info("Database initialization completed successfully")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            result["errors"].append(str(e))
        
        return result
    
    def _needs_initialization(self) -> bool:
        """Check if database needs initialization."""
        try:
            with self.db_manager.get_connection() as conn:
                inspector = inspect(conn)
                tables = inspector.get_table_names()
                
                # Check for core tables
                core_tables = ["users", "audit_events", "policies", "documents"]
                return not any(table in tables for table in core_tables)
        
        except Exception as e:
            logger.warning(f"Could not check database state: {e}")
            return True
    
    def _drop_all_tables(self):
        """Drop all tables in the database."""
        try:
            Base.metadata.drop_all(bind=self.db_manager.engine)
            logger.info("All tables dropped")
        except Exception as e:
            logger.error(f"Failed to drop tables: {e}")
            raise
    
    def _create_schema(self):
        """Create database schema using SQLAlchemy models."""
        try:
            Base.metadata.create_all(bind=self.db_manager.engine)
            logger.info("Database schema created successfully")
        except Exception as e:
            logger.error(f"Failed to create schema: {e}")
            raise
    
    def _has_alembic_setup(self) -> bool:
        """Check if Alembic is properly set up."""
        return (
            self.alembic_cfg_path.exists() and
            self.migrations_dir.exists() and
            (self.migrations_dir / "versions").exists()
        )
    
    def _initialize_alembic(self):
        """Initialize Alembic migration tracking."""
        try:
            if not self._has_alembic_setup():
                logger.warning("Alembic not properly set up, skipping migration initialization")
                return
            
            alembic_cfg = Config(str(self.alembic_cfg_path))
            
            # Check if alembic_version table exists
            with self.db_manager.get_connection() as conn:
                inspector = inspect(conn)
                if "alembic_version" not in inspector.get_table_names():
                    # Stamp with initial revision
                    command.stamp(alembic_cfg, "head")
                    logger.info("Alembic version tracking initialized")
        
        except Exception as e:
            logger.error(f"Failed to initialize Alembic: {e}")
            raise
    
    def run_migrations(self, target_revision: Optional[str] = None) -> Dict[str, Any]:
        """
        Run database migrations.
        
        Args:
            target_revision: Specific revision to migrate to (defaults to head)
            
        Returns:
            Migration result dictionary
        """
        result = {
            "success": False,
            "migrations_applied": 0,
            "errors": [],
            "current_revision": None,
            "target_revision": target_revision or "head"
        }
        
        try:
            if not self._has_alembic_setup():
                result["errors"].append("Alembic not properly configured")
                return result
            
            alembic_cfg = Config(str(self.alembic_cfg_path))
            
            # Get current revision
            with self.db_manager.get_connection() as conn:
                try:
                    current_result = conn.execute(text("SELECT version_num FROM alembic_version"))
                    current_revision = current_result.scalar()
                    result["current_revision"] = current_revision
                except:
                    # No alembic_version table - first time setup
                    command.stamp(alembic_cfg, "head")
                    result["current_revision"] = "head"
                    result["success"] = True
                    return result
            
            # Run migrations
            command.upgrade(alembic_cfg, target_revision or "head")
            
            # Count applied migrations (simplified)
            result["migrations_applied"] = 1  # This would need more sophisticated tracking
            result["success"] = True
            
            logger.info(f"Migrations completed successfully to {target_revision or 'head'}")
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            result["errors"].append(str(e))
        
        return result
    
    def create_migration(self, message: str, autogenerate: bool = True) -> Dict[str, Any]:
        """
        Create a new migration.
        
        Args:
            message: Migration description
            autogenerate: Whether to auto-detect model changes
            
        Returns:
            Migration creation result
        """
        result = {
            "success": False,
            "migration_file": None,
            "errors": []
        }
        
        try:
            if not self._has_alembic_setup():
                result["errors"].append("Alembic not properly configured")
                return result
            
            alembic_cfg = Config(str(self.alembic_cfg_path))
            
            # Create migration
            command.revision(
                alembic_cfg,
                message=message,
                autogenerate=autogenerate
            )
            
            result["success"] = True
            logger.info(f"Migration created: {message}")
            
        except Exception as e:
            logger.error(f"Failed to create migration: {e}")
            result["errors"].append(str(e))
        
        return result
    
    def _seed_initial_data(self):
        """Seed initial data into the database."""
        try:
            with self.db_manager.get_session() as session:
                # Import here to avoid circular imports
                from .repositories import RepositoryFactory
                
                repos = RepositoryFactory(session)
                
                # Seed compliance standards
                self._seed_compliance_standards(repos)
                
                # Seed initial admin user if configured
                self._seed_admin_user(repos)
                
                # Seed default policy templates
                self._seed_policy_templates(repos)
                
                session.commit()
                logger.info("Initial data seeded successfully")
        
        except Exception as e:
            logger.error(f"Failed to seed initial data: {e}")
            raise
    
    def _seed_compliance_standards(self, repos):
        """Seed compliance standards."""
        from .models import ComplianceStandard
        
        standards = [
            {
                "name": "GDPR",
                "description": "General Data Protection Regulation",
                "version": "2018.1",
                "authority": "European Union",
                "requirements": {
                    "data_minimization": True,
                    "consent_required": True,
                    "right_to_erasure": True,
                    "data_portability": True
                }
            },
            {
                "name": "HIPAA",
                "description": "Health Insurance Portability and Accountability Act",
                "version": "1996.1",
                "authority": "United States HHS",
                "requirements": {
                    "phi_protection": True,
                    "minimum_necessary": True,
                    "audit_controls": True,
                    "access_controls": True
                }
            },
            {
                "name": "NDHM",
                "description": "National Digital Health Mission",
                "version": "2020.1",
                "authority": "Government of India",
                "requirements": {
                    "health_data_protection": True,
                    "consent_framework": True,
                    "data_localization": True,
                    "interoperability": True
                }
            }
        ]
        
        for standard_data in standards:
            existing = repos.session.query(ComplianceStandard).filter(
                ComplianceStandard.name == standard_data["name"]
            ).first()
            
            if not existing:
                standard = ComplianceStandard(**standard_data)
                repos.session.add(standard)
    
    def _seed_admin_user(self, repos):
        """Seed initial admin user if configured."""
        admin_email = settings.initial_admin_email
        if not admin_email:
            return
        
        user_repo = repos.get_user_repository()
        existing_admin = user_repo.get_by_email(admin_email)
        
        if not existing_admin:
            # This would need proper password hashing
            admin_user = user_repo.create_user(
                username="admin",
                email=admin_email,
                password_hash="hashed_password",  # Use proper hashing
                full_name="System Administrator",
                role="admin"
            )
            logger.info(f"Created admin user: {admin_email}")
    
    def _seed_policy_templates(self, repos):
        """Seed default policy templates."""
        from .models import PolicyTemplate
        
        templates = [
            {
                "name": "GDPR Standard",
                "compliance_standard": "GDPR",
                "description": "Standard GDPR compliance policy template",
                "template_config": {
                    "default_redaction_method": "blackout",
                    "enable_audit_logging": True,
                    "require_approval": False,
                    "allow_pseudonymization": True
                }
            },
            {
                "name": "HIPAA Standard",
                "compliance_standard": "HIPAA",
                "description": "Standard HIPAA compliance policy template",
                "template_config": {
                    "default_redaction_method": "blackout",
                    "enable_audit_logging": True,
                    "require_approval": True,
                    "allow_pseudonymization": False
                }
            }
        ]
        
        for template_data in templates:
            existing = repos.session.query(PolicyTemplate).filter(
                PolicyTemplate.name == template_data["name"]
            ).first()
            
            if not existing:
                template = PolicyTemplate(**template_data)
                repos.session.add(template)
    
    def _validate_schema(self) -> Dict[str, Any]:
        """Validate the database schema."""
        result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "table_count": 0
        }
        
        try:
            with self.db_manager.get_connection() as conn:
                inspector = inspect(conn)
                tables = inspector.get_table_names()
                result["table_count"] = len(tables)
                
                # Check for required tables
                required_tables = [
                    "users", "user_sessions", "api_keys",
                    "compliance_standards", "policy_templates", "policies", "policy_rules",
                    "audit_events", "user_activities", "system_events", "security_events",
                    "documents", "document_versions", "file_storage", "redaction_metadata",
                    "batch_jobs", "processing_steps", "workflow_executions"
                ]
                
                missing_tables = [table for table in required_tables if table not in tables]
                if missing_tables:
                    result["errors"].append(f"Missing required tables: {missing_tables}")
                    result["valid"] = False
                
                # Check table structures
                for table in required_tables:
                    if table in tables:
                        columns = inspector.get_columns(table)
                        if not columns:
                            result["warnings"].append(f"Table {table} has no columns")
        
        except Exception as e:
            result["valid"] = False
            result["errors"].append(str(e))
        
        return result
    
    def get_migration_status(self) -> Dict[str, Any]:
        """Get current migration status."""
        result = {
            "current_revision": None,
            "pending_migrations": [],
            "migration_history": [],
            "alembic_configured": False
        }
        
        try:
            if not self._has_alembic_setup():
                return result
            
            result["alembic_configured"] = True
            
            alembic_cfg = Config(str(self.alembic_cfg_path))
            
            # Get current revision
            with self.db_manager.get_connection() as conn:
                try:
                    current_result = conn.execute(text("SELECT version_num FROM alembic_version"))
                    result["current_revision"] = current_result.scalar()
                except:
                    result["current_revision"] = None
            
            # This would need more sophisticated implementation to get
            # pending migrations and history from Alembic
        
        except Exception as e:
            logger.error(f"Failed to get migration status: {e}")
        
        return result
    
    def backup_database(self) -> Dict[str, Any]:
        """Create a database backup before major operations."""
        try:
            db_url = str(self.db_manager.engine.url)
            
            if 'sqlite' in db_url:
                from .database_encryption import db_encryption_manager
                return db_encryption_manager.create_encrypted_sqlite_backup(
                    db_url.replace('sqlite:///', '')
                )
            elif 'postgresql' in db_url:
                # Extract connection parameters
                url_parts = db_url.replace('postgresql://', '').split('@')
                auth_part = url_parts[0]
                host_part = url_parts[1]
                
                username, password = auth_part.split(':')
                host_port, database = host_part.split('/')
                host, port = host_port.split(':') if ':' in host_port else (host_port, '5432')
                
                connection_params = {
                    'host': host,
                    'port': int(port),
                    'username': username,
                    'password': password,
                    'database': database
                }
                
                from .database_encryption import db_encryption_manager
                return db_encryption_manager.create_postgresql_encrypted_backup(connection_params)
            
            return {"success": False, "error": "Unsupported database type for backup"}
        
        except Exception as e:
            return {"success": False, "error": str(e)}


# Global database initializer
_db_initializer: Optional[DatabaseInitializer] = None


def get_database_initializer() -> DatabaseInitializer:
    """Get the global database initializer instance."""
    global _db_initializer
    if _db_initializer is None:
        _db_initializer = DatabaseInitializer()
    return _db_initializer


def initialize_database_system(force_recreate: bool = False) -> Dict[str, Any]:
    """Initialize the complete database system."""
    initializer = get_database_initializer()
    return initializer.initialize_database(force_recreate)


def run_database_migrations(target_revision: Optional[str] = None) -> Dict[str, Any]:
    """Run database migrations."""
    initializer = get_database_initializer()
    return initializer.run_migrations(target_revision)


def create_database_migration(message: str, autogenerate: bool = True) -> Dict[str, Any]:
    """Create a new database migration."""
    initializer = get_database_initializer()
    return initializer.create_migration(message, autogenerate)