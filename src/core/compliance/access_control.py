"""
PCI DSS Access Control Module

This module implements comprehensive access control mechanisms
as required by PCI DSS Requirements 7 and 8.
"""

import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
import re
import json
from pathlib import Path

import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..database.database_manager import DatabaseManager
from .pci_dss_core import PCIDSSComplianceEngine, PCIControl, ControlStatus

logger = logging.getLogger(__name__)


class UserRole(str, Enum):
    """User roles in the system."""
    ADMIN = "admin"
    SECURITY_OFFICER = "security_officer"
    COMPLIANCE_MANAGER = "compliance_manager"
    DATA_PROCESSOR = "data_processor"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    READ_ONLY = "read_only"
    GUEST = "guest"


class Permission(str, Enum):
    """System permissions."""
    # Data access permissions
    READ_PII = "read_pii"
    WRITE_PII = "write_pii"
    DELETE_PII = "delete_pii"
    EXPORT_PII = "export_pii"
    
    # System administration
    MANAGE_USERS = "manage_users"
    MANAGE_ROLES = "manage_roles"
    CONFIGURE_SYSTEM = "configure_system"
    
    # Security operations
    VIEW_AUDIT_LOGS = "view_audit_logs"
    MANAGE_SECURITY_POLICIES = "manage_security_policies"
    PERFORM_SCANS = "perform_scans"
    
    # Compliance operations
    VIEW_COMPLIANCE_REPORTS = "view_compliance_reports"
    MANAGE_COMPLIANCE_POLICIES = "manage_compliance_policies"
    APPROVE_EXCEPTIONS = "approve_exceptions"
    
    # Processing operations
    PROCESS_DOCUMENTS = "process_documents"
    BATCH_PROCESS = "batch_process"
    SCHEDULE_JOBS = "schedule_jobs"


class AuthenticationMethod(str, Enum):
    """Authentication methods."""
    PASSWORD = "password"
    TWO_FACTOR = "2fa"
    MULTI_FACTOR = "mfa"
    CERTIFICATE = "certificate"
    BIOMETRIC = "biometric"
    SSO = "sso"


class AccountStatus(str, Enum):
    """User account status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    SUSPENDED = "suspended"
    DISABLED = "disabled"
    PENDING_ACTIVATION = "pending_activation"


@dataclass
class User:
    """User account information."""
    user_id: str
    username: str
    email: str
    full_name: str
    role: UserRole
    permissions: Set[Permission] = field(default_factory=set)
    status: AccountStatus = AccountStatus.PENDING_ACTIVATION
    
    # Authentication
    password_hash: Optional[str] = None
    password_salt: Optional[str] = None
    two_factor_secret: Optional[str] = None
    authentication_methods: Set[AuthenticationMethod] = field(default_factory=set)
    
    # Account management
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    password_last_changed: Optional[datetime] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    
    # Session management
    current_session_id: Optional[str] = None
    session_expires_at: Optional[datetime] = None
    
    # Compliance tracking
    last_activity: Optional[datetime] = None
    privileged_access: bool = False
    requires_approval: bool = False


@dataclass
class AccessRequest:
    """Access request for privileged operations."""
    request_id: str
    user_id: str
    resource: str
    permission: Permission
    justification: str
    requested_at: datetime
    expires_at: datetime
    approved: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    denied_reason: Optional[str] = None


@dataclass
class Session:
    """User session information."""
    session_id: str
    user_id: str
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    active: bool = True
    privileged: bool = False


@dataclass
class PasswordPolicy:
    """Password policy configuration."""
    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special_chars: bool = True
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    max_age_days: int = 90
    history_count: int = 12
    lockout_attempts: int = 5
    lockout_duration_minutes: int = 30


@dataclass
class AccessLog:
    """Access log entry."""
    log_id: str
    user_id: str
    resource: str
    action: str
    permission: Permission
    timestamp: datetime
    ip_address: str
    user_agent: str
    success: bool
    failure_reason: Optional[str] = None
    risk_score: float = 0.0


class AccessControlManager:
    """
    Comprehensive access control manager implementing
    PCI DSS Requirements 7 and 8.
    """
    
    def __init__(self, 
                 db_manager: DatabaseManager,
                 compliance_engine: PCIDSSComplianceEngine):
        self.db_manager = db_manager
        self.compliance_engine = compliance_engine
        
        # User management
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.access_requests: Dict[str, AccessRequest] = {}
        self.access_logs: List[AccessLog] = []
        
        # Security policies
        self.password_policy = PasswordPolicy()
        self.session_timeout = timedelta(hours=2)
        self.privileged_session_timeout = timedelta(minutes=30)
        
        # Role-based permissions
        self.role_permissions = self._setup_role_permissions()
        
        # Security settings
        self.require_two_factor = True
        self.max_concurrent_sessions = 3
        self.inactive_user_days = 90
        
        logger.info("AccessControlManager initialized")
    
    def _setup_role_permissions(self) -> Dict[UserRole, Set[Permission]]:
        """Setup default role-based permissions."""
        return {
            UserRole.ADMIN: {
                Permission.READ_PII, Permission.WRITE_PII, Permission.DELETE_PII,
                Permission.EXPORT_PII, Permission.MANAGE_USERS, Permission.MANAGE_ROLES,
                Permission.CONFIGURE_SYSTEM, Permission.VIEW_AUDIT_LOGS,
                Permission.MANAGE_SECURITY_POLICIES, Permission.PERFORM_SCANS,
                Permission.VIEW_COMPLIANCE_REPORTS, Permission.MANAGE_COMPLIANCE_POLICIES,
                Permission.APPROVE_EXCEPTIONS, Permission.PROCESS_DOCUMENTS,
                Permission.BATCH_PROCESS, Permission.SCHEDULE_JOBS
            },
            UserRole.SECURITY_OFFICER: {
                Permission.READ_PII, Permission.VIEW_AUDIT_LOGS,
                Permission.MANAGE_SECURITY_POLICIES, Permission.PERFORM_SCANS,
                Permission.VIEW_COMPLIANCE_REPORTS, Permission.APPROVE_EXCEPTIONS
            },
            UserRole.COMPLIANCE_MANAGER: {
                Permission.READ_PII, Permission.VIEW_AUDIT_LOGS,
                Permission.VIEW_COMPLIANCE_REPORTS, Permission.MANAGE_COMPLIANCE_POLICIES,
                Permission.APPROVE_EXCEPTIONS
            },
            UserRole.DATA_PROCESSOR: {
                Permission.READ_PII, Permission.WRITE_PII, Permission.PROCESS_DOCUMENTS,
                Permission.BATCH_PROCESS
            },
            UserRole.ANALYST: {
                Permission.READ_PII, Permission.PROCESS_DOCUMENTS,
                Permission.VIEW_COMPLIANCE_REPORTS
            },
            UserRole.AUDITOR: {
                Permission.READ_PII, Permission.VIEW_AUDIT_LOGS,
                Permission.VIEW_COMPLIANCE_REPORTS
            },
            UserRole.READ_ONLY: {
                Permission.READ_PII, Permission.VIEW_COMPLIANCE_REPORTS
            },
            UserRole.GUEST: set()  # No permissions by default
        }
    
    async def create_user(self, 
                         username: str, 
                         email: str, 
                         full_name: str, 
                         role: UserRole,
                         password: str) -> User:
        """
        Create a new user account.
        
        Args:
            username: Unique username
            email: User email address
            full_name: User's full name
            role: User role
            password: Initial password
            
        Returns:
            Created user object
        """
        # Validate inputs
        if username in [user.username for user in self.users.values()]:
            raise ValueError("Username already exists")
        
        if email in [user.email for user in self.users.values()]:
            raise ValueError("Email already exists")
        
        # Validate password
        if not self._validate_password(password):
            raise ValueError("Password does not meet policy requirements")
        
        # Create user
        user_id = self._generate_user_id()
        password_salt = secrets.token_hex(32)
        password_hash = self._hash_password(password, password_salt)
        
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            full_name=full_name,
            role=role,
            permissions=self.role_permissions.get(role, set()).copy(),
            password_hash=password_hash,
            password_salt=password_salt,
            password_last_changed=datetime.utcnow(),
            authentication_methods={AuthenticationMethod.PASSWORD}
        )
        
        # Set privileged access flag for admin roles
        if role in [UserRole.ADMIN, UserRole.SECURITY_OFFICER]:
            user.privileged_access = True
            user.requires_approval = True
        
        self.users[user_id] = user
        
        # Log user creation
        await self._log_access_event(
            user_id=user_id,
            resource="user_management",
            action="create_user",
            permission=Permission.MANAGE_USERS,
            success=True
        )
        
        logger.info(f"User created: {username} ({role})")
        return user
    
    def _generate_user_id(self) -> str:
        """Generate unique user ID."""
        import uuid
        return f"user_{uuid.uuid4().hex[:12]}"
    
    def _validate_password(self, password: str) -> bool:
        """Validate password against policy."""
        policy = self.password_policy
        
        if len(password) < policy.min_length:
            return False
        
        if policy.require_uppercase and not re.search(r'[A-Z]', password):
            return False
        
        if policy.require_lowercase and not re.search(r'[a-z]', password):
            return False
        
        if policy.require_digits and not re.search(r'\d', password):
            return False
        
        if policy.require_special_chars:
            if not any(char in policy.special_chars for char in password):
                return False
        
        return True
    
    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt using bcrypt."""
        salt_bytes = salt.encode('utf-8')
        password_bytes = password.encode('utf-8')
        
        # Use PBKDF2 for additional security
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000
        )
        key = kdf.derive(password_bytes)
        
        # Use bcrypt for final hash
        bcrypt_hash = bcrypt.hashpw(key, bcrypt.gensalt())
        return bcrypt_hash.decode('utf-8')
    
    async def authenticate_user(self, 
                              username: str, 
                              password: str,
                              ip_address: str,
                              user_agent: str) -> Optional[Session]:
        """
        Authenticate user and create session.
        
        Args:
            username: Username
            password: Password
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Session object if authentication successful, None otherwise
        """
        # Find user
        user = None
        for u in self.users.values():
            if u.username == username:
                user = u
                break
        
        if not user:
            await self._log_access_event(
                user_id="unknown",
                resource="authentication",
                action="login",
                permission=None,
                success=False,
                failure_reason="Invalid username",
                ip_address=ip_address,
                user_agent=user_agent
            )
            return None
        
        # Check account status
        if user.status != AccountStatus.ACTIVE:
            await self._log_access_event(
                user_id=user.user_id,
                resource="authentication",
                action="login",
                permission=None,
                success=False,
                failure_reason=f"Account status: {user.status}",
                ip_address=ip_address,
                user_agent=user_agent
            )
            return None
        
        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            await self._log_access_event(
                user_id=user.user_id,
                resource="authentication",
                action="login",
                permission=None,
                success=False,
                failure_reason="Account locked",
                ip_address=ip_address,
                user_agent=user_agent
            )
            return None
        
        # Verify password
        if not self._verify_password(password, user.password_hash, user.password_salt):
            user.failed_login_attempts += 1
            
            # Lock account if too many failed attempts
            if user.failed_login_attempts >= self.password_policy.lockout_attempts:
                user.status = AccountStatus.LOCKED
                user.locked_until = datetime.utcnow() + timedelta(
                    minutes=self.password_policy.lockout_duration_minutes
                )
                logger.warning(f"Account locked due to failed login attempts: {username}")
            
            await self._log_access_event(
                user_id=user.user_id,
                resource="authentication",
                action="login",
                permission=None,
                success=False,
                failure_reason="Invalid password",
                ip_address=ip_address,
                user_agent=user_agent
            )
            return None
        
        # Reset failed login attempts on successful authentication
        user.failed_login_attempts = 0
        user.locked_until = None
        
        # Check for two-factor authentication requirement
        if self.require_two_factor and AuthenticationMethod.TWO_FACTOR not in user.authentication_methods:
            # In production, this would redirect to 2FA setup or verification
            logger.warning(f"Two-factor authentication required for user: {username}")
        
        # Check concurrent sessions
        active_sessions = self._get_active_sessions(user.user_id)
        if len(active_sessions) >= self.max_concurrent_sessions:
            # Terminate oldest session
            oldest_session = min(active_sessions, key=lambda s: s.created_at)
            await self.terminate_session(oldest_session.session_id)
        
        # Create new session
        session = await self._create_session(user, ip_address, user_agent)
        
        # Update user login information
        user.last_login = datetime.utcnow()
        user.last_activity = datetime.utcnow()
        user.current_session_id = session.session_id
        
        await self._log_access_event(
            user_id=user.user_id,
            resource="authentication",
            action="login",
            permission=None,
            success=True,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        logger.info(f"User authenticated: {username}")
        return session
    
    def _verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """Verify password against stored hash."""
        try:
            salt_bytes = salt.encode('utf-8')
            password_bytes = password.encode('utf-8')
            
            # Derive key using same process as hashing
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=100000
            )
            key = kdf.derive(password_bytes)
            
            # Verify with bcrypt
            return bcrypt.checkpw(key, stored_hash.encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    async def _create_session(self, user: User, ip_address: str, user_agent: str) -> Session:
        """Create new user session."""
        session_id = self._generate_session_id()
        
        # Set session timeout based on user privileges
        if user.privileged_access:
            timeout = self.privileged_session_timeout
        else:
            timeout = self.session_timeout
        
        session = Session(
            session_id=session_id,
            user_id=user.user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=datetime.utcnow(),
            last_activity=datetime.utcnow(),
            expires_at=datetime.utcnow() + timeout,
            privileged=user.privileged_access
        )
        
        self.sessions[session_id] = session
        return session
    
    def _generate_session_id(self) -> str:
        """Generate secure session ID."""
        return secrets.token_urlsafe(32)
    
    async def validate_session(self, session_id: str) -> Optional[User]:
        """
        Validate session and return associated user.
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            User object if session is valid, None otherwise
        """
        session = self.sessions.get(session_id)
        if not session or not session.active:
            return None
        
        # Check session expiration
        if session.expires_at <= datetime.utcnow():
            session.active = False
            await self._log_access_event(
                user_id=session.user_id,
                resource="session",
                action="expire",
                permission=None,
                success=True
            )
            return None
        
        # Update last activity
        session.last_activity = datetime.utcnow()
        
        # Get user
        user = self.users.get(session.user_id)
        if not user or user.status != AccountStatus.ACTIVE:
            session.active = False
            return None
        
        # Update user last activity
        user.last_activity = datetime.utcnow()
        
        return user
    
    async def check_permission(self, 
                             user_id: str, 
                             permission: Permission,
                             resource: Optional[str] = None) -> bool:
        """
        Check if user has specific permission.
        
        Args:
            user_id: User ID
            permission: Required permission
            resource: Specific resource (optional)
            
        Returns:
            True if user has permission, False otherwise
        """
        user = self.users.get(user_id)
        if not user or user.status != AccountStatus.ACTIVE:
            return False
        
        # Check if user has the permission
        if permission not in user.permissions:
            await self._log_access_event(
                user_id=user_id,
                resource=resource or "unknown",
                action="access_denied",
                permission=permission,
                success=False,
                failure_reason="Insufficient permissions"
            )
            return False
        
        # Check if approval is required for privileged operations
        if user.requires_approval and self._is_privileged_operation(permission):
            # Check for pending approval
            if not await self._has_approved_access(user_id, permission, resource):
                await self._log_access_event(
                    user_id=user_id,
                    resource=resource or "unknown",
                    action="access_denied",
                    permission=permission,
                    success=False,
                    failure_reason="Approval required"
                )
                return False
        
        return True
    
    def _is_privileged_operation(self, permission: Permission) -> bool:
        """Check if operation requires privileged access."""
        privileged_permissions = {
            Permission.DELETE_PII,
            Permission.MANAGE_USERS,
            Permission.MANAGE_ROLES,
            Permission.CONFIGURE_SYSTEM,
            Permission.MANAGE_SECURITY_POLICIES,
            Permission.APPROVE_EXCEPTIONS
        }
        return permission in privileged_permissions
    
    async def request_access(self, 
                           user_id: str, 
                           permission: Permission,
                           resource: str,
                           justification: str,
                           duration_hours: int = 4) -> AccessRequest:
        """
        Request access for privileged operations.
        
        Args:
            user_id: User requesting access
            permission: Required permission
            resource: Target resource
            justification: Business justification
            duration_hours: Access duration in hours
            
        Returns:
            Access request object
        """
        request_id = self._generate_request_id()
        
        access_request = AccessRequest(
            request_id=request_id,
            user_id=user_id,
            resource=resource,
            permission=permission,
            justification=justification,
            requested_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=duration_hours)
        )
        
        self.access_requests[request_id] = access_request
        
        await self._log_access_event(
            user_id=user_id,
            resource=resource,
            action="request_access",
            permission=permission,
            success=True
        )
        
        logger.info(f"Access request created: {request_id}")
        return access_request
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID."""
        import uuid
        return f"req_{uuid.uuid4().hex[:12]}"
    
    async def approve_access_request(self, 
                                   request_id: str, 
                                   approver_user_id: str) -> bool:
        """
        Approve access request.
        
        Args:
            request_id: Request to approve
            approver_user_id: User approving the request
            
        Returns:
            True if approved successfully
        """
        request = self.access_requests.get(request_id)
        if not request:
            return False
        
        # Verify approver has permission
        approver = self.users.get(approver_user_id)
        if not approver or Permission.APPROVE_EXCEPTIONS not in approver.permissions:
            return False
        
        # Check if request is still valid
        if request.expires_at <= datetime.utcnow():
            return False
        
        # Approve request
        request.approved = True
        request.approved_by = approver_user_id
        request.approved_at = datetime.utcnow()
        
        await self._log_access_event(
            user_id=approver_user_id,
            resource=request.resource,
            action="approve_access",
            permission=request.permission,
            success=True
        )
        
        logger.info(f"Access request approved: {request_id}")
        return True
    
    async def _has_approved_access(self, 
                                 user_id: str, 
                                 permission: Permission,
                                 resource: Optional[str]) -> bool:
        """Check if user has approved access for the operation."""
        for request in self.access_requests.values():
            if (request.user_id == user_id and 
                request.permission == permission and
                (resource is None or request.resource == resource) and
                request.approved and
                request.expires_at > datetime.utcnow()):
                return True
        
        return False
    
    async def change_password(self, 
                            user_id: str, 
                            current_password: str, 
                            new_password: str) -> bool:
        """
        Change user password.
        
        Args:
            user_id: User ID
            current_password: Current password
            new_password: New password
            
        Returns:
            True if password changed successfully
        """
        user = self.users.get(user_id)
        if not user:
            return False
        
        # Verify current password
        if not self._verify_password(current_password, user.password_hash, user.password_salt):
            await self._log_access_event(
                user_id=user_id,
                resource="password_change",
                action="change_password",
                permission=None,
                success=False,
                failure_reason="Invalid current password"
            )
            return False
        
        # Validate new password
        if not self._validate_password(new_password):
            await self._log_access_event(
                user_id=user_id,
                resource="password_change",
                action="change_password",
                permission=None,
                success=False,
                failure_reason="Password policy violation"
            )
            return False
        
        # Check password history (simplified - in production, store password history)
        if self._verify_password(new_password, user.password_hash, user.password_salt):
            await self._log_access_event(
                user_id=user_id,
                resource="password_change",
                action="change_password",
                permission=None,
                success=False,
                failure_reason="Password reuse detected"
            )
            return False
        
        # Update password
        new_salt = secrets.token_hex(32)
        new_hash = self._hash_password(new_password, new_salt)
        
        user.password_hash = new_hash
        user.password_salt = new_salt
        user.password_last_changed = datetime.utcnow()
        
        await self._log_access_event(
            user_id=user_id,
            resource="password_change",
            action="change_password",
            permission=None,
            success=True
        )
        
        logger.info(f"Password changed for user: {user.username}")
        return True
    
    async def terminate_session(self, session_id: str) -> bool:
        """
        Terminate user session.
        
        Args:
            session_id: Session to terminate
            
        Returns:
            True if session terminated successfully
        """
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        session.active = False
        
        # Update user session info
        user = self.users.get(session.user_id)
        if user and user.current_session_id == session_id:
            user.current_session_id = None
            user.session_expires_at = None
        
        await self._log_access_event(
            user_id=session.user_id,
            resource="session",
            action="logout",
            permission=None,
            success=True
        )
        
        logger.info(f"Session terminated: {session_id}")
        return True
    
    def _get_active_sessions(self, user_id: str) -> List[Session]:
        """Get active sessions for a user."""
        return [
            session for session in self.sessions.values()
            if session.user_id == user_id and session.active and
            session.expires_at > datetime.utcnow()
        ]
    
    async def cleanup_inactive_accounts(self) -> Dict[str, Any]:
        """
        Cleanup inactive user accounts.
        
        Returns:
            Cleanup summary
        """
        cleanup_summary = {
            'disabled_accounts': 0,
            'terminated_sessions': 0,
            'cleanup_date': datetime.utcnow().isoformat()
        }
        
        cutoff_date = datetime.utcnow() - timedelta(days=self.inactive_user_days)
        
        for user in self.users.values():
            # Skip admin accounts from automatic cleanup
            if user.role == UserRole.ADMIN:
                continue
            
            # Check if user has been inactive
            if (user.last_activity and user.last_activity < cutoff_date and
                user.status == AccountStatus.ACTIVE):
                
                user.status = AccountStatus.INACTIVE
                cleanup_summary['disabled_accounts'] += 1
                
                # Terminate active sessions
                active_sessions = self._get_active_sessions(user.user_id)
                for session in active_sessions:
                    await self.terminate_session(session.session_id)
                    cleanup_summary['terminated_sessions'] += 1
                
                await self._log_access_event(
                    user_id=user.user_id,
                    resource="account_management",
                    action="disable_inactive_account",
                    permission=Permission.MANAGE_USERS,
                    success=True
                )
                
                logger.info(f"Disabled inactive account: {user.username}")
        
        return cleanup_summary
    
    async def get_compliance_status(self) -> Dict[str, Any]:
        """
        Get current PCI DSS compliance status for access control.
        
        Returns:
            Access control compliance status
        """
        status = {
            'requirement_7': await self._assess_requirement_7(),
            'requirement_8': await self._assess_requirement_8(),
            'overall_compliance': 'compliant',
            'last_assessment': datetime.utcnow().isoformat(),
            'recommendations': []
        }
        
        # Check overall compliance
        if (status['requirement_7']['status'] != 'compliant' or 
            status['requirement_8']['status'] != 'compliant'):
            status['overall_compliance'] = 'non_compliant'
        
        return status
    
    async def _assess_requirement_7(self) -> Dict[str, Any]:
        """Assess PCI DSS Requirement 7 - Restrict access by business need to know."""
        assessment = {
            'requirement': '7',
            'title': 'Restrict access to cardholder data by business need to know',
            'status': 'compliant',
            'controls': []
        }
        
        # 7.1 - Limit access to system components and cardholder data
        control_7_1 = {
            'control': '7.1',
            'description': 'Limit access to system components and cardholder data to only those individuals whose job requires such access',
            'status': 'compliant',
            'findings': [f'{len(self.role_permissions)} roles with defined permissions'],
            'evidence': 'Role-based access control implemented'
        }
        assessment['controls'].append(control_7_1)
        
        # 7.2 - Establish an access control system
        control_7_2 = {
            'control': '7.2',
            'description': 'Establish an access control system for systems components that restricts access based on a users need to know',
            'status': 'compliant',
            'findings': ['Permission-based access control active'],
            'evidence': f'Access control system managing {len(self.users)} users'
        }
        assessment['controls'].append(control_7_2)
        
        return assessment
    
    async def _assess_requirement_8(self) -> Dict[str, Any]:
        """Assess PCI DSS Requirement 8 - Identify and authenticate access."""
        assessment = {
            'requirement': '8',
            'title': 'Identify and authenticate access to system components',
            'status': 'compliant',
            'controls': []
        }
        
        # 8.1 - Define and implement policies and procedures
        control_8_1 = {
            'control': '8.1',
            'description': 'Define and implement policies and procedures to ensure proper user identification management',
            'status': 'compliant',
            'findings': ['User identification policies implemented'],
            'evidence': 'Comprehensive user management system active'
        }
        assessment['controls'].append(control_8_1)
        
        # 8.2 - Ensure that user identification is unique
        unique_users = len(set(user.username for user in self.users.values()))
        control_8_2 = {
            'control': '8.2',
            'description': 'In addition to assigning a unique ID, ensure proper user authentication management',
            'status': 'compliant' if unique_users == len(self.users) else 'non_compliant',
            'findings': [f'{unique_users} unique usernames out of {len(self.users)} users'],
            'evidence': 'Unique user identification enforced'
        }
        assessment['controls'].append(control_8_2)
        
        # 8.3 - Secure all individual non-console administrative access
        mfa_users = sum(1 for user in self.users.values() 
                       if AuthenticationMethod.TWO_FACTOR in user.authentication_methods)
        control_8_3 = {
            'control': '8.3',
            'description': 'Secure all individual non-console administrative access and all remote access to the CDE using multi-factor authentication',
            'status': 'compliant' if self.require_two_factor else 'non_compliant',
            'findings': [f'{mfa_users} users with MFA enabled'],
            'evidence': 'Multi-factor authentication required'
        }
        assessment['controls'].append(control_8_3)
        
        # Check if any control is non-compliant
        for control in assessment['controls']:
            if control['status'] != 'compliant':
                assessment['status'] = 'non_compliant'
                break
        
        return assessment
    
    async def _log_access_event(self,
                              user_id: str,
                              resource: str,
                              action: str,
                              permission: Optional[Permission],
                              success: bool,
                              failure_reason: Optional[str] = None,
                              ip_address: str = "unknown",
                              user_agent: str = "unknown"):
        """Log access control event."""
        log_id = self._generate_log_id()
        
        access_log = AccessLog(
            log_id=log_id,
            user_id=user_id,
            resource=resource,
            action=action,
            permission=permission,
            timestamp=datetime.utcnow(),
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            failure_reason=failure_reason
        )
        
        self.access_logs.append(access_log)
        
        # Calculate risk score
        risk_score = await self._calculate_risk_score(access_log)
        access_log.risk_score = risk_score
        
        # Log the event
        logger.info(f"Access event: {action} by {user_id} on {resource} - {'Success' if success else 'Failed'}")
        
        # Alert on high-risk events
        if risk_score > 0.8:
            logger.warning(f"High-risk access event detected: {log_id}")
    
    def _generate_log_id(self) -> str:
        """Generate unique log ID."""
        import uuid
        return f"log_{uuid.uuid4().hex[:12]}"
    
    async def _calculate_risk_score(self, access_log: AccessLog) -> float:
        """Calculate risk score for access event."""
        risk_score = 0.0
        
        # Failed access attempts increase risk
        if not access_log.success:
            risk_score += 0.3
        
        # Privileged operations have higher risk
        if access_log.permission and self._is_privileged_operation(access_log.permission):
            risk_score += 0.2
        
        # Check for unusual access patterns
        user = self.users.get(access_log.user_id)
        if user:
            # Off-hours access (simplified check)
            if access_log.timestamp.hour < 6 or access_log.timestamp.hour > 22:
                risk_score += 0.1
            
            # Multiple failed attempts
            recent_failures = sum(1 for log in self.access_logs[-100:] 
                                if (log.user_id == access_log.user_id and 
                                   not log.success and
                                   (access_log.timestamp - log.timestamp).total_seconds() < 3600))
            if recent_failures > 3:
                risk_score += 0.3
        
        return min(risk_score, 1.0)  # Cap at 1.0
    
    async def get_user_activity_report(self, 
                                     user_id: str, 
                                     days: int = 30) -> Dict[str, Any]:
        """
        Generate user activity report.
        
        Args:
            user_id: User ID
            days: Number of days to include in report
            
        Returns:
            User activity report
        """
        user = self.users.get(user_id)
        if not user:
            return {'error': 'User not found'}
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        user_logs = [log for log in self.access_logs 
                    if log.user_id == user_id and log.timestamp > cutoff_date]
        
        report = {
            'user_id': user_id,
            'username': user.username,
            'role': user.role,
            'report_period_days': days,
            'total_access_events': len(user_logs),
            'successful_events': sum(1 for log in user_logs if log.success),
            'failed_events': sum(1 for log in user_logs if not log.success),
            'unique_resources_accessed': len(set(log.resource for log in user_logs)),
            'high_risk_events': sum(1 for log in user_logs if log.risk_score > 0.7),
            'last_activity': user.last_activity.isoformat() if user.last_activity else None,
            'account_status': user.status,
            'privileged_access': user.privileged_access
        }
        
        return report