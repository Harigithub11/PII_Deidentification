"""
User Management API Endpoints

Comprehensive user management with CRUD operations, role management,
session management, and API key management.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status, Query, Path, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, validator
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc

from ..core.database.session import get_db_session
from ..core.database.models import User, UserSession, APIKey, UserRole, SessionStatus
from ..core.security.auth import get_password_hash, verify_password, create_access_token
from ..core.security.dependencies import (
    get_current_active_user,
    get_current_admin_user,
    require_permissions,
    standard_rate_limit,
    AuditLogDependency
)
from ..core.security.models import UserResponse

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/users", tags=["User Management"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class UserCreateRequest(BaseModel):
    """Request model for creating a new user."""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_-]+$')
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=200)
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(UserRole.USER, description="User role")
    is_active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('role')
    def validate_role(cls, v):
        valid_roles = [UserRole.ADMIN, UserRole.USER, UserRole.AUDITOR, 
                      UserRole.DATA_PROCESSOR, UserRole.COMPLIANCE_OFFICER]
        if v not in valid_roles:
            raise ValueError(f'Role must be one of: {valid_roles}')
        return v


class UserUpdateRequest(BaseModel):
    """Request model for updating user information."""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, max_length=200)
    role: Optional[str] = None
    is_active: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None
    
    @validator('role')
    def validate_role(cls, v):
        if v is not None:
            valid_roles = [UserRole.ADMIN, UserRole.USER, UserRole.AUDITOR, 
                          UserRole.DATA_PROCESSOR, UserRole.COMPLIANCE_OFFICER]
            if v not in valid_roles:
                raise ValueError(f'Role must be one of: {valid_roles}')
        return v


class PasswordChangeRequest(BaseModel):
    """Request model for changing user password."""
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(..., min_length=8, max_length=128)
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v


class UserDetailResponse(BaseModel):
    """Detailed user response model."""
    id: UUID
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    is_verified: bool
    failed_login_attempts: int
    locked_until: Optional[datetime]
    last_login: Optional[datetime]
    password_changed_at: datetime
    two_factor_enabled: bool
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any]
    
    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """User list response model."""
    id: UUID
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    last_login: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True


class SessionResponse(BaseModel):
    """User session response model."""
    id: UUID
    session_token: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    status: str
    expires_at: datetime
    last_accessed: datetime
    created_at: datetime
    location_country: Optional[str]
    location_city: Optional[str]
    
    class Config:
        from_attributes = True


class APIKeyCreateRequest(BaseModel):
    """Request model for creating API key."""
    key_name: str = Field(..., min_length=1, max_length=100)
    scopes: List[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None
    rate_limit_per_hour: int = Field(1000, ge=1, le=10000)


class APIKeyResponse(BaseModel):
    """API key response model."""
    id: UUID
    key_name: str
    key_prefix: str
    scopes: List[str]
    is_active: bool
    expires_at: Optional[datetime]
    last_used: Optional[datetime]
    usage_count: int
    rate_limit_per_hour: int
    created_at: datetime
    
    class Config:
        from_attributes = True


class UserStatsResponse(BaseModel):
    """User statistics response model."""
    total_users: int
    active_users: int
    inactive_users: int
    users_by_role: Dict[str, int]
    recent_registrations: int
    locked_users: int
    users_with_2fa: int


class PaginatedResponse(BaseModel):
    """Paginated response wrapper."""
    items: List[Any]
    total: int
    page: int
    per_page: int
    pages: int
    has_next: bool
    has_prev: bool


# =============================================================================
# USER CRUD ENDPOINTS
# =============================================================================

@router.post("/", response_model=UserDetailResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: UserCreateRequest,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("user_create"))
):
    """Create a new user (Admin only)."""
    
    # Check if username or email already exists
    existing_user = db.query(User).filter(
        or_(User.username == request.username, User.email == request.email)
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already exists"
        )
    
    # Create new user
    user = User(
        id=uuid4(),
        username=request.username,
        email=request.email,
        full_name=request.full_name,
        password_hash=get_password_hash(request.password),
        role=request.role,
        is_active=request.is_active,
        metadata=request.metadata,
        created_by=current_user.id,
        password_changed_at=datetime.utcnow()
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    logger.info(f"User created: {user.username} by {current_user.username}")
    
    return UserDetailResponse.from_orm(user)


@router.get("/{user_id}", response_model=UserDetailResponse)
async def get_user(
    user_id: UUID = Path(..., description="User ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """Get user details by ID."""
    
    # Users can only access their own details unless they're admin
    if user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this user's details"
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserDetailResponse.from_orm(user)


@router.get("/", response_model=PaginatedResponse)
async def list_users(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    role: Optional[str] = Query(None, description="Filter by role"),
    active: Optional[bool] = Query(None, description="Filter by active status"),
    search: Optional[str] = Query(None, description="Search by username or email"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    """List all users with filtering and pagination (Admin only)."""
    
    query = db.query(User)
    
    # Apply filters
    if role:
        query = query.filter(User.role == role)
    
    if active is not None:
        query = query.filter(User.is_active == active)
    
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                User.username.ilike(search_term),
                User.email.ilike(search_term),
                User.full_name.ilike(search_term)
            )
        )
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * per_page
    users = query.offset(offset).limit(per_page).all()
    
    # Calculate pagination info
    pages = (total + per_page - 1) // per_page
    has_next = page < pages
    has_prev = page > 1
    
    items = [UserListResponse.from_orm(user) for user in users]
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
        has_next=has_next,
        has_prev=has_prev
    )


@router.put("/{user_id}", response_model=UserDetailResponse)
async def update_user(
    request: UserUpdateRequest,
    user_id: UUID = Path(..., description="User ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("user_update"))
):
    """Update user information."""
    
    # Users can only update their own info (except role), admins can update anyone
    if user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this user"
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Non-admin users cannot change role
    if (request.role and request.role != user.role and 
        current_user.role != UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to change user role"
        )
    
    # Update user fields
    update_data = request.dict(exclude_unset=True)
    
    for field, value in update_data.items():
        setattr(user, field, value)
    
    user.updated_by = current_user.id
    user.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(user)
    
    logger.info(f"User updated: {user.username} by {current_user.username}")
    
    return UserDetailResponse.from_orm(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: UUID = Path(..., description="User ID"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("user_delete"))
):
    """Delete user (Admin only)."""
    
    # Cannot delete self
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Soft delete by marking as inactive
    user.is_active = False
    user.updated_by = current_user.id
    user.updated_at = datetime.utcnow()
    
    db.commit()
    
    logger.info(f"User deleted: {user.username} by {current_user.username}")


# =============================================================================
# PASSWORD MANAGEMENT
# =============================================================================

@router.post("/{user_id}/change-password")
async def change_password(
    request: PasswordChangeRequest,
    user_id: UUID = Path(..., description="User ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("password_change"))
):
    """Change user password."""
    
    # Users can only change their own password unless they're admin
    if user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to change this user's password"
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Verify current password (skip for admin changing other user's password)
    if user_id == current_user.id:
        if not verify_password(request.current_password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
    
    # Update password
    user.password_hash = get_password_hash(request.new_password)
    user.password_changed_at = datetime.utcnow()
    user.updated_by = current_user.id
    user.updated_at = datetime.utcnow()
    
    db.commit()
    
    logger.info(f"Password changed for user: {user.username}")
    
    return {"message": "Password changed successfully"}


# =============================================================================
# SESSION MANAGEMENT
# =============================================================================

@router.get("/{user_id}/sessions", response_model=List[SessionResponse])
async def get_user_sessions(
    user_id: UUID = Path(..., description="User ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """Get user's active sessions."""
    
    # Users can only view their own sessions unless they're admin
    if user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this user's sessions"
        )
    
    sessions = db.query(UserSession).filter(
        and_(
            UserSession.user_id == user_id,
            UserSession.status == SessionStatus.ACTIVE,
            UserSession.expires_at > datetime.utcnow()
        )
    ).order_by(desc(UserSession.last_accessed)).all()
    
    return [SessionResponse.from_orm(session) for session in sessions]


@router.delete("/{user_id}/sessions/{session_id}")
async def terminate_session(
    user_id: UUID = Path(..., description="User ID"),
    session_id: UUID = Path(..., description="Session ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("session_terminate"))
):
    """Terminate a specific user session."""
    
    # Users can only terminate their own sessions unless they're admin
    if user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to terminate this user's sessions"
        )
    
    session = db.query(UserSession).filter(
        and_(
            UserSession.id == session_id,
            UserSession.user_id == user_id
        )
    ).first()
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    # Terminate session
    session.status = SessionStatus.TERMINATED
    session.terminated_at = datetime.utcnow()
    session.terminated_by = current_user.id
    session.termination_reason = "Manual termination"
    
    db.commit()
    
    logger.info(f"Session terminated: {session_id} for user: {user_id}")
    
    return {"message": "Session terminated successfully"}


@router.delete("/{user_id}/sessions")
async def terminate_all_sessions(
    user_id: UUID = Path(..., description="User ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("sessions_terminate_all"))
):
    """Terminate all user sessions."""
    
    # Users can only terminate their own sessions unless they're admin
    if user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to terminate this user's sessions"
        )
    
    # Get all active sessions
    sessions = db.query(UserSession).filter(
        and_(
            UserSession.user_id == user_id,
            UserSession.status == SessionStatus.ACTIVE
        )
    ).all()
    
    # Terminate all sessions
    terminated_count = 0
    for session in sessions:
        session.status = SessionStatus.TERMINATED
        session.terminated_at = datetime.utcnow()
        session.terminated_by = current_user.id
        session.termination_reason = "Bulk termination"
        terminated_count += 1
    
    db.commit()
    
    logger.info(f"All sessions terminated for user: {user_id} (count: {terminated_count})")
    
    return {"message": f"Terminated {terminated_count} sessions"}


# =============================================================================
# API KEY MANAGEMENT
# =============================================================================

@router.post("/{user_id}/api-keys", response_model=Dict[str, Any])
async def create_api_key(
    request: APIKeyCreateRequest,
    user_id: UUID = Path(..., description="User ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("api_key_create"))
):
    """Create API key for user."""
    
    # Users can only create API keys for themselves unless they're admin
    if user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create API keys for this user"
        )
    
    # Check if key name already exists for this user
    existing_key = db.query(APIKey).filter(
        and_(
            APIKey.user_id == user_id,
            APIKey.key_name == request.key_name
        )
    ).first()
    
    if existing_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key with this name already exists"
        )
    
    # Generate API key
    import secrets
    api_key_value = f"deident_{secrets.token_urlsafe(32)}"
    key_prefix = api_key_value[:10]
    key_hash = get_password_hash(api_key_value)
    
    # Create API key record
    api_key = APIKey(
        id=uuid4(),
        user_id=user_id,
        key_name=request.key_name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        scopes=request.scopes,
        expires_at=request.expires_at,
        rate_limit_per_hour=request.rate_limit_per_hour
    )
    
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    
    logger.info(f"API key created: {request.key_name} for user: {user_id}")
    
    return {
        "api_key": api_key_value,  # Only returned on creation
        "key_info": APIKeyResponse.from_orm(api_key),
        "message": "API key created successfully. Save the key value - it won't be shown again."
    }


@router.get("/{user_id}/api-keys", response_model=List[APIKeyResponse])
async def list_api_keys(
    user_id: UUID = Path(..., description="User ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """List user's API keys."""
    
    # Users can only list their own API keys unless they're admin
    if user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this user's API keys"
        )
    
    api_keys = db.query(APIKey).filter(APIKey.user_id == user_id).all()
    
    return [APIKeyResponse.from_orm(key) for key in api_keys]


@router.delete("/{user_id}/api-keys/{key_id}")
async def revoke_api_key(
    user_id: UUID = Path(..., description="User ID"),
    key_id: UUID = Path(..., description="API Key ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("api_key_revoke"))
):
    """Revoke API key."""
    
    # Users can only revoke their own API keys unless they're admin
    if user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to revoke this user's API keys"
        )
    
    api_key = db.query(APIKey).filter(
        and_(APIKey.id == key_id, APIKey.user_id == user_id)
    ).first()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    # Revoke API key
    api_key.is_active = False
    api_key.revoked_at = datetime.utcnow()
    api_key.revoked_by = current_user.id
    api_key.revocation_reason = "Manual revocation"
    
    db.commit()
    
    logger.info(f"API key revoked: {api_key.key_name} for user: {user_id}")
    
    return {"message": "API key revoked successfully"}


# =============================================================================
# USER STATISTICS
# =============================================================================

@router.get("/stats/overview", response_model=UserStatsResponse)
async def get_user_stats(
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    """Get user statistics overview (Admin only)."""
    
    # Total users
    total_users = db.query(User).count()
    
    # Active/inactive users
    active_users = db.query(User).filter(User.is_active == True).count()
    inactive_users = total_users - active_users
    
    # Users by role
    roles_query = db.query(User.role, db.func.count(User.id)).group_by(User.role).all()
    users_by_role = {role: count for role, count in roles_query}
    
    # Recent registrations (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_registrations = db.query(User).filter(
        User.created_at >= thirty_days_ago
    ).count()
    
    # Locked users
    locked_users = db.query(User).filter(
        and_(
            User.locked_until != None,
            User.locked_until > datetime.utcnow()
        )
    ).count()
    
    # Users with 2FA
    users_with_2fa = db.query(User).filter(User.two_factor_enabled == True).count()
    
    return UserStatsResponse(
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        users_by_role=users_by_role,
        recent_registrations=recent_registrations,
        locked_users=locked_users,
        users_with_2fa=users_with_2fa
    )


# =============================================================================
# ACCOUNT MANAGEMENT
# =============================================================================

@router.post("/{user_id}/unlock")
async def unlock_user_account(
    user_id: UUID = Path(..., description="User ID"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("account_unlock"))
):
    """Unlock user account (Admin only)."""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Unlock account
    user.failed_login_attempts = 0
    user.locked_until = None
    user.updated_by = current_user.id
    user.updated_at = datetime.utcnow()
    
    db.commit()
    
    logger.info(f"User account unlocked: {user.username} by {current_user.username}")
    
    return {"message": "User account unlocked successfully"}


@router.post("/{user_id}/enable-2fa")
async def enable_two_factor_auth(
    user_id: UUID = Path(..., description="User ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("2fa_enable"))
):
    """Enable two-factor authentication for user."""
    
    # Users can only enable 2FA for themselves unless they're admin
    if user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to enable 2FA for this user"
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Two-factor authentication is already enabled"
        )
    
    # Generate 2FA secret
    import pyotp
    secret = pyotp.random_base32()
    
    # Enable 2FA
    user.two_factor_enabled = True
    user.two_factor_secret = secret  # This should be encrypted in production
    user.updated_by = current_user.id
    user.updated_at = datetime.utcnow()
    
    db.commit()
    
    logger.info(f"2FA enabled for user: {user.username}")
    
    # Generate QR code URL for setup
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email,
        issuer_name="PII De-identification System"
    )
    
    return {
        "message": "Two-factor authentication enabled",
        "secret": secret,
        "qr_code_url": totp_uri
    }


@router.post("/{user_id}/disable-2fa")
async def disable_two_factor_auth(
    user_id: UUID = Path(..., description="User ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("2fa_disable"))
):
    """Disable two-factor authentication for user."""
    
    # Users can only disable 2FA for themselves unless they're admin
    if user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to disable 2FA for this user"
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if not user.two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Two-factor authentication is not enabled"
        )
    
    # Disable 2FA
    user.two_factor_enabled = False
    user.two_factor_secret = None
    user.updated_by = current_user.id
    user.updated_at = datetime.utcnow()
    
    db.commit()
    
    logger.info(f"2FA disabled for user: {user.username}")
    
    return {"message": "Two-factor authentication disabled"}


# =============================================================================
# BULK OPERATIONS
# =============================================================================

@router.post("/bulk/activate")
async def bulk_activate_users(
    user_ids: List[UUID],
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("bulk_activate"))
):
    """Bulk activate users (Admin only)."""
    
    if len(user_ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 100 users can be processed at once"
        )
    
    # Update users
    updated_count = db.query(User).filter(
        User.id.in_(user_ids)
    ).update(
        {
            "is_active": True,
            "updated_by": current_user.id,
            "updated_at": datetime.utcnow()
        },
        synchronize_session=False
    )
    
    db.commit()
    
    logger.info(f"Bulk activated {updated_count} users by {current_user.username}")
    
    return {"message": f"Successfully activated {updated_count} users"}


@router.post("/bulk/deactivate")
async def bulk_deactivate_users(
    user_ids: List[UUID],
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("bulk_deactivate"))
):
    """Bulk deactivate users (Admin only)."""
    
    if len(user_ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 100 users can be processed at once"
        )
    
    # Cannot deactivate self
    if current_user.id in user_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account"
        )
    
    # Update users
    updated_count = db.query(User).filter(
        User.id.in_(user_ids)
    ).update(
        {
            "is_active": False,
            "updated_by": current_user.id,
            "updated_at": datetime.utcnow()
        },
        synchronize_session=False
    )
    
    db.commit()
    
    logger.info(f"Bulk deactivated {updated_count} users by {current_user.username}")
    
    return {"message": f"Successfully deactivated {updated_count} users"}