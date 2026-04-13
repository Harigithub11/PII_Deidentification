"""
Authentication API Endpoints

Provides login, logout, token refresh, and user management endpoints.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request
from fastapi.security import OAuth2PasswordRequestForm

from ..core.security.auth import (
    authenticate_user, 
    create_access_token, 
    create_refresh_token,
    verify_token,
    create_password_reset_token,
    verify_password_reset_token,
    get_password_hash
)
from ..core.security.models import (
    LoginRequest,
    TokenResponse,
    UserResponse,
    PasswordChangeRequest,
    PasswordResetRequest,
    PasswordResetConfirm,
    APIKeyCreate,
    APIKeyResponse
)
from ..core.security.dependencies import (
    get_current_active_user,
    get_current_admin_user,
    require_permissions,
    standard_rate_limit,
    strict_rate_limit,
    AuditLogDependency
)
from ..core.security.encryption import key_manager

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


@router.post("/token", response_model=TokenResponse)
async def login(
    background_tasks: BackgroundTasks,
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    rate_limit=Depends(standard_rate_limit),
    audit_log=Depends(AuditLogDependency("login"))
):
    """
    OAuth2 compatible login endpoint for access token generation.
    """
    try:
        # Authenticate user
        user = authenticate_user(form_data.username, form_data.password)
        if not user:
            # Log failed login attempt
            background_tasks.add_task(
                log_security_event,
                "login_failed",
                form_data.username,
                request.client.host
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check if user is active
        if not user.get("is_active"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is disabled"
            )
        
        # Determine scopes
        requested_scopes = form_data.scopes or []
        user_scopes = user.get("scopes", [])
        granted_scopes = [scope for scope in requested_scopes if scope in user_scopes]
        
        # If no specific scopes requested, grant all user scopes
        if not requested_scopes:
            granted_scopes = user_scopes
        
        # Create tokens
        token_data = {"sub": user["username"]}
        access_token = create_access_token(token_data, scopes=granted_scopes)
        refresh_token = create_refresh_token(token_data)
        
        # Log successful login
        background_tasks.add_task(
            log_security_event,
            "login_success",
            user["username"],
            request.client.host
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=30 * 60,  # 30 minutes
            scopes=granted_scopes
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    refresh_token: str,
    rate_limit=Depends(standard_rate_limit)
):
    """
    Refresh access token using refresh token.
    """
    try:
        # Verify refresh token
        payload = verify_token(refresh_token, token_type="refresh")
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        username = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Get user info (in production, fetch from database)
        user = authenticate_user(username, "")  # Would need different method for token refresh
        if not user or not user.get("is_active"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Create new access token
        token_data = {"sub": username}
        new_access_token = create_access_token(token_data, scopes=user.get("scopes", []))
        
        return TokenResponse(
            access_token=new_access_token,
            token_type="bearer", 
            expires_in=30 * 60,
            scopes=user.get("scopes", [])
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )


@router.post("/logout")
async def logout(
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Logout user and invalidate token.
    """
    try:
        # In production, add token to blacklist/revocation list
        username = current_user.get("username")
        
        # Log logout event
        background_tasks.add_task(
            log_security_event,
            "logout",
            username,
            request.client.host
        )
        
        return {"message": "Successfully logged out"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Get current user information.
    """
    return UserResponse(
        id=current_user.get("id", "00000000-0000-0000-0000-000000000000"),
        username=current_user["username"],
        email=current_user.get("email", ""),
        full_name=current_user.get("full_name"),
        role=current_user.get("role", "user"),
        is_active=current_user.get("is_active", True),
        is_verified=current_user.get("is_verified", False),
        permissions=current_user.get("scopes", []),
        created_at=datetime.now(timezone.utc),
        last_login=current_user.get("last_login")
    )


@router.post("/change-password")
async def change_password(
    password_data: PasswordChangeRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: Dict = Depends(get_current_active_user),
    rate_limit=Depends(strict_rate_limit)
):
    """
    Change user password.
    """
    try:
        # Verify current password
        if not authenticate_user(current_user["username"], password_data.current_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Hash new password
        hashed_password = get_password_hash(password_data.new_password)
        
        # In production, update password in database
        # user_db.update_password(current_user["id"], hashed_password)
        
        # Log password change
        background_tasks.add_task(
            log_security_event,
            "password_changed",
            current_user["username"],
            request.client.host
        )
        
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )


@router.post("/forgot-password")
async def forgot_password(
    password_reset: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    rate_limit=Depends(strict_rate_limit)
):
    """
    Request password reset token.
    """
    try:
        # In production, verify email exists in database
        # For demo, accept any email
        
        # Create password reset token
        reset_token = create_password_reset_token(password_reset.email)
        
        # In production, send email with reset token
        background_tasks.add_task(
            send_password_reset_email,
            password_reset.email,
            reset_token
        )
        
        return {"message": "Password reset instructions sent to email"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset request failed"
        )


@router.post("/reset-password")
async def reset_password(
    reset_data: PasswordResetConfirm,
    background_tasks: BackgroundTasks,
    rate_limit=Depends(strict_rate_limit)
):
    """
    Reset password using reset token.
    """
    try:
        # Verify reset token
        username = verify_password_reset_token(reset_data.token)
        if not username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        # Hash new password
        hashed_password = get_password_hash(reset_data.new_password)
        
        # In production, update password in database
        # user_db.update_password_by_username(username, hashed_password)
        
        # Log password reset
        background_tasks.add_task(
            log_security_event,
            "password_reset",
            username,
            None
        )
        
        return {"message": "Password reset successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset failed"
        )


@router.post("/api-keys", response_model=Dict[str, str])
async def create_api_key(
    api_key_data: APIKeyCreate,
    background_tasks: BackgroundTasks,
    current_user: Dict = Depends(get_current_active_user),
    admin_check=Depends(require_permissions(["admin"]))
):
    """
    Create new API key (admin only).
    """
    try:
        # Generate API key
        api_key = key_manager.generate_api_key()
        api_key_hash = key_manager.hash_api_key(api_key)
        
        # In production, store in database
        key_record = {
            "name": api_key_data.name,
            "key_hash": api_key_hash,
            "prefix": api_key[:8],
            "user_id": current_user["id"],
            "scopes": api_key_data.scopes,
            "expires_at": api_key_data.expires_at
        }
        
        # Log API key creation
        background_tasks.add_task(
            log_security_event,
            "api_key_created",
            current_user["username"],
            None,
            {"key_name": api_key_data.name}
        )
        
        return {
            "api_key": api_key,
            "prefix": api_key[:8],
            "message": "API key created successfully. Store this key securely - it won't be shown again."
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API key creation failed"
        )


@router.get("/api-keys", response_model=List[APIKeyResponse])
async def list_api_keys(
    current_user: Dict = Depends(get_current_active_user),
    admin_check=Depends(require_permissions(["admin"]))
):
    """
    List API keys (admin only).
    """
    try:
        # In production, fetch from database
        # For demo, return empty list
        return []
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve API keys"
        )


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    background_tasks: BackgroundTasks,
    current_user: Dict = Depends(get_current_active_user),
    admin_check=Depends(require_permissions(["admin"]))
):
    """
    Revoke API key (admin only).
    """
    try:
        # In production, mark key as inactive in database
        
        # Log API key revocation
        background_tasks.add_task(
            log_security_event,
            "api_key_revoked",
            current_user["username"],
            None,
            {"key_id": key_id}
        )
        
        return {"message": "API key revoked successfully"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API key revocation failed"
        )


# Helper functions for background tasks
async def log_security_event(
    action: str,
    username: str,
    ip_address: str,
    details: Dict = None
):
    """Log security event."""
    event_data = {
        "action": action,
        "username": username,
        "ip_address": ip_address,
        "timestamp": datetime.now(timezone.utc),
        "details": details or {}
    }
    
    # In production, store in database
    print(f"SECURITY EVENT: {event_data}")


async def send_password_reset_email(email: str, reset_token: str):
    """Send password reset email."""
    # In production, implement email sending
    print(f"PASSWORD RESET EMAIL: {email} - Token: {reset_token}")


# Health check endpoint
@router.get("/health")
async def auth_health_check():
    """Authentication service health check."""
    return {
        "status": "healthy",
        "service": "authentication",
        "timestamp": datetime.now(timezone.utc)
    }