"""
FastAPI Security Dependencies

Provides authentication and authorization dependencies for FastAPI endpoints.
"""

import time
from functools import wraps
from typing import Dict, List, Optional, Callable

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .auth import get_current_user, validate_api_key, has_permission
from .models import UserRole


# Security schemes
security = HTTPBearer()


def get_current_active_user(current_user: Dict = Depends(get_current_user)) -> Dict:
    """Get current active user dependency."""
    if not current_user.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


def get_current_admin_user(current_user: Dict = Depends(get_current_active_user)) -> Dict:
    """Get current admin user dependency."""
    if not current_user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions. Admin access required."
        )
    return current_user


def require_permissions(required_scopes: List[str]):
    """Decorator to require specific permissions."""
    def dependency(current_user: Dict = Depends(get_current_active_user)) -> Dict:
        user_scopes = current_user.get("scopes", [])
        
        # Check if user has admin privileges (admin has all permissions)
        if "admin" in user_scopes:
            return current_user
        
        # Check if user has required scopes
        for scope in required_scopes:
            if scope not in user_scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Not enough permissions. Required scope: {scope}"
                )
        
        return current_user
    
    return dependency


def require_role(required_role: UserRole):
    """Decorator to require specific user role."""
    def dependency(current_user: Dict = Depends(get_current_active_user)) -> Dict:
        user_role = current_user.get("role", UserRole.USER)
        
        if user_role != required_role.value and user_role != UserRole.ADMIN.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {required_role.value}"
            )
        
        return current_user
    
    return dependency


async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[Dict]:
    """Optional authentication dependency."""
    if not credentials:
        return None
    
    try:
        return get_current_user(credentials.credentials)
    except HTTPException:
        return None


async def api_key_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Dict:
    """API key authentication dependency."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_info = validate_api_key(credentials.credentials)
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user_info


def require_api_permissions(required_scopes: List[str]):
    """Decorator for API key permission requirements."""
    def dependency(user_info: Dict = Depends(api_key_auth)) -> Dict:
        user_scopes = user_info.get("scopes", [])
        
        for scope in required_scopes:
            if scope not in user_scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient API permissions. Required scope: {scope}"
                )
        
        return user_info
    
    return dependency


class RateLimitDependency:
    """Rate limiting dependency."""
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.request_counts: Dict[str, List[float]] = {}
    
    def __call__(self, request: Request) -> None:
        import time
        
        # Get client IP address
        client_ip = request.client.host
        current_time = time.time()
        
        # Clean old requests (older than 1 minute)
        if client_ip in self.request_counts:
            self.request_counts[client_ip] = [
                req_time for req_time in self.request_counts[client_ip]
                if current_time - req_time < 60
            ]
        else:
            self.request_counts[client_ip] = []
        
        # Check rate limit
        if len(self.request_counts[client_ip]) >= self.requests_per_minute:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
        
        # Record this request
        self.request_counts[client_ip].append(current_time)


class AuditLogDependency:
    """Audit logging dependency."""
    
    def __init__(self, action: str, resource_type: Optional[str] = None):
        self.action = action
        self.resource_type = resource_type
    
    def __call__(
        self, 
        request: Request,
        current_user: Optional[Dict] = Depends(get_current_user_optional)
    ) -> None:
        # In production, this would log to database
        audit_data = {
            "action": self.action,
            "resource_type": self.resource_type,
            "ip_address": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "username": current_user.get("username") if current_user else None,
            "timestamp": time.time()
        }
        
        # Log audit event (implement actual logging here)
        print(f"AUDIT: {audit_data}")


# Pre-configured dependencies
require_read_permission = require_permissions(["read"])
require_write_permission = require_permissions(["write"]) 
require_admin_permission = require_permissions(["admin"])
require_audit_permission = require_permissions(["audit"])

# Rate limiting instances
standard_rate_limit = RateLimitDependency(60)  # 60 requests per minute
strict_rate_limit = RateLimitDependency(20)    # 20 requests per minute
upload_rate_limit = RateLimitDependency(10)    # 10 requests per minute


def secure_endpoint(
    required_scopes: Optional[List[str]] = None,
    required_role: Optional[UserRole] = None,
    rate_limit: Optional[RateLimitDependency] = None,
    audit_action: Optional[str] = None,
    allow_api_key: bool = True
):
    """
    Comprehensive security decorator for endpoints.
    
    Args:
        required_scopes: List of required permission scopes
        required_role: Required user role
        rate_limit: Rate limiting configuration
        audit_action: Action to log for audit purposes
        allow_api_key: Whether to allow API key authentication
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Apply dependencies based on configuration
            dependencies = []
            
            if rate_limit:
                dependencies.append(Depends(rate_limit))
            
            if audit_action:
                dependencies.append(Depends(AuditLogDependency(audit_action)))
            
            if required_scopes:
                if allow_api_key:
                    # Try JWT first, fall back to API key
                    dependencies.append(Depends(require_permissions(required_scopes)))
                else:
                    dependencies.append(Depends(require_permissions(required_scopes)))
            elif required_role:
                dependencies.append(Depends(require_role(required_role)))
            else:
                dependencies.append(Depends(get_current_active_user))
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


# Utility functions for manual security checks
def check_document_access(user: Dict, document_id: str) -> bool:
    """Check if user has access to specific document."""
    # In production, implement proper access control logic
    return True  # Placeholder


def check_admin_access(user: Dict) -> bool:
    """Check if user has admin access."""
    return user.get("is_admin", False) or "admin" in user.get("scopes", [])


def get_user_permissions(user: Dict) -> List[str]:
    """Get all permissions for a user."""
    base_permissions = user.get("scopes", [])
    
    # Add role-based permissions
    role = user.get("role", UserRole.USER)
    if role == UserRole.ADMIN.value:
        return ["read", "write", "admin", "audit"]
    elif role == UserRole.AUDITOR.value:
        return base_permissions + ["audit"]
    
    return base_permissions