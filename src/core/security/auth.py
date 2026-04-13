"""
Authentication and Authorization System

Provides JWT token generation, OAuth2 implementation, and user authentication.
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext

from ..config.settings import get_settings

settings = get_settings()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="api/v1/auth/token",
    scopes={
        "read": "Read access to documents and processing results",
        "write": "Write access to upload and process documents", 
        "admin": "Administrative access to user management",
        "audit": "Access to audit logs and compliance reports"
    }
)

# Token settings
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7


class TokenData:
    """Token data structure."""
    def __init__(self, username: Optional[str] = None, scopes: list[str] = None):
        self.username = username
        self.scopes = scopes or []


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(
    data: dict, 
    expires_delta: Optional[timedelta] = None,
    scopes: Optional[list[str]] = None
) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access"
    })
    
    if scopes:
        to_encode["scopes"] = scopes
    
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """Create JWT refresh token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh"
    })
    
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        
        # Check token type
        if payload.get("type") != token_type:
            return None
            
        # Check expiration
        exp = payload.get("exp")
        if exp is None:
            return None
            
        if datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            return None
            
        return payload
        
    except InvalidTokenError:
        return None


def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    """Get current user from token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    payload = verify_token(token)
    if payload is None:
        raise credentials_exception
        
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception
        
    token_scopes = payload.get("scopes", [])
    token_data = TokenData(username=username, scopes=token_scopes)
    
    # In a real application, fetch user from database
    # For now, return token data
    user = {
        "username": username,
        "scopes": token_scopes,
        "is_active": True,
        "is_admin": "admin" in token_scopes
    }
    
    if not user:
        raise credentials_exception
        
    return user


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate user credentials."""
    # In production, this would query the database
    # For demo purposes, using hardcoded admin user
    users_db = {
        "admin": {
            "username": "admin",
            "email": "admin@example.com",
            "hashed_password": get_password_hash("admin123"),
            "is_active": True,
            "scopes": ["read", "write", "admin", "audit"],
            "role": "administrator"
        },
        "user": {
            "username": "user",
            "email": "user@example.com", 
            "hashed_password": get_password_hash("user123"),
            "is_active": True,
            "scopes": ["read", "write"],
            "role": "user"
        }
    }
    
    user = users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
        
    return user


def generate_api_key() -> str:
    """Generate a secure API key."""
    return secrets.token_urlsafe(32)


def validate_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """Validate API key and return associated user info."""
    # In production, this would query the database
    # For demo purposes, using hardcoded API keys
    api_keys_db = {
        "test-api-key-12345": {
            "key_id": "test-api-key-12345",
            "username": "api_user",
            "scopes": ["read", "write"],
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "last_used": None
        }
    }
    
    key_info = api_keys_db.get(api_key)
    if not key_info or not key_info["is_active"]:
        return None
        
    # Update last used timestamp
    key_info["last_used"] = datetime.now(timezone.utc)
    
    return {
        "username": key_info["username"],
        "scopes": key_info["scopes"],
        "is_active": True,
        "auth_type": "api_key"
    }


def has_permission(user: Dict[str, Any], required_scope: str) -> bool:
    """Check if user has required permission scope."""
    user_scopes = user.get("scopes", [])
    
    # Admin has all permissions
    if "admin" in user_scopes:
        return True
        
    return required_scope in user_scopes


def create_password_reset_token(username: str) -> str:
    """Create password reset token."""
    expire = datetime.now(timezone.utc) + timedelta(hours=1)
    data = {
        "sub": username,
        "exp": expire,
        "type": "password_reset",
        "reset_id": secrets.token_hex(16)
    }
    
    return jwt.encode(data, settings.secret_key, algorithm=ALGORITHM)


def verify_password_reset_token(token: str) -> Optional[str]:
    """Verify password reset token and return username."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        
        if payload.get("type") != "password_reset":
            return None
            
        username = payload.get("sub")
        return username
        
    except InvalidTokenError:
        return None