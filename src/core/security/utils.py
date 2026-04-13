"""
Security utilities for authentication, authorization, and cryptographic functions.
"""

import hashlib
import secrets
import bcrypt
from typing import Optional
from datetime import datetime, timedelta, timezone


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def get_password_hash(password: str) -> str:
    """Alias for hash_password for compatibility."""
    return hash_password(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False


def generate_api_key(length: int = 32) -> str:
    """Generate a secure API key."""
    return secrets.token_urlsafe(length)


def generate_session_token(length: int = 32) -> str:
    """Generate a secure session token."""
    return secrets.token_urlsafe(length)


def hash_api_key(api_key: str) -> str:
    """Hash an API key for storage."""
    return hashlib.sha256(api_key.encode('utf-8')).hexdigest()


def verify_api_key(api_key: str, hashed_key: str) -> bool:
    """Verify an API key against its hash."""
    return hashlib.sha256(api_key.encode('utf-8')).hexdigest() == hashed_key


def generate_password_reset_token() -> str:
    """Generate a password reset token."""
    return secrets.token_urlsafe(32)


def is_token_expired(created_at: datetime, expires_in_hours: int = 24) -> bool:
    """Check if a token has expired."""
    expiry_time = created_at + timedelta(hours=expires_in_hours)
    return datetime.now(timezone.utc) > expiry_time