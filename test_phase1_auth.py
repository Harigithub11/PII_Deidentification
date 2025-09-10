#!/usr/bin/env python3
"""
Phase 1 Authentication System Testing

Tests JWT tokens, OAuth2, and authentication components without requiring server startup.
"""

import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
import json

# Add src to path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

def test_password_hashing():
    """Test password hashing functionality."""
    print("Testing password hashing...")
    
    try:
        from src.core.security.auth import pwd_context, verify_password
        
        test_password = "test_password_123"
        
        # Hash password
        hashed = pwd_context.hash(test_password)
        
        # Verify correct password
        if not verify_password(test_password, hashed):
            print("[FAIL] Password verification failed")
            return False
        
        # Verify wrong password
        if verify_password("wrong_password", hashed):
            print("[FAIL] Wrong password was accepted")
            return False
        
        print("[PASS] Password hashing and verification working")
        return True
        
    except Exception as e:
        print(f"[ERROR] Password hashing test failed: {e}")
        return False

def test_jwt_token_creation():
    """Test JWT token creation and validation."""
    print("Testing JWT token creation...")
    
    try:
        from src.core.security.auth import create_access_token, verify_token
        from src.core.config.settings import get_settings
        
        # Test data
        test_user = "testuser"
        test_scopes = ["read", "write"]
        
        # Create token
        token = create_access_token(
            data={"sub": test_user, "scopes": test_scopes},
            expires_delta=timedelta(minutes=30)
        )
        
        if not token:
            print("[FAIL] Token creation failed")
            return False
        
        # Verify token
        payload = verify_token(token)
        
        if payload["sub"] != test_user:
            print("[FAIL] Token payload verification failed")
            return False
        
        print(f"[PASS] JWT token creation and verification working")
        print(f"   Token user: {payload['sub']}")
        print(f"   Token scopes: {payload.get('scopes', [])}")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] JWT token test failed: {e}")
        return False

def test_oauth2_scopes():
    """Test OAuth2 scopes configuration."""
    print("Testing OAuth2 scopes...")
    
    try:
        from src.core.security.auth import oauth2_scheme
        
        expected_scopes = {"read", "write", "admin", "audit"}
        actual_scopes = set(oauth2_scheme.scopes.keys())
        
        if not expected_scopes.issubset(actual_scopes):
            print(f"[FAIL] Missing scopes. Expected: {expected_scopes}, Got: {actual_scopes}")
            return False
        
        print("[PASS] OAuth2 scopes configured correctly")
        print(f"   Available scopes: {list(actual_scopes)}")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] OAuth2 scopes test failed: {e}")
        return False

def test_user_management():
    """Test user management functionality."""
    print("Testing user management...")
    
    try:
        from src.core.security.auth import get_user, authenticate_user
        from src.core.security.models import User
        
        # Test getting default users
        admin_user = get_user("admin")
        regular_user = get_user("user")
        
        if not admin_user:
            print("[FAIL] Admin user not found")
            return False
        
        if not regular_user:
            print("[FAIL] Regular user not found")
            return False
        
        # Test authentication
        auth_result = authenticate_user("admin", "admin123")
        if not auth_result:
            print("[FAIL] Admin authentication failed")
            return False
        
        # Test wrong password
        auth_result = authenticate_user("admin", "wrong_password")
        if auth_result:
            print("[FAIL] Authentication accepted wrong password")
            return False
        
        print("[PASS] User management working")
        print(f"   Admin user: {admin_user.username} (scopes: {admin_user.scopes})")
        print(f"   Regular user: {regular_user.username} (scopes: {regular_user.scopes})")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] User management test failed: {e}")
        return False

def test_token_expiration():
    """Test token expiration functionality."""
    print("Testing token expiration...")
    
    try:
        from src.core.security.auth import create_access_token, verify_token
        import jwt
        
        # Create token with very short expiration
        short_token = create_access_token(
            data={"sub": "testuser"},
            expires_delta=timedelta(seconds=-1)  # Already expired
        )
        
        # Try to verify expired token
        try:
            payload = verify_token(short_token)
            print("[FAIL] Expired token was accepted")
            return False
        except jwt.ExpiredSignatureError:
            print("[PASS] Expired token correctly rejected")
            return True
        except Exception as e:
            print(f"[FAIL] Unexpected error with expired token: {e}")
            return False
        
    except Exception as e:
        print(f"[ERROR] Token expiration test failed: {e}")
        return False

def test_settings_configuration():
    """Test security settings configuration."""
    print("Testing security settings...")
    
    try:
        from src.core.config.settings import get_settings
        
        settings = get_settings()
        
        # Check essential security settings
        if not hasattr(settings, 'secret_key') or not settings.secret_key:
            print("[FAIL] Secret key not configured")
            return False
        
        if not hasattr(settings, 'database_url'):
            print("[FAIL] Database URL not configured")
            return False
        
        print("[PASS] Security settings configured")
        print(f"   Secret key length: {len(settings.secret_key)}")
        print(f"   Database URL configured: {bool(settings.database_url)}")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Settings test failed: {e}")
        return False

def main():
    """Run authentication system tests."""
    print("### Phase 1 Authentication System Testing ###")
    print("=" * 50)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    tests = [
        ("Settings Configuration", test_settings_configuration),
        ("Password Hashing", test_password_hashing),
        ("JWT Token Creation", test_jwt_token_creation),
        ("OAuth2 Scopes", test_oauth2_scopes),
        ("User Management", test_user_management),
        ("Token Expiration", test_token_expiration)
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_func in tests:
        print(f"\nTEST: {test_name}")
        print("-" * 30)
        
        if test_func():
            passed_tests += 1
    
    # Summary
    print("\n" + "=" * 50)
    print("AUTHENTICATION TESTING SUMMARY")
    print("=" * 50)
    
    success_rate = (passed_tests / total_tests) * 100
    print(f"Tests Passed: {passed_tests}/{total_tests} ({success_rate:.1f}%)")
    
    if success_rate >= 100:
        print("\n[SUCCESS] All authentication tests passed!")
        print("✓ Password hashing secure")
        print("✓ JWT tokens working")
        print("✓ OAuth2 scopes configured") 
        print("✓ User management functional")
        print("✓ Token expiration working")
    elif success_rate >= 80:
        print("\n[OK] Most authentication tests passed")
    else:
        print("\n[WARNING] Multiple authentication test failures")
    
    return 0 if success_rate >= 80 else 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)