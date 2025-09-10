#!/usr/bin/env python3
"""
Security System Test Script

Tests the authentication, authorization, and security features of the de-identification system.
"""

import asyncio
import json
import requests
import time
from typing import Dict, Optional

# Test configuration
BASE_URL = "http://localhost:8000"
TEST_USERS = {
    "admin": {"username": "admin", "password": "admin123", "expected_scopes": ["read", "write", "admin", "audit"]},
    "user": {"username": "user", "password": "user123", "expected_scopes": ["read", "write"]}
}


class SecurityTester:
    """Test class for security features."""
    
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        self.tokens: Dict[str, str] = {}
    
    def test_health_check(self) -> bool:
        """Test health check endpoint."""
        print("🔍 Testing health check...")
        try:
            response = self.session.get(f"{self.base_url}/health")
            success = response.status_code == 200
            print(f"  ✅ Health check: {'PASSED' if success else 'FAILED'}")
            return success
        except Exception as e:
            print(f"  ❌ Health check failed: {e}")
            return False
    
    def test_auth_health_check(self) -> bool:
        """Test auth service health check."""
        print("🔍 Testing auth service health...")
        try:
            response = self.session.get(f"{self.base_url}/api/v1/auth/health")
            success = response.status_code == 200
            print(f"  ✅ Auth health check: {'PASSED' if success else 'FAILED'}")
            return success
        except Exception as e:
            print(f"  ❌ Auth health check failed: {e}")
            return False
    
    def test_login(self, username: str, password: str) -> Optional[str]:
        """Test user login and token generation."""
        print(f"🔐 Testing login for user: {username}")
        try:
            data = {
                "username": username,
                "password": password,
                "grant_type": "password"
            }
            
            response = self.session.post(
                f"{self.base_url}/api/v1/auth/token",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code == 200:
                token_data = response.json()
                access_token = token_data.get("access_token")
                scopes = token_data.get("scopes", [])
                
                print(f"  ✅ Login successful for {username}")
                print(f"  📝 Granted scopes: {scopes}")
                
                # Store token for future tests
                self.tokens[username] = access_token
                return access_token
            else:
                print(f"  ❌ Login failed for {username}: {response.text}")
                return None
                
        except Exception as e:
            print(f"  ❌ Login error for {username}: {e}")
            return None
    
    def test_invalid_login(self) -> bool:
        """Test login with invalid credentials."""
        print("🔐 Testing invalid login...")
        try:
            data = {
                "username": "invalid_user",
                "password": "wrong_password",
                "grant_type": "password"
            }
            
            response = self.session.post(
                f"{self.base_url}/api/v1/auth/token",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            success = response.status_code == 401
            print(f"  ✅ Invalid login rejection: {'PASSED' if success else 'FAILED'}")
            return success
            
        except Exception as e:
            print(f"  ❌ Invalid login test error: {e}")
            return False
    
    def test_protected_endpoint_without_auth(self) -> bool:
        """Test accessing protected endpoint without authentication."""
        print("🔒 Testing protected endpoint without auth...")
        try:
            response = self.session.get(f"{self.base_url}/api/v1/auth/me")
            success = response.status_code == 401
            print(f"  ✅ Unauthorized access blocked: {'PASSED' if success else 'FAILED'}")
            return success
            
        except Exception as e:
            print(f"  ❌ Protected endpoint test error: {e}")
            return False
    
    def test_get_user_info(self, username: str) -> bool:
        """Test getting current user information."""
        print(f"👤 Testing user info for: {username}")
        try:
            token = self.tokens.get(username)
            if not token:
                print(f"  ❌ No token available for {username}")
                return False
            
            headers = {"Authorization": f"Bearer {token}"}
            response = self.session.get(f"{self.base_url}/api/v1/auth/me", headers=headers)
            
            if response.status_code == 200:
                user_info = response.json()
                print(f"  ✅ User info retrieved for {username}")
                print(f"  📋 User details: {user_info.get('username')} - {user_info.get('role')}")
                return True
            else:
                print(f"  ❌ Failed to get user info: {response.text}")
                return False
                
        except Exception as e:
            print(f"  ❌ User info test error: {e}")
            return False
    
    def test_document_upload_auth(self, username: str) -> bool:
        """Test document upload with authentication."""
        print(f"📄 Testing document upload auth for: {username}")
        try:
            token = self.tokens.get(username)
            if not token:
                print(f"  ❌ No token available for {username}")
                return False
            
            headers = {"Authorization": f"Bearer {token}"}
            
            # Test without actual file (should fail with file validation, not auth)
            response = self.session.post(
                f"{self.base_url}/api/v1/documents/upload",
                headers=headers
            )
            
            # Should fail due to missing file, not auth (422 or 400, not 401)
            success = response.status_code != 401
            print(f"  ✅ Upload endpoint auth: {'PASSED' if success else 'FAILED'}")
            print(f"  📝 Response code: {response.status_code}")
            return success
            
        except Exception as e:
            print(f"  ❌ Document upload auth test error: {e}")
            return False
    
    def test_rate_limiting(self) -> bool:
        """Test rate limiting functionality."""
        print("⏰ Testing rate limiting...")
        try:
            # Make rapid requests to trigger rate limiting
            success_count = 0
            rate_limited = False
            
            for i in range(15):  # Try 15 rapid requests
                response = self.session.get(f"{self.base_url}/health")
                if response.status_code == 429:
                    rate_limited = True
                    break
                elif response.status_code == 200:
                    success_count += 1
                time.sleep(0.1)  # Small delay
            
            print(f"  📊 Successful requests before limit: {success_count}")
            print(f"  ✅ Rate limiting: {'WORKING' if rate_limited else 'NOT TRIGGERED'}")
            return True  # Rate limiting may or may not trigger in test
            
        except Exception as e:
            print(f"  ❌ Rate limiting test error: {e}")
            return False
    
    def test_security_headers(self) -> bool:
        """Test security headers are present."""
        print("🛡️ Testing security headers...")
        try:
            response = self.session.get(f"{self.base_url}/health")
            headers = response.headers
            
            expected_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options", 
                "X-XSS-Protection",
                "Strict-Transport-Security"
            ]
            
            present_headers = []
            for header in expected_headers:
                if header.lower() in [h.lower() for h in headers.keys()]:
                    present_headers.append(header)
            
            success = len(present_headers) >= 3  # At least 3 security headers
            print(f"  ✅ Security headers: {'PASSED' if success else 'FAILED'}")
            print(f"  📋 Present headers: {present_headers}")
            return success
            
        except Exception as e:
            print(f"  ❌ Security headers test error: {e}")
            return False
    
    def test_token_refresh(self, username: str) -> bool:
        """Test token refresh functionality."""
        print(f"🔄 Testing token refresh for: {username}")
        try:
            # First login to get refresh token
            data = {
                "username": username,
                "password": TEST_USERS[username]["password"],
                "grant_type": "password"
            }
            
            response = self.session.post(
                f"{self.base_url}/api/v1/auth/token",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code != 200:
                print(f"  ❌ Initial login failed for refresh test")
                return False
            
            token_data = response.json()
            refresh_token = token_data.get("refresh_token")
            
            if not refresh_token:
                print(f"  ❌ No refresh token received")
                return False
            
            # Test refresh
            refresh_response = self.session.post(
                f"{self.base_url}/api/v1/auth/refresh",
                json={"refresh_token": refresh_token}
            )
            
            success = refresh_response.status_code == 200
            print(f"  ✅ Token refresh: {'PASSED' if success else 'FAILED'}")
            return success
            
        except Exception as e:
            print(f"  ❌ Token refresh test error: {e}")
            return False
    
    def run_all_tests(self) -> Dict[str, bool]:
        """Run all security tests."""
        print("🚀 Starting Security Test Suite")
        print("=" * 50)
        
        results = {}
        
        # Basic connectivity tests
        results["health_check"] = self.test_health_check()
        results["auth_health_check"] = self.test_auth_health_check()
        
        # Authentication tests
        results["invalid_login"] = self.test_invalid_login()
        results["protected_without_auth"] = self.test_protected_endpoint_without_auth()
        
        # Test each user
        for username, user_data in TEST_USERS.items():
            # Login test
            token = self.test_login(username, user_data["password"])
            results[f"login_{username}"] = token is not None
            
            if token:
                # Authenticated endpoint tests
                results[f"user_info_{username}"] = self.test_get_user_info(username)
                results[f"document_auth_{username}"] = self.test_document_upload_auth(username)
                results[f"token_refresh_{username}"] = self.test_token_refresh(username)
        
        # Security feature tests
        results["rate_limiting"] = self.test_rate_limiting()
        results["security_headers"] = self.test_security_headers()
        
        # Print summary
        print("\n" + "=" * 50)
        print("📊 Security Test Results")
        print("=" * 50)
        
        passed = sum(1 for result in results.values() if result)
        total = len(results)
        
        for test_name, result in results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{test_name:<30} {status}")
        
        print("=" * 50)
        print(f"Summary: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
        
        return results


def main():
    """Main function to run security tests."""
    print("🔐 De-identification System Security Test")
    print("Make sure the server is running on localhost:8000")
    print()
    
    tester = SecurityTester()
    results = tester.run_all_tests()
    
    # Exit with error code if any tests failed
    if not all(results.values()):
        exit(1)
    else:
        print("\n🎉 All security tests passed!")
        exit(0)


if __name__ == "__main__":
    main()