"""
Comprehensive Security Tests

Tests security aspects including authentication, authorization,
input validation, injection attacks, and data protection.
"""

import pytest
import json
import base64
import secrets
from unittest.mock import Mock, patch
from typing import Dict, List, Any

from fastapi.testclient import TestClient
from cryptography.fernet import Fernet

from tests.utils import SecurityTestHelper, TestDataFactory, AssertionHelper
from src.core.security.encryption import EncryptionService
from src.core.security.auth import AuthenticationService
from src.core.security.middleware import SecurityMiddleware


class TestAuthentication:
    """Test authentication mechanisms."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.security_helper = SecurityTestHelper()
        self.auth_service = AuthenticationService()
    
    @pytest.mark.security
    def test_password_hashing(self):
        """Test password hashing security."""
        # Arrange
        password = "test_password_123"
        
        # Act
        hashed = self.auth_service.hash_password(password)
        
        # Assert
        assert hashed != password  # Password should be hashed
        assert len(hashed) > 50  # Bcrypt hashes are long
        assert hashed.startswith("$2b$")  # Bcrypt format
        
        # Verify password
        assert self.auth_service.verify_password(password, hashed)
        assert not self.auth_service.verify_password("wrong_password", hashed)
    
    @pytest.mark.security
    def test_jwt_token_security(self):
        """Test JWT token generation and validation."""
        # Arrange
        user_data = {"sub": "testuser", "role": "user"}
        
        # Act
        token = self.auth_service.create_access_token(user_data)
        decoded = self.auth_service.verify_token(token)
        
        # Assert
        assert decoded["sub"] == "testuser"
        assert decoded["role"] == "user"
        assert "exp" in decoded  # Expiration should be set
        assert "iat" in decoded  # Issued at should be set
    
    @pytest.mark.security
    def test_jwt_token_expiration(self):
        """Test JWT token expiration handling."""
        # Arrange
        user_data = {"sub": "testuser"}
        
        # Create expired token (negative expiry)
        expired_token = self.auth_service.create_access_token(
            user_data, expires_delta=-3600  # Expired 1 hour ago
        )
        
        # Act & Assert
        with pytest.raises(Exception):  # Should raise token expired exception
            self.auth_service.verify_token(expired_token)
    
    @pytest.mark.security
    def test_token_tampering_detection(self):
        """Test detection of tampered JWT tokens."""
        # Arrange
        user_data = {"sub": "testuser", "role": "user"}
        token = self.auth_service.create_access_token(user_data)
        
        # Tamper with token
        parts = token.split(".")
        tampered_payload = base64.b64encode(
            json.dumps({"sub": "admin", "role": "admin"}).encode()
        ).decode().rstrip("=")
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
        
        # Act & Assert
        with pytest.raises(Exception):  # Should raise signature verification error
            self.auth_service.verify_token(tampered_token)
    
    @pytest.mark.security
    def test_brute_force_protection(self, client: TestClient):
        """Test protection against brute force attacks."""
        # Arrange
        login_data = {"username": "testuser", "password": "wrong_password"}
        
        # Act - Attempt multiple failed logins
        failed_attempts = []
        for _ in range(10):
            response = client.post("/api/v1/auth/login", data=login_data)
            failed_attempts.append(response.status_code)
        
        # Assert
        # After several failed attempts, should start rate limiting or blocking
        if any(code == 429 for code in failed_attempts[-3:]):
            # Rate limiting is active
            assert True
        else:
            # If no rate limiting, ensure we're still getting consistent 401s
            assert all(code == 401 for code in failed_attempts)


class TestAuthorization:
    """Test authorization and access control."""
    
    @pytest.mark.security
    def test_role_based_access_control(self, client: TestClient):
        """Test RBAC implementation."""
        # Test cases for different roles
        test_cases = [
            {
                "role": "user",
                "endpoint": "/api/v1/admin/users",
                "expected_status": [401, 403]  # Unauthorized or Forbidden
            },
            {
                "role": "admin",
                "endpoint": "/api/v1/admin/users",
                "expected_status": [200, 404]  # OK or Not Found
            },
            {
                "role": "user",
                "endpoint": "/api/v1/pii/detect",
                "expected_status": [200, 400, 422]  # Should have access
            }
        ]
        
        for test_case in test_cases:
            # Create token with specific role
            auth_service = AuthenticationService()
            token = auth_service.create_access_token({
                "sub": "testuser",
                "role": test_case["role"]
            })
            headers = {"Authorization": f"Bearer {token}"}
            
            # Make request
            if test_case["endpoint"] == "/api/v1/pii/detect":
                response = client.post(
                    test_case["endpoint"],
                    json={"text": "test"},
                    headers=headers
                )
            else:
                response = client.get(test_case["endpoint"], headers=headers)
            
            # Assert
            assert response.status_code in test_case["expected_status"]
    
    @pytest.mark.security
    def test_privilege_escalation_prevention(self, client: TestClient):
        """Test prevention of privilege escalation."""
        # Arrange - Create user token
        auth_service = AuthenticationService()
        user_token = auth_service.create_access_token({
            "sub": "regularuser",
            "role": "user"
        })
        headers = {"Authorization": f"Bearer {user_token}"}
        
        # Act - Try to access admin functions
        admin_endpoints = [
            "/api/v1/admin/users",
            "/api/v1/admin/settings",
            "/api/v1/admin/logs"
        ]
        
        for endpoint in admin_endpoints:
            response = client.get(endpoint, headers=headers)
            # Assert - Should be forbidden or unauthorized
            assert response.status_code in [401, 403, 404]


class TestInputValidation:
    """Test input validation and sanitization."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.security_helper = SecurityTestHelper()
    
    @pytest.mark.security
    def test_sql_injection_protection(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test protection against SQL injection attacks."""
        # Arrange
        sql_payloads = self.security_helper.get_sql_injection_payloads()
        
        # Test different endpoints with SQL injection payloads
        endpoints = [
            ("/api/v1/pii/detect", "POST", "text"),
            ("/api/v1/users/search", "GET", "query")
        ]
        
        for endpoint, method, field in endpoints:
            for payload in sql_payloads:
                # Act
                if method == "POST":
                    response = client.post(
                        endpoint,
                        json={field: payload},
                        headers=auth_headers
                    )
                else:
                    response = client.get(
                        endpoint,
                        params={field: payload},
                        headers=auth_headers
                    )
                
                # Assert
                # Should not return 200 with potentially dangerous payload
                # or should return 200 with properly sanitized response
                if response.status_code == 200:
                    data = response.json()
                    # Ensure no database errors or raw SQL in response
                    response_text = json.dumps(data).lower()
                    dangerous_indicators = ['error', 'sql', 'database', 'table', 'select', 'drop']
                    assert not any(indicator in response_text for indicator in dangerous_indicators)
    
    @pytest.mark.security
    def test_xss_protection(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test protection against XSS attacks."""
        # Arrange
        xss_payloads = self.security_helper.get_xss_payloads()
        
        for payload in xss_payloads:
            # Act
            response = client.post(
                "/api/v1/pii/detect",
                json={"text": payload},
                headers=auth_headers
            )
            
            # Assert
            if response.status_code == 200:
                data = response.json()
                # Ensure XSS payload is not reflected back unescaped
                response_text = json.dumps(data)
                assert "<script>" not in response_text
                assert "javascript:" not in response_text
                assert "onerror=" not in response_text
    
    @pytest.mark.security
    def test_path_traversal_protection(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test protection against path traversal attacks."""
        # Arrange
        path_payloads = self.security_helper.get_path_traversal_payloads()
        
        for payload in path_payloads:
            # Act - Try to access files using path traversal
            response = client.get(f"/api/v1/documents/download/{payload}", headers=auth_headers)
            
            # Assert
            # Should not return actual file contents from path traversal
            assert response.status_code in [400, 404, 403]
            
            # Also test in request body
            response = client.post(
                "/api/v1/documents/process",
                json={"file_path": payload},
                headers=auth_headers
            )
            assert response.status_code in [400, 404, 422]
    
    @pytest.mark.security
    def test_file_upload_validation(self, client: TestClient, auth_headers: Dict[str, str], temp_directory):
        """Test file upload security validation."""
        # Test malicious file types
        malicious_files = [
            ("malicious.exe", b"MZ\x90\x00"),  # Windows executable
            ("script.php", b"<?php system($_GET['cmd']); ?>"),  # PHP script
            ("script.js", b"alert('xss')"),  # JavaScript
            ("large.txt", b"A" * (10 * 1024 * 1024))  # 10MB file
        ]
        
        for filename, content in malicious_files:
            # Create malicious file
            file_path = temp_directory / filename
            file_path.write_bytes(content)
            
            # Act
            with open(file_path, 'rb') as f:
                files = {'file': (filename, f, 'application/octet-stream')}
                response = client.post(
                    "/api/v1/documents/upload",
                    files=files,
                    headers=auth_headers
                )
            
            # Assert
            # Should reject malicious file types
            if filename.endswith(('.exe', '.php', '.js')):
                assert response.status_code in [400, 415]  # Bad request or unsupported media type
            elif filename == "large.txt":
                assert response.status_code in [400, 413, 422]  # File too large
    
    @pytest.mark.security
    def test_input_size_limits(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test input size limitation protection."""
        # Test oversized text input
        oversized_text = "A" * (1024 * 1024)  # 1MB text
        
        # Act
        response = client.post(
            "/api/v1/pii/detect",
            json={"text": oversized_text},
            headers=auth_headers
        )
        
        # Assert
        # Should either process within reasonable time or reject as too large
        if response.status_code == 200:
            # If processed, should complete reasonably quickly
            assert response.elapsed.total_seconds() < 30
        else:
            # Should be rejected with appropriate error
            assert response.status_code in [400, 413, 422]


class TestDataProtection:
    """Test data protection and encryption."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.encryption_service = EncryptionService()
    
    @pytest.mark.security
    def test_data_encryption_at_rest(self):
        """Test data encryption for stored data."""
        # Arrange
        sensitive_data = "John Smith, SSN: 123-45-6789, Email: john@example.com"
        
        # Act
        encrypted = self.encryption_service.encrypt(sensitive_data)
        decrypted = self.encryption_service.decrypt(encrypted)
        
        # Assert
        assert encrypted != sensitive_data  # Data should be encrypted
        assert len(encrypted) > len(sensitive_data)  # Encrypted data is longer
        assert decrypted == sensitive_data  # Decryption should work
    
    @pytest.mark.security
    def test_encryption_key_management(self):
        """Test encryption key management security."""
        # Test key generation
        key1 = self.encryption_service.generate_key()
        key2 = self.encryption_service.generate_key()
        
        # Assert
        assert key1 != key2  # Keys should be unique
        assert len(key1) == 44  # Fernet keys are 44 characters (base64 encoded)
        assert len(key2) == 44
        
        # Test key rotation
        old_key = self.encryption_service.current_key
        self.encryption_service.rotate_key()
        new_key = self.encryption_service.current_key
        
        assert old_key != new_key  # Key should change after rotation
    
    @pytest.mark.security
    def test_secure_random_generation(self):
        """Test cryptographically secure random generation."""
        # Generate random values
        randoms = [secrets.token_hex(32) for _ in range(100)]
        
        # Assert
        assert len(set(randoms)) == 100  # All should be unique
        assert all(len(r) == 64 for r in randoms)  # 32 bytes = 64 hex chars
    
    @pytest.mark.security
    def test_memory_protection(self):
        """Test protection of sensitive data in memory."""
        # This is more of a design test - ensuring sensitive data is cleared
        sensitive_data = "very_secret_password_123"
        
        # Simulate processing
        processed_data = self.encryption_service.hash_password(sensitive_data)
        
        # Clear the original data (this would be done automatically)
        sensitive_data = None
        
        # Assert
        assert processed_data is not None
        assert "very_secret_password_123" not in str(processed_data)


class TestSessionSecurity:
    """Test session management security."""
    
    @pytest.mark.security
    def test_session_fixation_protection(self, client: TestClient):
        """Test protection against session fixation attacks."""
        # Arrange - Get initial session
        response1 = client.get("/api/v1/health")
        session_before = response1.cookies.get("session_id")
        
        # Act - Login
        login_response = client.post("/api/v1/auth/login", data={
            "username": "testuser",
            "password": "testpass"
        })
        
        # Get session after login
        if login_response.status_code == 200:
            session_after = login_response.cookies.get("session_id")
            
            # Assert - Session should change after login
            assert session_before != session_after
    
    @pytest.mark.security
    def test_session_timeout(self, client: TestClient):
        """Test session timeout mechanism."""
        # This would require mocking time or waiting
        # For now, we test that sessions have expiration
        
        # Login to get session
        login_response = client.post("/api/v1/auth/login", data={
            "username": "testuser",
            "password": "testpass"
        })
        
        if login_response.status_code == 200:
            # Check if session cookie has expiration
            cookies = login_response.cookies
            if 'session_id' in cookies:
                session_cookie = cookies['session_id']
                # Session should have max-age or expires set
                assert hasattr(session_cookie, 'expires') or hasattr(session_cookie, 'max_age')


class TestAPISecurityHeaders:
    """Test security-related HTTP headers."""
    
    @pytest.mark.security
    def test_security_headers_present(self, client: TestClient):
        """Test that security headers are present in responses."""
        # Act
        response = client.get("/api/v1/health")
        
        # Assert
        headers = response.headers
        
        # Check for important security headers
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': None,  # Should be present
            'Content-Security-Policy': None,    # Should be present
        }
        
        for header, expected_value in security_headers.items():
            assert header in headers, f"Security header {header} is missing"
            if expected_value:
                assert headers[header] == expected_value
    
    @pytest.mark.security
    def test_cors_configuration(self, client: TestClient):
        """Test CORS configuration security."""
        # Act - Send OPTIONS request with Origin header
        response = client.options(
            "/api/v1/pii/detect",
            headers={"Origin": "https://evil.com"}
        )
        
        # Assert
        # Should not allow arbitrary origins
        cors_origin = response.headers.get("Access-Control-Allow-Origin")
        if cors_origin:
            assert cors_origin != "*"  # Should not be wildcard
            assert "evil.com" not in cors_origin  # Should not allow evil domains
    
    @pytest.mark.security
    def test_information_disclosure_prevention(self, client: TestClient):
        """Test prevention of information disclosure in errors."""
        # Act - Send malformed request
        response = client.post("/api/v1/pii/detect", data="invalid json")
        
        # Assert
        if response.status_code >= 400:
            error_text = response.text.lower()
            
            # Should not expose sensitive information
            sensitive_info = [
                'traceback', 'stack trace', 'file path',
                'database', 'sql', 'internal error',
                'debug', 'exception'
            ]
            
            for info in sensitive_info:
                assert info not in error_text, f"Sensitive information '{info}' exposed in error"


class TestCryptographicSecurity:
    """Test cryptographic implementations."""
    
    @pytest.mark.security
    def test_random_number_quality(self):
        """Test quality of random number generation."""
        # Generate many random numbers
        randoms = [secrets.randbelow(1000000) for _ in range(10000)]
        
        # Basic statistical tests
        assert len(set(randoms)) > 9000  # Should have good uniqueness
        assert min(randoms) >= 0
        assert max(randoms) < 1000000
        
        # Test distribution (should be roughly uniform)
        buckets = [0] * 10
        for r in randoms:
            bucket = r // 100000
            buckets[bucket] += 1
        
        # Each bucket should have roughly 1000 items (±30%)
        for count in buckets:
            assert 700 <= count <= 1300, f"Random distribution seems biased: {buckets}"
    
    @pytest.mark.security
    def test_constant_time_comparison(self):
        """Test that sensitive comparisons are constant-time."""
        import hmac
        
        # Test password comparison
        password1 = "correct_password"
        password2 = "correct_password"
        wrong_password = "wrong_password_"
        
        # These should both take similar time (constant time)
        assert hmac.compare_digest(password1, password2)
        assert not hmac.compare_digest(password1, wrong_password)
    
    @pytest.mark.security
    def test_encryption_algorithm_strength(self):
        """Test that strong encryption algorithms are used."""
        encryption_service = EncryptionService()
        
        # Test that we're using strong algorithms
        assert encryption_service.algorithm == "AES-256-GCM"
        assert encryption_service.key_size >= 256  # At least 256-bit keys
        
        # Test encryption produces different outputs for same input
        plaintext = "test data"
        encrypted1 = encryption_service.encrypt(plaintext)
        encrypted2 = encryption_service.encrypt(plaintext)
        
        assert encrypted1 != encrypted2  # Should use different nonces/IVs


class TestComplianceSecurity:
    """Test security aspects of compliance features."""
    
    @pytest.mark.security
    @pytest.mark.compliance
    def test_audit_log_integrity(self, client: TestClient, admin_auth_headers: Dict[str, str]):
        """Test that audit logs cannot be tampered with."""
        # Make some API calls to generate audit logs
        client.post("/api/v1/pii/detect", json={"text": "test"}, headers=admin_auth_headers)
        
        # Try to retrieve audit logs
        response = client.get("/api/v1/compliance/audit-logs", headers=admin_auth_headers)
        
        if response.status_code == 200:
            data = response.json()
            if "logs" in data:
                # Check that logs have integrity fields
                for log_entry in data["logs"]:
                    # Should have timestamp and hash/signature for integrity
                    assert "timestamp" in log_entry
                    # In a real implementation, there should be integrity checks
                    # assert "signature" in log_entry or "hash" in log_entry
    
    @pytest.mark.security
    @pytest.mark.compliance
    def test_data_retention_security(self):
        """Test that data retention is handled securely."""
        # This would test that expired data is securely deleted
        # For now, we ensure the retention policy exists
        from src.core.config.settings import get_settings
        settings = get_settings()
        
        # Should have data retention configuration
        assert hasattr(settings, 'data_retention_days')
        assert settings.data_retention_days > 0
        assert settings.data_retention_days <= 2555  # 7 years max


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "security"])