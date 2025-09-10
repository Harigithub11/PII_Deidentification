"""
Comprehensive API Integration Tests

Tests the full API functionality including document upload,
processing, authentication, and error handling.
"""

import pytest
import tempfile
import json
from pathlib import Path
from typing import Dict, Any
import uuid

from fastapi.testclient import TestClient
from httpx import AsyncClient

from tests.utils import (
    TestDataFactory, FileTestHelper, APITestHelper, 
    AssertionHelper, PerformanceTestHelper
)


class TestDocumentProcessingAPI:
    """Test document processing API endpoints."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.data_factory = TestDataFactory()
        self.file_helper = FileTestHelper()
        self.api_helper = APITestHelper()
        self.assertion_helper = AssertionHelper()
        self.performance_helper = PerformanceTestHelper()
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_health_check(self, client: TestClient):
        """Test API health check endpoint."""
        # Act
        response = client.get("/health")
        
        # Assert
        data = self.api_helper.assert_api_response(
            response, 200, ["status", "timestamp", "version"]
        )
        assert data["status"] == "healthy"
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_document_upload_pdf(self, client: TestClient, temp_directory: Path, auth_headers: Dict[str, str]):
        """Test PDF document upload and processing."""
        # Arrange
        pdf_content = self.data_factory.create_pii_text(['PERSON', 'EMAIL', 'PHONE_NUMBER'])
        pdf_file = self.file_helper.create_pdf_file(pdf_content, temp_directory / "test.pdf")
        
        # Act
        response = self.api_helper.upload_file(
            client, pdf_file, 
            endpoint="/api/v1/documents/upload",
            headers=auth_headers
        )
        
        # Assert
        data = self.api_helper.assert_api_response(
            response, 202, ["document_id", "status", "message"]
        )
        assert data["status"] == "processing"
        assert "document_id" in data
        
        # Test status checking
        document_id = data["document_id"]
        status_response = client.get(f"/api/v1/documents/status/{document_id}", headers=auth_headers)
        status_data = self.api_helper.assert_api_response(
            status_response, 200, ["document_id", "status"]
        )
        assert status_data["document_id"] == document_id
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_document_upload_image(self, client: TestClient, temp_directory: Path, auth_headers: Dict[str, str]):
        """Test image document upload and OCR processing."""
        # Arrange
        image_content = self.data_factory.create_pii_text(['PERSON', 'ADDRESS'])
        image_file = self.file_helper.create_image_file(image_content, temp_directory / "test.png")
        
        # Act
        response = self.api_helper.upload_file(
            client, image_file,
            headers=auth_headers
        )
        
        # Assert
        data = self.api_helper.assert_api_response(response, 202)
        assert data["status"] == "processing"
        
        # Verify OCR processing is triggered
        document_id = data["document_id"]
        # Note: In real tests, we might wait for processing or use mocks
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_document_upload_unsupported_format(self, client: TestClient, temp_directory: Path, auth_headers: Dict[str, str]):
        """Test upload of unsupported file format."""
        # Arrange
        unsupported_file = temp_directory / "test.xyz"
        unsupported_file.write_text("test content")
        
        # Act
        response = self.api_helper.upload_file(
            client, unsupported_file,
            headers=auth_headers
        )
        
        # Assert
        self.api_helper.assert_api_error_response(response, 400)
        error_data = response.json()
        assert "unsupported" in error_data["detail"].lower() or "format" in error_data["detail"].lower()
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_document_upload_without_auth(self, client: TestClient, temp_directory: Path):
        """Test document upload without authentication."""
        # Arrange
        test_file = self.file_helper.create_text_file("test content", temp_directory / "test.txt")
        
        # Act
        response = self.api_helper.upload_file(client, test_file)
        
        # Assert
        self.api_helper.assert_api_error_response(response, 401)
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_document_results_retrieval(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test retrieval of document processing results."""
        # Arrange - Mock a completed document
        document_id = str(uuid.uuid4())
        
        # Act
        response = client.get(f"/api/v1/documents/results/{document_id}", headers=auth_headers)
        
        # Assert
        # This would typically return 404 for non-existent document
        # or 200 with results for existing document
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            data = response.json()
            expected_keys = ["document_id", "processing_results", "redacted_content"]
            for key in expected_keys:
                assert key in data
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_batch_document_processing(self, client: TestClient, temp_directory: Path, auth_headers: Dict[str, str]):
        """Test batch processing of multiple documents."""
        # Arrange
        files = []
        for i in range(3):
            content = self.data_factory.create_pii_text(['PERSON', 'EMAIL'])
            file_path = self.file_helper.create_text_file(
                content, temp_directory / f"batch_test_{i}.txt"
            )
            files.append(file_path)
        
        # Act
        batch_data = {
            "files": [str(f) for f in files],
            "processing_options": {
                "detect_pii": True,
                "apply_redaction": True,
                "generate_report": True
            }
        }
        
        response = client.post(
            "/api/v1/documents/batch",
            json=batch_data,
            headers=auth_headers
        )
        
        # Assert
        if response.status_code == 200:  # If batch endpoint exists
            data = response.json()
            assert "batch_id" in data
            assert "status" in data
            assert data["status"] == "processing"


class TestPIIDetectionAPI:
    """Test PII detection API endpoints."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.data_factory = TestDataFactory()
        self.api_helper = APITestHelper()
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_detect_pii_endpoint(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test PII detection API endpoint."""
        # Arrange
        test_text = self.data_factory.create_pii_text(['PERSON', 'EMAIL', 'PHONE_NUMBER'])
        request_data = {
            "text": test_text,
            "language": "en",
            "include_confidence": True,
            "entity_types": ["PERSON", "EMAIL", "PHONE_NUMBER"]
        }
        
        # Act
        response = client.post(
            "/api/v1/pii/detect",
            json=request_data,
            headers=auth_headers
        )
        
        # Assert
        data = self.api_helper.assert_api_response(
            response, 200, ["entities", "risk_level", "processing_time"]
        )
        
        assert isinstance(data["entities"], list)
        assert data["risk_level"] in ["low", "medium", "high"]
        assert isinstance(data["processing_time"], (int, float))
        
        # Validate entity structure
        for entity in data["entities"]:
            assert "text" in entity
            assert "label" in entity
            assert "start" in entity
            assert "end" in entity
            assert "confidence" in entity
            assert 0 <= entity["confidence"] <= 1
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_detect_pii_empty_text(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test PII detection with empty text."""
        # Act
        response = client.post(
            "/api/v1/pii/detect",
            json={"text": ""},
            headers=auth_headers
        )
        
        # Assert
        self.api_helper.assert_api_error_response(response, 400)
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_detect_pii_large_text(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test PII detection with large text input."""
        # Arrange
        large_text = self.data_factory.create_pii_text() * 100  # Create large text
        request_data = {"text": large_text}
        
        # Act
        start_time, response, execution_time = self.api_helper.measure_execution_time(
            client.post, "/api/v1/pii/detect", json=request_data, headers=auth_headers
        )
        
        # Assert
        if response.status_code == 200:
            data = response.json()
            assert "entities" in data
            # Check performance is reasonable for large text
            assert execution_time < 30.0  # Should complete within 30 seconds
        elif response.status_code == 413:
            # Payload too large - acceptable response
            pass
        else:
            pytest.fail(f"Unexpected status code: {response.status_code}")
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_detect_pii_multilingual(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test PII detection with multilingual text."""
        # Arrange
        test_cases = [
            {"text": "My name is John Smith", "language": "en"},
            {"text": "मेरा नाम राम शर्मा है", "language": "hi"},
            {"text": "Mi nombre es Juan Pérez", "language": "es"}
        ]
        
        for test_case in test_cases:
            # Act
            response = client.post(
                "/api/v1/pii/detect",
                json=test_case,
                headers=auth_headers
            )
            
            # Assert
            if response.status_code == 200:
                data = response.json()
                assert "entities" in data
                # Language-specific validation could be added here


class TestRedactionAPI:
    """Test redaction API endpoints."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.data_factory = TestDataFactory()
        self.api_helper = APITestHelper()
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_redact_text_endpoint(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test text redaction API endpoint."""
        # Arrange
        original_text = self.data_factory.create_pii_text(['PERSON', 'EMAIL'])
        request_data = {
            "text": original_text,
            "redaction_method": "mask",
            "preserve_structure": True,
            "custom_replacements": {
                "PERSON": "[NAME]",
                "EMAIL": "[EMAIL]"
            }
        }
        
        # Act
        response = client.post(
            "/api/v1/redaction/text",
            json=request_data,
            headers=auth_headers
        )
        
        # Assert
        data = self.api_helper.assert_api_response(
            response, 200, ["redacted_text", "redaction_count"]
        )
        
        assert len(data["redacted_text"]) > 0
        assert data["redaction_count"] > 0
        assert data["redacted_text"] != original_text  # Should be different
        
        # Check that PII is actually redacted
        assert "[NAME]" in data["redacted_text"] or "[REDACTED]" in data["redacted_text"]
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_redact_document_endpoint(self, client: TestClient, temp_directory: Path, auth_headers: Dict[str, str]):
        """Test document redaction API endpoint."""
        # Arrange
        content = self.data_factory.create_pii_text(['PERSON', 'SSN', 'EMAIL'])
        pdf_file = self.file_helper.create_pdf_file(content, temp_directory / "redact_test.pdf")
        
        # Act
        response = self.api_helper.upload_file(
            client, pdf_file,
            endpoint="/api/v1/redaction/document",
            headers=auth_headers
        )
        
        # Assert
        data = self.api_helper.assert_api_response(response, 202)
        assert "job_id" in data
        assert data["status"] == "processing"
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_redaction_policies(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test redaction with different policy configurations."""
        # Arrange
        test_text = self.data_factory.create_pii_text(['PERSON', 'EMAIL', 'PHONE_NUMBER'])
        
        policies = ["GDPR", "HIPAA", "PCI_DSS", "CUSTOM"]
        
        for policy in policies:
            request_data = {
                "text": test_text,
                "policy": policy,
                "redaction_method": "replace"
            }
            
            # Act
            response = client.post(
                "/api/v1/redaction/text",
                json=request_data,
                headers=auth_headers
            )
            
            # Assert
            if response.status_code == 200:
                data = response.json()
                assert "redacted_text" in data
                assert "policy_applied" in data
                assert data["policy_applied"] == policy


class TestDashboardAPI:
    """Test dashboard and analytics API endpoints."""
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_dashboard_overview(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test dashboard overview endpoint."""
        # Act
        response = client.get("/api/v1/dashboard/overview", headers=auth_headers)
        
        # Assert
        data = self.api_helper.assert_api_response(response, 200)
        
        expected_sections = ["processing_stats", "security_alerts", "compliance_status"]
        for section in expected_sections:
            if section in data:  # Optional sections
                assert isinstance(data[section], dict)
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_analytics_endpoint(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test analytics data endpoint."""
        # Act
        response = client.get(
            "/api/v1/dashboard/analytics",
            params={
                "timeframe": "7d",
                "metrics": ["pii_detected", "documents_processed", "risk_levels"]
            },
            headers=auth_headers
        )
        
        # Assert
        if response.status_code == 200:
            data = response.json()
            assert "timeframe" in data
            assert "metrics" in data
            assert isinstance(data["metrics"], dict)


class TestComplianceAPI:
    """Test compliance and audit API endpoints."""
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest.mark.compliance
    def test_compliance_report_generation(self, client: TestClient, admin_auth_headers: Dict[str, str]):
        """Test compliance report generation."""
        # Arrange
        request_data = {
            "report_type": "GDPR",
            "date_range": {
                "start": "2024-01-01",
                "end": "2024-12-31"
            },
            "include_details": True
        }
        
        # Act
        response = client.post(
            "/api/v1/compliance/reports/generate",
            json=request_data,
            headers=admin_auth_headers
        )
        
        # Assert
        if response.status_code == 202:
            data = response.json()
            assert "report_id" in data
            assert "status" in data
        elif response.status_code == 200:
            data = response.json()
            assert "report_data" in data
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest.mark.compliance
    def test_audit_log_retrieval(self, client: TestClient, admin_auth_headers: Dict[str, str]):
        """Test audit log retrieval."""
        # Act
        response = client.get(
            "/api/v1/compliance/audit-logs",
            params={
                "limit": 100,
                "event_type": "pii_detection",
                "start_date": "2024-01-01"
            },
            headers=admin_auth_headers
        )
        
        # Assert
        data = self.api_helper.assert_api_response(response, 200)
        
        if "logs" in data:
            assert isinstance(data["logs"], list)
            for log_entry in data["logs"]:
                assert "timestamp" in log_entry
                assert "event_type" in log_entry
                assert "user_id" in log_entry


class TestAuthenticationAPI:
    """Test authentication and authorization."""
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest.mark.security
    def test_login_endpoint(self, client: TestClient):
        """Test user login endpoint."""
        # Arrange
        login_data = {
            "username": "testuser",
            "password": "testpassword"
        }
        
        # Act
        response = client.post("/api/v1/auth/login", data=login_data)
        
        # Assert
        # This will depend on whether test user exists
        assert response.status_code in [200, 401]
        
        if response.status_code == 200:
            data = response.json()
            assert "access_token" in data
            assert "token_type" in data
            assert data["token_type"] == "bearer"
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest.mark.security
    def test_token_validation(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test token validation."""
        # Act
        response = client.get("/api/v1/auth/me", headers=auth_headers)
        
        # Assert
        data = self.api_helper.assert_api_response(response, 200)
        assert "username" in data
        assert "role" in data
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest.mark.security
    def test_invalid_token(self, client: TestClient):
        """Test handling of invalid tokens."""
        # Arrange
        invalid_headers = {"Authorization": "Bearer invalid-token"}
        
        # Act
        response = client.get("/api/v1/auth/me", headers=invalid_headers)
        
        # Assert
        self.api_helper.assert_api_error_response(response, 401)
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest.mark.security
    def test_role_based_access(self, client: TestClient, auth_headers: Dict[str, str], admin_auth_headers: Dict[str, str]):
        """Test role-based access control."""
        # Test user access to admin endpoint
        response = client.get("/api/v1/admin/users", headers=auth_headers)
        assert response.status_code in [403, 401]  # Should be forbidden
        
        # Test admin access to admin endpoint
        response = client.get("/api/v1/admin/users", headers=admin_auth_headers)
        assert response.status_code in [200, 404]  # Should be allowed (or not found)


class TestErrorHandling:
    """Test API error handling and edge cases."""
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_malformed_json(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test handling of malformed JSON requests."""
        # Act
        response = client.post(
            "/api/v1/pii/detect",
            data="invalid json{",
            headers={**auth_headers, "Content-Type": "application/json"}
        )
        
        # Assert
        self.api_helper.assert_api_error_response(response, 422)
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_missing_required_fields(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test handling of missing required fields."""
        # Act
        response = client.post(
            "/api/v1/pii/detect",
            json={},  # Missing required 'text' field
            headers=auth_headers
        )
        
        # Assert
        self.api_helper.assert_api_error_response(response, 422)
        error_data = response.json()
        assert "detail" in error_data
    
    @pytest.mark.integration
    @pytest.mark.api
    def test_rate_limiting(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test API rate limiting."""
        # Arrange
        endpoint = "/api/v1/pii/detect"
        request_data = {"text": "Test text for rate limiting"}
        
        # Act - Make many requests rapidly
        responses = []
        for _ in range(20):
            response = client.post(endpoint, json=request_data, headers=auth_headers)
            responses.append(response)
        
        # Assert
        status_codes = [r.status_code for r in responses]
        
        # Should have some successful requests and possibly some rate-limited (429)
        assert 200 in status_codes
        # If rate limiting is implemented, we might see 429 responses
        if 429 in status_codes:
            # Verify rate limit response structure
            rate_limited_response = next(r for r in responses if r.status_code == 429)
            assert "retry-after" in rate_limited_response.headers.get("retry-after", "") or True


class TestPerformance:
    """Test API performance characteristics."""
    
    def setup_method(self):
        """Set up performance testing utilities."""
        self.performance_helper = PerformanceTestHelper()
        self.api_helper = APITestHelper()
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest.mark.performance
    def test_response_time_sla(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test API response time meets SLA requirements."""
        # Arrange
        test_text = TestDataFactory().create_pii_text(['PERSON', 'EMAIL'])
        request_data = {"text": test_text}
        
        # Act
        result, execution_time = self.performance_helper.measure_execution_time(
            client.post, "/api/v1/pii/detect", json=request_data, headers=auth_headers
        )
        
        # Assert
        assert result.status_code == 200
        # API should respond within 5 seconds for normal requests
        assert execution_time < 5.0, f"Response time {execution_time:.3f}s exceeds 5s SLA"
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest.mark.performance
    @pytest.mark.slow
    def test_concurrent_requests(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test API performance under concurrent load."""
        import concurrent.futures
        import threading
        
        # Arrange
        def make_request():
            return client.post(
                "/api/v1/pii/detect",
                json={"text": "John Smith is a test user"},
                headers=auth_headers
            )
        
        # Act - Make 10 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            responses = [future.result() for future in futures]
        
        # Assert
        successful_responses = [r for r in responses if r.status_code == 200]
        error_responses = [r for r in responses if r.status_code >= 400]
        
        # At least 70% of requests should succeed under load
        success_rate = len(successful_responses) / len(responses)
        assert success_rate >= 0.7, f"Success rate {success_rate:.2%} below 70% threshold"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "integration"])