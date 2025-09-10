"""
Test Utilities and Helper Functions

This module provides utility functions and helpers for testing
the PII De-identification System.
"""

import json
import random
import string
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import Mock, AsyncMock
import uuid

import httpx
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw, ImageFont


class TestDataFactory:
    """Factory for creating test data."""
    
    @staticmethod
    def create_pii_text(include_types: Optional[List[str]] = None) -> str:
        """Create text containing various PII types."""
        pii_examples = {
            "PERSON": ["John Smith", "Mary Johnson", "David Brown", "Sarah Wilson"],
            "EMAIL": ["john.smith@email.com", "mary@company.com", "user@domain.org"],
            "PHONE_NUMBER": ["(555) 123-4567", "555-987-6543", "+1-555-123-4567"],
            "SSN": ["123-45-6789", "987-65-4321", "456-78-9012"],
            "CREDIT_CARD": ["4111-1111-1111-1111", "5555-5555-5555-4444", "378282246310005"],
            "ADDRESS": ["123 Main Street, New York, NY 10001", "456 Oak Ave, Los Angeles, CA 90210"],
            "DATE_OF_BIRTH": ["01/15/1990", "December 25, 1985", "1988-07-04"],
            "MEDICAL_RECORD": ["MRN: 123456789", "Patient ID: ABC-123", "Chart #: XYZ-789"]
        }
        
        if include_types is None:
            include_types = list(pii_examples.keys())
        
        text_parts = ["This document contains personal information:"]
        
        for pii_type in include_types:
            if pii_type in pii_examples:
                example = random.choice(pii_examples[pii_type])
                text_parts.append(f" {example}")
        
        return " ".join(text_parts) + "."
    
    @staticmethod
    def create_document_metadata(
        filename: str = None,
        content_type: str = "application/pdf",
        size: int = None
    ) -> Dict[str, Any]:
        """Create document metadata for testing."""
        if filename is None:
            filename = f"test_document_{uuid.uuid4().hex[:8]}.pdf"
        
        if size is None:
            size = random.randint(1024, 1024*1024)  # 1KB to 1MB
        
        return {
            "document_id": str(uuid.uuid4()),
            "filename": filename,
            "content_type": content_type,
            "size": size,
            "upload_date": datetime.utcnow(),
            "status": "uploaded",
            "metadata": {
                "pages": random.randint(1, 10),
                "language": "en",
                "encrypted": False
            }
        }
    
    @staticmethod
    def create_detection_result(
        entity_count: int = 5,
        confidence_range: Tuple[float, float] = (0.7, 0.95)
    ) -> Dict[str, Any]:
        """Create PII detection result for testing."""
        entities = []
        entity_types = ["PERSON", "EMAIL", "PHONE_NUMBER", "SSN", "ADDRESS"]
        
        for i in range(entity_count):
            entity_type = random.choice(entity_types)
            confidence = random.uniform(*confidence_range)
            
            entities.append({
                "text": f"test_{entity_type.lower()}_{i}",
                "label": entity_type,
                "start": i * 20,
                "end": (i * 20) + 10,
                "confidence": round(confidence, 3)
            })
        
        return {
            "entities": entities,
            "total_entities": entity_count,
            "high_confidence_entities": len([e for e in entities if e["confidence"] > 0.9]),
            "processing_time": random.uniform(0.1, 2.0),
            "risk_level": random.choice(["low", "medium", "high"])
        }
    
    @staticmethod
    def create_user_data(
        role: str = "user",
        status: str = "active"
    ) -> Dict[str, Any]:
        """Create user data for testing."""
        user_id = str(uuid.uuid4())
        username = f"testuser_{user_id[:8]}"
        
        return {
            "user_id": user_id,
            "username": username,
            "email": f"{username}@example.com",
            "full_name": f"Test User {user_id[:8]}",
            "hashed_password": "$2b$12$test_hashed_password",
            "role": role,
            "status": status,
            "created_at": datetime.utcnow() - timedelta(days=random.randint(1, 365)),
            "last_login": datetime.utcnow() - timedelta(hours=random.randint(1, 24))
        }


class FileTestHelper:
    """Helper for creating test files."""
    
    @staticmethod
    def create_pdf_file(content: str, file_path: Path) -> Path:
        """Create a PDF file with specified content."""
        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter
            
            c = canvas.Canvas(str(file_path), pagesize=letter)
            
            # Split content into lines
            lines = content.split('\n')
            y_position = 750
            
            for line in lines:
                if y_position < 50:  # Start new page
                    c.showPage()
                    y_position = 750
                
                c.drawString(50, y_position, line.strip())
                y_position -= 20
            
            c.save()
            
        except ImportError:
            # Fallback: create basic PDF structure
            pdf_content = f"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length {len(content)}
>>
stream
BT
/F1 12 Tf
50 750 Td
({content}) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000010 00000 n 
0000000079 00000 n 
0000000173 00000 n 
0000000301 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
492
%%EOF"""
            file_path.write_text(pdf_content)
        
        return file_path
    
    @staticmethod
    def create_image_file(
        content: str,
        file_path: Path,
        width: int = 800,
        height: int = 600
    ) -> Path:
        """Create an image file with text content."""
        try:
            img = Image.new('RGB', (width, height), color='white')
            draw = ImageDraw.Draw(img)
            
            try:
                font = ImageFont.truetype("arial.ttf", 20)
            except (OSError, IOError):
                font = ImageFont.load_default()
            
            # Draw text on image
            lines = content.split('\n')
            y_position = 50
            
            for line in lines:
                if y_position > height - 50:
                    break
                draw.text((50, y_position), line.strip(), fill='black', font=font)
                y_position += 30
            
            img.save(file_path)
            
        except ImportError:
            # Fallback: create minimal PNG file
            png_header = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x03 \x00\x00\x02X\x08\x06\x00\x00\x00'
            file_path.write_bytes(png_header + b'\x00' * 100)
        
        return file_path
    
    @staticmethod
    def create_text_file(content: str, file_path: Path) -> Path:
        """Create a text file with specified content."""
        file_path.write_text(content, encoding='utf-8')
        return file_path


class APITestHelper:
    """Helper for API testing."""
    
    @staticmethod
    def make_authenticated_request(
        client: TestClient,
        method: str,
        url: str,
        token: str,
        **kwargs
    ) -> httpx.Response:
        """Make authenticated API request."""
        headers = kwargs.pop('headers', {})
        headers['Authorization'] = f'Bearer {token}'
        
        return client.request(method, url, headers=headers, **kwargs)
    
    @staticmethod
    def upload_file(
        client: TestClient,
        file_path: Path,
        endpoint: str = "/api/v1/documents/upload",
        headers: Optional[Dict[str, str]] = None
    ) -> httpx.Response:
        """Upload file via API."""
        with open(file_path, 'rb') as file:
            files = {'file': (file_path.name, file, 'application/octet-stream')}
            return client.post(endpoint, files=files, headers=headers or {})
    
    @staticmethod
    def wait_for_processing(
        client: TestClient,
        job_id: str,
        timeout: int = 30,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Wait for document processing to complete."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            response = client.get(f"/api/v1/documents/status/{job_id}", headers=headers or {})
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') in ['completed', 'failed', 'error']:
                    return result
            
            time.sleep(1)
        
        raise TimeoutError(f"Processing timeout after {timeout} seconds")
    
    @staticmethod
    def assert_api_response(
        response: httpx.Response,
        expected_status: int = 200,
        expected_keys: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Assert API response structure and status."""
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}: {response.text}"
        
        if expected_status < 400:
            data = response.json()
            
            if expected_keys:
                for key in expected_keys:
                    assert key in data, f"Expected key '{key}' not found in response: {data}"
            
            return data
        
        return {}


class MockHelper:
    """Helper for creating mocks."""
    
    @staticmethod
    def create_mock_model_manager():
        """Create mock model manager."""
        manager = Mock()
        
        # Mock spaCy model
        mock_doc = Mock()
        mock_doc.ents = []
        mock_nlp = Mock(return_value=mock_doc)
        
        manager.get_spacy_model.return_value = mock_nlp
        manager.load_model = AsyncMock(return_value=True)
        manager.is_model_loaded.return_value = True
        
        return manager
    
    @staticmethod
    def create_mock_pii_detector():
        """Create mock PII detector."""
        detector = Mock()
        
        detector.detect_pii = AsyncMock(return_value={
            "entities": [
                {
                    "text": "John Smith",
                    "label": "PERSON",
                    "start": 0,
                    "end": 10,
                    "confidence": 0.95
                }
            ],
            "risk_level": "medium",
            "processing_time": 0.123
        })
        
        return detector
    
    @staticmethod
    def create_mock_redaction_engine():
        """Create mock redaction engine."""
        engine = Mock()
        
        engine.redact_text = AsyncMock(return_value={
            "redacted_text": "[REDACTED] information here",
            "redaction_map": [{"original": "sensitive", "redacted": "[REDACTED]"}],
            "redaction_count": 1
        })
        
        return engine
    
    @staticmethod
    def create_mock_database():
        """Create mock database session."""
        db = Mock()
        db.query.return_value.filter.return_value.first.return_value = None
        db.add = Mock()
        db.commit = Mock()
        db.refresh = Mock()
        db.rollback = Mock()
        db.close = Mock()
        
        return db


class PerformanceTestHelper:
    """Helper for performance testing."""
    
    @staticmethod
    def measure_execution_time(func, *args, **kwargs):
        """Measure function execution time."""
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        return result, end_time - start_time
    
    @staticmethod
    async def measure_async_execution_time(func, *args, **kwargs):
        """Measure async function execution time."""
        start_time = time.time()
        result = await func(*args, **kwargs)
        end_time = time.time()
        
        return result, end_time - start_time
    
    @staticmethod
    def generate_load_test_data(size: int = 1000) -> List[str]:
        """Generate data for load testing."""
        templates = [
            "Name: {name}, Email: {email}, Phone: {phone}",
            "Patient: {name}, DOB: {date}, MRN: {id}",
            "Customer: {name}, Account: {account}, Address: {address}"
        ]
        
        data = []
        for _ in range(size):
            template = random.choice(templates)
            data.append(template.format(
                name=f"User {random.randint(1000, 9999)}",
                email=f"user{random.randint(100, 999)}@example.com",
                phone=f"555-{random.randint(100, 999)}-{random.randint(1000, 9999)}",
                date=f"{random.randint(1, 12)}/{random.randint(1, 28)}/{random.randint(1970, 2000)}",
                id=f"ID-{random.randint(100000, 999999)}",
                account=f"ACC-{random.randint(10000, 99999)}",
                address=f"{random.randint(100, 9999)} Main St"
            ))
        
        return data


class SecurityTestHelper:
    """Helper for security testing."""
    
    @staticmethod
    def get_sql_injection_payloads() -> List[str]:
        """Get SQL injection test payloads."""
        return [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'/*",
            "' UNION SELECT * FROM users --",
            "1'; EXEC xp_cmdshell('dir'); --",
            "1' AND (SELECT COUNT(*) FROM users) > 0 --"
        ]
    
    @staticmethod
    def get_xss_payloads() -> List[str]:
        """Get XSS test payloads."""
        return [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert(String.fromCharCode(88,83,83))//",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "<svg/onload=alert('XSS')>"
        ]
    
    @staticmethod
    def get_path_traversal_payloads() -> List[str]:
        """Get path traversal test payloads."""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
    
    @staticmethod
    def test_input_validation(
        client: TestClient,
        endpoint: str,
        field: str,
        payloads: List[str],
        method: str = "POST"
    ) -> Dict[str, Any]:
        """Test input validation with malicious payloads."""
        results = {
            "vulnerable": [],
            "protected": [],
            "errors": []
        }
        
        for payload in payloads:
            try:
                data = {field: payload}
                response = client.request(method, endpoint, json=data)
                
                if response.status_code == 200:
                    results["vulnerable"].append({
                        "payload": payload,
                        "response": response.json()
                    })
                else:
                    results["protected"].append({
                        "payload": payload,
                        "status_code": response.status_code
                    })
                    
            except Exception as e:
                results["errors"].append({
                    "payload": payload,
                    "error": str(e)
                })
        
        return results


class ComplianceTestHelper:
    """Helper for compliance testing."""
    
    @staticmethod
    def create_gdpr_test_data() -> Dict[str, Any]:
        """Create GDPR compliance test data."""
        return {
            "personal_data": {
                "name": "John Doe",
                "email": "john.doe@example.com",
                "phone": "+1-555-123-4567",
                "address": "123 Main Street, City, Country",
                "date_of_birth": "1990-01-01"
            },
            "sensitive_data": {
                "health_data": "Patient has diabetes",
                "biometric_data": "Fingerprint: ABC123",
                "genetic_data": "Gene variant: XYZ789"
            },
            "consent_records": [
                {
                    "purpose": "processing",
                    "consent_given": True,
                    "timestamp": datetime.utcnow()
                },
                {
                    "purpose": "marketing",
                    "consent_given": False,
                    "timestamp": datetime.utcnow()
                }
            ]
        }
    
    @staticmethod
    def create_hipaa_test_data() -> Dict[str, Any]:
        """Create HIPAA compliance test data."""
        return {
            "phi_identifiers": [
                "John Smith",  # Name
                "123-45-6789",  # SSN
                "john.smith@email.com",  # Email
                "(555) 123-4567",  # Phone
                "123 Main Street",  # Address
                "01/15/1990",  # Date of birth
                "MRN-123456",  # Medical record number
                "ACC-789012"   # Account number
            ],
            "medical_information": {
                "diagnosis": "Type 2 Diabetes",
                "treatment": "Metformin 500mg",
                "provider": "Dr. Johnson",
                "facility": "Metro Hospital"
            },
            "dates": [
                "2024-01-15",  # Service date
                "2024-02-20",  # Admission date
                "2024-03-10"   # Discharge date
            ]
        }
    
    @staticmethod
    def validate_redaction_compliance(
        original_text: str,
        redacted_text: str,
        standard: str = "HIPAA"
    ) -> Dict[str, Any]:
        """Validate redaction compliance with standards."""
        validation_result = {
            "compliant": True,
            "violations": [],
            "recommendations": []
        }
        
        if standard == "HIPAA":
            # Check for Safe Harbor identifiers
            safe_harbor_patterns = [
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',  # Dates
                r'\(\d{3}\)\s?\d{3}-\d{4}',  # Phone numbers
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Emails
            ]
            
            import re
            for pattern in safe_harbor_patterns:
                if re.search(pattern, redacted_text):
                    validation_result["compliant"] = False
                    validation_result["violations"].append(f"HIPAA identifier found: {pattern}")
        
        elif standard == "GDPR":
            # Check for personal data
            if any(indicator in redacted_text.lower() for indicator in ["name", "email", "phone", "address"]):
                validation_result["compliant"] = False
                validation_result["violations"].append("Personal data may still be present")
        
        return validation_result


class AssertionHelper:
    """Helper for common test assertions."""
    
    @staticmethod
    def assert_pii_detected(detection_result: Dict[str, Any], expected_count: int = None):
        """Assert PII was properly detected."""
        assert "entities" in detection_result
        assert isinstance(detection_result["entities"], list)
        
        if expected_count is not None:
            assert len(detection_result["entities"]) == expected_count
        
        for entity in detection_result["entities"]:
            assert "text" in entity
            assert "label" in entity
            assert "confidence" in entity
            assert 0 <= entity["confidence"] <= 1
    
    @staticmethod
    def assert_redaction_successful(redaction_result: Dict[str, Any]):
        """Assert redaction was successful."""
        assert "redacted_text" in redaction_result
        assert "redaction_count" in redaction_result
        assert redaction_result["redaction_count"] > 0
        
        if "redaction_map" in redaction_result:
            assert isinstance(redaction_result["redaction_map"], list)
    
    @staticmethod
    def assert_api_error_response(response: httpx.Response, expected_code: int):
        """Assert API error response structure."""
        assert response.status_code == expected_code
        
        if response.status_code >= 400:
            error_data = response.json()
            assert "detail" in error_data or "error" in error_data
    
    @staticmethod
    def assert_performance_acceptable(
        execution_time: float,
        max_time: float,
        operation: str = "Operation"
    ):
        """Assert performance is within acceptable limits."""
        assert execution_time <= max_time, f"{operation} took {execution_time:.3f}s, expected < {max_time}s"
    
    @staticmethod
    def assert_compliance_met(
        validation_result: Dict[str, Any],
        standard: str
    ):
        """Assert compliance requirements are met."""
        assert validation_result["compliant"], f"{standard} compliance failed: {validation_result['violations']}"


# Export all helpers
__all__ = [
    'TestDataFactory',
    'FileTestHelper', 
    'APITestHelper',
    'MockHelper',
    'PerformanceTestHelper',
    'SecurityTestHelper',
    'ComplianceTestHelper',
    'AssertionHelper'
]