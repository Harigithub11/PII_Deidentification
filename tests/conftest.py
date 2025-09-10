"""
Comprehensive Test Configuration and Fixtures

This module provides shared test fixtures, configurations, and utilities
for the PII De-identification System test suite.
"""

import asyncio
import os
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import AsyncGenerator, Dict, Generator, List, Optional
from unittest.mock import AsyncMock, Mock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Test framework imports
from fastapi import FastAPI
from httpx import AsyncClient

# Application imports
from src.main import app
from src.core.config.settings import get_settings
from src.core.database.models import Base
from src.core.database.session import get_db
from src.core.security.auth import create_access_token, get_current_user
from src.core.security.models import User, UserRole, AccountStatus
from src.core.models.model_manager import ModelManager
from src.core.services.pii_detector import PIIDetectionService
from src.core.services.redaction_engine import RedactionEngine
from src.core.config.policies.base import PolicyManager


# Test Configuration
TEST_DATABASE_URL = "sqlite:///./test.db"
TEST_REDIS_URL = "redis://localhost:6379/15"  # Use test database

# Set test environment variables
os.environ["TEST_MODE"] = "true"
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["REDIS_URL"] = TEST_REDIS_URL
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"
os.environ["ENCRYPTION_KEY"] = "test-encryption-key-32-bytes-long"


# Database Fixtures
@pytest.fixture(scope="session")
def test_engine():
    """Create test database engine."""
    engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="session")
def test_session_factory(test_engine):
    """Create test session factory."""
    return sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture
def test_db(test_session_factory):
    """Create test database session."""
    session = test_session_factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def override_get_db(test_db):
    """Override database dependency for testing."""
    def _override_get_db():
        try:
            yield test_db
        finally:
            test_db.close()
    
    app.dependency_overrides[get_db] = _override_get_db
    yield
    app.dependency_overrides.clear()


# Application Fixtures
@pytest.fixture
def test_app(override_get_db) -> FastAPI:
    """Create test FastAPI application."""
    return app


@pytest.fixture
def client(test_app) -> TestClient:
    """Create test client."""
    return TestClient(test_app)


@pytest.fixture
async def async_client(test_app) -> AsyncGenerator[AsyncClient, None]:
    """Create async test client."""
    async with AsyncClient(app=test_app, base_url="http://test") as ac:
        yield ac


# User and Authentication Fixtures
@pytest.fixture
def test_user() -> User:
    """Create test user."""
    return User(
        user_id=str(uuid.uuid4()),
        username="testuser",
        email="test@example.com",
        full_name="Test User",
        hashed_password="$2b$12$test_hashed_password",
        role=UserRole.USER,
        status=AccountStatus.ACTIVE,
        created_at=datetime.utcnow(),
        last_login=datetime.utcnow()
    )


@pytest.fixture
def test_admin_user() -> User:
    """Create test admin user."""
    return User(
        user_id=str(uuid.uuid4()),
        username="admin",
        email="admin@example.com",
        full_name="Admin User",
        hashed_password="$2b$12$test_hashed_password",
        role=UserRole.ADMIN,
        status=AccountStatus.ACTIVE,
        created_at=datetime.utcnow(),
        last_login=datetime.utcnow()
    )


@pytest.fixture
def auth_headers(test_user) -> Dict[str, str]:
    """Create authentication headers."""
    token = create_access_token(data={"sub": test_user.username})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_auth_headers(test_admin_user) -> Dict[str, str]:
    """Create admin authentication headers."""
    token = create_access_token(data={"sub": test_admin_user.username})
    return {"Authorization": f"Bearer {token}"}


# Mock Services
@pytest.fixture
def mock_model_manager():
    """Mock model manager."""
    manager = Mock(spec=ModelManager)
    
    # Mock model loading
    manager.load_model = AsyncMock(return_value=True)
    manager.is_model_loaded = Mock(return_value=True)
    manager.get_model = Mock(return_value=Mock())
    
    # Mock spaCy model
    mock_doc = Mock()
    mock_doc.ents = []
    mock_nlp = Mock()
    mock_nlp.return_value = mock_doc
    manager.get_spacy_model = Mock(return_value=mock_nlp)
    
    return manager


@pytest.fixture
def mock_pii_detector(mock_model_manager):
    """Mock PII detection service."""
    detector = Mock(spec=PIIDetectionService)
    
    # Mock detection results
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
    
    detector.analyze_document = AsyncMock(return_value={
        "document_id": str(uuid.uuid4()),
        "total_entities": 5,
        "high_risk_entities": 2,
        "processing_status": "completed"
    })
    
    return detector


@pytest.fixture
def mock_redaction_engine():
    """Mock redaction engine."""
    engine = Mock(spec=RedactionEngine)
    
    # Mock redaction results
    engine.redact_text = AsyncMock(return_value={
        "redacted_text": "[REDACTED] is a test user",
        "redaction_map": [{"original": "John Smith", "redacted": "[REDACTED]"}],
        "redaction_count": 1
    })
    
    engine.redact_document = AsyncMock(return_value={
        "document_path": "/tmp/redacted_document.pdf",
        "redaction_summary": {"entities_redacted": 5},
        "processing_time": 1.234
    })
    
    return engine


@pytest.fixture
def mock_policy_manager():
    """Mock policy manager."""
    manager = Mock(spec=PolicyManager)
    
    # Mock policy loading
    manager.load_policy = AsyncMock(return_value=True)
    manager.get_policy = Mock(return_value={
        "name": "test_policy",
        "version": "1.0",
        "rules": [],
        "compliance_standards": ["GDPR"]
    })
    
    return manager


# Test Data Fixtures
@pytest.fixture
def sample_text_with_pii() -> str:
    """Sample text containing PII for testing."""
    return """
    John Smith is a patient at Metro Hospital. His SSN is 123-45-6789 and his email 
    is john.smith@email.com. He can be reached at (555) 123-4567. His address is 
    123 Main Street, New York, NY 10001. His credit card number is 4532-1234-5678-9012.
    """


@pytest.fixture
def sample_text_no_pii() -> str:
    """Sample text without PII for testing."""
    return "This is a sample document with no personally identifiable information."


@pytest.fixture
def sample_medical_text() -> str:
    """Sample medical text with PII."""
    return """
    Patient: Jane Doe
    MRN: 123456789
    DOB: 01/15/1985
    Diagnosis: Type 2 Diabetes
    Medication: Metformin 500mg
    Treatment: Lifestyle modification and medication management
    """


@pytest.fixture
def sample_financial_text() -> str:
    """Sample financial text with PII."""
    return """
    Account Holder: Robert Johnson
    Account Number: 1234567890
    Routing Number: 021000021
    Card Number: 4111-1111-1111-1111
    CVV: 123
    Expiry: 12/25
    """


# File Fixtures
@pytest.fixture
def temp_directory() -> Generator[Path, None, None]:
    """Create temporary directory for test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def sample_pdf_file(temp_directory) -> Path:
    """Create sample PDF file for testing."""
    pdf_path = temp_directory / "sample.pdf"
    
    # Create a simple PDF using reportlab
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        
        c = canvas.Canvas(str(pdf_path), pagesize=letter)
        c.drawString(100, 750, "Sample PDF Document")
        c.drawString(100, 700, "Name: John Smith")
        c.drawString(100, 650, "Email: john.smith@email.com")
        c.drawString(100, 600, "Phone: (555) 123-4567")
        c.save()
        
    except ImportError:
        # Fallback: create dummy PDF file
        pdf_path.write_bytes(b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n")
    
    return pdf_path


@pytest.fixture
def sample_image_file(temp_directory) -> Path:
    """Create sample image file for testing."""
    image_path = temp_directory / "sample.png"
    
    try:
        from PIL import Image, ImageDraw, ImageFont
        
        # Create a simple image with text
        img = Image.new('RGB', (800, 600), color='white')
        draw = ImageDraw.Draw(img)
        
        # Add some text that contains PII
        try:
            font = ImageFont.truetype("arial.ttf", 24)
        except OSError:
            font = ImageFont.load_default()
        
        draw.text((50, 50), "Name: John Smith", fill='black', font=font)
        draw.text((50, 100), "Email: john.smith@email.com", fill='black', font=font)
        draw.text((50, 150), "Phone: (555) 123-4567", fill='black', font=font)
        
        img.save(image_path)
        
    except ImportError:
        # Fallback: create dummy image file
        image_path.write_bytes(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01')
    
    return image_path


# Configuration Fixtures
@pytest.fixture
def test_settings():
    """Test application settings."""
    return {
        "environment": "test",
        "debug": True,
        "database_url": TEST_DATABASE_URL,
        "redis_url": TEST_REDIS_URL,
        "secret_key": "test-secret-key",
        "log_level": "DEBUG"
    }


@pytest.fixture
def test_policy_config():
    """Test policy configuration."""
    return {
        "gdpr_policy": {
            "enabled": True,
            "strict_mode": False,
            "retention_period": 30
        },
        "hipaa_policy": {
            "enabled": True,
            "safe_harbor": True,
            "audit_required": True
        },
        "custom_entities": [
            "CUSTOM_ID",
            "EMPLOYEE_ID"
        ]
    }


# Performance Testing Fixtures
@pytest.fixture
def performance_test_data():
    """Generate performance test data."""
    return {
        "small_document": "John Smith" * 10,
        "medium_document": "John Smith john.smith@email.com (555) 123-4567" * 100,
        "large_document": "This is a large document with PII. " * 1000 + "John Smith",
        "concurrent_requests": 10,
        "load_test_duration": 30
    }


# Security Testing Fixtures
@pytest.fixture
def security_test_payloads():
    """Security test payloads for injection testing."""
    return {
        "sql_injection": [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'/*",
            "' UNION SELECT * FROM users --"
        ],
        "xss_payloads": [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd"
        ]
    }


# Compliance Testing Fixtures
@pytest.fixture
def gdpr_test_scenarios():
    """GDPR compliance test scenarios."""
    return {
        "data_subject_requests": [
            {"type": "access", "user_id": "test-user-1"},
            {"type": "rectification", "user_id": "test-user-2"},
            {"type": "erasure", "user_id": "test-user-3"},
            {"type": "portability", "user_id": "test-user-4"}
        ],
        "consent_scenarios": [
            {"consent_given": True, "purpose": "processing"},
            {"consent_given": False, "purpose": "marketing"},
            {"consent_withdrawn": True, "purpose": "analytics"}
        ],
        "breach_scenarios": [
            {"severity": "high", "affected_records": 1000},
            {"severity": "medium", "affected_records": 100},
            {"severity": "low", "affected_records": 10}
        ]
    }


@pytest.fixture
def hipaa_test_scenarios():
    """HIPAA compliance test scenarios."""
    return {
        "phi_types": [
            "NAME", "ADDRESS", "BIRTH_DATE", "PHONE_NUMBER",
            "EMAIL", "SSN", "MRN", "ACCOUNT_NUMBER"
        ],
        "minimum_necessary": [
            {"role": "physician", "access_level": "full"},
            {"role": "nurse", "access_level": "limited"},
            {"role": "administrative", "access_level": "minimal"}
        ],
        "audit_events": [
            {"event": "phi_access", "user": "physician1"},
            {"event": "phi_modification", "user": "nurse1"},
            {"event": "unauthorized_access", "user": "unknown"}
        ]
    }


# Async Test Utilities
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def async_mock_services():
    """Async mock services."""
    return {
        "pii_detector": AsyncMock(),
        "redaction_engine": AsyncMock(),
        "policy_manager": AsyncMock(),
        "audit_logger": AsyncMock()
    }


# Cleanup Fixtures
@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Cleanup test files after each test."""
    yield
    
    # Cleanup temporary files
    test_files = [
        "test.db",
        "test.db-journal",
        "test_upload.txt",
        "test_output.pdf"
    ]
    
    for file_name in test_files:
        file_path = Path(file_name)
        if file_path.exists():
            file_path.unlink()


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables after each test."""
    original_env = os.environ.copy()
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


# Test Markers and Categories
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "api: API endpoint tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "compliance: Compliance tests")
    config.addinivalue_line("markers", "slow: Slow running tests")
    config.addinivalue_line("markers", "requires_models: Tests requiring AI models")
    config.addinivalue_line("markers", "requires_database: Tests requiring database")
    config.addinivalue_line("markers", "requires_redis: Tests requiring Redis")


# Test Data Generators
class TestDataGenerator:
    """Generate test data for various scenarios."""
    
    @staticmethod
    def generate_pii_text(entity_count: int = 5) -> str:
        """Generate text with specified number of PII entities."""
        entities = [
            "John Smith", "jane.doe@email.com", "(555) 123-4567",
            "123-45-6789", "123 Main Street", "New York, NY 10001",
            "4111-1111-1111-1111", "DOB: 01/15/1990"
        ]
        
        base_text = "This is a sample document containing personal information. "
        pii_text = " ".join(entities[:entity_count])
        
        return base_text + pii_text
    
    @staticmethod
    def generate_users(count: int = 10) -> List[Dict]:
        """Generate test user data."""
        users = []
        for i in range(count):
            users.append({
                "user_id": str(uuid.uuid4()),
                "username": f"testuser{i}",
                "email": f"user{i}@example.com",
                "full_name": f"Test User {i}",
                "role": UserRole.USER,
                "status": AccountStatus.ACTIVE
            })
        return users
    
    @staticmethod
    def generate_documents(count: int = 5) -> List[Dict]:
        """Generate test document data."""
        documents = []
        for i in range(count):
            documents.append({
                "document_id": str(uuid.uuid4()),
                "filename": f"test_document_{i}.pdf",
                "content_type": "application/pdf",
                "size": 1024 * (i + 1),
                "upload_date": datetime.utcnow() - timedelta(days=i)
            })
        return documents


@pytest.fixture
def test_data_generator():
    """Test data generator fixture."""
    return TestDataGenerator()


# Performance Measurement
@pytest.fixture
def performance_monitor():
    """Performance monitoring fixture."""
    import time
    import psutil
    
    class PerformanceMonitor:
        def __init__(self):
            self.start_time = None
            self.start_memory = None
            
        def start(self):
            self.start_time = time.time()
            self.start_memory = psutil.Process().memory_info().rss
            
        def stop(self):
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss
            
            return {
                "execution_time": end_time - self.start_time,
                "memory_used": end_memory - self.start_memory,
                "peak_memory": psutil.Process().memory_info().rss
            }
    
    return PerformanceMonitor()


# Error Simulation
@pytest.fixture
def error_simulator():
    """Simulate various error conditions for testing."""
    class ErrorSimulator:
        @staticmethod
        def database_error():
            return Exception("Database connection failed")
        
        @staticmethod
        def redis_error():
            return ConnectionError("Redis server unavailable")
        
        @staticmethod
        def model_loading_error():
            return RuntimeError("Failed to load AI model")
        
        @staticmethod
        def file_processing_error():
            return IOError("File processing failed")
        
        @staticmethod
        def authentication_error():
            return PermissionError("Authentication failed")
    
    return ErrorSimulator()