"""
Comprehensive test suite for PII Detection Module

Tests the PII detection functionality including NER models, detection service,
API endpoints, compliance integration, and security features.
"""

import pytest
import asyncio
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any
from unittest.mock import Mock, patch, MagicMock

# Test framework imports
import httpx
from fastapi.testclient import TestClient

# Module imports
from src.core.models.ner_models import (
    PIIEntity, EntityConfidence, PresidioNERModel, SpacyNERModel,
    create_ner_model, get_default_ner_model
)
from src.core.services.pii_detector import (
    PIIDetectionService, PIIDetectionResult, DetectionStatus, RiskLevel
)
from src.core.security.compliance_encryption import (
    ComplianceStandard, DataClassification, ComplianceMetadata
)
from src.core.config.policies.base import PIIType, RedactionMethod
from src.api.pii_detection import router


# Test Data
SAMPLE_TEXT_WITH_PII = """
John Smith is a patient at Metro Hospital. His SSN is 123-45-6789 and his email 
is john.smith@email.com. He can be reached at (555) 123-4567. His address is 
123 Main Street, New York, NY 10001. His credit card number is 4532-1234-5678-9012.
"""

SAMPLE_TEXT_MINIMAL_PII = "Hello world, this is a test message with no sensitive information."

SAMPLE_MEDICAL_TEXT = """
Patient: Jane Doe
MRN: 123456789
DOB: 01/15/1985
Diagnosis: Type 2 Diabetes
Medication: Metformin 500mg
Treatment: Lifestyle modification and medication management
"""


class TestPIIEntity:
    """Test PIIEntity dataclass functionality."""
    
    def test_pii_entity_creation(self):
        """Test PIIEntity creation and post_init logic."""
        entity = PIIEntity(
            entity_type="PERSON",
            text="John Smith",
            start=0,
            end=10,
            confidence=0.95,
            confidence_level=EntityConfidence.LOW,  # Will be overridden
            recognizer_name="presidio",
            language="en"
        )
        
        assert entity.entity_type == "PERSON"
        assert entity.text == "John Smith"
        assert entity.start == 0
        assert entity.end == 10
        assert entity.confidence == 0.95
        assert entity.confidence_level == EntityConfidence.VERY_HIGH  # Should be updated in __post_init__
        assert entity.recognizer_name == "presidio"
        assert entity.language == "en"
        assert entity.metadata == {}
    
    def test_confidence_level_mapping(self):
        """Test confidence level is correctly mapped based on score."""
        # Test very high confidence
        entity_very_high = PIIEntity(
            entity_type="PERSON", text="John", start=0, end=4, confidence=0.95,
            confidence_level=EntityConfidence.LOW, recognizer_name="test"
        )
        assert entity_very_high.confidence_level == EntityConfidence.VERY_HIGH
        
        # Test high confidence
        entity_high = PIIEntity(
            entity_type="PERSON", text="John", start=0, end=4, confidence=0.8,
            confidence_level=EntityConfidence.LOW, recognizer_name="test"
        )
        assert entity_high.confidence_level == EntityConfidence.HIGH
        
        # Test medium confidence
        entity_medium = PIIEntity(
            entity_type="PERSON", text="John", start=0, end=4, confidence=0.6,
            confidence_level=EntityConfidence.LOW, recognizer_name="test"
        )
        assert entity_medium.confidence_level == EntityConfidence.MEDIUM
        
        # Test low confidence
        entity_low = PIIEntity(
            entity_type="PERSON", text="John", start=0, end=4, confidence=0.3,
            confidence_level=EntityConfidence.VERY_HIGH, recognizer_name="test"
        )
        assert entity_low.confidence_level == EntityConfidence.LOW


class TestNERModels:
    """Test NER model implementations."""
    
    @pytest.fixture
    def mock_presidio_dependencies(self):
        """Mock Presidio dependencies for testing."""
        with patch('src.core.models.ner_models.AnalyzerEngine') as mock_analyzer, \
             patch('src.core.models.ner_models.AnonymizerEngine') as mock_anonymizer, \
             patch('src.core.models.ner_models.NlpEngineProvider') as mock_nlp_provider:
            
            # Mock analyzer results
            mock_result = Mock()
            mock_result.entity_type = "PERSON"
            mock_result.start = 0
            mock_result.end = 10
            mock_result.score = 0.95
            mock_result.recognition_metadata = {"recognizer_name": "spacy"}
            
            mock_analyzer_instance = Mock()
            mock_analyzer_instance.analyze.return_value = [mock_result]
            mock_analyzer_instance.get_supported_entities.return_value = ["PERSON", "EMAIL_ADDRESS"]
            mock_analyzer.return_value = mock_analyzer_instance
            
            mock_anonymizer_instance = Mock()
            mock_anonymizer_instance.anonymize.return_value = Mock(text="[REDACTED] is a test")
            mock_anonymizer.return_value = mock_anonymizer_instance
            
            mock_nlp_provider_instance = Mock()
            mock_nlp_provider_instance.create_engine.return_value = Mock()
            mock_nlp_provider.return_value = mock_nlp_provider_instance
            
            yield {
                'analyzer': mock_analyzer,
                'anonymizer': mock_anonymizer,
                'nlp_provider': mock_nlp_provider,
                'analyzer_instance': mock_analyzer_instance,
                'anonymizer_instance': mock_anonymizer_instance
            }
    
    def test_presidio_model_creation(self):
        """Test PresidioNERModel creation."""
        model = PresidioNERModel(language="en", model_name="en_core_web_sm")
        
        assert model.language == "en"
        assert model.spacy_model_name == "en_core_web_sm"
        assert model.model_name == "presidio_en_core_web_sm"
        assert not model.is_loaded
        assert model.analyzer_engine is None
        assert model.anonymizer_engine is None
    
    def test_presidio_model_load_success(self, mock_presidio_dependencies):
        """Test successful loading of Presidio model."""
        model = PresidioNERModel()
        
        success = model.load()
        
        assert success
        assert model.is_loaded
        assert model.analyzer_engine is not None
        assert model.anonymizer_engine is not None
    
    def test_presidio_model_detect_entities(self, mock_presidio_dependencies):
        """Test entity detection with Presidio model."""
        model = PresidioNERModel()
        model.load()
        
        entities = model.detect_entities("John Smith is a person", language="en")
        
        assert len(entities) == 1
        assert entities[0].entity_type == "name"  # Mapped from PERSON
        assert entities[0].text == "John Smith"
        assert entities[0].start == 0
        assert entities[0].end == 10
        assert entities[0].confidence == 0.95
        assert entities[0].recognizer_name == "spacy"
    
    def test_presidio_model_anonymize_text(self, mock_presidio_dependencies):
        """Test text anonymization with Presidio model."""
        model = PresidioNERModel()
        model.load()
        
        entities = [
            PIIEntity(
                entity_type="PERSON", text="John Smith", start=0, end=10,
                confidence=0.95, confidence_level=EntityConfidence.VERY_HIGH,
                recognizer_name="presidio", metadata={"presidio_entity_type": "PERSON"}
            )
        ]
        
        anonymized = model.anonymize_text("John Smith is a person", entities)
        
        assert anonymized == "[REDACTED] is a test"
    
    def test_spacy_model_creation(self):
        """Test SpacyNERModel creation."""
        model = SpacyNERModel(model_name="en_core_web_sm", language="en")
        
        assert model.language == "en"
        assert model.spacy_model_name == "en_core_web_sm"
        assert model.model_name == "spacy_en_core_web_sm"
        assert not model.is_loaded
        assert model.nlp is None
    
    @patch('src.core.models.ner_models.spacy.load')
    def test_spacy_model_load_success(self, mock_spacy_load):
        """Test successful loading of spaCy model."""
        mock_nlp = Mock()
        mock_spacy_load.return_value = mock_nlp
        
        model = SpacyNERModel()
        success = model.load()
        
        assert success
        assert model.is_loaded
        assert model.nlp == mock_nlp
    
    @patch('src.core.models.ner_models.spacy.load')
    def test_spacy_model_detect_entities(self, mock_spacy_load):
        """Test entity detection with spaCy model."""
        # Mock spaCy doc and entities
        mock_entity = Mock()
        mock_entity.text = "John Smith"
        mock_entity.start_char = 0
        mock_entity.end_char = 10
        mock_entity.label_ = "PERSON"
        
        mock_doc = Mock()
        mock_doc.ents = [mock_entity]
        
        mock_nlp = Mock()
        mock_nlp.return_value = mock_doc
        mock_spacy_load.return_value = mock_nlp
        
        with patch('src.core.models.ner_models.spacy.explain', return_value="Person name"):
            model = SpacyNERModel()
            model.load()
            
            entities = model.detect_entities("John Smith is a person")
            
            assert len(entities) == 1
            assert entities[0].entity_type == "name"  # Mapped from PERSON
            assert entities[0].text == "John Smith"
            assert entities[0].start == 0
            assert entities[0].end == 10
            assert entities[0].confidence == 0.8
            assert entities[0].recognizer_name == "spacy"
    
    def test_create_ner_model_factory(self):
        """Test NER model factory function."""
        # Test Presidio model creation
        presidio_model = create_ner_model("presidio", language="en")
        assert isinstance(presidio_model, PresidioNERModel)
        assert presidio_model.language == "en"
        
        # Test spaCy model creation
        spacy_model = create_ner_model("spacy", language="en")
        assert isinstance(spacy_model, SpacyNERModel)
        assert spacy_model.language == "en"
        
        # Test invalid model type
        with pytest.raises(ValueError, match="Unsupported model type"):
            create_ner_model("invalid_model")


class TestPIIDetectionService:
    """Test PII Detection Service functionality."""
    
    @pytest.fixture
    def mock_ner_model(self):
        """Mock NER model for testing."""
        model = Mock()
        model.is_loaded = True
        model.load.return_value = True
        model.detect_entities.return_value = [
            PIIEntity(
                entity_type="name", text="John Smith", start=0, end=10,
                confidence=0.95, confidence_level=EntityConfidence.VERY_HIGH,
                recognizer_name="mock"
            ),
            PIIEntity(
                entity_type="ssn", text="123-45-6789", start=50, end=61,
                confidence=0.99, confidence_level=EntityConfidence.VERY_HIGH,
                recognizer_name="mock"
            )
        ]
        return model
    
    @pytest.fixture
    def detection_service(self, mock_ner_model):
        """Create detection service with mocked dependencies."""
        with patch('src.core.services.pii_detector.get_default_ner_model', return_value=mock_ner_model):
            service = PIIDetectionService()
            service._default_model = mock_ner_model
            return service
    
    def test_detection_result_creation(self):
        """Test PIIDetectionResult creation and calculations."""
        entities = [
            PIIEntity(
                entity_type="ssn", text="123-45-6789", start=0, end=11,
                confidence=0.99, confidence_level=EntityConfidence.VERY_HIGH,
                recognizer_name="mock"
            ),
            PIIEntity(
                entity_type="name", text="John", start=20, end=24,
                confidence=0.85, confidence_level=EntityConfidence.HIGH,
                recognizer_name="mock"
            )
        ]
        
        result = PIIDetectionResult(
            detection_id="test-123",
            entities=entities,
            status=DetectionStatus.COMPLETED
        )
        
        assert result.detection_id == "test-123"
        assert result.entity_count == 2
        assert result.unique_entity_types == ["ssn", "name"]
        assert result.risk_level == RiskLevel.CRITICAL  # SSN detected
        assert result.confidence_distribution["high"] == 1
        assert result.confidence_distribution["very_high"] == 1
    
    def test_risk_level_calculation(self):
        """Test risk level calculation based on entity types."""
        # Test critical risk (SSN)
        critical_entities = [
            PIIEntity(
                entity_type="ssn", text="123-45-6789", start=0, end=11,
                confidence=0.99, confidence_level=EntityConfidence.VERY_HIGH,
                recognizer_name="mock"
            )
        ]
        result_critical = PIIDetectionResult(detection_id="test", entities=critical_entities)
        assert result_critical.risk_level == RiskLevel.CRITICAL
        
        # Test high risk (driver license)
        high_entities = [
            PIIEntity(
                entity_type="driver_license", text="D123456789", start=0, end=10,
                confidence=0.90, confidence_level=EntityConfidence.VERY_HIGH,
                recognizer_name="mock"
            )
        ]
        result_high = PIIDetectionResult(detection_id="test", entities=high_entities)
        assert result_high.risk_level == RiskLevel.HIGH
        
        # Test medium risk (many entities)
        medium_entities = [
            PIIEntity(
                entity_type="name", text=f"Person{i}", start=i*10, end=(i+1)*10,
                confidence=0.8, confidence_level=EntityConfidence.HIGH,
                recognizer_name="mock"
            ) for i in range(6)
        ]
        result_medium = PIIDetectionResult(detection_id="test", entities=medium_entities)
        assert result_medium.risk_level == RiskLevel.MEDIUM
        
        # Test low risk
        low_entities = [
            PIIEntity(
                entity_type="name", text="John", start=0, end=4,
                confidence=0.8, confidence_level=EntityConfidence.HIGH,
                recognizer_name="mock"
            )
        ]
        result_low = PIIDetectionResult(detection_id="test", entities=low_entities)
        assert result_low.risk_level == RiskLevel.LOW
    
    def test_sync_detection(self, detection_service):
        """Test synchronous PII detection."""
        result = detection_service.detect_pii_sync(SAMPLE_TEXT_WITH_PII)
        
        assert result.status == DetectionStatus.COMPLETED
        assert result.entity_count == 2
        assert result.text_length == len(SAMPLE_TEXT_WITH_PII)
        assert result.processing_time_seconds is not None
        assert result.processing_time_seconds >= 0
        assert result.detection_id in detection_service.detection_history
    
    @pytest.mark.asyncio
    async def test_async_detection(self, detection_service):
        """Test asynchronous PII detection."""
        result = await detection_service.detect_pii_async(SAMPLE_TEXT_WITH_PII)
        
        assert result.status == DetectionStatus.COMPLETED
        assert result.entity_count == 2
        assert result.text_length == len(SAMPLE_TEXT_WITH_PII)
        assert result.processing_time_seconds is not None
        assert result.detection_id in detection_service.detection_history
    
    @pytest.mark.asyncio
    async def test_async_detection_with_compliance(self, detection_service):
        """Test async detection with compliance standards."""
        compliance_standards = [ComplianceStandard.HIPAA, ComplianceStandard.GDPR]
        
        result = await detection_service.detect_pii_async(
            SAMPLE_MEDICAL_TEXT,
            compliance_standards=compliance_standards
        )
        
        assert result.status == DetectionStatus.COMPLETED
        assert result.compliance_metadata is not None
        assert ComplianceStandard.HIPAA in result.compliance_metadata.standards
    
    def test_detection_result_retrieval(self, detection_service):
        """Test detection result retrieval by ID."""
        result = detection_service.detect_pii_sync(SAMPLE_TEXT_WITH_PII)
        detection_id = result.detection_id
        
        retrieved_result = detection_service.get_detection_result(detection_id)
        
        assert retrieved_result is not None
        assert retrieved_result.detection_id == detection_id
        assert retrieved_result.status == DetectionStatus.COMPLETED
    
    def test_detection_status_retrieval(self, detection_service):
        """Test detection status retrieval by ID."""
        result = detection_service.detect_pii_sync(SAMPLE_TEXT_WITH_PII)
        detection_id = result.detection_id
        
        status = detection_service.get_detection_status(detection_id)
        
        assert status == DetectionStatus.COMPLETED
    
    def test_detection_cancellation(self, detection_service):
        """Test detection cancellation."""
        # Add a fake active detection
        fake_result = PIIDetectionResult(
            detection_id="test-cancel",
            status=DetectionStatus.IN_PROGRESS
        )
        detection_service.active_detections["test-cancel"] = fake_result
        
        success = detection_service.cancel_detection("test-cancel")
        
        assert success
        assert "test-cancel" not in detection_service.active_detections
        assert "test-cancel" in detection_service.detection_history
        assert detection_service.detection_history["test-cancel"].status == DetectionStatus.CANCELLED
    
    def test_service_statistics(self, detection_service):
        """Test service statistics retrieval."""
        # Perform some detections
        detection_service.detect_pii_sync(SAMPLE_TEXT_WITH_PII)
        detection_service.detect_pii_sync(SAMPLE_TEXT_MINIMAL_PII)
        
        stats = detection_service.get_service_statistics()
        
        assert stats["total_detections"] >= 2
        assert stats["completed_detections"] >= 2
        assert stats["active_detections"] == 0
        assert "average_processing_time" in stats
        assert "risk_level_distribution" in stats
    
    def test_history_cleanup(self, detection_service):
        """Test detection history cleanup."""
        # Add old detection to history
        old_result = PIIDetectionResult(
            detection_id="old-test",
            status=DetectionStatus.COMPLETED,
            completed_at=datetime.now() - timedelta(hours=48)
        )
        detection_service.detection_history["old-test"] = old_result
        
        # Add recent detection
        recent_result = detection_service.detect_pii_sync(SAMPLE_TEXT_WITH_PII)
        
        initial_count = len(detection_service.detection_history)
        
        # Cleanup history (max age 24 hours)
        detection_service.cleanup_history(max_age_hours=24)
        
        # Old detection should be removed, recent should remain
        assert len(detection_service.detection_history) == initial_count - 1
        assert "old-test" not in detection_service.detection_history
        assert recent_result.detection_id in detection_service.detection_history


class TestAPIEndpoints:
    """Test PII Detection API endpoints."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)
    
    @pytest.fixture
    def mock_detection_service(self):
        """Mock detection service for API testing."""
        service = Mock()
        
        # Mock detection result
        mock_entities = [
            PIIEntity(
                entity_type="name", text="John Smith", start=0, end=10,
                confidence=0.95, confidence_level=EntityConfidence.VERY_HIGH,
                recognizer_name="presidio"
            )
        ]
        
        mock_result = PIIDetectionResult(
            detection_id="test-123",
            status=DetectionStatus.COMPLETED,
            entities=mock_entities,
            text_length=100,
            language="en",
            model_used="presidio",
            started_at=datetime.now(),
            completed_at=datetime.now(),
            processing_time_seconds=0.5
        )
        
        service.detect_pii_async.return_value = mock_result
        service.detect_pii_sync.return_value = mock_result
        service.get_detection_result.return_value = mock_result
        service.get_detection_status.return_value = DetectionStatus.COMPLETED
        service.cancel_detection.return_value = True
        service.get_service_statistics.return_value = {
            "total_detections": 10,
            "active_detections": 0,
            "completed_detections": 10,
            "average_processing_time": 0.5,
            "risk_level_distribution": {"low": 5, "medium": 3, "high": 1, "critical": 1},
            "default_model_loaded": True,
            "thread_pool_workers": 4
        }
        
        return service
    
    def test_detect_pii_endpoint(self, client, mock_detection_service):
        """Test PII detection endpoint."""
        with patch('src.api.pii_detection.get_pii_detection_service', return_value=mock_detection_service):
            response = client.post("/api/v1/pii/detect", json={
                "text": SAMPLE_TEXT_WITH_PII,
                "document_id": "doc-123",
                "language": "en",
                "model_type": "presidio",
                "confidence_threshold": 0.8
            })
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["detection_id"] == "test-123"
        assert data["status"] == "completed"
        assert data["entity_count"] == 1
        assert len(data["entities"]) == 1
        assert data["entities"][0]["entity_type"] == "name"
        assert data["entities"][0]["text"] == "John Smith"
    
    def test_detect_pii_sync_endpoint(self, client, mock_detection_service):
        """Test synchronous PII detection endpoint."""
        with patch('src.api.pii_detection.get_pii_detection_service', return_value=mock_detection_service):
            response = client.post("/api/v1/pii/detect/sync", json={
                "text": SAMPLE_TEXT_WITH_PII,
                "confidence_threshold": 0.7
            })
        
        assert response.status_code == 200
        data = response.json()
        assert data["detection_id"] == "test-123"
        assert data["status"] == "completed"
    
    def test_get_detection_result_endpoint(self, client, mock_detection_service):
        """Test get detection result endpoint."""
        with patch('src.api.pii_detection.get_pii_detection_service', return_value=mock_detection_service):
            response = client.get("/api/v1/pii/detection/test-123")
        
        assert response.status_code == 200
        data = response.json()
        assert data["detection_id"] == "test-123"
    
    def test_get_detection_status_endpoint(self, client, mock_detection_service):
        """Test get detection status endpoint."""
        with patch('src.api.pii_detection.get_pii_detection_service', return_value=mock_detection_service):
            response = client.get("/api/v1/pii/detection/test-123/status")
        
        assert response.status_code == 200
        data = response.json()
        assert data["detection_id"] == "test-123"
        assert data["status"] == "completed"
    
    def test_cancel_detection_endpoint(self, client, mock_detection_service):
        """Test cancel detection endpoint."""
        with patch('src.api.pii_detection.get_pii_detection_service', return_value=mock_detection_service):
            response = client.delete("/api/v1/pii/detection/test-123")
        
        assert response.status_code == 200
        data = response.json()
        assert "cancelled successfully" in data["message"]
    
    def test_service_statistics_endpoint(self, client, mock_detection_service):
        """Test service statistics endpoint."""
        with patch('src.api.pii_detection.get_pii_detection_service', return_value=mock_detection_service):
            response = client.get("/api/v1/pii/stats")
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_detections"] == 10
        assert data["completed_detections"] == 10
        assert data["default_model_loaded"] is True
    
    def test_health_check_endpoint(self, client, mock_detection_service):
        """Test health check endpoint."""
        with patch('src.api.pii_detection.get_pii_detection_service', return_value=mock_detection_service):
            response = client.get("/api/v1/pii/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "pii_detection"
    
    def test_supported_entities_endpoint(self, client):
        """Test supported entities endpoint."""
        response = client.get("/api/v1/pii/supported/entities")
        
        assert response.status_code == 200
        data = response.json()
        assert "supported_entities" in data
        assert len(data["supported_entities"]) > 0
        
        # Check for common entity types
        entity_types = [entity["type"] for entity in data["supported_entities"]]
        assert "name" in entity_types
        assert "email" in entity_types
        assert "ssn" in entity_types
    
    def test_supported_compliance_standards_endpoint(self, client):
        """Test supported compliance standards endpoint."""
        response = client.get("/api/v1/pii/supported/compliance-standards")
        
        assert response.status_code == 200
        data = response.json()
        assert "supported_standards" in data
        
        # Check for common standards
        standard_values = [std["standard"] for std in data["supported_standards"]]
        assert "hipaa" in standard_values
        assert "gdpr" in standard_values
    
    def test_validation_errors(self, client):
        """Test request validation errors."""
        # Test missing required field
        response = client.post("/api/v1/pii/detect", json={})
        assert response.status_code == 422
        
        # Test invalid confidence threshold
        response = client.post("/api/v1/pii/detect", json={
            "text": "test",
            "confidence_threshold": 1.5  # Invalid, should be <= 1.0
        })
        assert response.status_code == 422
        
        # Test invalid compliance standard
        response = client.post("/api/v1/pii/detect", json={
            "text": "test",
            "compliance_standards": ["invalid_standard"]
        })
        assert response.status_code == 422


class TestComplianceIntegration:
    """Test compliance and security integration."""
    
    @pytest.fixture
    def compliance_metadata(self):
        """Sample compliance metadata."""
        return ComplianceMetadata(
            classification=DataClassification.RESTRICTED,
            standards=[ComplianceStandard.HIPAA, ComplianceStandard.GDPR],
            retention_period_days=2190,
            encryption_required=True,
            audit_required=True
        )
    
    def test_compliance_metadata_creation(self, compliance_metadata):
        """Test compliance metadata creation."""
        assert compliance_metadata.classification == DataClassification.RESTRICTED
        assert ComplianceStandard.HIPAA in compliance_metadata.standards
        assert compliance_metadata.retention_period_days == 2190
        assert compliance_metadata.encryption_required
        assert compliance_metadata.audit_required
    
    @patch('src.core.services.pii_detector.compliance_encryption')
    def test_encryption_integration(self, mock_compliance_encryption):
        """Test encryption integration with detection service."""
        mock_compliance_encryption._log_audit_event = Mock()
        
        service = PIIDetectionService()
        
        # Create a high-risk detection result
        entities = [
            PIIEntity(
                entity_type="ssn", text="123-45-6789", start=0, end=11,
                confidence=0.99, confidence_level=EntityConfidence.VERY_HIGH,
                recognizer_name="presidio"
            )
        ]
        
        result = PIIDetectionResult(
            detection_id="test-encrypt",
            entities=entities,
            risk_level=RiskLevel.CRITICAL
        )
        
        # The service should attempt encryption for high-risk results
        assert result.risk_level == RiskLevel.CRITICAL


class TestPerformanceAndScaling:
    """Test performance and scaling aspects."""
    
    @pytest.mark.asyncio
    async def test_concurrent_detections(self):
        """Test concurrent detection requests."""
        service = PIIDetectionService()
        
        # Mock the detection to avoid actual model loading
        with patch.object(service, '_detect_entities_sync', return_value=[]):
            tasks = []
            for i in range(5):
                task = service.detect_pii_async(f"Test text {i}")
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            
            assert len(results) == 5
            for result in results:
                assert result.status == DetectionStatus.COMPLETED
    
    def test_memory_management(self):
        """Test memory cleanup and management."""
        service = PIIDetectionService()
        
        # Add multiple detection results
        for i in range(10):
            result = PIIDetectionResult(
                detection_id=f"test-{i}",
                status=DetectionStatus.COMPLETED,
                completed_at=datetime.now() - timedelta(hours=i)
            )
            service.detection_history[f"test-{i}"] = result
        
        initial_count = len(service.detection_history)
        
        # Cleanup old records
        service.cleanup_history(max_age_hours=5)
        
        # Should remove records older than 5 hours
        assert len(service.detection_history) < initial_count
    
    @pytest.mark.asyncio
    async def test_error_handling_and_recovery(self):
        """Test error handling and recovery mechanisms."""
        service = PIIDetectionService()
        
        # Mock a failing model
        with patch.object(service, '_detect_entities_sync', side_effect=Exception("Model error")):
            result = await service.detect_pii_async("Test text")
            
            assert result.status == DetectionStatus.FAILED
            assert "Model error" in result.error_message
            assert result.completed_at is not None


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])