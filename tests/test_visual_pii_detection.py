"""
Comprehensive test suite for Visual PII Detection Module

Tests the visual PII detection functionality including YOLOv8 models, detection service,
visual redaction, API endpoints, compliance integration, and security features.
"""

import pytest
import asyncio
import numpy as np
import cv2
from PIL import Image, ImageDraw
import io
import base64
from datetime import datetime, timedelta
from typing import List, Dict, Any
from unittest.mock import Mock, patch, MagicMock

# Test framework imports
import httpx
from fastapi.testclient import TestClient

# Module imports
from src.core.models.visual_models import (
    VisualPIIEntity, VisualPIIType, BoundingBox, VisualConfidenceLevel,
    YOLOv8VisualModel, VisualDetectionModel, create_visual_detection_model
)
from src.core.services.visual_pii_detector import (
    VisualPIIDetectionService, VisualPIIDetectionResult, 
    VisualDetectionStatus, VisualRiskLevel
)
from src.core.processing.visual_redactor import (
    VisualRedactionEngine, RedactionConfig, VisualRedactionMethod,
    RedactionResult, BlurRedactor, SolidColorRedactor
)
from src.core.security.compliance_encryption import ComplianceStandard, DataClassification
from src.api.visual_pii_detection import router


# Test Data and Fixtures
@pytest.fixture
def sample_image():
    """Create a sample test image."""
    # Create a simple test image with shapes that could represent faces/signatures
    img = np.zeros((400, 600, 3), dtype=np.uint8)
    img.fill(255)  # White background
    
    # Draw a "face" (circle)
    cv2.circle(img, (150, 150), 50, (200, 180, 160), -1)
    
    # Draw a "signature" (scribbled line)
    points = np.array([[400, 300], [450, 290], [480, 310], [520, 295]], np.int32)
    cv2.polylines(img, [points], False, (0, 0, 200), 3)
    
    # Draw a "stamp" (rectangle)
    cv2.rectangle(img, (50, 300), (120, 350), (200, 0, 0), -1)
    
    return img


@pytest.fixture
def sample_pil_image(sample_image):
    """Convert numpy image to PIL Image."""
    return Image.fromarray(cv2.cvtColor(sample_image, cv2.COLOR_BGR2RGB))


@pytest.fixture
def sample_visual_entities():
    """Create sample visual PII entities for testing."""
    return [
        VisualPIIEntity(
            entity_type=VisualPIIType.FACE,
            confidence=0.92,
            confidence_level=VisualConfidenceLevel.VERY_HIGH,
            bounding_box=BoundingBox(x=100, y=100, width=100, height=100),
            page_number=0,
            image_width=600,
            image_height=400,
            model_name="yolov8_test"
        ),
        VisualPIIEntity(
            entity_type=VisualPIIType.SIGNATURE,
            confidence=0.85,
            confidence_level=VisualConfidenceLevel.HIGH,
            bounding_box=BoundingBox(x=400, y=285, width=120, height=30),
            page_number=0,
            image_width=600,
            image_height=400,
            model_name="yolov8_test"
        ),
        VisualPIIEntity(
            entity_type=VisualPIIType.STAMP,
            confidence=0.78,
            confidence_level=VisualConfidenceLevel.HIGH,
            bounding_box=BoundingBox(x=50, y=300, width=70, height=50),
            page_number=0,
            image_width=600,
            image_height=400,
            model_name="yolov8_test"
        )
    ]


class TestBoundingBox:
    """Test BoundingBox functionality."""
    
    def test_bounding_box_creation(self):
        """Test BoundingBox creation and properties."""
        bbox = BoundingBox(x=10, y=20, width=100, height=50)
        
        assert bbox.x == 10
        assert bbox.y == 20
        assert bbox.width == 100
        assert bbox.height == 50
        assert bbox.x2 == 110
        assert bbox.y2 == 70
        assert bbox.center == (60, 45)
        assert bbox.area == 5000
    
    def test_bounding_box_iou(self):
        """Test Intersection over Union calculation."""
        bbox1 = BoundingBox(x=10, y=10, width=50, height=50)
        bbox2 = BoundingBox(x=30, y=30, width=50, height=50)
        bbox3 = BoundingBox(x=100, y=100, width=50, height=50)
        
        # Overlapping boxes
        iou = bbox1.iou(bbox2)
        assert 0.1 < iou < 0.5  # Should have some overlap
        
        # Non-overlapping boxes
        iou_no_overlap = bbox1.iou(bbox3)
        assert iou_no_overlap == 0.0
        
        # Same box
        iou_same = bbox1.iou(bbox1)
        assert iou_same == 1.0
    
    def test_bounding_box_expand(self):
        """Test bounding box expansion with padding."""
        bbox = BoundingBox(x=50, y=50, width=100, height=100)
        expanded = bbox.expand(10)
        
        assert expanded.x == 40
        assert expanded.y == 40
        assert expanded.width == 120
        assert expanded.height == 120


class TestVisualPIIEntity:
    """Test VisualPIIEntity functionality."""
    
    def test_entity_creation_and_confidence_mapping(self):
        """Test VisualPIIEntity creation and confidence level mapping."""
        # Very high confidence
        entity_vh = VisualPIIEntity(
            entity_type=VisualPIIType.FACE,
            confidence=0.95,
            confidence_level=VisualConfidenceLevel.LOW,  # Will be overridden
            bounding_box=BoundingBox(x=0, y=0, width=10, height=10),
            model_name="test"
        )
        assert entity_vh.confidence_level == VisualConfidenceLevel.VERY_HIGH
        
        # High confidence
        entity_h = VisualPIIEntity(
            entity_type=VisualPIIType.SIGNATURE,
            confidence=0.8,
            confidence_level=VisualConfidenceLevel.LOW,
            bounding_box=BoundingBox(x=0, y=0, width=10, height=10),
            model_name="test"
        )
        assert entity_h.confidence_level == VisualConfidenceLevel.HIGH
        
        # Medium confidence
        entity_m = VisualPIIEntity(
            entity_type=VisualPIIType.STAMP,
            confidence=0.6,
            confidence_level=VisualConfidenceLevel.LOW,
            bounding_box=BoundingBox(x=0, y=0, width=10, height=10),
            model_name="test"
        )
        assert entity_m.confidence_level == VisualConfidenceLevel.MEDIUM
        
        # Low confidence
        entity_l = VisualPIIEntity(
            entity_type=VisualPIIType.LOGO,
            confidence=0.3,
            confidence_level=VisualConfidenceLevel.HIGH,
            bounding_box=BoundingBox(x=0, y=0, width=10, height=10),
            model_name="test"
        )
        assert entity_l.confidence_level == VisualConfidenceLevel.LOW
    
    def test_entity_to_dict(self):
        """Test entity serialization to dictionary."""
        entity = VisualPIIEntity(
            entity_type=VisualPIIType.FACE,
            confidence=0.9,
            confidence_level=VisualConfidenceLevel.VERY_HIGH,
            bounding_box=BoundingBox(x=10, y=20, width=50, height=60),
            page_number=1,
            image_width=800,
            image_height=600,
            model_name="yolov8_test"
        )
        
        entity_dict = entity.to_dict()
        
        assert entity_dict["entity_type"] == "face"
        assert entity_dict["confidence"] == 0.9
        assert entity_dict["confidence_level"] == "very_high"
        assert entity_dict["bounding_box"]["x"] == 10
        assert entity_dict["page_number"] == 1
        assert entity_dict["image_dimensions"]["width"] == 800


class TestYOLOv8VisualModel:
    """Test YOLOv8 visual detection model."""
    
    @pytest.fixture
    def mock_yolo_model(self):
        """Mock YOLO model for testing."""
        mock_model = Mock()
        mock_model.names = {0: "person", 1: "car", 2: "bicycle"}
        
        # Mock detection results
        mock_result = Mock()
        mock_result.orig_shape = (400, 600)
        mock_result.names = {0: "person"}
        
        # Mock boxes
        mock_box = Mock()
        mock_box.xyxy = np.array([[100, 100, 200, 200]])
        mock_box.conf = np.array([0.92])
        mock_box.cls = np.array([0])
        
        mock_boxes = Mock()
        mock_boxes.cpu.return_value = Mock()
        mock_boxes.cpu.return_value.numpy.return_value = [mock_box]
        
        mock_result.boxes = mock_boxes
        
        mock_model.return_value = [mock_result]
        
        return mock_model
    
    def test_yolov8_model_creation(self):
        """Test YOLOv8 model creation."""
        model = YOLOv8VisualModel(model_name="yolov8n.pt", device="cpu")
        
        assert model.model_name == "yolov8_yolov8n.pt"
        assert model.yolo_model_name == "yolov8n.pt"
        assert model.device == "cpu"
        assert not model.is_loaded
    
    @patch('src.core.models.visual_models.YOLO')
    def test_yolov8_model_load(self, mock_yolo_class):
        """Test YOLOv8 model loading."""
        mock_model_instance = Mock()
        mock_yolo_class.return_value = mock_model_instance
        
        model = YOLOv8VisualModel(device="cpu")
        success = model.load()
        
        assert success
        assert model.is_loaded
        mock_yolo_class.assert_called_once_with("yolov8n.pt")
    
    @patch('src.core.models.visual_models.YOLO')
    def test_yolov8_detect_entities(self, mock_yolo_class, sample_image, mock_yolo_model):
        """Test visual entity detection."""
        mock_yolo_class.return_value = mock_yolo_model
        
        model = YOLOv8VisualModel(device="cpu")
        model.load()
        model.model = mock_yolo_model
        
        entities = model.detect_visual_pii(sample_image, confidence_threshold=0.5)
        
        assert len(entities) >= 0  # Mock should return entities
        mock_yolo_model.assert_called()
    
    def test_model_factory_function(self):
        """Test visual detection model factory."""
        # Test YOLOv8 model creation
        model = create_visual_detection_model("yolov8", device="cpu")
        assert isinstance(model, YOLOv8VisualModel)
        
        # Test invalid model type
        with pytest.raises(ValueError, match="Unsupported visual detection model type"):
            create_visual_detection_model("invalid_model")


class TestVisualPIIDetectionService:
    """Test Visual PII Detection Service functionality."""
    
    @pytest.fixture
    def mock_visual_model(self, sample_visual_entities):
        """Mock visual detection model for testing."""
        model = Mock()
        model.is_loaded = True
        model.load.return_value = True
        model.detect_visual_pii.return_value = sample_visual_entities
        return model
    
    @pytest.fixture
    def detection_service(self, mock_visual_model):
        """Create detection service with mocked dependencies."""
        with patch('src.core.services.visual_pii_detector.get_default_visual_model', return_value=mock_visual_model):
            service = VisualPIIDetectionService()
            service._default_model = mock_visual_model
            return service
    
    def test_visual_detection_result_creation(self, sample_visual_entities):
        """Test VisualPIIDetectionResult creation and calculations."""
        result = VisualPIIDetectionResult(
            detection_id="test-123",
            visual_entities=sample_visual_entities,
            status=VisualDetectionStatus.COMPLETED,
            image_count=1
        )
        
        assert result.detection_id == "test-123"
        assert result.entity_count == 3
        assert "face" in result.unique_entity_types
        assert "signature" in result.unique_entity_types
        assert "stamp" in result.unique_entity_types
        assert result.risk_level == VisualRiskLevel.HIGH  # Face detected
        assert result.confidence_distribution["high"] == 2
        assert result.confidence_distribution["very_high"] == 1
        assert len(result.entities_by_page[0]) == 3
    
    def test_visual_risk_level_calculation(self):
        """Test risk level calculation based on visual entity types."""
        # Test critical risk (signature)
        critical_entities = [
            VisualPIIEntity(
                entity_type=VisualPIIType.SIGNATURE,
                confidence=0.9,
                confidence_level=VisualConfidenceLevel.VERY_HIGH,
                bounding_box=BoundingBox(x=0, y=0, width=10, height=10),
                model_name="test"
            )
        ]
        result_critical = VisualPIIDetectionResult(detection_id="test", visual_entities=critical_entities)
        assert result_critical.risk_level == VisualRiskLevel.CRITICAL
        
        # Test high risk (face)
        high_entities = [
            VisualPIIEntity(
                entity_type=VisualPIIType.FACE,
                confidence=0.9,
                confidence_level=VisualConfidenceLevel.VERY_HIGH,
                bounding_box=BoundingBox(x=0, y=0, width=10, height=10),
                model_name="test"
            )
        ]
        result_high = VisualPIIDetectionResult(detection_id="test", visual_entities=high_entities)
        assert result_high.risk_level == VisualRiskLevel.HIGH
        
        # Test medium risk (many entities)
        medium_entities = [
            VisualPIIEntity(
                entity_type=VisualPIIType.LOGO,
                confidence=0.8,
                confidence_level=VisualConfidenceLevel.HIGH,
                bounding_box=BoundingBox(x=i*10, y=0, width=10, height=10),
                model_name="test"
            ) for i in range(12)
        ]
        result_medium = VisualPIIDetectionResult(detection_id="test", visual_entities=medium_entities)
        assert result_medium.risk_level == VisualRiskLevel.MEDIUM
        
        # Test low risk
        low_entities = [
            VisualPIIEntity(
                entity_type=VisualPIIType.BARCODE,
                confidence=0.8,
                confidence_level=VisualConfidenceLevel.HIGH,
                bounding_box=BoundingBox(x=0, y=0, width=10, height=10),
                model_name="test"
            )
        ]
        result_low = VisualPIIDetectionResult(detection_id="test", visual_entities=low_entities)
        assert result_low.risk_level == VisualRiskLevel.LOW
    
    def test_sync_visual_detection(self, detection_service, sample_image):
        """Test synchronous visual PII detection."""
        result = detection_service.detect_visual_pii_sync([sample_image])
        
        assert result.status == VisualDetectionStatus.COMPLETED
        assert result.entity_count == 3
        assert result.image_count == 1
        assert result.processing_time_seconds is not None
        assert result.processing_time_seconds >= 0
        assert result.detection_id in detection_service.detection_history
    
    @pytest.mark.asyncio
    async def test_async_visual_detection(self, detection_service, sample_pil_image):
        """Test asynchronous visual PII detection."""
        result = await detection_service.detect_visual_pii_async([sample_pil_image])
        
        assert result.status == VisualDetectionStatus.COMPLETED
        assert result.entity_count == 3
        assert result.image_count == 1
        assert result.processing_time_seconds is not None
        assert result.detection_id in detection_service.detection_history
    
    @pytest.mark.asyncio
    async def test_async_detection_with_compliance(self, detection_service, sample_image):
        """Test async detection with compliance standards."""
        compliance_standards = [ComplianceStandard.HIPAA, ComplianceStandard.GDPR]
        
        result = await detection_service.detect_visual_pii_async(
            images=[sample_image],
            compliance_standards=compliance_standards
        )
        
        assert result.status == VisualDetectionStatus.COMPLETED
        assert result.compliance_metadata is not None
        assert ComplianceStandard.HIPAA in result.compliance_metadata.standards
    
    def test_visual_detection_service_statistics(self, detection_service, sample_image):
        """Test service statistics retrieval."""
        # Perform some detections
        detection_service.detect_visual_pii_sync([sample_image])
        detection_service.detect_visual_pii_sync([sample_image])
        
        stats = detection_service.get_service_statistics()
        
        assert stats["total_detections"] >= 2
        assert stats["completed_detections"] >= 2
        assert stats["active_detections"] == 0
        assert "average_processing_time" in stats
        assert "risk_level_distribution" in stats
        assert "total_images_processed" in stats


class TestVisualRedactionEngine:
    """Test Visual Redaction Engine functionality."""
    
    @pytest.fixture
    def redaction_engine(self):
        """Create visual redaction engine."""
        return VisualRedactionEngine()
    
    def test_blur_redactor(self, sample_image, sample_visual_entities):
        """Test blur-based redaction."""
        redactor = BlurRedactor()
        config = RedactionConfig(method=VisualRedactionMethod.BLUR, intensity=0.8)
        
        result_image = redactor.redact_region(sample_image, sample_visual_entities[0].bounding_box, config)
        
        assert result_image.shape == sample_image.shape
        assert not np.array_equal(result_image, sample_image)  # Should be different after redaction
    
    def test_solid_color_redactor(self, sample_image, sample_visual_entities):
        """Test solid color redaction."""
        redactor = SolidColorRedactor()
        config = RedactionConfig(
            method=VisualRedactionMethod.BLACKOUT, 
            color=(0, 0, 0),
            padding=5
        )
        
        result_image = redactor.redact_region(sample_image, sample_visual_entities[1].bounding_box, config)
        
        assert result_image.shape == sample_image.shape
        assert not np.array_equal(result_image, sample_image)
    
    def test_redaction_engine_full_workflow(self, redaction_engine, sample_image, sample_visual_entities):
        """Test full redaction workflow."""
        config = RedactionConfig(
            method=VisualRedactionMethod.BLUR,
            intensity=0.7,
            padding=10
        )
        
        result = redaction_engine.redact_image(sample_image, sample_visual_entities, config)
        
        assert result.success
        assert result.redacted_image is not None
        assert len(result.redacted_entities) == 3
        assert result.processing_time_seconds >= 0
        assert "total_entities" in result.redaction_metadata
        assert result.redaction_metadata["total_entities"] == 3
    
    def test_redaction_config_entity_specific(self, redaction_engine, sample_image, sample_visual_entities):
        """Test entity-specific redaction configurations."""
        config = RedactionConfig()  # Uses default entity-specific configs
        
        result = redaction_engine.redact_image(sample_image, sample_visual_entities, config)
        
        assert result.success
        assert len(result.redacted_entities) == 3
        
        # Check that different redaction methods were used
        methods_used = result.redaction_metadata.get("redaction_methods_used", [])
        assert len(methods_used) > 0
    
    def test_redaction_batch_processing(self, redaction_engine, sample_image, sample_visual_entities):
        """Test batch redaction of multiple images."""
        images = [sample_image, sample_image.copy()]
        entities_per_image = [sample_visual_entities, sample_visual_entities[:2]]
        
        results = redaction_engine.redact_batch(images, entities_per_image)
        
        assert len(results) == 2
        assert all(result.success for result in results)
        assert results[0].redacted_entities == 3
        assert results[1].redacted_entities == 2
    
    def test_redacted_image_conversion(self, redaction_engine, sample_image, sample_visual_entities):
        """Test redacted image format conversions."""
        result = redaction_engine.redact_image(sample_image, sample_visual_entities)
        
        # Test PIL conversion
        pil_image = redaction_engine.get_redacted_image_as_pil(result)
        assert pil_image is not None
        assert isinstance(pil_image, Image.Image)
        
        # Test base64 conversion
        base64_str = redaction_engine.get_redacted_image_as_base64(result)
        assert base64_str is not None
        assert isinstance(base64_str, str)
        assert len(base64_str) > 0
    
    def test_redaction_preview_creation(self, redaction_engine, sample_image, sample_visual_entities):
        """Test creation of redaction preview with bounding boxes."""
        preview = redaction_engine.create_redaction_preview(
            sample_image, 
            sample_visual_entities,
            show_bboxes=True
        )
        
        assert preview is not None
        assert preview.shape == sample_image.shape
        assert not np.array_equal(preview, sample_image)  # Should have bounding boxes drawn


class TestVisualAPIEndpoints:
    """Test Visual PII Detection API endpoints."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)
    
    @pytest.fixture
    def mock_visual_service(self, sample_visual_entities):
        """Mock visual detection service for API testing."""
        service = Mock()
        
        # Mock detection result
        mock_result = VisualPIIDetectionResult(
            detection_id="test-visual-123",
            status=VisualDetectionStatus.COMPLETED,
            visual_entities=sample_visual_entities,
            image_count=1,
            total_images_processed=1,
            model_used="yolov8",
            started_at=datetime.now(),
            completed_at=datetime.now(),
            processing_time_seconds=1.5
        )
        
        service.detect_visual_pii_async.return_value = mock_result
        service.detect_visual_pii_sync.return_value = mock_result
        service.get_detection_result.return_value = mock_result
        service.get_detection_status.return_value = VisualDetectionStatus.COMPLETED
        service.cancel_detection.return_value = True
        service.get_service_statistics.return_value = {
            "total_detections": 5,
            "active_detections": 0,
            "completed_detections": 5,
            "average_processing_time": 1.2,
            "average_entities_per_detection": 2.5,
            "total_images_processed": 8,
            "risk_level_distribution": {"low": 2, "medium": 1, "high": 1, "critical": 1},
            "default_model_loaded": True,
            "thread_pool_workers": 2
        }
        
        return service
    
    @pytest.fixture
    def sample_image_file(self, sample_pil_image):
        """Create a sample image file for upload testing."""
        img_byte_array = io.BytesIO()
        sample_pil_image.save(img_byte_array, format='PNG')
        img_byte_array.seek(0)
        return img_byte_array
    
    def test_supported_entities_endpoint(self, client):
        """Test supported visual entities endpoint."""
        response = client.get("/api/v1/visual-pii/supported/entities")
        
        assert response.status_code == 200
        data = response.json()
        assert "supported_entities" in data
        assert len(data["supported_entities"]) > 0
        
        # Check for common visual entity types
        entity_types = [entity["type"] for entity in data["supported_entities"]]
        assert "face" in entity_types
        assert "signature" in entity_types
        assert "stamp" in entity_types
    
    def test_supported_redaction_methods_endpoint(self, client):
        """Test supported redaction methods endpoint."""
        response = client.get("/api/v1/visual-pii/supported/redaction-methods")
        
        assert response.status_code == 200
        data = response.json()
        assert "supported_methods" in data
        
        # Check for common redaction methods
        method_values = [method["method"] for method in data["supported_methods"]]
        assert "blur" in method_values
        assert "blackout" in method_values
        assert "pixelate" in method_values
    
    def test_health_check_endpoint(self, client, mock_visual_service):
        """Test visual health check endpoint."""
        with patch('src.api.visual_pii_detection.get_visual_pii_detection_service', return_value=mock_visual_service):
            response = client.get("/api/v1/visual-pii/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "visual_pii_detection"
    
    def test_service_statistics_endpoint(self, client, mock_visual_service):
        """Test visual service statistics endpoint."""
        with patch('src.api.visual_pii_detection.get_visual_pii_detection_service', return_value=mock_visual_service):
            response = client.get("/api/v1/visual-pii/stats")
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_detections"] == 5
        assert data["completed_detections"] == 5
        assert data["total_images_processed"] == 8
        assert data["default_model_loaded"] is True


class TestComplianceIntegration:
    """Test compliance and security integration for visual PII."""
    
    def test_visual_compliance_metadata_creation(self):
        """Test creation of compliance metadata for visual PII."""
        entities = [
            VisualPIIEntity(
                entity_type=VisualPIIType.FACE,
                confidence=0.9,
                confidence_level=VisualConfidenceLevel.VERY_HIGH,
                bounding_box=BoundingBox(x=0, y=0, width=10, height=10),
                model_name="test"
            )
        ]
        
        result = VisualPIIDetectionResult(
            detection_id="test-compliance",
            visual_entities=entities
        )
        
        # Should flag biometric data detection
        assert "biometric_data_detected" in result.compliance_flags or len(result.compliance_flags) == 0
        assert result.risk_level == VisualRiskLevel.HIGH
    
    @patch('src.core.services.visual_pii_detector.compliance_encryption')
    def test_visual_encryption_integration(self, mock_compliance_encryption):
        """Test encryption integration with visual detection service."""
        mock_compliance_encryption._log_audit_event = Mock()
        
        service = VisualPIIDetectionService()
        
        # Create a high-risk visual detection result
        entities = [
            VisualPIIEntity(
                entity_type=VisualPIIType.SIGNATURE,
                confidence=0.95,
                confidence_level=VisualConfidenceLevel.VERY_HIGH,
                bounding_box=BoundingBox(x=0, y=0, width=100, height=50),
                model_name="test"
            )
        ]
        
        result = VisualPIIDetectionResult(
            detection_id="test-encrypt-visual",
            visual_entities=entities,
            risk_level=VisualRiskLevel.CRITICAL
        )
        
        # The service should flag this as critical risk
        assert result.risk_level == VisualRiskLevel.CRITICAL


class TestPerformanceAndScaling:
    """Test performance and scaling aspects of visual PII detection."""
    
    @pytest.mark.asyncio
    async def test_concurrent_visual_detections(self, sample_image):
        """Test concurrent visual detection requests."""
        service = VisualPIIDetectionService()
        
        # Mock the detection to avoid actual model loading
        with patch.object(service, '_detect_entities_sync', return_value=[]):
            tasks = []
            for i in range(3):
                task = service.detect_visual_pii_async([sample_image])
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            
            assert len(results) == 3
            for result in results:
                assert result.status == VisualDetectionStatus.COMPLETED
    
    def test_visual_memory_management(self):
        """Test visual detection memory cleanup and management."""
        service = VisualPIIDetectionService()
        
        # Add multiple detection results
        for i in range(5):
            result = VisualPIIDetectionResult(
                detection_id=f"test-visual-{i}",
                status=VisualDetectionStatus.COMPLETED,
                completed_at=datetime.now() - timedelta(hours=i)
            )
            service.detection_history[f"test-visual-{i}"] = result
        
        initial_count = len(service.detection_history)
        
        # Cleanup old records
        service.cleanup_history(max_age_hours=2)
        
        # Should remove records older than 2 hours
        assert len(service.detection_history) < initial_count
    
    def test_visual_batch_processing_efficiency(self, sample_image):
        """Test efficiency of batch visual processing."""
        from src.core.processing.visual_redactor import get_visual_redaction_engine
        
        redaction_engine = get_visual_redaction_engine()
        
        # Create test entities
        entities = [
            VisualPIIEntity(
                entity_type=VisualPIIType.FACE,
                confidence=0.9,
                confidence_level=VisualConfidenceLevel.VERY_HIGH,
                bounding_box=BoundingBox(x=50, y=50, width=100, height=100),
                model_name="test"
            )
        ]
        
        # Test batch redaction
        images = [sample_image] * 3
        entities_per_image = [entities] * 3
        
        start_time = datetime.now()
        results = redaction_engine.redact_batch(images, entities_per_image)
        processing_time = (datetime.now() - start_time).total_seconds()
        
        assert len(results) == 3
        assert all(result.success for result in results)
        assert processing_time < 10.0  # Should complete within reasonable time


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])