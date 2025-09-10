"""
Integration Tests for Document PII Processing Pipeline

Comprehensive tests for the integrated document processing with PII detection,
covering various document types, processing modes, and edge cases.
"""

import pytest
import tempfile
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import uuid
import base64
import io

from PIL import Image
import numpy as np

from src.core.processing.document_pii_processor import (
    DocumentPIIProcessor,
    PIIProcessingOptions,
    PIIProcessingMode,
    PIIDocumentResult,
    get_document_pii_processor,
    quick_document_pii_analysis,
    quick_document_pii_analysis_sync
)
from src.core.processing.document_factory import ProcessingOptions, ProcessingMode
from src.core.services.pii_detector import PIIDetectionResult, DetectionStatus, RiskLevel
from src.core.services.visual_pii_detector import VisualDetectionResult, VisualDetectionStatus
from src.core.models.ner_models import PIIEntity, EntityConfidence
from src.core.models.visual_models import VisualPIIEntity, VisualPIIType, BoundingBox
from src.core.security.compliance_encryption import ComplianceStandard


class TestDocumentPIIIntegration:
    """Integration tests for the complete document PII processing pipeline."""
    
    @pytest.fixture
    def processor(self):
        """Create a DocumentPIIProcessor instance for testing."""
        return DocumentPIIProcessor()
    
    @pytest.fixture
    def sample_pdf_file(self):
        """Create a temporary PDF file for testing."""
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_file:
            # Create a simple PDF content (mock)
            tmp_file.write(b'%PDF-1.4\n%Mock PDF content for testing')
            tmp_file_path = Path(tmp_file.name)
        return tmp_file_path
    
    @pytest.fixture
    def sample_image_file(self):
        """Create a temporary image file for testing."""
        # Create a simple test image
        image = Image.new('RGB', (100, 100), color='white')
        
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp_file:
            image.save(tmp_file, format='PNG')
            tmp_file_path = Path(tmp_file.name)
        return tmp_file_path
    
    @pytest.fixture
    def mock_text_pii_entities(self):
        """Mock text PII entities for testing."""
        return [
            PIIEntity(
                text="john.doe@email.com",
                entity_type="EMAIL_ADDRESS",
                start_position=10,
                end_position=27,
                confidence=0.95,
                confidence_level=EntityConfidence.VERY_HIGH
            ),
            PIIEntity(
                text="123-45-6789",
                entity_type="US_SSN",
                start_position=50,
                end_position=61,
                confidence=0.92,
                confidence_level=EntityConfidence.VERY_HIGH
            )
        ]
    
    @pytest.fixture
    def mock_visual_pii_entities(self):
        """Mock visual PII entities for testing."""
        return [
            VisualPIIEntity(
                entity_type=VisualPIIType.FACE,
                bounding_box=BoundingBox(x1=10, y1=10, x2=50, y2=50),
                confidence=0.88,
                metadata={"face_id": "face_001"}
            ),
            VisualPIIEntity(
                entity_type=VisualPIIType.ID_CARD,
                bounding_box=BoundingBox(x1=100, y1=100, x2=200, y2=150),
                confidence=0.79,
                metadata={"card_type": "driver_license"}
            )
        ]
    
    @pytest.mark.asyncio
    async def test_comprehensive_pdf_processing(self, processor, sample_pdf_file, mock_text_pii_entities, mock_visual_pii_entities):
        """Test comprehensive PDF processing with PII detection."""
        
        with patch.object(processor.document_factory, 'process_document') as mock_doc_process, \
             patch.object(processor.pii_service, 'detect_pii_async') as mock_text_pii, \
             patch.object(processor.visual_pii_service, 'detect_visual_pii_async') as mock_visual_pii, \
             patch.object(processor.ocr_service, 'process_image_async') as mock_ocr:
            
            # Mock document processing result
            mock_doc_result = Mock()
            mock_doc_result.success = True
            mock_doc_result.document_type = Mock(value="pdf")
            mock_doc_result.page_count = 2
            mock_doc_result.extracted_text = "Sample text with john.doe@email.com and SSN 123-45-6789"
            mock_doc_result.extracted_images = [Image.new('RGB', (100, 100))]
            mock_doc_result.errors_encountered = []
            mock_doc_process.return_value = mock_doc_result
            
            # Mock text PII detection
            mock_text_pii_result = PIIDetectionResult(
                detection_id=str(uuid.uuid4()),
                status=DetectionStatus.COMPLETED,
                entities=mock_text_pii_entities,
                risk_level=RiskLevel.HIGH
            )
            mock_text_pii.return_value = mock_text_pii_result
            
            # Mock visual PII detection
            mock_visual_pii_result = VisualDetectionResult(
                detection_id=str(uuid.uuid4()),
                status=VisualDetectionStatus.COMPLETED,
                entities=mock_visual_pii_entities,
                risk_level=RiskLevel.MEDIUM
            )
            mock_visual_pii.return_value = mock_visual_pii_result
            
            # Mock OCR processing
            mock_ocr_result = Mock()
            mock_ocr_result.success = True
            mock_ocr_result.extracted_text = "OCR extracted text with phone (555) 123-4567"
            mock_ocr.return_value = mock_ocr_result
            
            # Create processing options
            processing_options = ProcessingOptions(mode=ProcessingMode.ENHANCED)
            pii_options = PIIProcessingOptions(
                pii_mode=PIIProcessingMode.COMPREHENSIVE,
                text_confidence_threshold=0.5,
                visual_confidence_threshold=0.6,
                parallel_processing=True
            )
            
            # Process document
            result = await processor.process_document_with_pii(
                file_path=sample_pdf_file,
                processing_options=processing_options,
                pii_options=pii_options
            )
            
            # Assertions
            assert result.success
            assert result.document_type.value == "pdf"
            assert result.page_count == 2
            assert len(result.text_pii_results) > 0
            assert len(result.visual_pii_results) > 0
            assert result.total_text_entities == 2  # From mock_text_pii_entities
            assert result.total_visual_entities == 2  # From mock_visual_pii_entities
            assert result.overall_risk_level == RiskLevel.HIGH  # Should take highest risk level
            assert "document_processing" in result.operations_performed
            assert "text_pii_detection" in result.operations_performed
            assert "visual_pii_detection" in result.operations_performed
            
        # Cleanup
        sample_pdf_file.unlink()
    
    @pytest.mark.asyncio
    async def test_image_only_processing(self, processor, sample_image_file, mock_visual_pii_entities):
        """Test image-only processing with visual PII detection."""
        
        with patch.object(processor.document_factory, 'process_document') as mock_doc_process, \
             patch.object(processor.visual_pii_service, 'detect_visual_pii_async') as mock_visual_pii:
            
            # Mock document processing result
            mock_doc_result = Mock()
            mock_doc_result.success = True
            mock_doc_result.document_type = Mock(value="image")
            mock_doc_result.page_count = 1
            mock_doc_result.extracted_text = ""  # No text from image
            mock_doc_result.extracted_images = [Image.new('RGB', (200, 200))]
            mock_doc_result.errors_encountered = []
            mock_doc_process.return_value = mock_doc_result
            
            # Mock visual PII detection
            mock_visual_pii_result = VisualDetectionResult(
                detection_id=str(uuid.uuid4()),
                status=VisualDetectionStatus.COMPLETED,
                entities=mock_visual_pii_entities,
                risk_level=RiskLevel.MEDIUM
            )
            mock_visual_pii.return_value = mock_visual_pii_result
            
            # Create processing options for visual-only
            pii_options = PIIProcessingOptions(
                pii_mode=PIIProcessingMode.VISUAL_ONLY,
                enable_text_pii=False,
                enable_visual_pii=True,
                enable_ocr_pii=False
            )
            
            # Process document
            result = await processor.process_document_with_pii(
                file_path=sample_image_file,
                pii_options=pii_options
            )
            
            # Assertions
            assert result.success
            assert result.document_type.value == "image"
            assert len(result.text_pii_results) == 0  # No text processing
            assert len(result.visual_pii_results) > 0
            assert result.total_visual_entities == 2
            assert "visual_pii_detection" in result.operations_performed
            assert "text_pii_detection" not in result.operations_performed
            
        # Cleanup
        sample_image_file.unlink()
    
    @pytest.mark.asyncio
    async def test_text_only_processing(self, processor, sample_pdf_file, mock_text_pii_entities):
        """Test text-only processing with text PII detection."""
        
        with patch.object(processor.document_factory, 'process_document') as mock_doc_process, \
             patch.object(processor.pii_service, 'detect_pii_async') as mock_text_pii:
            
            # Mock document processing result
            mock_doc_result = Mock()
            mock_doc_result.success = True
            mock_doc_result.document_type = Mock(value="pdf")
            mock_doc_result.page_count = 1
            mock_doc_result.extracted_text = "Document contains sensitive information like john.doe@email.com"
            mock_doc_result.extracted_images = []  # No images
            mock_doc_result.errors_encountered = []
            mock_doc_process.return_value = mock_doc_result
            
            # Mock text PII detection
            mock_text_pii_result = PIIDetectionResult(
                detection_id=str(uuid.uuid4()),
                status=DetectionStatus.COMPLETED,
                entities=mock_text_pii_entities,
                risk_level=RiskLevel.HIGH
            )
            mock_text_pii.return_value = mock_text_pii_result
            
            # Create processing options for text-only
            pii_options = PIIProcessingOptions(
                pii_mode=PIIProcessingMode.TEXT_ONLY,
                enable_text_pii=True,
                enable_visual_pii=False,
                enable_ocr_pii=False
            )
            
            # Process document
            result = await processor.process_document_with_pii(
                file_path=sample_pdf_file,
                pii_options=pii_options
            )
            
            # Assertions
            assert result.success
            assert len(result.text_pii_results) > 0
            assert len(result.visual_pii_results) == 0  # No visual processing
            assert result.total_text_entities == 2
            assert "text_pii_detection" in result.operations_performed
            assert "visual_pii_detection" not in result.operations_performed
            
        # Cleanup
        sample_pdf_file.unlink()
    
    @pytest.mark.asyncio
    async def test_error_handling(self, processor, sample_pdf_file):
        """Test error handling in the processing pipeline."""
        
        with patch.object(processor.document_factory, 'process_document') as mock_doc_process:
            
            # Mock document processing failure
            mock_doc_result = Mock()
            mock_doc_result.success = False
            mock_doc_result.errors_encountered = ["Failed to parse PDF"]
            mock_doc_process.return_value = mock_doc_result
            
            # Process document
            result = await processor.process_document_with_pii(
                file_path=sample_pdf_file
            )
            
            # Assertions
            assert not result.success
            assert len(result.errors_encountered) > 0
            assert "Failed to parse PDF" in str(result.errors_encountered)
            
        # Cleanup
        sample_pdf_file.unlink()
    
    @pytest.mark.asyncio
    async def test_compliance_integration(self, processor, sample_pdf_file, mock_text_pii_entities):
        """Test compliance standards integration."""
        
        with patch.object(processor.document_factory, 'process_document') as mock_doc_process, \
             patch.object(processor.pii_service, 'detect_pii_async') as mock_text_pii:
            
            # Mock document processing result
            mock_doc_result = Mock()
            mock_doc_result.success = True
            mock_doc_result.document_type = Mock(value="pdf")
            mock_doc_result.page_count = 1
            mock_doc_result.extracted_text = "Medical record with patient info"
            mock_doc_result.extracted_images = []
            mock_doc_result.errors_encountered = []
            mock_doc_process.return_value = mock_doc_result
            
            # Mock text PII detection with compliance flags
            mock_text_pii_result = PIIDetectionResult(
                detection_id=str(uuid.uuid4()),
                status=DetectionStatus.COMPLETED,
                entities=mock_text_pii_entities,
                risk_level=RiskLevel.CRITICAL,
                compliance_flags=["hipaa_violation", "critical_pii_detected"]
            )
            mock_text_pii.return_value = mock_text_pii_result
            
            # Create processing options with compliance standards
            pii_options = PIIProcessingOptions(
                compliance_standards=[ComplianceStandard.HIPAA, ComplianceStandard.GDPR],
                encrypt_results=True,
                audit_logging=True
            )
            
            # Process document
            result = await processor.process_document_with_pii(
                file_path=sample_pdf_file,
                pii_options=pii_options
            )
            
            # Assertions
            assert result.success
            assert result.overall_risk_level == RiskLevel.CRITICAL
            assert "hipaa_violation" in result.compliance_flags
            assert "critical_pii_detected" in result.compliance_flags
            
        # Cleanup
        sample_pdf_file.unlink()
    
    def test_synchronous_processing(self, processor, sample_image_file):
        """Test synchronous processing interface."""
        
        with patch.object(processor.document_factory, 'process_document') as mock_doc_process:
            
            # Mock document processing result
            mock_doc_result = Mock()
            mock_doc_result.success = True
            mock_doc_result.document_type = Mock(value="image")
            mock_doc_result.page_count = 1
            mock_doc_result.extracted_text = ""
            mock_doc_result.extracted_images = [Image.new('RGB', (100, 100))]
            mock_doc_result.errors_encountered = []
            mock_doc_process.return_value = mock_doc_result
            
            # Process document synchronously
            result = processor.process_document_with_pii_sync(
                file_path=sample_image_file
            )
            
            # Assertions
            assert isinstance(result, PIIDocumentResult)
            assert result.processing_id is not None
            assert result.document_id is not None
            
        # Cleanup
        sample_image_file.unlink()
    
    @pytest.mark.asyncio
    async def test_quick_analysis_functions(self, sample_image_file):
        """Test quick analysis convenience functions."""
        
        with patch('src.core.processing.document_pii_processor.get_document_pii_processor') as mock_get_processor:
            
            # Mock processor and its methods
            mock_processor = Mock()
            mock_result = PIIDocumentResult(
                document_id=str(uuid.uuid4()),
                processing_id=str(uuid.uuid4()),
                success=True,
                started_at=datetime.now(),
                completed_at=datetime.now(),
                total_processing_time=1.5
            )
            mock_processor.process_document_with_pii = Mock(return_value=mock_result)
            mock_processor.process_document_with_pii_sync = Mock(return_value=mock_result)
            mock_get_processor.return_value = mock_processor
            
            # Test async quick analysis
            result_async = await quick_document_pii_analysis(
                file_path=sample_image_file,
                pii_mode=PIIProcessingMode.COMPREHENSIVE,
                confidence_threshold=0.7
            )
            
            # Test sync quick analysis
            result_sync = quick_document_pii_analysis_sync(
                file_path=sample_image_file,
                pii_mode=PIIProcessingMode.TEXT_ONLY,
                confidence_threshold=0.6
            )
            
            # Assertions
            assert isinstance(result_async, PIIDocumentResult)
            assert isinstance(result_sync, PIIDocumentResult)
            assert result_async.success
            assert result_sync.success
            
            # Verify correct options were passed
            mock_processor.process_document_with_pii.assert_called_once()
            mock_processor.process_document_with_pii_sync.assert_called_once()
            
        # Cleanup
        sample_image_file.unlink()
    
    def test_processor_statistics(self, processor):
        """Test processor statistics and performance metrics."""
        
        # Add some mock processing history
        mock_result1 = PIIDocumentResult(
            document_id=str(uuid.uuid4()),
            processing_id=str(uuid.uuid4()),
            success=True,
            started_at=datetime.now(),
            completed_at=datetime.now(),
            total_processing_time=2.1,
            overall_risk_level=RiskLevel.HIGH,
            unique_pii_types=["EMAIL_ADDRESS", "PHONE_NUMBER"]
        )
        
        mock_result2 = PIIDocumentResult(
            document_id=str(uuid.uuid4()),
            processing_id=str(uuid.uuid4()),
            success=True,
            started_at=datetime.now(),
            completed_at=datetime.now(),
            total_processing_time=1.8,
            overall_risk_level=RiskLevel.LOW,
            unique_pii_types=["PERSON_NAME"]
        )
        
        processor.processing_history[mock_result1.processing_id] = mock_result1
        processor.processing_history[mock_result2.processing_id] = mock_result2
        
        # Get statistics
        stats = processor.get_processing_statistics()
        
        # Assertions
        assert stats["total_processed"] == 2
        assert stats["success_rate"] == 1.0
        assert stats["average_processing_time"] == 1.95
        assert "high" in stats["risk_level_distribution"]
        assert "low" in stats["risk_level_distribution"]
        assert "EMAIL_ADDRESS" in stats["pii_type_distribution"]
        assert "PHONE_NUMBER" in stats["pii_type_distribution"]
        assert "PERSON_NAME" in stats["pii_type_distribution"]
    
    def test_history_cleanup(self, processor):
        """Test processing history cleanup functionality."""
        
        # Add old mock result
        old_result = PIIDocumentResult(
            document_id=str(uuid.uuid4()),
            processing_id=str(uuid.uuid4()),
            success=True,
            started_at=datetime.now(),
            completed_at=datetime(2023, 1, 1)  # Old date
        )
        
        # Add recent mock result
        recent_result = PIIDocumentResult(
            document_id=str(uuid.uuid4()),
            processing_id=str(uuid.uuid4()),
            success=True,
            started_at=datetime.now(),
            completed_at=datetime.now()
        )
        
        processor.processing_history[old_result.processing_id] = old_result
        processor.processing_history[recent_result.processing_id] = recent_result
        
        # Cleanup old results (max age 1 hour)
        processor.cleanup_history(max_age_hours=1)
        
        # Assertions
        assert recent_result.processing_id in processor.processing_history
        assert old_result.processing_id not in processor.processing_history
    
    def test_global_processor_instance(self):
        """Test global processor instance getter."""
        
        # Get processor instance
        processor1 = get_document_pii_processor()
        processor2 = get_document_pii_processor()
        
        # Should be the same instance
        assert processor1 is processor2
        assert isinstance(processor1, DocumentPIIProcessor)


class TestDocumentPIIAPIIntegration:
    """Integration tests for the API layer."""
    
    @pytest.fixture
    def api_client(self):
        """Create a test API client."""
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        from src.api.document_pii_processing import router
        
        app = FastAPI()
        app.include_router(router)
        
        return TestClient(app)
    
    def test_api_endpoints_available(self, api_client):
        """Test that API endpoints are properly registered."""
        
        # This test would require proper FastAPI setup and authentication mocks
        # For now, we'll just verify the router exists
        from src.api.document_pii_processing import router
        
        assert router is not None
        assert router.prefix == "/api/v1/document-pii"
        assert len(router.routes) > 0
        
        # Check that expected endpoints exist
        route_paths = [route.path for route in router.routes]
        assert "/process" in route_paths
        assert "/quick-analysis" in route_paths
        assert "/status/{processing_id}" in route_paths
        assert "/result/{processing_id}" in route_paths
        assert "/statistics" in route_paths


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])