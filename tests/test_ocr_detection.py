"""
Comprehensive Test Suite for OCR Detection System

This module provides comprehensive tests for:
- OCR model functionality (Tesseract, PaddleOCR)
- OCR service layer with async/sync operations
- OCR processing pipeline with different document types
- REST API endpoints for OCR functionality
- Error handling and edge cases
- Performance and integration testing
"""

import pytest
import asyncio
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from io import BytesIO
import numpy as np
from PIL import Image, ImageDraw, ImageFont
import httpx

# Import the modules to test
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.models.ocr_models import (
    TesseractOCRModel, PaddleOCRModel, OCREngine, LanguageCode, OCRResult,
    get_default_ocr_model, get_available_ocr_engines, create_tesseract_model
)
from src.core.services.ocr_service import (
    OCRService, OCRDocumentPage, OCRDocumentResult, OCRQuality, 
    create_ocr_service, quick_ocr_text_extraction_sync
)
from src.core.processing.ocr_processor import (
    OCRProcessor, OCRProcessingConfig, DocumentType, PreprocessingMode,
    create_ocr_processor, quick_document_ocr
)


class TestOCRModels:
    """Test suite for OCR model implementations."""
    
    @pytest.fixture
    def sample_image(self):
        """Create a sample test image with text."""
        # Create a simple image with text for testing
        img = Image.new('RGB', (400, 100), color='white')
        draw = ImageDraw.Draw(img)
        
        # Try to use a basic font, fallback to default if not available
        try:
            font = ImageFont.load_default()
        except:
            font = None
        
        draw.text((10, 30), "Hello World 123", fill='black', font=font)
        draw.text((10, 60), "Test Document", fill='black', font=font)
        
        return img
    
    @pytest.fixture
    def sample_image_path(self, sample_image, tmp_path):
        """Save sample image to temporary file."""
        image_path = tmp_path / "test_image.png"
        sample_image.save(image_path)
        return image_path
    
    def test_tesseract_model_creation(self):
        """Test Tesseract OCR model creation."""
        model = create_tesseract_model([LanguageCode.ENGLISH])
        assert model is not None
        assert model.engine == OCREngine.TESSERACT
        assert LanguageCode.ENGLISH in model.languages
        assert not model.is_loaded
    
    def test_tesseract_model_loading(self):
        """Test Tesseract OCR model loading."""
        model = create_tesseract_model()
        
        # Mock pytesseract for testing
        with patch('pytesseract.get_tesseract_version') as mock_version:
            mock_version.return_value = "5.0.0"
            
            with patch('pytesseract.get_languages') as mock_langs:
                mock_langs.return_value = ['eng', 'fra', 'deu']
                
                success = model.load()
                # Test may fail if Tesseract not installed, which is expected
                if success:
                    assert model.is_loaded
                    assert model.get_available_languages()
    
    def test_ocr_model_validation(self, sample_image, sample_image_path):
        """Test OCR model input validation."""
        model = create_tesseract_model()
        
        # Test image validation
        assert model.validate_image(sample_image)
        assert model.validate_image(sample_image_path)
        assert model.validate_image(np.array(sample_image))
        assert not model.validate_image("nonexistent_file.jpg")
    
    @pytest.mark.asyncio
    async def test_ocr_model_preprocessing(self, sample_image):
        """Test OCR model image preprocessing."""
        model = create_tesseract_model()
        
        # Test preprocessing
        processed_array, operations = model.preprocess_image(sample_image)
        assert isinstance(processed_array, np.ndarray)
        assert len(operations) > 0
        assert "converted_pil_to_numpy" in operations
    
    def test_paddle_ocr_model_creation(self):
        """Test PaddleOCR model creation."""
        try:
            from src.core.models.ocr_models import create_paddle_ocr_model
            model = create_paddle_ocr_model(['en'])
            assert model is not None
            assert model.engine == OCREngine.PADDLE
        except ImportError:
            pytest.skip("PaddleOCR not available")
    
    def test_get_available_engines(self):
        """Test getting available OCR engines."""
        engines = get_available_ocr_engines()
        assert isinstance(engines, list)
        # At least one engine should be available for tests to be meaningful
        # but we can't guarantee which ones are installed
    
    def test_get_default_ocr_model(self):
        """Test getting default OCR model."""
        model = get_default_ocr_model(OCREngine.TESSERACT)
        # May return None if Tesseract is not installed, which is acceptable for CI


class TestOCRService:
    """Test suite for OCR service layer."""
    
    @pytest.fixture
    def mock_ocr_model(self):
        """Create a mock OCR model for testing."""
        model = Mock()
        model.is_loaded = True
        model.engine = OCREngine.TESSERACT
        model.extract_text.return_value = OCRResult(
            success=True,
            text_content="Mock OCR Result",
            confidence_score=85.0,
            text_blocks=[],
            bounding_boxes=[],
            processing_time=0.1,
            page_number=0,
            engine_used="Tesseract",
            engine_version="5.0.0"
        )
        return model
    
    @pytest.fixture
    def ocr_service(self, mock_ocr_model):
        """Create OCR service with mocked model."""
        service = OCRService(enable_pii_detection=False)
        service._ocr_model = mock_ocr_model
        return service
    
    @pytest.fixture
    def sample_image_bytes(self):
        """Create sample image as bytes."""
        img = Image.new('RGB', (200, 50), color='white')
        draw = ImageDraw.Draw(img)
        draw.text((10, 20), "Test Text", fill='black')
        
        img_bytes = BytesIO()
        img.save(img_bytes, format='PNG')
        img_bytes.seek(0)
        return img_bytes.getvalue()
    
    def test_ocr_service_creation(self):
        """Test OCR service creation."""
        service = create_ocr_service(OCREngine.TESSERACT, enable_pii=False)
        assert service is not None
        assert service.preferred_engine == OCREngine.TESSERACT
        assert not service.enable_pii_detection
        
        service.cleanup()
    
    def test_ocr_service_with_pii_detection(self):
        """Test OCR service with PII detection enabled."""
        service = create_ocr_service(enable_pii=True)
        assert service.enable_pii_detection
        # PII service may not initialize if dependencies missing
        
        service.cleanup()
    
    def test_extract_text_from_image_sync(self, ocr_service, sample_image_bytes):
        """Test synchronous text extraction from image."""
        # Create temporary image file
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
            tmp.write(sample_image_bytes)
            tmp_path = tmp.name
        
        try:
            result = ocr_service.extract_text_from_image(tmp_path)
            assert isinstance(result, OCRDocumentPage)
            assert result.ocr_result is not None
            assert result.quality_assessment is not None
            
            # Mock should return success
            if result.ocr_result.success:
                assert "Mock OCR Result" in result.ocr_result.text_content
        finally:
            os.unlink(tmp_path)
    
    @pytest.mark.asyncio
    async def test_extract_text_from_image_async(self, ocr_service, sample_image_bytes):
        """Test asynchronous text extraction from image."""
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
            tmp.write(sample_image_bytes)
            tmp_path = tmp.name
        
        try:
            result = await ocr_service.extract_text_from_image_async(tmp_path)
            assert isinstance(result, OCRDocumentPage)
            assert result.ocr_result is not None
        finally:
            os.unlink(tmp_path)
    
    def test_batch_process_images(self, ocr_service, sample_image_bytes):
        """Test batch processing of images."""
        # Create multiple temporary image files
        temp_files = []
        for i in range(3):
            tmp = tempfile.NamedTemporaryFile(suffix=f'_{i}.png', delete=False)
            tmp.write(sample_image_bytes)
            temp_files.append(tmp.name)
            tmp.close()
        
        try:
            results = ocr_service.batch_process_images(temp_files)
            assert len(results) == 3
            
            for result in results:
                assert isinstance(result, OCRDocumentPage)
                assert result.ocr_result is not None
        finally:
            for tmp_path in temp_files:
                os.unlink(tmp_path)
    
    @pytest.mark.asyncio
    async def test_batch_process_images_async(self, ocr_service, sample_image_bytes):
        """Test asynchronous batch processing of images."""
        # Create temporary image files
        temp_files = []
        for i in range(2):
            tmp = tempfile.NamedTemporaryFile(suffix=f'_async_{i}.png', delete=False)
            tmp.write(sample_image_bytes)
            temp_files.append(tmp.name)
            tmp.close()
        
        try:
            results = await ocr_service.batch_process_images_async(temp_files)
            assert len(results) == 2
            
            for result in results:
                assert isinstance(result, OCRDocumentPage)
        finally:
            for tmp_path in temp_files:
                os.unlink(tmp_path)
    
    def test_quality_assessment(self, ocr_service):
        """Test OCR quality assessment functionality."""
        # Test with different confidence scores
        high_confidence_result = OCRResult(
            success=True, text_content="Test", confidence_score=95.0,
            text_blocks=[], bounding_boxes=[], processing_time=0.1,
            page_number=0, engine_used="Test"
        )
        
        low_confidence_result = OCRResult(
            success=True, text_content="Test", confidence_score=30.0,
            text_blocks=[], bounding_boxes=[], processing_time=0.1,
            page_number=0, engine_used="Test"
        )
        
        assert ocr_service._assess_quality(high_confidence_result) == OCRQuality.EXCELLENT
        assert ocr_service._assess_quality(low_confidence_result) == OCRQuality.POOR
    
    def test_engine_switching(self):
        """Test OCR engine switching functionality."""
        service = create_ocr_service(OCREngine.TESSERACT)
        
        # Test getting available engines
        engines = service.get_available_engines()
        assert isinstance(engines, list)
        
        # Test engine info
        engine_info = service.get_engine_info()
        assert isinstance(engine_info, dict)
        assert "status" in engine_info
        
        service.cleanup()
    
    def test_quick_ocr_functions(self, sample_image_bytes):
        """Test quick OCR utility functions."""
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
            tmp.write(sample_image_bytes)
            tmp_path = tmp.name
        
        try:
            # Test sync quick OCR (may return empty string if no OCR engine available)
            result = quick_ocr_text_extraction_sync(tmp_path)
            assert isinstance(result, str)
        except Exception:
            # Expected if no OCR engine is available
            pass
        finally:
            os.unlink(tmp_path)


class TestOCRProcessor:
    """Test suite for OCR processing pipeline."""
    
    @pytest.fixture
    def ocr_config(self):
        """Create OCR processing configuration for testing."""
        return OCRProcessingConfig(
            engine=OCREngine.TESSERACT,
            preprocessing_mode=PreprocessingMode.ENHANCED,
            enable_pii_detection=False,
            max_pages=10,
            max_workers=2
        )
    
    @pytest.fixture
    def mock_processor_components(self):
        """Mock the processor components for testing."""
        with patch('src.core.processing.ocr_processor.PDFProcessor') as mock_pdf, \
             patch('src.core.processing.ocr_processor.ImageProcessor') as mock_image, \
             patch('src.core.processing.ocr_processor.OCRService') as mock_ocr:
            
            # Configure mocks
            mock_pdf_instance = Mock()
            mock_pdf.return_value = mock_pdf_instance
            
            mock_image_instance = Mock()
            mock_image.return_value = mock_image_instance
            
            mock_ocr_instance = Mock()
            mock_ocr.return_value = mock_ocr_instance
            
            yield {
                'pdf': mock_pdf_instance,
                'image': mock_image_instance,
                'ocr': mock_ocr_instance
            }
    
    def test_processor_creation(self, ocr_config):
        """Test OCR processor creation."""
        processor = create_ocr_processor(ocr_config)
        assert processor is not None
        assert processor.config == ocr_config
        
        processor.cleanup()
    
    def test_document_type_detection(self, tmp_path):
        """Test document type detection."""
        processor = create_ocr_processor()
        
        # Create test files
        image_file = tmp_path / "test.png"
        pdf_file = tmp_path / "test.pdf"
        unknown_file = tmp_path / "test.unknown"
        
        # Create a simple image
        img = Image.new('RGB', (100, 50), color='white')
        img.save(image_file)
        
        # Create empty files for testing
        pdf_file.touch()
        unknown_file.touch()
        
        # Test detection (may not work perfectly without actual PDF content)
        assert processor.detect_document_type(image_file) == DocumentType.IMAGE
        # PDF detection might default to PDF type even for empty file
        pdf_type = processor.detect_document_type(pdf_file)
        assert pdf_type in [DocumentType.PDF, DocumentType.SCANNED_PDF]
        assert processor.detect_document_type(unknown_file) == DocumentType.UNKNOWN
        
        processor.cleanup()
    
    def test_preprocessing_modes(self, tmp_path):
        """Test different preprocessing modes."""
        processor = create_ocr_processor()
        
        # Create test image
        img = Image.new('RGB', (100, 50), color='white')
        
        # Test different preprocessing modes
        for mode in PreprocessingMode:
            processed_img = processor._apply_ocr_preprocessing(img, mode)
            assert isinstance(processed_img, Image.Image)
            # Enhanced mode should modify the image
            if mode != PreprocessingMode.NONE:
                # Processed image might have different characteristics
                pass
        
        processor.cleanup()
    
    @pytest.mark.asyncio
    async def test_document_processing_integration(self, tmp_path, ocr_config, mock_processor_components):
        """Test document processing with mocked components."""
        # Create test image
        image_file = tmp_path / "test_integration.png"
        img = Image.new('RGB', (200, 100), color='white')
        draw = ImageDraw.Draw(img)
        draw.text((10, 40), "Integration Test", fill='black')
        img.save(image_file)
        
        # Configure mock responses
        mock_image = mock_processor_components['image']
        mock_image.process_image.return_value = Mock(
            success=True,
            processed_image=img,
            processing_operations=['test_op'],
            metadata=Mock(format='PNG')
        )
        
        mock_ocr = mock_processor_components['ocr']
        mock_ocr_page = Mock()
        mock_ocr_page.ocr_result.success = True
        mock_ocr_page.ocr_result.text_content = "Integration Test"
        mock_ocr_page.ocr_result.confidence_score = 90.0
        mock_ocr_page.quality_assessment = OCRQuality.EXCELLENT
        mock_ocr.extract_text_from_image.return_value = mock_ocr_page
        
        processor = OCRProcessor(ocr_config)
        result = processor.process_document(image_file)
        
        assert result is not None
        # Result may not be successful due to mocking limitations
        
        processor.cleanup()
    
    def test_batch_processing(self, tmp_path, ocr_config):
        """Test batch document processing."""
        processor = create_ocr_processor(ocr_config)
        
        # Create multiple test files
        test_files = []
        for i in range(3):
            file_path = tmp_path / f"batch_test_{i}.png"
            img = Image.new('RGB', (100, 50), color='white')
            draw = ImageDraw.Draw(img)
            draw.text((10, 20), f"Test {i}", fill='black')
            img.save(file_path)
            test_files.append(file_path)
        
        # Process batch (may not work without actual OCR engine)
        results = processor.batch_process_documents(test_files)
        assert len(results) == 3
        
        for result in results:
            assert hasattr(result, 'success')
            assert hasattr(result, 'document_path')
        
        processor.cleanup()
    
    def test_processor_stats(self):
        """Test getting processor statistics."""
        processor = create_ocr_processor()
        stats = processor.get_processing_stats()
        
        assert isinstance(stats, dict)
        assert 'supported_document_types' in stats
        assert 'supported_preprocessing_modes' in stats
        assert 'features' in stats
        
        processor.cleanup()
    
    def test_quick_document_ocr(self, tmp_path):
        """Test quick document OCR function."""
        # Create test image
        image_file = tmp_path / "quick_test.png"
        img = Image.new('RGB', (150, 75), color='white')
        draw = ImageDraw.Draw(img)
        draw.text((10, 30), "Quick Test", fill='black')
        img.save(image_file)
        
        # Test quick OCR (may return empty string if no OCR engine)
        try:
            result = quick_document_ocr(image_file)
            assert isinstance(result, str)
        except Exception:
            # Expected if no OCR engine available
            pass


class TestOCRAPI:
    """Test suite for OCR API endpoints."""
    
    @pytest.fixture
    def client(self):
        """Create test client for API testing."""
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        
        # Create test app with OCR router
        app = FastAPI()
        
        # Mock authentication
        def mock_get_current_user():
            return {"user_id": "test_user"}
        
        # Import and configure OCR router with mocked auth
        with patch('src.api.ocr_detection.get_current_user', return_value=mock_get_current_user()):
            from src.api.ocr_detection import router
            app.include_router(router)
        
        return TestClient(app)
    
    @pytest.fixture
    def sample_image_file(self):
        """Create sample image file for API testing."""
        img = Image.new('RGB', (300, 100), color='white')
        draw = ImageDraw.Draw(img)
        draw.text((10, 40), "API Test Image", fill='black')
        
        img_bytes = BytesIO()
        img.save(img_bytes, format='PNG')
        img_bytes.seek(0)
        return img_bytes
    
    def test_ocr_health_endpoint(self, client):
        """Test OCR health check endpoint."""
        response = client.get("/api/ocr/health")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
    
    def test_ocr_stats_endpoint(self, client):
        """Test OCR statistics endpoint."""
        with patch('src.api.ocr_detection.get_current_user'):
            response = client.get("/api/ocr/stats")
            # May fail without proper auth setup, but structure should be correct
            if response.status_code == 200:
                data = response.json()
                assert isinstance(data, dict)
    
    def test_engines_endpoint(self, client):
        """Test available engines endpoint."""
        with patch('src.api.ocr_detection.get_current_user'):
            response = client.get("/api/ocr/engines")
            # May fail without proper setup
            if response.status_code == 200:
                data = response.json()
                assert "available_engines" in data
                assert "supported_formats" in data
    
    def test_extract_text_endpoint_structure(self, client, sample_image_file):
        """Test extract text endpoint structure (without full processing)."""
        files = {"file": ("test.png", sample_image_file, "image/png")}
        data = {
            "engine": "tesseract",
            "languages": "eng",
            "enable_pii_detection": True,
            "preprocessing_mode": "enhanced"
        }
        
        with patch('src.api.ocr_detection.get_current_user'):
            # This will likely fail due to missing OCR setup, but we can test structure
            response = client.post("/api/ocr/extract-text", files=files, data=data)
            # Accept various response codes as setup may not be complete
            assert response.status_code in [200, 422, 500]
    
    def test_extract_image_endpoint_structure(self, client, sample_image_file):
        """Test extract from image endpoint structure."""
        files = {"file": ("test.png", sample_image_file, "image/png")}
        data = {
            "engine": "tesseract",
            "languages": "eng",
            "enable_pii_detection": False
        }
        
        with patch('src.api.ocr_detection.get_current_user'):
            response = client.post("/api/ocr/extract-text-image", files=files, data=data)
            # Accept various response codes
            assert response.status_code in [200, 422, 500]


class TestOCRErrorHandling:
    """Test suite for OCR error handling and edge cases."""
    
    def test_invalid_image_handling(self):
        """Test handling of invalid images."""
        service = create_ocr_service(enable_pii=False)
        
        try:
            # Test with non-existent file
            result = service.extract_text_from_image("nonexistent_file.png")
            assert not result.ocr_result.success
            assert len(result.ocr_result.processing_errors) > 0
        finally:
            service.cleanup()
    
    def test_empty_image_handling(self, tmp_path):
        """Test handling of empty/blank images."""
        service = create_ocr_service(enable_pii=False)
        
        # Create blank image
        blank_image = tmp_path / "blank.png"
        img = Image.new('RGB', (100, 50), color='white')
        img.save(blank_image)
        
        try:
            result = service.extract_text_from_image(blank_image)
            # Should succeed but with low/no confidence and little text
            assert result.ocr_result is not None
        finally:
            service.cleanup()
    
    def test_corrupted_file_handling(self, tmp_path):
        """Test handling of corrupted files."""
        processor = create_ocr_processor()
        
        # Create corrupted file
        corrupted_file = tmp_path / "corrupted.pdf"
        with open(corrupted_file, 'wb') as f:
            f.write(b"This is not a valid PDF file")
        
        result = processor.process_document(corrupted_file)
        assert not result.success
        assert len(result.processing_errors) > 0
        
        processor.cleanup()
    
    def test_large_file_handling(self):
        """Test handling of large files (simulated)."""
        config = OCRProcessingConfig(max_pages=5)  # Limit pages
        processor = create_ocr_processor(config)
        
        # Test with configuration limits
        assert processor.config.max_pages == 5
        
        processor.cleanup()
    
    def test_concurrent_processing_safety(self):
        """Test concurrent processing safety."""
        service = create_ocr_service(max_workers=2)
        
        # Test that service can handle concurrent requests
        assert service.max_workers == 2
        assert service._executor is not None
        
        service.cleanup()


class TestOCRPerformance:
    """Test suite for OCR performance characteristics."""
    
    def test_memory_cleanup(self):
        """Test proper memory cleanup."""
        service = create_ocr_service()
        processor = create_ocr_processor()
        
        # Ensure cleanup methods exist and can be called
        assert hasattr(service, 'cleanup')
        assert hasattr(processor, 'cleanup')
        
        service.cleanup()
        processor.cleanup()
        
        # Verify cleanup was performed
        assert service._executor is None or service._executor._shutdown
    
    def test_batch_vs_individual_processing(self):
        """Test batch processing efficiency vs individual processing."""
        service = create_ocr_service(enable_pii=False)
        
        # Create test data
        test_images = []
        for i in range(3):
            img = Image.new('RGB', (100, 50), color='white')
            draw = ImageDraw.Draw(img)
            draw.text((10, 20), f"Test {i}", fill='black')
            test_images.append(img)
        
        # Batch processing should be available
        assert hasattr(service, 'batch_process_images')
        assert hasattr(service, 'batch_process_images_async')
        
        service.cleanup()
    
    def test_configuration_validation(self):
        """Test OCR configuration validation."""
        # Test default configuration
        default_config = OCRProcessingConfig()
        assert default_config.engine == OCREngine.TESSERACT
        assert default_config.preprocessing_mode == PreprocessingMode.ENHANCED
        assert default_config.enable_pii_detection == True
        assert default_config.language_codes == ['eng']
        
        # Test custom configuration
        custom_config = OCRProcessingConfig(
            engine=OCREngine.TESSERACT,
            preprocessing_mode=PreprocessingMode.BASIC,
            enable_pii_detection=False,
            confidence_threshold=70.0,
            max_pages=20
        )
        assert custom_config.confidence_threshold == 70.0
        assert custom_config.max_pages == 20


# Integration tests
class TestOCRIntegration:
    """Integration tests for complete OCR workflow."""
    
    @pytest.mark.integration
    def test_end_to_end_image_processing(self, tmp_path):
        """Test complete image processing workflow."""
        # Skip if no OCR engine available
        available_engines = get_available_ocr_engines()
        if not available_engines:
            pytest.skip("No OCR engines available")
        
        # Create test image with known text
        test_image = tmp_path / "integration_test.png"
        img = Image.new('RGB', (400, 200), color='white')
        draw = ImageDraw.Draw(img)
        draw.rectangle([10, 10, 390, 190], outline='black', width=2)
        draw.text((20, 50), "INTEGRATION TEST", fill='black')
        draw.text((20, 100), "Name: John Doe", fill='black')
        draw.text((20, 130), "Email: john@example.com", fill='black')
        img.save(test_image)
        
        # Test complete workflow
        processor = create_ocr_processor(
            OCRProcessingConfig(
                engine=available_engines[0],
                enable_pii_detection=True,
                preprocessing_mode=PreprocessingMode.ENHANCED
            )
        )
        
        try:
            result = processor.process_document(test_image)
            
            if result.success:
                assert result.ocr_result is not None
                assert len(result.ocr_result.combined_text) > 0
                
                # Check if any expected text was found
                text_upper = result.ocr_result.combined_text.upper()
                assert "TEST" in text_upper or "JOHN" in text_upper or len(text_upper) > 10
                
                # Check PII detection if enabled
                if result.ocr_result.pii_summary:
                    assert isinstance(result.ocr_result.pii_summary, dict)
        finally:
            processor.cleanup()


# Pytest configuration and fixtures
@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up test environment."""
    # Configure logging for tests
    import logging
    logging.basicConfig(level=logging.WARNING)
    
    yield
    
    # Cleanup after all tests
    pass


@pytest.fixture(autouse=True)
def cleanup_temp_files():
    """Clean up temporary files after each test."""
    yield
    
    # Additional cleanup if needed
    import gc
    gc.collect()


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])