"""
Comprehensive Unit Tests for PII Detection Service

Tests the core PII detection functionality including NER models,
detection algorithms, confidence scoring, and error handling.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Test utilities
from tests.utils import TestDataFactory, MockHelper, AssertionHelper

# Application imports
from src.core.services.pii_detector import (
    PIIDetectionService, PIIDetectionResult, DetectionStatus, RiskLevel
)
from src.core.models.ner_models import (
    PIIEntity, EntityConfidence, PresidioNERModel, SpacyNERModel
)
from src.core.config.policies.base import PIIType, RedactionMethod


class TestPIIDetectionService:
    """Test suite for PII Detection Service."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.mock_model_manager = MockHelper.create_mock_model_manager()
        self.detector = PIIDetectionService(model_manager=self.mock_model_manager)
        self.test_data_factory = TestDataFactory()
        self.assertion_helper = AssertionHelper()
    
    @pytest.mark.unit
    def test_initialization(self):
        """Test service initialization."""
        assert self.detector is not None
        assert self.detector.model_manager is not None
        assert hasattr(self.detector, 'confidence_threshold')
        assert self.detector.confidence_threshold >= 0.0
        assert self.detector.confidence_threshold <= 1.0
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detect_pii_basic(self):
        """Test basic PII detection functionality."""
        # Arrange
        test_text = self.test_data_factory.create_pii_text(['PERSON', 'EMAIL'])
        
        # Mock model response
        mock_entities = [
            PIIEntity(
                text="John Smith",
                label="PERSON",
                start=0,
                end=10,
                confidence=0.95
            ),
            PIIEntity(
                text="john.smith@email.com",
                label="EMAIL",
                start=20,
                end=40,
                confidence=0.88
            )
        ]
        
        with patch.object(self.detector, '_extract_entities', return_value=mock_entities):
            # Act
            result = await self.detector.detect_pii(test_text)
        
        # Assert
        assert isinstance(result, dict)
        self.assertion_helper.assert_pii_detected(result, expected_count=2)
        assert result['risk_level'] in ['low', 'medium', 'high']
        assert 'processing_time' in result
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detect_pii_empty_text(self):
        """Test PII detection with empty text."""
        # Act & Assert
        with pytest.raises(ValueError, match="Text cannot be empty"):
            await self.detector.detect_pii("")
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detect_pii_whitespace_only(self):
        """Test PII detection with whitespace-only text."""
        # Act & Assert
        with pytest.raises(ValueError, match="Text cannot be empty"):
            await self.detector.detect_pii("   \n\t   ")
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detect_pii_no_entities(self):
        """Test PII detection with text containing no PII."""
        # Arrange
        clean_text = "This is a clean document with no personal information."
        
        with patch.object(self.detector, '_extract_entities', return_value=[]):
            # Act
            result = await self.detector.detect_pii(clean_text)
        
        # Assert
        assert result['entities'] == []
        assert result['total_entities'] == 0
        assert result['risk_level'] == 'low'
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detect_pii_confidence_filtering(self):
        """Test confidence threshold filtering."""
        # Arrange
        test_text = "John Smith works at Company Inc."
        
        mock_entities = [
            PIIEntity(text="John Smith", label="PERSON", start=0, end=10, confidence=0.95),
            PIIEntity(text="Company Inc", label="ORG", start=20, end=31, confidence=0.60)  # Below threshold
        ]
        
        self.detector.confidence_threshold = 0.8
        
        with patch.object(self.detector, '_extract_entities', return_value=mock_entities):
            # Act
            result = await self.detector.detect_pii(test_text)
        
        # Assert
        # Only high-confidence entity should be included
        assert len(result['entities']) == 1
        assert result['entities'][0]['text'] == "John Smith"
        assert result['entities'][0]['confidence'] >= 0.8
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detect_pii_risk_assessment(self):
        """Test risk level assessment based on entity types and count."""
        test_cases = [
            {
                'entities': [
                    PIIEntity(text="John", label="PERSON", start=0, end=4, confidence=0.9)
                ],
                'expected_risk': 'low'
            },
            {
                'entities': [
                    PIIEntity(text="John Smith", label="PERSON", start=0, end=10, confidence=0.9),
                    PIIEntity(text="john@email.com", label="EMAIL", start=15, end=30, confidence=0.9),
                    PIIEntity(text="555-1234", label="PHONE", start=35, end=43, confidence=0.9)
                ],
                'expected_risk': 'medium'
            },
            {
                'entities': [
                    PIIEntity(text="John Smith", label="PERSON", start=0, end=10, confidence=0.9),
                    PIIEntity(text="123-45-6789", label="SSN", start=15, end=26, confidence=0.9),
                    PIIEntity(text="4111-1111-1111-1111", label="CREDIT_CARD", start=30, end=49, confidence=0.9),
                    PIIEntity(text="DOB: 01/01/1990", label="DATE_OF_BIRTH", start=55, end=70, confidence=0.9)
                ],
                'expected_risk': 'high'
            }
        ]
        
        for test_case in test_cases:
            with patch.object(self.detector, '_extract_entities', return_value=test_case['entities']):
                result = await self.detector.detect_pii("test text")
                assert result['risk_level'] == test_case['expected_risk']
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detect_pii_with_context(self):
        """Test PII detection with context analysis."""
        # Arrange
        medical_text = """
        Patient: John Smith
        DOB: 01/15/1990
        Diagnosis: Type 2 Diabetes
        Treatment: Metformin 500mg
        """
        
        mock_entities = [
            PIIEntity(text="John Smith", label="PERSON", start=17, end=27, confidence=0.9),
            PIIEntity(text="01/15/1990", label="DATE_OF_BIRTH", start=38, end=48, confidence=0.85)
        ]
        
        with patch.object(self.detector, '_extract_entities', return_value=mock_entities):
            with patch.object(self.detector, '_analyze_context', return_value={'domain': 'healthcare', 'sensitivity': 'high'}):
                # Act
                result = await self.detector.detect_pii(medical_text, include_context=True)
        
        # Assert
        assert 'context' in result
        assert result['context']['domain'] == 'healthcare'
        assert result['context']['sensitivity'] == 'high'
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detect_pii_multilingual(self):
        """Test PII detection with multilingual text."""
        # Arrange - Hindi text with PII
        hindi_text = "मेरा नाम राम शर्मा है और मेरा ईमेल ram.sharma@email.com है।"
        
        mock_entities = [
            PIIEntity(text="राम शर्मा", label="PERSON", start=8, end=16, confidence=0.88),
            PIIEntity(text="ram.sharma@email.com", label="EMAIL", start=35, end=55, confidence=0.92)
        ]
        
        with patch.object(self.detector, '_extract_entities', return_value=mock_entities):
            # Act
            result = await self.detector.detect_pii(hindi_text, language='hi')
        
        # Assert
        assert len(result['entities']) == 2
        assert result['entities'][0]['label'] == 'PERSON'
        assert result['entities'][1]['label'] == 'EMAIL'
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detect_pii_custom_entities(self):
        """Test detection of custom entity types."""
        # Arrange
        text_with_custom = "Employee ID: EMP-12345, Badge: BDG-67890"
        
        mock_entities = [
            PIIEntity(text="EMP-12345", label="EMPLOYEE_ID", start=13, end=22, confidence=0.9),
            PIIEntity(text="BDG-67890", label="BADGE_ID", start=31, end=40, confidence=0.85)
        ]
        
        custom_entity_types = ["EMPLOYEE_ID", "BADGE_ID"]
        
        with patch.object(self.detector, '_extract_entities', return_value=mock_entities):
            # Act
            result = await self.detector.detect_pii(
                text_with_custom,
                entity_types=custom_entity_types
            )
        
        # Assert
        assert len(result['entities']) == 2
        assert all(e['label'] in custom_entity_types for e in result['entities'])
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detect_pii_performance_metrics(self):
        """Test performance metrics collection."""
        # Arrange
        test_text = self.test_data_factory.create_pii_text()
        
        with patch.object(self.detector, '_extract_entities', return_value=[]):
            # Act
            result = await self.detector.detect_pii(test_text)
        
        # Assert
        assert 'processing_time' in result
        assert isinstance(result['processing_time'], float)
        assert result['processing_time'] >= 0
        
        if 'performance_metrics' in result:
            metrics = result['performance_metrics']
            assert 'model_inference_time' in metrics
            assert 'post_processing_time' in metrics
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detect_pii_batch_processing(self):
        """Test batch processing of multiple texts."""
        # Arrange
        text_batch = [
            self.test_data_factory.create_pii_text(['PERSON']),
            self.test_data_factory.create_pii_text(['EMAIL']),
            self.test_data_factory.create_pii_text(['PHONE_NUMBER'])
        ]
        
        with patch.object(self.detector, 'detect_pii') as mock_detect:
            mock_detect.side_effect = [
                {'entities': [{'label': 'PERSON'}], 'risk_level': 'low'},
                {'entities': [{'label': 'EMAIL'}], 'risk_level': 'low'},
                {'entities': [{'label': 'PHONE_NUMBER'}], 'risk_level': 'low'}
            ]
            
            # Act
            results = await self.detector.detect_pii_batch(text_batch)
        
        # Assert
        assert len(results) == 3
        assert all('entities' in result for result in results)
        assert mock_detect.call_count == 3
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_model_fallback(self):
        """Test model fallback mechanism."""
        # Arrange
        test_text = "John Smith is a patient."
        
        # Simulate primary model failure
        with patch.object(self.detector.model_manager, 'get_spacy_model', side_effect=Exception("Model not loaded")):
            with patch.object(self.detector, '_use_fallback_detection', return_value=[]) as mock_fallback:
                # Act
                result = await self.detector.detect_pii(test_text)
        
        # Assert
        mock_fallback.assert_called_once()
        assert 'entities' in result
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_error_handling_invalid_input(self):
        """Test error handling for invalid input types."""
        # Test None input
        with pytest.raises(TypeError):
            await self.detector.detect_pii(None)
        
        # Test non-string input
        with pytest.raises(TypeError):
            await self.detector.detect_pii(123)
        
        # Test list input
        with pytest.raises(TypeError):
            await self.detector.detect_pii(['text', 'in', 'list'])
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_memory_usage_optimization(self):
        """Test memory usage with large texts."""
        # Arrange - Create large text
        large_text = "John Smith is a patient. " * 10000  # ~250KB text
        
        mock_entities = [
            PIIEntity(text="John Smith", label="PERSON", start=0, end=10, confidence=0.9)
        ] * 10  # Simulate many detections
        
        with patch.object(self.detector, '_extract_entities', return_value=mock_entities):
            # Act
            result = await self.detector.detect_pii(large_text, optimize_memory=True)
        
        # Assert
        assert 'entities' in result
        # Check that results are paginated or limited for memory optimization
        if 'pagination' in result:
            assert 'page_size' in result['pagination']
            assert 'total_pages' in result['pagination']


class TestPIIEntity:
    """Test suite for PIIEntity model."""
    
    @pytest.mark.unit
    def test_pii_entity_creation(self):
        """Test PIIEntity creation and validation."""
        entity = PIIEntity(
            text="John Smith",
            label="PERSON",
            start=0,
            end=10,
            confidence=0.95
        )
        
        assert entity.text == "John Smith"
        assert entity.label == "PERSON"
        assert entity.start == 0
        assert entity.end == 10
        assert entity.confidence == 0.95
    
    @pytest.mark.unit
    def test_pii_entity_confidence_validation(self):
        """Test confidence score validation."""
        # Valid confidence scores
        valid_confidences = [0.0, 0.5, 0.95, 1.0]
        for conf in valid_confidences:
            entity = PIIEntity(
                text="test", label="TEST", start=0, end=4, confidence=conf
            )
            assert entity.confidence == conf
        
        # Invalid confidence scores
        invalid_confidences = [-0.1, 1.1, 2.0, -1.0]
        for conf in invalid_confidences:
            with pytest.raises(ValueError):
                PIIEntity(
                    text="test", label="TEST", start=0, end=4, confidence=conf
                )
    
    @pytest.mark.unit
    def test_pii_entity_position_validation(self):
        """Test position validation."""
        # Valid positions
        entity = PIIEntity(
            text="John", label="PERSON", start=0, end=4, confidence=0.9
        )
        assert entity.start < entity.end
        
        # Invalid positions
        with pytest.raises(ValueError):
            PIIEntity(
                text="John", label="PERSON", start=4, end=0, confidence=0.9
            )
    
    @pytest.mark.unit
    def test_pii_entity_serialization(self):
        """Test entity serialization to dict."""
        entity = PIIEntity(
            text="John Smith",
            label="PERSON",
            start=0,
            end=10,
            confidence=0.95
        )
        
        entity_dict = entity.to_dict()
        
        expected_keys = {'text', 'label', 'start', 'end', 'confidence'}
        assert set(entity_dict.keys()) == expected_keys
        assert entity_dict['text'] == "John Smith"
        assert entity_dict['label'] == "PERSON"


class TestEntityConfidence:
    """Test suite for confidence scoring algorithms."""
    
    @pytest.mark.unit
    def test_confidence_calculation(self):
        """Test confidence score calculation."""
        # Mock model predictions
        predictions = [
            {'label': 'PERSON', 'score': 0.95},
            {'label': 'O', 'score': 0.05}  # Outside entity
        ]
        
        confidence_calc = EntityConfidence()
        score = confidence_calc.calculate_confidence(predictions, 'PERSON')
        
        assert 0 <= score <= 1
        assert score > 0.5  # Should be high for clear prediction
    
    @pytest.mark.unit
    def test_confidence_aggregation(self):
        """Test confidence aggregation from multiple models."""
        model_scores = [0.92, 0.88, 0.94]
        
        confidence_calc = EntityConfidence()
        
        # Test different aggregation methods
        avg_score = confidence_calc.aggregate_confidence(model_scores, method='average')
        assert avg_score == sum(model_scores) / len(model_scores)
        
        max_score = confidence_calc.aggregate_confidence(model_scores, method='max')
        assert max_score == max(model_scores)
        
        min_score = confidence_calc.aggregate_confidence(model_scores, method='min')
        assert min_score == min(model_scores)
    
    @pytest.mark.unit
    def test_confidence_calibration(self):
        """Test confidence calibration for better accuracy."""
        raw_scores = [0.6, 0.7, 0.8, 0.9, 0.95]
        
        confidence_calc = EntityConfidence()
        
        # Test Platt scaling calibration
        calibrated_scores = confidence_calc.calibrate_confidence(
            raw_scores, method='platt_scaling'
        )
        
        assert len(calibrated_scores) == len(raw_scores)
        assert all(0 <= score <= 1 for score in calibrated_scores)


class TestModelIntegration:
    """Test integration between different PII detection models."""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_spacy_model_integration(self):
        """Test spaCy model integration."""
        # Mock spaCy model
        mock_doc = Mock()
        mock_doc.ents = [
            Mock(text="John Smith", label_="PERSON", start_char=0, end_char=10)
        ]
        
        mock_nlp = Mock(return_value=mock_doc)
        
        spacy_model = SpacyNERModel(model=mock_nlp)
        result = await spacy_model.predict("John Smith is here.")
        
        assert len(result) == 1
        assert result[0].text == "John Smith"
        assert result[0].label == "PERSON"
    
    @pytest.mark.unit 
    @pytest.mark.asyncio
    async def test_presidio_model_integration(self):
        """Test Presidio model integration."""
        # Mock Presidio analyzer
        mock_analyzer = Mock()
        mock_analyzer.analyze.return_value = [
            Mock(
                entity_type="EMAIL_ADDRESS",
                start=0,
                end=20,
                score=0.95
            )
        ]
        
        presidio_model = PresidioNERModel(analyzer=mock_analyzer)
        result = await presidio_model.predict("test@example.com is email")
        
        assert len(result) == 1
        assert result[0].label == "EMAIL_ADDRESS"
        assert result[0].confidence == 0.95
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_ensemble_model_prediction(self):
        """Test ensemble model combining multiple predictors."""
        # Mock multiple model predictions
        spacy_results = [
            PIIEntity(text="John", label="PERSON", start=0, end=4, confidence=0.85)
        ]
        
        presidio_results = [
            PIIEntity(text="John Smith", label="PERSON", start=0, end=10, confidence=0.92)
        ]
        
        detector = PIIDetectionService()
        
        with patch.object(detector, '_get_spacy_predictions', return_value=spacy_results):
            with patch.object(detector, '_get_presidio_predictions', return_value=presidio_results):
                # Act
                ensemble_results = await detector._ensemble_predict("John Smith works here")
        
        # Assert - Should combine and deduplicate results
        assert len(ensemble_results) >= 1
        # Check that ensemble improves confidence or coverage
        

class TestPerformanceOptimization:
    """Test performance optimization features."""
    
    @pytest.mark.unit
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_caching_mechanism(self):
        """Test caching of detection results."""
        detector = PIIDetectionService(enable_cache=True)
        test_text = "John Smith is a patient."
        
        # First call should hit the model
        with patch.object(detector, '_extract_entities') as mock_extract:
            mock_extract.return_value = [
                PIIEntity(text="John Smith", label="PERSON", start=0, end=10, confidence=0.9)
            ]
            
            result1 = await detector.detect_pii(test_text)
            result2 = await detector.detect_pii(test_text)  # Should use cache
        
        # Assert model was called only once due to caching
        assert mock_extract.call_count == 1
        assert result1 == result2
    
    @pytest.mark.unit
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_concurrent_processing(self):
        """Test concurrent processing of multiple texts."""
        detector = PIIDetectionService()
        texts = [f"User {i} has email user{i}@example.com" for i in range(10)]
        
        with patch.object(detector, 'detect_pii', return_value={'entities': []}) as mock_detect:
            # Act - Process concurrently
            tasks = [detector.detect_pii(text) for text in texts]
            results = await asyncio.gather(*tasks)
        
        # Assert
        assert len(results) == 10
        assert mock_detect.call_count == 10
    
    @pytest.mark.unit
    @pytest.mark.performance
    def test_memory_efficient_processing(self):
        """Test memory-efficient processing for large documents."""
        detector = PIIDetectionService()
        
        # Create large text
        large_text = "Personal information: John Smith. " * 100000  # ~3.5MB
        
        # Mock chunked processing
        with patch.object(detector, '_process_in_chunks') as mock_chunk:
            mock_chunk.return_value = {'entities': [], 'chunks_processed': 100}
            
            result = detector._process_large_text(large_text, chunk_size=1000)
        
        # Assert chunked processing was used
        mock_chunk.assert_called_once()
        assert 'chunks_processed' in result


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])