"""
Comprehensive Test Suite for Redaction System

This module provides extensive testing for all redaction functionalities including
text redaction, visual redaction, pseudonymization, generalization, and policy-driven redaction.
"""

import pytest
import asyncio
import numpy as np
from PIL import Image
from datetime import datetime
from typing import List
import tempfile
import json

from src.core.config.policies.base import PIIType, RedactionMethod
from src.core.config.policy_models import PolicyContext
from src.core.models.ner_models import PIIEntity
from src.core.models.visual_models import VisualPIIEntity, BoundingBox, VisualPIIType
from src.core.services.redaction_engine import (
    get_redaction_engine, RedactionRequest, RedactionType, 
    RedactionParameters, RedactionIntensity
)
from src.core.services.pseudonymization_service import (
    get_pseudonymization_service, PseudonymizationConfig, 
    GeneralizationConfig, PseudonymizationMethod, GeneralizationLevel
)
from src.core.services.policy_redaction_service import (
    get_policy_redaction_service, PolicyRedactionRequest
)
from src.core.security.compliance_encryption import DataClassification


class TestUnifiedRedactionEngine:
    """Test suite for the unified redaction engine."""
    
    @pytest.fixture
    def redaction_engine(self):
        return get_redaction_engine()
    
    @pytest.fixture
    def sample_text(self):
        return "John Doe's phone number is (555) 123-4567 and his email is john@example.com"
    
    @pytest.fixture
    def sample_entities(self):
        return [
            PIIEntity(
                text="John Doe",
                entity_type=PIIType.NAME,
                start=0,
                end=8,
                confidence=0.95
            ),
            PIIEntity(
                text="(555) 123-4567",
                entity_type=PIIType.PHONE,
                start=30,
                end=44,
                confidence=0.90
            ),
            PIIEntity(
                text="john@example.com",
                entity_type=PIIType.EMAIL,
                start=64,
                end=80,
                confidence=0.92
            )
        ]
    
    def test_text_redaction_delete(self, redaction_engine, sample_text, sample_entities):
        """Test text redaction with DELETE method."""
        parameters = RedactionParameters(
            method=RedactionMethod.DELETE,
            intensity=RedactionIntensity.MAXIMUM
        )
        
        request = RedactionRequest(
            redaction_type=RedactionType.TEXT,
            content=sample_text,
            entities=sample_entities,
            parameters=parameters
        )
        
        result = redaction_engine.redact(request)
        
        assert result.success
        assert result.redacted_content is not None
        assert "John Doe" not in result.redacted_content
        assert "(555) 123-4567" not in result.redacted_content
        assert "john@example.com" not in result.redacted_content
        assert len(result.entities_redacted) == 3
    
    def test_text_redaction_mask_asterisk(self, redaction_engine, sample_text, sample_entities):
        """Test text redaction with MASK_ASTERISK method."""
        parameters = RedactionParameters(
            method=RedactionMethod.MASK_ASTERISK,
            intensity=RedactionIntensity.MEDIUM,
            preserve_length=True
        )
        
        request = RedactionRequest(
            redaction_type=RedactionType.TEXT,
            content=sample_text,
            entities=sample_entities,
            parameters=parameters
        )
        
        result = redaction_engine.redact(request)
        
        assert result.success
        assert "*" in result.redacted_content
        assert "John Doe" not in result.redacted_content
        assert len(result.entities_redacted) == 3
    
    def test_text_redaction_partial_mask(self, redaction_engine, sample_text, sample_entities):
        """Test text redaction with PARTIAL_MASK method."""
        parameters = RedactionParameters(
            method=RedactionMethod.PARTIAL_MASK,
            intensity=RedactionIntensity.MEDIUM
        )
        
        request = RedactionRequest(
            redaction_type=RedactionType.TEXT,
            content=sample_text,
            entities=sample_entities,
            parameters=parameters
        )
        
        result = redaction_engine.redact(request)
        
        assert result.success
        assert result.redacted_content is not None
        # Should show some original characters with masking
        assert "*" in result.redacted_content
        assert len(result.entities_redacted) == 3
    
    def test_text_redaction_placeholder(self, redaction_engine, sample_text, sample_entities):
        """Test text redaction with PLACEHOLDER method."""
        parameters = RedactionParameters(
            method=RedactionMethod.PLACEHOLDER,
            custom_placeholder="[HIDDEN]"
        )
        
        request = RedactionRequest(
            redaction_type=RedactionType.TEXT,
            content=sample_text,
            entities=sample_entities,
            parameters=parameters
        )
        
        result = redaction_engine.redact(request)
        
        assert result.success
        assert "[HIDDEN]" in result.redacted_content
        assert "John Doe" not in result.redacted_content
        assert len(result.entities_redacted) == 3
    
    def test_visual_redaction_blackout(self, redaction_engine):
        """Test visual redaction with BLACKOUT method."""
        # Create test image
        test_image = np.random.randint(0, 255, (100, 150, 3), dtype=np.uint8)
        
        # Create visual entity
        visual_entity = VisualPIIEntity(
            entity_type=VisualPIIType.FACE,
            confidence=0.95,
            bounding_box=BoundingBox(x=20, y=30, width=40, height=50)
        )
        
        parameters = RedactionParameters(
            method=RedactionMethod.BLACKOUT,
            intensity=RedactionIntensity.MAXIMUM,
            color=(0, 0, 0)
        )
        
        request = RedactionRequest(
            redaction_type=RedactionType.VISUAL,
            content=test_image,
            entities=[visual_entity],
            parameters=parameters
        )
        
        result = redaction_engine.redact(request)
        
        assert result.success
        assert result.redacted_content is not None
        assert result.redacted_content.shape == test_image.shape
        assert len(result.entities_redacted) == 1
        
        # Check that redacted region is black
        redacted_region = result.redacted_content[30:80, 20:60]  # y:y+height, x:x+width
        assert np.all(redacted_region == 0)  # Should be black
    
    def test_visual_redaction_blur(self, redaction_engine):
        """Test visual redaction with BLUR method."""
        # Create test image with distinct pattern
        test_image = np.zeros((100, 150, 3), dtype=np.uint8)
        test_image[30:80, 20:60] = 255  # White rectangle
        
        visual_entity = VisualPIIEntity(
            entity_type=VisualPIIType.SIGNATURE,
            confidence=0.90,
            bounding_box=BoundingBox(x=20, y=30, width=40, height=50)
        )
        
        parameters = RedactionParameters(
            method=RedactionMethod.BLUR,
            intensity=RedactionIntensity.HIGH
        )
        
        request = RedactionRequest(
            redaction_type=RedactionType.VISUAL,
            content=test_image,
            entities=[visual_entity],
            parameters=parameters
        )
        
        result = redaction_engine.redact(request)
        
        assert result.success
        assert result.redacted_content is not None
        assert len(result.entities_redacted) == 1
        
        # Check that region is blurred (values should be between 0 and 255, not exactly 255)
        redacted_region = result.redacted_content[30:80, 20:60]
        assert not np.all(redacted_region == 255)  # Should not be pure white anymore
        assert not np.all(redacted_region == 0)    # Should not be pure black
    
    @pytest.mark.asyncio
    async def test_async_redaction(self, redaction_engine, sample_text, sample_entities):
        """Test asynchronous redaction."""
        parameters = RedactionParameters(
            method=RedactionMethod.REDACTED_LABEL,
            intensity=RedactionIntensity.MEDIUM
        )
        
        request = RedactionRequest(
            redaction_type=RedactionType.TEXT,
            content=sample_text,
            entities=sample_entities,
            parameters=parameters
        )
        
        result = await redaction_engine.redact_async(request)
        
        assert result.success
        assert "[REDACTED]" in result.redacted_content
        assert len(result.entities_redacted) == 3
    
    def test_redaction_validation_errors(self, redaction_engine):
        """Test redaction request validation."""
        # Empty content
        request = RedactionRequest(
            redaction_type=RedactionType.TEXT,
            content="",
            entities=[],
            parameters=RedactionParameters(method=RedactionMethod.DELETE)
        )
        
        errors = redaction_engine.validate_request(request)
        assert "Content is required" in errors
        assert "At least one entity is required" in errors
        
        # Wrong content type for text redaction
        request = RedactionRequest(
            redaction_type=RedactionType.TEXT,
            content=123,  # Should be string
            entities=[PIIEntity(text="test", entity_type=PIIType.NAME, start=0, end=4, confidence=0.8)],
            parameters=RedactionParameters(method=RedactionMethod.DELETE)
        )
        
        errors = redaction_engine.validate_request(request)
        assert "Text redaction requires string content" in errors


class TestPseudonymizationService:
    """Test suite for pseudonymization and generalization service."""
    
    @pytest.fixture
    def pseudonymization_service(self):
        return get_pseudonymization_service()
    
    def test_name_pseudonymization(self, pseudonymization_service):
        """Test name pseudonymization."""
        config = PseudonymizationConfig(
            method=PseudonymizationMethod.CONSISTENT_HASH,
            preserve_format=True
        )
        
        result = pseudonymization_service.pseudonymize(
            "John Smith", PIIType.NAME, config
        )
        
        assert result.success
        assert result.anonymized_value != "John Smith"
        assert result.anonymized_value in pseudonymization_service.pseudonym_generator.fake_names
        
        # Test consistency - same input should give same output
        result2 = pseudonymization_service.pseudonymize(
            "John Smith", PIIType.NAME, config
        )
        assert result.anonymized_value == result2.anonymized_value
    
    def test_email_pseudonymization(self, pseudonymization_service):
        """Test email pseudonymization."""
        config = PseudonymizationConfig(
            method=PseudonymizationMethod.DETERMINISTIC_MAPPING,
            preserve_format=True
        )
        
        result = pseudonymization_service.pseudonymize(
            "user@company.com", PIIType.EMAIL, config
        )
        
        assert result.success
        assert result.anonymized_value != "user@company.com"
        assert "@" in result.anonymized_value
        assert result.anonymized_value.endswith(
            tuple(pseudonymization_service.pseudonym_generator.fake_domains)
        )
    
    def test_phone_pseudonymization(self, pseudonymization_service):
        """Test phone number pseudonymization."""
        config = PseudonymizationConfig(
            method=PseudonymizationMethod.FORMAT_PRESERVING,
            preserve_format=True
        )
        
        result = pseudonymization_service.pseudonymize(
            "(555) 123-4567", PIIType.PHONE, config
        )
        
        assert result.success
        assert result.anonymized_value != "(555) 123-4567"
        assert "(" in result.anonymized_value
        assert ")" in result.anonymized_value
        assert "-" in result.anonymized_value
    
    def test_age_generalization(self, pseudonymization_service):
        """Test age generalization."""
        config = GeneralizationConfig(
            level=GeneralizationLevel.MODERATE,
            preserve_utility=True
        )
        
        # Test various ages
        test_cases = [
            ("25", "25-54"),
            ("17", "Under 25"),
            ("65", "55+"),
            ("35", "25-54")
        ]
        
        for age, expected_category in test_cases:
            result = pseudonymization_service.generalize(age, PIIType.AGE, config)
            assert result.success
            assert result.anonymized_value == expected_category
    
    def test_income_generalization(self, pseudonymization_service):
        """Test income generalization."""
        config = GeneralizationConfig(
            level=GeneralizationLevel.MINIMAL,
            preserve_utility=True
        )
        
        test_cases = [
            ("25000", "Under $30K"),
            ("45000", "$30K-$60K"),
            ("75000", "$60K-$100K"),
            ("150000", "Over $100K")
        ]
        
        for income, expected_bracket in test_cases:
            result = pseudonymization_service.generalize(income, PIIType.INCOME, config)
            assert result.success
            assert result.anonymized_value == expected_bracket
    
    def test_date_generalization(self, pseudonymization_service):
        """Test date generalization."""
        config = GeneralizationConfig(
            level=GeneralizationLevel.MODERATE,
            preserve_utility=True
        )
        
        result = pseudonymization_service.generalize(
            "1990-05-15", PIIType.DATE_OF_BIRTH, config
        )
        
        assert result.success
        assert result.anonymized_value == "1990"  # Should generalize to year only
    
    def test_mapping_cache(self, pseudonymization_service):
        """Test pseudonymization mapping cache functionality."""
        config = PseudonymizationConfig(consistency_key="test_key")
        
        # Clear cache first
        pseudonymization_service.clear_mapping_cache()
        
        # First pseudonymization
        result1 = pseudonymization_service.pseudonymize("Test Name", PIIType.NAME, config)
        
        # Second pseudonymization with same input should return same result
        result2 = pseudonymization_service.pseudonymize("Test Name", PIIType.NAME, config)
        
        assert result1.anonymized_value == result2.anonymized_value
        
        # Check cache stats
        stats = pseudonymization_service.get_mapping_stats()
        assert stats["total_mappings"] > 0
    
    def test_export_import_mappings(self, pseudonymization_service):
        """Test exporting and importing pseudonymization mappings."""
        config = PseudonymizationConfig(consistency_key="export_test")
        
        # Generate some mappings
        pseudonymization_service.pseudonymize("John Doe", PIIType.NAME, config)
        pseudonymization_service.pseudonymize("jane@test.com", PIIType.EMAIL, config)
        
        # Export mappings
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            export_path = f.name
        
        success = pseudonymization_service.export_mappings(
            Path(export_path), encrypted=False
        )
        assert success
        
        # Clear cache
        original_mappings = pseudonymization_service.mapping_cache.copy()
        pseudonymization_service.clear_mapping_cache()
        
        # Import mappings
        success = pseudonymization_service.import_mappings(
            Path(export_path), encrypted=False
        )
        assert success
        
        # Verify mappings are restored
        for key, value in original_mappings.items():
            assert pseudonymization_service.mapping_cache.get(key) == value
        
        # Clean up
        Path(export_path).unlink()


class TestPolicyRedactionService:
    """Test suite for policy-driven redaction service."""
    
    @pytest.fixture
    def policy_redaction_service(self):
        return get_policy_redaction_service()
    
    @pytest.fixture
    def sample_context(self):
        return PolicyContext(
            user_id="test_user",
            document_type="medical_record",
            compliance_standard="HIPAA",
            processing_purpose="redaction_test",
            data_classification=DataClassification.CONFIDENTIAL.value,
            geographic_location="US"
        )
    
    @pytest.fixture
    def sample_entities(self):
        return [
            PIIEntity(
                text="John Patient",
                entity_type=PIIType.NAME,
                start=0,
                end=12,
                confidence=0.95
            ),
            PIIEntity(
                text="123-45-6789",
                entity_type=PIIType.SSN,
                start=25,
                end=36,
                confidence=0.98
            )
        ]
    
    def test_policy_redaction_request_validation(self, policy_redaction_service, sample_context, sample_entities):
        """Test policy redaction request validation."""
        # Valid request
        request = PolicyRedactionRequest(
            request_id="test_123",
            content="John Patient's SSN is 123-45-6789",
            entities=sample_entities,
            context=sample_context,
            redaction_type=RedactionType.TEXT
        )
        
        errors = policy_redaction_service.validate_redaction_request(request)
        assert len(errors) == 0
        
        # Invalid request - empty content
        request.content = ""
        errors = policy_redaction_service.validate_redaction_request(request)
        assert "Content is required" in errors
        
        # Invalid request - no entities
        request.content = "Valid content"
        request.entities = []
        errors = policy_redaction_service.validate_redaction_request(request)
        assert "At least one entity is required" in errors
    
    @pytest.mark.asyncio
    async def test_policy_driven_redaction(self, policy_redaction_service, sample_context, sample_entities):
        """Test policy-driven redaction execution."""
        request = PolicyRedactionRequest(
            request_id="policy_test_001",
            content="John Patient's SSN is 123-45-6789",
            entities=sample_entities,
            context=sample_context,
            redaction_type=RedactionType.TEXT
        )
        
        result = await policy_redaction_service.redact_with_policy_async(request)
        
        assert result.success
        assert result.redacted_content is not None
        assert result.redacted_content != request.content
        assert len(result.policy_decisions) > 0
        assert result.processing_time_seconds > 0
    
    def test_redaction_preview(self, policy_redaction_service, sample_context, sample_entities):
        """Test redaction preview functionality."""
        request = PolicyRedactionRequest(
            request_id="preview_test",
            content="John Patient's SSN is 123-45-6789",
            entities=sample_entities,
            context=sample_context,
            redaction_type=RedactionType.TEXT
        )
        
        preview = policy_redaction_service.get_redaction_preview(
            request, include_policy_details=True
        )
        
        assert preview["success"] == True
        assert preview["total_entities"] == len(sample_entities)
        assert "redaction_methods" in preview
        assert "applied_policies" in preview
    
    def test_service_stats(self, policy_redaction_service):
        """Test service statistics retrieval."""
        stats = policy_redaction_service.get_service_stats()
        
        assert "policy_engine_stats" in stats
        assert "redaction_engine_stats" in stats
        assert "pseudonymization_stats" in stats


class TestRedactionAPI:
    """Test suite for redaction API endpoints (would require FastAPI test client)."""
    
    # These tests would require setting up a test client
    # and are placeholder examples of what comprehensive API tests would look like
    
    def test_get_redaction_methods_endpoint(self):
        """Test GET /redaction/methods endpoint."""
        # This would use FastAPI TestClient
        pass
    
    def test_text_redaction_endpoint(self):
        """Test POST /redaction/text endpoint."""
        pass
    
    def test_visual_redaction_endpoint(self):
        """Test POST /redaction/visual endpoint."""
        pass
    
    def test_policy_driven_redaction_endpoint(self):
        """Test POST /redaction/policy-driven endpoint."""
        pass
    
    def test_pseudonymization_endpoint(self):
        """Test POST /redaction/pseudonymize endpoint."""
        pass


class TestRedactionPerformance:
    """Performance tests for redaction system."""
    
    @pytest.fixture
    def large_text_sample(self):
        """Generate large text sample for performance testing."""
        base_text = "John Doe works at Acme Corp. His email is john@acme.com and phone is (555) 123-4567. "
        return base_text * 100  # Repeat 100 times
    
    @pytest.fixture
    def many_entities(self):
        """Generate many entities for performance testing."""
        entities = []
        base_text = "John Doe works at Acme Corp. His email is john@acme.com and phone is (555) 123-4567. "
        
        for i in range(100):
            offset = i * len(base_text)
            entities.extend([
                PIIEntity(
                    text="John Doe",
                    entity_type=PIIType.NAME,
                    start=offset,
                    end=offset + 8,
                    confidence=0.95
                ),
                PIIEntity(
                    text="john@acme.com",
                    entity_type=PIIType.EMAIL,
                    start=offset + 41,
                    end=offset + 54,
                    confidence=0.90
                ),
                PIIEntity(
                    text="(555) 123-4567",
                    entity_type=PIIType.PHONE,
                    start=offset + 68,
                    end=offset + 82,
                    confidence=0.92
                )
            ])
        
        return entities
    
    def test_large_text_redaction_performance(self, large_text_sample, many_entities):
        """Test redaction performance with large text and many entities."""
        redaction_engine = get_redaction_engine()
        
        parameters = RedactionParameters(
            method=RedactionMethod.REDACTED_LABEL,
            intensity=RedactionIntensity.MEDIUM
        )
        
        request = RedactionRequest(
            redaction_type=RedactionType.TEXT,
            content=large_text_sample,
            entities=many_entities,
            parameters=parameters
        )
        
        import time
        start_time = time.time()
        result = redaction_engine.redact(request)
        end_time = time.time()
        
        processing_time = end_time - start_time
        
        assert result.success
        assert processing_time < 5.0  # Should complete within 5 seconds
        assert len(result.entities_redacted) > 0
        
        print(f"Processed {len(many_entities)} entities in {processing_time:.2f} seconds")
    
    def test_concurrent_redaction_performance(self):
        """Test concurrent redaction requests."""
        import concurrent.futures
        import threading
        
        redaction_engine = get_redaction_engine()
        
        def single_redaction(request_id):
            entities = [
                PIIEntity(
                    text="Test Name",
                    entity_type=PIIType.NAME,
                    start=0,
                    end=9,
                    confidence=0.95
                )
            ]
            
            request = RedactionRequest(
                redaction_type=RedactionType.TEXT,
                content="Test Name is redacted",
                entities=entities,
                parameters=RedactionParameters(method=RedactionMethod.REDACTED_LABEL)
            )
            
            result = redaction_engine.redact(request)
            return result.success
        
        # Test with 10 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(single_redaction, i) for i in range(10)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # All requests should succeed
        assert all(results)
        assert len(results) == 10


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])