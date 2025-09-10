#!/usr/bin/env python3
"""
Basic verification test for PII Detection Module

This script performs basic functionality tests to verify the PII detection
implementation is working correctly.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

import asyncio
from datetime import datetime

# Ensure UTF-8 encoding for Windows
import locale
sys.stdout.reconfigure(encoding='utf-8')

# Test sample text with various PII types
SAMPLE_TEXT = """
John Smith is a patient at Metro Hospital. His SSN is 123-45-6789 and his email 
is john.smith@email.com. He can be reached at (555) 123-4567. His address is 
123 Main Street, New York, NY 10001.
"""

def test_imports():
    """Test that all modules can be imported correctly."""
    print("Testing imports...")
    
    try:
        from src.core.models.ner_models import PIIEntity, PresidioNERModel, create_ner_model
        print("OK NER models imported successfully")
        
        from src.core.services.pii_detector import PIIDetectionService, PIIDetectionResult
        print("OK PII detection service imported successfully")
        
        from src.core.config.policies.base import PIIType, RedactionMethod
        print("OK Policy base classes imported successfully")
        
        from src.core.security.compliance_encryption import ComplianceStandard, DataClassification
        print("OK Compliance encryption imported successfully")
        
        return True
    except Exception as e:
        print(f"FAIL Import failed: {e}")
        return False

def test_pii_entity():
    """Test PIIEntity dataclass functionality."""
    print("\nTesting PIIEntity...")
    
    try:
        from src.core.models.ner_models import PIIEntity, EntityConfidence
        
        entity = PIIEntity(
            entity_type="PERSON",
            text="John Smith",
            start=0,
            end=10,
            confidence=0.95,
            confidence_level=EntityConfidence.LOW,  # Will be updated in __post_init__
            recognizer_name="test"
        )
        
        assert entity.entity_type == "PERSON"
        assert entity.text == "John Smith"
        assert entity.confidence_level == EntityConfidence.VERY_HIGH  # Should be updated
        assert entity.metadata == {}
        
        print("OK PIIEntity creation and confidence mapping works correctly")
        return True
    except Exception as e:
        print(f"FAIL PIIEntity test failed: {e}")
        return False

def test_ner_model_creation():
    """Test NER model creation."""
    print("\nTesting NER model creation...")
    
    try:
        from src.core.models.ner_models import create_ner_model, PresidioNERModel, SpacyNERModel
        
        # Test Presidio model creation
        presidio_model = create_ner_model("presidio", language="en")
        assert isinstance(presidio_model, PresidioNERModel)
        assert presidio_model.language == "en"
        print("OK Presidio model creation works")
        
        # Test spaCy model creation
        spacy_model = create_ner_model("spacy", language="en")
        assert isinstance(spacy_model, SpacyNERModel)
        assert spacy_model.language == "en"
        print("OK spaCy model creation works")
        
        return True
    except Exception as e:
        print(f"FAIL NER model creation test failed: {e}")
        return False

def test_detection_service():
    """Test PII detection service."""
    print("\nTesting PII Detection Service...")
    
    try:
        from src.core.services.pii_detector import PIIDetectionService, DetectionStatus
        
        service = PIIDetectionService()
        assert service is not None
        print("OK PII Detection Service created successfully")
        
        # Test service statistics
        stats = service.get_service_statistics()
        assert "total_detections" in stats
        assert "active_detections" in stats
        print("OK Service statistics retrieval works")
        
        return True
    except Exception as e:
        print(f"FAIL Detection service test failed: {e}")
        return False

def test_detection_result():
    """Test detection result functionality."""
    print("\nTesting PIIDetectionResult...")
    
    try:
        from src.core.services.pii_detector import PIIDetectionResult, DetectionStatus, RiskLevel
        from src.core.models.ner_models import PIIEntity, EntityConfidence
        
        # Create sample entities
        entities = [
            PIIEntity(
                entity_type="ssn", text="123-45-6789", start=0, end=11,
                confidence=0.99, confidence_level=EntityConfidence.VERY_HIGH,
                recognizer_name="test"
            ),
            PIIEntity(
                entity_type="name", text="John Smith", start=20, end=30,
                confidence=0.85, confidence_level=EntityConfidence.HIGH,
                recognizer_name="test"
            )
        ]
        
        result = PIIDetectionResult(
            detection_id="test-123",
            entities=entities,
            status=DetectionStatus.COMPLETED
        )
        
        assert result.entity_count == 2
        assert result.risk_level == RiskLevel.CRITICAL  # Due to SSN
        assert len(result.unique_entity_types) == 2
        print("OK PIIDetectionResult creation and risk calculation works")
        
        # Test serialization
        result_dict = result.to_dict()
        assert "detection_id" in result_dict
        assert "entities" in result_dict
        print("OK PIIDetectionResult serialization works")
        
        return True
    except Exception as e:
        print(f"FAIL Detection result test failed: {e}")
        return False

def test_compliance_integration():
    """Test compliance framework integration."""
    print("\nTesting Compliance Integration...")
    
    try:
        from src.core.security.compliance_encryption import (
            ComplianceStandard, DataClassification, ComplianceMetadata
        )
        
        metadata = ComplianceMetadata(
            classification=DataClassification.RESTRICTED,
            standards=[ComplianceStandard.HIPAA, ComplianceStandard.GDPR],
            retention_period_days=2190,
            encryption_required=True,
            audit_required=True
        )
        
        assert metadata.classification == DataClassification.RESTRICTED
        assert ComplianceStandard.HIPAA in metadata.standards
        assert metadata.retention_period_days == 2190
        print("OK Compliance metadata creation works")
        
        return True
    except Exception as e:
        print(f"FAIL Compliance integration test failed: {e}")
        return False

def main():
    """Run all basic tests."""
    print("=== PII Detection Module - Basic Verification Tests ===")
    print(f"Started at: {datetime.now()}")
    
    tests = [
        test_imports,
        test_pii_entity,
        test_ner_model_creation,
        test_detection_service,
        test_detection_result,
        test_compliance_integration
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        else:
            print("Continuing with next test...")
    
    print(f"\n=== Test Results ===")
    print(f"Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("SUCCESS All basic verification tests passed!")
        return 0
    else:
        print("WARNING Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())