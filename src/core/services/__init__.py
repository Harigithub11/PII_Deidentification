"""
Services package for PII De-identification System

This package contains high-level business logic services including:
- PII detection and analysis (text and visual)
- OCR text extraction with PII integration
- Advanced spaCy NLP processing and analysis
- Document processing orchestration
- Compliance policy enforcement
- Unified redaction engine with multiple methods
- Pseudonymization and generalization services
- Policy-driven redaction orchestration
- Audit and reporting services
"""

from .pii_detector import PIIDetectionService, PIIDetectionResult
from .visual_pii_detector import VisualPIIDetectionService, VisualPIIDetectionResult
from .ocr_service import (
    OCRService, OCRDocumentPage, OCRDocumentResult, OCRQuality,
    create_ocr_service, quick_ocr_text_extraction, quick_ocr_text_extraction_sync
)
from .spacy_service import (
    SpacyService, NLPProcessingJob, BatchProcessingResult, StreamProcessingStats,
    ProcessingPriority, create_spacy_service, quick_nlp_analysis
)
from .redaction_engine import (
    get_redaction_engine, UnifiedRedactionEngine, RedactionRequest, RedactionResult,
    RedactionType, RedactionParameters, RedactionIntensity, TextRedactor
)
from .pseudonymization_service import (
    get_pseudonymization_service, PseudonymizationService, 
    PseudonymizationConfig, GeneralizationConfig, AnonymizationResult,
    PseudonymizationMethod, GeneralizationLevel
)
from .policy_redaction_service import (
    get_policy_redaction_service, PolicyRedactionService,
    PolicyRedactionRequest, PolicyRedactionResult
)

__all__ = [
    "PIIDetectionService",
    "PIIDetectionResult",
    "VisualPIIDetectionService",
    "VisualPIIDetectionResult",
    "OCRService",
    "OCRDocumentPage", 
    "OCRDocumentResult",
    "OCRQuality",
    "create_ocr_service",
    "quick_ocr_text_extraction",
    "quick_ocr_text_extraction_sync",
    "SpacyService",
    "NLPProcessingJob",
    "BatchProcessingResult",
    "StreamProcessingStats",
    "ProcessingPriority",
    "create_spacy_service",
    "quick_nlp_analysis",
    
    # Redaction Services
    "get_redaction_engine",
    "UnifiedRedactionEngine",
    "RedactionRequest",
    "RedactionResult",
    "RedactionType",
    "RedactionParameters",
    "RedactionIntensity",
    "TextRedactor",
    
    # Pseudonymization Services
    "get_pseudonymization_service",
    "PseudonymizationService",
    "PseudonymizationConfig",
    "GeneralizationConfig",
    "AnonymizationResult",
    "PseudonymizationMethod",
    "GeneralizationLevel",
    
    # Policy Redaction Services
    "get_policy_redaction_service",
    "PolicyRedactionService",
    "PolicyRedactionRequest",
    "PolicyRedactionResult"
]