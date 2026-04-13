"""
Document Processing Pipeline for PII De-identification System

This module provides multi-format document processing capabilities including
PDF extraction, image processing, scanned document optimization, OCR processing,
comprehensive spaCy NLP analysis, and integrated PII detection.
"""

from .document_factory import DocumentFactory
from .pdf_processor import PDFProcessor
from .image_processor import ImageProcessor
from .scanner_processor import ScannerProcessor
from .ocr_processor import (
    OCRProcessor, OCRProcessingConfig, OCRProcessingResult, 
    DocumentType, PreprocessingMode, create_ocr_processor, quick_document_ocr
)
from .spacy_processor import (
    SpacyProcessor, SpacyProcessingConfig, SpacyAnalysisResult,
    LanguageSupport, TextComplexity, DocumentStructure, LinguisticToken,
    LinguisticSentence, LanguageDetectionResult, create_spacy_processor,
    quick_language_detection, quick_linguistic_analysis
)
from .document_pii_processor import (
    DocumentPIIProcessor, PIIProcessingOptions, PIIProcessingMode,
    PIIDocumentResult, get_document_pii_processor, 
    quick_document_pii_analysis, quick_document_pii_analysis_sync
)

__all__ = [
    "DocumentFactory",
    "PDFProcessor", 
    "ImageProcessor",
    "ScannerProcessor",
    "OCRProcessor",
    "OCRProcessingConfig",
    "OCRProcessingResult",
    "DocumentType",
    "PreprocessingMode",
    "create_ocr_processor",
    "quick_document_ocr",
    "SpacyProcessor",
    "SpacyProcessingConfig",
    "SpacyAnalysisResult",
    "LanguageSupport",
    "TextComplexity",
    "DocumentStructure",
    "LinguisticToken",
    "LinguisticSentence", 
    "LanguageDetectionResult",
    "create_spacy_processor",
    "quick_language_detection",
    "quick_linguistic_analysis",
    "DocumentPIIProcessor",
    "PIIProcessingOptions",
    "PIIProcessingMode",
    "PIIDocumentResult",
    "get_document_pii_processor",
    "quick_document_pii_analysis",
    "quick_document_pii_analysis_sync"
]