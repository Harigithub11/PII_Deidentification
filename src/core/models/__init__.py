"""
Models package for PII De-identification System

This package contains model management and AI model implementations for:
- OCR models (Tesseract, PaddleOCR)
- NER models (spaCy, Presidio)
- Layout analysis models (LayoutLMv3)
- Visual PII detection models (YOLOv8)
- Large Language Models (Mistral 7B)
"""

from .model_manager import ModelManager
from .ner_models import NERModel, PresidioNERModel, SpacyNERModel
from .visual_models import VisualDetectionModel, YOLOv8VisualModel, VisualPIIEntity, BoundingBox
from .ocr_models import (
    OCRModel, TesseractOCRModel, PaddleOCRModel, OCRResult, OCRTextBlock, 
    OCRBoundingBox, OCREngine, LanguageCode, create_tesseract_model, 
    create_paddle_ocr_model, get_default_ocr_model, get_available_ocr_engines
)

__all__ = [
    "ModelManager",
    "NERModel",
    "PresidioNERModel",
    "SpacyNERModel",
    "VisualDetectionModel",
    "YOLOv8VisualModel", 
    "VisualPIIEntity",
    "BoundingBox",
    "OCRModel",
    "TesseractOCRModel",
    "PaddleOCRModel",
    "OCRResult",
    "OCRTextBlock",
    "OCRBoundingBox",
    "OCREngine",
    "LanguageCode",
    "create_tesseract_model",
    "create_paddle_ocr_model",
    "get_default_ocr_model",
    "get_available_ocr_engines",
]
