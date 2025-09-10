"""
OCR Service for PII De-identification System

This module provides high-level OCR services with support for:
- Multiple OCR engines (Tesseract, PaddleOCR)
- Async/sync text extraction from images and documents
- Integration with PII detection pipeline
- Batch processing for multi-page documents
- Quality assessment and confidence metrics
"""

import asyncio
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
import json

from PIL import Image
import numpy as np

from ..models.ocr_models import (
    OCRModel, OCRResult, OCREngine, LanguageCode,
    get_default_ocr_model, get_available_ocr_engines,
    create_tesseract_model, create_paddle_ocr_model
)
from ..models.model_manager import get_model_manager
from ..config.settings import get_settings
from .pii_detector import PIIDetectionService, PIIDetectionResult

logger = logging.getLogger(__name__)


class OCRQuality(Enum):
    """OCR result quality levels."""
    EXCELLENT = "excellent"  # >90% confidence
    GOOD = "good"           # 70-90% confidence
    FAIR = "fair"           # 50-70% confidence
    POOR = "poor"           # <50% confidence


@dataclass
class OCRDocumentPage:
    """Container for OCR results from a single document page."""
    page_number: int
    ocr_result: OCRResult
    pii_detection_result: Optional[PIIDetectionResult] = None
    quality_assessment: Optional[OCRQuality] = None
    processing_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OCRDocumentResult:
    """Container for OCR results from an entire document."""
    success: bool
    document_path: str
    total_pages: int
    pages: List[OCRDocumentPage]
    combined_text: str
    overall_confidence: float
    processing_time: float
    engine_used: str
    languages_detected: List[str]
    pii_summary: Optional[Dict[str, Any]] = None
    quality_summary: Dict[str, int] = field(default_factory=dict)
    processing_errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def word_count(self) -> int:
        """Total word count across all pages."""
        return len(self.combined_text.split()) if self.combined_text else 0
    
    @property
    def character_count(self) -> int:
        """Total character count across all pages."""
        return len(self.combined_text) if self.combined_text else 0


class OCRService:
    """High-level OCR service with PII detection integration."""
    
    def __init__(self, 
                 preferred_engine: OCREngine = OCREngine.TESSERACT,
                 enable_pii_detection: bool = True,
                 max_workers: int = 4):
        self.settings = get_settings()
        self.model_manager = get_model_manager()
        self.preferred_engine = preferred_engine
        self.enable_pii_detection = enable_pii_detection
        self.max_workers = max_workers
        
        # Initialize OCR model
        self._ocr_model: Optional[OCRModel] = None
        self._backup_ocr_model: Optional[OCRModel] = None
        
        # Initialize PII detection service if enabled
        self._pii_service: Optional[PIIDetectionService] = None
        if enable_pii_detection:
            try:
                self._pii_service = PIIDetectionService()
            except Exception as e:
                logger.warning(f"Failed to initialize PII detection service: {e}")
        
        # Thread pool for concurrent processing
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Quality thresholds
        self.quality_thresholds = {
            OCRQuality.EXCELLENT: 90.0,
            OCRQuality.GOOD: 70.0,
            OCRQuality.FAIR: 50.0,
            OCRQuality.POOR: 0.0
        }
        
        logger.info(f"OCRService initialized with {preferred_engine.value} engine")
    
    def _get_ocr_model(self, force_reload: bool = False) -> Optional[OCRModel]:
        """Get OCR model, loading if necessary."""
        if self._ocr_model and not force_reload:
            return self._ocr_model
        
        try:
            # Try to get preferred model
            if self.preferred_engine == OCREngine.TESSERACT:
                model = self.model_manager.get_model("ocr_model")
            else:
                model = self.model_manager.get_model("paddleocr")
            
            if model:
                self._ocr_model = model
                return model
            
            # Fallback to alternative engine
            logger.warning(f"Preferred OCR engine {self.preferred_engine.value} not available, trying fallback")
            
            if self.preferred_engine == OCREngine.TESSERACT:
                fallback_model = self.model_manager.get_model("paddleocr")
            else:
                fallback_model = self.model_manager.get_model("ocr_model")
            
            if fallback_model:
                self._backup_ocr_model = fallback_model
                return fallback_model
            
            logger.error("No OCR models available")
            return None
            
        except Exception as e:
            logger.error(f"Failed to get OCR model: {e}")
            return None
    
    def extract_text_from_image(self, 
                               image: Union[str, Path, Image.Image, np.ndarray],
                               page_number: int = 0,
                               detect_pii: bool = None,
                               **ocr_kwargs) -> OCRDocumentPage:
        """Extract text from a single image with optional PII detection."""
        if detect_pii is None:
            detect_pii = self.enable_pii_detection
        
        try:
            # Get OCR model
            ocr_model = self._get_ocr_model()
            if not ocr_model:
                raise Exception("No OCR model available")
            
            # Perform OCR
            ocr_result = ocr_model.extract_text(image, page_number, **ocr_kwargs)
            
            # Assess quality
            quality = self._assess_quality(ocr_result)
            
            # Perform PII detection if enabled
            pii_result = None
            if detect_pii and ocr_result.success and ocr_result.text_content:
                try:
                    if self._pii_service:
                        pii_result = self._pii_service.detect_pii(ocr_result.text_content)
                except Exception as e:
                    logger.warning(f"PII detection failed: {e}")
            
            # Create processing metadata
            metadata = {
                'ocr_engine': ocr_result.engine_used,
                'ocr_version': ocr_result.engine_version,
                'preprocessing_applied': ocr_result.preprocessing_applied,
                'image_dimensions': ocr_result.image_dimensions,
                'processing_time': ocr_result.processing_time
            }
            
            return OCRDocumentPage(
                page_number=page_number,
                ocr_result=ocr_result,
                pii_detection_result=pii_result,
                quality_assessment=quality,
                processing_metadata=metadata
            )
            
        except Exception as e:
            logger.error(f"Failed to extract text from image: {e}")
            # Return failed OCR result
            empty_result = OCRResult(
                success=False,
                text_content="",
                confidence_score=0.0,
                text_blocks=[],
                bounding_boxes=[],
                processing_time=0.0,
                page_number=page_number,
                processing_errors=[str(e)]
            )
            
            return OCRDocumentPage(
                page_number=page_number,
                ocr_result=empty_result,
                quality_assessment=OCRQuality.POOR,
                processing_metadata={'error': str(e)}
            )
    
    async def extract_text_from_image_async(self, 
                                           image: Union[str, Path, Image.Image, np.ndarray],
                                           page_number: int = 0,
                                           detect_pii: bool = None,
                                           **ocr_kwargs) -> OCRDocumentPage:
        """Async version of extract_text_from_image."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self.extract_text_from_image,
            image, page_number, detect_pii,
            **ocr_kwargs
        )
    
    def extract_text_from_pdf(self, 
                             pdf_path: Union[str, Path],
                             page_range: Optional[Tuple[int, int]] = None,
                             detect_pii: bool = None,
                             **ocr_kwargs) -> OCRDocumentResult:
        """Extract text from PDF document with OCR."""
        if detect_pii is None:
            detect_pii = self.enable_pii_detection
        
        start_time = time.time()
        pdf_path = Path(pdf_path)
        
        try:
            # Get PDF processor
            pdf_processor = self.model_manager.get_model("pdf_processor")
            if not pdf_processor:
                raise Exception("PDF processor not available")
            
            # Process PDF to get pages as images
            pdf_result = pdf_processor.process_pdf(pdf_path)
            if not pdf_result.success:
                raise Exception(f"PDF processing failed: {pdf_result.processing_errors}")
            
            # Determine page range
            total_pages = pdf_result.total_pages
            if page_range:
                start_page, end_page = page_range
                start_page = max(0, start_page)
                end_page = min(total_pages, end_page)
            else:
                start_page, end_page = 0, total_pages
            
            # Extract text from each page
            pages = []
            processing_errors = []
            
            for page_num in range(start_page, end_page):
                try:
                    # Extract page as image
                    page_image = pdf_processor.extract_page_as_image(pdf_path, page_num)
                    if page_image is None:
                        logger.warning(f"Failed to extract page {page_num + 1} as image")
                        continue
                    
                    # Perform OCR on page
                    page_result = self.extract_text_from_image(
                        page_image, page_num, detect_pii, **ocr_kwargs
                    )
                    pages.append(page_result)
                    
                except Exception as e:
                    error_msg = f"Failed to process page {page_num + 1}: {str(e)}"
                    logger.error(error_msg)
                    processing_errors.append(error_msg)
            
            # Combine results
            return self._combine_page_results(
                pdf_path, pages, processing_errors, time.time() - start_time
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"PDF OCR failed: {e}")
            
            return OCRDocumentResult(
                success=False,
                document_path=str(pdf_path),
                total_pages=0,
                pages=[],
                combined_text="",
                overall_confidence=0.0,
                processing_time=processing_time,
                engine_used="",
                languages_detected=[],
                processing_errors=[str(e)]
            )
    
    async def extract_text_from_pdf_async(self, 
                                         pdf_path: Union[str, Path],
                                         page_range: Optional[Tuple[int, int]] = None,
                                         detect_pii: bool = None,
                                         **ocr_kwargs) -> OCRDocumentResult:
        """Async version of extract_text_from_pdf."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self.extract_text_from_pdf,
            pdf_path, page_range, detect_pii,
            **ocr_kwargs
        )
    
    def batch_process_images(self, 
                            image_paths: List[Union[str, Path]],
                            detect_pii: bool = None,
                            **ocr_kwargs) -> List[OCRDocumentPage]:
        """Process multiple images in batch."""
        if detect_pii is None:
            detect_pii = self.enable_pii_detection
        
        results = []
        
        # Process images concurrently
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for i, image_path in enumerate(image_paths):
                future = executor.submit(
                    self.extract_text_from_image,
                    image_path, i, detect_pii, **ocr_kwargs
                )
                futures.append(future)
            
            # Collect results
            for future in futures:
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Batch processing failed for image: {e}")
        
        return results
    
    async def batch_process_images_async(self, 
                                        image_paths: List[Union[str, Path]],
                                        detect_pii: bool = None,
                                        **ocr_kwargs) -> List[OCRDocumentPage]:
        """Async version of batch_process_images."""
        if detect_pii is None:
            detect_pii = self.enable_pii_detection
        
        # Create async tasks
        tasks = []
        for i, image_path in enumerate(image_paths):
            task = self.extract_text_from_image_async(
                image_path, i, detect_pii, **ocr_kwargs
            )
            tasks.append(task)
        
        # Execute tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Async batch processing failed: {result}")
            else:
                valid_results.append(result)
        
        return valid_results
    
    def _assess_quality(self, ocr_result: OCRResult) -> OCRQuality:
        """Assess the quality of OCR results."""
        if not ocr_result.success:
            return OCRQuality.POOR
        
        confidence = ocr_result.confidence_score
        
        if confidence >= self.quality_thresholds[OCRQuality.EXCELLENT]:
            return OCRQuality.EXCELLENT
        elif confidence >= self.quality_thresholds[OCRQuality.GOOD]:
            return OCRQuality.GOOD
        elif confidence >= self.quality_thresholds[OCRQuality.FAIR]:
            return OCRQuality.FAIR
        else:
            return OCRQuality.POOR
    
    def _combine_page_results(self, 
                             document_path: Path,
                             pages: List[OCRDocumentPage],
                             processing_errors: List[str],
                             processing_time: float) -> OCRDocumentResult:
        """Combine individual page results into document result."""
        
        # Combine text content
        combined_text = ""
        all_confidences = []
        all_languages = set()
        quality_counts = {quality: 0 for quality in OCRQuality}
        all_pii_entities = []
        
        engine_used = ""
        
        for page in pages:
            if page.ocr_result.success:
                combined_text += page.ocr_result.text_content + "\n\n"
                all_confidences.append(page.ocr_result.confidence_score)
                
                if page.ocr_result.language_detected:
                    all_languages.add(page.ocr_result.language_detected)
                
                if not engine_used:
                    engine_used = page.ocr_result.engine_used
                
                # Count quality levels
                if page.quality_assessment:
                    quality_counts[page.quality_assessment] += 1
                
                # Collect PII entities
                if page.pii_detection_result and page.pii_detection_result.entities:
                    all_pii_entities.extend(page.pii_detection_result.entities)
        
        # Calculate overall metrics
        overall_confidence = np.mean(all_confidences) if all_confidences else 0.0
        combined_text = combined_text.strip()
        
        # Create PII summary
        pii_summary = None
        if all_pii_entities:
            pii_summary = self._create_pii_summary(all_pii_entities)
        
        # Convert quality counts enum keys to strings for JSON serialization
        quality_summary = {quality.value: count for quality, count in quality_counts.items()}
        
        return OCRDocumentResult(
            success=len(pages) > 0,
            document_path=str(document_path),
            total_pages=len(pages),
            pages=pages,
            combined_text=combined_text,
            overall_confidence=overall_confidence,
            processing_time=processing_time,
            engine_used=engine_used,
            languages_detected=list(all_languages),
            pii_summary=pii_summary,
            quality_summary=quality_summary,
            processing_errors=processing_errors
        )
    
    def _create_pii_summary(self, pii_entities: List[Any]) -> Dict[str, Any]:
        """Create summary of PII entities found."""
        entity_counts = {}
        risk_levels = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        
        for entity in pii_entities:
            entity_type = entity.entity_type
            entity_counts[entity_type] = entity_counts.get(entity_type, 0) + 1
            
            # Count risk levels if available
            if hasattr(entity, 'risk_level'):
                risk_level = entity.risk_level
                if risk_level in risk_levels:
                    risk_levels[risk_level] += 1
        
        return {
            'total_entities': len(pii_entities),
            'entity_types': entity_counts,
            'risk_distribution': risk_levels,
            'has_sensitive_data': len(pii_entities) > 0
        }
    
    def get_available_engines(self) -> List[OCREngine]:
        """Get list of available OCR engines."""
        return get_available_ocr_engines()
    
    def switch_engine(self, engine: OCREngine) -> bool:
        """Switch to a different OCR engine."""
        try:
            self.preferred_engine = engine
            self._ocr_model = None  # Force reload
            
            # Test the new engine
            test_model = self._get_ocr_model()
            if test_model:
                logger.info(f"Switched to OCR engine: {engine.value}")
                return True
            else:
                logger.error(f"Failed to switch to OCR engine: {engine.value}")
                return False
                
        except Exception as e:
            logger.error(f"Engine switch failed: {e}")
            return False
    
    def get_engine_info(self) -> Dict[str, Any]:
        """Get information about current OCR engine."""
        model = self._get_ocr_model()
        if not model:
            return {"status": "no_model_loaded"}
        
        try:
            available_langs = model.get_available_languages()
            
            return {
                "engine": model.engine.value,
                "is_loaded": model.is_loaded,
                "available_languages": available_langs,
                "supported_formats": model.supported_formats,
                "status": "ready"
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def cleanup(self):
        """Clean up resources."""
        try:
            if self._executor:
                self._executor.shutdown(wait=True)
            
            if self._ocr_model:
                self._ocr_model.unload()
            
            if self._backup_ocr_model:
                self._backup_ocr_model.unload()
            
            logger.info("OCRService cleanup completed")
            
        except Exception as e:
            logger.error(f"OCRService cleanup failed: {e}")


# Convenience functions
def create_ocr_service(engine: OCREngine = OCREngine.TESSERACT,
                      enable_pii: bool = True,
                      max_workers: int = 4) -> OCRService:
    """Create OCR service with specified configuration."""
    return OCRService(engine, enable_pii, max_workers)


async def quick_ocr_text_extraction(image: Union[str, Path, Image.Image, np.ndarray],
                                   engine: OCREngine = OCREngine.TESSERACT) -> str:
    """Quick text extraction from image using OCR."""
    service = create_ocr_service(engine, enable_pii=False)
    try:
        result = await service.extract_text_from_image_async(image, detect_pii=False)
        return result.ocr_result.text_content if result.ocr_result.success else ""
    finally:
        service.cleanup()


def quick_ocr_text_extraction_sync(image: Union[str, Path, Image.Image, np.ndarray],
                                  engine: OCREngine = OCREngine.TESSERACT) -> str:
    """Quick synchronous text extraction from image using OCR."""
    service = create_ocr_service(engine, enable_pii=False)
    try:
        result = service.extract_text_from_image(image, detect_pii=False)
        return result.ocr_result.text_content if result.ocr_result.success else ""
    finally:
        service.cleanup()