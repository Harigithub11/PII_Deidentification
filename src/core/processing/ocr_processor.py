"""
OCR Processor for PII De-identification System

This module provides specialized OCR processing with:
- Integration with existing PDF and image processors
- Advanced preprocessing for OCR optimization
- Multi-format document support
- Batch processing capabilities
- Quality optimization and error handling
"""

import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import json

import numpy as np
from PIL import Image
import cv2

from .pdf_processor import PDFProcessor, PDFProcessingResult
from .image_processor import ImageProcessor, ImageProcessingResult
from ..models.ocr_models import OCREngine, OCRResult
from ..services.ocr_service import OCRService, OCRDocumentResult, OCRDocumentPage
from ..config.settings import get_settings

logger = logging.getLogger(__name__)


class DocumentType(Enum):
    """Supported document types for OCR processing."""
    IMAGE = "image"
    PDF = "pdf"
    SCANNED_PDF = "scanned_pdf"
    MULTI_PAGE_TIFF = "multi_page_tiff"
    UNKNOWN = "unknown"


class PreprocessingMode(Enum):
    """OCR preprocessing modes."""
    NONE = "none"
    BASIC = "basic"
    ENHANCED = "enhanced"
    DOCUMENT = "document"
    HANDWRITING = "handwriting"


@dataclass
class OCRProcessingConfig:
    """Configuration for OCR processing."""
    engine: OCREngine = OCREngine.TESSERACT
    preprocessing_mode: PreprocessingMode = PreprocessingMode.ENHANCED
    enable_pii_detection: bool = True
    language_codes: List[str] = None
    confidence_threshold: float = 50.0
    max_pages: int = 100
    dpi: int = 300
    enable_parallel_processing: bool = True
    max_workers: int = 4
    
    def __post_init__(self):
        if self.language_codes is None:
            self.language_codes = ['eng']


@dataclass
class OCRProcessingResult:
    """Result of OCR processing operation."""
    success: bool
    document_type: DocumentType
    document_path: str
    ocr_result: Optional[OCRDocumentResult] = None
    original_processing_result: Optional[Union[PDFProcessingResult, ImageProcessingResult]] = None
    processing_time: float = 0.0
    preprocessing_operations: List[str] = None
    processing_errors: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.preprocessing_operations is None:
            self.preprocessing_operations = []
        if self.processing_errors is None:
            self.processing_errors = []
        if self.metadata is None:
            self.metadata = {}


class OCRProcessor:
    """Specialized OCR processor with advanced document handling."""
    
    def __init__(self, config: Optional[OCRProcessingConfig] = None):
        self.config = config or OCRProcessingConfig()
        self.settings = get_settings()
        
        # Initialize processors
        self.pdf_processor = PDFProcessor()
        self.image_processor = ImageProcessor()
        self.ocr_service = OCRService(
            preferred_engine=self.config.engine,
            enable_pii_detection=self.config.enable_pii_detection,
            max_workers=self.config.max_workers
        )
        
        # File type detection patterns
        self.image_extensions = {'.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp', '.gif', '.webp'}
        self.pdf_extensions = {'.pdf'}
        
        # Preprocessing configurations
        self.preprocessing_configs = {
            PreprocessingMode.NONE: {},
            PreprocessingMode.BASIC: {
                'apply_gaussian_blur': True,
                'blur_kernel': (1, 1),
                'apply_threshold': False
            },
            PreprocessingMode.ENHANCED: {
                'apply_gaussian_blur': True,
                'blur_kernel': (1, 1),
                'apply_threshold': True,
                'threshold_type': cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                'apply_morphology': True,
                'apply_denoising': True
            },
            PreprocessingMode.DOCUMENT: {
                'apply_gaussian_blur': True,
                'blur_kernel': (1, 1),
                'apply_threshold': True,
                'threshold_type': cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                'apply_morphology': True,
                'apply_denoising': True,
                'enhance_contrast': True,
                'enhance_sharpness': True
            },
            PreprocessingMode.HANDWRITING: {
                'apply_gaussian_blur': False,
                'apply_threshold': True,
                'threshold_type': cv2.ADAPTIVE_THRESH_MEAN_C,
                'apply_morphology': False,
                'apply_denoising': True,
                'enhance_contrast': True
            }
        }
        
        logger.info("OCRProcessor initialized with configuration")
    
    def detect_document_type(self, file_path: Union[str, Path]) -> DocumentType:
        """Detect the type of document for appropriate processing."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            return DocumentType.UNKNOWN
        
        file_ext = file_path.suffix.lower()
        
        if file_ext in self.image_extensions:
            # Check for multi-page TIFF
            if file_ext in {'.tiff', '.tif'}:
                try:
                    with Image.open(file_path) as img:
                        if getattr(img, 'n_frames', 1) > 1:
                            return DocumentType.MULTI_PAGE_TIFF
                except Exception:
                    pass
            return DocumentType.IMAGE
        
        elif file_ext in self.pdf_extensions:
            # Determine if PDF is scanned (image-based) or text-based
            try:
                pdf_result = self.pdf_processor.process_pdf(file_path)
                if pdf_result.success:
                    # Check if PDF has meaningful text content
                    text_ratio = self._calculate_text_to_image_ratio(pdf_result)
                    if text_ratio < 0.1:  # Less than 10% text content
                        return DocumentType.SCANNED_PDF
                    else:
                        return DocumentType.PDF
            except Exception as e:
                logger.warning(f"Failed to analyze PDF type: {e}")
                return DocumentType.PDF  # Default assumption
        
        return DocumentType.UNKNOWN
    
    def _calculate_text_to_image_ratio(self, pdf_result: PDFProcessingResult) -> float:
        """Calculate the ratio of text content to images in a PDF."""
        if not pdf_result.pages:
            return 0.0
        
        total_text_chars = 0
        total_images = 0
        
        for page in pdf_result.pages:
            total_text_chars += len(page.text_content) if page.text_content else 0
            total_images += len(page.images)
        
        # Simple heuristic: if there are many images and little text, it's likely scanned
        if total_images == 0:
            return 1.0  # Pure text PDF
        
        return total_text_chars / (total_text_chars + total_images * 100)
    
    def process_document(self, 
                        file_path: Union[str, Path],
                        config_override: Optional[OCRProcessingConfig] = None) -> OCRProcessingResult:
        """Process document with OCR based on its type."""
        start_time = time.time()
        file_path = Path(file_path)
        
        # Use override config if provided
        config = config_override or self.config
        
        try:
            # Detect document type
            doc_type = self.detect_document_type(file_path)
            logger.info(f"Detected document type: {doc_type.value} for {file_path.name}")
            
            # Process based on document type
            if doc_type == DocumentType.IMAGE:
                return self._process_image_document(file_path, config, start_time)
            
            elif doc_type == DocumentType.PDF:
                return self._process_text_pdf_document(file_path, config, start_time)
            
            elif doc_type == DocumentType.SCANNED_PDF:
                return self._process_scanned_pdf_document(file_path, config, start_time)
            
            elif doc_type == DocumentType.MULTI_PAGE_TIFF:
                return self._process_multipage_tiff_document(file_path, config, start_time)
            
            else:
                raise Exception(f"Unsupported document type: {doc_type.value}")
        
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Document OCR processing failed: {e}")
            
            return OCRProcessingResult(
                success=False,
                document_type=DocumentType.UNKNOWN,
                document_path=str(file_path),
                processing_time=processing_time,
                processing_errors=[str(e)]
            )
    
    def _process_image_document(self, 
                               file_path: Path, 
                               config: OCRProcessingConfig,
                               start_time: float) -> OCRProcessingResult:
        """Process single image document."""
        try:
            # First process image for optimization
            image_result = self.image_processor.process_image(
                file_path, enhance_quality=True
            )
            
            if not image_result.success:
                raise Exception(f"Image processing failed: {image_result.processing_errors}")
            
            # Apply OCR-specific preprocessing
            processed_image = self._apply_ocr_preprocessing(
                image_result.processed_image, config.preprocessing_mode
            )
            
            # Perform OCR
            ocr_page_result = self.ocr_service.extract_text_from_image(
                processed_image,
                page_number=0,
                detect_pii=config.enable_pii_detection
            )
            
            # Create document result
            ocr_doc_result = OCRDocumentResult(
                success=ocr_page_result.ocr_result.success,
                document_path=str(file_path),
                total_pages=1,
                pages=[ocr_page_result],
                combined_text=ocr_page_result.ocr_result.text_content,
                overall_confidence=ocr_page_result.ocr_result.confidence_score,
                processing_time=ocr_page_result.ocr_result.processing_time,
                engine_used=ocr_page_result.ocr_result.engine_used,
                languages_detected=[ocr_page_result.ocr_result.language_detected] if ocr_page_result.ocr_result.language_detected else [],
                quality_summary={ocr_page_result.quality_assessment.value: 1} if ocr_page_result.quality_assessment else {},
                processing_errors=ocr_page_result.ocr_result.processing_errors or []
            )
            
            processing_time = time.time() - start_time
            
            return OCRProcessingResult(
                success=ocr_doc_result.success,
                document_type=DocumentType.IMAGE,
                document_path=str(file_path),
                ocr_result=ocr_doc_result,
                original_processing_result=image_result,
                processing_time=processing_time,
                preprocessing_operations=image_result.processing_operations,
                processing_errors=ocr_doc_result.processing_errors,
                metadata={
                    'image_dimensions': image_result.processed_image.size if image_result.processed_image else (0, 0),
                    'image_format': image_result.metadata.format if image_result.metadata else 'unknown',
                    'preprocessing_mode': config.preprocessing_mode.value
                }
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Image document processing failed: {e}")
            
            return OCRProcessingResult(
                success=False,
                document_type=DocumentType.IMAGE,
                document_path=str(file_path),
                processing_time=processing_time,
                processing_errors=[str(e)]
            )
    
    def _process_text_pdf_document(self, 
                                  file_path: Path, 
                                  config: OCRProcessingConfig,
                                  start_time: float) -> OCRProcessingResult:
        """Process text-based PDF document (minimal OCR needed)."""
        try:
            # Process PDF to extract existing text
            pdf_result = self.pdf_processor.process_pdf(file_path)
            
            if not pdf_result.success:
                raise Exception(f"PDF processing failed: {pdf_result.processing_errors}")
            
            # For text PDFs, we might still want OCR for images within the PDF
            # or to verify/enhance existing text extraction
            ocr_doc_result = self.ocr_service.extract_text_from_pdf(
                file_path,
                detect_pii=config.enable_pii_detection
            )
            
            # Combine PDF text extraction with OCR results
            combined_text = self._combine_pdf_and_ocr_text(pdf_result, ocr_doc_result)
            
            processing_time = time.time() - start_time
            
            # Update combined text in OCR result
            if ocr_doc_result:
                ocr_doc_result.combined_text = combined_text
            
            return OCRProcessingResult(
                success=pdf_result.success and (ocr_doc_result.success if ocr_doc_result else True),
                document_type=DocumentType.PDF,
                document_path=str(file_path),
                ocr_result=ocr_doc_result,
                original_processing_result=pdf_result,
                processing_time=processing_time,
                preprocessing_operations=['pdf_text_extraction'],
                processing_errors=(pdf_result.processing_errors or []) + (ocr_doc_result.processing_errors if ocr_doc_result else []),
                metadata={
                    'pdf_pages': pdf_result.total_pages,
                    'pdf_metadata': pdf_result.document_metadata,
                    'text_extraction_method': 'hybrid_pdf_ocr'
                }
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Text PDF processing failed: {e}")
            
            return OCRProcessingResult(
                success=False,
                document_type=DocumentType.PDF,
                document_path=str(file_path),
                processing_time=processing_time,
                processing_errors=[str(e)]
            )
    
    def _process_scanned_pdf_document(self, 
                                     file_path: Path, 
                                     config: OCRProcessingConfig,
                                     start_time: float) -> OCRProcessingResult:
        """Process scanned PDF document (heavy OCR needed)."""
        try:
            # For scanned PDFs, we rely primarily on OCR
            ocr_doc_result = self.ocr_service.extract_text_from_pdf(
                file_path,
                detect_pii=config.enable_pii_detection
            )
            
            # Also get PDF processing result for metadata
            pdf_result = self.pdf_processor.process_pdf(file_path)
            
            processing_time = time.time() - start_time
            
            return OCRProcessingResult(
                success=ocr_doc_result.success if ocr_doc_result else False,
                document_type=DocumentType.SCANNED_PDF,
                document_path=str(file_path),
                ocr_result=ocr_doc_result,
                original_processing_result=pdf_result if pdf_result.success else None,
                processing_time=processing_time,
                preprocessing_operations=['scanned_pdf_ocr'],
                processing_errors=ocr_doc_result.processing_errors if ocr_doc_result else ['OCR failed'],
                metadata={
                    'pdf_pages': pdf_result.total_pages if pdf_result.success else 0,
                    'text_extraction_method': 'ocr_primary',
                    'preprocessing_mode': config.preprocessing_mode.value
                }
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Scanned PDF processing failed: {e}")
            
            return OCRProcessingResult(
                success=False,
                document_type=DocumentType.SCANNED_PDF,
                document_path=str(file_path),
                processing_time=processing_time,
                processing_errors=[str(e)]
            )
    
    def _process_multipage_tiff_document(self, 
                                        file_path: Path, 
                                        config: OCRProcessingConfig,
                                        start_time: float) -> OCRProcessingResult:
        """Process multi-page TIFF document."""
        try:
            # Extract each page from TIFF and process with OCR
            page_results = []
            processing_errors = []
            
            with Image.open(file_path) as tiff_image:
                page_count = getattr(tiff_image, 'n_frames', 1)
                
                for page_num in range(min(page_count, config.max_pages)):
                    try:
                        tiff_image.seek(page_num)
                        page_image = tiff_image.copy()
                        
                        # Apply preprocessing
                        processed_image = self._apply_ocr_preprocessing(
                            page_image, config.preprocessing_mode
                        )
                        
                        # Perform OCR
                        page_result = self.ocr_service.extract_text_from_image(
                            processed_image,
                            page_number=page_num,
                            detect_pii=config.enable_pii_detection
                        )
                        page_results.append(page_result)
                        
                    except Exception as e:
                        error_msg = f"Failed to process TIFF page {page_num + 1}: {str(e)}"
                        logger.error(error_msg)
                        processing_errors.append(error_msg)
            
            # Combine page results
            combined_text = "\n\n".join([
                page.ocr_result.text_content 
                for page in page_results 
                if page.ocr_result.success and page.ocr_result.text_content
            ])
            
            overall_confidence = np.mean([
                page.ocr_result.confidence_score 
                for page in page_results 
                if page.ocr_result.success
            ]) if page_results else 0.0
            
            # Create document result
            ocr_doc_result = OCRDocumentResult(
                success=len(page_results) > 0,
                document_path=str(file_path),
                total_pages=len(page_results),
                pages=page_results,
                combined_text=combined_text,
                overall_confidence=overall_confidence,
                processing_time=sum([p.ocr_result.processing_time for p in page_results]),
                engine_used=page_results[0].ocr_result.engine_used if page_results else "",
                languages_detected=list(set([
                    p.ocr_result.language_detected for p in page_results 
                    if p.ocr_result.language_detected
                ])),
                processing_errors=processing_errors
            )
            
            processing_time = time.time() - start_time
            
            return OCRProcessingResult(
                success=ocr_doc_result.success,
                document_type=DocumentType.MULTI_PAGE_TIFF,
                document_path=str(file_path),
                ocr_result=ocr_doc_result,
                processing_time=processing_time,
                preprocessing_operations=['multipage_tiff_extraction'],
                processing_errors=processing_errors,
                metadata={
                    'tiff_pages': page_count,
                    'processed_pages': len(page_results),
                    'preprocessing_mode': config.preprocessing_mode.value
                }
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Multi-page TIFF processing failed: {e}")
            
            return OCRProcessingResult(
                success=False,
                document_type=DocumentType.MULTI_PAGE_TIFF,
                document_path=str(file_path),
                processing_time=processing_time,
                processing_errors=[str(e)]
            )
    
    def _apply_ocr_preprocessing(self, 
                                image: Image.Image, 
                                mode: PreprocessingMode) -> Image.Image:
        """Apply OCR-specific preprocessing based on mode."""
        if mode == PreprocessingMode.NONE:
            return image
        
        try:
            # Get preprocessing config
            prep_config = self.preprocessing_configs[mode]
            
            # Convert to numpy array for OpenCV operations
            img_array = np.array(image)
            
            # Convert to grayscale if needed
            if len(img_array.shape) == 3:
                if img_array.shape[2] == 4:  # RGBA
                    img_array = cv2.cvtColor(img_array, cv2.COLOR_RGBA2GRAY)
                elif img_array.shape[2] == 3:  # RGB
                    img_array = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            
            # Apply Gaussian blur if configured
            if prep_config.get('apply_gaussian_blur', False):
                kernel_size = prep_config.get('blur_kernel', (1, 1))
                img_array = cv2.GaussianBlur(img_array, kernel_size, 0)
            
            # Apply thresholding if configured
            if prep_config.get('apply_threshold', False):
                threshold_type = prep_config.get('threshold_type', cv2.ADAPTIVE_THRESH_GAUSSIAN_C)
                img_array = cv2.adaptiveThreshold(
                    img_array, 255, threshold_type, cv2.THRESH_BINARY, 11, 2
                )
            
            # Apply morphological operations if configured
            if prep_config.get('apply_morphology', False):
                kernel = np.ones((1, 1), np.uint8)
                img_array = cv2.morphologyEx(img_array, cv2.MORPH_CLOSE, kernel)
            
            # Apply denoising if configured
            if prep_config.get('apply_denoising', False):
                img_array = cv2.fastNlMeansDenoising(img_array, None, 10, 7, 21)
            
            # Convert back to PIL Image
            processed_image = Image.fromarray(img_array)
            
            # Apply PIL-based enhancements if configured
            if prep_config.get('enhance_contrast', False):
                from PIL import ImageEnhance
                enhancer = ImageEnhance.Contrast(processed_image)
                processed_image = enhancer.enhance(1.2)
            
            if prep_config.get('enhance_sharpness', False):
                from PIL import ImageEnhance
                enhancer = ImageEnhance.Sharpness(processed_image)
                processed_image = enhancer.enhance(1.3)
            
            return processed_image
            
        except Exception as e:
            logger.warning(f"OCR preprocessing failed, using original image: {e}")
            return image
    
    def _combine_pdf_and_ocr_text(self, 
                                 pdf_result: PDFProcessingResult, 
                                 ocr_result: Optional[OCRDocumentResult]) -> str:
        """Combine PDF text extraction with OCR results for better accuracy."""
        combined_text = ""
        
        try:
            # Start with PDF extracted text
            for page in pdf_result.pages:
                if page.text_content and len(page.text_content.strip()) > 0:
                    combined_text += page.text_content + "\n\n"
            
            # Add OCR text where PDF text is missing or poor quality
            if ocr_result and ocr_result.pages:
                for i, ocr_page in enumerate(ocr_result.pages):
                    # Check if corresponding PDF page has sufficient text
                    pdf_page_text = ""
                    if i < len(pdf_result.pages):
                        pdf_page_text = pdf_result.pages[i].text_content or ""
                    
                    # If PDF page has little text but OCR found text, add OCR text
                    if len(pdf_page_text.strip()) < 50 and len(ocr_page.ocr_result.text_content.strip()) > 50:
                        combined_text += f"\n[OCR Page {i+1}]\n{ocr_page.ocr_result.text_content}\n\n"
            
            return combined_text.strip()
            
        except Exception as e:
            logger.warning(f"Failed to combine PDF and OCR text: {e}")
            # Fallback to PDF text or OCR text
            if pdf_result.pages:
                return "\n\n".join([p.text_content for p in pdf_result.pages if p.text_content])
            elif ocr_result:
                return ocr_result.combined_text
            return ""
    
    def batch_process_documents(self, 
                               file_paths: List[Union[str, Path]],
                               config_override: Optional[OCRProcessingConfig] = None) -> List[OCRProcessingResult]:
        """Process multiple documents in batch."""
        results = []
        config = config_override or self.config
        
        for file_path in file_paths:
            try:
                result = self.process_document(file_path, config)
                results.append(result)
                logger.info(f"Processed {file_path}: {'Success' if result.success else 'Failed'}")
            except Exception as e:
                logger.error(f"Batch processing failed for {file_path}: {e}")
                results.append(OCRProcessingResult(
                    success=False,
                    document_type=DocumentType.UNKNOWN,
                    document_path=str(file_path),
                    processing_errors=[str(e)]
                ))
        
        return results
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """Get processor statistics and capabilities."""
        available_engines = self.ocr_service.get_available_engines()
        
        return {
            'supported_document_types': [dt.value for dt in DocumentType],
            'supported_preprocessing_modes': [pm.value for pm in PreprocessingMode],
            'available_ocr_engines': [engine.value for engine in available_engines],
            'current_engine': self.config.engine.value,
            'supported_image_formats': list(self.image_extensions),
            'supported_pdf_formats': list(self.pdf_extensions),
            'max_pages': self.config.max_pages,
            'features': [
                'document_type_detection',
                'adaptive_preprocessing',
                'multi_engine_support',
                'batch_processing',
                'pii_integration',
                'quality_assessment'
            ]
        }
    
    def cleanup(self):
        """Clean up resources."""
        try:
            if hasattr(self, 'ocr_service'):
                self.ocr_service.cleanup()
            logger.info("OCRProcessor cleanup completed")
        except Exception as e:
            logger.error(f"OCRProcessor cleanup failed: {e}")


# Convenience functions
def create_ocr_processor(config: Optional[OCRProcessingConfig] = None) -> OCRProcessor:
    """Create OCR processor with specified configuration."""
    return OCRProcessor(config)


def quick_document_ocr(file_path: Union[str, Path], 
                      engine: OCREngine = OCREngine.TESSERACT) -> str:
    """Quick OCR text extraction from document."""
    config = OCRProcessingConfig(
        engine=engine,
        enable_pii_detection=False,
        preprocessing_mode=PreprocessingMode.ENHANCED
    )
    
    processor = create_ocr_processor(config)
    try:
        result = processor.process_document(file_path)
        if result.success and result.ocr_result:
            return result.ocr_result.combined_text
        return ""
    finally:
        processor.cleanup()