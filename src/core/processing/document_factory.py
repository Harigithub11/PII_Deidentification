"""
Document Factory for PII De-identification System

This module provides centralized document format detection and routing to
appropriate processors based on file type and content analysis.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple
import mimetypes
from dataclasses import dataclass
from enum import Enum

import magic
from PIL import Image

from .pdf_processor import PDFProcessor, PDFProcessingResult
from .image_processor import ImageProcessor, ImageProcessingResult
from .scanner_processor import ScannerProcessor, ScanProcessingResult

logger = logging.getLogger(__name__)


class DocumentType(Enum):
    """Supported document types."""
    PDF = "pdf"
    IMAGE = "image"
    SCANNED_DOCUMENT = "scanned_document"
    UNKNOWN = "unknown"


class ProcessingMode(Enum):
    """Document processing modes."""
    BASIC = "basic"          # Basic processing without enhancements
    ENHANCED = "enhanced"    # Full processing with quality improvements
    OCR_READY = "ocr_ready"  # Optimized specifically for OCR


@dataclass
class DocumentInfo:
    """Container for document information."""
    file_path: Path
    document_type: DocumentType
    mime_type: str
    file_size_bytes: int
    estimated_pages: int
    is_scanned: bool
    confidence_score: float
    metadata: Dict[str, Any]


@dataclass
class ProcessingOptions:
    """Options for document processing."""
    mode: ProcessingMode = ProcessingMode.ENHANCED
    apply_scan_optimization: bool = True
    target_dpi: int = 300
    max_dimension: int = 2048
    enhance_for_ocr: bool = True
    preserve_original: bool = True
    
    # PII Detection options (optional)
    enable_pii_detection: bool = False
    pii_text_detection: bool = True
    pii_visual_detection: bool = True
    pii_confidence_threshold: float = 0.5
    pii_model_type: str = "presidio"


@dataclass
class UnifiedProcessingResult:
    """Unified result container for all processing types."""
    success: bool
    document_type: DocumentType
    processing_mode: ProcessingMode
    
    # Original processors' results
    pdf_result: Optional[PDFProcessingResult] = None
    image_result: Optional[ImageProcessingResult] = None
    scan_result: Optional[ScanProcessingResult] = None
    
    # Unified outputs
    extracted_images: List[Image.Image] = None
    extracted_text: str = ""
    page_count: int = 0
    quality_score: float = 0.0
    
    # Processing information
    processing_time_seconds: float = 0.0
    operations_performed: List[str] = None
    errors_encountered: List[str] = None
    
    # PII Detection integration (optional)
    pii_enabled: bool = False
    text_pii_detected: bool = False
    visual_pii_detected: bool = False
    pii_risk_level: Optional[str] = None
    pii_entity_count: int = 0
    pii_processing_id: Optional[str] = None


class DocumentFactory:
    """Factory for document format detection and processing coordination."""
    
    def __init__(self):
        # Initialize processors
        self.pdf_processor = PDFProcessor()
        self.image_processor = ImageProcessor()
        self.scanner_processor = ScannerProcessor()
        
        # Supported file extensions mapping
        self.extension_mapping = {
            '.pdf': DocumentType.PDF,
            '.png': DocumentType.IMAGE,
            '.jpg': DocumentType.IMAGE,
            '.jpeg': DocumentType.IMAGE,
            '.tiff': DocumentType.IMAGE,
            '.tif': DocumentType.IMAGE,
            '.bmp': DocumentType.IMAGE,
            '.webp': DocumentType.IMAGE,
            '.gif': DocumentType.IMAGE
        }
        
        # MIME type mapping
        self.mime_mapping = {
            'application/pdf': DocumentType.PDF,
            'image/png': DocumentType.IMAGE,
            'image/jpeg': DocumentType.IMAGE,
            'image/tiff': DocumentType.IMAGE,
            'image/bmp': DocumentType.IMAGE,
            'image/webp': DocumentType.IMAGE,
            'image/gif': DocumentType.IMAGE
        }
        
        logger.info("DocumentFactory initialized with all processors")
    
    def analyze_document(self, file_path: Union[str, Path]) -> DocumentInfo:
        """Analyze document to determine type and characteristics."""
        file_path = Path(file_path)
        
        try:
            # Basic file information
            file_size = file_path.stat().st_size
            file_ext = file_path.suffix.lower()
            
            # Detect MIME type
            mime_type = self._detect_mime_type(file_path)
            
            # Determine document type from extension and MIME type
            document_type = self._determine_document_type(file_ext, mime_type)
            
            # Estimate characteristics based on type
            estimated_pages = 1
            is_scanned = False
            confidence_score = 0.0
            metadata = {}
            
            if document_type == DocumentType.PDF:
                # Quick PDF analysis
                try:
                    import fitz  # PyMuPDF
                    doc = fitz.open(str(file_path))
                    estimated_pages = len(doc)
                    
                    # Check if PDF contains mostly images (likely scanned)
                    is_scanned = self._is_scanned_pdf(doc)
                    confidence_score = 0.9
                    
                    metadata = {
                        'pdf_version': doc.pdf_version(),
                        'is_encrypted': doc.is_encrypted,
                        'page_count': estimated_pages
                    }
                    doc.close()
                    
                except Exception as e:
                    logger.warning(f"PDF analysis failed: {e}")
                    confidence_score = 0.5
            
            elif document_type == DocumentType.IMAGE:
                # Quick image analysis
                try:
                    with Image.open(file_path) as img:
                        width, height = img.size
                        
                        # Heuristic to detect scanned documents
                        is_scanned = self._is_scanned_image(img, file_path)
                        confidence_score = 0.8
                        
                        metadata = {
                            'dimensions': (width, height),
                            'mode': img.mode,
                            'format': img.format
                        }
                        
                except Exception as e:
                    logger.warning(f"Image analysis failed: {e}")
                    confidence_score = 0.3
            
            return DocumentInfo(
                file_path=file_path,
                document_type=document_type,
                mime_type=mime_type,
                file_size_bytes=file_size,
                estimated_pages=estimated_pages,
                is_scanned=is_scanned,
                confidence_score=confidence_score,
                metadata=metadata
            )
            
        except Exception as e:
            logger.error(f"Document analysis failed: {e}")
            return DocumentInfo(
                file_path=file_path,
                document_type=DocumentType.UNKNOWN,
                mime_type="unknown",
                file_size_bytes=0,
                estimated_pages=0,
                is_scanned=False,
                confidence_score=0.0,
                metadata={'error': str(e)}
            )
    
    def process_document(self, file_path: Union[str, Path], 
                        options: Optional[ProcessingOptions] = None) -> UnifiedProcessingResult:
        """Process document using appropriate processor based on type."""
        import time
        start_time = time.time()
        
        if options is None:
            options = ProcessingOptions()
        
        # Analyze document first
        doc_info = self.analyze_document(file_path)
        
        operations_performed = []
        errors_encountered = []
        extracted_images = []
        extracted_text = ""
        page_count = 0
        quality_score = 0.0
        
        pdf_result = None
        image_result = None
        scan_result = None
        
        try:
            if doc_info.document_type == DocumentType.PDF:
                # Process PDF
                pdf_result = self.pdf_processor.process_pdf(file_path)
                operations_performed.extend(["pdf_processing"])
                
                if pdf_result.success:
                    # Extract text and images
                    for page in pdf_result.pages:
                        extracted_text += page.text_content + "\n"
                        for img_data in page.images:
                            try:
                                # Decode base64 image data
                                import base64
                                import io
                                img_bytes = base64.b64decode(img_data['image_data'])
                                img = Image.open(io.BytesIO(img_bytes))
                                extracted_images.append(img)
                            except Exception as e:
                                errors_encountered.append(f"Image extraction failed: {e}")
                    
                    page_count = pdf_result.total_pages
                    quality_score = sum(p.confidence_score for p in pdf_result.pages) / len(pdf_result.pages)
                    
                    # Apply scan optimization if needed
                    if doc_info.is_scanned and options.apply_scan_optimization:
                        operations_performed.append("scan_optimization_applied")
                        # Process extracted images with scanner processor
                        optimized_images = []
                        for img in extracted_images:
                            try:
                                scan_result = self.scanner_processor.process_scanned_document(img)
                                if scan_result.success:
                                    optimized_images.append(scan_result.processed_image)
                                else:
                                    optimized_images.append(img)
                            except Exception as e:
                                errors_encountered.append(f"Scan optimization failed: {e}")
                                optimized_images.append(img)
                        extracted_images = optimized_images
                
                else:
                    errors_encountered.extend(pdf_result.processing_errors)
            
            elif doc_info.document_type == DocumentType.IMAGE:
                # Process image
                image_result = self.image_processor.process_image(
                    file_path, 
                    enhance_quality=(options.mode != ProcessingMode.BASIC)
                )
                operations_performed.append("image_processing")
                
                if image_result.success:
                    extracted_images = [image_result.processed_image]
                    page_count = 1
                    quality_score = image_result.quality_metrics.get('entropy', 0) / 8.0 * 100  # Normalize entropy
                    
                    # Apply scan optimization if needed
                    if doc_info.is_scanned and options.apply_scan_optimization:
                        operations_performed.append("scan_optimization_applied")
                        scan_result = self.scanner_processor.process_scanned_document(image_result.processed_image)
                        if scan_result.success:
                            extracted_images = [scan_result.processed_image]
                            quality_score = scan_result.quality_metrics.overall_quality
                        else:
                            errors_encountered.extend(scan_result.processing_errors)
                
                else:
                    errors_encountered.extend(image_result.processing_errors)
            
            else:
                errors_encountered.append(f"Unsupported document type: {doc_info.document_type}")
            
            # Apply OCR-specific optimizations if requested
            if options.enhance_for_ocr and extracted_images:
                operations_performed.append("ocr_optimization")
                ocr_optimized_images = []
                for img in extracted_images:
                    try:
                        ocr_img = self.image_processor.extract_image_for_ocr(img)
                        ocr_optimized_images.append(ocr_img)
                    except Exception as e:
                        errors_encountered.append(f"OCR optimization failed: {e}")
                        ocr_optimized_images.append(img)
                extracted_images = ocr_optimized_images
            
            processing_time = time.time() - start_time
            
            return UnifiedProcessingResult(
                success=len(errors_encountered) == 0 or len(extracted_images) > 0,
                document_type=doc_info.document_type,
                processing_mode=options.mode,
                pdf_result=pdf_result,
                image_result=image_result,
                scan_result=scan_result,
                extracted_images=extracted_images,
                extracted_text=extracted_text,
                page_count=page_count,
                quality_score=quality_score,
                processing_time_seconds=processing_time,
                operations_performed=operations_performed,
                errors_encountered=errors_encountered
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Document processing failed: {e}")
            return UnifiedProcessingResult(
                success=False,
                document_type=doc_info.document_type,
                processing_mode=options.mode,
                pdf_result=pdf_result,
                image_result=image_result,
                scan_result=scan_result,
                extracted_images=[],
                extracted_text="",
                page_count=0,
                quality_score=0.0,
                processing_time_seconds=processing_time,
                operations_performed=operations_performed,
                errors_encountered=[f"Processing failed: {str(e)}"]
            )
    
    def _detect_mime_type(self, file_path: Path) -> str:
        """Detect MIME type of file."""
        try:
            # Try using python-magic first
            mime_type = magic.from_file(str(file_path), mime=True)
            return mime_type
        except Exception:
            # Fallback to mimetypes module
            mime_type, _ = mimetypes.guess_type(str(file_path))
            return mime_type or "application/octet-stream"
    
    def _determine_document_type(self, file_ext: str, mime_type: str) -> DocumentType:
        """Determine document type from extension and MIME type."""
        # Check extension first
        if file_ext in self.extension_mapping:
            return self.extension_mapping[file_ext]
        
        # Check MIME type
        if mime_type in self.mime_mapping:
            return self.mime_mapping[mime_type]
        
        # Check MIME type prefix
        if mime_type.startswith('image/'):
            return DocumentType.IMAGE
        elif mime_type.startswith('application/pdf'):
            return DocumentType.PDF
        
        return DocumentType.UNKNOWN
    
    def _is_scanned_pdf(self, pdf_doc) -> bool:
        """Heuristic to determine if PDF contains scanned content."""
        try:
            if len(pdf_doc) == 0:
                return False
            
            # Check first few pages
            pages_to_check = min(3, len(pdf_doc))
            image_heavy_pages = 0
            
            for page_num in range(pages_to_check):
                page = pdf_doc.load_page(page_num)
                
                # Get text content
                text = page.get_text().strip()
                
                # Get image list
                images = page.get_images()
                
                # If page has very little text but has images, likely scanned
                if len(text) < 50 and len(images) > 0:
                    image_heavy_pages += 1
                elif len(images) > 0:
                    # Check if images cover most of the page
                    page_area = page.rect.width * page.rect.height
                    image_area = 0
                    
                    for img in images:
                        bbox = page.get_image_bbox(img)
                        if bbox:
                            image_area += (bbox[2] - bbox[0]) * (bbox[3] - bbox[1])
                    
                    if image_area > page_area * 0.7:  # Images cover >70% of page
                        image_heavy_pages += 1
            
            # If more than half the checked pages are image-heavy, likely scanned
            return image_heavy_pages > pages_to_check / 2
            
        except Exception as e:
            logger.warning(f"Scanned PDF detection failed: {e}")
            return False
    
    def _is_scanned_image(self, image: Image.Image, file_path: Path) -> bool:
        """Heuristic to determine if image is a scanned document."""
        try:
            width, height = image.size
            
            # Check aspect ratio - documents usually have standard ratios
            aspect_ratio = width / height
            document_ratios = [
                (8.5 / 11.0),    # US Letter
                (210 / 297),     # A4
                (1 / 1.414),     # A-series general
                (11.0 / 8.5),    # US Letter landscape
                (297 / 210),     # A4 landscape
            ]
            
            ratio_match = any(abs(aspect_ratio - ratio) < 0.1 for ratio in document_ratios)
            
            # Check file size vs dimensions (scanned docs tend to be larger files)
            file_size_mb = file_path.stat().st_size / (1024 * 1024)
            pixels = width * height
            
            # Rough heuristic: if file size is large relative to pixel count, likely scanned
            size_density = file_size_mb / (pixels / 1000000)  # MB per megapixel
            
            # Check image mode (scanned documents often in specific modes)
            mode_indicators = image.mode in ['L', 'RGB']  # Grayscale or RGB
            
            # Combine heuristics
            scanned_indicators = sum([
                ratio_match,
                size_density > 0.5,  # Large file relative to pixels
                mode_indicators,
                width > 1000 and height > 1000  # High resolution
            ])
            
            return scanned_indicators >= 3
            
        except Exception as e:
            logger.warning(f"Scanned image detection failed: {e}")
            return False
    
    def get_supported_formats(self) -> Dict[str, List[str]]:
        """Get list of supported formats by type."""
        return {
            'pdf': ['.pdf'],
            'images': ['.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp', '.webp', '.gif'],
            'mime_types': list(self.mime_mapping.keys())
        }
    
    def validate_document(self, file_path: Union[str, Path]) -> Tuple[bool, str]:
        """Validate if document can be processed."""
        file_path = Path(file_path)
        
        # Check if file exists
        if not file_path.exists():
            return False, f"File does not exist: {file_path}"
        
        # Check file extension
        file_ext = file_path.suffix.lower()
        if file_ext not in self.extension_mapping:
            return False, f"Unsupported file format: {file_ext}"
        
        # Check file size (100MB limit)
        file_size_mb = file_path.stat().st_size / (1024 * 1024)
        if file_size_mb > 100:
            return False, f"File too large: {file_size_mb:.1f}MB > 100MB"
        
        # Specific validation based on type
        doc_type = self.extension_mapping[file_ext]
        
        if doc_type == DocumentType.PDF:
            return self.pdf_processor.validate_pdf(file_path)
        elif doc_type == DocumentType.IMAGE:
            return self.image_processor.validate_image(file_path)
        
        return True, "Document is valid"
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """Get comprehensive processing statistics."""
        return {
            'supported_formats': self.get_supported_formats(),
            'processors': {
                'pdf': self.pdf_processor.get_processing_stats(),
                'image': self.image_processor.get_processing_stats(),
                'scanner': self.scanner_processor.get_processing_stats()
            },
            'document_types': [dt.value for dt in DocumentType],
            'processing_modes': [pm.value for pm in ProcessingMode],
            'features': [
                'automatic_format_detection',
                'multi_format_support',
                'scanned_document_detection',
                'unified_processing_results',
                'quality_optimization',
                'ocr_preparation'
            ]
        }