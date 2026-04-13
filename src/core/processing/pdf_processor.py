"""
PDF Processor for PII De-identification System

This module handles PDF document processing including text extraction,
image extraction, and multi-page document handling.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union
import io
import base64
from dataclasses import dataclass

import fitz  # PyMuPDF
import PyPDF2
from PIL import Image
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class PDFPageContent:
    """Container for PDF page content."""
    page_number: int
    text_content: str
    images: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    bbox_info: List[Dict[str, Any]]
    confidence_score: float


@dataclass
class PDFProcessingResult:
    """Container for PDF processing results."""
    success: bool
    total_pages: int
    pages: List[PDFPageContent]
    document_metadata: Dict[str, Any]
    processing_errors: List[str]
    file_info: Dict[str, Any]


class PDFProcessor:
    """PDF document processor with multi-page support."""
    
    def __init__(self):
        self.supported_formats = ['.pdf']
        self.max_file_size_mb = 100
        self.max_pages = 500
        self.image_formats = ['jpeg', 'png', 'tiff']
        
        logger.info("PDFProcessor initialized")
    
    def validate_pdf(self, file_path: Union[str, Path]) -> Tuple[bool, str]:
        """Validate PDF file before processing."""
        try:
            file_path = Path(file_path)
            
            # Check file exists
            if not file_path.exists():
                return False, f"File does not exist: {file_path}"
            
            # Check file extension
            if file_path.suffix.lower() not in self.supported_formats:
                return False, f"Unsupported format: {file_path.suffix}"
            
            # Check file size
            file_size_mb = file_path.stat().st_size / (1024 * 1024)
            if file_size_mb > self.max_file_size_mb:
                return False, f"File too large: {file_size_mb:.1f}MB > {self.max_file_size_mb}MB"
            
            # Try to open with PyMuPDF
            try:
                doc = fitz.open(str(file_path))
                page_count = len(doc)
                doc.close()
                
                if page_count > self.max_pages:
                    return False, f"Too many pages: {page_count} > {self.max_pages}"
                
                return True, "Valid PDF file"
            except Exception as e:
                return False, f"Cannot open PDF: {str(e)}"
                
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    def process_pdf(self, file_path: Union[str, Path]) -> PDFProcessingResult:
        """Process PDF file and extract all content."""
        file_path = Path(file_path)
        
        # Validate file first
        is_valid, validation_msg = self.validate_pdf(file_path)
        if not is_valid:
            return PDFProcessingResult(
                success=False,
                total_pages=0,
                pages=[],
                document_metadata={},
                processing_errors=[validation_msg],
                file_info={}
            )
        
        try:
            return self._process_with_pymupdf(file_path)
        except Exception as e:
            logger.warning(f"PyMuPDF failed, trying PyPDF2: {e}")
            try:
                return self._process_with_pypdf2(file_path)
            except Exception as e2:
                return PDFProcessingResult(
                    success=False,
                    total_pages=0,
                    pages=[],
                    document_metadata={},
                    processing_errors=[f"Both processors failed: PyMuPDF: {e}, PyPDF2: {e2}"],
                    file_info={'file_path': str(file_path)}
                )
    
    def _process_with_pymupdf(self, file_path: Path) -> PDFProcessingResult:
        """Process PDF using PyMuPDF (fitz)."""
        doc = fitz.open(str(file_path))
        pages = []
        processing_errors = []
        
        try:
            # Extract document metadata
            doc_metadata = self._extract_document_metadata_pymupdf(doc)
            
            # Process each page
            for page_num in range(len(doc)):
                try:
                    page_content = self._process_page_pymupdf(doc, page_num)
                    pages.append(page_content)
                except Exception as e:
                    error_msg = f"Error processing page {page_num + 1}: {str(e)}"
                    logger.error(error_msg)
                    processing_errors.append(error_msg)
            
            file_info = {
                'file_path': str(file_path),
                'file_size_mb': file_path.stat().st_size / (1024 * 1024),
                'processor_used': 'PyMuPDF'
            }
            
            return PDFProcessingResult(
                success=len(pages) > 0,
                total_pages=len(doc),
                pages=pages,
                document_metadata=doc_metadata,
                processing_errors=processing_errors,
                file_info=file_info
            )
            
        finally:
            doc.close()
    
    def _process_page_pymupdf(self, doc: fitz.Document, page_num: int) -> PDFPageContent:
        """Process a single page with PyMuPDF."""
        page = doc.load_page(page_num)
        
        # Extract text
        text_content = page.get_text()
        
        # Extract text with position information
        text_dict = page.get_text("dict")
        bbox_info = self._extract_bbox_info_pymupdf(text_dict)
        
        # Extract images
        images = self._extract_images_pymupdf(page, page_num)
        
        # Extract page metadata
        page_metadata = {
            'page_number': page_num + 1,
            'rotation': page.rotation,
            'mediabox': list(page.mediabox),
            'rect': list(page.rect),
            'word_count': len(text_content.split()) if text_content else 0,
            'image_count': len(images)
        }
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(text_content, images, bbox_info)
        
        return PDFPageContent(
            page_number=page_num + 1,
            text_content=text_content,
            images=images,
            metadata=page_metadata,
            bbox_info=bbox_info,
            confidence_score=confidence_score
        )
    
    def _extract_images_pymupdf(self, page: fitz.Page, page_num: int) -> List[Dict[str, Any]]:
        """Extract images from PDF page using PyMuPDF."""
        images = []
        image_list = page.get_images()
        
        for img_index, img in enumerate(image_list):
            try:
                # Get the image
                xref = img[0]
                base_image = page.parent.extract_image(xref)
                image_bytes = base_image["image"]
                image_ext = base_image["ext"]
                
                # Convert to PIL Image for processing
                pil_image = Image.open(io.BytesIO(image_bytes))
                
                # Get image info
                width, height = pil_image.size
                
                image_info = {
                    'index': img_index,
                    'page_number': page_num + 1,
                    'format': image_ext,
                    'size': (width, height),
                    'mode': pil_image.mode,
                    'bbox': list(page.get_image_bbox(img)),
                    'image_data': base64.b64encode(image_bytes).decode('utf-8'),
                    'image_size_bytes': len(image_bytes)
                }
                
                images.append(image_info)
                
            except Exception as e:
                logger.warning(f"Failed to extract image {img_index} from page {page_num + 1}: {e}")
        
        return images
    
    def _extract_bbox_info_pymupdf(self, text_dict: Dict) -> List[Dict[str, Any]]:
        """Extract bounding box information for text elements."""
        bbox_info = []
        
        for block in text_dict.get("blocks", []):
            if "lines" in block:  # Text block
                for line in block["lines"]:
                    for span in line["spans"]:
                        bbox_info.append({
                            'text': span.get('text', ''),
                            'bbox': span.get('bbox', []),
                            'font': span.get('font', ''),
                            'size': span.get('size', 0),
                            'flags': span.get('flags', 0),
                            'color': span.get('color', 0)
                        })
        
        return bbox_info
    
    def _extract_document_metadata_pymupdf(self, doc: fitz.Document) -> Dict[str, Any]:
        """Extract document metadata using PyMuPDF."""
        metadata = doc.metadata
        
        return {
            'title': metadata.get('title', ''),
            'author': metadata.get('author', ''),
            'subject': metadata.get('subject', ''),
            'creator': metadata.get('creator', ''),
            'producer': metadata.get('producer', ''),
            'creation_date': metadata.get('creationDate', ''),
            'modification_date': metadata.get('modDate', ''),
            'trapped': metadata.get('trapped', ''),
            'keywords': metadata.get('keywords', ''),
            'page_count': len(doc),
            'is_encrypted': doc.is_encrypted,
            'needs_pass': doc.needs_pass,
            'permissions': doc.permissions
        }
    
    def _process_with_pypdf2(self, file_path: Path) -> PDFProcessingResult:
        """Process PDF using PyPDF2 as fallback."""
        pages = []
        processing_errors = []
        
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                # Check if PDF is encrypted
                if pdf_reader.is_encrypted:
                    processing_errors.append("PDF is encrypted - cannot process")
                    return PDFProcessingResult(
                        success=False,
                        total_pages=0,
                        pages=[],
                        document_metadata={},
                        processing_errors=processing_errors,
                        file_info={'file_path': str(file_path)}
                    )
                
                # Extract document metadata
                doc_metadata = self._extract_document_metadata_pypdf2(pdf_reader)
                
                # Process each page
                for page_num, page in enumerate(pdf_reader.pages):
                    try:
                        page_content = self._process_page_pypdf2(page, page_num)
                        pages.append(page_content)
                    except Exception as e:
                        error_msg = f"Error processing page {page_num + 1}: {str(e)}"
                        logger.error(error_msg)
                        processing_errors.append(error_msg)
                
                file_info = {
                    'file_path': str(file_path),
                    'file_size_mb': file_path.stat().st_size / (1024 * 1024),
                    'processor_used': 'PyPDF2'
                }
                
                return PDFProcessingResult(
                    success=len(pages) > 0,
                    total_pages=len(pdf_reader.pages),
                    pages=pages,
                    document_metadata=doc_metadata,
                    processing_errors=processing_errors,
                    file_info=file_info
                )
                
        except Exception as e:
            return PDFProcessingResult(
                success=False,
                total_pages=0,
                pages=[],
                document_metadata={},
                processing_errors=[f"PyPDF2 processing failed: {str(e)}"],
                file_info={'file_path': str(file_path)}
            )
    
    def _process_page_pypdf2(self, page: PyPDF2.PageObject, page_num: int) -> PDFPageContent:
        """Process a single page with PyPDF2."""
        # Extract text
        try:
            text_content = page.extract_text()
        except Exception as e:
            text_content = ""
            logger.warning(f"Failed to extract text from page {page_num + 1}: {e}")
        
        # PyPDF2 has limited image extraction capabilities
        images = []  # Would need additional processing for image extraction
        
        # Limited bbox information from PyPDF2
        bbox_info = []
        
        # Extract page metadata
        page_metadata = {
            'page_number': page_num + 1,
            'rotation': page.get('/Rotate', 0),
            'mediabox': list(page.mediabox) if hasattr(page, 'mediabox') else [],
            'word_count': len(text_content.split()) if text_content else 0,
            'image_count': 0
        }
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(text_content, images, bbox_info)
        
        return PDFPageContent(
            page_number=page_num + 1,
            text_content=text_content,
            images=images,
            metadata=page_metadata,
            bbox_info=bbox_info,
            confidence_score=confidence_score
        )
    
    def _extract_document_metadata_pypdf2(self, pdf_reader: PyPDF2.PdfReader) -> Dict[str, Any]:
        """Extract document metadata using PyPDF2."""
        try:
            metadata = pdf_reader.metadata
            if metadata:
                return {
                    'title': metadata.get('/Title', ''),
                    'author': metadata.get('/Author', ''),
                    'subject': metadata.get('/Subject', ''),
                    'creator': metadata.get('/Creator', ''),
                    'producer': metadata.get('/Producer', ''),
                    'creation_date': metadata.get('/CreationDate', ''),
                    'modification_date': metadata.get('/ModDate', ''),
                    'page_count': len(pdf_reader.pages),
                    'is_encrypted': pdf_reader.is_encrypted
                }
        except Exception as e:
            logger.warning(f"Failed to extract metadata: {e}")
        
        return {
            'page_count': len(pdf_reader.pages),
            'is_encrypted': pdf_reader.is_encrypted
        }
    
    def _calculate_confidence_score(self, text: str, images: List, bbox_info: List) -> float:
        """Calculate confidence score for page processing."""
        score = 0.0
        
        # Text content score (0-40%)
        if text and len(text.strip()) > 0:
            score += min(40.0, len(text.split()) * 2)
        
        # Image extraction score (0-30%)
        if images:
            score += min(30.0, len(images) * 10)
        
        # Structure information score (0-30%)
        if bbox_info:
            score += min(30.0, len(bbox_info) * 0.5)
        
        return min(100.0, score)
    
    def extract_page_as_image(self, file_path: Union[str, Path], page_num: int, dpi: int = 200) -> Optional[Image.Image]:
        """Extract a specific page as an image for OCR processing."""
        try:
            doc = fitz.open(str(file_path))
            if page_num >= len(doc):
                logger.error(f"Page {page_num} does not exist in PDF")
                return None
            
            page = doc.load_page(page_num)
            
            # Render page as image
            mat = fitz.Matrix(dpi/72, dpi/72)  # Scaling matrix
            pix = page.get_pixmap(matrix=mat)
            
            # Convert to PIL Image
            img_data = pix.tobytes("ppm")
            img = Image.open(io.BytesIO(img_data))
            
            doc.close()
            return img
            
        except Exception as e:
            logger.error(f"Failed to extract page {page_num} as image: {e}")
            return None
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """Get processor statistics and capabilities."""
        return {
            'supported_formats': self.supported_formats,
            'max_file_size_mb': self.max_file_size_mb,
            'max_pages': self.max_pages,
            'image_formats': self.image_formats,
            'features': [
                'text_extraction',
                'image_extraction',
                'metadata_extraction',
                'bbox_information',
                'multi_page_support',
                'page_as_image_rendering'
            ]
        }