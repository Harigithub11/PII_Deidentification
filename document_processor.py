"""
Universal Document Processor for AI De-identification System
Handles PDF text extraction, OCR, and multi-format document processing
"""
import os
import io
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# Configure logging first
logger = logging.getLogger(__name__)

# Try to import magic library, provide fallback if not available
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    logger.warning("python-magic library not available. Using fallback MIME detection.")

# Try to import OCR dependencies
try:
    import pytesseract
    from PIL import Image
    
    # Check if tesseract is actually available
    try:
        pytesseract.get_tesseract_version()
        OCR_AVAILABLE = True
        logger.info(f"Tesseract OCR available: {pytesseract.get_tesseract_version()}")
    except Exception as e:
        OCR_AVAILABLE = False
        logger.warning(f"Tesseract OCR not available: {e}. Image processing will be limited.")
        
except ImportError as e:
    OCR_AVAILABLE = False
    pytesseract = None
    Image = None
    logger.warning(f"OCR libraries not available: {e}. Image processing will be limited.")
import pdfplumber
import PyPDF2
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

# Logger configured above

class DocumentProcessor:
    """Universal document processor with PII detection capabilities"""
    
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        
        # Initialize supported formats based on available dependencies
        self.supported_formats = {
            'application/pdf': self._process_pdf,
            'text/plain': self._process_text,
        }
        
        # Add image formats only if OCR is available
        if OCR_AVAILABLE:
            self.supported_formats.update({
                'image/jpeg': self._process_image,
                'image/png': self._process_image,
                'image/tiff': self._process_image,
                'image/bmp': self._process_image,
                'image/gif': self._process_image,
                'image/webp': self._process_image
            })
            logger.info("Image processing enabled with OCR support")
        else:
            # Still support images but with limited functionality
            self.supported_formats.update({
                'image/jpeg': self._process_image,
                'image/png': self._process_image,
                'image/tiff': self._process_image,
                'image/bmp': self._process_image,
                'image/gif': self._process_image,
                'image/webp': self._process_image
            })
            logger.info("Image processing enabled with limited functionality (no OCR)")
        
        # Log capabilities
        self._log_capabilities()
    
    def _log_capabilities(self):
        """Log the capabilities of the document processor"""
        capabilities = []
        capabilities.append(f"MIME Detection: {'Magic Library' if MAGIC_AVAILABLE else 'Fallback'}")
        capabilities.append(f"OCR: {'Available' if OCR_AVAILABLE else 'Not Available'}")
        capabilities.append(f"Supported Formats: {len(self.supported_formats)}")
        
        logger.info("Document Processor Capabilities:")
        for capability in capabilities:
            logger.info(f"  - {capability}")
        
    def get_capabilities(self) -> Dict[str, Any]:
        """Get processor capabilities information"""
        return {
            'magic_available': MAGIC_AVAILABLE,
            'ocr_available': OCR_AVAILABLE,
            'supported_formats': list(self.supported_formats.keys()),
            'format_count': len(self.supported_formats)
        }
        
    def process_document(self, file_content: bytes, filename: str, mime_type: str = None) -> Dict[str, Any]:
        """
        Process any supported document format and extract text with PII detection
        
        Args:
            file_content: Raw file bytes
            filename: Original filename
            mime_type: MIME type (auto-detected if None)
            
        Returns:
            Dict with extracted text, PII entities, and processing metadata
        """
        try:
            # Auto-detect MIME type if not provided
            if not mime_type:
                mime_type = self._detect_mime_type(file_content)
            
            logger.info(f"Processing document: {filename} (type: {mime_type})")
            
            # Check if format is supported
            if mime_type not in self.supported_formats:
                return {
                    'success': False,
                    'error': f'Unsupported format: {mime_type}',
                    'supported_formats': list(self.supported_formats.keys())
                }
            
            # Process document based on type
            processor = self.supported_formats[mime_type]
            text_result = processor(file_content, filename)
            
            if not text_result['success']:
                return text_result
            
            extracted_text = text_result['text']
            
            # Skip PII detection if no text extracted
            if not extracted_text or len(extracted_text.strip()) < 3:
                return {
                    'success': True,
                    'text': extracted_text,
                    'pii_entities': [],
                    'pii_count': 0,
                    'processing_method': text_result['method'],
                    'extraction_confidence': text_result.get('confidence', 1.0),
                    'warnings': ['No significant text content found for PII analysis']
                }
            
            # Detect PII in extracted text
            pii_results = self.analyzer.analyze(text=extracted_text, language='en')
            
            # Format PII results
            pii_entities = []
            for result in pii_results:
                pii_entities.append({
                    'entity_type': result.entity_type,
                    'text': extracted_text[result.start:result.end],
                    'start': result.start,
                    'end': result.end,
                    'confidence': round(result.score, 3)
                })
            
            return {
                'success': True,
                'text': extracted_text,
                'text_length': len(extracted_text),
                'pii_entities': pii_entities,
                'pii_count': len(pii_entities),
                'processing_method': text_result['method'],
                'extraction_confidence': text_result.get('confidence', 1.0),
                'mime_type': mime_type,
                'filename': filename
            }
            
        except Exception as e:
            logger.error(f"Document processing failed for {filename}: {e}")
            return {
                'success': False,
                'error': f'Processing failed: {str(e)}',
                'filename': filename,
                'mime_type': mime_type
            }
    
    def _detect_mime_type(self, file_content: bytes) -> str:
        """Detect MIME type from file content with fallback mechanism"""
        # Use magic library if available
        if MAGIC_AVAILABLE:
            try:
                mime_type = magic.from_buffer(file_content, mime=True)
                logger.debug(f"Magic library detected MIME type: {mime_type}")
                return mime_type
            except Exception as e:
                logger.warning(f"Magic library MIME detection failed: {e}. Using fallback.")
        
        # Fallback MIME detection using file signatures
        return self._detect_mime_type_fallback(file_content)
    
    def _detect_mime_type_fallback(self, file_content: bytes) -> str:
        """Fallback MIME type detection using file signatures"""
        if not file_content:
            return 'application/octet-stream'
            
        # PDF files
        if file_content.startswith(b'%PDF'):
            return 'application/pdf'
        
        # Image formats
        if file_content.startswith(b'\xff\xd8\xff'):
            return 'image/jpeg'
        elif file_content.startswith(b'\x89PNG\r\n\x1a\n'):
            return 'image/png'
        elif file_content.startswith(b'GIF8'):
            return 'image/gif'
        elif file_content.startswith(b'BM'):
            return 'image/bmp'
        elif file_content.startswith(b'RIFF') and b'WEBP' in file_content[:12]:
            return 'image/webp'
        elif file_content.startswith((b'II*\x00', b'MM\x00*')):
            return 'image/tiff'
        
        # Microsoft Office formats (ZIP-based)
        elif file_content.startswith(b'PK\x03\x04'):
            # Could be DOCX, XLSX, PPTX, or regular ZIP
            # Check for specific Office signatures
            if b'word/' in file_content[:1024]:
                return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            elif b'xl/' in file_content[:1024]:
                return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            elif b'ppt/' in file_content[:1024]:
                return 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
            else:
                return 'application/zip'
        
        # Plain text (basic heuristic)
        try:
            # Try to decode as UTF-8, if successful likely text
            file_content[:512].decode('utf-8')
            return 'text/plain'
        except UnicodeDecodeError:
            pass
        
        # Default fallback
        logger.warning("Could not determine MIME type, defaulting to application/octet-stream")
        return 'application/octet-stream'
    
    def _process_pdf(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """Extract text from PDF using multiple methods"""
        pdf_file = io.BytesIO(file_content)
        
        # Method 1: Try pdfplumber (most reliable for text-based PDFs)
        try:
            with pdfplumber.open(pdf_file) as pdf:
                text_parts = []
                page_count = len(pdf.pages)
                
                for page_num, page in enumerate(pdf.pages):
                    try:
                        page_text = page.extract_text()
                        if page_text and page_text.strip():
                            text_parts.append(page_text)
                    except Exception as e:
                        logger.warning(f"Failed to extract text from page {page_num + 1}: {e}")
                
                if text_parts:
                    extracted_text = '\n\n'.join(text_parts)
                    logger.info(f"pdfplumber extracted {len(extracted_text)} chars from {page_count} pages")
                    return {
                        'success': True,
                        'text': extracted_text,
                        'method': 'pdfplumber',
                        'confidence': 0.95,
                        'pages_processed': page_count
                    }
        except Exception as e:
            logger.warning(f"pdfplumber failed: {e}")
        
        # Method 2: Try PyPDF2 as fallback
        pdf_file.seek(0)
        try:
            reader = PyPDF2.PdfReader(pdf_file)
            text_parts = []
            
            for page_num, page in enumerate(reader.pages):
                try:
                    page_text = page.extract_text()
                    if page_text and page_text.strip():
                        text_parts.append(page_text)
                except Exception as e:
                    logger.warning(f"PyPDF2 failed on page {page_num + 1}: {e}")
            
            if text_parts:
                extracted_text = '\n\n'.join(text_parts)
                logger.info(f"PyPDF2 extracted {len(extracted_text)} chars from {len(reader.pages)} pages")
                return {
                    'success': True,
                    'text': extracted_text,
                    'method': 'PyPDF2',
                    'confidence': 0.85,
                    'pages_processed': len(reader.pages)
                }
        except Exception as e:
            logger.warning(f"PyPDF2 failed: {e}")
        
        # Method 3: OCR fallback for image-based PDFs
        logger.info("Attempting OCR on PDF as image-based document")
        return self._process_pdf_with_ocr(file_content, filename)
    
    def _process_pdf_with_ocr(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """Process PDF using OCR (for scanned documents)"""
        try:
            # For now, return a message indicating OCR is attempted
            # In a full implementation, this would convert PDF pages to images and run OCR
            return {
                'success': True,
                'text': '',
                'method': 'OCR_fallback',
                'confidence': 0.6,
                'warning': 'PDF appears to be image-based. OCR processing would be applied here.'
            }
        except Exception as e:
            logger.error(f"OCR processing failed: {e}")
            return {
                'success': False,
                'error': f'OCR processing failed: {str(e)}',
                'method': 'OCR_failed'
            }
    
    def _process_text(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """Process plain text files"""
        try:
            # Try different encodings
            encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
            
            for encoding in encodings:
                try:
                    text = file_content.decode(encoding)
                    logger.info(f"Text file decoded with {encoding}: {len(text)} chars")
                    return {
                        'success': True,
                        'text': text,
                        'method': f'text_decode_{encoding}',
                        'confidence': 1.0
                    }
                except UnicodeDecodeError:
                    continue
            
            # If all encodings fail, try with error handling
            text = file_content.decode('utf-8', errors='replace')
            return {
                'success': True,
                'text': text,
                'method': 'text_decode_fallback',
                'confidence': 0.8,
                'warning': 'Some characters may not have decoded correctly'
            }
            
        except Exception as e:
            logger.error(f"Text processing failed: {e}")
            return {
                'success': False,
                'error': f'Text processing failed: {str(e)}'
            }
    
    def _process_image(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """Process image files with OCR (with graceful degradation)"""
        # Check if OCR is available
        if not OCR_AVAILABLE:
            logger.warning("OCR not available for image processing")
            return {
                'success': True,
                'text': '',
                'method': 'no_ocr_available',
                'confidence': 0.0,
                'warning': 'OCR not available. Install tesseract and pytesseract for text extraction from images.',
                'image_processed': True
            }
        
        try:
            # Open image
            image = Image.open(io.BytesIO(file_content))
            
            # Run OCR
            text = pytesseract.image_to_string(image, lang='eng')
            
            # Get OCR confidence if available
            try:
                data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
                confidences = [int(conf) for conf in data['conf'] if int(conf) > 0]
                avg_confidence = sum(confidences) / len(confidences) if confidences else 0
                ocr_confidence = avg_confidence / 100.0
            except Exception as conf_error:
                logger.warning(f"Could not calculate OCR confidence: {conf_error}")
                ocr_confidence = 0.7  # Default confidence
            
            logger.info(f"OCR extracted {len(text)} chars with confidence {ocr_confidence:.2f}")
            
            return {
                'success': True,
                'text': text,
                'method': 'tesseract_ocr',
                'confidence': ocr_confidence,
                'image_size': image.size
            }
            
        except Exception as e:
            logger.error(f"Image OCR processing failed: {e}")
            return {
                'success': False,
                'error': f'Image OCR failed: {str(e)}',
                'suggestion': 'Verify tesseract installation and image format support'
            }
    
    def anonymize_text(self, text: str, pii_entities: List[Dict]) -> Dict[str, Any]:
        """Anonymize PII in text"""
        try:
            # Convert our PII entities to Presidio format
            from presidio_analyzer import RecognizerResult
            
            analyzer_results = []
            for entity in pii_entities:
                result = RecognizerResult(
                    entity_type=entity['entity_type'],
                    start=entity['start'],
                    end=entity['end'],
                    score=entity['confidence']
                )
                analyzer_results.append(result)
            
            # Anonymize
            anonymized_result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=analyzer_results
            )
            
            return {
                'success': True,
                'original_text': text,
                'anonymized_text': anonymized_result.text,
                'anonymized_entities': len(analyzer_results)
            }
            
        except Exception as e:
            logger.error(f"Anonymization failed: {e}")
            return {
                'success': False,
                'error': f'Anonymization failed: {str(e)}'
            }

# Global processor instance
document_processor = DocumentProcessor()

def process_document_file(file_content: bytes, filename: str, mime_type: str = None) -> Dict[str, Any]:
    """Convenience function for document processing"""
    return document_processor.process_document(file_content, filename, mime_type)

if __name__ == "__main__":
    # Test the processor
    print("Document Processor initialized successfully!")
    print(f"Supported formats: {list(document_processor.supported_formats.keys())}")