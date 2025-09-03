"""
Tesseract OCR service integration
"""
import os
import logging
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import fitz  # PyMuPDF
import pytesseract
from PIL import Image
import cv2
import numpy as np

from src.core.config import settings

logger = logging.getLogger(__name__)


class OCRService:
    """
    Tesseract OCR service wrapper
    """
    
    def __init__(self):
        """Initialize OCR service"""
        # Set Tesseract command path if specified
        if settings.TESSERACT_CMD != "tesseract":
            pytesseract.pytesseract.tesseract_cmd = settings.TESSERACT_CMD
        
        # Verify Tesseract installation
        self._verify_tesseract()
    
    def _verify_tesseract(self):
        """Verify Tesseract OCR is properly installed"""
        try:
            version = pytesseract.get_tesseract_version()
            logger.info(f"✅ Tesseract OCR version: {version}")
        except Exception as e:
            logger.error(f"❌ Tesseract OCR not found or not working: {e}")
            raise RuntimeError("Tesseract OCR is not properly installed or configured")
    
    def extract_text_from_image(
        self, 
        image_path: str, 
        language: str = None,
        enhance_image: bool = True
    ) -> Dict[str, any]:
        """
        Extract text from image file using OCR
        
        Args:
            image_path: Path to image file
            language: OCR language (default from settings)
            enhance_image: Whether to enhance image before OCR
            
        Returns:
            Dict containing extracted text and metadata
        """
        if language is None:
            language = settings.OCR_LANGUAGES
        
        try:
            # Load and preprocess image
            image = Image.open(image_path)
            
            if enhance_image:
                image = self._enhance_image(image)
            
            # Custom OCR configuration
            custom_config = f'--oem 3 --psm 6 -l {language}'
            
            # Extract text with confidence scores
            data = pytesseract.image_to_data(
                image, 
                config=custom_config, 
                output_type=pytesseract.Output.DICT
            )
            
            # Extract plain text
            text = pytesseract.image_to_string(
                image, 
                config=custom_config,
                lang=language
            )
            
            # Calculate average confidence
            confidences = [int(conf) for conf in data['conf'] if int(conf) > 0]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0
            
            # Extract word-level details
            words = self._extract_word_details(data)
            
            return {
                "text": text.strip(),
                "language": language,
                "confidence": avg_confidence,
                "word_count": len([word for word in words if word['confidence'] > settings.OCR_CONFIDENCE_THRESHOLD]),
                "words": words,
                "image_dimensions": image.size,
                "success": True
            }
            
        except Exception as e:
            logger.error(f"OCR extraction failed for {image_path}: {e}")
            return {
                "text": "",
                "language": language,
                "confidence": 0,
                "word_count": 0,
                "words": [],
                "error": str(e),
                "success": False
            }
    
    def extract_text_from_pdf(
        self, 
        pdf_path: str, 
        language: str = None,
        max_pages: int = None
    ) -> Dict[str, any]:
        """
        Extract text from PDF file using OCR
        
        Args:
            pdf_path: Path to PDF file
            language: OCR language (default from settings)
            max_pages: Maximum pages to process (None for all)
            
        Returns:
            Dict containing extracted text and metadata
        """
        if language is None:
            language = settings.OCR_LANGUAGES
        
        try:
            doc = fitz.open(pdf_path)
            total_pages = len(doc)
            
            if max_pages:
                total_pages = min(total_pages, max_pages)
            
            all_text = []
            all_words = []
            page_results = []
            total_confidence = 0
            
            for page_num in range(total_pages):
                page = doc[page_num]
                
                # First try to extract text directly (for text-based PDFs)
                direct_text = page.get_text()
                
                if direct_text.strip():
                    # Text-based PDF
                    page_result = {
                        "page_number": page_num + 1,
                        "text": direct_text,
                        "method": "direct",
                        "confidence": 100,
                        "word_count": len(direct_text.split())
                    }
                else:
                    # Image-based PDF - use OCR
                    # Convert page to image
                    mat = fitz.Matrix(2.0, 2.0)  # 2x zoom for better OCR
                    pix = page.get_pixmap(matrix=mat)
                    
                    # Save as temporary image
                    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp_file:
                        pix.save(tmp_file.name)
                        
                        # Run OCR on page image
                        ocr_result = self.extract_text_from_image(
                            tmp_file.name, 
                            language=language
                        )
                        
                        # Clean up temporary file
                        os.unlink(tmp_file.name)
                        
                        page_result = {
                            "page_number": page_num + 1,
                            "text": ocr_result["text"],
                            "method": "ocr",
                            "confidence": ocr_result["confidence"],
                            "word_count": ocr_result["word_count"],
                            "words": ocr_result.get("words", [])
                        }
                        
                        all_words.extend(ocr_result.get("words", []))
                
                all_text.append(page_result["text"])
                page_results.append(page_result)
                total_confidence += page_result["confidence"]
                
                logger.info(f"Processed page {page_num + 1}/{total_pages} of {Path(pdf_path).name}")
            
            doc.close()
            
            # Calculate overall statistics
            combined_text = "\n\n".join(all_text)
            avg_confidence = total_confidence / total_pages if total_pages > 0 else 0
            
            return {
                "text": combined_text,
                "language": language,
                "confidence": avg_confidence,
                "total_pages": total_pages,
                "word_count": len(combined_text.split()),
                "pages": page_results,
                "words": all_words,
                "success": True
            }
            
        except Exception as e:
            logger.error(f"PDF OCR extraction failed for {pdf_path}: {e}")
            return {
                "text": "",
                "language": language,
                "confidence": 0,
                "total_pages": 0,
                "word_count": 0,
                "pages": [],
                "words": [],
                "error": str(e),
                "success": False
            }
    
    def _enhance_image(self, image: Image.Image) -> Image.Image:
        """
        Enhance image quality for better OCR results
        """
        try:
            # Convert to OpenCV format
            opencv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            
            # Convert to grayscale
            gray = cv2.cvtColor(opencv_image, cv2.COLOR_BGR2GRAY)
            
            # Apply denoising
            denoised = cv2.fastNlMeansDenoising(gray)
            
            # Apply adaptive threshold
            thresh = cv2.adaptiveThreshold(
                denoised, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                cv2.THRESH_BINARY, 11, 2
            )
            
            # Convert back to PIL Image
            enhanced_image = Image.fromarray(thresh)
            
            return enhanced_image
            
        except Exception as e:
            logger.warning(f"Image enhancement failed, using original: {e}")
            return image
    
    def _extract_word_details(self, ocr_data: Dict) -> List[Dict]:
        """
        Extract word-level details from Tesseract OCR data
        """
        words = []
        
        for i, word_text in enumerate(ocr_data['text']):
            if word_text.strip():
                confidence = int(ocr_data['conf'][i])
                
                if confidence > settings.OCR_CONFIDENCE_THRESHOLD:
                    words.append({
                        "text": word_text,
                        "confidence": confidence,
                        "bbox": {
                            "left": int(ocr_data['left'][i]),
                            "top": int(ocr_data['top'][i]),
                            "width": int(ocr_data['width'][i]),
                            "height": int(ocr_data['height'][i])
                        }
                    })
        
        return words
    
    def get_supported_languages(self) -> List[str]:
        """
        Get list of languages supported by Tesseract installation
        """
        try:
            languages = pytesseract.get_languages(config='')
            return sorted(languages)
        except Exception as e:
            logger.error(f"Failed to get supported languages: {e}")
            return ["eng"]  # Default fallback
    
    def health_check(self) -> bool:
        """
        Check if OCR service is working properly
        """
        try:
            # Create a simple test image with text
            test_image = Image.new('RGB', (200, 50), color='white')
            
            # Test OCR on simple image
            result = pytesseract.image_to_string(test_image, config='--psm 6')
            
            # Service is working if no exception is raised
            return True
            
        except Exception as e:
            logger.error(f"OCR health check failed: {e}")
            return False


# Global OCR service instance
ocr_service = OCRService()