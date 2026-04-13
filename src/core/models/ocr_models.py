"""
OCR Models for PII De-identification System

This module provides OCR model implementations with support for:
- Tesseract OCR with advanced configuration
- PaddleOCR as alternative engine
- Text confidence scoring and language detection
- Integration with model manager for memory optimization
"""

import logging
import os
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass
from enum import Enum
import json
import re

import numpy as np
from PIL import Image
import cv2

logger = logging.getLogger(__name__)


class OCREngine(Enum):
    """Supported OCR engines."""
    TESSERACT = "tesseract"
    PADDLE = "paddle"


class LanguageCode(Enum):
    """Common language codes for OCR."""
    ENGLISH = "eng"
    HINDI = "hin"
    BENGALI = "ben"
    TELUGU = "tel"
    MARATHI = "mar"
    TAMIL = "tam"
    GUJARATI = "guj"
    KANNADA = "kan"
    MALAYALAM = "mal"
    PUNJABI = "pan"
    URDU = "urd"
    SPANISH = "spa"
    FRENCH = "fra"
    GERMAN = "deu"
    CHINESE = "chi_sim"
    JAPANESE = "jpn"
    KOREAN = "kor"
    ARABIC = "ara"


@dataclass
class OCRBoundingBox:
    """Container for OCR text bounding box information."""
    text: str
    confidence: float
    x: int
    y: int
    width: int
    height: int
    page_number: int = 0
    
    @property
    def coordinates(self) -> Tuple[int, int, int, int]:
        """Get bounding box coordinates as (x, y, x+width, y+height)."""
        return (self.x, self.y, self.x + self.width, self.y + self.height)
    
    @property
    def area(self) -> int:
        """Calculate bounding box area."""
        return self.width * self.height


@dataclass
class OCRTextBlock:
    """Container for OCR text block with hierarchical information."""
    text: str
    confidence: float
    level: str  # 'block', 'paragraph', 'line', 'word'
    bbox: OCRBoundingBox
    language_detected: Optional[str] = None
    font_info: Optional[Dict[str, Any]] = None
    

@dataclass
class OCRResult:
    """Container for OCR processing results."""
    success: bool
    text_content: str
    confidence_score: float
    text_blocks: List[OCRTextBlock]
    bounding_boxes: List[OCRBoundingBox]
    processing_time: float
    page_number: int
    language_detected: Optional[str] = None
    image_dimensions: Tuple[int, int] = (0, 0)
    preprocessing_applied: List[str] = None
    engine_used: str = ""
    engine_version: str = ""
    processing_errors: List[str] = None
    
    def __post_init__(self):
        if self.preprocessing_applied is None:
            self.preprocessing_applied = []
        if self.processing_errors is None:
            self.processing_errors = []
    
    @property
    def word_count(self) -> int:
        """Get word count from extracted text."""
        return len(self.text_content.split()) if self.text_content else 0
    
    @property
    def character_count(self) -> int:
        """Get character count from extracted text."""
        return len(self.text_content) if self.text_content else 0


class OCRModel(ABC):
    """Abstract base class for OCR models."""
    
    def __init__(self, engine: OCREngine, languages: List[LanguageCode] = None):
        self.engine = engine
        self.languages = languages or [LanguageCode.ENGLISH]
        self.is_loaded = False
        self._model_instance = None
        self.supported_formats = ['.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.gif']
        
    @abstractmethod
    def load(self) -> bool:
        """Load the OCR model."""
        pass
    
    @abstractmethod
    def unload(self):
        """Unload the OCR model to free memory."""
        pass
    
    @abstractmethod
    def extract_text(self, image: Union[str, Path, Image.Image, np.ndarray], 
                    page_number: int = 0, **kwargs) -> OCRResult:
        """Extract text from image using OCR."""
        pass
    
    @abstractmethod
    def get_available_languages(self) -> List[str]:
        """Get list of available languages for this OCR engine."""
        pass
    
    def validate_image(self, image: Union[str, Path, Image.Image, np.ndarray]) -> bool:
        """Validate if image can be processed."""
        try:
            if isinstance(image, (str, Path)):
                path = Path(image)
                return path.exists() and path.suffix.lower() in self.supported_formats
            elif isinstance(image, Image.Image):
                return image.size[0] > 0 and image.size[1] > 0
            elif isinstance(image, np.ndarray):
                return image.size > 0
            return False
        except Exception:
            return False
    
    def preprocess_image(self, image: Union[Image.Image, np.ndarray], 
                        apply_enhancements: bool = True) -> Tuple[np.ndarray, List[str]]:
        """Preprocess image for better OCR results."""
        operations = []
        
        try:
            # Convert PIL Image to numpy array if needed
            if isinstance(image, Image.Image):
                img_array = np.array(image)
                operations.append("converted_pil_to_numpy")
            else:
                img_array = image.copy()
            
            # Convert to grayscale if needed
            if len(img_array.shape) == 3 and img_array.shape[2] == 3:
                img_array = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
                operations.append("converted_to_grayscale")
            elif len(img_array.shape) == 3 and img_array.shape[2] == 4:
                img_array = cv2.cvtColor(img_array, cv2.COLOR_RGBA2GRAY)
                operations.append("converted_rgba_to_grayscale")
            
            if apply_enhancements:
                # Apply Gaussian blur to reduce noise
                img_array = cv2.GaussianBlur(img_array, (1, 1), 0)
                operations.append("applied_gaussian_blur")
                
                # Apply adaptive thresholding for better text detection
                img_array = cv2.adaptiveThreshold(
                    img_array, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
                )
                operations.append("applied_adaptive_threshold")
                
                # Apply morphological operations to clean up text
                kernel = np.ones((1, 1), np.uint8)
                img_array = cv2.morphologyEx(img_array, cv2.MORPH_CLOSE, kernel)
                operations.append("applied_morphological_closing")
                
                # Denoise using Non-local Means Denoising
                img_array = cv2.fastNlMeansDenoising(img_array, None, 10, 7, 21)
                operations.append("applied_nlm_denoising")
            
            return img_array, operations
            
        except Exception as e:
            logger.warning(f"Image preprocessing failed: {e}")
            # Return original image if preprocessing fails
            if isinstance(image, Image.Image):
                return np.array(image), ["preprocessing_failed"]
            return image, ["preprocessing_failed"]


class TesseractOCRModel(OCRModel):
    """Tesseract OCR model implementation with advanced configuration."""
    
    def __init__(self, languages: List[LanguageCode] = None, 
                 tesseract_path: Optional[str] = None,
                 tessdata_dir: Optional[str] = None):
        super().__init__(OCREngine.TESSERACT, languages)
        self.tesseract_path = tesseract_path
        self.tessdata_dir = tessdata_dir
        self._pytesseract = None
        
        # Tesseract configuration options
        self.config_options = {
            'default': '--oem 3 --psm 6',
            'single_line': '--oem 3 --psm 7',
            'single_word': '--oem 3 --psm 8',
            'single_char': '--oem 3 --psm 10',
            'vertical_text': '--oem 3 --psm 5',
            'single_block': '--oem 3 --psm 6',
            'uniform_block': '--oem 3 --psm 13'
        }
        
    def load(self) -> bool:
        """Load Tesseract OCR model."""
        try:
            import pytesseract
            self._pytesseract = pytesseract
            
            # Set Tesseract path if provided
            if self.tesseract_path:
                pytesseract.pytesseract.tesseract_cmd = self.tesseract_path
            else:
                # Try to find Tesseract binary
                tesseract_cmd = self._find_tesseract_binary()
                if tesseract_cmd:
                    pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
            
            # Set tessdata directory if provided
            if self.tessdata_dir:
                os.environ['TESSDATA_PREFIX'] = self.tessdata_dir
            
            # Test Tesseract installation
            version = pytesseract.get_tesseract_version()
            logger.info(f"Tesseract version: {version}")
            
            # Verify languages are available
            available_langs = self.get_available_languages()
            requested_langs = [lang.value for lang in self.languages]
            missing_langs = set(requested_langs) - set(available_langs)
            
            if missing_langs:
                logger.warning(f"Missing language packs: {missing_langs}")
            
            self.is_loaded = True
            logger.info("Tesseract OCR model loaded successfully")
            return True
            
        except ImportError:
            logger.error("pytesseract not installed. Install with: pip install pytesseract")
            return False
        except Exception as e:
            logger.error(f"Failed to load Tesseract OCR model: {e}")
            return False
    
    def unload(self):
        """Unload Tesseract OCR model."""
        self._pytesseract = None
        self.is_loaded = False
        logger.info("Tesseract OCR model unloaded")
    
    def _find_tesseract_binary(self) -> Optional[str]:
        """Find Tesseract binary in common locations."""
        common_paths = [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",  # Windows
            r"C:\Users\AppData\Local\Programs\Tesseract-OCR\tesseract.exe",  # Windows user
            "/usr/bin/tesseract",  # Linux
            "/usr/local/bin/tesseract",  # macOS/Linux
            "/opt/homebrew/bin/tesseract",  # macOS ARM
            "/snap/bin/tesseract"  # Snap package
        ]
        
        # Check common paths first
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        # Try to find in PATH
        tesseract_path = shutil.which("tesseract")
        if tesseract_path:
            return tesseract_path
        
        logger.warning("Tesseract binary not found in common locations")
        return None
    
    def get_available_languages(self) -> List[str]:
        """Get list of available languages for Tesseract."""
        if not self.is_loaded:
            return []
        
        try:
            langs = self._pytesseract.get_languages(config='')
            return langs
        except Exception as e:
            logger.warning(f"Failed to get available languages: {e}")
            return ['eng']  # Default to English
    
    def extract_text(self, image: Union[str, Path, Image.Image, np.ndarray], 
                    page_number: int = 0, config_mode: str = 'default',
                    apply_preprocessing: bool = True, **kwargs) -> OCRResult:
        """Extract text from image using Tesseract OCR."""
        import time
        start_time = time.time()
        
        if not self.is_loaded:
            return OCRResult(
                success=False,
                text_content="",
                confidence_score=0.0,
                text_blocks=[],
                bounding_boxes=[],
                processing_time=0.0,
                page_number=page_number,
                processing_errors=["Model not loaded"]
            )
        
        try:
            # Load and validate image
            if isinstance(image, (str, Path)):
                pil_image = Image.open(image)
            elif isinstance(image, np.ndarray):
                pil_image = Image.fromarray(image)
            else:
                pil_image = image
            
            if not self.validate_image(pil_image):
                return OCRResult(
                    success=False,
                    text_content="",
                    confidence_score=0.0,
                    text_blocks=[],
                    bounding_boxes=[],
                    processing_time=time.time() - start_time,
                    page_number=page_number,
                    processing_errors=["Invalid image format"]
                )
            
            # Preprocess image if requested
            preprocessing_operations = []
            if apply_preprocessing:
                img_array, preprocessing_operations = self.preprocess_image(pil_image)
                processed_image = Image.fromarray(img_array)
            else:
                processed_image = pil_image
            
            # Prepare language string
            lang_string = '+'.join([lang.value for lang in self.languages])
            
            # Get configuration
            config = self.config_options.get(config_mode, self.config_options['default'])
            
            # Extract text with detailed information
            detailed_data = self._pytesseract.image_to_data(
                processed_image, 
                lang=lang_string, 
                config=config,
                output_type=self._pytesseract.Output.DICT
            )
            
            # Extract basic text
            text_content = self._pytesseract.image_to_string(
                processed_image,
                lang=lang_string,
                config=config
            ).strip()
            
            # Process detailed OCR data
            text_blocks, bounding_boxes, overall_confidence = self._process_tesseract_data(
                detailed_data, page_number
            )
            
            # Detect language (use first detected language from blocks)
            language_detected = None
            for block in text_blocks:
                if block.language_detected:
                    language_detected = block.language_detected
                    break
            
            processing_time = time.time() - start_time
            
            return OCRResult(
                success=True,
                text_content=text_content,
                confidence_score=overall_confidence,
                text_blocks=text_blocks,
                bounding_boxes=bounding_boxes,
                processing_time=processing_time,
                page_number=page_number,
                language_detected=language_detected,
                image_dimensions=pil_image.size,
                preprocessing_applied=preprocessing_operations,
                engine_used="Tesseract",
                engine_version=str(self._pytesseract.get_tesseract_version()),
                processing_errors=[]
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Tesseract OCR failed: {e}")
            return OCRResult(
                success=False,
                text_content="",
                confidence_score=0.0,
                text_blocks=[],
                bounding_boxes=[],
                processing_time=processing_time,
                page_number=page_number,
                processing_errors=[str(e)]
            )
    
    def _process_tesseract_data(self, data: Dict, page_number: int) -> Tuple[List[OCRTextBlock], List[OCRBoundingBox], float]:
        """Process detailed Tesseract OCR data into structured format."""
        text_blocks = []
        bounding_boxes = []
        confidences = []
        
        try:
            for i in range(len(data['text'])):
                text = data['text'][i].strip()
                if not text:
                    continue
                
                confidence = float(data['conf'][i])
                if confidence < 0:  # Tesseract uses -1 for no confidence
                    continue
                
                confidences.append(confidence)
                
                # Create bounding box
                bbox = OCRBoundingBox(
                    text=text,
                    confidence=confidence,
                    x=data['left'][i],
                    y=data['top'][i],
                    width=data['width'][i],
                    height=data['height'][i],
                    page_number=page_number
                )
                bounding_boxes.append(bbox)
                
                # Create text block
                level_map = {
                    1: 'page',
                    2: 'block',
                    3: 'paragraph',
                    4: 'line',
                    5: 'word'
                }
                
                level = level_map.get(data['level'][i], 'unknown')
                
                text_block = OCRTextBlock(
                    text=text,
                    confidence=confidence,
                    level=level,
                    bbox=bbox
                )
                text_blocks.append(text_block)
            
            # Calculate overall confidence
            overall_confidence = np.mean(confidences) if confidences else 0.0
            
            return text_blocks, bounding_boxes, overall_confidence
            
        except Exception as e:
            logger.warning(f"Failed to process Tesseract data: {e}")
            return [], [], 0.0


class PaddleOCRModel(OCRModel):
    """PaddleOCR model implementation as alternative OCR engine."""
    
    def __init__(self, languages: List[str] = None, use_gpu: bool = False):
        # Convert to LanguageCode enum if strings provided
        if languages:
            lang_codes = []
            for lang in languages:
                try:
                    lang_codes.append(LanguageCode(lang))
                except ValueError:
                    logger.warning(f"Unknown language code: {lang}")
            languages = lang_codes or [LanguageCode.ENGLISH]
        else:
            languages = [LanguageCode.ENGLISH]
        
        super().__init__(OCREngine.PADDLE, languages)
        self.use_gpu = use_gpu
        self._paddle_ocr = None
        
    def load(self) -> bool:
        """Load PaddleOCR model."""
        try:
            from paddleocr import PaddleOCR
            
            # Map LanguageCode to PaddleOCR language codes
            lang_map = {
                LanguageCode.ENGLISH: 'en',
                LanguageCode.CHINESE: 'ch',
                LanguageCode.JAPANESE: 'japan',
                LanguageCode.KOREAN: 'korean',
                LanguageCode.HINDI: 'hi',
                LanguageCode.ARABIC: 'ar'
            }
            
            # Get first supported language
            paddle_lang = 'en'  # Default
            for lang in self.languages:
                if lang in lang_map:
                    paddle_lang = lang_map[lang]
                    break
            
            self._paddle_ocr = PaddleOCR(
                use_angle_cls=True, 
                lang=paddle_lang,
                use_gpu=self.use_gpu,
                show_log=False
            )
            
            self.is_loaded = True
            logger.info("PaddleOCR model loaded successfully")
            return True
            
        except ImportError:
            logger.error("PaddleOCR not installed. Install with: pip install paddlepaddle paddleocr")
            return False
        except Exception as e:
            logger.error(f"Failed to load PaddleOCR model: {e}")
            return False
    
    def unload(self):
        """Unload PaddleOCR model."""
        self._paddle_ocr = None
        self.is_loaded = False
        logger.info("PaddleOCR model unloaded")
    
    def get_available_languages(self) -> List[str]:
        """Get list of available languages for PaddleOCR."""
        # PaddleOCR supported languages
        return ['en', 'ch', 'japan', 'korean', 'hi', 'ar', 'fr', 'de', 'it']
    
    def extract_text(self, image: Union[str, Path, Image.Image, np.ndarray], 
                    page_number: int = 0, **kwargs) -> OCRResult:
        """Extract text from image using PaddleOCR."""
        import time
        start_time = time.time()
        
        if not self.is_loaded:
            return OCRResult(
                success=False,
                text_content="",
                confidence_score=0.0,
                text_blocks=[],
                bounding_boxes=[],
                processing_time=0.0,
                page_number=page_number,
                processing_errors=["Model not loaded"]
            )
        
        try:
            # Convert image to numpy array for PaddleOCR
            if isinstance(image, (str, Path)):
                img_array = np.array(Image.open(image))
            elif isinstance(image, Image.Image):
                img_array = np.array(image)
            else:
                img_array = image
            
            # Run PaddleOCR
            results = self._paddle_ocr.ocr(img_array, cls=True)
            
            # Process results
            text_content = ""
            text_blocks = []
            bounding_boxes = []
            confidences = []
            
            if results and results[0]:
                for line in results[0]:
                    if line is None:
                        continue
                    
                    bbox_coords = line[0]  # [[x1,y1], [x2,y2], [x3,y3], [x4,y4]]
                    text_info = line[1]    # (text, confidence)
                    
                    if not text_info:
                        continue
                    
                    text = text_info[0]
                    confidence = text_info[1] * 100  # Convert to percentage
                    
                    text_content += text + " "
                    confidences.append(confidence)
                    
                    # Calculate bounding box from coordinates
                    x_coords = [point[0] for point in bbox_coords]
                    y_coords = [point[1] for point in bbox_coords]
                    x, y = int(min(x_coords)), int(min(y_coords))
                    width = int(max(x_coords) - min(x_coords))
                    height = int(max(y_coords) - min(y_coords))
                    
                    # Create bounding box
                    bbox = OCRBoundingBox(
                        text=text,
                        confidence=confidence,
                        x=x,
                        y=y,
                        width=width,
                        height=height,
                        page_number=page_number
                    )
                    bounding_boxes.append(bbox)
                    
                    # Create text block
                    text_block = OCRTextBlock(
                        text=text,
                        confidence=confidence,
                        level='line',
                        bbox=bbox
                    )
                    text_blocks.append(text_block)
            
            text_content = text_content.strip()
            overall_confidence = np.mean(confidences) if confidences else 0.0
            processing_time = time.time() - start_time
            
            return OCRResult(
                success=True,
                text_content=text_content,
                confidence_score=overall_confidence,
                text_blocks=text_blocks,
                bounding_boxes=bounding_boxes,
                processing_time=processing_time,
                page_number=page_number,
                image_dimensions=(img_array.shape[1], img_array.shape[0]),
                engine_used="PaddleOCR",
                engine_version="2.6.0+",
                processing_errors=[]
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"PaddleOCR failed: {e}")
            return OCRResult(
                success=False,
                text_content="",
                confidence_score=0.0,
                text_blocks=[],
                bounding_boxes=[],
                processing_time=processing_time,
                page_number=page_number,
                processing_errors=[str(e)]
            )


# Factory functions for creating OCR models
def create_tesseract_model(languages: List[LanguageCode] = None,
                          tesseract_path: Optional[str] = None,
                          tessdata_dir: Optional[str] = None) -> TesseractOCRModel:
    """Create Tesseract OCR model with specified configuration."""
    return TesseractOCRModel(languages, tesseract_path, tessdata_dir)


def create_paddle_ocr_model(languages: List[str] = None,
                           use_gpu: bool = False) -> PaddleOCRModel:
    """Create PaddleOCR model with specified configuration."""
    return PaddleOCRModel(languages, use_gpu)


def get_default_ocr_model(prefer_engine: OCREngine = OCREngine.TESSERACT) -> OCRModel:
    """Get default OCR model based on preference and availability."""
    try:
        if prefer_engine == OCREngine.TESSERACT:
            model = create_tesseract_model()
            if model.load():
                return model
            else:
                # Fallback to PaddleOCR
                logger.info("Tesseract not available, trying PaddleOCR")
                model = create_paddle_ocr_model()
                if model.load():
                    return model
        else:
            model = create_paddle_ocr_model()
            if model.load():
                return model
            else:
                # Fallback to Tesseract
                logger.info("PaddleOCR not available, trying Tesseract")
                model = create_tesseract_model()
                if model.load():
                    return model
    except Exception as e:
        logger.error(f"Failed to create default OCR model: {e}")
    
    return None


def get_available_ocr_engines() -> List[OCREngine]:
    """Get list of available OCR engines on the system."""
    available = []
    
    # Test Tesseract
    try:
        model = create_tesseract_model()
        if model.load():
            available.append(OCREngine.TESSERACT)
            model.unload()
    except Exception:
        pass
    
    # Test PaddleOCR
    try:
        model = create_paddle_ocr_model()
        if model.load():
            available.append(OCREngine.PADDLE)
            model.unload()
    except Exception:
        pass
    
    return available