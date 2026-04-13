"""
Image Processor for PII De-identification System

This module handles image processing including format validation, quality enhancement,
and preprocessing for various image formats.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union
import io
import base64
from dataclasses import dataclass
from enum import Enum

import cv2
import numpy as np
from PIL import Image, ImageEnhance, ImageFilter, ExifTags
import magic

logger = logging.getLogger(__name__)


class ImageFormat(Enum):
    """Supported image formats."""
    PNG = "png"
    JPEG = "jpeg" 
    JPG = "jpg"
    TIFF = "tiff"
    TIF = "tif"
    BMP = "bmp"
    WEBP = "webp"
    GIF = "gif"


@dataclass
class ImageMetadata:
    """Container for image metadata."""
    format: str
    mode: str
    size: Tuple[int, int]
    has_alpha: bool
    dpi: Tuple[Optional[float], Optional[float]]
    exif_data: Dict[str, Any]
    file_size_bytes: int
    color_space: str
    bit_depth: int


@dataclass
class ImageProcessingResult:
    """Container for image processing results."""
    success: bool
    original_image: Optional[Image.Image]
    processed_image: Optional[Image.Image]
    metadata: Optional[ImageMetadata]
    processing_operations: List[str]
    quality_metrics: Dict[str, float]
    processing_errors: List[str]
    file_info: Dict[str, Any]


class ImageProcessor:
    """Image processor with format validation and enhancement."""
    
    def __init__(self):
        self.supported_formats = {
            '.png': ImageFormat.PNG,
            '.jpg': ImageFormat.JPEG,
            '.jpeg': ImageFormat.JPEG,
            '.tiff': ImageFormat.TIFF,
            '.tif': ImageFormat.TIF,
            '.bmp': ImageFormat.BMP,
            '.webp': ImageFormat.WEBP,
            '.gif': ImageFormat.GIF
        }
        
        self.max_file_size_mb = 50
        self.max_dimension = 8000
        self.min_dimension = 50
        
        # Quality enhancement parameters
        self.enhancement_params = {
            'contrast_factor': 1.2,
            'brightness_factor': 1.1,
            'sharpness_factor': 1.3,
            'denoise_strength': 3,
            'gamma_correction': 1.0
        }
        
        logger.info("ImageProcessor initialized")
    
    def validate_image(self, file_path: Union[str, Path]) -> Tuple[bool, str]:
        """Validate image file before processing."""
        try:
            file_path = Path(file_path)
            
            # Check file exists
            if not file_path.exists():
                return False, f"File does not exist: {file_path}"
            
            # Check file extension
            file_ext = file_path.suffix.lower()
            if file_ext not in self.supported_formats:
                return False, f"Unsupported format: {file_ext}"
            
            # Check file size
            file_size_mb = file_path.stat().st_size / (1024 * 1024)
            if file_size_mb > self.max_file_size_mb:
                return False, f"File too large: {file_size_mb:.1f}MB > {self.max_file_size_mb}MB"
            
            # Validate file type using magic
            try:
                file_type = magic.from_file(str(file_path), mime=True)
                if not file_type.startswith('image/'):
                    return False, f"Not a valid image file: {file_type}"
            except Exception:
                # Fallback validation with PIL
                pass
            
            # Try to open with PIL
            try:
                with Image.open(file_path) as img:
                    width, height = img.size
                    
                    if width > self.max_dimension or height > self.max_dimension:
                        return False, f"Image too large: {width}x{height} > {self.max_dimension}x{self.max_dimension}"
                    
                    if width < self.min_dimension or height < self.min_dimension:
                        return False, f"Image too small: {width}x{height} < {self.min_dimension}x{self.min_dimension}"
                
                return True, "Valid image file"
                
            except Exception as e:
                return False, f"Cannot open image: {str(e)}"
                
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    def process_image(self, file_path: Union[str, Path], enhance_quality: bool = True) -> ImageProcessingResult:
        """Process image file with optional quality enhancement."""
        file_path = Path(file_path)
        
        # Validate file first
        is_valid, validation_msg = self.validate_image(file_path)
        if not is_valid:
            return ImageProcessingResult(
                success=False,
                original_image=None,
                processed_image=None,
                metadata=None,
                processing_operations=[],
                quality_metrics={},
                processing_errors=[validation_msg],
                file_info={'file_path': str(file_path)}
            )
        
        processing_operations = []
        processing_errors = []
        
        try:
            # Load image
            original_image = Image.open(file_path)
            processing_operations.append("loaded_image")
            
            # Extract metadata
            metadata = self._extract_image_metadata(original_image, file_path)
            processing_operations.append("extracted_metadata")
            
            # Process image
            processed_image = original_image.copy()
            
            if enhance_quality:
                processed_image, enhancement_ops, enhancement_errors = self._enhance_image_quality(processed_image)
                processing_operations.extend(enhancement_ops)
                processing_errors.extend(enhancement_errors)
            
            # Calculate quality metrics
            quality_metrics = self._calculate_quality_metrics(original_image, processed_image)
            
            file_info = {
                'file_path': str(file_path),
                'file_size_mb': file_path.stat().st_size / (1024 * 1024),
                'format_detected': metadata.format if metadata else 'unknown'
            }
            
            return ImageProcessingResult(
                success=True,
                original_image=original_image,
                processed_image=processed_image,
                metadata=metadata,
                processing_operations=processing_operations,
                quality_metrics=quality_metrics,
                processing_errors=processing_errors,
                file_info=file_info
            )
            
        except Exception as e:
            return ImageProcessingResult(
                success=False,
                original_image=None,
                processed_image=None,
                metadata=None,
                processing_operations=processing_operations,
                quality_metrics={},
                processing_errors=[f"Processing failed: {str(e)}"],
                file_info={'file_path': str(file_path)}
            )
    
    def _extract_image_metadata(self, image: Image.Image, file_path: Path) -> ImageMetadata:
        """Extract comprehensive image metadata."""
        try:
            # Basic information
            format_str = image.format or 'unknown'
            mode = image.mode
            size = image.size
            has_alpha = mode in ('RGBA', 'LA') or 'transparency' in image.info
            
            # DPI information
            dpi = image.info.get('dpi', (None, None))
            
            # EXIF data
            exif_data = {}
            if hasattr(image, '_getexif') and image._getexif() is not None:
                exif_dict = image._getexif()
                for tag, value in exif_dict.items():
                    decoded = ExifTags.TAGS.get(tag, tag)
                    exif_data[decoded] = value
            
            # File size
            file_size_bytes = file_path.stat().st_size
            
            # Color space and bit depth
            color_space = self._detect_color_space(image)
            bit_depth = self._calculate_bit_depth(image)
            
            return ImageMetadata(
                format=format_str,
                mode=mode,
                size=size,
                has_alpha=has_alpha,
                dpi=dpi,
                exif_data=exif_data,
                file_size_bytes=file_size_bytes,
                color_space=color_space,
                bit_depth=bit_depth
            )
            
        except Exception as e:
            logger.warning(f"Failed to extract complete metadata: {e}")
            return ImageMetadata(
                format=image.format or 'unknown',
                mode=image.mode,
                size=image.size,
                has_alpha=False,
                dpi=(None, None),
                exif_data={},
                file_size_bytes=0,
                color_space='unknown',
                bit_depth=8
            )
    
    def _detect_color_space(self, image: Image.Image) -> str:
        """Detect image color space."""
        mode_mapping = {
            '1': 'bitmap',
            'L': 'grayscale',
            'P': 'palette',
            'RGB': 'RGB',
            'RGBA': 'RGBA',
            'CMYK': 'CMYK',
            'YCbCr': 'YCbCr',
            'LAB': 'LAB',
            'HSV': 'HSV'
        }
        return mode_mapping.get(image.mode, image.mode)
    
    def _calculate_bit_depth(self, image: Image.Image) -> int:
        """Calculate bit depth of image."""
        mode_bits = {
            '1': 1,
            'L': 8,
            'P': 8,
            'RGB': 24,
            'RGBA': 32,
            'CMYK': 32,
            'YCbCr': 24,
            'LAB': 24,
            'HSV': 24
        }
        return mode_bits.get(image.mode, 8)
    
    def _enhance_image_quality(self, image: Image.Image) -> Tuple[Image.Image, List[str], List[str]]:
        """Enhance image quality using various techniques."""
        operations = []
        errors = []
        enhanced_image = image.copy()
        
        try:
            # Convert to RGB if necessary for processing
            if enhanced_image.mode in ('RGBA', 'P'):
                if enhanced_image.mode == 'P':
                    enhanced_image = enhanced_image.convert('RGB')
                    operations.append("converted_palette_to_rgb")
            
            # Enhance contrast
            try:
                enhancer = ImageEnhance.Contrast(enhanced_image)
                enhanced_image = enhancer.enhance(self.enhancement_params['contrast_factor'])
                operations.append("enhanced_contrast")
            except Exception as e:
                errors.append(f"Contrast enhancement failed: {e}")
            
            # Enhance brightness
            try:
                enhancer = ImageEnhance.Brightness(enhanced_image)
                enhanced_image = enhancer.enhance(self.enhancement_params['brightness_factor'])
                operations.append("enhanced_brightness")
            except Exception as e:
                errors.append(f"Brightness enhancement failed: {e}")
            
            # Enhance sharpness
            try:
                enhancer = ImageEnhance.Sharpness(enhanced_image)
                enhanced_image = enhancer.enhance(self.enhancement_params['sharpness_factor'])
                operations.append("enhanced_sharpness")
            except Exception as e:
                errors.append(f"Sharpness enhancement failed: {e}")
            
            # Apply denoising using OpenCV
            try:
                enhanced_image = self._denoise_image(enhanced_image)
                operations.append("applied_denoising")
            except Exception as e:
                errors.append(f"Denoising failed: {e}")
            
            # Apply unsharp mask for better text clarity
            try:
                enhanced_image = enhanced_image.filter(ImageFilter.UnsharpMask(radius=2, percent=150, threshold=3))
                operations.append("applied_unsharp_mask")
            except Exception as e:
                errors.append(f"Unsharp mask failed: {e}")
            
        except Exception as e:
            errors.append(f"Image enhancement failed: {e}")
        
        return enhanced_image, operations, errors
    
    def _denoise_image(self, image: Image.Image) -> Image.Image:
        """Apply denoising to image using OpenCV."""
        try:
            # Convert PIL to OpenCV format
            cv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            
            # Apply Non-local Means Denoising
            denoised = cv2.fastNlMeansDenoisingColored(
                cv_image, None, 
                self.enhancement_params['denoise_strength'], 
                self.enhancement_params['denoise_strength'], 
                7, 21
            )
            
            # Convert back to PIL
            denoised_rgb = cv2.cvtColor(denoised, cv2.COLOR_BGR2RGB)
            return Image.fromarray(denoised_rgb)
            
        except Exception as e:
            logger.warning(f"OpenCV denoising failed, skipping: {e}")
            return image
    
    def _calculate_quality_metrics(self, original: Image.Image, processed: Image.Image) -> Dict[str, float]:
        """Calculate quality metrics for processed image."""
        metrics = {}
        
        try:
            # Basic metrics
            metrics['width'] = processed.size[0]
            metrics['height'] = processed.size[1]
            metrics['aspect_ratio'] = processed.size[0] / processed.size[1]
            
            # Calculate sharpness (Laplacian variance)
            try:
                processed_gray = processed.convert('L')
                cv_image = np.array(processed_gray)
                laplacian_var = cv2.Laplacian(cv_image, cv2.CV_64F).var()
                metrics['sharpness_score'] = float(laplacian_var)
            except Exception:
                metrics['sharpness_score'] = 0.0
            
            # Calculate brightness
            try:
                gray_array = np.array(processed.convert('L'))
                metrics['brightness'] = float(np.mean(gray_array))
            except Exception:
                metrics['brightness'] = 128.0
            
            # Calculate contrast (standard deviation)
            try:
                gray_array = np.array(processed.convert('L'))
                metrics['contrast'] = float(np.std(gray_array))
            except Exception:
                metrics['contrast'] = 0.0
            
            # Calculate entropy (measure of information content)
            try:
                histogram = processed.convert('L').histogram()
                normalized_hist = [h / sum(histogram) for h in histogram if h > 0]
                entropy = -sum(p * np.log2(p) for p in normalized_hist)
                metrics['entropy'] = float(entropy)
            except Exception:
                metrics['entropy'] = 0.0
            
        except Exception as e:
            logger.warning(f"Quality metrics calculation failed: {e}")
            metrics = {
                'width': processed.size[0] if processed else 0,
                'height': processed.size[1] if processed else 0,
                'aspect_ratio': 1.0,
                'sharpness_score': 0.0,
                'brightness': 128.0,
                'contrast': 0.0,
                'entropy': 0.0
            }
        
        return metrics
    
    def convert_format(self, image: Image.Image, target_format: ImageFormat, quality: int = 95) -> Tuple[Image.Image, str]:
        """Convert image to target format."""
        try:
            if target_format == ImageFormat.JPEG:
                # Convert to RGB if necessary (JPEG doesn't support transparency)
                if image.mode in ('RGBA', 'LA'):
                    rgb_image = Image.new('RGB', image.size, (255, 255, 255))
                    rgb_image.paste(image, mask=image.split()[-1] if 'A' in image.mode else None)
                    image = rgb_image
                
                # Save as JPEG
                output = io.BytesIO()
                image.save(output, format='JPEG', quality=quality)
                output.seek(0)
                converted_image = Image.open(output)
                
                return converted_image, "converted_to_jpeg"
                
            elif target_format == ImageFormat.PNG:
                output = io.BytesIO()
                image.save(output, format='PNG')
                output.seek(0)
                converted_image = Image.open(output)
                
                return converted_image, "converted_to_png"
                
            else:
                output = io.BytesIO()
                image.save(output, format=target_format.value.upper())
                output.seek(0)
                converted_image = Image.open(output)
                
                return converted_image, f"converted_to_{target_format.value}"
                
        except Exception as e:
            logger.error(f"Format conversion failed: {e}")
            return image, "conversion_failed"
    
    def resize_image(self, image: Image.Image, max_width: int = 2048, max_height: int = 2048, 
                    maintain_aspect: bool = True) -> Tuple[Image.Image, str]:
        """Resize image while maintaining quality."""
        try:
            original_size = image.size
            
            if maintain_aspect:
                # Calculate new size maintaining aspect ratio
                ratio = min(max_width / original_size[0], max_height / original_size[1])
                if ratio >= 1:
                    return image, "no_resize_needed"
                
                new_size = (int(original_size[0] * ratio), int(original_size[1] * ratio))
            else:
                new_size = (max_width, max_height)
            
            # Use high-quality resampling
            resized_image = image.resize(new_size, Image.Resampling.LANCZOS)
            
            return resized_image, f"resized_from_{original_size}_to_{new_size}"
            
        except Exception as e:
            logger.error(f"Image resize failed: {e}")
            return image, "resize_failed"
    
    def extract_image_for_ocr(self, image: Image.Image) -> Image.Image:
        """Prepare image specifically for OCR processing."""
        try:
            # Convert to grayscale for OCR
            if image.mode != 'L':
                ocr_image = image.convert('L')
            else:
                ocr_image = image.copy()
            
            # Apply additional preprocessing for OCR
            ocr_image = self._preprocess_for_ocr(ocr_image)
            
            return ocr_image
            
        except Exception as e:
            logger.error(f"OCR preprocessing failed: {e}")
            return image
    
    def _preprocess_for_ocr(self, image: Image.Image) -> Image.Image:
        """Apply OCR-specific preprocessing."""
        try:
            # Convert to OpenCV format
            cv_image = np.array(image)
            
            # Apply Gaussian blur to reduce noise
            blurred = cv2.GaussianBlur(cv_image, (1, 1), 0)
            
            # Apply adaptive thresholding
            thresh = cv2.adaptiveThreshold(
                blurred, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
            )
            
            # Convert back to PIL
            return Image.fromarray(thresh)
            
        except Exception as e:
            logger.warning(f"OCR preprocessing failed: {e}")
            return image
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """Get processor statistics and capabilities."""
        return {
            'supported_formats': list(self.supported_formats.keys()),
            'max_file_size_mb': self.max_file_size_mb,
            'max_dimension': self.max_dimension,
            'min_dimension': self.min_dimension,
            'enhancement_params': self.enhancement_params,
            'features': [
                'format_validation',
                'metadata_extraction',
                'quality_enhancement',
                'format_conversion',
                'image_resizing',
                'ocr_preprocessing',
                'denoising',
                'sharpening'
            ]
        }