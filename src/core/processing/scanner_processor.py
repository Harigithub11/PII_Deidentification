"""
Scanner Processor for PII De-identification System

This module handles optimization of scanned documents including deskewing,
noise reduction, rotation correction, and quality enhancement.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple, Union
import math
from dataclasses import dataclass

import cv2
import numpy as np
from PIL import Image
from scipy import ndimage
from skimage import filters, morphology, measure, transform
from sklearn.cluster import DBSCAN

logger = logging.getLogger(__name__)


@dataclass
class ScanQualityMetrics:
    """Container for scan quality metrics."""
    skew_angle: float
    rotation_angle: float
    noise_level: float
    contrast_score: float
    sharpness_score: float
    text_line_count: int
    overall_quality: float


@dataclass
class ScanProcessingResult:
    """Container for scan processing results."""
    success: bool
    original_image: Optional[Image.Image]
    processed_image: Optional[Image.Image]
    quality_metrics: ScanQualityMetrics
    processing_operations: List[str]
    processing_errors: List[str]
    enhancement_applied: Dict[str, bool]


class ScannerProcessor:
    """Processor for scanned document optimization."""
    
    def __init__(self):
        self.min_image_size = (100, 100)
        self.max_image_size = (6000, 6000)
        
        # Processing parameters
        self.skew_detection_params = {
            'angle_range': (-45, 45),
            'angle_step': 0.1,
            'min_line_length': 100,
            'max_line_gap': 10,
            'canny_low': 50,
            'canny_high': 150
        }
        
        self.noise_reduction_params = {
            'bilateral_d': 9,
            'bilateral_sigma_color': 75,
            'bilateral_sigma_space': 75,
            'morphology_kernel_size': (2, 2),
            'median_kernel_size': 3
        }
        
        self.contrast_params = {
            'clahe_clip_limit': 2.0,
            'clahe_grid_size': (8, 8),
            'gamma_correction': 1.2,
            'adaptive_threshold_block_size': 11,
            'adaptive_threshold_c': 2
        }
        
        logger.info("ScannerProcessor initialized")
    
    def process_scanned_document(self, image: Image.Image, apply_all_enhancements: bool = True) -> ScanProcessingResult:
        """Process scanned document with comprehensive optimization."""
        processing_operations = []
        processing_errors = []
        enhancement_applied = {
            'rotation_correction': False,
            'skew_correction': False,
            'noise_reduction': False,
            'contrast_enhancement': False,
            'sharpness_enhancement': False,
            'text_optimization': False
        }
        
        try:
            # Validate input image
            if not self._validate_image_size(image):
                return ScanProcessingResult(
                    success=False,
                    original_image=image,
                    processed_image=None,
                    quality_metrics=ScanQualityMetrics(0, 0, 0, 0, 0, 0, 0),
                    processing_operations=processing_operations,
                    processing_errors=["Invalid image size"],
                    enhancement_applied=enhancement_applied
                )
            
            processed_image = image.copy()
            original_image = image.copy()
            
            # Convert to OpenCV format for processing
            cv_image = cv2.cvtColor(np.array(processed_image), cv2.COLOR_RGB2BGR)
            processing_operations.append("converted_to_opencv")
            
            # Detect and correct rotation
            if apply_all_enhancements:
                try:
                    cv_image, rotation_angle = self._correct_rotation(cv_image)
                    if abs(rotation_angle) > 0.5:
                        enhancement_applied['rotation_correction'] = True
                        processing_operations.append(f"rotation_corrected_{rotation_angle:.1f}_degrees")
                except Exception as e:
                    processing_errors.append(f"Rotation correction failed: {e}")
            
            # Detect and correct skew
            if apply_all_enhancements:
                try:
                    cv_image, skew_angle = self._correct_skew(cv_image)
                    if abs(skew_angle) > 0.1:
                        enhancement_applied['skew_correction'] = True
                        processing_operations.append(f"skew_corrected_{skew_angle:.2f}_degrees")
                except Exception as e:
                    processing_errors.append(f"Skew correction failed: {e}")
            
            # Apply noise reduction
            if apply_all_enhancements:
                try:
                    cv_image = self._reduce_noise(cv_image)
                    enhancement_applied['noise_reduction'] = True
                    processing_operations.append("noise_reduced")
                except Exception as e:
                    processing_errors.append(f"Noise reduction failed: {e}")
            
            # Enhance contrast
            if apply_all_enhancements:
                try:
                    cv_image = self._enhance_contrast(cv_image)
                    enhancement_applied['contrast_enhancement'] = True
                    processing_operations.append("contrast_enhanced")
                except Exception as e:
                    processing_errors.append(f"Contrast enhancement failed: {e}")
            
            # Apply text optimization
            if apply_all_enhancements:
                try:
                    cv_image = self._optimize_for_text(cv_image)
                    enhancement_applied['text_optimization'] = True
                    processing_operations.append("text_optimized")
                except Exception as e:
                    processing_errors.append(f"Text optimization failed: {e}")
            
            # Convert back to PIL
            processed_image = Image.fromarray(cv2.cvtColor(cv_image, cv2.COLOR_BGR2RGB))
            processing_operations.append("converted_to_pil")
            
            # Calculate quality metrics
            quality_metrics = self._calculate_scan_quality(original_image, processed_image)
            
            return ScanProcessingResult(
                success=True,
                original_image=original_image,
                processed_image=processed_image,
                quality_metrics=quality_metrics,
                processing_operations=processing_operations,
                processing_errors=processing_errors,
                enhancement_applied=enhancement_applied
            )
            
        except Exception as e:
            return ScanProcessingResult(
                success=False,
                original_image=image,
                processed_image=None,
                quality_metrics=ScanQualityMetrics(0, 0, 0, 0, 0, 0, 0),
                processing_operations=processing_operations,
                processing_errors=[f"Processing failed: {str(e)}"],
                enhancement_applied=enhancement_applied
            )
    
    def _validate_image_size(self, image: Image.Image) -> bool:
        """Validate image size for processing."""
        width, height = image.size
        
        if (width < self.min_image_size[0] or height < self.min_image_size[1] or
            width > self.max_image_size[0] or height > self.max_image_size[1]):
            return False
        
        return True
    
    def _correct_rotation(self, cv_image: np.ndarray) -> Tuple[np.ndarray, float]:
        """Detect and correct document rotation."""
        try:
            # Convert to grayscale
            gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
            
            # Apply edge detection
            edges = cv2.Canny(gray, self.skew_detection_params['canny_low'], 
                             self.skew_detection_params['canny_high'])
            
            # Detect lines using HoughLinesP
            lines = cv2.HoughLinesP(
                edges, 
                1, 
                np.pi/180, 
                threshold=100,
                minLineLength=self.skew_detection_params['min_line_length'],
                maxLineGap=self.skew_detection_params['max_line_gap']
            )
            
            if lines is None:
                return cv_image, 0.0
            
            # Calculate angles for all detected lines
            angles = []
            for line in lines:
                x1, y1, x2, y2 = line[0]
                angle = np.arctan2(y2 - y1, x2 - x1) * 180 / np.pi
                angles.append(angle)
            
            if not angles:
                return cv_image, 0.0
            
            # Find the dominant angle using clustering
            angles_array = np.array(angles).reshape(-1, 1)
            
            # Use DBSCAN to find clusters of similar angles
            clustering = DBSCAN(eps=2.0, min_samples=5).fit(angles_array)
            labels = clustering.labels_
            
            # Find the largest cluster
            unique_labels = set(labels)
            if -1 in unique_labels:
                unique_labels.remove(-1)  # Remove noise points
            
            if not unique_labels:
                return cv_image, 0.0
            
            # Get the most common angle from the largest cluster
            largest_cluster = max(unique_labels, key=lambda x: np.sum(labels == x))
            cluster_angles = angles_array[labels == largest_cluster].flatten()
            rotation_angle = np.median(cluster_angles)
            
            # Only correct significant rotations
            if abs(rotation_angle) > 0.5:
                # Rotate the image
                height, width = cv_image.shape[:2]
                center = (width // 2, height // 2)
                rotation_matrix = cv2.getRotationMatrix2D(center, -rotation_angle, 1.0)
                rotated_image = cv2.warpAffine(cv_image, rotation_matrix, (width, height), 
                                             flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
                return rotated_image, rotation_angle
            
            return cv_image, 0.0
            
        except Exception as e:
            logger.warning(f"Rotation correction failed: {e}")
            return cv_image, 0.0
    
    def _correct_skew(self, cv_image: np.ndarray) -> Tuple[np.ndarray, float]:
        """Detect and correct document skew."""
        try:
            # Convert to grayscale
            gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
            
            # Apply morphological operations to close text lines
            kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (20, 1))
            morph = cv2.morphologyEx(gray, cv2.MORPH_CLOSE, kernel)
            
            # Find contours
            contours, _ = cv2.findContours(morph, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            # Filter contours to find text lines
            text_lines = []
            for contour in contours:
                x, y, w, h = cv2.boundingRect(contour)
                # Filter based on aspect ratio (width should be much larger than height)
                if w > h * 5 and w > 100 and h > 10:
                    text_lines.append(contour)
            
            if len(text_lines) < 3:
                return cv_image, 0.0
            
            # Calculate skew angle from text lines
            angles = []
            for contour in text_lines:
                # Fit a line to the contour
                [vx, vy, x, y] = cv2.fitLine(contour, cv2.DIST_L2, 0, 0.01, 0.01)
                angle = np.arctan2(vy, vx) * 180 / np.pi
                angles.append(angle)
            
            # Calculate median angle to reduce noise
            skew_angle = np.median(angles)
            
            # Only correct significant skew
            if abs(skew_angle) > 0.1:
                # Rotate the image
                height, width = cv_image.shape[:2]
                center = (width // 2, height // 2)
                rotation_matrix = cv2.getRotationMatrix2D(center, -skew_angle, 1.0)
                corrected_image = cv2.warpAffine(cv_image, rotation_matrix, (width, height),
                                               flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
                return corrected_image, skew_angle
            
            return cv_image, 0.0
            
        except Exception as e:
            logger.warning(f"Skew correction failed: {e}")
            return cv_image, 0.0
    
    def _reduce_noise(self, cv_image: np.ndarray) -> np.ndarray:
        """Apply noise reduction techniques."""
        try:
            # Apply bilateral filter to reduce noise while preserving edges
            denoised = cv2.bilateralFilter(
                cv_image, 
                self.noise_reduction_params['bilateral_d'],
                self.noise_reduction_params['bilateral_sigma_color'],
                self.noise_reduction_params['bilateral_sigma_space']
            )
            
            # Apply median filter for salt and pepper noise
            denoised = cv2.medianBlur(denoised, self.noise_reduction_params['median_kernel_size'])
            
            # Apply morphological operations to remove small noise
            kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, 
                                             self.noise_reduction_params['morphology_kernel_size'])
            denoised = cv2.morphologyEx(denoised, cv2.MORPH_OPEN, kernel)
            
            return denoised
            
        except Exception as e:
            logger.warning(f"Noise reduction failed: {e}")
            return cv_image
    
    def _enhance_contrast(self, cv_image: np.ndarray) -> np.ndarray:
        """Enhance image contrast using CLAHE and gamma correction."""
        try:
            # Convert to LAB color space
            lab = cv2.cvtColor(cv_image, cv2.COLOR_BGR2LAB)
            l_channel, a_channel, b_channel = cv2.split(lab)
            
            # Apply CLAHE to L channel
            clahe = cv2.createCLAHE(
                clipLimit=self.contrast_params['clahe_clip_limit'],
                tileGridSize=self.contrast_params['clahe_grid_size']
            )
            l_channel = clahe.apply(l_channel)
            
            # Merge channels back
            enhanced_lab = cv2.merge([l_channel, a_channel, b_channel])
            enhanced_image = cv2.cvtColor(enhanced_lab, cv2.COLOR_LAB2BGR)
            
            # Apply gamma correction
            gamma = self.contrast_params['gamma_correction']
            gamma_corrected = np.power(enhanced_image / 255.0, gamma)
            enhanced_image = (gamma_corrected * 255).astype(np.uint8)
            
            return enhanced_image
            
        except Exception as e:
            logger.warning(f"Contrast enhancement failed: {e}")
            return cv_image
    
    def _optimize_for_text(self, cv_image: np.ndarray) -> np.ndarray:
        """Apply text-specific optimizations."""
        try:
            # Convert to grayscale for text processing
            gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
            
            # Apply adaptive thresholding to improve text clarity
            adaptive_thresh = cv2.adaptiveThreshold(
                gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY,
                self.contrast_params['adaptive_threshold_block_size'],
                self.contrast_params['adaptive_threshold_c']
            )
            
            # Apply morphological operations to clean up text
            kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (1, 1))
            cleaned = cv2.morphologyEx(adaptive_thresh, cv2.MORPH_CLOSE, kernel)
            
            # Convert back to color
            if len(cv_image.shape) == 3:
                text_optimized = cv2.cvtColor(cleaned, cv2.COLOR_GRAY2BGR)
                
                # Blend with original image to maintain some color information
                alpha = 0.7
                blended = cv2.addWeighted(text_optimized, alpha, cv_image, 1 - alpha, 0)
                return blended
            else:
                return cleaned
                
        except Exception as e:
            logger.warning(f"Text optimization failed: {e}")
            return cv_image
    
    def _calculate_scan_quality(self, original: Image.Image, processed: Image.Image) -> ScanQualityMetrics:
        """Calculate comprehensive quality metrics for scanned documents."""
        try:
            # Convert images to OpenCV format
            orig_cv = cv2.cvtColor(np.array(original), cv2.COLOR_RGB2BGR)
            proc_cv = cv2.cvtColor(np.array(processed), cv2.COLOR_RGB2BGR)
            
            # Convert to grayscale
            orig_gray = cv2.cvtColor(orig_cv, cv2.COLOR_BGR2GRAY)
            proc_gray = cv2.cvtColor(proc_cv, cv2.COLOR_BGR2GRAY)
            
            # Calculate skew angle (using processed image)
            skew_angle = self._measure_skew_angle(proc_gray)
            
            # Rotation angle (approximated from skew for now)
            rotation_angle = 0.0  # Would need to be calculated during rotation correction
            
            # Calculate noise level
            noise_level = self._measure_noise_level(orig_gray)
            
            # Calculate contrast score
            contrast_score = self._measure_contrast(proc_gray)
            
            # Calculate sharpness score
            sharpness_score = self._measure_sharpness(proc_gray)
            
            # Count text lines
            text_line_count = self._count_text_lines(proc_gray)
            
            # Calculate overall quality score
            overall_quality = self._calculate_overall_quality(
                skew_angle, noise_level, contrast_score, sharpness_score, text_line_count
            )
            
            return ScanQualityMetrics(
                skew_angle=skew_angle,
                rotation_angle=rotation_angle,
                noise_level=noise_level,
                contrast_score=contrast_score,
                sharpness_score=sharpness_score,
                text_line_count=text_line_count,
                overall_quality=overall_quality
            )
            
        except Exception as e:
            logger.warning(f"Quality metrics calculation failed: {e}")
            return ScanQualityMetrics(0, 0, 50, 50, 50, 0, 50)
    
    def _measure_skew_angle(self, gray_image: np.ndarray) -> float:
        """Measure skew angle of document."""
        try:
            # Apply morphological operations to enhance text lines
            kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (20, 1))
            morph = cv2.morphologyEx(gray_image, cv2.MORPH_CLOSE, kernel)
            
            # Find contours
            contours, _ = cv2.findContours(morph, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            angles = []
            for contour in contours:
                if cv2.contourArea(contour) > 1000:
                    rect = cv2.minAreaRect(contour)
                    angles.append(rect[2])
            
            if angles:
                return float(np.median(angles))
            return 0.0
            
        except Exception:
            return 0.0
    
    def _measure_noise_level(self, gray_image: np.ndarray) -> float:
        """Measure noise level in image."""
        try:
            # Use Laplacian variance as a measure of noise
            laplacian_var = cv2.Laplacian(gray_image, cv2.CV_64F).var()
            
            # Normalize to 0-100 scale
            normalized_noise = min(100, max(0, (laplacian_var - 100) / 10))
            return float(normalized_noise)
            
        except Exception:
            return 50.0
    
    def _measure_contrast(self, gray_image: np.ndarray) -> float:
        """Measure image contrast."""
        try:
            # Calculate RMS contrast
            mean_brightness = np.mean(gray_image)
            rms_contrast = np.sqrt(np.mean((gray_image - mean_brightness) ** 2))
            
            # Normalize to 0-100 scale
            normalized_contrast = min(100, (rms_contrast / 255) * 100)
            return float(normalized_contrast)
            
        except Exception:
            return 50.0
    
    def _measure_sharpness(self, gray_image: np.ndarray) -> float:
        """Measure image sharpness."""
        try:
            # Use Laplacian variance as sharpness measure
            laplacian_var = cv2.Laplacian(gray_image, cv2.CV_64F).var()
            
            # Normalize to 0-100 scale
            normalized_sharpness = min(100, laplacian_var / 100)
            return float(normalized_sharpness)
            
        except Exception:
            return 50.0
    
    def _count_text_lines(self, gray_image: np.ndarray) -> int:
        """Count approximate number of text lines."""
        try:
            # Apply morphological operations to connect text
            kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (20, 1))
            morph = cv2.morphologyEx(gray_image, cv2.MORPH_CLOSE, kernel)
            
            # Find contours
            contours, _ = cv2.findContours(morph, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            # Count contours that could be text lines
            text_lines = 0
            for contour in contours:
                x, y, w, h = cv2.boundingRect(contour)
                if w > h * 3 and w > 50 and h > 5:  # Aspect ratio typical of text lines
                    text_lines += 1
            
            return text_lines
            
        except Exception:
            return 0
    
    def _calculate_overall_quality(self, skew_angle: float, noise_level: float, 
                                  contrast_score: float, sharpness_score: float, 
                                  text_line_count: int) -> float:
        """Calculate overall quality score."""
        try:
            # Skew penalty (lower is better)
            skew_score = max(0, 100 - abs(skew_angle) * 10)
            
            # Noise penalty (lower noise is better)
            noise_score = max(0, 100 - noise_level)
            
            # Text content bonus
            text_score = min(100, text_line_count * 5)
            
            # Weighted average
            overall = (skew_score * 0.2 + noise_score * 0.2 + 
                      contrast_score * 0.3 + sharpness_score * 0.2 + 
                      text_score * 0.1)
            
            return float(min(100, max(0, overall)))
            
        except Exception:
            return 50.0
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """Get processor statistics and capabilities."""
        return {
            'min_image_size': self.min_image_size,
            'max_image_size': self.max_image_size,
            'skew_detection_params': self.skew_detection_params,
            'noise_reduction_params': self.noise_reduction_params,
            'contrast_params': self.contrast_params,
            'features': [
                'rotation_correction',
                'skew_correction', 
                'noise_reduction',
                'contrast_enhancement',
                'text_optimization',
                'quality_assessment'
            ]
        }