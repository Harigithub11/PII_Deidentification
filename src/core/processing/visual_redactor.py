"""
Visual Redaction Engine

This module provides visual anonymization and redaction capabilities for images and documents,
including faces, signatures, stamps, and other visual PII elements.
"""

import logging
import numpy as np
import cv2
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter, ImageFont
import io
import base64

from ..models.visual_models import (
    VisualPIIEntity, 
    VisualPIIType,
    BoundingBox
)
from ..config.policies.base import RedactionMethod
from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class VisualRedactionMethod(str, Enum):
    """Visual redaction methods for different types of visual PII."""
    BLUR = "blur"
    BLACKOUT = "blackout"
    WHITEOUT = "whiteout"
    PIXELATE = "pixelate"
    GAUSSIAN_BLUR = "gaussian_blur"
    MOSAIC = "mosaic"
    SOLID_COLOR = "solid_color"
    PATTERN_FILL = "pattern_fill"
    CROP_OUT = "crop_out"
    REPLACE_WITH_PLACEHOLDER = "replace_with_placeholder"
    
    # Advanced visual methods
    DISTORT = "distort"
    NOISE = "noise"
    INVERT = "invert"
    EDGE_BLUR = "edge_blur"
    SCRAMBLE = "scramble"


@dataclass
class RedactionConfig:
    """Configuration for visual redaction operations."""
    method: VisualRedactionMethod = VisualRedactionMethod.BLUR
    intensity: float = 1.0  # 0.0 to 1.0, controls blur/pixelate intensity
    color: Tuple[int, int, int] = (0, 0, 0)  # RGB color for solid fills
    padding: int = 5  # Pixels to expand bounding box
    preserve_aspect_ratio: bool = True
    placeholder_text: Optional[str] = None
    font_size: int = 16
    
    # Entity-specific configurations
    entity_configs: Dict[VisualPIIType, Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.entity_configs is None:
            self.entity_configs = {
                VisualPIIType.FACE: {
                    "method": VisualRedactionMethod.GAUSSIAN_BLUR,
                    "intensity": 0.8,
                    "padding": 10
                },
                VisualPIIType.SIGNATURE: {
                    "method": VisualRedactionMethod.BLACKOUT,
                    "intensity": 1.0,
                    "padding": 5,
                    "placeholder_text": "[SIGNATURE]"
                },
                VisualPIIType.STAMP: {
                    "method": VisualRedactionMethod.MOSAIC,
                    "intensity": 0.6,
                    "padding": 8
                },
                VisualPIIType.SEAL: {
                    "method": VisualRedactionMethod.SOLID_COLOR,
                    "color": (128, 128, 128),
                    "padding": 8
                },
                VisualPIIType.HANDWRITING: {
                    "method": VisualRedactionMethod.BLUR,
                    "intensity": 0.7,
                    "padding": 3
                },
                VisualPIIType.QR_CODE: {
                    "method": VisualRedactionMethod.PIXELATE,
                    "intensity": 0.9,
                    "padding": 2
                },
                VisualPIIType.BARCODE: {
                    "method": VisualRedactionMethod.WHITEOUT,
                    "intensity": 1.0,
                    "padding": 2
                }
            }


@dataclass
class RedactionResult:
    """Result of visual redaction operation."""
    success: bool
    redacted_image: Optional[np.ndarray] = None
    redacted_entities: List[VisualPIIEntity] = None
    redaction_metadata: Dict[str, Any] = None
    error_message: Optional[str] = None
    processing_time_seconds: float = 0.0
    
    def __post_init__(self):
        if self.redacted_entities is None:
            self.redacted_entities = []
        if self.redaction_metadata is None:
            self.redaction_metadata = {}


class VisualRedactor(ABC):
    """Abstract base class for visual redaction methods."""
    
    @abstractmethod
    def redact_region(
        self,
        image: np.ndarray,
        bbox: BoundingBox,
        config: RedactionConfig
    ) -> np.ndarray:
        """Redact a specific region in the image."""
        pass
    
    def expand_bbox(self, bbox: BoundingBox, padding: int, img_width: int, img_height: int) -> BoundingBox:
        """Expand bounding box with padding, keeping within image bounds."""
        return BoundingBox(
            x=max(0, bbox.x - padding),
            y=max(0, bbox.y - padding),
            width=min(img_width - max(0, bbox.x - padding), bbox.width + 2 * padding),
            height=min(img_height - max(0, bbox.y - padding), bbox.height + 2 * padding)
        )


class BlurRedactor(VisualRedactor):
    """Blur-based redaction methods."""
    
    def redact_region(
        self,
        image: np.ndarray,
        bbox: BoundingBox,
        config: RedactionConfig
    ) -> np.ndarray:
        """Apply blur redaction to a region."""
        img_height, img_width = image.shape[:2]
        expanded_bbox = self.expand_bbox(bbox, config.padding, img_width, img_height)
        
        # Extract region
        region = image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2]
        
        # Apply blur based on method
        if config.method == VisualRedactionMethod.GAUSSIAN_BLUR:
            kernel_size = max(3, int(15 * config.intensity))
            if kernel_size % 2 == 0:
                kernel_size += 1
            blurred_region = cv2.GaussianBlur(region, (kernel_size, kernel_size), 0)
        else:  # Standard blur
            kernel_size = max(3, int(10 * config.intensity))
            if kernel_size % 2 == 0:
                kernel_size += 1
            blurred_region = cv2.blur(region, (kernel_size, kernel_size))
        
        # Replace region in original image
        result_image = image.copy()
        result_image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2] = blurred_region
        
        return result_image


class SolidColorRedactor(VisualRedactor):
    """Solid color redaction methods."""
    
    def redact_region(
        self,
        image: np.ndarray,
        bbox: BoundingBox,
        config: RedactionConfig
    ) -> np.ndarray:
        """Apply solid color redaction to a region."""
        img_height, img_width = image.shape[:2]
        expanded_bbox = self.expand_bbox(bbox, config.padding, img_width, img_height)
        
        result_image = image.copy()
        
        # Convert BGR to RGB color if needed
        color = config.color
        if len(image.shape) == 3 and image.shape[2] == 3:
            color = (color[2], color[1], color[0])  # RGB to BGR for OpenCV
        
        # Fill region with solid color
        result_image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2] = color
        
        return result_image


class PixelateRedactor(VisualRedactor):
    """Pixelate redaction method."""
    
    def redact_region(
        self,
        image: np.ndarray,
        bbox: BoundingBox,
        config: RedactionConfig
    ) -> np.ndarray:
        """Apply pixelate redaction to a region."""
        img_height, img_width = image.shape[:2]
        expanded_bbox = self.expand_bbox(bbox, config.padding, img_width, img_height)
        
        # Extract region
        region = image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2]
        
        # Calculate pixelation block size based on intensity
        region_height, region_width = region.shape[:2]
        block_size = max(2, int(min(region_width, region_height) * (1 - config.intensity) * 0.1 + 4))
        
        # Downsample and upsample to create pixelated effect
        small_height = max(1, region_height // block_size)
        small_width = max(1, region_width // block_size)
        
        # Resize down
        small = cv2.resize(region, (small_width, small_height), interpolation=cv2.INTER_LINEAR)
        
        # Resize back up with nearest neighbor for blocky effect
        pixelated_region = cv2.resize(small, (region_width, region_height), interpolation=cv2.INTER_NEAREST)
        
        # Replace region in original image
        result_image = image.copy()
        result_image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2] = pixelated_region
        
        return result_image


class MosaicRedactor(VisualRedactor):
    """Mosaic redaction method."""
    
    def redact_region(
        self,
        image: np.ndarray,
        bbox: BoundingBox,
        config: RedactionConfig
    ) -> np.ndarray:
        """Apply mosaic redaction to a region."""
        img_height, img_width = image.shape[:2]
        expanded_bbox = self.expand_bbox(bbox, config.padding, img_width, img_height)
        
        # Extract region
        region = image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2]
        region_height, region_width = region.shape[:2]
        
        # Calculate mosaic tile size
        tile_size = max(4, int(min(region_width, region_height) * (1 - config.intensity) * 0.2 + 6))
        
        # Create mosaic effect
        mosaic_region = region.copy()
        for y in range(0, region_height, tile_size):
            for x in range(0, region_width, tile_size):
                # Calculate tile boundaries
                y_end = min(y + tile_size, region_height)
                x_end = min(x + tile_size, region_width)
                
                # Get average color of tile
                tile = region[y:y_end, x:x_end]
                avg_color = np.mean(tile, axis=(0, 1))
                
                # Fill tile with average color
                mosaic_region[y:y_end, x:x_end] = avg_color
        
        # Replace region in original image
        result_image = image.copy()
        result_image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2] = mosaic_region
        
        return result_image


class PlaceholderRedactor(VisualRedactor):
    """Placeholder text redaction method."""
    
    def redact_region(
        self,
        image: np.ndarray,
        bbox: BoundingBox,
        config: RedactionConfig
    ) -> np.ndarray:
        """Replace region with placeholder text."""
        img_height, img_width = image.shape[:2]
        expanded_bbox = self.expand_bbox(bbox, config.padding, img_width, img_height)
        
        result_image = image.copy()
        
        # Fill with background color first
        color = config.color
        if len(image.shape) == 3 and image.shape[2] == 3:
            color = (color[2], color[1], color[0])  # RGB to BGR for OpenCV
        
        result_image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2] = color
        
        # Add placeholder text if specified
        if config.placeholder_text:
            text = config.placeholder_text
            font = cv2.FONT_HERSHEY_SIMPLEX
            font_scale = max(0.3, min(1.0, expanded_bbox.width / (len(text) * 10)))
            thickness = max(1, int(font_scale * 2))
            
            # Calculate text position (centered)
            text_size = cv2.getTextSize(text, font, font_scale, thickness)[0]
            text_x = expanded_bbox.x + (expanded_bbox.width - text_size[0]) // 2
            text_y = expanded_bbox.y + (expanded_bbox.height + text_size[1]) // 2
            
            # Draw text
            text_color = (255, 255, 255) if sum(color) < 384 else (0, 0, 0)
            cv2.putText(result_image, text, (text_x, text_y), font, font_scale, text_color, thickness)
        
        return result_image


class DistortRedactor(VisualRedactor):
    """Geometric distortion redaction method."""
    
    def redact_region(
        self,
        image: np.ndarray,
        bbox: BoundingBox,
        config: RedactionConfig
    ) -> np.ndarray:
        """Apply geometric distortion to a region."""
        img_height, img_width = image.shape[:2]
        expanded_bbox = self.expand_bbox(bbox, config.padding, img_width, img_height)
        
        # Extract region
        region = image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2]
        region_height, region_width = region.shape[:2]
        
        # Create distortion based on intensity
        distortion_strength = config.intensity * 20  # Scale factor
        
        # Create random displacement maps
        map_x = np.zeros((region_height, region_width), dtype=np.float32)
        map_y = np.zeros((region_height, region_width), dtype=np.float32)
        
        for i in range(region_height):
            for j in range(region_width):
                map_x[i, j] = j + distortion_strength * np.sin(i * 0.1) * np.cos(j * 0.1)
                map_y[i, j] = i + distortion_strength * np.cos(i * 0.1) * np.sin(j * 0.1)
        
        # Apply distortion
        distorted_region = cv2.remap(region, map_x, map_y, cv2.INTER_LINEAR, borderMode=cv2.BORDER_REFLECT)
        
        # Replace region in original image
        result_image = image.copy()
        result_image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2] = distorted_region
        
        return result_image


class NoiseRedactor(VisualRedactor):
    """Random noise overlay redaction method."""
    
    def redact_region(
        self,
        image: np.ndarray,
        bbox: BoundingBox,
        config: RedactionConfig
    ) -> np.ndarray:
        """Apply random noise overlay to a region."""
        img_height, img_width = image.shape[:2]
        expanded_bbox = self.expand_bbox(bbox, config.padding, img_width, img_height)
        
        # Extract region
        region = image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2]
        region_height, region_width = region.shape[:2]
        
        # Generate noise based on intensity
        noise_level = int(255 * config.intensity)
        
        # Create noise
        if len(region.shape) == 3:
            noise = np.random.randint(-noise_level, noise_level + 1, 
                                    (region_height, region_width, region.shape[2]), 
                                    dtype=np.int16)
        else:
            noise = np.random.randint(-noise_level, noise_level + 1, 
                                    (region_height, region_width), 
                                    dtype=np.int16)
        
        # Apply noise while preventing overflow
        noisy_region = region.astype(np.int16) + noise
        noisy_region = np.clip(noisy_region, 0, 255).astype(np.uint8)
        
        # Replace region in original image
        result_image = image.copy()
        result_image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2] = noisy_region
        
        return result_image


class InvertRedactor(VisualRedactor):
    """Color inversion redaction method."""
    
    def redact_region(
        self,
        image: np.ndarray,
        bbox: BoundingBox,
        config: RedactionConfig
    ) -> np.ndarray:
        """Apply color inversion to a region."""
        img_height, img_width = image.shape[:2]
        expanded_bbox = self.expand_bbox(bbox, config.padding, img_width, img_height)
        
        # Extract region
        region = image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2]
        
        # Invert colors
        if config.intensity >= 1.0:
            # Full inversion
            inverted_region = 255 - region
        else:
            # Partial inversion based on intensity
            inverted_region = region + (255 - 2 * region) * config.intensity
            inverted_region = np.clip(inverted_region, 0, 255).astype(np.uint8)
        
        # Replace region in original image
        result_image = image.copy()
        result_image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2] = inverted_region
        
        return result_image


class EdgeBlurRedactor(VisualRedactor):
    """Edge-preserving blur redaction method."""
    
    def redact_region(
        self,
        image: np.ndarray,
        bbox: BoundingBox,
        config: RedactionConfig
    ) -> np.ndarray:
        """Apply edge-preserving blur to a region."""
        img_height, img_width = image.shape[:2]
        expanded_bbox = self.expand_bbox(bbox, config.padding, img_width, img_height)
        
        # Extract region
        region = image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2]
        
        # Apply bilateral filter for edge-preserving blur
        d = max(5, int(15 * config.intensity))
        sigma_color = 80 * config.intensity
        sigma_space = 80 * config.intensity
        
        blurred_region = cv2.bilateralFilter(region, d, sigma_color, sigma_space)
        
        # Replace region in original image
        result_image = image.copy()
        result_image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2] = blurred_region
        
        return result_image


class ScrambleRedactor(VisualRedactor):
    """Pixel scrambling redaction method."""
    
    def redact_region(
        self,
        image: np.ndarray,
        bbox: BoundingBox,
        config: RedactionConfig
    ) -> np.ndarray:
        """Apply pixel scrambling to a region."""
        img_height, img_width = image.shape[:2]
        expanded_bbox = self.expand_bbox(bbox, config.padding, img_width, img_height)
        
        # Extract region
        region = image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2]
        region_height, region_width = region.shape[:2]
        
        # Create scramble pattern based on intensity
        scramble_region = region.copy()
        
        # Define block size for scrambling
        block_size = max(2, int(8 * (1 - config.intensity) + 2))
        
        # Scramble blocks
        for y in range(0, region_height, block_size):
            for x in range(0, region_width, block_size):
                y_end = min(y + block_size, region_height)
                x_end = min(x + block_size, region_width)
                
                # Extract block
                block = region[y:y_end, x:x_end].copy()
                
                # Flatten and shuffle pixels
                if len(block.shape) == 3:
                    flat_block = block.reshape(-1, block.shape[2])
                    np.random.shuffle(flat_block)
                    scrambled_block = flat_block.reshape(block.shape)
                else:
                    flat_block = block.flatten()
                    np.random.shuffle(flat_block)
                    scrambled_block = flat_block.reshape(block.shape)
                
                scramble_region[y:y_end, x:x_end] = scrambled_block
        
        # Replace region in original image
        result_image = image.copy()
        result_image[expanded_bbox.y:expanded_bbox.y2, expanded_bbox.x:expanded_bbox.x2] = scramble_region
        
        return result_image


class VisualRedactionEngine:
    """Main engine for visual PII redaction operations."""
    
    def __init__(self):
        self.redactors = {
            VisualRedactionMethod.BLUR: BlurRedactor(),
            VisualRedactionMethod.GAUSSIAN_BLUR: BlurRedactor(),
            VisualRedactionMethod.BLACKOUT: SolidColorRedactor(),
            VisualRedactionMethod.WHITEOUT: SolidColorRedactor(),
            VisualRedactionMethod.PIXELATE: PixelateRedactor(),
            VisualRedactionMethod.MOSAIC: MosaicRedactor(),
            VisualRedactionMethod.SOLID_COLOR: SolidColorRedactor(),
            VisualRedactionMethod.REPLACE_WITH_PLACEHOLDER: PlaceholderRedactor(),
            
            # Advanced redaction methods
            VisualRedactionMethod.DISTORT: DistortRedactor(),
            VisualRedactionMethod.NOISE: NoiseRedactor(),
            VisualRedactionMethod.INVERT: InvertRedactor(),
            VisualRedactionMethod.EDGE_BLUR: EdgeBlurRedactor(),
            VisualRedactionMethod.SCRAMBLE: ScrambleRedactor(),
        }
        
        logger.info("Initialized VisualRedactionEngine")
    
    def redact_image(
        self,
        image: Union[str, Path, np.ndarray, Image.Image],
        entities: List[VisualPIIEntity],
        config: Optional[RedactionConfig] = None
    ) -> RedactionResult:
        """Redact visual PII entities in an image."""
        import time
        start_time = time.time()
        
        try:
            # Load and convert image to numpy array
            img_array = self._load_image(image)
            if img_array is None:
                return RedactionResult(
                    success=False,
                    error_message="Failed to load image"
                )
            
            # Use default config if not provided
            if config is None:
                config = RedactionConfig()
            
            # Process each entity
            result_image = img_array.copy()
            redacted_entities = []
            
            for entity in entities:
                try:
                    # Get entity-specific config
                    entity_config = self._get_entity_config(entity.entity_type, config)
                    
                    # Get appropriate redactor
                    redactor = self.redactors.get(entity_config.method)
                    if redactor is None:
                        logger.warning(f"Unsupported redaction method: {entity_config.method}")
                        continue
                    
                    # Apply redaction
                    result_image = redactor.redact_region(result_image, entity.bounding_box, entity_config)
                    redacted_entities.append(entity)
                    
                    logger.debug(f"Redacted {entity.entity_type} at {entity.bounding_box}")
                    
                except Exception as e:
                    logger.error(f"Error redacting entity {entity.entity_type}: {e}")
                    continue
            
            processing_time = time.time() - start_time
            
            return RedactionResult(
                success=True,
                redacted_image=result_image,
                redacted_entities=redacted_entities,
                redaction_metadata={
                    "total_entities": len(entities),
                    "redacted_entities": len(redacted_entities),
                    "image_dimensions": img_array.shape,
                    "redaction_methods_used": list(set(
                        self._get_entity_config(entity.entity_type, config).method.value
                        for entity in redacted_entities
                    ))
                },
                processing_time_seconds=processing_time
            )
            
        except Exception as e:
            logger.error(f"Error in image redaction: {e}")
            return RedactionResult(
                success=False,
                error_message=str(e),
                processing_time_seconds=time.time() - start_time
            )
    
    def redact_batch(
        self,
        images: List[Union[str, Path, np.ndarray, Image.Image]],
        entities_per_image: List[List[VisualPIIEntity]],
        config: Optional[RedactionConfig] = None
    ) -> List[RedactionResult]:
        """Redact multiple images with their respective entities."""
        if len(images) != len(entities_per_image):
            raise ValueError("Number of images must match number of entity lists")
        
        results = []
        for image, entities in zip(images, entities_per_image):
            result = self.redact_image(image, entities, config)
            results.append(result)
        
        return results
    
    def _load_image(self, image: Union[str, Path, np.ndarray, Image.Image]) -> Optional[np.ndarray]:
        """Load image from various input types."""
        try:
            if isinstance(image, (str, Path)):
                img = cv2.imread(str(image))
                if img is None:
                    return None
                return cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            elif isinstance(image, Image.Image):
                return np.array(image.convert('RGB'))
            elif isinstance(image, np.ndarray):
                # Ensure it's RGB
                if len(image.shape) == 3 and image.shape[2] == 3:
                    return image.copy()
                else:
                    return None
            else:
                return None
        except Exception as e:
            logger.error(f"Error loading image: {e}")
            return None
    
    def _get_entity_config(self, entity_type: VisualPIIType, base_config: RedactionConfig) -> RedactionConfig:
        """Get redaction configuration for a specific entity type."""
        entity_settings = base_config.entity_configs.get(entity_type, {})
        
        # Create config for this entity, using entity-specific overrides
        entity_config = RedactionConfig(
            method=entity_settings.get('method', base_config.method),
            intensity=entity_settings.get('intensity', base_config.intensity),
            color=entity_settings.get('color', base_config.color),
            padding=entity_settings.get('padding', base_config.padding),
            preserve_aspect_ratio=entity_settings.get('preserve_aspect_ratio', base_config.preserve_aspect_ratio),
            placeholder_text=entity_settings.get('placeholder_text', base_config.placeholder_text),
            font_size=entity_settings.get('font_size', base_config.font_size)
        )
        
        return entity_config
    
    def save_redacted_image(
        self,
        result: RedactionResult,
        output_path: Union[str, Path],
        quality: int = 95
    ) -> bool:
        """Save redacted image to file."""
        if not result.success or result.redacted_image is None:
            return False
        
        try:
            # Convert RGB to BGR for OpenCV
            bgr_image = cv2.cvtColor(result.redacted_image, cv2.COLOR_RGB2BGR)
            
            # Save image
            return cv2.imwrite(str(output_path), bgr_image)
            
        except Exception as e:
            logger.error(f"Error saving redacted image: {e}")
            return False
    
    def get_redacted_image_as_pil(self, result: RedactionResult) -> Optional[Image.Image]:
        """Convert redacted image to PIL Image."""
        if not result.success or result.redacted_image is None:
            return None
        
        try:
            return Image.fromarray(result.redacted_image)
        except Exception as e:
            logger.error(f"Error converting to PIL Image: {e}")
            return None
    
    def get_redacted_image_as_base64(self, result: RedactionResult, format: str = "JPEG") -> Optional[str]:
        """Convert redacted image to base64 string."""
        pil_image = self.get_redacted_image_as_pil(result)
        if pil_image is None:
            return None
        
        try:
            buffer = io.BytesIO()
            pil_image.save(buffer, format=format)
            img_str = base64.b64encode(buffer.getvalue()).decode()
            return img_str
        except Exception as e:
            logger.error(f"Error converting to base64: {e}")
            return None
    
    def create_redaction_preview(
        self,
        image: Union[str, Path, np.ndarray, Image.Image],
        entities: List[VisualPIIEntity],
        show_bboxes: bool = True,
        bbox_color: Tuple[int, int, int] = (255, 0, 0),
        bbox_thickness: int = 2
    ) -> Optional[np.ndarray]:
        """Create a preview showing detected entities without redaction."""
        try:
            img_array = self._load_image(image)
            if img_array is None:
                return None
            
            preview_image = img_array.copy()
            
            if show_bboxes:
                # Draw bounding boxes around detected entities
                for entity in entities:
                    bbox = entity.bounding_box
                    
                    # Draw rectangle
                    cv2.rectangle(
                        preview_image,
                        (bbox.x, bbox.y),
                        (bbox.x2, bbox.y2),
                        bbox_color,
                        bbox_thickness
                    )
                    
                    # Add label
                    label = f"{entity.entity_type.value} ({entity.confidence:.2f})"
                    label_size = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 1)[0]
                    
                    # Draw label background
                    cv2.rectangle(
                        preview_image,
                        (bbox.x, bbox.y - label_size[1] - 10),
                        (bbox.x + label_size[0] + 5, bbox.y),
                        bbox_color,
                        -1
                    )
                    
                    # Draw label text
                    cv2.putText(
                        preview_image,
                        label,
                        (bbox.x + 2, bbox.y - 5),
                        cv2.FONT_HERSHEY_SIMPLEX,
                        0.5,
                        (255, 255, 255),
                        1
                    )
            
            return preview_image
            
        except Exception as e:
            logger.error(f"Error creating redaction preview: {e}")
            return None


# Global redaction engine instance
_default_redaction_engine = None

def get_visual_redaction_engine() -> VisualRedactionEngine:
    """Get or create the default visual redaction engine instance."""
    global _default_redaction_engine
    
    if _default_redaction_engine is None:
        _default_redaction_engine = VisualRedactionEngine()
    
    return _default_redaction_engine