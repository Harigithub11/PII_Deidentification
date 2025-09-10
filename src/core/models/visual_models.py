"""
Visual PII Detection Models for De-identification System

This module provides visual PII detection capabilities using YOLOv8 and other computer vision
models to detect faces, signatures, stamps, logos, and other visual PII elements in documents.
"""

import logging
import numpy as np
import cv2
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import torch
from PIL import Image, ImageDraw, ImageFilter
import io
import base64

# YOLOv8 imports
from ultralytics import YOLO
from ultralytics.engine.results import Results

from ..config.settings import get_settings
from ..config.policies.base import PIIType, RedactionMethod

logger = logging.getLogger(__name__)
settings = get_settings()


class VisualPIIType(str, Enum):
    """Types of visual PII that can be detected."""
    FACE = "face"
    SIGNATURE = "signature"
    STAMP = "stamp"
    SEAL = "seal"
    LOGO = "logo"
    QR_CODE = "qr_code"
    BARCODE = "barcode"
    HANDWRITING = "handwriting"
    PHOTO = "photo"
    FINGERPRINT = "fingerprint"
    ID_CARD = "id_card"
    DOCUMENT_HEADER = "document_header"


class VisualConfidenceLevel(str, Enum):
    """Confidence levels for visual detection."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass
class BoundingBox:
    """Represents a bounding box for detected visual elements."""
    x: int  # Left coordinate
    y: int  # Top coordinate
    width: int  # Box width
    height: int  # Box height
    
    @property
    def x2(self) -> int:
        """Right coordinate."""
        return self.x + self.width
    
    @property
    def y2(self) -> int:
        """Bottom coordinate."""
        return self.y + self.height
    
    @property
    def center(self) -> Tuple[int, int]:
        """Center point of the bounding box."""
        return (self.x + self.width // 2, self.y + self.height // 2)
    
    @property
    def area(self) -> int:
        """Area of the bounding box."""
        return self.width * self.height
    
    def iou(self, other: 'BoundingBox') -> float:
        """Calculate Intersection over Union with another bounding box."""
        # Calculate intersection coordinates
        x1 = max(self.x, other.x)
        y1 = max(self.y, other.y)
        x2 = min(self.x2, other.x2)
        y2 = min(self.y2, other.y2)
        
        # Calculate intersection area
        if x2 <= x1 or y2 <= y1:
            return 0.0
        
        intersection = (x2 - x1) * (y2 - y1)
        union = self.area + other.area - intersection
        
        return intersection / union if union > 0 else 0.0
    
    def expand(self, padding: int) -> 'BoundingBox':
        """Expand the bounding box by padding pixels."""
        return BoundingBox(
            x=max(0, self.x - padding),
            y=max(0, self.y - padding),
            width=self.width + 2 * padding,
            height=self.height + 2 * padding
        )


@dataclass
class VisualPIIEntity:
    """Detected visual PII entity with metadata."""
    entity_type: VisualPIIType
    confidence: float
    confidence_level: VisualConfidenceLevel
    bounding_box: BoundingBox
    page_number: int = 0  # For multi-page documents
    image_width: int = 0
    image_height: int = 0
    model_name: str = "yolov8"
    detection_metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.detection_metadata is None:
            self.detection_metadata = {}
        
        # Set confidence level based on score
        if self.confidence >= 0.9:
            self.confidence_level = VisualConfidenceLevel.VERY_HIGH
        elif self.confidence >= 0.7:
            self.confidence_level = VisualConfidenceLevel.HIGH
        elif self.confidence >= 0.5:
            self.confidence_level = VisualConfidenceLevel.MEDIUM
        else:
            self.confidence_level = VisualConfidenceLevel.LOW
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "entity_type": self.entity_type.value,
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.value,
            "bounding_box": asdict(self.bounding_box),
            "page_number": self.page_number,
            "image_dimensions": {
                "width": self.image_width,
                "height": self.image_height
            },
            "model_name": self.model_name,
            "detection_metadata": self.detection_metadata
        }


class VisualDetectionModel(ABC):
    """Abstract base class for visual PII detection models."""
    
    def __init__(self, model_name: str, device: str = "auto"):
        self.model_name = model_name
        self.device = device
        self.is_loaded = False
        self._supported_formats = [".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp", ".webp"]
        
    @abstractmethod
    def load(self) -> bool:
        """Load the visual detection model."""
        pass
    
    @abstractmethod
    def unload(self):
        """Unload the model to free memory."""
        pass
    
    @abstractmethod
    def detect_visual_pii(
        self,
        image: Union[str, Path, np.ndarray, Image.Image],
        confidence_threshold: float = 0.5,
        entity_types: Optional[List[VisualPIIType]] = None
    ) -> List[VisualPIIEntity]:
        """Detect visual PII entities in an image."""
        pass
    
    @abstractmethod
    def get_supported_entities(self) -> List[VisualPIIType]:
        """Get list of supported visual PII entity types."""
        pass
    
    def preprocess_image(
        self,
        image: Union[str, Path, np.ndarray, Image.Image],
        target_size: Optional[Tuple[int, int]] = None
    ) -> np.ndarray:
        """Preprocess image for detection."""
        # Convert various input types to numpy array
        if isinstance(image, (str, Path)):
            image = cv2.imread(str(image))
            if image is None:
                raise ValueError(f"Could not load image from {image}")
            image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        elif isinstance(image, Image.Image):
            image = np.array(image.convert('RGB'))
        elif isinstance(image, np.ndarray):
            # Ensure it's RGB
            if len(image.shape) == 3 and image.shape[2] == 3:
                pass  # Already RGB
            else:
                raise ValueError("Unsupported image format")
        else:
            raise ValueError("Unsupported image input type")
        
        # Resize if target size specified
        if target_size:
            image = cv2.resize(image, target_size, interpolation=cv2.INTER_AREA)
        
        return image


class YOLOv8VisualModel(VisualDetectionModel):
    """YOLOv8-based visual PII detection model."""
    
    def __init__(
        self,
        model_name: str = "yolov8n.pt",
        device: str = "auto",
        confidence_threshold: float = 0.5,
        iou_threshold: float = 0.45,
        custom_classes: Optional[Dict[int, VisualPIIType]] = None
    ):
        super().__init__(f"yolov8_{model_name}", device)
        
        self.yolo_model_name = model_name
        self.confidence_threshold = confidence_threshold
        self.iou_threshold = iou_threshold
        self.model: Optional[YOLO] = None
        
        # Default COCO class mappings to visual PII types
        self.class_mappings = custom_classes or {
            0: VisualPIIType.FACE,  # person (we'll assume faces)
            # Add custom mappings for trained models
        }
        
        # For custom PII detection, we'll need a model trained on PII data
        # For now, we'll use a generic approach with post-processing
        self.pii_class_mappings = {
            "face": VisualPIIType.FACE,
            "signature": VisualPIIType.SIGNATURE,
            "stamp": VisualPIIType.STAMP,
            "seal": VisualPIIType.SEAL,
            "logo": VisualPIIType.LOGO,
            "qr_code": VisualPIIType.QR_CODE,
            "barcode": VisualPIIType.BARCODE,
            "handwriting": VisualPIIType.HANDWRITING,
            "photo": VisualPIIType.PHOTO,
            "fingerprint": VisualPIIType.FINGERPRINT
        }
        
        logger.info(f"Initialized YOLOv8VisualModel with {model_name}")
    
    def load(self) -> bool:
        """Load YOLOv8 model."""
        try:
            # Initialize YOLO model
            self.model = YOLO(self.yolo_model_name)
            
            # Set device
            if self.device == "auto":
                device = "cuda" if torch.cuda.is_available() else "cpu"
            else:
                device = self.device
            
            # Move model to device
            self.model.to(device)
            
            self.is_loaded = True
            logger.info(f"Successfully loaded YOLOv8 model: {self.yolo_model_name} on {device}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load YOLOv8 model: {e}")
            self.is_loaded = False
            return False
    
    def unload(self):
        """Unload YOLOv8 model to free memory."""
        if self.model:
            self.model = None
        
        # Clear CUDA cache if using GPU
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        
        self.is_loaded = False
        logger.info("Unloaded YOLOv8 model")
    
    def detect_visual_pii(
        self,
        image: Union[str, Path, np.ndarray, Image.Image],
        confidence_threshold: float = None,
        entity_types: Optional[List[VisualPIIType]] = None
    ) -> List[VisualPIIEntity]:
        """Detect visual PII entities using YOLOv8."""
        if not self.is_loaded:
            raise RuntimeError("Model not loaded. Call load() first.")
        
        if confidence_threshold is None:
            confidence_threshold = self.confidence_threshold
        
        try:
            # Preprocess image
            if isinstance(image, (str, Path)):
                image_path = str(image)
                img_array = self.preprocess_image(image)
            else:
                img_array = self.preprocess_image(image)
                image_path = None
            
            # Run inference
            if image_path:
                results = self.model(image_path, conf=confidence_threshold, iou=self.iou_threshold)
            else:
                results = self.model(img_array, conf=confidence_threshold, iou=self.iou_threshold)
            
            # Extract detections
            visual_entities = []
            
            for result in results:
                # Get image dimensions
                img_height, img_width = result.orig_shape
                
                # Process detections
                if result.boxes is not None:
                    boxes = result.boxes.cpu().numpy()
                    
                    for box in boxes:
                        # Extract bounding box coordinates
                        x1, y1, x2, y2 = box.xyxy[0]
                        confidence = box.conf[0]
                        class_id = int(box.cls[0])
                        
                        # Map class to PII type
                        entity_type = self._map_class_to_pii_type(class_id, result.names)
                        
                        if entity_type and (not entity_types or entity_type in entity_types):
                            # Create bounding box
                            bbox = BoundingBox(
                                x=int(x1),
                                y=int(y1),
                                width=int(x2 - x1),
                                height=int(y2 - y1)
                            )
                            
                            # Create visual PII entity
                            entity = VisualPIIEntity(
                                entity_type=entity_type,
                                confidence=float(confidence),
                                confidence_level=VisualConfidenceLevel.LOW,  # Will be set in __post_init__
                                bounding_box=bbox,
                                page_number=0,
                                image_width=img_width,
                                image_height=img_height,
                                model_name=self.model_name,
                                detection_metadata={
                                    "yolo_class_id": class_id,
                                    "yolo_class_name": result.names.get(class_id, "unknown"),
                                    "iou_threshold": self.iou_threshold
                                }
                            )
                            
                            visual_entities.append(entity)
            
            logger.debug(f"Detected {len(visual_entities)} visual PII entities")
            return visual_entities
            
        except Exception as e:
            logger.error(f"Error detecting visual PII: {e}")
            return []
    
    def _map_class_to_pii_type(self, class_id: int, class_names: Dict[int, str]) -> Optional[VisualPIIType]:
        """Map YOLO class ID to PII type."""
        # First check custom class mappings
        if class_id in self.class_mappings:
            return self.class_mappings[class_id]
        
        # Check class name mappings
        class_name = class_names.get(class_id, "").lower()
        
        # Map common YOLO classes to PII types
        if "person" in class_name:
            return VisualPIIType.FACE  # Assume person detection implies face
        elif any(keyword in class_name for keyword in ["book", "newspaper", "paper"]):
            return VisualPIIType.DOCUMENT_HEADER
        elif "cell phone" in class_name or "mobile" in class_name:
            return None  # Not PII
        
        # For custom PII models, map directly
        for pii_keyword, pii_type in self.pii_class_mappings.items():
            if pii_keyword in class_name:
                return pii_type
        
        # Default: no PII mapping
        return None
    
    def get_supported_entities(self) -> List[VisualPIIType]:
        """Get supported visual PII entity types."""
        if not self.is_loaded:
            return list(VisualPIIType)
        
        # Return all possible PII types that this model can detect
        return [
            VisualPIIType.FACE,
            VisualPIIType.SIGNATURE,
            VisualPIIType.STAMP,
            VisualPIIType.SEAL,
            VisualPIIType.LOGO,
            VisualPIIType.QR_CODE,
            VisualPIIType.BARCODE,
            VisualPIIType.HANDWRITING,
            VisualPIIType.PHOTO
        ]
    
    def detect_faces_advanced(
        self,
        image: Union[str, Path, np.ndarray, Image.Image],
        confidence_threshold: float = 0.5
    ) -> List[VisualPIIEntity]:
        """Advanced face detection using additional techniques."""
        # This could integrate with specialized face detection models
        # For now, use the standard detection
        return self.detect_visual_pii(
            image, 
            confidence_threshold=confidence_threshold,
            entity_types=[VisualPIIType.FACE]
        )
    
    def detect_signatures(
        self,
        image: Union[str, Path, np.ndarray, Image.Image],
        confidence_threshold: float = 0.3
    ) -> List[VisualPIIEntity]:
        """Specialized signature detection."""
        # This would require a custom-trained model for signatures
        # For demonstration, we'll use image processing techniques
        
        try:
            img_array = self.preprocess_image(image)
            img_height, img_width = img_array.shape[:2]
            
            # Convert to grayscale for signature detection
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            
            # Use simple techniques to find signature-like regions
            # This is a placeholder - real signature detection would use ML
            
            # Find contours that might be signatures
            edges = cv2.Canny(gray, 50, 150)
            contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            signatures = []
            for contour in contours:
                # Filter contours by size and aspect ratio (signatures are typically wide)
                x, y, w, h = cv2.boundingRect(contour)
                
                # Skip very small or very large regions
                if w < 50 or h < 20 or w > img_width * 0.8 or h > img_height * 0.5:
                    continue
                
                # Check aspect ratio (signatures are usually wider than tall)
                aspect_ratio = w / h
                if aspect_ratio < 1.5 or aspect_ratio > 8:
                    continue
                
                # Create signature entity
                bbox = BoundingBox(x=x, y=y, width=w, height=h)
                
                entity = VisualPIIEntity(
                    entity_type=VisualPIIType.SIGNATURE,
                    confidence=0.6,  # Moderate confidence for rule-based detection
                    confidence_level=VisualConfidenceLevel.MEDIUM,
                    bounding_box=bbox,
                    page_number=0,
                    image_width=img_width,
                    image_height=img_height,
                    model_name=f"{self.model_name}_signature_detector",
                    detection_metadata={
                        "detection_method": "contour_analysis",
                        "aspect_ratio": aspect_ratio,
                        "contour_area": cv2.contourArea(contour)
                    }
                )
                
                signatures.append(entity)
            
            return signatures[:10]  # Limit to top 10 detections
            
        except Exception as e:
            logger.error(f"Error in signature detection: {e}")
            return []
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information and statistics."""
        info = {
            "model_name": self.model_name,
            "yolo_model": self.yolo_model_name,
            "is_loaded": self.is_loaded,
            "device": self.device,
            "confidence_threshold": self.confidence_threshold,
            "iou_threshold": self.iou_threshold,
            "supported_formats": self._supported_formats,
            "supported_entities": len(self.get_supported_entities())
        }
        
        if self.is_loaded and self.model:
            try:
                info.update({
                    "model_device": str(self.model.device),
                    "model_classes": len(self.model.names) if hasattr(self.model, 'names') else 0
                })
            except:
                pass
        
        return info


# Factory function for creating visual detection models
def create_visual_detection_model(
    model_type: str = "yolov8",
    model_name: str = "yolov8n.pt",
    device: str = "auto",
    **kwargs
) -> VisualDetectionModel:
    """Factory function to create visual detection model instances."""
    
    if model_type.lower() == "yolov8":
        return YOLOv8VisualModel(
            model_name=model_name,
            device=device,
            **kwargs
        )
    else:
        raise ValueError(f"Unsupported visual detection model type: {model_type}")


# Default model instance
_default_visual_model = None

def get_default_visual_model() -> YOLOv8VisualModel:
    """Get or create the default visual detection model instance."""
    global _default_visual_model
    
    if _default_visual_model is None:
        _default_visual_model = create_visual_detection_model("yolov8")
        if not _default_visual_model.load():
            logger.warning("Failed to load default YOLOv8 model")
            # Could fall back to a CPU-only model or alternative approach
    
    return _default_visual_model