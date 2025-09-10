"""
Visual PII Detection Service

High-level service for detecting visual PII entities in images and documents,
with integration to security framework, compliance policies, and audit logging.
"""

import logging
import time
import uuid
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import numpy as np
from PIL import Image
import io
import base64

from ..models.visual_models import (
    VisualDetectionModel, 
    YOLOv8VisualModel, 
    VisualPIIEntity, 
    VisualPIIType,
    BoundingBox,
    get_default_visual_model
)
from ..models.model_manager import ModelManager
from ..config.policies.base import PIIType, RedactionMethod, BasePolicy
from ..config.settings import get_settings
from ..security.encryption import encryption_manager
from ..security.compliance_encryption import (
    compliance_encryption, 
    ComplianceStandard, 
    DataClassification, 
    ComplianceMetadata,
    AuditEventType
)

logger = logging.getLogger(__name__)
settings = get_settings()


class VisualDetectionStatus(str, Enum):
    """Status of visual PII detection operation."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VisualRiskLevel(str, Enum):
    """Risk level assessment for detected visual PII."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class VisualPIIDetectionResult:
    """Result of visual PII detection analysis."""
    
    # Unique identifiers
    detection_id: str
    document_id: Optional[str] = None
    
    # Detection status and timing
    status: VisualDetectionStatus = VisualDetectionStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    processing_time_seconds: Optional[float] = None
    
    # Input information
    image_count: int = 0
    total_images_processed: int = 0
    model_used: str = "yolov8"
    
    # Detection results
    visual_entities: List[VisualPIIEntity] = None
    entity_count: int = 0
    unique_entity_types: List[str] = None
    entities_by_page: Dict[int, List[VisualPIIEntity]] = None
    
    # Risk assessment
    risk_level: VisualRiskLevel = VisualRiskLevel.LOW
    compliance_flags: List[str] = None
    
    # Processing metadata
    confidence_distribution: Dict[str, int] = None
    model_performance: Dict[str, Any] = None
    error_message: Optional[str] = None
    
    # Image metadata
    image_dimensions: Dict[str, Tuple[int, int]] = None
    image_formats: List[str] = None
    
    # Security and audit
    encrypted: bool = False
    audit_logged: bool = False
    compliance_metadata: Optional[ComplianceMetadata] = None
    
    def __post_init__(self):
        if self.visual_entities is None:
            self.visual_entities = []
        if self.unique_entity_types is None:
            self.unique_entity_types = []
        if self.compliance_flags is None:
            self.compliance_flags = []
        if self.confidence_distribution is None:
            self.confidence_distribution = {}
        if self.model_performance is None:
            self.model_performance = {}
        if self.entities_by_page is None:
            self.entities_by_page = {}
        if self.image_dimensions is None:
            self.image_dimensions = {}
        if self.image_formats is None:
            self.image_formats = []
        
        # Set detection_id if not provided
        if not self.detection_id:
            self.detection_id = str(uuid.uuid4())
        
        # Calculate derived fields
        self.entity_count = len(self.visual_entities)
        self.unique_entity_types = list(set(entity.entity_type.value for entity in self.visual_entities))
        
        # Group entities by page
        self._group_entities_by_page()
        
        # Calculate risk level based on entities found
        self._calculate_risk_level()
        
        # Build confidence distribution
        self._build_confidence_distribution()
    
    def _group_entities_by_page(self):
        """Group visual entities by page number."""
        for entity in self.visual_entities:
            page = entity.page_number
            if page not in self.entities_by_page:
                self.entities_by_page[page] = []
            self.entities_by_page[page].append(entity)
    
    def _calculate_risk_level(self):
        """Calculate risk level based on detected visual entities."""
        if not self.visual_entities:
            self.risk_level = VisualRiskLevel.LOW
            return
        
        # Define high-risk visual entity types
        critical_entities = {
            VisualPIIType.SIGNATURE, 
            VisualPIIType.FINGERPRINT, 
            VisualPIIType.ID_CARD
        }
        high_risk_entities = {
            VisualPIIType.FACE, 
            VisualPIIType.STAMP, 
            VisualPIIType.SEAL,
            VisualPIIType.PHOTO
        }
        medium_risk_entities = {
            VisualPIIType.HANDWRITING,
            VisualPIIType.LOGO,
            VisualPIIType.QR_CODE
        }
        
        entity_types = set(entity.entity_type for entity in self.visual_entities)
        
        # Check for critical risk entities
        if any(entity in critical_entities for entity in entity_types):
            self.risk_level = VisualRiskLevel.CRITICAL
            self.compliance_flags.append("critical_visual_pii_detected")
        elif any(entity in high_risk_entities for entity in entity_types):
            self.risk_level = VisualRiskLevel.HIGH
            self.compliance_flags.append("high_risk_visual_pii_detected")
        elif any(entity in medium_risk_entities for entity in entity_types):
            self.risk_level = VisualRiskLevel.MEDIUM
        elif len(self.visual_entities) > 10:
            self.risk_level = VisualRiskLevel.MEDIUM
        else:
            self.risk_level = VisualRiskLevel.LOW
    
    def _build_confidence_distribution(self):
        """Build confidence level distribution."""
        distribution = {"low": 0, "medium": 0, "high": 0, "very_high": 0}
        
        for entity in self.visual_entities:
            distribution[entity.confidence_level.value] += 1
        
        self.confidence_distribution = distribution
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result_dict = asdict(self)
        
        # Convert datetime objects to ISO strings
        if self.started_at:
            result_dict["started_at"] = self.started_at.isoformat()
        if self.completed_at:
            result_dict["completed_at"] = self.completed_at.isoformat()
        
        # Convert visual entities to dict format
        result_dict["visual_entities"] = [entity.to_dict() for entity in self.visual_entities]
        
        # Convert entities by page
        result_dict["entities_by_page"] = {
            str(page): [entity.to_dict() for entity in entities]
            for page, entities in self.entities_by_page.items()
        }
        
        return result_dict
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics of visual detection results."""
        return {
            "detection_id": self.detection_id,
            "status": self.status.value,
            "entity_count": self.entity_count,
            "unique_types": len(self.unique_entity_types),
            "risk_level": self.risk_level.value,
            "processing_time": self.processing_time_seconds,
            "image_count": self.image_count,
            "pages_with_pii": len([p for p, entities in self.entities_by_page.items() if entities]),
            "compliance_flags": self.compliance_flags,
            "confidence_distribution": self.confidence_distribution
        }


class VisualPIIDetectionService:
    """High-level service for visual PII detection and management."""
    
    def __init__(self, model_manager: Optional[ModelManager] = None):
        self.model_manager = model_manager or ModelManager()
        self.settings = get_settings()
        
        # Detection history and caching
        self.detection_history: Dict[str, VisualPIIDetectionResult] = {}
        self.active_detections: Dict[str, VisualPIIDetectionResult] = {}
        
        # Thread pool for async operations
        self.thread_pool = ThreadPoolExecutor(max_workers=2)  # Visual processing is memory-intensive
        
        # Default visual model
        self._default_model: Optional[VisualDetectionModel] = None
        
        logger.info("Initialized VisualPIIDetectionService")
    
    async def detect_visual_pii_async(
        self,
        images: Union[str, Path, List[Union[str, Path]], np.ndarray, Image.Image, List[Image.Image]],
        document_id: Optional[str] = None,
        model_type: str = "yolov8",
        entity_types: Optional[List[VisualPIIType]] = None,
        confidence_threshold: float = 0.5,
        compliance_standards: Optional[List[ComplianceStandard]] = None
    ) -> VisualPIIDetectionResult:
        """Asynchronously detect visual PII in images."""
        
        detection_result = VisualPIIDetectionResult(
            detection_id=str(uuid.uuid4()),
            document_id=document_id,
            model_used=model_type,
            started_at=datetime.now()
        )
        
        # Add to active detections
        self.active_detections[detection_result.detection_id] = detection_result
        detection_result.status = VisualDetectionStatus.IN_PROGRESS
        
        try:
            # Normalize images to list
            image_list = self._normalize_image_input(images)
            detection_result.image_count = len(image_list)
            detection_result.total_images_processed = 0
            
            # Run detection in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            all_entities = await loop.run_in_executor(
                self.thread_pool,
                self._detect_entities_sync,
                image_list, model_type, entity_types, confidence_threshold
            )
            
            # Filter by confidence threshold
            filtered_entities = [
                entity for entity in all_entities
                if entity.confidence >= confidence_threshold
            ]
            
            detection_result.visual_entities = filtered_entities
            detection_result.total_images_processed = len(image_list)
            detection_result.completed_at = datetime.now()
            detection_result.processing_time_seconds = (
                detection_result.completed_at - detection_result.started_at
            ).total_seconds()
            detection_result.status = VisualDetectionStatus.COMPLETED
            
            # Apply compliance analysis
            if compliance_standards:
                detection_result.compliance_metadata = self._analyze_compliance(
                    detection_result, compliance_standards
                )
            
            # Encrypt sensitive detection results if needed
            if detection_result.risk_level in [VisualRiskLevel.HIGH, VisualRiskLevel.CRITICAL]:
                detection_result = await self._encrypt_detection_result(detection_result)
            
            # Log audit trail
            await self._log_detection_audit(detection_result)
            
        except Exception as e:
            logger.error(f"Error in visual PII detection: {e}")
            detection_result.status = VisualDetectionStatus.FAILED
            detection_result.error_message = str(e)
            detection_result.completed_at = datetime.now()
        
        finally:
            # Move from active to history
            if detection_result.detection_id in self.active_detections:
                del self.active_detections[detection_result.detection_id]
            self.detection_history[detection_result.detection_id] = detection_result
        
        return detection_result
    
    def detect_visual_pii_sync(
        self,
        images: Union[str, Path, List[Union[str, Path]], np.ndarray, Image.Image, List[Image.Image]],
        document_id: Optional[str] = None,
        model_type: str = "yolov8",
        entity_types: Optional[List[VisualPIIType]] = None,
        confidence_threshold: float = 0.5
    ) -> VisualPIIDetectionResult:
        """Synchronously detect visual PII in images."""
        
        detection_result = VisualPIIDetectionResult(
            detection_id=str(uuid.uuid4()),
            document_id=document_id,
            model_used=model_type,
            started_at=datetime.now(),
            status=VisualDetectionStatus.IN_PROGRESS
        )
        
        try:
            # Normalize images to list
            image_list = self._normalize_image_input(images)
            detection_result.image_count = len(image_list)
            
            # Detect entities
            all_entities = self._detect_entities_sync(
                image_list, model_type, entity_types, confidence_threshold
            )
            
            # Filter by confidence threshold
            filtered_entities = [
                entity for entity in all_entities
                if entity.confidence >= confidence_threshold
            ]
            
            detection_result.visual_entities = filtered_entities
            detection_result.total_images_processed = len(image_list)
            detection_result.completed_at = datetime.now()
            detection_result.processing_time_seconds = (
                detection_result.completed_at - detection_result.started_at
            ).total_seconds()
            detection_result.status = VisualDetectionStatus.COMPLETED
            
        except Exception as e:
            logger.error(f"Error in sync visual PII detection: {e}")
            detection_result.status = VisualDetectionStatus.FAILED
            detection_result.error_message = str(e)
            detection_result.completed_at = datetime.now()
        
        # Store in history
        self.detection_history[detection_result.detection_id] = detection_result
        return detection_result
    
    def _normalize_image_input(
        self, 
        images: Union[str, Path, List[Union[str, Path]], np.ndarray, Image.Image, List[Image.Image]]
    ) -> List[Union[str, Path, np.ndarray, Image.Image]]:
        """Normalize various image input types to a list."""
        if isinstance(images, (str, Path, np.ndarray, Image.Image)):
            return [images]
        elif isinstance(images, list):
            return images
        else:
            raise ValueError(f"Unsupported image input type: {type(images)}")
    
    def _detect_entities_sync(
        self,
        image_list: List[Union[str, Path, np.ndarray, Image.Image]],
        model_type: str,
        entity_types: Optional[List[VisualPIIType]],
        confidence_threshold: float
    ) -> List[VisualPIIEntity]:
        """Internal synchronous entity detection for multiple images."""
        
        # Get or create model
        model = self._get_model(model_type)
        
        if not model.is_loaded:
            if not model.load():
                raise RuntimeError(f"Failed to load {model_type} visual model")
        
        # Detect entities in each image
        all_entities = []
        
        for page_num, image in enumerate(image_list):
            try:
                entities = model.detect_visual_pii(
                    image=image,
                    confidence_threshold=confidence_threshold,
                    entity_types=entity_types
                )
                
                # Set page number for each entity
                for entity in entities:
                    entity.page_number = page_num
                
                all_entities.extend(entities)
                logger.debug(f"Detected {len(entities)} entities in image {page_num}")
                
            except Exception as e:
                logger.error(f"Error detecting entities in image {page_num}: {e}")
                continue
        
        return all_entities
    
    def _get_model(self, model_type: str) -> VisualDetectionModel:
        """Get or create visual detection model instance."""
        
        if model_type.lower() == "yolov8":
            if self._default_model is None:
                self._default_model = get_default_visual_model()
            return self._default_model
        else:
            # Could support other model types in the future
            raise ValueError(f"Unsupported visual model type: {model_type}")
    
    def _analyze_compliance(
        self,
        detection_result: VisualPIIDetectionResult,
        standards: List[ComplianceStandard]
    ) -> ComplianceMetadata:
        """Analyze detection results for compliance requirements."""
        
        # Determine data classification based on detected entities
        classification = DataClassification.INTERNAL
        
        critical_entities = {VisualPIIType.SIGNATURE, VisualPIIType.FINGERPRINT, VisualPIIType.ID_CARD}
        confidential_entities = {VisualPIIType.FACE, VisualPIIType.PHOTO}
        
        entity_types = set(entity.entity_type for entity in detection_result.visual_entities)
        
        if any(entity in critical_entities for entity in entity_types):
            classification = DataClassification.RESTRICTED
            detection_result.compliance_flags.append("critical_visual_pii_detected")
        elif any(entity in confidential_entities for entity in entity_types):
            classification = DataClassification.CONFIDENTIAL
            detection_result.compliance_flags.append("confidential_visual_pii_detected")
        
        # Check for face detection (GDPR/HIPAA relevant)
        if any(entity.entity_type == VisualPIIType.FACE for entity in detection_result.visual_entities):
            detection_result.compliance_flags.append("biometric_data_detected")
        
        # Create compliance metadata
        metadata = ComplianceMetadata(
            classification=classification,
            standards=standards,
            retention_period_days=2190 if ComplianceStandard.HIPAA in standards else 2555,
            encryption_required=True,
            audit_required=True,
            created_at=datetime.now()
        )
        
        return metadata
    
    async def _encrypt_detection_result(self, detection_result: VisualPIIDetectionResult) -> VisualPIIDetectionResult:
        """Encrypt sensitive visual detection results."""
        try:
            # For visual PII, we might encrypt bounding box coordinates and metadata
            # rather than the actual entity text (which would be image regions)
            
            high_risk_entities = [
                entity for entity in detection_result.visual_entities
                if entity.confidence >= 0.8 and entity.entity_type in [
                    VisualPIIType.SIGNATURE, VisualPIIType.FACE, VisualPIIType.FINGERPRINT
                ]
            ]
            
            for entity in high_risk_entities:
                # Encrypt sensitive metadata
                if entity.detection_metadata:
                    sensitive_data = str(entity.detection_metadata)
                    entity.detection_metadata["encrypted_data"] = encryption_manager.encrypt_text(sensitive_data)
                    entity.detection_metadata["original_cleared"] = True
            
            detection_result.encrypted = True
            logger.debug(f"Encrypted visual detection result {detection_result.detection_id}")
            
        except Exception as e:
            logger.error(f"Failed to encrypt visual detection result: {e}")
        
        return detection_result
    
    async def _log_detection_audit(self, detection_result: VisualPIIDetectionResult):
        """Log visual detection operation to audit trail."""
        try:
            audit_data = {
                "detection_id": detection_result.detection_id,
                "document_id": detection_result.document_id,
                "entity_count": detection_result.entity_count,
                "image_count": detection_result.image_count,
                "risk_level": detection_result.risk_level.value,
                "status": detection_result.status.value,
                "processing_time": detection_result.processing_time_seconds,
                "model_used": detection_result.model_used,
                "entity_types": detection_result.unique_entity_types,
                "timestamp": datetime.now().isoformat()
            }
            
            # Use compliance encryption for audit logging if available
            if hasattr(compliance_encryption, '_log_audit_event'):
                compliance_encryption._log_audit_event(
                    AuditEventType.DATA_ACCESS,
                    "visual_pii_detection_completed",
                    "success",
                    audit_data
                )
            
            detection_result.audit_logged = True
            logger.debug(f"Logged audit for visual detection {detection_result.detection_id}")
            
        except Exception as e:
            logger.error(f"Failed to log visual detection audit: {e}")
    
    def get_detection_result(self, detection_id: str) -> Optional[VisualPIIDetectionResult]:
        """Get visual detection result by ID."""
        # Check active detections first
        if detection_id in self.active_detections:
            return self.active_detections[detection_id]
        
        # Check history
        return self.detection_history.get(detection_id)
    
    def get_detection_status(self, detection_id: str) -> Optional[VisualDetectionStatus]:
        """Get visual detection status by ID."""
        result = self.get_detection_result(detection_id)
        return result.status if result else None
    
    def cancel_detection(self, detection_id: str) -> bool:
        """Cancel an active visual detection operation."""
        if detection_id in self.active_detections:
            result = self.active_detections[detection_id]
            result.status = VisualDetectionStatus.CANCELLED
            result.completed_at = datetime.now()
            
            # Move to history
            del self.active_detections[detection_id]
            self.detection_history[detection_id] = result
            
            logger.info(f"Cancelled visual detection {detection_id}")
            return True
        
        return False
    
    def get_service_statistics(self) -> Dict[str, Any]:
        """Get visual detection service performance and usage statistics."""
        total_detections = len(self.detection_history) + len(self.active_detections)
        
        completed_detections = [
            result for result in self.detection_history.values()
            if result.status == VisualDetectionStatus.COMPLETED
        ]
        
        avg_processing_time = 0
        avg_entities_per_detection = 0
        total_images_processed = 0
        
        if completed_detections:
            processing_times = [r.processing_time_seconds for r in completed_detections if r.processing_time_seconds]
            avg_processing_time = sum(processing_times) / len(processing_times) if processing_times else 0
            
            entity_counts = [r.entity_count for r in completed_detections]
            avg_entities_per_detection = sum(entity_counts) / len(entity_counts) if entity_counts else 0
            
            total_images_processed = sum(r.total_images_processed for r in completed_detections)
        
        risk_distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for result in completed_detections:
            risk_distribution[result.risk_level.value] += 1
        
        return {
            "total_detections": total_detections,
            "active_detections": len(self.active_detections),
            "completed_detections": len(completed_detections),
            "average_processing_time": avg_processing_time,
            "average_entities_per_detection": avg_entities_per_detection,
            "total_images_processed": total_images_processed,
            "risk_level_distribution": risk_distribution,
            "default_model_loaded": self._default_model is not None and self._default_model.is_loaded,
            "thread_pool_workers": self.thread_pool._max_workers
        }
    
    def cleanup_history(self, max_age_hours: int = 24):
        """Clean up old visual detection history."""
        cutoff_time = datetime.now().timestamp() - (max_age_hours * 3600)
        
        to_remove = []
        for detection_id, result in self.detection_history.items():
            if result.completed_at and result.completed_at.timestamp() < cutoff_time:
                to_remove.append(detection_id)
        
        for detection_id in to_remove:
            del self.detection_history[detection_id]
        
        logger.info(f"Cleaned up {len(to_remove)} old visual detection records")


# Global service instance
_default_visual_pii_service = None

def get_visual_pii_detection_service() -> VisualPIIDetectionService:
    """Get or create the default visual PII detection service instance."""
    global _default_visual_pii_service
    
    if _default_visual_pii_service is None:
        _default_visual_pii_service = VisualPIIDetectionService()
    
    return _default_visual_pii_service