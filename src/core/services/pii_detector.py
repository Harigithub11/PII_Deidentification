"""
PII Detection Service

High-level service for detecting and managing PII entities in documents and text,
with integration to security framework, compliance policies, and audit logging.
"""

import logging
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio
from concurrent.futures import ThreadPoolExecutor

from ..models.ner_models import NERModel, PIIEntity, PresidioNERModel, create_ner_model, get_default_ner_model
from ..models.model_manager import ModelManager
from ..config.policies.base import PIIType, RedactionMethod, BasePolicy
from ..config.settings import get_settings
from ..security.encryption import encryption_manager
from ..security.compliance_encryption import compliance_encryption, ComplianceStandard, DataClassification, ComplianceMetadata

logger = logging.getLogger(__name__)
settings = get_settings()


class DetectionStatus(str, Enum):
    """Status of PII detection operation."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RiskLevel(str, Enum):
    """Risk level assessment for detected PII."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PIIDetectionResult:
    """Result of PII detection analysis."""
    
    # Unique identifiers
    detection_id: str
    document_id: Optional[str] = None
    
    # Detection status and timing
    status: DetectionStatus = DetectionStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    processing_time_seconds: Optional[float] = None
    
    # Input information
    text_length: int = 0
    language: str = "en"
    model_used: str = "presidio"
    
    # Detection results
    entities: List[PIIEntity] = None
    entity_count: int = 0
    unique_entity_types: List[str] = None
    
    # Risk assessment
    risk_level: RiskLevel = RiskLevel.LOW
    compliance_flags: List[str] = None
    
    # Processing metadata
    confidence_distribution: Dict[str, int] = None
    model_performance: Dict[str, Any] = None
    error_message: Optional[str] = None
    
    # Security and audit
    encrypted: bool = False
    audit_logged: bool = False
    compliance_metadata: Optional[ComplianceMetadata] = None
    
    def __post_init__(self):
        if self.entities is None:
            self.entities = []
        if self.unique_entity_types is None:
            self.unique_entity_types = []
        if self.compliance_flags is None:
            self.compliance_flags = []
        if self.confidence_distribution is None:
            self.confidence_distribution = {}
        if self.model_performance is None:
            self.model_performance = {}
        
        # Set detection_id if not provided
        if not self.detection_id:
            self.detection_id = str(uuid.uuid4())
        
        # Calculate derived fields
        self.entity_count = len(self.entities)
        self.unique_entity_types = list(set(entity.entity_type for entity in self.entities))
        
        # Calculate risk level based on entities found
        self._calculate_risk_level()
        
        # Build confidence distribution
        self._build_confidence_distribution()
    
    def _calculate_risk_level(self):
        """Calculate risk level based on detected entities."""
        if not self.entities:
            self.risk_level = RiskLevel.LOW
            return
        
        # Define high-risk entity types
        critical_entities = {PIIType.SSN, PIIType.CREDIT_CARD, PIIType.PASSPORT, PIIType.MEDICAL_RECORD}
        high_risk_entities = {PIIType.DRIVER_LICENSE, PIIType.BANK_ACCOUNT, PIIType.NATIONAL_ID}
        
        entity_types = set(self.unique_entity_types)
        
        if any(entity in critical_entities for entity in entity_types):
            self.risk_level = RiskLevel.CRITICAL
        elif any(entity in high_risk_entities for entity in entity_types):
            self.risk_level = RiskLevel.HIGH
        elif len(self.entities) > 5:
            self.risk_level = RiskLevel.MEDIUM
        else:
            self.risk_level = RiskLevel.LOW
    
    def _build_confidence_distribution(self):
        """Build confidence level distribution."""
        distribution = {"low": 0, "medium": 0, "high": 0, "very_high": 0}
        
        for entity in self.entities:
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
        
        # Convert entities to dict format
        result_dict["entities"] = [asdict(entity) for entity in self.entities]
        
        return result_dict
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics of detection results."""
        return {
            "detection_id": self.detection_id,
            "status": self.status.value,
            "entity_count": self.entity_count,
            "unique_types": len(self.unique_entity_types),
            "risk_level": self.risk_level.value,
            "processing_time": self.processing_time_seconds,
            "compliance_flags": self.compliance_flags,
            "confidence_distribution": self.confidence_distribution
        }


class PIIDetectionService:
    """High-level service for PII detection and management."""
    
    def __init__(self, model_manager: Optional[ModelManager] = None):
        self.model_manager = model_manager or ModelManager()
        self.settings = get_settings()
        
        # Detection history and caching
        self.detection_history: Dict[str, PIIDetectionResult] = {}
        self.active_detections: Dict[str, PIIDetectionResult] = {}
        
        # Thread pool for async operations
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
        # Default NER model
        self._default_model: Optional[NERModel] = None
        
        logger.info("Initialized PIIDetectionService")
    
    async def detect_pii_async(
        self,
        text: str,
        document_id: Optional[str] = None,
        language: str = "en",
        model_type: str = "presidio",
        entity_types: Optional[List[str]] = None,
        confidence_threshold: float = 0.5,
        compliance_standards: Optional[List[ComplianceStandard]] = None
    ) -> PIIDetectionResult:
        """Asynchronously detect PII in text."""
        
        detection_result = PIIDetectionResult(
            detection_id=str(uuid.uuid4()),
            document_id=document_id,
            text_length=len(text),
            language=language,
            model_used=model_type,
            started_at=datetime.now()
        )
        
        # Add to active detections
        self.active_detections[detection_result.detection_id] = detection_result
        detection_result.status = DetectionStatus.IN_PROGRESS
        
        try:
            # Run detection in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            entities = await loop.run_in_executor(
                self.thread_pool,
                self._detect_entities_sync,
                text, language, model_type, entity_types, confidence_threshold
            )
            
            # Filter by confidence threshold
            filtered_entities = [
                entity for entity in entities 
                if entity.confidence >= confidence_threshold
            ]
            
            detection_result.entities = filtered_entities
            detection_result.completed_at = datetime.now()
            detection_result.processing_time_seconds = (
                detection_result.completed_at - detection_result.started_at
            ).total_seconds()
            detection_result.status = DetectionStatus.COMPLETED
            
            # Apply compliance analysis
            if compliance_standards:
                detection_result.compliance_metadata = self._analyze_compliance(
                    detection_result, compliance_standards
                )
            
            # Encrypt sensitive detection results if needed
            if detection_result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                detection_result = await self._encrypt_detection_result(detection_result)
            
            # Log audit trail
            await self._log_detection_audit(detection_result)
            
        except Exception as e:
            logger.error(f"Error in PII detection: {e}")
            detection_result.status = DetectionStatus.FAILED
            detection_result.error_message = str(e)
            detection_result.completed_at = datetime.now()
        
        finally:
            # Move from active to history
            if detection_result.detection_id in self.active_detections:
                del self.active_detections[detection_result.detection_id]
            self.detection_history[detection_result.detection_id] = detection_result
        
        return detection_result
    
    def detect_pii_sync(
        self,
        text: str,
        document_id: Optional[str] = None,
        language: str = "en",
        model_type: str = "presidio",
        entity_types: Optional[List[str]] = None,
        confidence_threshold: float = 0.5
    ) -> PIIDetectionResult:
        """Synchronously detect PII in text."""
        
        detection_result = PIIDetectionResult(
            detection_id=str(uuid.uuid4()),
            document_id=document_id,
            text_length=len(text),
            language=language,
            model_used=model_type,
            started_at=datetime.now(),
            status=DetectionStatus.IN_PROGRESS
        )
        
        try:
            # Detect entities
            entities = self._detect_entities_sync(
                text, language, model_type, entity_types, confidence_threshold
            )
            
            # Filter by confidence threshold
            filtered_entities = [
                entity for entity in entities 
                if entity.confidence >= confidence_threshold
            ]
            
            detection_result.entities = filtered_entities
            detection_result.completed_at = datetime.now()
            detection_result.processing_time_seconds = (
                detection_result.completed_at - detection_result.started_at
            ).total_seconds()
            detection_result.status = DetectionStatus.COMPLETED
            
        except Exception as e:
            logger.error(f"Error in sync PII detection: {e}")
            detection_result.status = DetectionStatus.FAILED
            detection_result.error_message = str(e)
            detection_result.completed_at = datetime.now()
        
        # Store in history
        self.detection_history[detection_result.detection_id] = detection_result
        return detection_result
    
    def _detect_entities_sync(
        self,
        text: str,
        language: str,
        model_type: str,
        entity_types: Optional[List[str]],
        confidence_threshold: float
    ) -> List[PIIEntity]:
        """Internal synchronous entity detection."""
        
        # Get or create model
        model = self._get_model(model_type, language)
        
        if not model.is_loaded:
            if not model.load():
                raise RuntimeError(f"Failed to load {model_type} model")
        
        # Detect entities
        entities = model.detect_entities(
            text=text,
            language=language,
            entities=entity_types
        )
        
        return entities
    
    def _get_model(self, model_type: str, language: str) -> NERModel:
        """Get or create NER model instance."""
        
        if model_type.lower() == "presidio":
            if self._default_model is None:
                self._default_model = get_default_ner_model()
            return self._default_model
        else:
            return create_ner_model(model_type, language)
    
    def _analyze_compliance(
        self,
        detection_result: PIIDetectionResult,
        standards: List[ComplianceStandard]
    ) -> ComplianceMetadata:
        """Analyze detection results for compliance requirements."""
        
        # Determine data classification based on detected entities
        classification = DataClassification.INTERNAL
        
        critical_entities = {PIIType.SSN, PIIType.CREDIT_CARD, PIIType.PASSPORT}
        confidential_entities = {PIIType.MEDICAL_RECORD, PIIType.BANK_ACCOUNT}
        
        entity_types = set(detection_result.unique_entity_types)
        
        if any(entity in critical_entities for entity in entity_types):
            classification = DataClassification.RESTRICTED
            detection_result.compliance_flags.append("critical_pii_detected")
        elif any(entity in confidential_entities for entity in entity_types):
            classification = DataClassification.CONFIDENTIAL
            detection_result.compliance_flags.append("confidential_pii_detected")
        
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
    
    async def _encrypt_detection_result(self, detection_result: PIIDetectionResult) -> PIIDetectionResult:
        """Encrypt sensitive detection results."""
        try:
            # Encrypt entity text content
            for entity in detection_result.entities:
                if entity.confidence >= 0.8:  # Only encrypt high-confidence entities
                    entity.text = encryption_manager.encrypt_text(entity.text)
            
            detection_result.encrypted = True
            logger.debug(f"Encrypted detection result {detection_result.detection_id}")
            
        except Exception as e:
            logger.error(f"Failed to encrypt detection result: {e}")
        
        return detection_result
    
    async def _log_detection_audit(self, detection_result: PIIDetectionResult):
        """Log detection operation to audit trail."""
        try:
            audit_data = {
                "detection_id": detection_result.detection_id,
                "document_id": detection_result.document_id,
                "entity_count": detection_result.entity_count,
                "risk_level": detection_result.risk_level.value,
                "status": detection_result.status.value,
                "processing_time": detection_result.processing_time_seconds,
                "model_used": detection_result.model_used,
                "timestamp": datetime.now().isoformat()
            }
            
            # Use compliance encryption for audit logging if available
            if hasattr(compliance_encryption, '_log_audit_event'):
                from ..security.compliance_encryption import AuditEventType
                compliance_encryption._log_audit_event(
                    AuditEventType.DATA_ACCESS,
                    "pii_detection_completed",
                    "success",
                    audit_data
                )
            
            detection_result.audit_logged = True
            logger.debug(f"Logged audit for detection {detection_result.detection_id}")
            
        except Exception as e:
            logger.error(f"Failed to log detection audit: {e}")
    
    def get_detection_result(self, detection_id: str) -> Optional[PIIDetectionResult]:
        """Get detection result by ID."""
        # Check active detections first
        if detection_id in self.active_detections:
            return self.active_detections[detection_id]
        
        # Check history
        return self.detection_history.get(detection_id)
    
    def get_detection_status(self, detection_id: str) -> Optional[DetectionStatus]:
        """Get detection status by ID."""
        result = self.get_detection_result(detection_id)
        return result.status if result else None
    
    def cancel_detection(self, detection_id: str) -> bool:
        """Cancel an active detection operation."""
        if detection_id in self.active_detections:
            result = self.active_detections[detection_id]
            result.status = DetectionStatus.CANCELLED
            result.completed_at = datetime.now()
            
            # Move to history
            del self.active_detections[detection_id]
            self.detection_history[detection_id] = result
            
            logger.info(f"Cancelled detection {detection_id}")
            return True
        
        return False
    
    def get_service_statistics(self) -> Dict[str, Any]:
        """Get service performance and usage statistics."""
        total_detections = len(self.detection_history) + len(self.active_detections)
        
        completed_detections = [
            result for result in self.detection_history.values()
            if result.status == DetectionStatus.COMPLETED
        ]
        
        avg_processing_time = 0
        if completed_detections:
            processing_times = [r.processing_time_seconds for r in completed_detections if r.processing_time_seconds]
            avg_processing_time = sum(processing_times) / len(processing_times) if processing_times else 0
        
        risk_distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for result in completed_detections:
            risk_distribution[result.risk_level.value] += 1
        
        return {
            "total_detections": total_detections,
            "active_detections": len(self.active_detections),
            "completed_detections": len(completed_detections),
            "average_processing_time": avg_processing_time,
            "risk_level_distribution": risk_distribution,
            "default_model_loaded": self._default_model is not None and self._default_model.is_loaded,
            "thread_pool_workers": self.thread_pool._max_workers
        }
    
    def cleanup_history(self, max_age_hours: int = 24):
        """Clean up old detection history."""
        cutoff_time = datetime.now().timestamp() - (max_age_hours * 3600)
        
        to_remove = []
        for detection_id, result in self.detection_history.items():
            if result.completed_at and result.completed_at.timestamp() < cutoff_time:
                to_remove.append(detection_id)
        
        for detection_id in to_remove:
            del self.detection_history[detection_id]
        
        logger.info(f"Cleaned up {len(to_remove)} old detection records")


# Global service instance
_default_pii_service = None

def get_pii_detection_service() -> PIIDetectionService:
    """Get or create the default PII detection service instance."""
    global _default_pii_service
    
    if _default_pii_service is None:
        _default_pii_service = PIIDetectionService()
    
    return _default_pii_service