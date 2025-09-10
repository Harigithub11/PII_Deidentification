"""
PII Detection API Endpoints

FastAPI endpoints for PII detection, anonymization, and compliance management
with comprehensive validation, error handling, and security features.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from enum import Enum

from ..core.services.pii_detector import (
    PIIDetectionService, 
    PIIDetectionResult, 
    DetectionStatus, 
    RiskLevel,
    get_pii_detection_service
)
from ..core.security.compliance_encryption import (
    ComplianceStandard, 
    DataClassification,
    ComplianceMetadata,
    compliance_encryption
)
from ..core.config.policies.base import PIIType, RedactionMethod
from ..core.models.ner_models import EntityConfidence

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/pii", tags=["PII Detection"])


# Request/Response Models
class PIIDetectionRequest(BaseModel):
    """Request model for PII detection."""
    text: str = Field(..., min_length=1, max_length=100000, description="Text to analyze for PII")
    document_id: Optional[str] = Field(None, description="Optional document identifier")
    language: str = Field("en", description="Language code for analysis")
    model_type: str = Field("presidio", description="NER model to use")
    entity_types: Optional[List[str]] = Field(None, description="Specific entity types to detect")
    confidence_threshold: float = Field(0.5, ge=0.0, le=1.0, description="Minimum confidence threshold")
    compliance_standards: Optional[List[str]] = Field(None, description="Compliance standards to apply")
    
    @validator('compliance_standards')
    def validate_compliance_standards(cls, v):
        if v is not None:
            valid_standards = [s.value for s in ComplianceStandard]
            invalid = [s for s in v if s not in valid_standards]
            if invalid:
                raise ValueError(f"Invalid compliance standards: {invalid}")
        return v
    
    @validator('entity_types')
    def validate_entity_types(cls, v):
        if v is not None:
            valid_types = [t.value for t in PIIType]
            invalid = [t for t in v if t not in valid_types]
            if invalid:
                raise ValueError(f"Invalid entity types: {invalid}")
        return v


class PIIEntityResponse(BaseModel):
    """Response model for detected PII entity."""
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float
    confidence_level: str
    recognizer_name: str
    language: str
    metadata: Dict[str, Any]


class PIIDetectionResponse(BaseModel):
    """Response model for PII detection results."""
    detection_id: str
    document_id: Optional[str]
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    processing_time_seconds: Optional[float]
    text_length: int
    language: str
    model_used: str
    entities: List[PIIEntityResponse]
    entity_count: int
    unique_entity_types: List[str]
    risk_level: str
    compliance_flags: List[str]
    confidence_distribution: Dict[str, int]
    encrypted: bool
    audit_logged: bool


class AnonymizationRequest(BaseModel):
    """Request model for text anonymization."""
    text: str = Field(..., min_length=1, max_length=100000)
    detection_id: Optional[str] = Field(None, description="Use existing detection results")
    anonymization_config: Optional[Dict[str, Dict[str, Any]]] = Field(None, description="Custom anonymization config")
    redaction_method: str = Field("replace", description="Default redaction method")
    
    @validator('redaction_method')
    def validate_redaction_method(cls, v):
        valid_methods = [m.value for m in RedactionMethod]
        if v not in valid_methods:
            raise ValueError(f"Invalid redaction method. Valid options: {valid_methods}")
        return v


class AnonymizationResponse(BaseModel):
    """Response model for text anonymization."""
    anonymized_text: str
    detection_id: str
    entities_anonymized: int
    redaction_method: str
    processing_time_seconds: float


class DetectionStatusResponse(BaseModel):
    """Response model for detection status."""
    detection_id: str
    status: str
    progress: Optional[float] = None
    message: Optional[str] = None


class ServiceStatsResponse(BaseModel):
    """Response model for service statistics."""
    total_detections: int
    active_detections: int
    completed_detections: int
    average_processing_time: float
    risk_level_distribution: Dict[str, int]
    default_model_loaded: bool
    thread_pool_workers: int


# Dependency injection
def get_detection_service() -> PIIDetectionService:
    """Get PII detection service instance."""
    return get_pii_detection_service()


# API Endpoints

@router.post("/detect", response_model=PIIDetectionResponse, status_code=status.HTTP_200_OK)
async def detect_pii(
    request: PIIDetectionRequest,
    background_tasks: BackgroundTasks,
    service: PIIDetectionService = Depends(get_detection_service)
):
    """
    Detect PII entities in text.
    
    This endpoint analyzes text for personally identifiable information using
    advanced NER models and returns detailed detection results with compliance
    analysis and risk assessment.
    """
    try:
        # Convert compliance standards
        compliance_standards = None
        if request.compliance_standards:
            compliance_standards = [
                ComplianceStandard(standard) 
                for standard in request.compliance_standards
            ]
        
        # Perform detection
        result = await service.detect_pii_async(
            text=request.text,
            document_id=request.document_id,
            language=request.language,
            model_type=request.model_type,
            entity_types=request.entity_types,
            confidence_threshold=request.confidence_threshold,
            compliance_standards=compliance_standards
        )
        
        # Convert result to response format
        entities = [
            PIIEntityResponse(
                entity_type=entity.entity_type,
                text=entity.text,
                start=entity.start,
                end=entity.end,
                confidence=entity.confidence,
                confidence_level=entity.confidence_level.value,
                recognizer_name=entity.recognizer_name,
                language=entity.language,
                metadata=entity.metadata or {}
            )
            for entity in result.entities
        ]
        
        response = PIIDetectionResponse(
            detection_id=result.detection_id,
            document_id=result.document_id,
            status=result.status.value,
            started_at=result.started_at,
            completed_at=result.completed_at,
            processing_time_seconds=result.processing_time_seconds,
            text_length=result.text_length,
            language=result.language,
            model_used=result.model_used,
            entities=entities,
            entity_count=result.entity_count,
            unique_entity_types=result.unique_entity_types,
            risk_level=result.risk_level.value,
            compliance_flags=result.compliance_flags,
            confidence_distribution=result.confidence_distribution,
            encrypted=result.encrypted,
            audit_logged=result.audit_logged
        )
        
        logger.info(f"PII detection completed: {result.detection_id}")
        return response
        
    except Exception as e:
        logger.error(f"PII detection failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PII detection failed: {str(e)}"
        )


@router.post("/detect/sync", response_model=PIIDetectionResponse)
def detect_pii_sync(
    request: PIIDetectionRequest,
    service: PIIDetectionService = Depends(get_detection_service)
):
    """
    Detect PII entities in text (synchronous version).
    
    Synchronous version of PII detection for smaller texts or when
    immediate results are required.
    """
    try:
        # Perform synchronous detection
        result = service.detect_pii_sync(
            text=request.text,
            document_id=request.document_id,
            language=request.language,
            model_type=request.model_type,
            entity_types=request.entity_types,
            confidence_threshold=request.confidence_threshold
        )
        
        # Convert result to response format
        entities = [
            PIIEntityResponse(
                entity_type=entity.entity_type,
                text=entity.text,
                start=entity.start,
                end=entity.end,
                confidence=entity.confidence,
                confidence_level=entity.confidence_level.value,
                recognizer_name=entity.recognizer_name,
                language=entity.language,
                metadata=entity.metadata or {}
            )
            for entity in result.entities
        ]
        
        response = PIIDetectionResponse(
            detection_id=result.detection_id,
            document_id=result.document_id,
            status=result.status.value,
            started_at=result.started_at,
            completed_at=result.completed_at,
            processing_time_seconds=result.processing_time_seconds,
            text_length=result.text_length,
            language=result.language,
            model_used=result.model_used,
            entities=entities,
            entity_count=result.entity_count,
            unique_entity_types=result.unique_entity_types,
            risk_level=result.risk_level.value,
            compliance_flags=result.compliance_flags,
            confidence_distribution=result.confidence_distribution,
            encrypted=result.encrypted,
            audit_logged=result.audit_logged
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Sync PII detection failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PII detection failed: {str(e)}"
        )


@router.post("/anonymize", response_model=AnonymizationResponse)
async def anonymize_text(
    request: AnonymizationRequest,
    service: PIIDetectionService = Depends(get_detection_service)
):
    """
    Anonymize text by replacing detected PII entities.
    
    This endpoint can either use existing detection results (if detection_id is provided)
    or perform new detection and anonymization in one step.
    """
    try:
        start_time = datetime.now()
        
        # Get detection results
        if request.detection_id:
            # Use existing detection results
            detection_result = service.get_detection_result(request.detection_id)
            if not detection_result:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Detection result not found: {request.detection_id}"
                )
            
            if detection_result.status != DetectionStatus.COMPLETED:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Detection not completed. Status: {detection_result.status.value}"
                )
            
            detection_id = request.detection_id
            entities = detection_result.entities
            text = request.text
        else:
            # Perform new detection
            detection_result = await service.detect_pii_async(
                text=request.text,
                language="en",
                model_type="presidio"
            )
            
            detection_id = detection_result.detection_id
            entities = detection_result.entities
            text = request.text
        
        # Get NER model for anonymization
        from ..core.models.ner_models import get_default_ner_model
        model = get_default_ner_model()
        
        if not model.is_loaded:
            if not model.load():
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="NER model unavailable"
                )
        
        # Anonymize text
        anonymized_text = model.anonymize_text(text, entities, request.anonymization_config)
        
        processing_time = (datetime.now() - start_time).total_seconds()
        
        response = AnonymizationResponse(
            anonymized_text=anonymized_text,
            detection_id=detection_id,
            entities_anonymized=len(entities),
            redaction_method=request.redaction_method,
            processing_time_seconds=processing_time
        )
        
        logger.info(f"Text anonymization completed: {detection_id}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Text anonymization failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Anonymization failed: {str(e)}"
        )


@router.get("/detection/{detection_id}", response_model=PIIDetectionResponse)
def get_detection_result(
    detection_id: str,
    service: PIIDetectionService = Depends(get_detection_service)
):
    """Get detection result by ID."""
    try:
        result = service.get_detection_result(detection_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Detection result not found: {detection_id}"
            )
        
        # Convert result to response format
        entities = [
            PIIEntityResponse(
                entity_type=entity.entity_type,
                text=entity.text,
                start=entity.start,
                end=entity.end,
                confidence=entity.confidence,
                confidence_level=entity.confidence_level.value,
                recognizer_name=entity.recognizer_name,
                language=entity.language,
                metadata=entity.metadata or {}
            )
            for entity in result.entities
        ]
        
        return PIIDetectionResponse(
            detection_id=result.detection_id,
            document_id=result.document_id,
            status=result.status.value,
            started_at=result.started_at,
            completed_at=result.completed_at,
            processing_time_seconds=result.processing_time_seconds,
            text_length=result.text_length,
            language=result.language,
            model_used=result.model_used,
            entities=entities,
            entity_count=result.entity_count,
            unique_entity_types=result.unique_entity_types,
            risk_level=result.risk_level.value,
            compliance_flags=result.compliance_flags,
            confidence_distribution=result.confidence_distribution,
            encrypted=result.encrypted,
            audit_logged=result.audit_logged
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get detection result {detection_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve detection result: {str(e)}"
        )


@router.get("/detection/{detection_id}/status", response_model=DetectionStatusResponse)
def get_detection_status(
    detection_id: str,
    service: PIIDetectionService = Depends(get_detection_service)
):
    """Get detection status by ID."""
    try:
        status_value = service.get_detection_status(detection_id)
        
        if not status_value:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Detection not found: {detection_id}"
            )
        
        return DetectionStatusResponse(
            detection_id=detection_id,
            status=status_value.value,
            progress=1.0 if status_value == DetectionStatus.COMPLETED else None,
            message=f"Detection {status_value.value}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get detection status {detection_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve detection status: {str(e)}"
        )


@router.delete("/detection/{detection_id}")
def cancel_detection(
    detection_id: str,
    service: PIIDetectionService = Depends(get_detection_service)
):
    """Cancel an active detection operation."""
    try:
        success = service.cancel_detection(detection_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Active detection not found: {detection_id}"
            )
        
        return {"message": f"Detection {detection_id} cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel detection {detection_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cancel detection: {str(e)}"
        )


@router.get("/stats", response_model=ServiceStatsResponse)
def get_service_statistics(
    service: PIIDetectionService = Depends(get_detection_service)
):
    """Get PII detection service statistics."""
    try:
        stats = service.get_service_statistics()
        
        return ServiceStatsResponse(
            total_detections=stats["total_detections"],
            active_detections=stats["active_detections"],
            completed_detections=stats["completed_detections"],
            average_processing_time=stats["average_processing_time"],
            risk_level_distribution=stats["risk_level_distribution"],
            default_model_loaded=stats["default_model_loaded"],
            thread_pool_workers=stats["thread_pool_workers"]
        )
        
    except Exception as e:
        logger.error(f"Failed to get service statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve statistics: {str(e)}"
        )


@router.post("/cleanup")
def cleanup_detection_history(
    max_age_hours: int = Query(24, ge=1, le=168, description="Maximum age in hours"),
    service: PIIDetectionService = Depends(get_detection_service)
):
    """Clean up old detection history."""
    try:
        service.cleanup_history(max_age_hours)
        return {"message": f"Cleaned up detection history older than {max_age_hours} hours"}
        
    except Exception as e:
        logger.error(f"Failed to cleanup detection history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cleanup failed: {str(e)}"
        )


@router.get("/health")
def health_check():
    """Health check endpoint for PII detection service."""
    try:
        service = get_pii_detection_service()
        stats = service.get_service_statistics()
        
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "service": "pii_detection",
            "version": "1.0.0",
            "statistics": {
                "total_detections": stats["total_detections"],
                "active_detections": stats["active_detections"],
                "model_loaded": stats["default_model_loaded"]
            }
        }
        
        return JSONResponse(content=health_status, status_code=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            content={
                "status": "unhealthy",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            },
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE
        )


# Supported entity types and standards endpoints
@router.get("/supported/entities")
def get_supported_entities():
    """Get list of supported PII entity types."""
    entities = [
        {
            "type": pii_type.value,
            "description": pii_type.name.replace("_", " ").title()
        }
        for pii_type in PIIType
    ]
    
    return {"supported_entities": entities}


@router.get("/supported/compliance-standards")
def get_supported_compliance_standards():
    """Get list of supported compliance standards."""
    standards = [
        {
            "standard": std.value,
            "description": std.name.replace("_", " ").title()
        }
        for std in ComplianceStandard
    ]
    
    return {"supported_standards": standards}


@router.get("/supported/redaction-methods")
def get_supported_redaction_methods():
    """Get list of supported redaction methods."""
    methods = [
        {
            "method": method.value,
            "description": method.name.replace("_", " ").title()
        }
        for method in RedactionMethod
    ]
    
    return {"supported_methods": methods}