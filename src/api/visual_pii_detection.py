"""
Visual PII Detection API Endpoints

FastAPI endpoints for visual PII detection, redaction, and compliance management
with comprehensive validation, error handling, and security features for images and documents.
"""

import logging
import io
import base64
from typing import Dict, List, Optional, Any
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query, status, UploadFile, File, Form
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, validator
from enum import Enum
import numpy as np
from PIL import Image

from ..core.services.visual_pii_detector import (
    VisualPIIDetectionService, 
    VisualPIIDetectionResult, 
    VisualDetectionStatus, 
    VisualRiskLevel,
    get_visual_pii_detection_service
)
from ..core.models.visual_models import VisualPIIType, VisualPIIEntity, BoundingBox
from ..core.processing.visual_redactor import (
    VisualRedactionEngine,
    RedactionConfig,
    VisualRedactionMethod,
    RedactionResult,
    get_visual_redaction_engine
)
from ..core.security.compliance_encryption import ComplianceStandard, DataClassification
from ..core.config.policies.base import PIIType, RedactionMethod

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/visual-pii", tags=["Visual PII Detection"])


# Request/Response Models
class BoundingBoxResponse(BaseModel):
    """Response model for bounding box."""
    x: int
    y: int
    width: int
    height: int
    x2: int
    y2: int
    area: int
    center: List[int]


class VisualPIIEntityResponse(BaseModel):
    """Response model for detected visual PII entity."""
    entity_type: str
    confidence: float
    confidence_level: str
    bounding_box: BoundingBoxResponse
    page_number: int
    image_width: int
    image_height: int
    model_name: str
    detection_metadata: Dict[str, Any]


class VisualPIIDetectionRequest(BaseModel):
    """Request model for visual PII detection."""
    model_type: str = Field("yolov8", description="Visual detection model to use")
    entity_types: Optional[List[str]] = Field(None, description="Specific entity types to detect")
    confidence_threshold: float = Field(0.5, ge=0.0, le=1.0, description="Minimum confidence threshold")
    compliance_standards: Optional[List[str]] = Field(None, description="Compliance standards to apply")
    document_id: Optional[str] = Field(None, description="Optional document identifier")
    
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
            valid_types = [t.value for t in VisualPIIType]
            invalid = [t for t in v if t not in valid_types]
            if invalid:
                raise ValueError(f"Invalid entity types: {invalid}")
        return v


class VisualPIIDetectionResponse(BaseModel):
    """Response model for visual PII detection results."""
    detection_id: str
    document_id: Optional[str]
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    processing_time_seconds: Optional[float]
    image_count: int
    total_images_processed: int
    model_used: str
    visual_entities: List[VisualPIIEntityResponse]
    entity_count: int
    unique_entity_types: List[str]
    entities_by_page: Dict[str, List[VisualPIIEntityResponse]]
    risk_level: str
    compliance_flags: List[str]
    confidence_distribution: Dict[str, int]
    encrypted: bool
    audit_logged: bool


class VisualRedactionRequest(BaseModel):
    """Request model for visual redaction."""
    detection_id: Optional[str] = Field(None, description="Use existing detection results")
    redaction_method: str = Field("blur", description="Default redaction method")
    intensity: float = Field(0.8, ge=0.0, le=1.0, description="Redaction intensity")
    padding: int = Field(5, ge=0, le=50, description="Padding around detected regions")
    entity_specific_methods: Optional[Dict[str, str]] = Field(None, description="Entity-specific redaction methods")
    preserve_aspect_ratio: bool = Field(True, description="Preserve aspect ratio during redaction")
    
    @validator('redaction_method')
    def validate_redaction_method(cls, v):
        valid_methods = [m.value for m in VisualRedactionMethod]
        if v not in valid_methods:
            raise ValueError(f"Invalid redaction method. Valid options: {valid_methods}")
        return v


class VisualRedactionResponse(BaseModel):
    """Response model for visual redaction."""
    success: bool
    detection_id: str
    redacted_entities: List[VisualPIIEntityResponse]
    redaction_metadata: Dict[str, Any]
    processing_time_seconds: float
    redacted_image_base64: Optional[str] = None
    error_message: Optional[str] = None


class VisualDetectionStatusResponse(BaseModel):
    """Response model for visual detection status."""
    detection_id: str
    status: str
    progress: Optional[float] = None
    images_processed: Optional[int] = None
    total_images: Optional[int] = None
    message: Optional[str] = None


class VisualServiceStatsResponse(BaseModel):
    """Response model for visual service statistics."""
    total_detections: int
    active_detections: int
    completed_detections: int
    average_processing_time: float
    average_entities_per_detection: float
    total_images_processed: int
    risk_level_distribution: Dict[str, int]
    default_model_loaded: bool
    thread_pool_workers: int


# Dependency injection
def get_visual_detection_service() -> VisualPIIDetectionService:
    """Get visual PII detection service instance."""
    return get_visual_pii_detection_service()


def get_redaction_engine() -> VisualRedactionEngine:
    """Get visual redaction engine instance."""
    return get_visual_redaction_engine()


# Helper functions
async def process_uploaded_images(files: List[UploadFile]) -> List[Image.Image]:
    """Process uploaded image files."""
    images = []
    
    for file in files:
        # Validate file type
        if not file.content_type.startswith('image/'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File {file.filename} is not an image"
            )
        
        # Read and convert to PIL Image
        try:
            content = await file.read()
            image = Image.open(io.BytesIO(content))
            images.append(image.convert('RGB'))
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to process image {file.filename}: {str(e)}"
            )
    
    return images


def convert_entities_to_response(entities: List[VisualPIIEntity]) -> List[VisualPIIEntityResponse]:
    """Convert VisualPIIEntity objects to response format."""
    response_entities = []
    
    for entity in entities:
        bbox_response = BoundingBoxResponse(
            x=entity.bounding_box.x,
            y=entity.bounding_box.y,
            width=entity.bounding_box.width,
            height=entity.bounding_box.height,
            x2=entity.bounding_box.x2,
            y2=entity.bounding_box.y2,
            area=entity.bounding_box.area,
            center=list(entity.bounding_box.center)
        )
        
        entity_response = VisualPIIEntityResponse(
            entity_type=entity.entity_type.value,
            confidence=entity.confidence,
            confidence_level=entity.confidence_level.value,
            bounding_box=bbox_response,
            page_number=entity.page_number,
            image_width=entity.image_width,
            image_height=entity.image_height,
            model_name=entity.model_name,
            detection_metadata=entity.detection_metadata or {}
        )
        
        response_entities.append(entity_response)
    
    return response_entities


# API Endpoints

@router.post("/detect", response_model=VisualPIIDetectionResponse, status_code=status.HTTP_200_OK)
async def detect_visual_pii(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(..., description="Image files to analyze"),
    model_type: str = Form("yolov8", description="Visual detection model to use"),
    entity_types: Optional[str] = Form(None, description="Comma-separated list of entity types"),
    confidence_threshold: float = Form(0.5, description="Minimum confidence threshold"),
    compliance_standards: Optional[str] = Form(None, description="Comma-separated compliance standards"),
    document_id: Optional[str] = Form(None, description="Optional document identifier"),
    service: VisualPIIDetectionService = Depends(get_visual_detection_service)
):
    """
    Detect visual PII entities in uploaded images.
    
    This endpoint analyzes uploaded images for visual PII like faces, signatures,
    stamps, and other sensitive visual elements using advanced computer vision models.
    """
    try:
        # Validate uploaded files
        if not files or len(files) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No image files provided"
            )
        
        # Process uploaded images
        images = await process_uploaded_images(files)
        
        # Parse entity types
        entity_type_list = None
        if entity_types:
            try:
                entity_type_list = [VisualPIIType(et.strip()) for et in entity_types.split(',')]
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid entity type: {e}"
                )
        
        # Parse compliance standards
        compliance_standards_list = None
        if compliance_standards:
            try:
                compliance_standards_list = [ComplianceStandard(cs.strip()) for cs in compliance_standards.split(',')]
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid compliance standard: {e}"
                )
        
        # Perform detection
        result = await service.detect_visual_pii_async(
            images=images,
            document_id=document_id,
            model_type=model_type,
            entity_types=entity_type_list,
            confidence_threshold=confidence_threshold,
            compliance_standards=compliance_standards_list
        )
        
        # Convert result to response format
        entities_response = convert_entities_to_response(result.visual_entities)
        
        # Convert entities by page
        entities_by_page_response = {}
        for page, page_entities in result.entities_by_page.items():
            entities_by_page_response[str(page)] = convert_entities_to_response(page_entities)
        
        response = VisualPIIDetectionResponse(
            detection_id=result.detection_id,
            document_id=result.document_id,
            status=result.status.value,
            started_at=result.started_at,
            completed_at=result.completed_at,
            processing_time_seconds=result.processing_time_seconds,
            image_count=result.image_count,
            total_images_processed=result.total_images_processed,
            model_used=result.model_used,
            visual_entities=entities_response,
            entity_count=result.entity_count,
            unique_entity_types=result.unique_entity_types,
            entities_by_page=entities_by_page_response,
            risk_level=result.risk_level.value,
            compliance_flags=result.compliance_flags,
            confidence_distribution=result.confidence_distribution,
            encrypted=result.encrypted,
            audit_logged=result.audit_logged
        )
        
        logger.info(f"Visual PII detection completed: {result.detection_id}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Visual PII detection failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Visual PII detection failed: {str(e)}"
        )


@router.post("/redact", response_model=VisualRedactionResponse)
async def redact_visual_pii(
    files: List[UploadFile] = File(..., description="Image files to redact"),
    detection_id: Optional[str] = Form(None, description="Existing detection ID to use"),
    redaction_method: str = Form("blur", description="Default redaction method"),
    intensity: float = Form(0.8, description="Redaction intensity"),
    padding: int = Form(5, description="Padding around detected regions"),
    return_image: bool = Form(True, description="Return redacted image as base64"),
    service: VisualPIIDetectionService = Depends(get_visual_detection_service),
    redaction_engine: VisualRedactionEngine = Depends(get_redaction_engine)
):
    """
    Redact visual PII in uploaded images.
    
    This endpoint can either use existing detection results or perform new detection
    and redaction in one step.
    """
    try:
        # Process uploaded images
        images = await process_uploaded_images(files)
        
        if len(images) != 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Redaction currently supports only one image at a time"
            )
        
        image = images[0]
        
        # Get detection results
        if detection_id:
            # Use existing detection results
            detection_result = service.get_detection_result(detection_id)
            if not detection_result:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Detection result not found: {detection_id}"
                )
            
            if detection_result.status != VisualDetectionStatus.COMPLETED:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Detection not completed. Status: {detection_result.status.value}"
                )
            
            entities = detection_result.visual_entities
        else:
            # Perform new detection
            detection_result = await service.detect_visual_pii_async(
                images=[image],
                model_type="yolov8",
                confidence_threshold=0.5
            )
            
            detection_id = detection_result.detection_id
            entities = detection_result.visual_entities
        
        # Create redaction config
        try:
            redaction_method_enum = VisualRedactionMethod(redaction_method)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid redaction method: {redaction_method}"
            )
        
        config = RedactionConfig(
            method=redaction_method_enum,
            intensity=intensity,
            padding=padding
        )
        
        # Perform redaction
        redaction_result = redaction_engine.redact_image(image, entities, config)
        
        # Prepare response
        redacted_entities_response = convert_entities_to_response(redaction_result.redacted_entities)
        
        redacted_image_base64 = None
        if return_image and redaction_result.success:
            redacted_image_base64 = redaction_engine.get_redacted_image_as_base64(redaction_result)
        
        response = VisualRedactionResponse(
            success=redaction_result.success,
            detection_id=detection_id,
            redacted_entities=redacted_entities_response,
            redaction_metadata=redaction_result.redaction_metadata,
            processing_time_seconds=redaction_result.processing_time_seconds,
            redacted_image_base64=redacted_image_base64,
            error_message=redaction_result.error_message
        )
        
        logger.info(f"Visual redaction completed: {detection_id}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Visual redaction failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Visual redaction failed: {str(e)}"
        )


@router.get("/detection/{detection_id}", response_model=VisualPIIDetectionResponse)
def get_visual_detection_result(
    detection_id: str,
    service: VisualPIIDetectionService = Depends(get_visual_detection_service)
):
    """Get visual detection result by ID."""
    try:
        result = service.get_detection_result(detection_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Visual detection result not found: {detection_id}"
            )
        
        # Convert result to response format
        entities_response = convert_entities_to_response(result.visual_entities)
        
        entities_by_page_response = {}
        for page, page_entities in result.entities_by_page.items():
            entities_by_page_response[str(page)] = convert_entities_to_response(page_entities)
        
        return VisualPIIDetectionResponse(
            detection_id=result.detection_id,
            document_id=result.document_id,
            status=result.status.value,
            started_at=result.started_at,
            completed_at=result.completed_at,
            processing_time_seconds=result.processing_time_seconds,
            image_count=result.image_count,
            total_images_processed=result.total_images_processed,
            model_used=result.model_used,
            visual_entities=entities_response,
            entity_count=result.entity_count,
            unique_entity_types=result.unique_entity_types,
            entities_by_page=entities_by_page_response,
            risk_level=result.risk_level.value,
            compliance_flags=result.compliance_flags,
            confidence_distribution=result.confidence_distribution,
            encrypted=result.encrypted,
            audit_logged=result.audit_logged
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get visual detection result {detection_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve visual detection result: {str(e)}"
        )


@router.get("/detection/{detection_id}/status", response_model=VisualDetectionStatusResponse)
def get_visual_detection_status(
    detection_id: str,
    service: VisualPIIDetectionService = Depends(get_visual_detection_service)
):
    """Get visual detection status by ID."""
    try:
        result = service.get_detection_result(detection_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Visual detection not found: {detection_id}"
            )
        
        progress = None
        if result.status == VisualDetectionStatus.IN_PROGRESS and result.image_count > 0:
            progress = result.total_images_processed / result.image_count
        elif result.status == VisualDetectionStatus.COMPLETED:
            progress = 1.0
        
        return VisualDetectionStatusResponse(
            detection_id=detection_id,
            status=result.status.value,
            progress=progress,
            images_processed=result.total_images_processed,
            total_images=result.image_count,
            message=f"Visual detection {result.status.value}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get visual detection status {detection_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve visual detection status: {str(e)}"
        )


@router.delete("/detection/{detection_id}")
def cancel_visual_detection(
    detection_id: str,
    service: VisualPIIDetectionService = Depends(get_visual_detection_service)
):
    """Cancel an active visual detection operation."""
    try:
        success = service.cancel_detection(detection_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Active visual detection not found: {detection_id}"
            )
        
        return {"message": f"Visual detection {detection_id} cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel visual detection {detection_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cancel visual detection: {str(e)}"
        )


@router.get("/stats", response_model=VisualServiceStatsResponse)
def get_visual_service_statistics(
    service: VisualPIIDetectionService = Depends(get_visual_detection_service)
):
    """Get visual PII detection service statistics."""
    try:
        stats = service.get_service_statistics()
        
        return VisualServiceStatsResponse(
            total_detections=stats["total_detections"],
            active_detections=stats["active_detections"],
            completed_detections=stats["completed_detections"],
            average_processing_time=stats["average_processing_time"],
            average_entities_per_detection=stats["average_entities_per_detection"],
            total_images_processed=stats["total_images_processed"],
            risk_level_distribution=stats["risk_level_distribution"],
            default_model_loaded=stats["default_model_loaded"],
            thread_pool_workers=stats["thread_pool_workers"]
        )
        
    except Exception as e:
        logger.error(f"Failed to get visual service statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve visual service statistics: {str(e)}"
        )


@router.post("/cleanup")
def cleanup_visual_detection_history(
    max_age_hours: int = Query(24, ge=1, le=168, description="Maximum age in hours"),
    service: VisualPIIDetectionService = Depends(get_visual_detection_service)
):
    """Clean up old visual detection history."""
    try:
        service.cleanup_history(max_age_hours)
        return {"message": f"Cleaned up visual detection history older than {max_age_hours} hours"}
        
    except Exception as e:
        logger.error(f"Failed to cleanup visual detection history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Visual detection cleanup failed: {str(e)}"
        )


@router.get("/health")
def visual_health_check():
    """Health check endpoint for visual PII detection service."""
    try:
        service = get_visual_pii_detection_service()
        stats = service.get_service_statistics()
        
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "service": "visual_pii_detection",
            "version": "1.0.0",
            "statistics": {
                "total_detections": stats["total_detections"],
                "active_detections": stats["active_detections"],
                "model_loaded": stats["default_model_loaded"]
            }
        }
        
        return JSONResponse(content=health_status, status_code=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Visual health check failed: {e}")
        return JSONResponse(
            content={
                "status": "unhealthy",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            },
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE
        )


# Supported entity types and redaction methods endpoints
@router.get("/supported/entities")
def get_supported_visual_entities():
    """Get list of supported visual PII entity types."""
    entities = [
        {
            "type": pii_type.value,
            "description": pii_type.name.replace("_", " ").title()
        }
        for pii_type in VisualPIIType
    ]
    
    return {"supported_entities": entities}


@router.get("/supported/redaction-methods")
def get_supported_visual_redaction_methods():
    """Get list of supported visual redaction methods."""
    methods = [
        {
            "method": method.value,
            "description": method.name.replace("_", " ").title()
        }
        for method in VisualRedactionMethod
    ]
    
    return {"supported_methods": methods}