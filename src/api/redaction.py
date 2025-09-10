"""
Comprehensive Redaction API Endpoints

This module provides REST API endpoints for all redaction functionalities including
unified redaction, policy-driven redaction, pseudonymization, and generalization.
"""

import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import base64
import io

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, validator
from PIL import Image
import numpy as np

from ..core.config.policies.base import PIIType, RedactionMethod
from ..core.config.policy_models import PolicyContext
from ..core.models.ner_models import PIIEntity
from ..core.models.visual_models import VisualPIIEntity, BoundingBox
from ..core.services.redaction_engine import (
    get_redaction_engine, RedactionRequest, RedactionType, 
    RedactionParameters, RedactionIntensity
)
from ..core.services.policy_redaction_service import (
    get_policy_redaction_service, PolicyRedactionRequest
)
from ..core.services.pseudonymization_service import (
    get_pseudonymization_service, PseudonymizationConfig, 
    GeneralizationConfig, PseudonymizationMethod, GeneralizationLevel
)
from ..core.security.dependencies import (
    get_current_active_user, require_permissions
)
from ..core.security.compliance_encryption import ComplianceStandard, DataClassification

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/redaction", tags=["redaction"])


# Request/Response Models

class RedactionMethodInfo(BaseModel):
    """Information about a redaction method."""
    method: str
    name: str
    description: str
    supported_types: List[str]
    parameters: Dict[str, Any] = {}


class PIIEntityRequest(BaseModel):
    """Request model for PII entity."""
    text: str
    entity_type: PIIType
    start: int
    end: int
    confidence: float = Field(ge=0.0, le=1.0)


class VisualPIIEntityRequest(BaseModel):
    """Request model for visual PII entity."""
    entity_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    bounding_box: Dict[str, int]  # {x, y, width, height}


class TextRedactionRequest(BaseModel):
    """Request model for text redaction."""
    text: str
    entities: List[PIIEntityRequest]
    method: RedactionMethod = RedactionMethod.REDACTED_LABEL
    intensity: RedactionIntensity = RedactionIntensity.MEDIUM
    preserve_format: bool = True
    preserve_length: bool = False
    custom_placeholder: Optional[str] = None
    pseudonym_seed: Optional[str] = None


class VisualRedactionRequest(BaseModel):
    """Request model for visual redaction."""
    entities: List[VisualPIIEntityRequest]
    method: RedactionMethod = RedactionMethod.BLACKOUT
    intensity: RedactionIntensity = RedactionIntensity.MEDIUM
    color: List[int] = Field(default=[0, 0, 0], min_items=3, max_items=3)
    padding: int = Field(default=5, ge=0)


class PolicyRedactionRequest(BaseModel):
    """Request model for policy-driven redaction."""
    content: str
    entities: List[PIIEntityRequest]
    redaction_type: RedactionType = RedactionType.TEXT
    context: Dict[str, Any]  # Will be converted to PolicyContext
    policy_names: Optional[List[str]] = None
    override_method: Optional[RedactionMethod] = None
    
    @validator('context')
    def validate_context(cls, v):
        required_fields = ['user_id', 'document_type', 'compliance_standard']
        for field in required_fields:
            if field not in v:
                raise ValueError(f"Context must include {field}")
        return v


class PseudonymizationRequest(BaseModel):
    """Request model for pseudonymization."""
    values: List[Dict[str, Any]]  # [{"value": str, "pii_type": PIIType}]
    method: PseudonymizationMethod = PseudonymizationMethod.CONSISTENT_HASH
    preserve_format: bool = True
    preserve_length: bool = True
    consistency_key: Optional[str] = None


class GeneralizationRequest(BaseModel):
    """Request model for generalization."""
    values: List[Dict[str, Any]]  # [{"value": str, "pii_type": PIIType}]
    level: GeneralizationLevel = GeneralizationLevel.MODERATE
    preserve_utility: bool = True
    custom_categories: Optional[Dict[str, List[str]]] = None


class RedactionResponse(BaseModel):
    """Response model for redaction operations."""
    success: bool
    redacted_content: Optional[Any] = None
    original_content: Optional[Any] = None
    entities_processed: int = 0
    method_used: Optional[str] = None
    processing_time_seconds: float = 0.0
    quality_score: float = 1.0
    metadata: Dict[str, Any] = {}
    error_message: Optional[str] = None


# API Endpoints

@router.get("/methods", response_model=List[RedactionMethodInfo])
async def get_redaction_methods(
    redaction_type: Optional[RedactionType] = None,
    current_user = Depends(get_current_active_user)
):
    """Get available redaction methods."""
    try:
        redaction_engine = get_redaction_engine()
        
        if redaction_type:
            supported_methods = redaction_engine.get_supported_methods(redaction_type)
        else:
            # Get all methods
            text_methods = redaction_engine.get_supported_methods(RedactionType.TEXT)
            visual_methods = redaction_engine.get_supported_methods(RedactionType.VISUAL)
            supported_methods = list(set(text_methods + visual_methods))
        
        method_info = []
        for method in supported_methods:
            info = RedactionMethodInfo(
                method=method.value,
                name=method.name.replace("_", " ").title(),
                description=_get_method_description(method),
                supported_types=_get_method_types(method),
                parameters=_get_method_parameters(method)
            )
            method_info.append(info)
        
        return method_info
    
    except Exception as e:
        logger.error(f"Failed to get redaction methods: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/text", response_model=RedactionResponse)
async def redact_text(
    request: TextRedactionRequest,
    current_user = Depends(get_current_active_user)
):
    """Redact PII entities in text content."""
    try:
        # Convert request entities to PIIEntity objects
        entities = []
        for entity_req in request.entities:
            entity = PIIEntity(
                text=entity_req.text,
                entity_type=entity_req.entity_type,
                start=entity_req.start,
                end=entity_req.end,
                confidence=entity_req.confidence
            )
            entities.append(entity)
        
        # Create redaction parameters
        parameters = RedactionParameters(
            method=request.method,
            intensity=request.intensity,
            preserve_format=request.preserve_format,
            preserve_length=request.preserve_length,
            custom_placeholder=request.custom_placeholder,
            pseudonym_seed=request.pseudonym_seed
        )
        
        # Create redaction request
        redaction_engine = get_redaction_engine()
        redaction_request = RedactionRequest(
            redaction_type=RedactionType.TEXT,
            content=request.text,
            entities=entities,
            parameters=parameters
        )
        
        # Execute redaction
        result = redaction_engine.redact(redaction_request)
        
        return RedactionResponse(
            success=result.success,
            redacted_content=result.redacted_content,
            original_content=result.original_content,
            entities_processed=len(result.entities_redacted),
            method_used=result.method_used.value if result.method_used else None,
            processing_time_seconds=result.processing_time_seconds,
            quality_score=result.quality_score,
            metadata=result.metadata,
            error_message=result.error_message
        )
    
    except Exception as e:
        logger.error(f"Text redaction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/visual")
async def redact_visual(
    image: UploadFile = File(...),
    entities: str = Form(...),  # JSON string of VisualPIIEntityRequest list
    method: RedactionMethod = Form(RedactionMethod.BLACKOUT),
    intensity: RedactionIntensity = Form(RedactionIntensity.MEDIUM),
    color_r: int = Form(0),
    color_g: int = Form(0),
    color_b: int = Form(0),
    padding: int = Form(5),
    current_user = Depends(get_current_active_user)
):
    """Redact visual PII in image content."""
    try:
        import json
        
        # Parse entities from JSON string
        entities_data = json.loads(entities)
        visual_entities = []
        
        for entity_data in entities_data:
            bbox_data = entity_data["bounding_box"]
            bbox = BoundingBox(
                x=bbox_data["x"],
                y=bbox_data["y"],
                width=bbox_data["width"],
                height=bbox_data["height"]
            )
            
            entity = VisualPIIEntity(
                entity_type=entity_data["entity_type"],
                confidence=entity_data["confidence"],
                bounding_box=bbox
            )
            visual_entities.append(entity)
        
        # Load image
        image_content = await image.read()
        pil_image = Image.open(io.BytesIO(image_content))
        image_array = np.array(pil_image)
        
        # Create redaction parameters
        parameters = RedactionParameters(
            method=method,
            intensity=intensity,
            color=(color_r, color_g, color_b)
        )
        
        # Create redaction request
        redaction_engine = get_redaction_engine()
        redaction_request = RedactionRequest(
            redaction_type=RedactionType.VISUAL,
            content=image_array,
            entities=visual_entities,
            parameters=parameters
        )
        
        # Execute redaction
        result = redaction_engine.redact(redaction_request)
        
        if not result.success:
            raise HTTPException(status_code=500, detail=result.error_message)
        
        # Convert result back to image
        redacted_image = Image.fromarray(result.redacted_content)
        
        # Return as streaming response
        img_buffer = io.BytesIO()
        redacted_image.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        return StreamingResponse(
            io.BytesIO(img_buffer.getvalue()), 
            media_type="image/png",
            headers={
                "X-Processing-Time": str(result.processing_time_seconds),
                "X-Entities-Processed": str(len(result.entities_redacted)),
                "X-Quality-Score": str(result.quality_score)
            }
        )
    
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid entities JSON")
    except Exception as e:
        logger.error(f"Visual redaction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/policy-driven", response_model=Dict[str, Any])
async def redact_with_policy(
    request: PolicyRedactionRequest,
    current_user = Depends(get_current_active_user)
):
    """Perform policy-driven redaction."""
    try:
        # Convert request entities to PIIEntity objects
        entities = []
        for entity_req in request.entities:
            entity = PIIEntity(
                text=entity_req.text,
                entity_type=entity_req.entity_type,
                start=entity_req.start,
                end=entity_req.end,
                confidence=entity_req.confidence
            )
            entities.append(entity)
        
        # Create policy context
        context_data = request.context
        policy_context = PolicyContext(
            user_id=context_data.get("user_id"),
            document_type=context_data.get("document_type"),
            compliance_standard=context_data.get("compliance_standard"),
            processing_purpose=context_data.get("processing_purpose", "redaction"),
            data_classification=context_data.get("data_classification", DataClassification.INTERNAL.value),
            geographic_location=context_data.get("geographic_location"),
            metadata=context_data.get("metadata", {})
        )
        
        # Create policy redaction request
        service = get_policy_redaction_service()
        policy_request = PolicyRedactionRequest(
            request_id=f"api_{datetime.utcnow().timestamp()}",
            content=request.content,
            entities=entities,
            context=policy_context,
            redaction_type=request.redaction_type,
            policy_names=request.policy_names,
            override_method=request.override_method
        )
        
        # Execute policy-driven redaction
        result = await service.redact_with_policy_async(policy_request)
        
        return {
            "success": result.success,
            "redacted_content": result.redacted_content,
            "policy_decisions": [
                {
                    "decision_type": d.decision_type.value,
                    "pii_type": d.pii_type.value,
                    "confidence": d.confidence,
                    "applied_policy": d.applied_policy,
                    "redaction_method": d.redaction_method.value if d.redaction_method else None
                }
                for d in result.policy_decisions
            ],
            "violations": [
                {
                    "type": v.violation_type.value,
                    "policy": v.policy_name,
                    "message": v.message
                }
                for v in result.policy_violations
            ],
            "processing_time_seconds": result.processing_time_seconds,
            "metadata": result.metadata,
            "error_message": result.error_message
        }
    
    except Exception as e:
        logger.error(f"Policy-driven redaction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pseudonymize", response_model=Dict[str, Any])
async def pseudonymize_data(
    request: PseudonymizationRequest,
    current_user = Depends(get_current_active_user)
):
    """Pseudonymize PII values."""
    try:
        service = get_pseudonymization_service()
        
        # Create configuration
        config = PseudonymizationConfig(
            method=request.method,
            preserve_format=request.preserve_format,
            preserve_length=request.preserve_length,
            consistency_key=request.consistency_key
        )
        
        # Process each value
        results = []
        for value_data in request.values:
            pii_type = PIIType(value_data["pii_type"])
            value = value_data["value"]
            
            result = service.pseudonymize(value, pii_type, config)
            results.append({
                "original_value": result.original_value,
                "pseudonymized_value": result.anonymized_value,
                "pii_type": pii_type.value,
                "success": result.success,
                "method_used": result.method_used,
                "error_message": result.error_message
            })
        
        return {
            "success": all(r["success"] for r in results),
            "results": results,
            "total_processed": len(results)
        }
    
    except Exception as e:
        logger.error(f"Pseudonymization failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generalize", response_model=Dict[str, Any])
async def generalize_data(
    request: GeneralizationRequest,
    current_user = Depends(get_current_active_user)
):
    """Generalize PII values."""
    try:
        service = get_pseudonymization_service()
        
        # Create configuration
        config = GeneralizationConfig(
            level=request.level,
            preserve_utility=request.preserve_utility,
            custom_categories=request.custom_categories
        )
        
        # Process each value
        results = []
        for value_data in request.values:
            pii_type = PIIType(value_data["pii_type"])
            value = value_data["value"]
            
            result = service.generalize(value, pii_type, config)
            results.append({
                "original_value": result.original_value,
                "generalized_value": result.anonymized_value,
                "pii_type": pii_type.value,
                "success": result.success,
                "method_used": result.method_used,
                "error_message": result.error_message
            })
        
        return {
            "success": all(r["success"] for r in results),
            "results": results,
            "total_processed": len(results)
        }
    
    except Exception as e:
        logger.error(f"Generalization failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/preview")
async def get_redaction_preview(
    request: PolicyRedactionRequest,
    current_user = Depends(get_current_active_user)
):
    """Get preview of policy-driven redaction without executing it."""
    try:
        # Convert to internal format (similar to redact_with_policy)
        entities = []
        for entity_req in request.entities:
            entity = PIIEntity(
                text=entity_req.text,
                entity_type=entity_req.entity_type,
                start=entity_req.start,
                end=entity_req.end,
                confidence=entity_req.confidence
            )
            entities.append(entity)
        
        context_data = request.context
        policy_context = PolicyContext(
            user_id=context_data.get("user_id"),
            document_type=context_data.get("document_type"),
            compliance_standard=context_data.get("compliance_standard"),
            processing_purpose=context_data.get("processing_purpose", "preview"),
            data_classification=context_data.get("data_classification", DataClassification.INTERNAL.value)
        )
        
        service = get_policy_redaction_service()
        policy_request = PolicyRedactionRequest(
            request_id=f"preview_{datetime.utcnow().timestamp()}",
            content=request.content,
            entities=entities,
            context=policy_context,
            redaction_type=request.redaction_type,
            policy_names=request.policy_names,
            override_method=request.override_method
        )
        
        preview = service.get_redaction_preview(policy_request, include_policy_details=True)
        return preview
    
    except Exception as e:
        logger.error(f"Preview generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_redaction_stats(
    current_user = Depends(get_current_active_user)
):
    """Get redaction service statistics."""
    try:
        service = get_policy_redaction_service()
        return service.get_service_stats()
    
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Helper functions

def _get_method_description(method: RedactionMethod) -> str:
    """Get description for redaction method."""
    descriptions = {
        RedactionMethod.DELETE: "Completely remove the text",
        RedactionMethod.MASK_ASTERISK: "Replace with asterisks (***)",
        RedactionMethod.MASK_X: "Replace with X characters (XXX)",
        RedactionMethod.REDACTED_LABEL: "Replace with [REDACTED] label",
        RedactionMethod.PLACEHOLDER: "Replace with custom placeholder",
        RedactionMethod.PSEUDONYMIZE: "Replace with consistent fake data",
        RedactionMethod.GENERALIZE: "Replace with generalized category",
        RedactionMethod.BLACKOUT: "Fill visual region with black",
        RedactionMethod.BLUR: "Apply blur effect to visual region",
        RedactionMethod.PIXELATE: "Apply pixelation to visual region",
    }
    return descriptions.get(method, "Redaction method")


def _get_method_types(method: RedactionMethod) -> List[str]:
    """Get supported content types for method."""
    text_methods = [
        RedactionMethod.DELETE, RedactionMethod.MASK_ASTERISK, 
        RedactionMethod.MASK_X, RedactionMethod.REDACTED_LABEL,
        RedactionMethod.PLACEHOLDER, RedactionMethod.PSEUDONYMIZE,
        RedactionMethod.GENERALIZE
    ]
    
    visual_methods = [
        RedactionMethod.BLACKOUT, RedactionMethod.WHITEOUT,
        RedactionMethod.BLUR, RedactionMethod.PIXELATE,
        RedactionMethod.MOSAIC, RedactionMethod.SOLID_COLOR
    ]
    
    types = []
    if method in text_methods:
        types.append("text")
    if method in visual_methods:
        types.append("visual")
    
    return types


def _get_method_parameters(method: RedactionMethod) -> Dict[str, Any]:
    """Get available parameters for method."""
    parameters = {}
    
    if method in [RedactionMethod.BLACKOUT, RedactionMethod.WHITEOUT, RedactionMethod.SOLID_COLOR]:
        parameters["color"] = {"type": "array", "items": "integer", "description": "RGB color values"}
    
    if method == RedactionMethod.PLACEHOLDER:
        parameters["custom_placeholder"] = {"type": "string", "description": "Custom text to use as placeholder"}
    
    if method in [RedactionMethod.PSEUDONYMIZE, RedactionMethod.GENERALIZE]:
        parameters["consistency_key"] = {"type": "string", "description": "Key for consistent pseudonymization"}
    
    parameters["intensity"] = {"type": "string", "enum": ["low", "medium", "high", "maximum"]}
    
    return parameters