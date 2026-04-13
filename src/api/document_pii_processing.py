"""
Unified Document Processing with PII Detection API

FastAPI endpoints for complete document processing with integrated PII detection,
providing comprehensive analysis of both text and visual content.
"""

import logging
import tempfile
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
import uuid

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from enum import Enum

from ..core.processing.document_pii_processor import (
    DocumentPIIProcessor,
    PIIProcessingOptions,
    PIIProcessingMode,
    PIIDocumentResult,
    get_document_pii_processor,
    quick_document_pii_analysis
)
from ..core.processing.document_factory import ProcessingOptions, ProcessingMode
from ..core.security.compliance_encryption import ComplianceStandard, DataClassification
from ..core.config.policies.base import PIIType, RedactionMethod
from ..core.services.pii_detector import RiskLevel, DetectionStatus
from ..core.security.dependencies import (
    get_current_active_user,
    require_write_permission,
    require_read_permission,
    upload_rate_limit
)

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/document-pii", tags=["Document PII Processing"])

# Global processor instance
document_pii_processor = None


def get_processor():
    """Get document PII processor instance."""
    global document_pii_processor
    if document_pii_processor is None:
        document_pii_processor = get_document_pii_processor()
    return document_pii_processor


# Request/Response Models
class PIIProcessingModeEnum(str, Enum):
    """PII processing mode enumeration for API."""
    text_only = "text_only"
    visual_only = "visual_only"
    comprehensive = "comprehensive"
    ocr_enhanced = "ocr_enhanced"


class ProcessingModeEnum(str, Enum):
    """Document processing mode enumeration for API."""
    basic = "basic"
    enhanced = "enhanced"
    ocr_ready = "ocr_ready"


class ComplianceStandardEnum(str, Enum):
    """Compliance standard enumeration for API."""
    gdpr = "gdpr"
    hipaa = "hipaa"
    ccpa = "ccpa"
    pci_dss = "pci_dss"
    sox = "sox"
    ferpa = "ferpa"


class DocumentPIIProcessingRequest(BaseModel):
    """Request model for document PII processing."""
    
    # Document processing options
    processing_mode: ProcessingModeEnum = ProcessingModeEnum.enhanced
    apply_scan_optimization: bool = True
    enhance_for_ocr: bool = True
    
    # PII processing options
    pii_mode: PIIProcessingModeEnum = PIIProcessingModeEnum.comprehensive
    enable_text_pii: bool = True
    enable_visual_pii: bool = True
    enable_ocr_pii: bool = True
    
    # Detection parameters
    text_confidence_threshold: float = Field(0.5, ge=0.0, le=1.0)
    visual_confidence_threshold: float = Field(0.6, ge=0.0, le=1.0)
    language: str = Field("en", min_length=2, max_length=5)
    model_type: str = Field("presidio")
    visual_model_type: str = Field("yolov8")
    
    # Entity filtering
    entity_types: Optional[List[str]] = Field(None, description="Specific text entity types to detect")
    visual_entity_types: Optional[List[str]] = Field(None, description="Specific visual entity types to detect")
    
    # Compliance and security
    compliance_standards: Optional[List[ComplianceStandardEnum]] = Field(None)
    encrypt_results: bool = True
    audit_logging: bool = True
    
    # Processing optimization
    parallel_processing: bool = True
    timeout_seconds: int = Field(300, ge=30, le=1800)
    
    @validator('compliance_standards')
    def validate_compliance_standards(cls, v):
        if v is not None:
            valid_standards = [item.value for item in ComplianceStandardEnum]
            for standard in v:
                if standard not in valid_standards:
                    raise ValueError(f"Invalid compliance standard: {standard}")
        return v


class DocumentPIIResponse(BaseModel):
    """Response model for document PII processing."""
    
    # Processing status
    success: bool
    processing_id: str
    document_id: str
    message: str
    
    # Document information
    document_type: Optional[str] = None
    filename: str
    file_size: int
    page_count: int = 0
    
    # Processing timing
    started_at: datetime
    completed_at: Optional[datetime] = None
    total_processing_time: float = 0.0
    
    # PII Detection Summary
    pii_summary: Dict[str, Any] = Field(default_factory=dict)
    
    # Risk and compliance
    overall_risk_level: str = "low"
    compliance_flags: List[str] = Field(default_factory=list)
    
    # Performance metrics
    performance: Dict[str, float] = Field(default_factory=dict)
    
    # Processing details
    operations_performed: List[str] = Field(default_factory=list)
    errors_encountered: List[str] = Field(default_factory=list)


class ProcessingStatusResponse(BaseModel):
    """Response model for processing status check."""
    processing_id: str
    status: str
    progress: Dict[str, Any] = Field(default_factory=dict)
    estimated_completion: Optional[datetime] = None


class ProcessingStatisticsResponse(BaseModel):
    """Response model for processing statistics."""
    total_processed: int
    success_rate: float
    average_processing_time: float
    risk_level_distribution: Dict[str, int]
    pii_type_distribution: Dict[str, int]
    supported_formats: Dict[str, List[str]]


# API Endpoints
@router.post(
    "/process", 
    response_model=DocumentPIIResponse,
    summary="Process document with integrated PII detection",
    description="Upload and process a document with comprehensive PII detection for text and visual content"
)
async def process_document_with_pii(
    file: UploadFile = File(..., description="Document file to process"),
    request_data: str = Form(..., description="JSON string of processing options"),
    background_tasks: BackgroundTasks = None,
    current_user=Depends(get_current_active_user),
    _=Depends(require_write_permission),
    _rate_limit=Depends(upload_rate_limit)
):
    """Process document with integrated PII detection."""
    
    # Parse request data
    try:
        import json
        request_options = DocumentPIIProcessingRequest.parse_raw(request_data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid request data: {str(e)}")
    
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Check file size (100MB limit)
    if file.size and file.size > 100 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 100MB)")
    
    # Check file extension
    file_ext = Path(file.filename).suffix.lower()
    supported_extensions = ['.pdf', '.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp', '.gif']
    if file_ext not in supported_extensions:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported file format: {file_ext}. Supported: {supported_extensions}"
        )
    
    processor = get_processor()
    document_id = str(uuid.uuid4())
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp_file:
        tmp_file.write(await file.read())
        tmp_file_path = tmp_file.name
    
    try:
        # Convert request options to processing options
        processing_options = ProcessingOptions(
            mode=ProcessingMode(request_options.processing_mode.value),
            apply_scan_optimization=request_options.apply_scan_optimization,
            enhance_for_ocr=request_options.enhance_for_ocr
        )
        
        # Convert compliance standards
        compliance_standards = None
        if request_options.compliance_standards:
            compliance_standards = [
                ComplianceStandard(standard.value) 
                for standard in request_options.compliance_standards
            ]
        
        pii_options = PIIProcessingOptions(
            pii_mode=PIIProcessingMode(request_options.pii_mode.value),
            enable_text_pii=request_options.enable_text_pii,
            enable_visual_pii=request_options.enable_visual_pii,
            enable_ocr_pii=request_options.enable_ocr_pii,
            text_confidence_threshold=request_options.text_confidence_threshold,
            visual_confidence_threshold=request_options.visual_confidence_threshold,
            language=request_options.language,
            model_type=request_options.model_type,
            visual_model_type=request_options.visual_model_type,
            entity_types=request_options.entity_types,
            visual_entity_types=request_options.visual_entity_types,
            compliance_standards=compliance_standards,
            encrypt_results=request_options.encrypt_results,
            audit_logging=request_options.audit_logging,
            parallel_processing=request_options.parallel_processing,
            timeout_seconds=request_options.timeout_seconds
        )
        
        # Process document with PII detection
        start_time = datetime.now()
        
        result = await processor.process_document_with_pii(
            file_path=tmp_file_path,
            document_id=document_id,
            processing_options=processing_options,
            pii_options=pii_options
        )
        
        # Convert result to response format
        response = DocumentPIIResponse(
            success=result.success,
            processing_id=result.processing_id,
            document_id=result.document_id,
            message="Document processed successfully" if result.success else "Processing completed with errors",
            document_type=result.document_type.value if result.document_type else None,
            filename=file.filename,
            file_size=file.size or 0,
            page_count=result.page_count,
            started_at=result.started_at,
            completed_at=result.completed_at,
            total_processing_time=result.total_processing_time,
            pii_summary={
                "total_text_entities": result.total_text_entities,
                "total_visual_entities": result.total_visual_entities,
                "unique_pii_types": len(result.unique_pii_types),
                "pii_types_found": result.unique_pii_types
            },
            overall_risk_level=result.overall_risk_level.value,
            compliance_flags=result.compliance_flags,
            performance={
                "document_processing_time": result.document_processing_time,
                "text_pii_processing_time": result.text_pii_processing_time,
                "visual_pii_processing_time": result.visual_pii_processing_time,
                "ocr_processing_time": result.ocr_processing_time
            },
            operations_performed=result.operations_performed,
            errors_encountered=result.errors_encountered
        )
        
        logger.info(f"Document processing completed: {result.processing_id}")
        return response
        
    except Exception as e:
        logger.error(f"Error processing document: {e}")
        raise HTTPException(status_code=500, detail=f"Processing failed: {str(e)}")
    
    finally:
        # Clean up temporary file
        try:
            Path(tmp_file_path).unlink()
        except Exception:
            pass


@router.post(
    "/quick-analysis",
    response_model=DocumentPIIResponse,
    summary="Quick document PII analysis",
    description="Quick document processing with PII detection using default settings"
)
async def quick_document_analysis(
    file: UploadFile = File(..., description="Document file to analyze"),
    pii_mode: PIIProcessingModeEnum = Query(PIIProcessingModeEnum.comprehensive, description="PII processing mode"),
    confidence_threshold: float = Query(0.5, ge=0.0, le=1.0, description="Confidence threshold"),
    current_user=Depends(get_current_active_user),
    _=Depends(require_read_permission)
):
    """Quick document analysis with PII detection using default settings."""
    
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    file_ext = Path(file.filename).suffix.lower()
    supported_extensions = ['.pdf', '.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp', '.gif']
    if file_ext not in supported_extensions:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported file format: {file_ext}"
        )
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp_file:
        tmp_file.write(await file.read())
        tmp_file_path = tmp_file.name
    
    try:
        # Quick analysis using convenience function
        result = await quick_document_pii_analysis(
            file_path=tmp_file_path,
            pii_mode=PIIProcessingMode(pii_mode.value),
            confidence_threshold=confidence_threshold
        )
        
        # Convert result to response format
        response = DocumentPIIResponse(
            success=result.success,
            processing_id=result.processing_id,
            document_id=result.document_id,
            message="Quick analysis completed successfully" if result.success else "Analysis completed with errors",
            document_type=result.document_type.value if result.document_type else None,
            filename=file.filename,
            file_size=file.size or 0,
            page_count=result.page_count,
            started_at=result.started_at,
            completed_at=result.completed_at,
            total_processing_time=result.total_processing_time,
            pii_summary={
                "total_text_entities": result.total_text_entities,
                "total_visual_entities": result.total_visual_entities,
                "unique_pii_types": len(result.unique_pii_types),
                "pii_types_found": result.unique_pii_types
            },
            overall_risk_level=result.overall_risk_level.value,
            compliance_flags=result.compliance_flags,
            performance={
                "document_processing_time": result.document_processing_time,
                "text_pii_processing_time": result.text_pii_processing_time,
                "visual_pii_processing_time": result.visual_pii_processing_time,
                "ocr_processing_time": result.ocr_processing_time
            },
            operations_performed=result.operations_performed,
            errors_encountered=result.errors_encountered
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error in quick analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    
    finally:
        # Clean up temporary file
        try:
            Path(tmp_file_path).unlink()
        except Exception:
            pass


@router.get(
    "/status/{processing_id}",
    response_model=ProcessingStatusResponse,
    summary="Get processing status",
    description="Check the status of a document processing operation"
)
async def get_processing_status(
    processing_id: str,
    current_user=Depends(get_current_active_user),
    _=Depends(require_read_permission)
):
    """Get processing status by ID."""
    
    processor = get_processor()
    result = processor.get_processing_result(processing_id)
    
    if not result:
        raise HTTPException(status_code=404, detail="Processing ID not found")
    
    # Determine status
    if result.completed_at:
        status = "completed" if result.success else "failed"
    else:
        status = "in_progress"
    
    return ProcessingStatusResponse(
        processing_id=processing_id,
        status=status,
        progress={
            "operations_completed": len(result.operations_performed),
            "errors_count": len(result.errors_encountered),
            "processing_time": result.total_processing_time
        },
        estimated_completion=result.completed_at
    )


@router.get(
    "/result/{processing_id}",
    response_model=DocumentPIIResponse,
    summary="Get processing result",
    description="Retrieve the complete result of a document processing operation"
)
async def get_processing_result(
    processing_id: str,
    current_user=Depends(get_current_active_user),
    _=Depends(require_read_permission)
):
    """Get complete processing result by ID."""
    
    processor = get_processor()
    result = processor.get_processing_result(processing_id)
    
    if not result:
        raise HTTPException(status_code=404, detail="Processing ID not found")
    
    # Convert result to response format
    response = DocumentPIIResponse(
        success=result.success,
        processing_id=result.processing_id,
        document_id=result.document_id,
        message="Processing completed" if result.success else "Processing completed with errors",
        document_type=result.document_type.value if result.document_type else None,
        filename="[Retrieved Result]",
        file_size=0,
        page_count=result.page_count,
        started_at=result.started_at,
        completed_at=result.completed_at,
        total_processing_time=result.total_processing_time,
        pii_summary={
            "total_text_entities": result.total_text_entities,
            "total_visual_entities": result.total_visual_entities,
            "unique_pii_types": len(result.unique_pii_types),
            "pii_types_found": result.unique_pii_types
        },
        overall_risk_level=result.overall_risk_level.value,
        compliance_flags=result.compliance_flags,
        performance={
            "document_processing_time": result.document_processing_time,
            "text_pii_processing_time": result.text_pii_processing_time,
            "visual_pii_processing_time": result.visual_pii_processing_time,
            "ocr_processing_time": result.ocr_processing_time
        },
        operations_performed=result.operations_performed,
        errors_encountered=result.errors_encountered
    )
    
    return response


@router.get(
    "/statistics",
    response_model=ProcessingStatisticsResponse,
    summary="Get processing statistics",
    description="Get overall processing statistics and performance metrics"
)
async def get_processing_statistics(
    current_user=Depends(get_current_active_user),
    _=Depends(require_read_permission)
):
    """Get processing statistics and performance metrics."""
    
    processor = get_processor()
    stats = processor.get_processing_statistics()
    
    return ProcessingStatisticsResponse(
        total_processed=stats["total_processed"],
        success_rate=stats["success_rate"],
        average_processing_time=stats["average_processing_time"],
        risk_level_distribution=stats["risk_level_distribution"],
        pii_type_distribution=stats["pii_type_distribution"],
        supported_formats=stats["supported_formats"]
    )


@router.delete(
    "/cleanup",
    summary="Cleanup old processing results",
    description="Clean up old processing results from memory"
)
async def cleanup_old_results(
    max_age_hours: int = Query(24, ge=1, le=168, description="Maximum age in hours"),
    current_user=Depends(get_current_active_user),
    _=Depends(require_write_permission)
):
    """Clean up old processing results."""
    
    processor = get_processor()
    processor.cleanup_history(max_age_hours)
    
    return {"message": f"Cleaned up processing results older than {max_age_hours} hours"}