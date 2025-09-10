"""
Batch Processing API Endpoints

RESTful API endpoints for batch processing operations including document processing,
bulk redaction, and job management.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, Path
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator

from ..core.batch.engine import BatchProcessingEngine, get_batch_engine, BatchJob, BatchStatus, BatchJobType, JobPriority
from ..core.batch.job_manager import JobManager
from ..core.batch.document_processor import DocumentBatchProcessor, DocumentBatchType, ProcessingMode, DocumentBatchConfig, get_document_batch_processor
from ..core.batch.bulk_redaction_processor import BulkRedactionProcessor, BulkRedactionConfig, RedactionQualityLevel, RedactionScope, get_bulk_redaction_processor
from ..core.security.auth import get_current_user
from ..core.database.models import User
from ..core.config.policies.base import RedactionMethod, PIIType

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/batch", tags=["Batch Processing"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class JobSubmissionRequest(BaseModel):
    """Request model for job submission."""
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    job_type: BatchJobType
    parameters: Dict[str, Any] = Field(default_factory=dict)
    priority: JobPriority = JobPriority.NORMAL
    timeout_seconds: int = Field(3600, ge=60, le=86400)
    max_workers: int = Field(1, ge=1, le=10)


class DocumentBatchRequest(BaseModel):
    """Request model for document batch processing."""
    document_ids: List[UUID] = Field(..., min_items=1, max_items=1000)
    batch_type: DocumentBatchType
    policy_id: UUID
    batch_name: Optional[str] = None
    processing_mode: ProcessingMode = ProcessingMode.PARALLEL
    max_concurrent_documents: int = Field(5, ge=1, le=20)
    timeout_per_document: int = Field(300, ge=60, le=3600)
    continue_on_error: bool = True
    
    @validator('document_ids')
    def validate_document_ids(cls, v):
        if len(v) != len(set(v)):
            raise ValueError('Duplicate document IDs not allowed')
        return v


class BulkRedactionRequest(BaseModel):
    """Request model for bulk redaction processing."""
    document_ids: List[UUID] = Field(..., min_items=1, max_items=500)
    policy_id: UUID
    batch_name: Optional[str] = None
    
    # Redaction configuration
    redaction_method: RedactionMethod = RedactionMethod.BLACKOUT
    quality_level: RedactionQualityLevel = RedactionQualityLevel.STANDARD
    redaction_scope: RedactionScope = RedactionScope.PII_ONLY
    confidence_threshold: float = Field(0.75, ge=0.0, le=1.0)
    
    # Entity types to redact
    entity_types_to_redact: List[str] = Field(default_factory=lambda: [
        "email", "phone", "ssn", "credit_card"
    ])
    
    # Processing options
    preserve_layout: bool = True
    create_backup: bool = True
    enable_quality_validation: bool = True
    generate_redaction_report: bool = True
    
    # Performance settings
    max_concurrent_redactions: int = Field(3, ge=1, le=10)
    use_gpu_acceleration: bool = False


class JobResponse(BaseModel):
    """Response model for job information."""
    id: UUID
    name: str
    description: Optional[str]
    job_type: BatchJobType
    status: BatchStatus
    priority: JobPriority
    progress_percentage: int
    current_step: str
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_by: UUID
    processing_time_seconds: Optional[float] = None
    error_message: Optional[str] = None


class BatchStatusResponse(BaseModel):
    """Response model for batch status."""
    batch_id: UUID
    job_id: UUID
    status: str
    document_count: int
    processed_count: int
    successful_count: int
    failed_count: int
    created_at: datetime
    completed_at: Optional[datetime]
    batch_type: str
    progress_percentage: int = 0


class BatchMetricsResponse(BaseModel):
    """Response model for batch processing metrics."""
    total_jobs: int
    active_jobs: int
    completed_jobs: int
    failed_jobs: int
    cancelled_jobs: int
    queue_depth: int
    worker_utilization: float
    average_job_time_ms: float
    success_rate: float
    throughput_jobs_per_hour: float


# =============================================================================
# DEPENDENCY FUNCTIONS
# =============================================================================

async def get_batch_manager() -> JobManager:
    """Get batch job manager."""
    engine = get_batch_engine()
    manager = JobManager(engine)
    return manager


async def get_doc_batch_processor() -> DocumentBatchProcessor:
    """Get document batch processor."""
    engine = get_batch_engine()
    manager = await get_batch_manager()
    return get_document_batch_processor(engine, manager)


async def get_redaction_processor() -> BulkRedactionProcessor:
    """Get bulk redaction processor."""
    doc_processor = await get_doc_batch_processor()
    return get_bulk_redaction_processor(doc_processor)


# =============================================================================
# JOB MANAGEMENT ENDPOINTS
# =============================================================================

@router.post("/jobs", response_model=Dict[str, Any])
async def submit_job(
    request: JobSubmissionRequest,
    current_user: User = Depends(get_current_user),
    job_manager: JobManager = Depends(get_batch_manager)
):
    """Submit a new batch job."""
    
    try:
        job_id = await job_manager.create_job(
            name=request.name,
            job_type=request.job_type,
            parameters=request.parameters,
            created_by=current_user.id,
            description=request.description,
            priority=request.priority,
            timeout_seconds=request.timeout_seconds,
            max_workers=request.max_workers
        )
        
        return {
            "job_id": str(job_id),
            "message": "Job submitted successfully",
            "status": "queued"
        }
        
    except Exception as e:
        logger.error(f"Error submitting job: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit job: {str(e)}")


@router.get("/jobs/{job_id}", response_model=JobResponse)
async def get_job_status(
    job_id: UUID = Path(..., description="Job ID"),
    engine: BatchProcessingEngine = Depends(get_batch_engine)
):
    """Get job status and details."""
    
    job = await engine.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    processing_time = None
    if job.started_at and job.completed_at:
        processing_time = (job.completed_at - job.started_at).total_seconds()
    
    return JobResponse(
        id=job.id,
        name=job.name,
        description=job.description,
        job_type=job.job_type,
        status=job.status,
        priority=job.priority,
        progress_percentage=job.progress_percentage,
        current_step=job.current_step,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        created_by=job.created_by,
        processing_time_seconds=processing_time,
        error_message=job.error_message
    )


@router.get("/jobs", response_model=List[JobResponse])
async def list_jobs(
    status: Optional[BatchStatus] = Query(None, description="Filter by job status"),
    job_type: Optional[BatchJobType] = Query(None, description="Filter by job type"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of jobs to return"),
    current_user: User = Depends(get_current_user),
    engine: BatchProcessingEngine = Depends(get_batch_engine)
):
    """List jobs with optional filtering."""
    
    jobs = engine.get_jobs(
        status=status,
        job_type=job_type,
        created_by=current_user.id,
        limit=limit
    )
    
    return [
        JobResponse(
            id=job.id,
            name=job.name,
            description=job.description,
            job_type=job.job_type,
            status=job.status,
            priority=job.priority,
            progress_percentage=job.progress_percentage,
            current_step=job.current_step,
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
            created_by=job.created_by,
            processing_time_seconds=(
                (job.completed_at - job.started_at).total_seconds()
                if job.started_at and job.completed_at else None
            ),
            error_message=job.error_message
        )
        for job in jobs
    ]


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(
    job_id: UUID = Path(..., description="Job ID"),
    engine: BatchProcessingEngine = Depends(get_batch_engine)
):
    """Cancel a running or queued job."""
    
    success = await engine.cancel_job(job_id)
    if not success:
        raise HTTPException(status_code=404, detail="Job not found or cannot be cancelled")
    
    return {"message": "Job cancelled successfully", "job_id": str(job_id)}


@router.post("/jobs/{job_id}/pause")
async def pause_job(
    job_id: UUID = Path(..., description="Job ID"),
    engine: BatchProcessingEngine = Depends(get_batch_engine)
):
    """Pause a running job."""
    
    success = await engine.pause_job(job_id)
    if not success:
        raise HTTPException(status_code=404, detail="Job not found or cannot be paused")
    
    return {"message": "Job paused successfully", "job_id": str(job_id)}


@router.post("/jobs/{job_id}/resume")
async def resume_job(
    job_id: UUID = Path(..., description="Job ID"),
    engine: BatchProcessingEngine = Depends(get_batch_engine)
):
    """Resume a paused job."""
    
    success = await engine.resume_job(job_id)
    if not success:
        raise HTTPException(status_code=404, detail="Job not found or cannot be resumed")
    
    return {"message": "Job resumed successfully", "job_id": str(job_id)}


# =============================================================================
# DOCUMENT BATCH PROCESSING ENDPOINTS
# =============================================================================

@router.post("/documents", response_model=Dict[str, Any])
async def submit_document_batch(
    request: DocumentBatchRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    processor: DocumentBatchProcessor = Depends(get_doc_batch_processor)
):
    """Submit a batch of documents for processing."""
    
    try:
        # Create configuration
        config = DocumentBatchConfig(
            processing_mode=request.processing_mode,
            max_concurrent_documents=request.max_concurrent_documents,
            timeout_per_document=request.timeout_per_document,
            continue_on_error=request.continue_on_error
        )
        
        # Submit batch
        batch_id, job_id = await processor.submit_document_batch(
            document_ids=request.document_ids,
            batch_type=request.batch_type,
            policy_id=request.policy_id,
            batch_name=request.batch_name,
            created_by=current_user.id,
            config_override=config.__dict__
        )
        
        return {
            "batch_id": str(batch_id),
            "job_id": str(job_id),
            "message": "Document batch submitted successfully",
            "document_count": len(request.document_ids),
            "status": "queued"
        }
        
    except Exception as e:
        logger.error(f"Error submitting document batch: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit document batch: {str(e)}")


@router.get("/documents/{batch_id}/status", response_model=BatchStatusResponse)
async def get_document_batch_status(
    batch_id: UUID = Path(..., description="Batch ID"),
    processor: DocumentBatchProcessor = Depends(get_doc_batch_processor)
):
    """Get document batch processing status."""
    
    status = processor.get_batch_status(batch_id)
    if not status:
        raise HTTPException(status_code=404, detail="Batch not found")
    
    return BatchStatusResponse(**status)


@router.get("/documents/{batch_id}/results")
async def get_document_batch_results(
    batch_id: UUID = Path(..., description="Batch ID"),
    processor: DocumentBatchProcessor = Depends(get_doc_batch_processor)
):
    """Get detailed document batch processing results."""
    
    results = processor.get_batch_results(batch_id)
    if results is None:
        raise HTTPException(status_code=404, detail="Batch not found")
    
    return {
        "batch_id": str(batch_id),
        "results": results
    }


# =============================================================================
# BULK REDACTION ENDPOINTS
# =============================================================================

@router.post("/redaction", response_model=Dict[str, Any])
async def submit_bulk_redaction(
    request: BulkRedactionRequest,
    current_user: User = Depends(get_current_user),
    processor: BulkRedactionProcessor = Depends(get_redaction_processor)
):
    """Submit a bulk redaction job."""
    
    try:
        # Create redaction configuration
        config = BulkRedactionConfig(
            default_redaction_method=request.redaction_method,
            quality_level=request.quality_level,
            redaction_scope=request.redaction_scope,
            confidence_threshold=request.confidence_threshold,
            entity_types_to_redact=request.entity_types_to_redact,
            preserve_layout=request.preserve_layout,
            create_backup=request.create_backup,
            enable_quality_validation=request.enable_quality_validation,
            generate_redaction_report=request.generate_redaction_report,
            max_concurrent_redactions=request.max_concurrent_redactions,
            use_gpu_acceleration=request.use_gpu_acceleration
        )
        
        # Submit bulk redaction
        batch_id, job_id = await processor.submit_bulk_redaction(
            document_ids=request.document_ids,
            policy_id=request.policy_id,
            batch_name=request.batch_name,
            config=config,
            created_by=current_user.id
        )
        
        return {
            "batch_id": str(batch_id),
            "job_id": str(job_id),
            "message": "Bulk redaction submitted successfully",
            "document_count": len(request.document_ids),
            "status": "queued"
        }
        
    except Exception as e:
        logger.error(f"Error submitting bulk redaction: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit bulk redaction: {str(e)}")


@router.get("/redaction/{redaction_id}/status")
async def get_redaction_status(
    redaction_id: UUID = Path(..., description="Redaction ID"),
    processor: BulkRedactionProcessor = Depends(get_redaction_processor)
):
    """Get redaction operation status."""
    
    status = processor.get_redaction_status(redaction_id)
    if not status:
        raise HTTPException(status_code=404, detail="Redaction not found")
    
    return status


@router.get("/redaction/statistics")
async def get_redaction_statistics(
    processor: BulkRedactionProcessor = Depends(get_redaction_processor)
):
    """Get bulk redaction processing statistics."""
    
    return processor.get_bulk_redaction_statistics()


# =============================================================================
# SYSTEM STATUS AND METRICS ENDPOINTS
# =============================================================================

@router.get("/metrics", response_model=BatchMetricsResponse)
async def get_batch_metrics(
    engine: BatchProcessingEngine = Depends(get_batch_engine)
):
    """Get batch processing system metrics."""
    
    metrics = engine.get_metrics()
    
    return BatchMetricsResponse(
        total_jobs=metrics.total_jobs,
        active_jobs=metrics.active_jobs,
        completed_jobs=metrics.completed_jobs,
        failed_jobs=metrics.failed_jobs,
        cancelled_jobs=metrics.cancelled_jobs,
        queue_depth=metrics.queue_depth,
        worker_utilization=metrics.worker_utilization,
        average_job_time_ms=metrics.average_job_time_ms,
        success_rate=metrics.success_rate,
        throughput_jobs_per_hour=metrics.throughput_jobs_per_hour
    )


@router.get("/status")
async def get_system_status(
    engine: BatchProcessingEngine = Depends(get_batch_engine)
):
    """Get batch processing system status."""
    
    queue_status = engine.get_queue_status()
    
    return {
        "system_status": "operational" if queue_status["is_running"] else "stopped",
        "queue_depth": queue_status["queue_depth"],
        "running_jobs": queue_status["running_jobs"],
        "total_jobs": queue_status["total_jobs"],
        "is_paused": queue_status["is_paused"],
        "max_concurrent_jobs": queue_status["max_concurrent"],
        "timestamp": datetime.now().isoformat()
    }


@router.get("/health")
async def health_check():
    """Health check endpoint for batch processing system."""
    
    try:
        engine = get_batch_engine()
        status = engine.get_queue_status()
        
        health_status = "healthy" if status["is_running"] else "unhealthy"
        
        return {
            "status": health_status,
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0",
            "components": {
                "batch_engine": "healthy" if status["is_running"] else "unhealthy",
                "job_queue": "healthy",
                "worker_pool": "healthy"
            }
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        )


# =============================================================================
# UTILITY ENDPOINTS
# =============================================================================

@router.get("/supported-types")
async def get_supported_types():
    """Get supported batch job types and document types."""
    
    return {
        "job_types": [job_type.value for job_type in BatchJobType],
        "document_batch_types": [batch_type.value for batch_type in DocumentBatchType],
        "processing_modes": [mode.value for mode in ProcessingMode],
        "redaction_methods": [method.value for method in RedactionMethod],
        "quality_levels": [level.value for level in RedactionQualityLevel],
        "redaction_scopes": [scope.value for scope in RedactionScope],
        "supported_pii_types": [
            "email", "phone", "ssn", "credit_card", "address", "name",
            "date_of_birth", "passport", "driver_license", "bank_account"
        ]
    }


@router.post("/cleanup")
async def cleanup_old_data(
    max_age_hours: int = Query(24, ge=1, le=168, description="Maximum age in hours"),
    current_user: User = Depends(get_current_user),
    processor: DocumentBatchProcessor = Depends(get_doc_batch_processor)
):
    """Clean up old batch processing data."""
    
    # Only allow admin users to perform cleanup
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        processor.cleanup_completed_batches(max_age_hours)
        
        return {
            "message": "Cleanup completed successfully",
            "max_age_hours": max_age_hours,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Cleanup failed: {str(e)}")


# Add router to main app
# This would be done in the main FastAPI app setup:
# app.include_router(router)