"""
Document Upload API for PII De-identification System

This module provides FastAPI endpoints for multi-format document upload,
processing, and PII detection.
"""

import logging
import tempfile
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
import uuid

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..core.processing.document_factory import DocumentFactory, ProcessingOptions, ProcessingMode
from ..core.models.model_manager import get_model_manager
from ..core.security.dependencies import (
    get_current_active_user,
    require_write_permission,
    require_read_permission,
    upload_rate_limit
)

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/documents", tags=["documents"])

# Global instances
document_factory = None
model_manager = None


def get_document_factory():
    """Get document factory instance."""
    global document_factory
    if document_factory is None:
        model_manager_instance = get_model_manager()
        document_factory = model_manager_instance.get_model("document_factory")
    return document_factory


def get_model_manager_instance():
    """Get model manager instance."""
    global model_manager
    if model_manager is None:
        model_manager = get_model_manager()
    return model_manager


# Request/Response Models
class DocumentUploadResponse(BaseModel):
    """Response model for document upload."""
    success: bool
    message: str
    document_id: str
    document_type: str
    file_size_bytes: int
    estimated_pages: int
    processing_job_id: Optional[str] = None


class ProcessingOptionsRequest(BaseModel):
    """Request model for processing options."""
    mode: str = Field(default="enhanced", description="Processing mode: basic, enhanced, ocr_ready")
    apply_scan_optimization: bool = Field(default=True, description="Apply scan optimization")
    enhance_for_ocr: bool = Field(default=True, description="Enhance for OCR")
    target_dpi: int = Field(default=300, description="Target DPI for processing")
    max_dimension: int = Field(default=2048, description="Maximum image dimension")


class DocumentProcessingResult(BaseModel):
    """Response model for document processing results."""
    success: bool
    document_id: str
    document_type: str
    processing_mode: str
    page_count: int
    quality_score: float
    processing_time_seconds: float
    operations_performed: List[str]
    errors_encountered: List[str]
    extracted_text_preview: str = Field(description="First 500 characters of extracted text")
    pii_detected: bool = Field(default=False, description="Whether PII was detected")
    pii_summary: Dict[str, Any] = Field(default_factory=dict, description="Summary of detected PII")


class DocumentInfo(BaseModel):
    """Model for document information."""
    document_id: str
    filename: str
    document_type: str
    file_size_bytes: int
    estimated_pages: int
    upload_timestamp: datetime
    processing_status: str
    is_scanned: bool
    confidence_score: float


# In-memory storage for demo purposes (in production, use a proper database)
document_store: Dict[str, Dict[str, Any]] = {}
processing_jobs: Dict[str, Dict[str, Any]] = {}


@router.post("/upload", response_model=DocumentUploadResponse)
async def upload_document(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Document file to upload"),
    auto_process: bool = Form(default=True, description="Automatically start processing"),
    processing_options: Optional[str] = Form(default=None, description="JSON processing options"),
    current_user: Dict = Depends(require_write_permission),
    rate_limit=Depends(upload_rate_limit)
):
    """
    Upload a document for PII detection and de-identification.
    
    Supports multiple formats: PDF, PNG, JPG, JPEG, TIFF, BMP, WebP, GIF
    """
    try:
        # Generate unique document ID
        document_id = str(uuid.uuid4())
        
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        file_extension = Path(file.filename).suffix.lower()
        supported_formats = ['.pdf', '.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp', '.webp', '.gif']
        
        if file_extension not in supported_formats:
            raise HTTPException(
                status_code=400, 
                detail=f"Unsupported file format: {file_extension}. Supported: {', '.join(supported_formats)}"
            )
        
        # Check file size (100MB limit)
        file_content = await file.read()
        file_size = len(file_content)
        max_size = 100 * 1024 * 1024  # 100MB
        
        if file_size > max_size:
            raise HTTPException(
                status_code=400,
                detail=f"File too large: {file_size / (1024*1024):.1f}MB > {max_size / (1024*1024)}MB"
            )
        
        # Save file temporarily
        temp_dir = Path(tempfile.gettempdir()) / "pii_processing"
        temp_dir.mkdir(exist_ok=True)
        temp_file_path = temp_dir / f"{document_id}_{file.filename}"
        
        with open(temp_file_path, "wb") as temp_file:
            temp_file.write(file_content)
        
        # Analyze document
        factory = get_document_factory()
        doc_info = factory.analyze_document(temp_file_path)
        
        # Store document information
        document_store[document_id] = {
            "document_id": document_id,
            "filename": file.filename,
            "temp_file_path": str(temp_file_path),
            "document_type": doc_info.document_type.value,
            "file_size_bytes": file_size,
            "estimated_pages": doc_info.estimated_pages,
            "upload_timestamp": datetime.now(),
            "processing_status": "uploaded",
            "is_scanned": doc_info.is_scanned,
            "confidence_score": doc_info.confidence_score,
            "metadata": doc_info.metadata
        }
        
        response = DocumentUploadResponse(
            success=True,
            message="Document uploaded successfully",
            document_id=document_id,
            document_type=doc_info.document_type.value,
            file_size_bytes=file_size,
            estimated_pages=doc_info.estimated_pages
        )
        
        # Start processing if requested
        if auto_process:
            # Parse processing options
            options = ProcessingOptions()
            if processing_options:
                try:
                    import json
                    options_dict = json.loads(processing_options)
                    options = ProcessingOptions(**options_dict)
                except Exception as e:
                    logger.warning(f"Failed to parse processing options: {e}")
            
            # Start background processing
            job_id = str(uuid.uuid4())
            processing_jobs[job_id] = {
                "job_id": job_id,
                "document_id": document_id,
                "status": "queued",
                "start_time": datetime.now(),
                "options": options
            }
            
            background_tasks.add_task(process_document_background, document_id, job_id, options)
            response.processing_job_id = job_id
            
            # Update document status
            document_store[document_id]["processing_status"] = "processing"
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Document upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@router.post("/process/{document_id}", response_model=Dict[str, Any])
async def process_document(
    document_id: str,
    background_tasks: BackgroundTasks,
    options: ProcessingOptionsRequest = ProcessingOptionsRequest(),
    current_user: Dict = Depends(require_write_permission)
):
    """
    Start processing a previously uploaded document.
    """
    try:
        # Check if document exists
        if document_id not in document_store:
            raise HTTPException(status_code=404, detail="Document not found")
        
        doc_info = document_store[document_id]
        
        # Check if already processing
        if doc_info["processing_status"] == "processing":
            raise HTTPException(status_code=400, detail="Document is already being processed")
        
        # Create processing options
        processing_mode_map = {
            "basic": ProcessingMode.BASIC,
            "enhanced": ProcessingMode.ENHANCED,
            "ocr_ready": ProcessingMode.OCR_READY
        }
        
        processing_options = ProcessingOptions(
            mode=processing_mode_map.get(options.mode, ProcessingMode.ENHANCED),
            apply_scan_optimization=options.apply_scan_optimization,
            enhance_for_ocr=options.enhance_for_ocr,
            target_dpi=options.target_dpi,
            max_dimension=options.max_dimension
        )
        
        # Start background processing
        job_id = str(uuid.uuid4())
        processing_jobs[job_id] = {
            "job_id": job_id,
            "document_id": document_id,
            "status": "queued",
            "start_time": datetime.now(),
            "options": processing_options
        }
        
        background_tasks.add_task(process_document_background, document_id, job_id, processing_options)
        
        # Update document status
        document_store[document_id]["processing_status"] = "processing"
        
        return {
            "success": True,
            "message": "Processing started",
            "job_id": job_id,
            "document_id": document_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Processing start failed: {e}")
        raise HTTPException(status_code=500, detail=f"Processing failed: {str(e)}")


@router.get("/status/{document_id}", response_model=DocumentInfo)
async def get_document_status(
    document_id: str,
    current_user: Dict = Depends(require_read_permission)
):
    """Get status information for a document."""
    try:
        if document_id not in document_store:
            raise HTTPException(status_code=404, detail="Document not found")
        
        doc_info = document_store[document_id]
        
        return DocumentInfo(
            document_id=document_id,
            filename=doc_info["filename"],
            document_type=doc_info["document_type"],
            file_size_bytes=doc_info["file_size_bytes"],
            estimated_pages=doc_info["estimated_pages"],
            upload_timestamp=doc_info["upload_timestamp"],
            processing_status=doc_info["processing_status"],
            is_scanned=doc_info["is_scanned"],
            confidence_score=doc_info["confidence_score"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Status check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")


@router.get("/results/{document_id}", response_model=DocumentProcessingResult)
async def get_processing_results(
    document_id: str,
    current_user: Dict = Depends(require_read_permission)
):
    """Get processing results for a document."""
    try:
        if document_id not in document_store:
            raise HTTPException(status_code=404, detail="Document not found")
        
        doc_info = document_store[document_id]
        
        if doc_info["processing_status"] != "completed":
            raise HTTPException(
                status_code=400, 
                detail=f"Document processing not completed. Status: {doc_info['processing_status']}"
            )
        
        # Get results from document store
        results = doc_info.get("processing_results")
        if not results:
            raise HTTPException(status_code=404, detail="Processing results not found")
        
        return DocumentProcessingResult(**results)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Results retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Results retrieval failed: {str(e)}")


@router.get("/job/{job_id}")
async def get_job_status(job_id: str):
    """Get status of a processing job."""
    try:
        if job_id not in processing_jobs:
            raise HTTPException(status_code=404, detail="Job not found")
        
        job_info = processing_jobs[job_id]
        return {
            "job_id": job_id,
            "document_id": job_info["document_id"],
            "status": job_info["status"],
            "start_time": job_info["start_time"],
            "end_time": job_info.get("end_time"),
            "progress": job_info.get("progress", 0),
            "error_message": job_info.get("error_message")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Job status check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Job status check failed: {str(e)}")


@router.get("/formats")
async def get_supported_formats():
    """Get list of supported document formats."""
    try:
        factory = get_document_factory()
        formats = factory.get_supported_formats()
        
        return {
            "success": True,
            "supported_formats": formats,
            "max_file_size_mb": 100,
            "max_pages": 500
        }
        
    except Exception as e:
        logger.error(f"Format info retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Format info retrieval failed: {str(e)}")


@router.delete("/documents/{document_id}")
async def delete_document(document_id: str):
    """Delete a document and its associated files."""
    try:
        if document_id not in document_store:
            raise HTTPException(status_code=404, detail="Document not found")
        
        doc_info = document_store[document_id]
        
        # Delete temporary file
        temp_file_path = Path(doc_info["temp_file_path"])
        if temp_file_path.exists():
            temp_file_path.unlink()
        
        # Remove from store
        del document_store[document_id]
        
        # Remove associated jobs
        jobs_to_remove = [job_id for job_id, job_info in processing_jobs.items() 
                         if job_info["document_id"] == document_id]
        for job_id in jobs_to_remove:
            del processing_jobs[job_id]
        
        return {
            "success": True,
            "message": "Document deleted successfully",
            "document_id": document_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Document deletion failed: {e}")
        raise HTTPException(status_code=500, detail=f"Document deletion failed: {str(e)}")


async def process_document_background(document_id: str, job_id: str, options: ProcessingOptions):
    """Background task to process document."""
    try:
        # Update job status
        processing_jobs[job_id]["status"] = "processing"
        processing_jobs[job_id]["progress"] = 10
        
        # Get document info
        doc_info = document_store[document_id]
        temp_file_path = Path(doc_info["temp_file_path"])
        
        # Process document
        factory = get_document_factory()
        result = factory.process_document(temp_file_path, options)
        
        processing_jobs[job_id]["progress"] = 80
        
        # Prepare results for storage
        extracted_text_preview = result.extracted_text[:500] if result.extracted_text else ""
        
        processing_result = {
            "success": result.success,
            "document_id": document_id,
            "document_type": result.document_type.value,
            "processing_mode": result.processing_mode.value,
            "page_count": result.page_count,
            "quality_score": result.quality_score,
            "processing_time_seconds": result.processing_time_seconds,
            "operations_performed": result.operations_performed or [],
            "errors_encountered": result.errors_encountered or [],
            "extracted_text_preview": extracted_text_preview,
            "pii_detected": False,  # TODO: Integrate with PII detection
            "pii_summary": {}      # TODO: Integrate with PII detection
        }
        
        # Store results
        document_store[document_id]["processing_results"] = processing_result
        document_store[document_id]["processing_status"] = "completed"
        
        # Update job status
        processing_jobs[job_id]["status"] = "completed"
        processing_jobs[job_id]["progress"] = 100
        processing_jobs[job_id]["end_time"] = datetime.now()
        
        logger.info(f"Document {document_id} processed successfully")
        
    except Exception as e:
        logger.error(f"Background processing failed for document {document_id}: {e}")
        
        # Update job with error
        processing_jobs[job_id]["status"] = "failed"
        processing_jobs[job_id]["error_message"] = str(e)
        processing_jobs[job_id]["end_time"] = datetime.now()
        
        # Update document status
        document_store[document_id]["processing_status"] = "failed"
        document_store[document_id]["error_message"] = str(e)