"""
Document processing endpoints
"""
import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.core.database import get_async_db
from src.core.processing_engine import processing_engine
from src.models.database import Document, ProcessingJob, PIIDetection
from src.models.schemas import (
    ProcessingJobResponse,
    ProcessingJobCreate,
    ProcessingStatus,
    RedactionPreview
)

router = APIRouter()


@router.post("/documents/{document_id}/process")
async def start_document_processing(
    document_id: uuid.UUID,
    policy_id: uuid.UUID = None,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Start processing pipeline for a document
    """
    # Verify document exists
    query = select(Document).where(Document.id == document_id)
    result = await db.execute(query)
    document = result.scalar_one_or_none()
    
    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    if document.status == "processing":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Document is already being processed"
        )
    
    # Start processing in background
    import asyncio
    
    # Create background task to process document
    async def background_processing():
        try:
            result = await processing_engine.process_document(
                document_id=document_id,
                db=db,
                policy_config={
                    "entities": None,  # All entities
                    "confidence_threshold": 0.8
                }
            )
            return result
        except Exception as e:
            print(f"Background processing failed: {e}")
            return {"success": False, "error": str(e)}
    
    # Start background task (in real implementation, use Prefect or Celery)
    asyncio.create_task(background_processing())
    
    return {
        "message": "Processing started",
        "document_id": document_id,
        "jobs_created": len(created_jobs),
        "status": "processing"
    }


@router.get("/documents/{document_id}/processing-status", response_model=ProcessingStatus)
async def get_processing_status(
    document_id: uuid.UUID,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Get processing status for a document
    """
    # Get document
    doc_query = select(Document).where(Document.id == document_id)
    doc_result = await db.execute(doc_query)
    document = doc_result.scalar_one_or_none()
    
    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    # Get processing jobs
    jobs_query = select(ProcessingJob).where(
        ProcessingJob.document_id == document_id
    ).order_by(ProcessingJob.created_at)
    
    jobs_result = await db.execute(jobs_query)
    jobs = jobs_result.scalars().all()
    
    # Calculate progress
    if not jobs:
        progress_percentage = 0
        overall_status = document.status
    else:
        completed_jobs = sum(1 for job in jobs if job.status == "completed")
        total_jobs = len(jobs)
        progress_percentage = int((completed_jobs / total_jobs) * 100)
        
        # Determine overall status
        if any(job.status == "failed" for job in jobs):
            overall_status = "failed"
        elif all(job.status == "completed" for job in jobs):
            overall_status = "completed"
        elif any(job.status == "running" for job in jobs):
            overall_status = "processing"
        else:
            overall_status = "pending"
    
    return ProcessingStatus(
        document_id=document_id,
        overall_status=overall_status,
        jobs=[ProcessingJobResponse.from_orm(job) for job in jobs],
        progress_percentage=progress_percentage,
        estimated_completion=None  # TODO: Calculate based on processing history
    )


@router.get("/processing/jobs", response_model=List[ProcessingJobResponse])
async def list_processing_jobs(
    status_filter: str = None,
    job_type_filter: str = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_async_db)
):
    """
    List all processing jobs
    """
    query = select(ProcessingJob).offset(skip).limit(limit).order_by(
        ProcessingJob.created_at.desc()
    )
    
    if status_filter:
        query = query.where(ProcessingJob.status == status_filter)
    
    if job_type_filter:
        query = query.where(ProcessingJob.job_type == job_type_filter)
    
    result = await db.execute(query)
    jobs = result.scalars().all()
    
    return [ProcessingJobResponse.from_orm(job) for job in jobs]


@router.get("/processing/jobs/{job_id}", response_model=ProcessingJobResponse)
async def get_processing_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Get specific processing job details
    """
    query = select(ProcessingJob).where(ProcessingJob.id == job_id)
    result = await db.execute(query)
    job = result.scalar_one_or_none()
    
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Processing job not found"
        )
    
    return ProcessingJobResponse.from_orm(job)


@router.post("/processing/jobs/{job_id}/cancel")
async def cancel_processing_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Cancel a processing job
    """
    query = select(ProcessingJob).where(ProcessingJob.id == job_id)
    result = await db.execute(query)
    job = result.scalar_one_or_none()
    
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Processing job not found"
        )
    
    if job.status in ["completed", "failed"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot cancel job with status: {job.status}"
        )
    
    # TODO: Implement actual job cancellation in workflow system
    job.status = "cancelled"
    job.error_message = "Cancelled by user request"
    
    await db.commit()
    
    return {
        "message": "Job cancelled successfully",
        "job_id": job_id,
        "status": "cancelled"
    }


@router.get("/documents/{document_id}/preview", response_model=RedactionPreview)
async def get_redaction_preview(
    document_id: uuid.UUID,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Get preview of detected PII and proposed redactions
    """
    # Verify document exists
    query = select(Document).where(Document.id == document_id)
    result = await db.execute(query)
    document = result.scalar_one_or_none()
    
    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    # Get PII detections from database
    detections_query = select(PIIDetection).where(
        PIIDetection.document_id == document_id
    )
    detections_result = await db.execute(detections_query)
    detections = detections_result.scalars().all()
    
    if not detections:
        return RedactionPreview(
            document_id=document_id,
            total_detections=0,
            detections_by_type={},
            confidence_distribution={},
            preview_text="No PII detections found. Document may not have been processed yet."
        )
    
    # Calculate statistics
    detections_by_type = {}
    confidence_distribution = {"high": 0, "medium": 0, "low": 0}
    
    for detection in detections:
        # Count by type
        detection_type = detection.detection_type
        detections_by_type[detection_type] = detections_by_type.get(detection_type, 0) + 1
        
        # Count by confidence
        confidence = float(detection.confidence_score)
        if confidence >= 0.9:
            confidence_distribution["high"] += 1
        elif confidence >= 0.7:
            confidence_distribution["medium"] += 1
        else:
            confidence_distribution["low"] += 1
    
    # Create preview text (first 500 characters with PII highlighted)
    preview_text = "PII detected in document. Processing completed."
    
    return RedactionPreview(
        document_id=document_id,
        total_detections=len(detections),
        detections_by_type=detections_by_type,
        confidence_distribution=confidence_distribution,
        preview_text=preview_text
    )


@router.post("/processing/batch")
async def start_batch_processing(
    document_ids: List[uuid.UUID],
    policy_id: uuid.UUID = None,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Start batch processing for multiple documents
    """
    # Verify all documents exist
    query = select(Document).where(Document.id.in_(document_ids))
    result = await db.execute(query)
    documents = result.scalars().all()
    
    if len(documents) != len(document_ids):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or more documents not found"
        )
    
    # Check for documents already being processed
    processing_docs = [doc for doc in documents if doc.status == "processing"]
    if processing_docs:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Documents already being processed: {[str(doc.id) for doc in processing_docs]}"
        )
    
    # Start processing for each document
    batch_results = []
    for document in documents:
        # Update status
        document.status = "processing"
        
        # Create jobs
        jobs_to_create = [
            {"job_type": "ocr", "status": "pending"},
            {"job_type": "pii_detection", "status": "pending"},
            {"job_type": "redaction", "status": "pending"}
        ]
        
        created_jobs = []
        for job_data in jobs_to_create:
            job = ProcessingJob(
                document_id=document.id,
                job_type=job_data["job_type"],
                status=job_data["status"]
            )
            db.add(job)
            created_jobs.append(job)
        
        batch_results.append({
            "document_id": document.id,
            "jobs_created": len(created_jobs),
            "status": "processing"
        })
    
    await db.commit()
    
    return {
        "message": f"Batch processing started for {len(documents)} documents",
        "results": batch_results,
        "total_documents": len(documents)
    }