"""
Document Batch Processor

Specialized batch processor for document workflows, integrating PII detection,
redaction, and compliance processing in a scalable batch environment.
"""

import logging
import asyncio
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor

from pydantic import BaseModel, Field

from .engine import BatchJob, BatchJobType, BatchProcessingEngine, JobPriority
from .job_manager import JobManager
from ..services.pii_detector import PIIDetectionService, get_pii_detection_service
from ..processing.document_pii_processor import DocumentPIIProcessor, get_document_pii_processor
from ..services.redaction_engine import RedactionEngine
from ..database.models import DocumentMetadata, ProcessingSession, SessionDocument
from ..database.session import get_db_session
from ..config.policies.base import PIIType, RedactionMethod
from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class DocumentBatchType(str, Enum):
    """Types of document batch operations."""
    BULK_PII_DETECTION = "bulk_pii_detection"
    BULK_REDACTION = "bulk_redaction"
    COMPLIANCE_VALIDATION = "compliance_validation"
    DOCUMENT_CLASSIFICATION = "document_classification"
    BULK_OCR_PROCESSING = "bulk_ocr_processing"
    WORKFLOW_PROCESSING = "workflow_processing"


class ProcessingMode(str, Enum):
    """Processing modes for batch operations."""
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"
    PIPELINE = "pipeline"
    SMART_BATCH = "smart_batch"


@dataclass
class DocumentBatchConfig:
    """Configuration for document batch processing."""
    
    # Processing configuration
    processing_mode: ProcessingMode = ProcessingMode.PARALLEL
    max_concurrent_documents: int = 5
    chunk_size: int = 10
    timeout_per_document: int = 300
    
    # Quality settings
    min_confidence_threshold: float = 0.7
    enable_manual_review: bool = False
    quality_validation: bool = True
    
    # Output settings
    preserve_original: bool = True
    output_format: str = "pdf"
    compression_enabled: bool = True
    
    # Compliance settings
    compliance_validation: bool = True
    audit_trail: bool = True
    encryption_required: bool = False
    
    # Retry and error handling
    max_retries: int = 3
    retry_delay_seconds: int = 60
    continue_on_error: bool = False
    
    # Resource limits
    memory_limit_mb: int = 2048
    cpu_cores: int = 2
    temp_storage_limit_mb: int = 5120


@dataclass
class DocumentProcessingResult:
    """Result of document processing operation."""
    
    document_id: UUID
    document_name: str
    processing_status: str = "pending"
    
    # Timing information
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    processing_time_seconds: float = 0.0
    
    # Processing results
    pii_detected_count: int = 0
    pii_redacted_count: int = 0
    pages_processed: int = 0
    confidence_scores: List[float] = field(default_factory=list)
    
    # Quality metrics
    ocr_quality_score: float = 0.0
    redaction_quality_score: float = 0.0
    overall_quality_score: float = 0.0
    
    # Output information
    output_file_path: Optional[str] = None
    output_file_size: int = 0
    thumbnail_path: Optional[str] = None
    
    # Error handling
    error_message: Optional[str] = None
    warning_messages: List[str] = field(default_factory=list)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


class DocumentBatchProcessor:
    """Specialized processor for document batch operations."""
    
    def __init__(self, 
                 batch_engine: BatchProcessingEngine,
                 job_manager: JobManager,
                 config: DocumentBatchConfig = None):
        self.batch_engine = batch_engine
        self.job_manager = job_manager
        self.config = config or DocumentBatchConfig()
        
        # Service dependencies
        self.pii_service = get_pii_detection_service()
        self.document_processor = get_document_pii_processor()
        self.session = get_db_session()
        
        # Processing state
        self.active_batches: Dict[UUID, Dict] = {}
        self.batch_results: Dict[UUID, List[DocumentProcessingResult]] = {}
        
        # Thread pool for I/O operations
        self.io_pool = ThreadPoolExecutor(max_workers=4)
        
        logger.info("DocumentBatchProcessor initialized")
    
    async def submit_document_batch(self,
                                  document_ids: List[UUID],
                                  batch_type: DocumentBatchType,
                                  policy_id: UUID,
                                  batch_name: str = None,
                                  created_by: UUID = None,
                                  config_override: Dict[str, Any] = None) -> Tuple[UUID, UUID]:
        """
        Submit a batch of documents for processing.
        
        Returns:
            Tuple of (batch_id, job_id)
        """
        
        batch_id = uuid4()
        batch_name = batch_name or f"Document Batch {batch_type.value}"
        
        # Merge configuration
        effective_config = self.config
        if config_override:
            # Create new config with overrides
            config_dict = effective_config.__dict__.copy()
            config_dict.update(config_override)
            effective_config = DocumentBatchConfig(**config_dict)
        
        # Create batch job
        job_config = {
            "name": batch_name,
            "description": f"Process {len(document_ids)} documents with {batch_type.value}",
            "job_type": self._get_job_type(batch_type),
            "parameters": {
                "batch_id": str(batch_id),
                "document_ids": [str(doc_id) for doc_id in document_ids],
                "batch_type": batch_type.value,
                "policy_id": str(policy_id),
                "config": effective_config.__dict__
            },
            "priority": JobPriority.NORMAL,
            "timeout_seconds": len(document_ids) * effective_config.timeout_per_document,
            "max_workers": effective_config.max_concurrent_documents,
            "memory_limit_mb": effective_config.memory_limit_mb,
            "created_by": created_by or uuid4()
        }
        
        job = BatchJob(**job_config)
        job_id = await self.batch_engine.submit_job(job)
        
        # Initialize batch tracking
        self.active_batches[batch_id] = {
            "job_id": job_id,
            "document_ids": document_ids,
            "batch_type": batch_type,
            "config": effective_config,
            "created_at": datetime.now(),
            "status": "queued"
        }
        
        self.batch_results[batch_id] = []
        
        logger.info(f"Submitted document batch {batch_id} with {len(document_ids)} documents")
        return batch_id, job_id
    
    def _get_job_type(self, batch_type: DocumentBatchType) -> BatchJobType:
        """Map document batch type to engine job type."""
        mapping = {
            DocumentBatchType.BULK_PII_DETECTION: BatchJobType.PII_DETECTION,
            DocumentBatchType.BULK_REDACTION: BatchJobType.BULK_REDACTION,
            DocumentBatchType.COMPLIANCE_VALIDATION: BatchJobType.COMPLIANCE_VALIDATION,
            DocumentBatchType.BULK_OCR_PROCESSING: BatchJobType.DOCUMENT_PROCESSING,
            DocumentBatchType.WORKFLOW_PROCESSING: BatchJobType.DOCUMENT_PROCESSING,
            DocumentBatchType.DOCUMENT_CLASSIFICATION: BatchJobType.CUSTOM
        }
        return mapping.get(batch_type, BatchJobType.DOCUMENT_PROCESSING)
    
    async def process_document_batch(self, batch_id: UUID, job: BatchJob) -> Dict[str, Any]:
        """Process a batch of documents."""
        
        if batch_id not in self.active_batches:
            raise ValueError(f"Batch {batch_id} not found")
        
        batch_info = self.active_batches[batch_id]
        document_ids = [UUID(doc_id) for doc_id in batch_info["document_ids"]]
        batch_type = batch_info["batch_type"]
        config = batch_info["config"]
        
        batch_info["status"] = "processing"
        job.update_progress(0, "Starting batch processing")
        
        results = []
        processed_count = 0
        successful_count = 0
        failed_count = 0
        
        try:
            # Process documents based on mode
            if config.processing_mode == ProcessingMode.PARALLEL:
                results = await self._process_parallel(
                    document_ids, batch_type, config, job
                )
            elif config.processing_mode == ProcessingMode.SEQUENTIAL:
                results = await self._process_sequential(
                    document_ids, batch_type, config, job
                )
            elif config.processing_mode == ProcessingMode.PIPELINE:
                results = await self._process_pipeline(
                    document_ids, batch_type, config, job
                )
            else:  # SMART_BATCH
                results = await self._process_smart_batch(
                    document_ids, batch_type, config, job
                )
            
            # Calculate final statistics
            processed_count = len(results)
            successful_count = len([r for r in results if r.processing_status == "completed"])
            failed_count = processed_count - successful_count
            
            batch_info["status"] = "completed" if failed_count == 0 else "partial"
            
        except Exception as e:
            logger.error(f"Error processing batch {batch_id}: {e}")
            batch_info["status"] = "failed"
            
            # Create error result for tracking
            error_result = DocumentProcessingResult(
                document_id=uuid4(),
                document_name="Batch Error",
                processing_status="failed",
                error_message=str(e),
                completed_at=datetime.now()
            )
            results = [error_result]
        
        # Store results
        self.batch_results[batch_id] = results
        batch_info["completed_at"] = datetime.now()
        
        # Update job progress
        job.update_progress(100, "Batch processing completed")
        
        return {
            "batch_id": str(batch_id),
            "status": batch_info["status"],
            "processed_count": processed_count,
            "successful_count": successful_count,
            "failed_count": failed_count,
            "results": [self._result_to_dict(r) for r in results]
        }
    
    async def _process_parallel(self, 
                              document_ids: List[UUID], 
                              batch_type: DocumentBatchType,
                              config: DocumentBatchConfig,
                              job: BatchJob) -> List[DocumentProcessingResult]:
        """Process documents in parallel."""
        
        results = []
        semaphore = asyncio.Semaphore(config.max_concurrent_documents)
        
        async def process_single_document(doc_id: UUID, index: int) -> DocumentProcessingResult:
            async with semaphore:
                try:
                    result = await self._process_document(doc_id, batch_type, config)
                    
                    # Update job progress
                    progress = int((index + 1) / len(document_ids) * 100)
                    job.update_progress(progress, f"Processed {index + 1}/{len(document_ids)} documents")
                    
                    return result
                    
                except Exception as e:
                    logger.error(f"Error processing document {doc_id}: {e}")
                    return DocumentProcessingResult(
                        document_id=doc_id,
                        document_name=f"Document {doc_id}",
                        processing_status="failed",
                        error_message=str(e),
                        completed_at=datetime.now()
                    )
        
        # Create tasks for all documents
        tasks = [
            process_single_document(doc_id, i) 
            for i, doc_id in enumerate(document_ids)
        ]
        
        # Execute all tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(DocumentProcessingResult(
                    document_id=document_ids[i],
                    document_name=f"Document {document_ids[i]}",
                    processing_status="failed",
                    error_message=str(result),
                    completed_at=datetime.now()
                ))
            else:
                final_results.append(result)
        
        return final_results
    
    async def _process_sequential(self, 
                                document_ids: List[UUID], 
                                batch_type: DocumentBatchType,
                                config: DocumentBatchConfig,
                                job: BatchJob) -> List[DocumentProcessingResult]:
        """Process documents sequentially."""
        
        results = []
        
        for i, doc_id in enumerate(document_ids):
            try:
                result = await self._process_document(doc_id, batch_type, config)
                results.append(result)
                
                # Update progress
                progress = int((i + 1) / len(document_ids) * 100)
                job.update_progress(progress, f"Processed {i + 1}/{len(document_ids)} documents")
                
            except Exception as e:
                logger.error(f"Error processing document {doc_id}: {e}")
                
                error_result = DocumentProcessingResult(
                    document_id=doc_id,
                    document_name=f"Document {doc_id}",
                    processing_status="failed",
                    error_message=str(e),
                    completed_at=datetime.now()
                )
                results.append(error_result)
                
                # Check if we should continue on error
                if not config.continue_on_error:
                    break
        
        return results
    
    async def _process_pipeline(self, 
                              document_ids: List[UUID], 
                              batch_type: DocumentBatchType,
                              config: DocumentBatchConfig,
                              job: BatchJob) -> List[DocumentProcessingResult]:
        """Process documents in pipeline stages."""
        
        # For pipeline processing, we'll process in chunks
        chunk_size = config.chunk_size
        chunks = [document_ids[i:i + chunk_size] for i in range(0, len(document_ids), chunk_size)]
        
        all_results = []
        
        for chunk_index, chunk in enumerate(chunks):
            # Process chunk in parallel
            chunk_results = await self._process_parallel(chunk, batch_type, config, job)
            all_results.extend(chunk_results)
            
            # Update progress
            progress = int((chunk_index + 1) / len(chunks) * 100)
            job.update_progress(progress, f"Processed chunk {chunk_index + 1}/{len(chunks)}")
            
            # Small delay between chunks to prevent resource exhaustion
            if chunk_index < len(chunks) - 1:
                await asyncio.sleep(1)
        
        return all_results
    
    async def _process_smart_batch(self, 
                                 document_ids: List[UUID], 
                                 batch_type: DocumentBatchType,
                                 config: DocumentBatchConfig,
                                 job: BatchJob) -> List[DocumentProcessingResult]:
        """Intelligent batch processing based on document characteristics."""
        
        # Group documents by size/type for optimal processing
        document_groups = await self._group_documents_intelligently(document_ids)
        
        all_results = []
        total_groups = len(document_groups)
        
        for group_index, (group_type, group_docs) in enumerate(document_groups.items()):
            logger.info(f"Processing {group_type} group with {len(group_docs)} documents")
            
            # Adjust processing based on group characteristics
            if group_type == "large_documents":
                # Process large documents sequentially
                group_results = await self._process_sequential(group_docs, batch_type, config, job)
            elif group_type == "small_documents":
                # Process small documents in parallel
                group_results = await self._process_parallel(group_docs, batch_type, config, job)
            else:
                # Default to pipeline for mixed groups
                group_results = await self._process_pipeline(group_docs, batch_type, config, job)
            
            all_results.extend(group_results)
            
            # Update progress
            progress = int((group_index + 1) / total_groups * 100)
            job.update_progress(progress, f"Processed group {group_index + 1}/{total_groups}")
        
        return all_results
    
    async def _group_documents_intelligently(self, document_ids: List[UUID]) -> Dict[str, List[UUID]]:
        """Group documents by characteristics for optimal processing."""
        
        groups = {
            "small_documents": [],
            "medium_documents": [],
            "large_documents": [],
            "complex_documents": []
        }
        
        # Query document metadata to make intelligent grouping decisions
        # This is a simplified version - in practice would use actual database queries
        for doc_id in document_ids:
            # For demonstration, we'll randomly assign documents to groups
            # In practice, this would be based on file size, type, complexity, etc.
            import random
            group_choice = random.choice(list(groups.keys()))
            groups[group_choice].append(doc_id)
        
        # Remove empty groups
        return {k: v for k, v in groups.items() if v}
    
    async def _process_document(self, 
                              document_id: UUID, 
                              batch_type: DocumentBatchType,
                              config: DocumentBatchConfig) -> DocumentProcessingResult:
        """Process a single document."""
        
        result = DocumentProcessingResult(
            document_id=document_id,
            document_name=f"Document {document_id}",
            started_at=datetime.now()
        )
        
        try:
            result.processing_status = "processing"
            
            # Simulate document processing based on type
            if batch_type == DocumentBatchType.BULK_PII_DETECTION:
                await self._perform_pii_detection(document_id, result, config)
            elif batch_type == DocumentBatchType.BULK_REDACTION:
                await self._perform_redaction(document_id, result, config)
            elif batch_type == DocumentBatchType.COMPLIANCE_VALIDATION:
                await self._perform_compliance_validation(document_id, result, config)
            else:
                await self._perform_generic_processing(document_id, result, config)
            
            result.processing_status = "completed"
            result.completed_at = datetime.now()
            
            if result.started_at and result.completed_at:
                result.processing_time_seconds = (
                    result.completed_at - result.started_at
                ).total_seconds()
            
        except Exception as e:
            result.processing_status = "failed"
            result.error_message = str(e)
            result.completed_at = datetime.now()
            logger.error(f"Document processing failed for {document_id}: {e}")
        
        return result
    
    async def _perform_pii_detection(self, 
                                   document_id: UUID, 
                                   result: DocumentProcessingResult,
                                   config: DocumentBatchConfig):
        """Perform PII detection on document."""
        
        # Simulate PII detection process
        await asyncio.sleep(0.1)  # Simulate processing time
        
        # Mock detection results
        result.pii_detected_count = 15
        result.confidence_scores = [0.85, 0.92, 0.78, 0.95]
        result.pages_processed = 3
        result.overall_quality_score = 88.5
        
        result.metadata = {
            "pii_types_found": ["email", "phone", "ssn", "address"],
            "high_confidence_detections": 12,
            "medium_confidence_detections": 3
        }
    
    async def _perform_redaction(self, 
                               document_id: UUID, 
                               result: DocumentProcessingResult,
                               config: DocumentBatchConfig):
        """Perform redaction on document."""
        
        # Simulate redaction process
        await asyncio.sleep(0.2)  # Simulate processing time
        
        # Mock redaction results
        result.pii_detected_count = 15
        result.pii_redacted_count = 14
        result.pages_processed = 3
        result.redaction_quality_score = 92.0
        result.overall_quality_score = 90.0
        
        result.output_file_path = f"/output/redacted_{document_id}.pdf"
        result.output_file_size = 1024 * 1024  # 1MB
        
        result.metadata = {
            "redaction_method": "blackout",
            "successful_redactions": 14,
            "failed_redactions": 1,
            "redaction_coverage": 93.3
        }
    
    async def _perform_compliance_validation(self, 
                                           document_id: UUID, 
                                           result: DocumentProcessingResult,
                                           config: DocumentBatchConfig):
        """Perform compliance validation on document."""
        
        # Simulate compliance validation
        await asyncio.sleep(0.05)  # Simulate processing time
        
        result.pages_processed = 1
        result.overall_quality_score = 95.0
        
        result.metadata = {
            "compliance_standard": "GDPR",
            "validation_passed": True,
            "violations_found": 0,
            "recommendations": ["Enable audit logging", "Review retention policy"]
        }
    
    async def _perform_generic_processing(self, 
                                        document_id: UUID, 
                                        result: DocumentProcessingResult,
                                        config: DocumentBatchConfig):
        """Perform generic document processing."""
        
        # Simulate generic processing
        await asyncio.sleep(0.1)  # Simulate processing time
        
        result.pages_processed = 5
        result.ocr_quality_score = 87.0
        result.overall_quality_score = 85.0
        
        result.metadata = {
            "processing_type": "generic",
            "text_extracted": True,
            "images_processed": 3
        }
    
    def _result_to_dict(self, result: DocumentProcessingResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        result_dict = {
            "document_id": str(result.document_id),
            "document_name": result.document_name,
            "processing_status": result.processing_status,
            "started_at": result.started_at.isoformat() if result.started_at else None,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "processing_time_seconds": result.processing_time_seconds,
            "pii_detected_count": result.pii_detected_count,
            "pii_redacted_count": result.pii_redacted_count,
            "pages_processed": result.pages_processed,
            "confidence_scores": result.confidence_scores,
            "ocr_quality_score": result.ocr_quality_score,
            "redaction_quality_score": result.redaction_quality_score,
            "overall_quality_score": result.overall_quality_score,
            "output_file_path": result.output_file_path,
            "output_file_size": result.output_file_size,
            "thumbnail_path": result.thumbnail_path,
            "error_message": result.error_message,
            "warning_messages": result.warning_messages,
            "metadata": result.metadata
        }
        return result_dict
    
    def get_batch_status(self, batch_id: UUID) -> Optional[Dict[str, Any]]:
        """Get batch processing status."""
        
        if batch_id not in self.active_batches:
            return None
        
        batch_info = self.active_batches[batch_id]
        results = self.batch_results.get(batch_id, [])
        
        return {
            "batch_id": str(batch_id),
            "job_id": str(batch_info["job_id"]),
            "status": batch_info["status"],
            "document_count": len(batch_info["document_ids"]),
            "processed_count": len(results),
            "successful_count": len([r for r in results if r.processing_status == "completed"]),
            "failed_count": len([r for r in results if r.processing_status == "failed"]),
            "created_at": batch_info["created_at"].isoformat(),
            "completed_at": batch_info.get("completed_at", {}).isoformat() if batch_info.get("completed_at") else None,
            "batch_type": batch_info["batch_type"].value
        }
    
    def get_batch_results(self, batch_id: UUID) -> Optional[List[Dict[str, Any]]]:
        """Get detailed batch processing results."""
        
        if batch_id not in self.batch_results:
            return None
        
        results = self.batch_results[batch_id]
        return [self._result_to_dict(result) for result in results]
    
    def cleanup_completed_batches(self, max_age_hours: int = 24):
        """Clean up old completed batch data."""
        
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        batches_to_remove = []
        
        for batch_id, batch_info in self.active_batches.items():
            completed_at = batch_info.get("completed_at")
            if completed_at and completed_at < cutoff_time:
                batches_to_remove.append(batch_id)
        
        for batch_id in batches_to_remove:
            del self.active_batches[batch_id]
            if batch_id in self.batch_results:
                del self.batch_results[batch_id]
        
        logger.info(f"Cleaned up {len(batches_to_remove)} completed batches")


# Global instance
_document_batch_processor = None

def get_document_batch_processor(batch_engine: BatchProcessingEngine = None,
                               job_manager: JobManager = None) -> DocumentBatchProcessor:
    """Get or create document batch processor instance."""
    global _document_batch_processor
    
    if _document_batch_processor is None and batch_engine and job_manager:
        _document_batch_processor = DocumentBatchProcessor(batch_engine, job_manager)
    
    return _document_batch_processor