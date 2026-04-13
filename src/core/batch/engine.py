"""
Core Batch Processing Engine

Main orchestrator for batch operations, providing job lifecycle management,
resource allocation, and integration with the PII detection and database systems.
"""

import logging
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable, Set
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import threading
from collections import defaultdict, deque

from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session

from ..database.session import get_db_session, transaction_scope
from ..database.repositories.batch_job_repository import BatchJobRepository
from ..database.repositories.batch_worker_repository import BatchWorkerRepository
from ..database.repositories.job_result_repository import JobResultRepository
from ..database.repositories.job_schedule_repository import JobScheduleRepository
from ..config.settings import get_settings
from ..processing.document_pii_processor import DocumentPIIProcessor, get_document_pii_processor

logger = logging.getLogger(__name__)
settings = get_settings()


class BatchStatus(str, Enum):
    """Status of batch job execution."""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class BatchJobType(str, Enum):
    """Types of batch jobs supported."""
    DOCUMENT_PROCESSING = "document_processing"
    PII_DETECTION = "pii_detection"
    BULK_REDACTION = "bulk_redaction"
    COMPLIANCE_VALIDATION = "compliance_validation"
    AUDIT_GENERATION = "audit_generation"
    BULK_ENCRYPTION = "bulk_encryption"
    POLICY_APPLICATION = "policy_application"
    REPORT_GENERATION = "report_generation"
    CUSTOM = "custom"


class JobPriority(str, Enum):
    """Priority levels for batch jobs."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"
    URGENT = "urgent"


@dataclass
class BatchMetrics:
    """Performance and status metrics for batch processing."""
    total_jobs: int = 0
    completed_jobs: int = 0
    failed_jobs: int = 0
    cancelled_jobs: int = 0
    active_jobs: int = 0
    queued_jobs: int = 0
    
    total_documents_processed: int = 0
    total_processing_time_ms: int = 0
    average_job_time_ms: float = 0.0
    
    queue_depth: int = 0
    active_workers: int = 0
    worker_utilization: float = 0.0
    
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    
    error_rate: float = 0.0
    success_rate: float = 0.0
    throughput_jobs_per_hour: float = 0.0
    
    last_updated: datetime = field(default_factory=datetime.utcnow)


class BatchJob(BaseModel):
    """Comprehensive batch job definition and tracking."""
    
    # Job identification
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    job_type: BatchJobType
    
    # Job configuration
    parameters: Dict[str, Any] = Field(default_factory=dict)
    priority: JobPriority = JobPriority.NORMAL
    timeout_seconds: int = Field(3600, ge=60, le=86400)  # 1 hour default, max 24 hours
    
    # Resource requirements
    max_workers: int = Field(1, ge=1, le=10)
    memory_limit_mb: int = Field(1024, ge=512, le=8192)
    cpu_limit_cores: float = Field(1.0, ge=0.5, le=4.0)
    
    # Input/Output
    input_data: Dict[str, Any] = Field(default_factory=dict)
    output_location: Optional[str] = None
    
    # Status and progress
    status: BatchStatus = BatchStatus.PENDING
    progress_percentage: int = Field(0, ge=0, le=100)
    current_step: str = "initialized"
    steps_completed: int = 0
    total_steps: int = 1
    
    # Timing information
    created_at: datetime = Field(default_factory=datetime.utcnow)
    queued_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    last_heartbeat: Optional[datetime] = None
    
    # User and permissions
    created_by: UUID
    assigned_to: Optional[UUID] = None
    access_permissions: List[UUID] = Field(default_factory=list)
    
    # Error handling and retry
    max_retries: int = Field(3, ge=0, le=10)
    retry_count: int = 0
    retry_delay_seconds: int = Field(60, ge=30, le=3600)
    
    # Dependencies and scheduling
    depends_on: List[UUID] = Field(default_factory=list)
    scheduled_at: Optional[datetime] = None
    
    # Results and error tracking
    result_summary: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    error_details: Dict[str, Any] = Field(default_factory=dict)
    
    # Audit and compliance
    compliance_standards: List[str] = Field(default_factory=list)
    audit_trail: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Metadata
    tags: List[str] = Field(default_factory=list)
    custom_metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('timeout_seconds')
    def validate_timeout(cls, v):
        if v < 60:
            raise ValueError('Timeout must be at least 60 seconds')
        return v
    
    @validator('priority')
    def validate_priority(cls, v):
        if isinstance(v, str):
            return JobPriority(v)
        return v
    
    def add_audit_entry(self, action: str, details: Dict[str, Any] = None) -> None:
        """Add entry to audit trail."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "details": details or {}
        }
        self.audit_trail.append(entry)
    
    def update_progress(self, percentage: int, step: str = None, steps_completed: int = None) -> None:
        """Update job progress information."""
        self.progress_percentage = max(0, min(100, percentage))
        if step:
            self.current_step = step
        if steps_completed is not None:
            self.steps_completed = steps_completed
        self.last_heartbeat = datetime.utcnow()
    
    def is_expired(self) -> bool:
        """Check if job has exceeded timeout."""
        if not self.started_at:
            return False
        elapsed = datetime.utcnow() - self.started_at
        return elapsed.total_seconds() > self.timeout_seconds
    
    def can_retry(self) -> bool:
        """Check if job can be retried."""
        return self.retry_count < self.max_retries
    
    def get_runtime_seconds(self) -> float:
        """Get job runtime in seconds."""
        if not self.started_at:
            return 0.0
        end_time = self.completed_at or datetime.utcnow()
        return (end_time - self.started_at).total_seconds()


class BatchProcessingEngine:
    """
    Main batch processing engine that orchestrates job execution,
    manages resources, and coordinates with PII detection systems.
    """
    
    def __init__(self, session: Optional[Session] = None):
        self._session = session
        
        # Repository layer for database persistence
        self._job_repository = BatchJobRepository(session)
        self._worker_repository = BatchWorkerRepository(session)
        self._result_repository = JobResultRepository(session)
        self._schedule_repository = JobScheduleRepository(session)
        
        # In-memory cache for active jobs (performance optimization)
        self._running_jobs: Dict[UUID, asyncio.Task] = {}
        self._worker_pool: Optional[ThreadPoolExecutor] = None
        
        # Status tracking
        self._is_running = False
        self._is_paused = False
        self._shutdown_event = asyncio.Event()
        
        # Metrics and monitoring (computed from database)
        self._metrics = BatchMetrics()
        self._performance_stats: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Configuration
        self._max_concurrent_jobs = getattr(settings, 'batch_max_concurrent_jobs', 5)
        self._heartbeat_interval = getattr(settings, 'batch_heartbeat_interval', 30)
        self._cleanup_interval = getattr(settings, 'batch_cleanup_interval', 300)
        
        # Event handlers
        self._job_start_handlers: List[Callable] = []
        self._job_complete_handlers: List[Callable] = []
        self._job_error_handlers: List[Callable] = []
        
        # Background tasks
        self._monitor_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        
        # Integration components
        self._document_processor: Optional[DocumentPIIProcessor] = None
        
        # Thread safety
        self._lock = threading.RLock()
        
        logger.info("Database-backed Batch Processing Engine initialized")
    
    @property
    def session(self) -> Session:
        """Get current database session."""
        if self._session:
            return self._session
        return get_db_session()
    
    async def start(self) -> None:
        """Start the batch processing engine."""
        if self._is_running:
            logger.warning("Batch engine is already running")
            return
        
        logger.info("Starting Batch Processing Engine...")
        
        try:
            # Initialize worker pool
            self._worker_pool = ThreadPoolExecutor(
                max_workers=self._max_concurrent_jobs,
                thread_name_prefix="batch-worker"
            )
            
            # Initialize document processor
            self._document_processor = get_document_pii_processor()
            
            # Start background tasks
            self._monitor_task = asyncio.create_task(self._monitoring_loop())
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            
            # Mark as running
            self._is_running = True
            self._shutdown_event.clear()
            
            # Start job processor
            asyncio.create_task(self._job_processor_loop())
            
            logger.info("✅ Batch Processing Engine started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start Batch Processing Engine: {e}")
            await self.stop()
            raise
    
    async def stop(self) -> None:
        """Stop the batch processing engine gracefully."""
        if not self._is_running:
            return
        
        logger.info("Stopping Batch Processing Engine...")
        
        # Signal shutdown
        self._is_running = False
        self._shutdown_event.set()
        
        # Cancel running jobs gracefully
        for job_id, task in list(self._running_jobs.items()):
            try:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            except Exception as e:
                logger.error(f"Error cancelling job {job_id}: {e}")
        
        # Cancel background tasks
        for task in [self._monitor_task, self._cleanup_task, self._heartbeat_task]:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Shutdown worker pool
        if self._worker_pool:
            self._worker_pool.shutdown(wait=True)
        
        logger.info("✅ Batch Processing Engine stopped")
    
    async def submit_job(self, job: BatchJob) -> UUID:
        """
        Submit a new batch job for processing.
        
        Args:
            job: Batch job to submit
            
        Returns:
            Job ID
        """
        if not self._is_running:
            raise RuntimeError("Batch engine is not running")
        
        try:
            with self._lock:
                # Validate job
                await self._validate_job(job)
                
                # Set initial status
                job.status = BatchStatus.QUEUED
                job.queued_at = datetime.utcnow()
                job.add_audit_entry("job_submitted", {
                    "job_type": job.job_type.value,
                    "priority": job.priority.value
                })
                
                # Store job
                self._jobs[job.id] = job
                
                # Add to queue based on priority
                self._add_to_queue(job)
                
                # Update metrics
                self._metrics.total_jobs += 1
                self._metrics.queued_jobs += 1
                
                logger.info(f"Job submitted: {job.id} ({job.name})")
                return job.id
                
        except Exception as e:
            logger.error(f"Failed to submit job: {e}")
            raise
    
    async def get_job(self, job_id: UUID) -> Optional[BatchJob]:
        """Get job by ID."""
        return self._jobs.get(job_id)
    
    async def cancel_job(self, job_id: UUID) -> bool:
        """
        Cancel a batch job.
        
        Args:
            job_id: Job ID to cancel
            
        Returns:
            True if cancelled successfully
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False
            
            if job.status in [BatchStatus.COMPLETED, BatchStatus.FAILED, BatchStatus.CANCELLED]:
                return False
            
            # Cancel running job
            if job_id in self._running_jobs:
                task = self._running_jobs[job_id]
                task.cancel()
            
            # Update job status
            job.status = BatchStatus.CANCELLED
            job.completed_at = datetime.utcnow()
            job.add_audit_entry("job_cancelled")
            
            # Update metrics
            self._metrics.cancelled_jobs += 1
            if job.status == BatchStatus.QUEUED:
                self._metrics.queued_jobs -= 1
            elif job.status == BatchStatus.RUNNING:
                self._metrics.active_jobs -= 1
            
            logger.info(f"Job cancelled: {job_id}")
            return True
    
    async def pause_job(self, job_id: UUID) -> bool:
        """Pause a running job."""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.status != BatchStatus.RUNNING:
                return False
            
            job.status = BatchStatus.PAUSED
            job.add_audit_entry("job_paused")
            
            logger.info(f"Job paused: {job_id}")
            return True
    
    async def resume_job(self, job_id: UUID) -> bool:
        """Resume a paused job."""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.status != BatchStatus.PAUSED:
                return False
            
            job.status = BatchStatus.QUEUED
            job.add_audit_entry("job_resumed")
            
            # Re-add to queue
            self._add_to_queue(job)
            
            logger.info(f"Job resumed: {job_id}")
            return True
    
    def get_jobs(self, 
                status: Optional[BatchStatus] = None,
                job_type: Optional[BatchJobType] = None,
                created_by: Optional[UUID] = None,
                limit: int = 100) -> List[BatchJob]:
        """Get jobs with optional filtering."""
        jobs = list(self._jobs.values())
        
        if status:
            jobs = [j for j in jobs if j.status == status]
        if job_type:
            jobs = [j for j in jobs if j.job_type == job_type]
        if created_by:
            jobs = [j for j in jobs if j.created_by == created_by]
        
        # Sort by created_at desc
        jobs.sort(key=lambda x: x.created_at, reverse=True)
        
        return jobs[:limit]
    
    def get_metrics(self) -> BatchMetrics:
        """Get current batch processing metrics."""
        with self._lock:
            # Update current metrics
            self._update_metrics()
            return self._metrics
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status."""
        with self._lock:
            return {
                "queue_depth": len(self._job_queue),
                "running_jobs": len(self._running_jobs),
                "total_jobs": len(self._jobs),
                "is_running": self._is_running,
                "is_paused": self._is_paused,
                "max_concurrent": self._max_concurrent_jobs
            }
    
    # Event handler registration
    def on_job_start(self, handler: Callable[[BatchJob], None]) -> None:
        """Register job start event handler."""
        self._job_start_handlers.append(handler)
    
    def on_job_complete(self, handler: Callable[[BatchJob], None]) -> None:
        """Register job completion event handler."""
        self._job_complete_handlers.append(handler)
    
    def on_job_error(self, handler: Callable[[BatchJob, Exception], None]) -> None:
        """Register job error event handler."""
        self._job_error_handlers.append(handler)
    
    # Private methods
    
    async def _validate_job(self, job: BatchJob) -> None:
        """Validate job configuration."""
        if not job.name.strip():
            raise ValueError("Job name is required")
        
        if job.timeout_seconds < 60:
            raise ValueError("Timeout must be at least 60 seconds")
        
        if job.max_workers > self._max_concurrent_jobs:
            raise ValueError(f"Max workers cannot exceed {self._max_concurrent_jobs}")
        
        # Validate dependencies
        for dep_id in job.depends_on:
            if dep_id not in self._jobs:
                raise ValueError(f"Dependency job not found: {dep_id}")
    
    def _add_to_queue(self, job: BatchJob) -> None:
        """Add job to queue based on priority."""
        # Priority-based insertion
        priority_order = {
            JobPriority.URGENT: 0,
            JobPriority.CRITICAL: 1,
            JobPriority.HIGH: 2,
            JobPriority.NORMAL: 3,
            JobPriority.LOW: 4
        }
        
        job_priority = priority_order.get(job.priority, 3)
        
        # Find insertion point
        inserted = False
        for i, queued_job_id in enumerate(self._job_queue):
            queued_job = self._jobs[queued_job_id]
            queued_priority = priority_order.get(queued_job.priority, 3)
            
            if job_priority < queued_priority:
                self._job_queue.insert(i, job.id)
                inserted = True
                break
        
        if not inserted:
            self._job_queue.append(job.id)
    
    async def _job_processor_loop(self) -> None:
        """Main job processing loop."""
        while self._is_running:
            try:
                # Check for available capacity
                if len(self._running_jobs) >= self._max_concurrent_jobs:
                    await asyncio.sleep(1)
                    continue
                
                # Get next job from queue
                job_id = None
                with self._lock:
                    if self._job_queue:
                        job_id = self._job_queue.popleft()
                
                if not job_id:
                    await asyncio.sleep(1)
                    continue
                
                job = self._jobs.get(job_id)
                if not job:
                    continue
                
                # Check job dependencies
                if not await self._check_dependencies(job):
                    # Re-queue job
                    with self._lock:
                        self._job_queue.append(job_id)
                    await asyncio.sleep(5)
                    continue
                
                # Start job execution
                task = asyncio.create_task(self._execute_job(job))
                self._running_jobs[job_id] = task
                
            except Exception as e:
                logger.error(f"Error in job processor loop: {e}")
                await asyncio.sleep(5)
    
    async def _check_dependencies(self, job: BatchJob) -> bool:
        """Check if job dependencies are satisfied."""
        for dep_id in job.depends_on:
            dep_job = self._jobs.get(dep_id)
            if not dep_job or dep_job.status != BatchStatus.COMPLETED:
                return False
        return True
    
    async def _execute_job(self, job: BatchJob) -> None:
        """Execute a batch job."""
        try:
            # Update job status
            job.status = BatchStatus.RUNNING
            job.started_at = datetime.utcnow()
            job.add_audit_entry("job_started")
            
            # Update metrics
            with self._lock:
                self._metrics.active_jobs += 1
                self._metrics.queued_jobs -= 1
            
            # Notify start handlers
            for handler in self._job_start_handlers:
                try:
                    handler(job)
                except Exception as e:
                    logger.error(f"Error in job start handler: {e}")
            
            logger.info(f"Starting job: {job.id} ({job.name})")
            
            # Execute job based on type
            if job.job_type == BatchJobType.DOCUMENT_PROCESSING:
                await self._execute_document_processing_job(job)
            elif job.job_type == BatchJobType.PII_DETECTION:
                await self._execute_pii_detection_job(job)
            elif job.job_type == BatchJobType.BULK_REDACTION:
                await self._execute_bulk_redaction_job(job)
            else:
                await self._execute_custom_job(job)
            
            # Mark as completed
            job.status = BatchStatus.COMPLETED
            job.completed_at = datetime.utcnow()
            job.progress_percentage = 100
            job.add_audit_entry("job_completed", {
                "runtime_seconds": job.get_runtime_seconds()
            })
            
            # Update metrics
            with self._lock:
                self._metrics.completed_jobs += 1
                self._metrics.active_jobs -= 1
                self._update_performance_stats(job)
            
            # Notify completion handlers
            for handler in self._job_complete_handlers:
                try:
                    handler(job)
                except Exception as e:
                    logger.error(f"Error in job complete handler: {e}")
            
            logger.info(f"Job completed: {job.id} in {job.get_runtime_seconds():.2f}s")
            
        except asyncio.CancelledError:
            job.status = BatchStatus.CANCELLED
            job.completed_at = datetime.utcnow()
            job.add_audit_entry("job_cancelled_during_execution")
            
            with self._lock:
                self._metrics.cancelled_jobs += 1
                self._metrics.active_jobs -= 1
            
            logger.info(f"Job cancelled during execution: {job.id}")
            
        except Exception as e:
            # Handle job failure
            job.status = BatchStatus.FAILED
            job.completed_at = datetime.utcnow()
            job.error_message = str(e)
            job.error_details = {
                "exception_type": type(e).__name__,
                "traceback": str(e)
            }
            job.add_audit_entry("job_failed", {"error": str(e)})
            
            # Update metrics
            with self._lock:
                self._metrics.failed_jobs += 1
                self._metrics.active_jobs -= 1
            
            # Notify error handlers
            for handler in self._job_error_handlers:
                try:
                    handler(job, e)
                except Exception as handler_error:
                    logger.error(f"Error in job error handler: {handler_error}")
            
            logger.error(f"Job failed: {job.id} - {e}")
            
            # Check for retry
            if job.can_retry():
                await self._schedule_retry(job)
        
        finally:
            # Clean up running job tracking
            self._running_jobs.pop(job.id, None)
            
            # Move to history
            self._job_history.append({
                "id": job.id,
                "name": job.name,
                "status": job.status,
                "runtime": job.get_runtime_seconds(),
                "completed_at": job.completed_at
            })
    
    async def _execute_document_processing_job(self, job: BatchJob) -> None:
        """Execute document processing batch job."""
        # This would integrate with DocumentBatchProcessor
        # For now, simulate processing
        documents = job.input_data.get("documents", [])
        total_docs = len(documents)
        
        job.total_steps = total_docs
        job.update_progress(0, "Starting document processing")
        
        for i, doc_path in enumerate(documents):
            if job.status == BatchStatus.CANCELLED:
                break
            
            # Simulate document processing
            await asyncio.sleep(0.1)  # Simulate processing time
            
            job.update_progress(
                int((i + 1) / total_docs * 100),
                f"Processing document {i + 1}/{total_docs}",
                i + 1
            )
        
        job.result_summary = {
            "documents_processed": len(documents),
            "total_time_seconds": job.get_runtime_seconds()
        }
    
    async def _execute_pii_detection_job(self, job: BatchJob) -> None:
        """Execute PII detection batch job."""
        # Integration point with PIIBatchAnalyzer
        documents = job.input_data.get("documents", [])
        job.total_steps = len(documents)
        
        pii_results = []
        for i, doc_path in enumerate(documents):
            if job.status == BatchStatus.CANCELLED:
                break
            
            # Simulate PII detection
            await asyncio.sleep(0.05)
            pii_results.append({
                "document": doc_path,
                "pii_found": True,
                "pii_count": 5
            })
            
            job.update_progress(
                int((i + 1) / len(documents) * 100),
                f"Analyzing document {i + 1}/{len(documents)}",
                i + 1
            )
        
        job.result_summary = {
            "documents_analyzed": len(documents),
            "total_pii_found": sum(r["pii_count"] for r in pii_results),
            "results": pii_results
        }
    
    async def _execute_bulk_redaction_job(self, job: BatchJob) -> None:
        """Execute bulk redaction batch job."""
        # Integration point with BulkRedactionProcessor
        documents = job.input_data.get("documents", [])
        job.total_steps = len(documents)
        
        for i, doc_path in enumerate(documents):
            if job.status == BatchStatus.CANCELLED:
                break
            
            # Simulate redaction
            await asyncio.sleep(0.2)
            
            job.update_progress(
                int((i + 1) / len(documents) * 100),
                f"Redacting document {i + 1}/{len(documents)}",
                i + 1
            )
        
        job.result_summary = {
            "documents_redacted": len(documents),
            "redaction_method": job.parameters.get("redaction_method", "blackout")
        }
    
    async def _execute_custom_job(self, job: BatchJob) -> None:
        """Execute custom batch job."""
        # Placeholder for custom job execution
        steps = job.parameters.get("steps", 10)
        job.total_steps = steps
        
        for i in range(steps):
            if job.status == BatchStatus.CANCELLED:
                break
            
            await asyncio.sleep(0.1)
            job.update_progress(
                int((i + 1) / steps * 100),
                f"Processing step {i + 1}/{steps}",
                i + 1
            )
        
        job.result_summary = {"steps_completed": steps}
    
    async def _schedule_retry(self, job: BatchJob) -> None:
        """Schedule job retry."""
        job.retry_count += 1
        job.status = BatchStatus.QUEUED
        job.add_audit_entry("job_retry_scheduled", {
            "retry_count": job.retry_count,
            "delay_seconds": job.retry_delay_seconds
        })
        
        # Schedule retry with delay
        await asyncio.sleep(job.retry_delay_seconds)
        
        with self._lock:
            self._add_to_queue(job)
            self._metrics.queued_jobs += 1
        
        logger.info(f"Job retry scheduled: {job.id} (attempt {job.retry_count})")
    
    async def _monitoring_loop(self) -> None:
        """Background monitoring loop."""
        while self._is_running:
            try:
                # Check for expired jobs
                await self._check_expired_jobs()
                
                # Update metrics
                with self._lock:
                    self._update_metrics()
                
                await asyncio.sleep(self._heartbeat_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(30)
    
    async def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while self._is_running:
            try:
                await self._cleanup_completed_jobs()
                await asyncio.sleep(self._cleanup_interval)
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(300)
    
    async def _heartbeat_loop(self) -> None:
        """Background heartbeat loop for running jobs."""
        while self._is_running:
            try:
                current_time = datetime.utcnow()
                
                # Update heartbeat for running jobs
                for job_id in list(self._running_jobs.keys()):
                    job = self._jobs.get(job_id)
                    if job and job.status == BatchStatus.RUNNING:
                        job.last_heartbeat = current_time
                
                await asyncio.sleep(self._heartbeat_interval)
                
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
                await asyncio.sleep(30)
    
    async def _check_expired_jobs(self) -> None:
        """Check for and handle expired jobs."""
        for job_id in list(self._running_jobs.keys()):
            job = self._jobs.get(job_id)
            if job and job.is_expired():
                logger.warning(f"Job expired, cancelling: {job_id}")
                await self.cancel_job(job_id)
    
    async def _cleanup_completed_jobs(self) -> None:
        """Clean up old completed jobs from memory."""
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        
        jobs_to_remove = []
        for job_id, job in self._jobs.items():
            if (job.status in [BatchStatus.COMPLETED, BatchStatus.FAILED, BatchStatus.CANCELLED] and
                job.completed_at and job.completed_at < cutoff_time):
                jobs_to_remove.append(job_id)
        
        for job_id in jobs_to_remove:
            del self._jobs[job_id]
        
        if jobs_to_remove:
            logger.info(f"Cleaned up {len(jobs_to_remove)} old jobs")
    
    def _update_metrics(self) -> None:
        """Update current metrics."""
        now = datetime.utcnow()
        
        # Count jobs by status
        status_counts = defaultdict(int)
        for job in self._jobs.values():
            status_counts[job.status] += 1
        
        self._metrics.active_jobs = status_counts[BatchStatus.RUNNING]
        self._metrics.queued_jobs = status_counts[BatchStatus.QUEUED]
        self._metrics.completed_jobs = status_counts[BatchStatus.COMPLETED]
        self._metrics.failed_jobs = status_counts[BatchStatus.FAILED]
        self._metrics.cancelled_jobs = status_counts[BatchStatus.CANCELLED]
        
        # Calculate rates
        total_processed = self._metrics.completed_jobs + self._metrics.failed_jobs
        if total_processed > 0:
            self._metrics.success_rate = self._metrics.completed_jobs / total_processed
            self._metrics.error_rate = self._metrics.failed_jobs / total_processed
        
        # Worker utilization
        if self._max_concurrent_jobs > 0:
            self._metrics.worker_utilization = len(self._running_jobs) / self._max_concurrent_jobs
        
        # Queue depth
        self._metrics.queue_depth = len(self._job_queue)
        self._metrics.last_updated = now
    
    def _update_performance_stats(self, job: BatchJob) -> None:
        """Update performance statistics from completed job."""
        runtime = job.get_runtime_seconds()
        
        self._performance_stats["job_times"].append(runtime)
        self._performance_stats["completion_times"].append(datetime.utcnow().timestamp())
        
        # Calculate average job time
        if self._performance_stats["job_times"]:
            self._metrics.average_job_time_ms = (
                sum(self._performance_stats["job_times"]) / 
                len(self._performance_stats["job_times"]) * 1000
            )
        
        # Calculate throughput (jobs per hour)
        recent_completions = [
            t for t in self._performance_stats["completion_times"]
            if t > datetime.utcnow().timestamp() - 3600  # Last hour
        ]
        self._metrics.throughput_jobs_per_hour = len(recent_completions)


# Global batch engine instance
_batch_engine: Optional[BatchProcessingEngine] = None


def get_batch_engine(session: Optional[Session] = None) -> BatchProcessingEngine:
    """Get the global batch processing engine instance."""
    global _batch_engine
    if _batch_engine is None:
        _batch_engine = BatchProcessingEngine(session)
    return _batch_engine


def initialize_batch_engine(session: Optional[Session] = None) -> BatchProcessingEngine:
    """Initialize the batch processing engine."""
    global _batch_engine
    _batch_engine = BatchProcessingEngine(session)
    logger.info("Batch Processing Engine initialized successfully")
    return _batch_engine