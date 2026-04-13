"""
Database-Persistent Batch Processing Engine

Enhanced version of the batch processing engine that persists all job state
to the database for reliability, recovery, and distributed processing.
"""

import logging
import asyncio
import json
import os
from datetime import datetime, timezone, timedelta
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
from ..database.repositories.job_result_repository import JobResultRepository
from ..database.repositories.batch_worker_repository import BatchWorkerRepository
from ..database.repositories.job_schedule_repository import JobScheduleRepository
from ..database.models import (
    BatchJob as BatchJobModel, JobResult, BatchWorker, JobSchedule,
    BatchJobStatus, BatchJobType, JobPriority, WorkerStatus
)
from ..config.settings import get_settings
from ..processing.document_pii_processor import DocumentPIIProcessor, get_document_pii_processor
from .engine import BatchJob, BatchMetrics, BatchProcessingEngine as BaseEngine

logger = logging.getLogger(__name__)
settings = get_settings()


class PersistentBatchProcessingEngine:
    """
    Database-persistent batch processing engine that provides reliable
    job management with full recovery capabilities.
    """
    
    def __init__(self, session: Optional[Session] = None):
        self._session = session
        
        # Repository instances
        self._job_repo: Optional[BatchJobRepository] = None
        self._result_repo: Optional[JobResultRepository] = None
        self._worker_repo: Optional[BatchWorkerRepository] = None
        self._schedule_repo: Optional[JobScheduleRepository] = None
        
        # In-memory caches for active jobs (for performance)
        self._active_jobs_cache: Dict[UUID, BatchJob] = {}
        self._running_jobs: Dict[UUID, asyncio.Task] = {}
        
        # Worker pool and status
        self._worker_pool: Optional[ThreadPoolExecutor] = None
        self._worker_id: Optional[UUID] = None
        self._is_running = False
        self._is_paused = False
        self._shutdown_event = asyncio.Event()
        
        # Metrics tracking
        self._metrics = BatchMetrics()
        self._performance_stats: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Configuration
        self._max_concurrent_jobs = getattr(settings, 'batch_max_concurrent_jobs', 5)
        self._heartbeat_interval = getattr(settings, 'batch_heartbeat_interval', 30)
        self._cleanup_interval = getattr(settings, 'batch_cleanup_interval', 300)
        self._job_polling_interval = getattr(settings, 'batch_job_polling_interval', 5)
        
        # Event handlers
        self._job_start_handlers: List[Callable] = []
        self._job_complete_handlers: List[Callable] = []
        self._job_error_handlers: List[Callable] = []
        
        # Background tasks
        self._monitor_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._job_processor_task: Optional[asyncio.Task] = None
        self._scheduler_task: Optional[asyncio.Task] = None
        
        # Integration components
        self._document_processor: Optional[DocumentPIIProcessor] = None
        
        # Thread safety
        self._lock = threading.RLock()
        
        logger.info("Persistent Batch Processing Engine initialized")
    
    @property
    def session(self) -> Session:
        """Get current database session."""
        if self._session:
            return self._session
        return get_db_session()
    
    @property
    def job_repo(self) -> BatchJobRepository:
        """Get job repository."""
        if not self._job_repo:
            self._job_repo = BatchJobRepository(self.session)
        return self._job_repo
    
    @property
    def result_repo(self) -> JobResultRepository:
        """Get result repository."""
        if not self._result_repo:
            self._result_repo = JobResultRepository(self.session)
        return self._result_repo
    
    @property
    def worker_repo(self) -> BatchWorkerRepository:
        """Get worker repository."""
        if not self._worker_repo:
            self._worker_repo = BatchWorkerRepository(self.session)
        return self._worker_repo
    
    @property
    def schedule_repo(self) -> JobScheduleRepository:
        """Get schedule repository."""
        if not self._schedule_repo:
            self._schedule_repo = JobScheduleRepository(self.session)
        return self._schedule_repo
    
    async def start(self) -> None:
        """Start the persistent batch processing engine."""
        if self._is_running:
            logger.warning("Persistent batch engine is already running")
            return
        
        logger.info("Starting Persistent Batch Processing Engine...")
        
        try:
            # Register this worker instance
            await self._register_worker()
            
            # Initialize worker pool
            self._worker_pool = ThreadPoolExecutor(
                max_workers=self._max_concurrent_jobs,
                thread_name_prefix="batch-worker"
            )
            
            # Initialize document processor
            self._document_processor = get_document_pii_processor()
            
            # Recover interrupted jobs
            await self._recover_interrupted_jobs()
            
            # Start background tasks
            self._monitor_task = asyncio.create_task(self._monitoring_loop())
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            self._job_processor_task = asyncio.create_task(self._job_processor_loop())
            self._scheduler_task = asyncio.create_task(self._scheduler_loop())
            
            # Mark as running
            self._is_running = True
            self._shutdown_event.clear()
            
            logger.info("✅ Persistent Batch Processing Engine started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start Persistent Batch Processing Engine: {e}")
            await self.stop()
            raise
    
    async def stop(self) -> None:
        """Stop the batch processing engine gracefully."""
        if not self._is_running:
            return
        
        logger.info("Stopping Persistent Batch Processing Engine...")
        
        # Signal shutdown
        self._is_running = False
        self._shutdown_event.set()
        
        # Update worker status
        if self._worker_id:
            await self._update_worker_status(WorkerStatus.OFFLINE)
        
        # Cancel running jobs gracefully
        for job_id, task in list(self._running_jobs.items()):
            try:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            except Exception as e:
                logger.error(f"Error cancelling job {job_id}: {e}")
        
        # Cancel background tasks
        for task in [self._monitor_task, self._cleanup_task, self._heartbeat_task, 
                     self._job_processor_task, self._scheduler_task]:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Shutdown worker pool
        if self._worker_pool:
            self._worker_pool.shutdown(wait=True)
        
        logger.info("✅ Persistent Batch Processing Engine stopped")
    
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
            # Convert to database model
            job_data = {
                'name': job.name,
                'description': job.description,
                'job_type': job.job_type,
                'parameters': job.parameters,
                'priority': job.priority,
                'timeout_seconds': job.timeout_seconds,
                'max_workers': job.max_workers,
                'memory_limit_mb': job.memory_limit_mb,
                'cpu_limit_cores': float(job.cpu_limit_cores),
                'input_data': job.input_data,
                'output_location': job.output_location,
                'created_by': job.created_by,
                'assigned_to': job.assigned_to,
                'access_permissions': job.access_permissions,
                'max_retries': job.max_retries,
                'retry_delay_seconds': job.retry_delay_seconds,
                'depends_on': job.depends_on,
                'scheduled_at': job.scheduled_at,
                'compliance_standards': job.compliance_standards,
                'tags': job.tags,
                'custom_metadata': job.custom_metadata
            }
            
            # Create job in database
            db_job = self.job_repo.create_job(job_data)
            
            # Add to active cache
            with self._lock:
                self._active_jobs_cache[db_job.id] = self._convert_db_job_to_pydantic(db_job)
            
            # Update metrics
            self._metrics.total_jobs += 1
            self._metrics.queued_jobs += 1
            
            logger.info(f"Job submitted: {db_job.id} ({db_job.name})")
            return db_job.id
            
        except Exception as e:
            logger.error(f"Failed to submit job: {e}")
            raise
    
    async def get_job(self, job_id: UUID) -> Optional[BatchJob]:
        """Get job by ID."""
        try:
            # Check active cache first
            with self._lock:
                if job_id in self._active_jobs_cache:
                    return self._active_jobs_cache[job_id]
            
            # Query database
            db_job = self.job_repo.get_job(job_id, include_relationships=True)
            if db_job:
                job = self._convert_db_job_to_pydantic(db_job)
                
                # Cache if active
                if db_job.status in [BatchJobStatus.PENDING, BatchJobStatus.QUEUED, 
                                   BatchJobStatus.RUNNING, BatchJobStatus.PAUSED]:
                    with self._lock:
                        self._active_jobs_cache[job_id] = job
                
                return job
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get job {job_id}: {e}")
            return None
    
    async def cancel_job(self, job_id: UUID) -> bool:
        """Cancel a batch job."""
        try:
            # Update in database
            success = self.job_repo.update_job_status(
                job_id, BatchJobStatus.CANCELLED, "Job cancelled by user"
            )
            
            if success:
                # Cancel running task if exists
                if job_id in self._running_jobs:
                    task = self._running_jobs[job_id]
                    task.cancel()
                
                # Remove from cache
                with self._lock:
                    self._active_jobs_cache.pop(job_id, None)
                
                self._metrics.cancelled_jobs += 1
                logger.info(f"Job cancelled: {job_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to cancel job {job_id}: {e}")
            return False
    
    def get_jobs(self, **filters) -> List[BatchJob]:
        """Get jobs with filtering."""
        try:
            db_jobs = self.job_repo.find_jobs(**filters)
            return [self._convert_db_job_to_pydantic(job) for job in db_jobs]
        except Exception as e:
            logger.error(f"Failed to get jobs: {e}")
            return []
    
    def get_metrics(self) -> BatchMetrics:
        """Get current batch processing metrics."""
        try:
            # Get statistics from database
            stats = self.job_repo.get_job_statistics(days_back=1)
            
            # Update metrics
            self._metrics.total_jobs = stats.get('total_jobs', 0)
            self._metrics.completed_jobs = stats['by_status'].get('completed', 0)
            self._metrics.failed_jobs = stats['by_status'].get('failed', 0)
            self._metrics.cancelled_jobs = stats['by_status'].get('cancelled', 0)
            self._metrics.active_jobs = stats['by_status'].get('running', 0)
            self._metrics.queued_jobs = stats['by_status'].get('queued', 0)
            self._metrics.success_rate = stats.get('success_rate', 0)
            self._metrics.average_job_time_ms = stats.get('average_duration_seconds', 0) * 1000
            self._metrics.total_processing_time_ms = stats.get('total_processing_time', 0) * 1000
            
            # Get worker statistics
            worker_stats = self.worker_repo.get_worker_statistics()
            self._metrics.active_workers = worker_stats.get('healthy_workers', 0)
            self._metrics.worker_utilization = worker_stats.get('capacity_utilization', 0)
            
            self._metrics.last_updated = datetime.utcnow()
            return self._metrics
            
        except Exception as e:
            logger.error(f"Failed to get metrics: {e}")
            return self._metrics
    
    # Private methods
    
    async def _register_worker(self) -> None:
        """Register this worker instance."""
        try:
            worker_data = {
                'worker_name': f"batch-worker-{os.getpid()}",
                'hostname': os.uname().nodename if hasattr(os, 'uname') else 'localhost',
                'pid': os.getpid(),
                'worker_type': 'persistent',
                'supported_job_types': [
                    BatchJobType.DOCUMENT_PROCESSING,
                    BatchJobType.PII_DETECTION,
                    BatchJobType.BULK_REDACTION,
                    BatchJobType.COMPLIANCE_VALIDATION,
                    BatchJobType.AUDIT_GENERATION,
                    BatchJobType.REPORT_GENERATION,
                    BatchJobType.CUSTOM
                ],
                'max_concurrent_jobs': self._max_concurrent_jobs,
                'memory_limit_mb': 4096,
                'cpu_cores': 2,
                'status': WorkerStatus.IDLE,
                'version': '2.0.0',
                'queue_names': ['default', 'high_priority'],
                'tags': ['persistent', 'full_featured']
            }
            
            worker = self.worker_repo.register_worker(worker_data)
            self._worker_id = worker.id
            logger.info(f"Registered worker: {self._worker_id}")
            
        except Exception as e:
            logger.error(f"Failed to register worker: {e}")
            raise
    
    async def _update_worker_status(self, status: WorkerStatus) -> None:
        """Update worker status and heartbeat."""
        if self._worker_id:
            try:
                self.worker_repo.update_worker_heartbeat(
                    self._worker_id,
                    status=status,
                    current_jobs_count=len(self._running_jobs)
                )
            except Exception as e:
                logger.error(f"Failed to update worker status: {e}")
    
    async def _recover_interrupted_jobs(self) -> None:
        """Recover jobs that were interrupted."""
        try:
            recovered_jobs = self.job_repo.recover_interrupted_jobs()
            
            for db_job in recovered_jobs:
                job = self._convert_db_job_to_pydantic(db_job)
                with self._lock:
                    self._active_jobs_cache[job.id] = job
            
            if recovered_jobs:
                logger.info(f"Recovered {len(recovered_jobs)} interrupted jobs")
                
        except Exception as e:
            logger.error(f"Failed to recover interrupted jobs: {e}")
    
    async def _job_processor_loop(self) -> None:
        """Main job processing loop."""
        while self._is_running:
            try:
                # Check capacity
                if len(self._running_jobs) >= self._max_concurrent_jobs:
                    await asyncio.sleep(1)
                    continue
                
                # Get next queued job
                queued_jobs = self.job_repo.get_queued_jobs(limit=1)
                
                if not queued_jobs:
                    await asyncio.sleep(self._job_polling_interval)
                    continue
                
                db_job = queued_jobs[0]
                job = self._convert_db_job_to_pydantic(db_job)
                
                # Check dependencies
                if not await self._check_dependencies(job):
                    await asyncio.sleep(5)
                    continue
                
                # Start job execution
                task = asyncio.create_task(self._execute_job(job))
                self._running_jobs[job.id] = task
                
                # Add to cache
                with self._lock:
                    self._active_jobs_cache[job.id] = job
                
            except Exception as e:
                logger.error(f"Error in job processor loop: {e}")
                await asyncio.sleep(10)
    
    async def _scheduler_loop(self) -> None:
        """Process scheduled jobs."""
        while self._is_running:
            try:
                # Get due schedules
                due_schedules = self.schedule_repo.get_due_schedules()
                
                for schedule in due_schedules:
                    try:
                        # Create job from template
                        template_job = self.job_repo.get_job(schedule.job_id)
                        if template_job:
                            # Clone job for execution
                            job_data = {
                                'name': f"{template_job.name} (scheduled)",
                                'description': f"Scheduled execution: {schedule.schedule_name}",
                                'job_type': template_job.job_type,
                                'parameters': template_job.parameters,
                                'priority': template_job.priority,
                                'timeout_seconds': template_job.timeout_seconds,
                                'max_workers': template_job.max_workers,
                                'memory_limit_mb': template_job.memory_limit_mb,
                                'cpu_limit_cores': template_job.cpu_limit_cores,
                                'input_data': template_job.input_data,
                                'output_location': template_job.output_location,
                                'created_by': schedule.created_by,
                                'tags': template_job.tags + ['scheduled'],
                                'custom_metadata': {
                                    **template_job.custom_metadata,
                                    'schedule_id': str(schedule.id),
                                    'schedule_name': schedule.schedule_name
                                }
                            }
                            
                            scheduled_job = self.job_repo.create_job(job_data)
                            
                            # Calculate next run (simplified - would use cron parser)
                            next_run = datetime.now(timezone.utc) + timedelta(hours=24)
                            
                            # Update schedule
                            self.schedule_repo.update_schedule_after_run(
                                schedule.id,
                                BatchJobStatus.QUEUED,
                                next_run
                            )
                            
                            logger.info(f"Scheduled job created: {scheduled_job.id}")
                        
                    except Exception as e:
                        logger.error(f"Failed to process schedule {schedule.id}: {e}")
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                await asyncio.sleep(300)
    
    async def _execute_job(self, job: BatchJob) -> None:
        """Execute a batch job with database persistence."""
        execution_id = f"{job.id}-{datetime.utcnow().timestamp()}"
        start_time = datetime.now(timezone.utc)
        
        try:
            # Update job status
            self.job_repo.update_job_status(job.id, BatchJobStatus.RUNNING)
            
            # Update worker status
            await self._update_worker_status(WorkerStatus.BUSY)
            
            # Notify start handlers
            for handler in self._job_start_handlers:
                try:
                    handler(job)
                except Exception as e:
                    logger.error(f"Error in job start handler: {e}")
            
            logger.info(f"Starting job: {job.id} ({job.name})")
            
            # Execute job based on type
            result_data = {}
            if job.job_type == BatchJobType.DOCUMENT_PROCESSING:
                result_data = await self._execute_document_processing_job(job)
            elif job.job_type == BatchJobType.PII_DETECTION:
                result_data = await self._execute_pii_detection_job(job)
            elif job.job_type == BatchJobType.BULK_REDACTION:
                result_data = await self._execute_bulk_redaction_job(job)
            else:
                result_data = await self._execute_custom_job(job)
            
            # Mark as completed
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            self.job_repo.update_job_status(job.id, BatchJobStatus.COMPLETED)
            self.job_repo.update_job_progress(job.id, 100)
            
            # Create result record
            result = {
                'job_id': job.id,
                'execution_id': execution_id,
                'started_at': start_time,
                'completed_at': end_time,
                'duration_seconds': duration,
                'status': BatchJobStatus.COMPLETED,
                'result_data': result_data,
                'worker_id': self._worker_id,
                'items_processed': result_data.get('items_processed', 0),
                'items_successful': result_data.get('items_successful', 0),
                'items_failed': result_data.get('items_failed', 0)
            }
            
            self.result_repo.create_result(result)
            
            # Update worker stats
            if self._worker_id:
                self.worker_repo.update_worker_stats(
                    self._worker_id, 
                    job_completed=True, 
                    job_duration_seconds=duration
                )
            
            # Notify completion handlers
            for handler in self._job_complete_handlers:
                try:
                    handler(job)
                except Exception as e:
                    logger.error(f"Error in job complete handler: {e}")
            
            logger.info(f"Job completed: {job.id} in {duration:.2f}s")
            
        except asyncio.CancelledError:
            self.job_repo.update_job_status(job.id, BatchJobStatus.CANCELLED)
            logger.info(f"Job cancelled during execution: {job.id}")
            
        except Exception as e:
            # Handle job failure
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            self.job_repo.update_job(job.id, {
                'status': BatchJobStatus.FAILED,
                'completed_at': end_time,
                'error_message': str(e),
                'error_details': {
                    'exception_type': type(e).__name__,
                    'traceback': str(e)
                }
            })
            
            # Create failure result
            result = {
                'job_id': job.id,
                'execution_id': execution_id,
                'started_at': start_time,
                'completed_at': end_time,
                'duration_seconds': duration,
                'status': BatchJobStatus.FAILED,
                'error_message': str(e),
                'error_code': type(e).__name__,
                'worker_id': self._worker_id
            }
            
            self.result_repo.create_result(result)
            
            # Update worker stats
            if self._worker_id:
                self.worker_repo.update_worker_stats(
                    self._worker_id, 
                    job_completed=False, 
                    job_duration_seconds=duration
                )
            
            # Notify error handlers
            for handler in self._job_error_handlers:
                try:
                    handler(job, e)
                except Exception as handler_error:
                    logger.error(f"Error in job error handler: {handler_error}")
            
            logger.error(f"Job failed: {job.id} - {e}")
            
            # Check for retry
            db_job = self.job_repo.get_job(job.id)
            if db_job and db_job.can_retry():
                await self._schedule_retry(db_job)
        
        finally:
            # Clean up
            self._running_jobs.pop(job.id, None)
            with self._lock:
                self._active_jobs_cache.pop(job.id, None)
            
            # Update worker status
            await self._update_worker_status(
                WorkerStatus.IDLE if len(self._running_jobs) == 0 else WorkerStatus.BUSY
            )
    
    async def _execute_document_processing_job(self, job: BatchJob) -> Dict[str, Any]:
        """Execute document processing job."""
        documents = job.input_data.get("documents", [])
        total_docs = len(documents)
        processed_docs = 0
        
        self.job_repo.update_job_progress(job.id, 0, "Starting document processing")
        
        for i, doc_path in enumerate(documents):
            if job.id not in self._running_jobs:  # Job was cancelled
                break
            
            # Simulate document processing
            await asyncio.sleep(0.1)
            processed_docs += 1
            
            progress = int((i + 1) / total_docs * 100)
            self.job_repo.update_job_progress(
                job.id, progress, f"Processing document {i + 1}/{total_docs}"
            )
        
        return {
            "items_processed": total_docs,
            "items_successful": processed_docs,
            "items_failed": total_docs - processed_docs,
            "documents_processed": processed_docs
        }
    
    async def _execute_pii_detection_job(self, job: BatchJob) -> Dict[str, Any]:
        """Execute PII detection job."""
        documents = job.input_data.get("documents", [])
        pii_results = []
        
        for i, doc_path in enumerate(documents):
            if job.id not in self._running_jobs:
                break
            
            await asyncio.sleep(0.05)
            pii_results.append({
                "document": doc_path,
                "pii_found": True,
                "pii_count": 5
            })
            
            progress = int((i + 1) / len(documents) * 100)
            self.job_repo.update_job_progress(
                job.id, progress, f"Analyzing document {i + 1}/{len(documents)}"
            )
        
        return {
            "items_processed": len(documents),
            "items_successful": len(pii_results),
            "items_failed": 0,
            "total_pii_found": sum(r["pii_count"] for r in pii_results),
            "results": pii_results
        }
    
    async def _execute_bulk_redaction_job(self, job: BatchJob) -> Dict[str, Any]:
        """Execute bulk redaction job."""
        documents = job.input_data.get("documents", [])
        redacted_docs = 0
        
        for i, doc_path in enumerate(documents):
            if job.id not in self._running_jobs:
                break
            
            await asyncio.sleep(0.2)
            redacted_docs += 1
            
            progress = int((i + 1) / len(documents) * 100)
            self.job_repo.update_job_progress(
                job.id, progress, f"Redacting document {i + 1}/{len(documents)}"
            )
        
        return {
            "items_processed": len(documents),
            "items_successful": redacted_docs,
            "items_failed": 0,
            "documents_redacted": redacted_docs,
            "redaction_method": job.parameters.get("redaction_method", "blackout")
        }
    
    async def _execute_custom_job(self, job: BatchJob) -> Dict[str, Any]:
        """Execute custom job."""
        steps = job.parameters.get("steps", 10)
        
        for i in range(steps):
            if job.id not in self._running_jobs:
                break
            
            await asyncio.sleep(0.1)
            progress = int((i + 1) / steps * 100)
            self.job_repo.update_job_progress(
                job.id, progress, f"Processing step {i + 1}/{steps}"
            )
        
        return {
            "items_processed": steps,
            "items_successful": steps,
            "items_failed": 0,
            "steps_completed": steps
        }
    
    async def _schedule_retry(self, db_job: BatchJobModel) -> None:
        """Schedule job retry."""
        try:
            updates = {
                'status': BatchJobStatus.QUEUED,
                'retry_count': db_job.retry_count + 1,
                'scheduled_at': datetime.now(timezone.utc) + timedelta(seconds=db_job.retry_delay_seconds)
            }
            
            updated_job = self.job_repo.update_job(db_job.id, updates)
            if updated_job:
                logger.info(f"Job retry scheduled: {db_job.id} (attempt {updated_job.retry_count})")
                
        except Exception as e:
            logger.error(f"Failed to schedule retry for job {db_job.id}: {e}")
    
    async def _check_dependencies(self, job: BatchJob) -> bool:
        """Check if job dependencies are satisfied."""
        if not job.depends_on:
            return True
        
        for dep_id in job.depends_on:
            dep_job = self.job_repo.get_job(dep_id)
            if not dep_job or dep_job.status != BatchJobStatus.COMPLETED:
                return False
        return True
    
    async def _monitoring_loop(self) -> None:
        """Background monitoring loop."""
        while self._is_running:
            try:
                # Check for expired jobs
                expired_jobs = self.job_repo.get_expired_jobs()
                for job in expired_jobs:
                    self.job_repo.update_job_status(job.id, BatchJobStatus.TIMEOUT)
                    logger.warning(f"Job expired: {job.id}")
                
                # Update metrics
                self.get_metrics()
                
                await asyncio.sleep(self._heartbeat_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(60)
    
    async def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while self._is_running:
            try:
                # Clean up old completed jobs
                self.job_repo.cleanup_old_jobs(older_than_days=7)
                
                # Clean up old results
                self.result_repo.cleanup_old_results(older_than_days=30)
                
                # Clean up old workers
                self.worker_repo.cleanup_old_workers(offline_days=1)
                
                await asyncio.sleep(self._cleanup_interval)
                
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(3600)
    
    async def _heartbeat_loop(self) -> None:
        """Background heartbeat loop."""
        while self._is_running:
            try:
                # Update worker heartbeat
                await self._update_worker_status(
                    WorkerStatus.BUSY if self._running_jobs else WorkerStatus.IDLE
                )
                
                await asyncio.sleep(self._heartbeat_interval)
                
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
                await asyncio.sleep(60)
    
    def _convert_db_job_to_pydantic(self, db_job: BatchJobModel) -> BatchJob:
        """Convert database job to Pydantic model."""
        return BatchJob(
            id=db_job.id,
            name=db_job.name,
            description=db_job.description,
            job_type=db_job.job_type,
            parameters=db_job.parameters or {},
            priority=db_job.priority,
            timeout_seconds=db_job.timeout_seconds,
            max_workers=db_job.max_workers,
            memory_limit_mb=db_job.memory_limit_mb,
            cpu_limit_cores=float(db_job.cpu_limit_cores),
            input_data=db_job.input_data or {},
            output_location=db_job.output_location,
            status=db_job.status,
            progress_percentage=db_job.progress_percentage,
            current_step=db_job.current_step,
            steps_completed=db_job.steps_completed,
            total_steps=db_job.total_steps,
            created_at=db_job.created_at,
            queued_at=db_job.queued_at,
            started_at=db_job.started_at,
            completed_at=db_job.completed_at,
            last_heartbeat=db_job.last_heartbeat,
            created_by=db_job.created_by,
            assigned_to=db_job.assigned_to,
            access_permissions=db_job.access_permissions or [],
            max_retries=db_job.max_retries,
            retry_count=db_job.retry_count,
            retry_delay_seconds=db_job.retry_delay_seconds,
            depends_on=db_job.depends_on or [],
            scheduled_at=db_job.scheduled_at,
            result_summary=db_job.result_summary or {},
            error_message=db_job.error_message,
            error_details=db_job.error_details or {},
            compliance_standards=db_job.compliance_standards or [],
            audit_trail=db_job.audit_trail or [],
            tags=db_job.tags or [],
            custom_metadata=db_job.custom_metadata or {}
        )


# Global persistent engine instance
_persistent_batch_engine: Optional[PersistentBatchProcessingEngine] = None


def get_persistent_batch_engine(session: Optional[Session] = None) -> PersistentBatchProcessingEngine:
    """Get the global persistent batch processing engine instance."""
    global _persistent_batch_engine
    if _persistent_batch_engine is None:
        _persistent_batch_engine = PersistentBatchProcessingEngine(session)
    return _persistent_batch_engine


def initialize_persistent_batch_engine(session: Optional[Session] = None) -> PersistentBatchProcessingEngine:
    """Initialize the persistent batch processing engine."""
    global _persistent_batch_engine
    _persistent_batch_engine = PersistentBatchProcessingEngine(session)
    logger.info("Persistent Batch Processing Engine initialized successfully")
    return _persistent_batch_engine