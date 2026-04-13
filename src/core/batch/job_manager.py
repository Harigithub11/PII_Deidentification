"""
Job Manager for Batch Processing

High-level job lifecycle operations, scheduling, and worker management
for the batch processing system.
"""

import logging
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable, Tuple
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field
import cron_descriptor
from croniter import croniter

from pydantic import BaseModel, Field, validator

from .engine import BatchJob, BatchStatus, BatchJobType, JobPriority, BatchProcessingEngine

logger = logging.getLogger(__name__)


class JobState(str, Enum):
    """Extended job states for management."""
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    RETRYING = "retrying"


class ScheduleType(str, Enum):
    """Types of job scheduling."""
    IMMEDIATE = "immediate"
    DELAYED = "delayed"
    CRON = "cron"
    INTERVAL = "interval"
    DEPENDENCY = "dependency"
    TRIGGER = "trigger"


@dataclass
class JobResult:
    """Comprehensive job result with detailed information."""
    job_id: UUID
    job_name: str
    status: JobState
    
    # Execution details
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    runtime_seconds: float = 0.0
    
    # Results
    result_data: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    # Success/failure details
    success: bool = True
    error_message: Optional[str] = None
    error_details: Dict[str, Any] = field(default_factory=dict)
    
    # Processing statistics
    items_processed: int = 0
    items_failed: int = 0
    items_skipped: int = 0
    
    # Resource usage
    memory_peak_mb: float = 0.0
    cpu_time_seconds: float = 0.0
    
    # Output information
    output_files: List[str] = field(default_factory=list)
    output_size_bytes: int = 0
    
    # Audit trail
    audit_entries: List[Dict[str, Any]] = field(default_factory=list)


class JobSchedule(BaseModel):
    """Job scheduling configuration."""
    
    schedule_type: ScheduleType
    
    # Immediate scheduling (no additional config needed)
    
    # Delayed scheduling
    delay_seconds: Optional[int] = Field(None, ge=0)
    scheduled_at: Optional[datetime] = None
    
    # Cron scheduling
    cron_expression: Optional[str] = None
    timezone: str = "UTC"
    
    # Interval scheduling
    interval_seconds: Optional[int] = Field(None, ge=60)
    max_runs: Optional[int] = Field(None, ge=1)
    run_count: int = 0
    
    # Dependency scheduling
    depends_on_jobs: List[UUID] = Field(default_factory=list)
    dependency_condition: str = "all_completed"  # all_completed, any_completed, all_success
    
    # Trigger scheduling
    trigger_condition: Optional[str] = None
    trigger_data: Dict[str, Any] = Field(default_factory=dict)
    
    # Schedule metadata
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    
    @validator('cron_expression')
    def validate_cron_expression(cls, v):
        if v:
            try:
                croniter(v)
            except Exception:
                raise ValueError('Invalid cron expression')
        return v
    
    def get_next_run_time(self, from_time: Optional[datetime] = None) -> Optional[datetime]:
        """Calculate next run time based on schedule type."""
        if not self.is_active:
            return None
        
        base_time = from_time or datetime.utcnow()
        
        if self.schedule_type == ScheduleType.IMMEDIATE:
            return base_time
        
        elif self.schedule_type == ScheduleType.DELAYED:
            if self.scheduled_at:
                return self.scheduled_at
            elif self.delay_seconds:
                return base_time + timedelta(seconds=self.delay_seconds)
        
        elif self.schedule_type == ScheduleType.CRON and self.cron_expression:
            cron = croniter(self.cron_expression, base_time)
            return cron.get_next(datetime)
        
        elif self.schedule_type == ScheduleType.INTERVAL and self.interval_seconds:
            if self.max_runs and self.run_count >= self.max_runs:
                return None
            
            if self.last_run:
                return self.last_run + timedelta(seconds=self.interval_seconds)
            else:
                return base_time + timedelta(seconds=self.interval_seconds)
        
        return None


class JobTemplate(BaseModel):
    """Reusable job template."""
    
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    
    # Template configuration
    job_type: BatchJobType
    default_parameters: Dict[str, Any] = Field(default_factory=dict)
    parameter_schema: Dict[str, Any] = Field(default_factory=dict)
    
    # Resource defaults
    default_priority: JobPriority = JobPriority.NORMAL
    default_timeout_seconds: int = 3600
    default_max_workers: int = 1
    
    # Template metadata
    category: str = "general"
    tags: List[str] = Field(default_factory=list)
    created_by: UUID
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    version: str = "1.0"
    
    # Usage statistics
    usage_count: int = 0
    success_rate: float = 0.0
    
    def create_job(self, 
                  name: str,
                  parameters: Dict[str, Any],
                  created_by: UUID,
                  **overrides) -> BatchJob:
        """Create a job from this template."""
        
        merged_params = {**self.default_parameters, **parameters}
        
        job_config = {
            "name": name,
            "job_type": self.job_type,
            "parameters": merged_params,
            "priority": self.default_priority,
            "timeout_seconds": self.default_timeout_seconds,
            "max_workers": self.default_max_workers,
            "created_by": created_by,
            **overrides
        }
        
        return BatchJob(**job_config)


class JobWorker:
    """Individual job worker with resource management and monitoring."""
    
    def __init__(self, worker_id: str, max_concurrent_jobs: int = 1):
        self.worker_id = worker_id
        self.max_concurrent_jobs = max_concurrent_jobs
        self.current_jobs: Dict[UUID, BatchJob] = {}
        self.total_jobs_processed = 0
        self.total_processing_time = 0.0
        self.is_active = True
        self.last_heartbeat = datetime.utcnow()
        self.stats = {
            "jobs_completed": 0,
            "jobs_failed": 0,
            "average_job_time": 0.0,
            "memory_usage_mb": 0.0,
            "cpu_usage_percent": 0.0
        }
    
    def can_accept_job(self) -> bool:
        """Check if worker can accept another job."""
        return (self.is_active and 
                len(self.current_jobs) < self.max_concurrent_jobs)
    
    async def assign_job(self, job: BatchJob) -> bool:
        """Assign job to this worker."""
        if not self.can_accept_job():
            return False
        
        self.current_jobs[job.id] = job
        job.assigned_to = UUID(self.worker_id)
        return True
    
    def complete_job(self, job_id: UUID, success: bool, runtime: float) -> None:
        """Mark job as completed and update stats."""
        if job_id in self.current_jobs:
            del self.current_jobs[job_id]
            
            self.total_jobs_processed += 1
            self.total_processing_time += runtime
            
            if success:
                self.stats["jobs_completed"] += 1
            else:
                self.stats["jobs_failed"] += 1
            
            # Update average job time
            if self.total_jobs_processed > 0:
                self.stats["average_job_time"] = (
                    self.total_processing_time / self.total_jobs_processed
                )
    
    def get_status(self) -> Dict[str, Any]:
        """Get worker status information."""
        return {
            "worker_id": self.worker_id,
            "is_active": self.is_active,
            "current_jobs": len(self.current_jobs),
            "max_concurrent_jobs": self.max_concurrent_jobs,
            "can_accept_job": self.can_accept_job(),
            "total_processed": self.total_jobs_processed,
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "stats": self.stats
        }


class JobScheduler:
    """Advanced job scheduler with cron support and dependency management."""
    
    def __init__(self, engine: BatchProcessingEngine):
        self.engine = engine
        self.scheduled_jobs: Dict[UUID, Tuple[BatchJob, JobSchedule]] = {}
        self.job_templates: Dict[UUID, JobTemplate] = {}
        self._scheduler_task: Optional[asyncio.Task] = None
        self._is_running = False
    
    async def start(self) -> None:
        """Start the job scheduler."""
        if self._is_running:
            return
        
        self._is_running = True
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("Job scheduler started")
    
    async def stop(self) -> None:
        """Stop the job scheduler."""
        self._is_running = False
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        logger.info("Job scheduler stopped")
    
    async def schedule_job(self, job: BatchJob, schedule: JobSchedule) -> UUID:
        """Schedule a job with specified schedule configuration."""
        
        # Calculate next run time
        next_run = schedule.get_next_run_time()
        if next_run:
            schedule.next_run = next_run
            self.scheduled_jobs[job.id] = (job, schedule)
            
            logger.info(f"Job scheduled: {job.id} for {next_run}")
            return job.id
        else:
            raise ValueError("Unable to determine next run time for schedule")
    
    async def unschedule_job(self, job_id: UUID) -> bool:
        """Remove job from schedule."""
        if job_id in self.scheduled_jobs:
            del self.scheduled_jobs[job_id]
            logger.info(f"Job unscheduled: {job_id}")
            return True
        return False
    
    def create_template(self, template: JobTemplate) -> UUID:
        """Create a reusable job template."""
        self.job_templates[template.id] = template
        logger.info(f"Job template created: {template.id} - {template.name}")
        return template.id
    
    def get_template(self, template_id: UUID) -> Optional[JobTemplate]:
        """Get job template by ID."""
        return self.job_templates.get(template_id)
    
    def list_templates(self, category: Optional[str] = None) -> List[JobTemplate]:
        """List available job templates."""
        templates = list(self.job_templates.values())
        if category:
            templates = [t for t in templates if t.category == category]
        return templates
    
    async def create_job_from_template(self, 
                                     template_id: UUID,
                                     name: str,
                                     parameters: Dict[str, Any],
                                     created_by: UUID,
                                     schedule: Optional[JobSchedule] = None,
                                     **overrides) -> UUID:
        """Create and optionally schedule job from template."""
        
        template = self.get_template(template_id)
        if not template:
            raise ValueError(f"Template not found: {template_id}")
        
        # Create job from template
        job = template.create_job(name, parameters, created_by, **overrides)
        
        # Update template usage stats
        template.usage_count += 1
        
        if schedule:
            # Schedule the job
            return await self.schedule_job(job, schedule)
        else:
            # Submit immediately
            return await self.engine.submit_job(job)
    
    def get_scheduled_jobs(self) -> List[Dict[str, Any]]:
        """Get list of scheduled jobs with next run times."""
        scheduled = []
        for job_id, (job, schedule) in self.scheduled_jobs.items():
            scheduled.append({
                "job_id": str(job_id),
                "job_name": job.name,
                "job_type": job.job_type.value,
                "schedule_type": schedule.schedule_type.value,
                "next_run": schedule.next_run.isoformat() if schedule.next_run else None,
                "is_active": schedule.is_active
            })
        return scheduled
    
    async def _scheduler_loop(self) -> None:
        """Main scheduler loop that checks for jobs to run."""
        while self._is_running:
            try:
                current_time = datetime.utcnow()
                jobs_to_run = []
                
                # Check scheduled jobs
                for job_id, (job, schedule) in list(self.scheduled_jobs.items()):
                    if (schedule.next_run and 
                        schedule.next_run <= current_time and
                        schedule.is_active):
                        
                        # Check dependencies if applicable
                        if schedule.schedule_type == ScheduleType.DEPENDENCY:
                            if not await self._check_dependency_condition(schedule):
                                continue
                        
                        jobs_to_run.append((job_id, job, schedule))
                
                # Submit jobs that are ready to run
                for job_id, job, schedule in jobs_to_run:
                    try:
                        # Submit job
                        await self.engine.submit_job(job)
                        
                        # Update schedule
                        schedule.last_run = current_time
                        schedule.run_count += 1
                        
                        # Calculate next run time
                        next_run = schedule.get_next_run_time(current_time)
                        if next_run:
                            schedule.next_run = next_run
                        else:
                            # No more runs, remove from schedule
                            del self.scheduled_jobs[job_id]
                            logger.info(f"Job schedule completed: {job_id}")
                        
                        logger.info(f"Scheduled job submitted: {job_id}")
                        
                    except Exception as e:
                        logger.error(f"Failed to submit scheduled job {job_id}: {e}")
                
                # Sleep before next check
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                await asyncio.sleep(60)
    
    async def _check_dependency_condition(self, schedule: JobSchedule) -> bool:
        """Check if dependency conditions are met."""
        if not schedule.depends_on_jobs:
            return True
        
        dependency_states = []
        for dep_job_id in schedule.depends_on_jobs:
            job = await self.engine.get_job(dep_job_id)
            if job:
                dependency_states.append(job.status)
            else:
                dependency_states.append(BatchStatus.FAILED)  # Missing job
        
        if schedule.dependency_condition == "all_completed":
            return all(state in [BatchStatus.COMPLETED, BatchStatus.FAILED] 
                      for state in dependency_states)
        
        elif schedule.dependency_condition == "any_completed":
            return any(state in [BatchStatus.COMPLETED, BatchStatus.FAILED] 
                      for state in dependency_states)
        
        elif schedule.dependency_condition == "all_success":
            return all(state == BatchStatus.COMPLETED for state in dependency_states)
        
        return False


class JobManager:
    """
    High-level job manager that provides advanced job lifecycle operations,
    workflow management, and integration with scheduling and monitoring.
    """
    
    def __init__(self, engine: BatchProcessingEngine):
        self.engine = engine
        self.scheduler = JobScheduler(engine)
        self.workers: Dict[str, JobWorker] = {}
        
        # Job workflows and chains
        self.job_workflows: Dict[UUID, List[UUID]] = {}
        self.job_chains: Dict[UUID, Dict[str, Any]] = {}
        
        # Job results storage
        self.job_results: Dict[UUID, JobResult] = {}
        
        # Event tracking
        self.event_handlers: Dict[str, List[Callable]] = {
            "job_created": [],
            "job_started": [],
            "job_completed": [],
            "job_failed": [],
            "workflow_completed": []
        }
        
        # Setup engine event handlers
        self.engine.on_job_complete(self._handle_job_completion)
        self.engine.on_job_error(self._handle_job_error)
    
    async def start(self) -> None:
        """Start the job manager and scheduler."""
        await self.scheduler.start()
        logger.info("Job Manager started")
    
    async def stop(self) -> None:
        """Stop the job manager and scheduler."""
        await self.scheduler.stop()
        logger.info("Job Manager stopped")
    
    async def create_job(self,
                        name: str,
                        job_type: BatchJobType,
                        parameters: Dict[str, Any],
                        created_by: UUID,
                        **kwargs) -> UUID:
        """Create and submit a new job."""
        
        job = BatchJob(
            name=name,
            job_type=job_type,
            parameters=parameters,
            created_by=created_by,
            **kwargs
        )
        
        job_id = await self.engine.submit_job(job)
        
        # Trigger event handlers
        await self._trigger_event("job_created", job)
        
        return job_id
    
    async def create_job_workflow(self,
                                 workflow_name: str,
                                 jobs: List[Dict[str, Any]],
                                 created_by: UUID) -> List[UUID]:
        """Create a workflow of dependent jobs."""
        
        job_ids = []
        previous_job_id = None
        
        for i, job_config in enumerate(jobs):
            # Set up dependencies
            depends_on = []
            if previous_job_id:
                depends_on.append(previous_job_id)
            
            # Add any additional dependencies
            if "depends_on" in job_config:
                depends_on.extend(job_config["depends_on"])
            
            # Create job
            job_name = f"{workflow_name} - Step {i+1}"
            if "name" in job_config:
                job_name = job_config["name"]
            
            job = BatchJob(
                name=job_name,
                job_type=BatchJobType(job_config["job_type"]),
                parameters=job_config.get("parameters", {}),
                depends_on=depends_on,
                created_by=created_by,
                **{k: v for k, v in job_config.items() 
                   if k not in ["name", "job_type", "parameters", "depends_on"]}
            )
            
            job_id = await self.engine.submit_job(job)
            job_ids.append(job_id)
            previous_job_id = job_id
        
        # Store workflow
        workflow_id = uuid4()
        self.job_workflows[workflow_id] = job_ids
        
        logger.info(f"Job workflow created: {workflow_name} with {len(job_ids)} jobs")
        return job_ids
    
    async def cancel_workflow(self, workflow_id: UUID) -> bool:
        """Cancel all jobs in a workflow."""
        if workflow_id not in self.job_workflows:
            return False
        
        job_ids = self.job_workflows[workflow_id]
        cancelled_count = 0
        
        for job_id in job_ids:
            if await self.engine.cancel_job(job_id):
                cancelled_count += 1
        
        logger.info(f"Cancelled {cancelled_count}/{len(job_ids)} jobs in workflow {workflow_id}")
        return cancelled_count > 0
    
    def add_worker(self, worker_id: str, max_concurrent_jobs: int = 1) -> None:
        """Add a job worker."""
        worker = JobWorker(worker_id, max_concurrent_jobs)
        self.workers[worker_id] = worker
        logger.info(f"Worker added: {worker_id}")
    
    def remove_worker(self, worker_id: str) -> bool:
        """Remove a job worker."""
        if worker_id in self.workers:
            worker = self.workers[worker_id]
            worker.is_active = False
            
            # Cancel current jobs
            for job_id in list(worker.current_jobs.keys()):
                asyncio.create_task(self.engine.cancel_job(job_id))
            
            del self.workers[worker_id]
            logger.info(f"Worker removed: {worker_id}")
            return True
        return False
    
    def get_worker_status(self) -> List[Dict[str, Any]]:
        """Get status of all workers."""
        return [worker.get_status() for worker in self.workers.values()]
    
    def get_job_result(self, job_id: UUID) -> Optional[JobResult]:
        """Get detailed job result."""
        return self.job_results.get(job_id)
    
    def get_workflow_status(self, workflow_id: UUID) -> Optional[Dict[str, Any]]:
        """Get status of workflow jobs."""
        if workflow_id not in self.job_workflows:
            return None
        
        job_ids = self.job_workflows[workflow_id]
        job_statuses = []
        
        for job_id in job_ids:
            job = asyncio.create_task(self.engine.get_job(job_id))
            # This would need to be async in real implementation
            job_statuses.append({
                "job_id": str(job_id),
                "status": "unknown"  # Would get actual status
            })
        
        return {
            "workflow_id": str(workflow_id),
            "total_jobs": len(job_ids),
            "jobs": job_statuses
        }
    
    def on_event(self, event_type: str, handler: Callable) -> None:
        """Register event handler."""
        if event_type in self.event_handlers:
            self.event_handlers[event_type].append(handler)
    
    async def _trigger_event(self, event_type: str, *args) -> None:
        """Trigger event handlers."""
        handlers = self.event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(*args)
                else:
                    handler(*args)
            except Exception as e:
                logger.error(f"Error in {event_type} event handler: {e}")
    
    def _handle_job_completion(self, job: BatchJob) -> None:
        """Handle job completion event from engine."""
        result = JobResult(
            job_id=job.id,
            job_name=job.name,
            status=JobState(job.status.value),
            started_at=job.started_at,
            completed_at=job.completed_at,
            runtime_seconds=job.get_runtime_seconds(),
            result_data=job.result_summary,
            success=job.status == BatchStatus.COMPLETED,
            audit_entries=job.audit_trail
        )
        
        self.job_results[job.id] = result
        
        # Update worker stats
        if job.assigned_to:
            worker_id = str(job.assigned_to)
            if worker_id in self.workers:
                self.workers[worker_id].complete_job(
                    job.id, 
                    result.success, 
                    result.runtime_seconds
                )
        
        # Trigger async event
        asyncio.create_task(self._trigger_event("job_completed", job, result))
    
    def _handle_job_error(self, job: BatchJob, error: Exception) -> None:
        """Handle job error event from engine."""
        result = JobResult(
            job_id=job.id,
            job_name=job.name,
            status=JobState.FAILED,
            started_at=job.started_at,
            completed_at=job.completed_at,
            runtime_seconds=job.get_runtime_seconds(),
            success=False,
            error_message=str(error),
            error_details=job.error_details,
            audit_entries=job.audit_trail
        )
        
        self.job_results[job.id] = result
        
        # Update worker stats
        if job.assigned_to:
            worker_id = str(job.assigned_to)
            if worker_id in self.workers:
                self.workers[worker_id].complete_job(
                    job.id, 
                    False, 
                    result.runtime_seconds
                )
        
        # Trigger async event
        asyncio.create_task(self._trigger_event("job_failed", job, error, result))