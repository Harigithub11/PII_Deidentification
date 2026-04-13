"""
Batch Job Repository for Database Persistence
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Union
from uuid import UUID
from contextlib import contextmanager

from sqlalchemy import and_, or_, desc, asc, text, func
from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from ..models import (
    BatchJob, JobResult, JobSchedule, BatchWorker,
    BatchJobStatus, BatchJobType, JobPriority, WorkerStatus
)
from ..session import get_db_session, transaction_scope
from .base import BaseRepository

logger = logging.getLogger(__name__)


class BatchJobRepository(BaseRepository[BatchJob]):
    """Repository for batch job operations with comprehensive database persistence."""
    
    def __init__(self, session: Optional[Session] = None):
        super().__init__(BatchJob, session)
    
    def create_job(self, job_data: Dict[str, Any]) -> BatchJob:
        """
        Create a new batch job with validation.
        
        Args:
            job_data: Dictionary containing job configuration
            
        Returns:
            Created BatchJob instance
            
        Raises:
            ValueError: If job data is invalid
            IntegrityError: If job name already exists for user
        """
        try:
            with transaction_scope(self.session) as session:
                # Validate required fields
                required_fields = ['name', 'job_type', 'created_by']
                for field in required_fields:
                    if field not in job_data:
                        raise ValueError(f"Missing required field: {field}")
                
                # Convert string enums to proper values
                if isinstance(job_data.get('job_type'), str):
                    job_data['job_type'] = getattr(BatchJobType, job_data['job_type'].upper(), None)
                    if not job_data['job_type']:
                        raise ValueError("Invalid job_type")
                
                if isinstance(job_data.get('priority'), str):
                    job_data['priority'] = getattr(JobPriority, job_data['priority'].upper(), None)
                    if not job_data['priority']:
                        job_data['priority'] = JobPriority.NORMAL
                
                # Set default values
                job_data.setdefault('status', BatchJobStatus.PENDING)
                job_data.setdefault('parameters', {})
                job_data.setdefault('input_data', {})
                job_data.setdefault('result_summary', {})
                job_data.setdefault('error_details', {})
                job_data.setdefault('audit_trail', [])
                job_data.setdefault('tags', [])
                job_data.setdefault('custom_metadata', {})
                job_data.setdefault('access_permissions', [])
                job_data.setdefault('depends_on', [])
                job_data.setdefault('compliance_standards', [])
                
                # Create job
                job = BatchJob(**job_data)
                job.add_audit_entry("job_created", {
                    "job_type": job.job_type,
                    "priority": job.priority,
                    "created_by": str(job.created_by)
                })
                
                session.add(job)
                session.flush()  # Get the ID
                
                logger.info(f"Created batch job: {job.id} ({job.name})")
                return job
                
        except IntegrityError as e:
            logger.error(f"Failed to create job due to integrity constraint: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to create job: {e}")
            raise
    
    def get_job(self, job_id: UUID, include_relationships: bool = False) -> Optional[BatchJob]:
        """
        Get job by ID with optional relationship loading.
        
        Args:
            job_id: Job UUID
            include_relationships: Whether to eagerly load relationships
            
        Returns:
            BatchJob instance or None
        """
        try:
            query = self.session.query(BatchJob).filter(BatchJob.id == job_id)
            
            if include_relationships:
                query = query.options(
                    joinedload(BatchJob.creator),
                    joinedload(BatchJob.assignee),
                    joinedload(BatchJob.assigned_worker),
                    selectinload(BatchJob.job_results),
                    selectinload(BatchJob.schedules)
                )
            
            return query.first()
            
        except Exception as e:
            logger.error(f"Failed to get job {job_id}: {e}")
            return None
    
    def update_job(self, job_id: UUID, updates: Dict[str, Any], 
                   add_audit_entry: bool = True) -> Optional[BatchJob]:
        """
        Update job with validation and audit trail.
        
        Args:
            job_id: Job UUID
            updates: Dictionary of fields to update
            add_audit_entry: Whether to add audit entry
            
        Returns:
            Updated BatchJob instance or None
        """
        try:
            with transaction_scope(self.session) as session:
                job = session.query(BatchJob).filter(BatchJob.id == job_id).first()
                if not job:
                    return None
                
                # Track changes for audit
                changes = {}
                
                for field, value in updates.items():
                    if hasattr(job, field):
                        old_value = getattr(job, field)
                        if old_value != value:
                            changes[field] = {"old": old_value, "new": value}
                            setattr(job, field, value)
                
                # Update last heartbeat on any update
                job.last_heartbeat = datetime.now(timezone.utc)
                
                if add_audit_entry and changes:
                    job.add_audit_entry("job_updated", {"changes": changes})
                
                session.flush()
                logger.debug(f"Updated job {job_id} with changes: {list(changes.keys())}")
                return job
                
        except Exception as e:
            logger.error(f"Failed to update job {job_id}: {e}")
            return None
    
    def update_job_status(self, job_id: UUID, status: BatchJobStatus, 
                         message: str = None) -> bool:
        """
        Update job status with timestamp tracking.
        
        Args:
            job_id: Job UUID
            status: New status
            message: Optional message
            
        Returns:
            True if successful
        """
        try:
            with transaction_scope(self.session) as session:
                job = session.query(BatchJob).filter(BatchJob.id == job_id).first()
                if not job:
                    return False
                
                old_status = job.status
                job.status = status
                job.last_heartbeat = datetime.now(timezone.utc)
                
                # Update timing fields based on status
                now = datetime.now(timezone.utc)
                if status == BatchJobStatus.QUEUED and not job.queued_at:
                    job.queued_at = now
                elif status == BatchJobStatus.RUNNING and not job.started_at:
                    job.started_at = now
                elif status in [BatchJobStatus.COMPLETED, BatchJobStatus.FAILED, 
                              BatchJobStatus.CANCELLED, BatchJobStatus.TIMEOUT] and not job.completed_at:
                    job.completed_at = now
                
                job.add_audit_entry("status_changed", {
                    "old_status": old_status,
                    "new_status": status,
                    "message": message
                })
                
                session.flush()
                logger.info(f"Updated job {job_id} status: {old_status} -> {status}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to update job status {job_id}: {e}")
            return False
    
    def update_job_progress(self, job_id: UUID, percentage: int, 
                          step: str = None, steps_completed: int = None) -> bool:
        """
        Update job progress information.
        
        Args:
            job_id: Job UUID
            percentage: Progress percentage (0-100)
            step: Current step description
            steps_completed: Number of completed steps
            
        Returns:
            True if successful
        """
        try:
            with transaction_scope(self.session) as session:
                job = session.query(BatchJob).filter(BatchJob.id == job_id).first()
                if not job:
                    return False
                
                job.update_progress(percentage, step, steps_completed)
                
                session.flush()
                return True
                
        except Exception as e:
            logger.error(f"Failed to update job progress {job_id}: {e}")
            return False
    
    def find_jobs(self, 
                  status: Optional[BatchJobStatus] = None,
                  job_type: Optional[BatchJobType] = None,
                  created_by: Optional[UUID] = None,
                  assigned_to: Optional[UUID] = None,
                  assigned_worker_id: Optional[UUID] = None,
                  tags: Optional[List[str]] = None,
                  scheduled_before: Optional[datetime] = None,
                  created_after: Optional[datetime] = None,
                  created_before: Optional[datetime] = None,
                  priority: Optional[JobPriority] = None,
                  limit: int = 100,
                  offset: int = 0,
                  order_by: str = 'created_at',
                  order_desc: bool = True) -> List[BatchJob]:
        """
        Find jobs with comprehensive filtering.
        
        Args:
            status: Filter by job status
            job_type: Filter by job type
            created_by: Filter by creator
            assigned_to: Filter by assignee
            assigned_worker_id: Filter by assigned worker
            tags: Filter by tags (job must have all tags)
            scheduled_before: Filter by scheduled time
            created_after: Filter by creation time
            created_before: Filter by creation time
            priority: Filter by priority
            limit: Maximum results
            offset: Result offset
            order_by: Field to order by
            order_desc: Whether to order descending
            
        Returns:
            List of matching BatchJob instances
        """
        try:
            query = self.session.query(BatchJob)
            
            # Apply filters
            if status:
                query = query.filter(BatchJob.status == status)
            if job_type:
                query = query.filter(BatchJob.job_type == job_type)
            if created_by:
                query = query.filter(BatchJob.created_by == created_by)
            if assigned_to:
                query = query.filter(BatchJob.assigned_to == assigned_to)
            if assigned_worker_id:
                query = query.filter(BatchJob.assigned_worker_id == assigned_worker_id)
            if priority:
                query = query.filter(BatchJob.priority == priority)
            if tags:
                for tag in tags:
                    query = query.filter(BatchJob.tags.contains([tag]))
            if scheduled_before:
                query = query.filter(
                    and_(
                        BatchJob.scheduled_at.isnot(None),
                        BatchJob.scheduled_at <= scheduled_before
                    )
                )
            if created_after:
                query = query.filter(BatchJob.created_at >= created_after)
            if created_before:
                query = query.filter(BatchJob.created_at <= created_before)
            
            # Apply ordering
            if hasattr(BatchJob, order_by):
                order_field = getattr(BatchJob, order_by)
                query = query.order_by(desc(order_field) if order_desc else asc(order_field))
            
            # Apply pagination
            query = query.offset(offset).limit(limit)
            
            return query.all()
            
        except Exception as e:
            logger.error(f"Failed to find jobs: {e}")
            return []
    
    def get_queued_jobs(self, worker_type: str = None, 
                       job_types: List[str] = None,
                       limit: int = 10) -> List[BatchJob]:
        """
        Get queued jobs ordered by priority and creation time.
        
        Args:
            worker_type: Filter by supported worker type
            job_types: Filter by job types
            limit: Maximum results
            
        Returns:
            List of queued BatchJob instances ordered by priority
        """
        try:
            query = self.session.query(BatchJob).filter(
                BatchJob.status == BatchJobStatus.QUEUED
            )
            
            if job_types:
                query = query.filter(BatchJob.job_type.in_(job_types))
            
            # Check dependencies are satisfied
            query = query.filter(
                or_(
                    BatchJob.depends_on == [],
                    ~BatchJob.depends_on.op('@>')(
                        self.session.query(BatchJob.id).filter(
                            and_(
                                BatchJob.status != BatchJobStatus.COMPLETED,
                                BatchJob.id.in_(BatchJob.depends_on)
                            )
                        ).scalar_subquery()
                    )
                )
            )
            
            # Order by priority (urgent first) then creation time
            priority_order = text("""
                CASE priority
                    WHEN 'urgent' THEN 1
                    WHEN 'critical' THEN 2
                    WHEN 'high' THEN 3
                    WHEN 'normal' THEN 4
                    WHEN 'low' THEN 5
                END
            """)
            
            query = query.order_by(priority_order, BatchJob.created_at).limit(limit)
            
            return query.all()
            
        except Exception as e:
            logger.error(f"Failed to get queued jobs: {e}")
            return []
    
    def get_expired_jobs(self) -> List[BatchJob]:
        """Get jobs that have exceeded their timeout."""
        try:
            cutoff_time = datetime.now(timezone.utc)
            
            return self.session.query(BatchJob).filter(
                and_(
                    BatchJob.status == BatchJobStatus.RUNNING,
                    BatchJob.started_at.isnot(None),
                    func.extract('epoch', cutoff_time - BatchJob.started_at) > BatchJob.timeout_seconds
                )
            ).all()
            
        except Exception as e:
            logger.error(f"Failed to get expired jobs: {e}")
            return []
    
    def get_stale_jobs(self, heartbeat_timeout: int = 300) -> List[BatchJob]:
        """
        Get running jobs with stale heartbeats.
        
        Args:
            heartbeat_timeout: Seconds since last heartbeat to consider stale
            
        Returns:
            List of jobs with stale heartbeats
        """
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=heartbeat_timeout)
            
            return self.session.query(BatchJob).filter(
                and_(
                    BatchJob.status == BatchJobStatus.RUNNING,
                    or_(
                        BatchJob.last_heartbeat.is_(None),
                        BatchJob.last_heartbeat < cutoff_time
                    )
                )
            ).all()
            
        except Exception as e:
            logger.error(f"Failed to get stale jobs: {e}")
            return []
    
    def cleanup_old_jobs(self, older_than_days: int = 30) -> int:
        """
        Clean up old completed/failed jobs.
        
        Args:
            older_than_days: Delete jobs older than this many days
            
        Returns:
            Number of jobs deleted
        """
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=older_than_days)
            
            with transaction_scope(self.session) as session:
                count = session.query(BatchJob).filter(
                    and_(
                        BatchJob.status.in_([
                            BatchJobStatus.COMPLETED,
                            BatchJobStatus.FAILED,
                            BatchJobStatus.CANCELLED
                        ]),
                        BatchJob.completed_at < cutoff_date
                    )
                ).count()
                
                session.query(BatchJob).filter(
                    and_(
                        BatchJob.status.in_([
                            BatchJobStatus.COMPLETED,
                            BatchJobStatus.FAILED,
                            BatchJobStatus.CANCELLED
                        ]),
                        BatchJob.completed_at < cutoff_date
                    )
                ).delete(synchronize_session=False)
                
                logger.info(f"Cleaned up {count} old batch jobs")
                return count
                
        except Exception as e:
            logger.error(f"Failed to cleanup old jobs: {e}")
            return 0
    
    def get_job_statistics(self, created_by: Optional[UUID] = None,
                          days_back: int = 30) -> Dict[str, Any]:
        """
        Get job statistics for the specified period.
        
        Args:
            created_by: Filter by creator (optional)
            days_back: Number of days to look back
            
        Returns:
            Dictionary with job statistics
        """
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
            
            query = self.session.query(BatchJob).filter(
                BatchJob.created_at >= cutoff_date
            )
            
            if created_by:
                query = query.filter(BatchJob.created_by == created_by)
            
            jobs = query.all()
            
            stats = {
                "total_jobs": len(jobs),
                "by_status": {},
                "by_type": {},
                "by_priority": {},
                "average_duration_seconds": 0,
                "success_rate": 0,
                "total_processing_time": 0
            }
            
            completed_jobs = []
            total_runtime = 0
            
            for job in jobs:
                # Count by status
                status_key = job.status.value if hasattr(job.status, 'value') else str(job.status)
                stats["by_status"][status_key] = stats["by_status"].get(status_key, 0) + 1
                
                # Count by type
                type_key = job.job_type.value if hasattr(job.job_type, 'value') else str(job.job_type)
                stats["by_type"][type_key] = stats["by_type"].get(type_key, 0) + 1
                
                # Count by priority
                priority_key = job.priority.value if hasattr(job.priority, 'value') else str(job.priority)
                stats["by_priority"][priority_key] = stats["by_priority"].get(priority_key, 0) + 1
                
                # Calculate runtime for completed jobs
                if job.status in [BatchJobStatus.COMPLETED, BatchJobStatus.FAILED] and job.started_at and job.completed_at:
                    runtime = job.get_runtime_seconds()
                    total_runtime += runtime
                    if job.status == BatchJobStatus.COMPLETED:
                        completed_jobs.append(job)
            
            # Calculate averages
            total_finished = stats["by_status"].get("completed", 0) + stats["by_status"].get("failed", 0)
            if total_finished > 0:
                stats["success_rate"] = stats["by_status"].get("completed", 0) / total_finished
                stats["average_duration_seconds"] = total_runtime / total_finished
            
            stats["total_processing_time"] = total_runtime
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get job statistics: {e}")
            return {}
    
    def recover_interrupted_jobs(self) -> List[BatchJob]:
        """
        Find and recover jobs that were interrupted (e.g., due to server restart).
        
        Returns:
            List of jobs that were recovered
        """
        try:
            with transaction_scope(self.session) as session:
                # Find jobs that are marked as running but have no recent heartbeat
                stale_running_jobs = self.get_stale_jobs(heartbeat_timeout=600)  # 10 minutes
                
                recovered_jobs = []
                
                for job in stale_running_jobs:
                    # Check if job can be retried
                    if job.can_retry():
                        job.status = BatchJobStatus.QUEUED
                        job.retry_count += 1
                        job.add_audit_entry("job_recovered", {
                            "reason": "interrupted_process",
                            "retry_count": job.retry_count
                        })
                        recovered_jobs.append(job)
                        logger.info(f"Recovered interrupted job: {job.id}")
                    else:
                        # Mark as failed if no more retries
                        job.status = BatchJobStatus.FAILED
                        job.completed_at = datetime.now(timezone.utc)
                        job.error_message = "Job interrupted and max retries exceeded"
                        job.add_audit_entry("job_failed", {
                            "reason": "max_retries_exceeded_after_interruption"
                        })
                        logger.warning(f"Failed interrupted job (max retries): {job.id}")
                
                session.flush()
                logger.info(f"Recovered {len(recovered_jobs)} interrupted jobs")
                return recovered_jobs
                
        except Exception as e:
            logger.error(f"Failed to recover interrupted jobs: {e}")
            return []