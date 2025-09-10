"""
Batch Worker Repository for Database Persistence
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID
import os

from sqlalchemy import and_, desc, func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from ..models import BatchWorker, WorkerStatus
from ..session import transaction_scope
from .base import BaseRepository

logger = logging.getLogger(__name__)


class BatchWorkerRepository(BaseRepository[BatchWorker]):
    """Repository for batch worker operations."""
    
    def __init__(self, session: Optional[Session] = None):
        super().__init__(BatchWorker, session)
    
    def register_worker(self, worker_data: Dict[str, Any]) -> BatchWorker:
        """
        Register a new batch worker.
        
        Args:
            worker_data: Dictionary containing worker configuration
            
        Returns:
            Created or updated BatchWorker instance
        """
        try:
            with transaction_scope(self.session) as session:
                # Set default values
                worker_data.setdefault('hostname', os.uname().nodename if hasattr(os, 'uname') else 'localhost')
                worker_data.setdefault('pid', os.getpid())
                worker_data.setdefault('worker_type', 'standard')
                worker_data.setdefault('supported_job_types', [])
                worker_data.setdefault('max_concurrent_jobs', 1)
                worker_data.setdefault('memory_limit_mb', 2048)
                worker_data.setdefault('cpu_cores', 1)
                worker_data.setdefault('status', WorkerStatus.IDLE)
                worker_data.setdefault('version', '1.0.0')
                worker_data.setdefault('queue_names', [])
                worker_data.setdefault('tags', [])
                worker_data.setdefault('configuration', {})
                worker_data.setdefault('started_at', datetime.now(timezone.utc))
                worker_data.setdefault('last_heartbeat', datetime.now(timezone.utc))
                
                # Check if worker already exists (same hostname + pid)
                existing_worker = session.query(BatchWorker).filter(
                    and_(
                        BatchWorker.hostname == worker_data['hostname'],
                        BatchWorker.pid == worker_data['pid']
                    )
                ).first()
                
                if existing_worker:
                    # Update existing worker
                    for key, value in worker_data.items():
                        if key not in ['id', 'started_at', 'total_jobs_processed', 'total_jobs_failed']:
                            setattr(existing_worker, key, value)
                    
                    existing_worker.last_heartbeat = datetime.now(timezone.utc)
                    session.flush()
                    logger.info(f"Updated existing worker: {existing_worker.id}")
                    return existing_worker
                else:
                    # Create new worker
                    worker = BatchWorker(**worker_data)
                    session.add(worker)
                    session.flush()
                    logger.info(f"Registered new worker: {worker.id} ({worker.worker_name})")
                    return worker
                    
        except IntegrityError as e:
            # Handle unique constraint violations
            logger.error(f"Worker registration failed due to integrity constraint: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to register worker: {e}")
            raise
    
    def update_worker_heartbeat(self, worker_id: UUID, 
                               status: Optional[WorkerStatus] = None,
                               current_jobs_count: Optional[int] = None,
                               memory_usage_mb: Optional[int] = None,
                               cpu_usage_percent: Optional[float] = None) -> bool:
        """
        Update worker heartbeat and status.
        
        Args:
            worker_id: Worker UUID
            status: New status (optional)
            current_jobs_count: Current number of jobs (optional)
            memory_usage_mb: Current memory usage (optional)
            cpu_usage_percent: Current CPU usage (optional)
            
        Returns:
            True if successful
        """
        try:
            with transaction_scope(self.session) as session:
                worker = session.query(BatchWorker).filter(BatchWorker.id == worker_id).first()
                if not worker:
                    return False
                
                worker.last_heartbeat = datetime.now(timezone.utc)
                
                if status:
                    worker.status = status
                if current_jobs_count is not None:
                    worker.current_jobs_count = current_jobs_count
                if memory_usage_mb is not None:
                    worker.current_memory_usage_mb = memory_usage_mb
                if cpu_usage_percent is not None:
                    worker.current_cpu_usage_percent = cpu_usage_percent
                
                session.flush()
                return True
                
        except Exception as e:
            logger.error(f"Failed to update worker heartbeat {worker_id}: {e}")
            return False
    
    def get_available_workers(self, job_type: Optional[str] = None,
                             min_memory_mb: Optional[int] = None,
                             required_tags: Optional[List[str]] = None) -> List[BatchWorker]:
        """
        Get available workers that can accept jobs.
        
        Args:
            job_type: Required job type support (optional)
            min_memory_mb: Minimum memory requirement (optional)
            required_tags: Required worker tags (optional)
            
        Returns:
            List of available BatchWorker instances
        """
        try:
            # Workers are available if they're idle and healthy
            query = self.session.query(BatchWorker).filter(
                and_(
                    BatchWorker.status.in_([WorkerStatus.IDLE, WorkerStatus.BUSY]),
                    BatchWorker.current_jobs_count < BatchWorker.max_concurrent_jobs
                )
            )
            
            # Filter by job type support
            if job_type:
                query = query.filter(BatchWorker.supported_job_types.contains([job_type]))
            
            # Filter by memory requirement
            if min_memory_mb:
                query = query.filter(BatchWorker.memory_limit_mb >= min_memory_mb)
            
            # Filter by required tags
            if required_tags:
                for tag in required_tags:
                    query = query.filter(BatchWorker.tags.contains([tag]))
            
            # Only include healthy workers (recent heartbeat)
            heartbeat_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
            query = query.filter(BatchWorker.last_heartbeat >= heartbeat_cutoff)
            
            # Order by load (least loaded first)
            return query.all()
            
        except Exception as e:
            logger.error(f"Failed to get available workers: {e}")
            return []
    
    def get_best_worker_for_job(self, job_type: str,
                               memory_requirement_mb: int = 1024,
                               cpu_requirement: float = 1.0,
                               required_tags: Optional[List[str]] = None) -> Optional[BatchWorker]:
        """
        Get the best available worker for a specific job.
        
        Args:
            job_type: Job type
            memory_requirement_mb: Memory requirement
            cpu_requirement: CPU requirement
            required_tags: Required tags
            
        Returns:
            Best available BatchWorker or None
        """
        try:
            available_workers = self.get_available_workers(
                job_type=job_type,
                min_memory_mb=memory_requirement_mb,
                required_tags=required_tags
            )
            
            if not available_workers:
                return None
            
            # Score workers based on:
            # 1. Current load (lower is better)
            # 2. Available memory (more is better)  
            # 3. Success rate (higher is better)
            # 4. Recent activity (more recent is better)
            
            best_worker = None
            best_score = -1
            
            for worker in available_workers:
                if not worker.can_accept_job(job_type):
                    continue
                
                # Calculate load score (0-1, lower is better)
                load_score = 1.0 - (worker.get_load_percentage() / 100.0)
                
                # Calculate memory score (0-1, higher available memory is better)
                memory_score = min(1.0, worker.memory_limit_mb / (memory_requirement_mb * 2))
                
                # Calculate success rate score (0-1, higher is better)
                success_score = (worker.success_rate or 50.0) / 100.0
                
                # Calculate recency score (0-1, more recent heartbeat is better)
                if worker.last_heartbeat:
                    minutes_since_heartbeat = (datetime.now(timezone.utc) - worker.last_heartbeat).total_seconds() / 60.0
                    recency_score = max(0.0, 1.0 - (minutes_since_heartbeat / 60.0))  # Decay over 1 hour
                else:
                    recency_score = 0.0
                
                # Weighted total score
                total_score = (
                    load_score * 0.4 +
                    memory_score * 0.3 +
                    success_score * 0.2 +
                    recency_score * 0.1
                )
                
                if total_score > best_score:
                    best_score = total_score
                    best_worker = worker
            
            if best_worker:
                logger.debug(f"Selected worker {best_worker.id} with score {best_score:.3f}")
            
            return best_worker
            
        except Exception as e:
            logger.error(f"Failed to get best worker for job: {e}")
            return None
    
    def update_worker_stats(self, worker_id: UUID,
                           job_completed: bool = True,
                           job_duration_seconds: Optional[float] = None) -> bool:
        """
        Update worker statistics after job completion.
        
        Args:
            worker_id: Worker UUID
            job_completed: Whether job completed successfully
            job_duration_seconds: Job duration
            
        Returns:
            True if successful
        """
        try:
            with transaction_scope(self.session) as session:
                worker = session.query(BatchWorker).filter(BatchWorker.id == worker_id).first()
                if not worker:
                    return False
                
                worker.total_jobs_processed += 1
                worker.last_job_completed_at = datetime.now(timezone.utc)
                
                if not job_completed:
                    worker.total_jobs_failed += 1
                    worker.consecutive_failures += 1
                else:
                    worker.consecutive_failures = 0
                
                # Update success rate
                if worker.total_jobs_processed > 0:
                    successful_jobs = worker.total_jobs_processed - worker.total_jobs_failed
                    worker.success_rate = (successful_jobs / worker.total_jobs_processed) * 100
                
                # Update average duration
                if job_duration_seconds and job_completed:
                    if worker.average_job_duration_seconds:
                        # Running average
                        weight = min(0.1, 1.0 / worker.total_jobs_processed)
                        worker.average_job_duration_seconds = (
                            worker.average_job_duration_seconds * (1 - weight) +
                            job_duration_seconds * weight
                        )
                    else:
                        worker.average_job_duration_seconds = job_duration_seconds
                
                session.flush()
                logger.debug(f"Updated stats for worker {worker_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to update worker stats {worker_id}: {e}")
            return False
    
    def get_inactive_workers(self, inactive_timeout: int = 600) -> List[BatchWorker]:
        """
        Get workers that haven't sent a heartbeat recently.
        
        Args:
            inactive_timeout: Seconds since last heartbeat to consider inactive
            
        Returns:
            List of inactive BatchWorker instances
        """
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=inactive_timeout)
            
            return self.session.query(BatchWorker).filter(
                and_(
                    BatchWorker.status != WorkerStatus.OFFLINE,
                    BatchWorker.last_heartbeat < cutoff_time
                )
            ).all()
            
        except Exception as e:
            logger.error(f"Failed to get inactive workers: {e}")
            return []
    
    def mark_workers_offline(self, worker_ids: List[UUID]) -> int:
        """
        Mark specified workers as offline.
        
        Args:
            worker_ids: List of worker UUIDs
            
        Returns:
            Number of workers marked offline
        """
        try:
            with transaction_scope(self.session) as session:
                count = session.query(BatchWorker).filter(
                    BatchWorker.id.in_(worker_ids)
                ).update(
                    {
                        "status": WorkerStatus.OFFLINE,
                        "current_jobs_count": 0
                    },
                    synchronize_session=False
                )
                
                logger.info(f"Marked {count} workers as offline")
                return count
                
        except Exception as e:
            logger.error(f"Failed to mark workers offline: {e}")
            return 0
    
    def cleanup_old_workers(self, offline_days: int = 7) -> int:
        """
        Clean up workers that have been offline for too long.
        
        Args:
            offline_days: Delete workers offline for more than this many days
            
        Returns:
            Number of workers deleted
        """
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=offline_days)
            
            with transaction_scope(self.session) as session:
                count = session.query(BatchWorker).filter(
                    and_(
                        BatchWorker.status == WorkerStatus.OFFLINE,
                        BatchWorker.last_heartbeat < cutoff_date
                    )
                ).count()
                
                session.query(BatchWorker).filter(
                    and_(
                        BatchWorker.status == WorkerStatus.OFFLINE,
                        BatchWorker.last_heartbeat < cutoff_date
                    )
                ).delete(synchronize_session=False)
                
                logger.info(f"Cleaned up {count} old offline workers")
                return count
                
        except Exception as e:
            logger.error(f"Failed to cleanup old workers: {e}")
            return 0
    
    def get_worker_statistics(self) -> Dict[str, Any]:
        """Get overall worker statistics."""
        try:
            total_workers = self.session.query(BatchWorker).count()
            
            status_counts = {}
            for status in [WorkerStatus.IDLE, WorkerStatus.BUSY, WorkerStatus.OFFLINE, 
                          WorkerStatus.ERROR, WorkerStatus.MAINTENANCE]:
                count = self.session.query(BatchWorker).filter(
                    BatchWorker.status == status
                ).count()
                status_counts[status.value if hasattr(status, 'value') else str(status)] = count
            
            # Get healthy workers (recent heartbeat)
            heartbeat_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
            healthy_workers = self.session.query(BatchWorker).filter(
                BatchWorker.last_heartbeat >= heartbeat_cutoff
            ).count()
            
            # Calculate total capacity
            total_capacity = self.session.query(
                func.sum(BatchWorker.max_concurrent_jobs)
            ).scalar() or 0
            
            current_load = self.session.query(
                func.sum(BatchWorker.current_jobs_count)
            ).scalar() or 0
            
            return {
                "total_workers": total_workers,
                "healthy_workers": healthy_workers,
                "status_counts": status_counts,
                "total_capacity": total_capacity,
                "current_load": current_load,
                "capacity_utilization": current_load / total_capacity if total_capacity > 0 else 0
            }
            
        except Exception as e:
            logger.error(f"Failed to get worker statistics: {e}")
            return {}