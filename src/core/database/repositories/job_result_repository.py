"""
Job Result Repository for Database Persistence
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID

from sqlalchemy import and_, desc, func
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from ..models import JobResult, BatchJob, BatchJobStatus
from ..session import transaction_scope
from .base import BaseRepository

logger = logging.getLogger(__name__)


class JobResultRepository(BaseRepository[JobResult]):
    """Repository for job result operations."""
    
    def __init__(self, session: Optional[Session] = None):
        super().__init__(JobResult, session)
    
    def create_result(self, result_data: Dict[str, Any]) -> JobResult:
        """
        Create a new job result.
        
        Args:
            result_data: Dictionary containing result information
            
        Returns:
            Created JobResult instance
        """
        try:
            with transaction_scope(self.session) as session:
                # Set default values
                result_data.setdefault('result_data', {})
                result_data.setdefault('output_files', [])
                result_data.setdefault('error_details', {})
                
                result = JobResult(**result_data)
                session.add(result)
                session.flush()
                
                logger.info(f"Created job result: {result.id} for job {result.job_id}")
                return result
                
        except Exception as e:
            logger.error(f"Failed to create job result: {e}")
            raise
    
    def get_results_for_job(self, job_id: UUID, 
                           limit: int = 10) -> List[JobResult]:
        """
        Get all results for a specific job.
        
        Args:
            job_id: Job UUID
            limit: Maximum results to return
            
        Returns:
            List of JobResult instances ordered by completion time
        """
        try:
            return self.session.query(JobResult).filter(
                JobResult.job_id == job_id
            ).order_by(desc(JobResult.completed_at)).limit(limit).all()
            
        except Exception as e:
            logger.error(f"Failed to get results for job {job_id}: {e}")
            return []
    
    def get_latest_result(self, job_id: UUID) -> Optional[JobResult]:
        """
        Get the latest result for a job.
        
        Args:
            job_id: Job UUID
            
        Returns:
            Latest JobResult instance or None
        """
        try:
            return self.session.query(JobResult).filter(
                JobResult.job_id == job_id
            ).order_by(desc(JobResult.completed_at)).first()
            
        except Exception as e:
            logger.error(f"Failed to get latest result for job {job_id}: {e}")
            return None
    
    def get_performance_metrics(self, 
                               worker_id: Optional[UUID] = None,
                               job_type: Optional[str] = None,
                               days_back: int = 30) -> Dict[str, Any]:
        """
        Get performance metrics for job results.
        
        Args:
            worker_id: Filter by worker (optional)
            job_type: Filter by job type (optional)
            days_back: Number of days to look back
            
        Returns:
            Dictionary with performance metrics
        """
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
            
            query = self.session.query(JobResult).filter(
                JobResult.completed_at >= cutoff_date
            )
            
            if worker_id:
                query = query.filter(JobResult.worker_id == worker_id)
            
            if job_type:
                query = query.join(BatchJob).filter(BatchJob.job_type == job_type)
            
            results = query.all()
            
            if not results:
                return {
                    "total_results": 0,
                    "average_duration_seconds": 0,
                    "success_rate": 0,
                    "average_memory_mb": 0,
                    "average_cpu_percent": 0,
                    "total_items_processed": 0
                }
            
            # Calculate metrics
            total_duration = sum(float(r.duration_seconds) for r in results)
            successful_results = [r for r in results if r.status == BatchJobStatus.COMPLETED]
            total_memory = sum(r.max_memory_mb for r in results if r.max_memory_mb)
            total_cpu = sum(float(r.avg_cpu_percent) for r in results if r.avg_cpu_percent)
            total_items = sum(r.items_processed for r in results)
            
            metrics = {
                "total_results": len(results),
                "average_duration_seconds": total_duration / len(results),
                "success_rate": len(successful_results) / len(results),
                "total_items_processed": total_items,
                "total_processing_time": total_duration
            }
            
            if total_memory > 0:
                memory_results = [r for r in results if r.max_memory_mb]
                metrics["average_memory_mb"] = total_memory / len(memory_results)
            else:
                metrics["average_memory_mb"] = 0
            
            if total_cpu > 0:
                cpu_results = [r for r in results if r.avg_cpu_percent]
                metrics["average_cpu_percent"] = total_cpu / len(cpu_results)
            else:
                metrics["average_cpu_percent"] = 0
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get performance metrics: {e}")
            return {}
    
    def cleanup_old_results(self, older_than_days: int = 90) -> int:
        """
        Clean up old job results.
        
        Args:
            older_than_days: Delete results older than this many days
            
        Returns:
            Number of results deleted
        """
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=older_than_days)
            
            with transaction_scope(self.session) as session:
                count = session.query(JobResult).filter(
                    JobResult.completed_at < cutoff_date
                ).count()
                
                session.query(JobResult).filter(
                    JobResult.completed_at < cutoff_date
                ).delete(synchronize_session=False)
                
                logger.info(f"Cleaned up {count} old job results")
                return count
                
        except Exception as e:
            logger.error(f"Failed to cleanup old results: {e}")
            return 0