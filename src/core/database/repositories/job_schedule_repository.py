"""
Job Schedule Repository for Database Persistence with Airflow Integration
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID
from croniter import croniter

from sqlalchemy import and_, desc, func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from ..models import JobSchedule, BatchJob, BatchJobStatus
from ..session import transaction_scope
from .base import BaseRepository

logger = logging.getLogger(__name__)


class JobScheduleRepository(BaseRepository[JobSchedule]):
    """Repository for job schedule operations."""
    
    def __init__(self, session: Optional[Session] = None):
        super().__init__(JobSchedule, session)
    
    def create_schedule(self, schedule_data: Dict[str, Any]) -> JobSchedule:
        """
        Create a new job schedule.
        
        Args:
            schedule_data: Dictionary containing schedule configuration
            
        Returns:
            Created JobSchedule instance
        """
        try:
            with transaction_scope(self.session) as session:
                # Validate required fields
                required_fields = ['job_id', 'schedule_name', 'cron_expression', 'created_by']
                for field in required_fields:
                    if field not in schedule_data:
                        raise ValueError(f"Missing required field: {field}")
                
                # Set default values
                schedule_data.setdefault('timezone', 'UTC')
                schedule_data.setdefault('is_active', True)
                schedule_data.setdefault('runs_completed', 0)
                schedule_data.setdefault('consecutive_failures', 0)
                schedule_data.setdefault('max_consecutive_failures', 3)
                schedule_data.setdefault('failure_notification_sent', False)
                
                # Calculate next run time from cron expression
                if 'next_run_at' not in schedule_data and schedule_data.get('cron_expression'):
                    schedule_data['next_run_at'] = self._calculate_next_run_time(
                        schedule_data['cron_expression'],
                        schedule_data.get('timezone', 'UTC')
                    )
                
                schedule = JobSchedule(**schedule_data)
                session.add(schedule)
                session.flush()
                
                logger.info(f"Created job schedule: {schedule.id} ({schedule.schedule_name})")
                return schedule
                
        except IntegrityError as e:
            logger.error(f"Failed to create schedule due to integrity constraint: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to create schedule: {e}")
            raise
    
    def get_due_schedules(self, check_time: Optional[datetime] = None) -> List[JobSchedule]:
        """
        Get schedules that are due for execution.
        
        Args:
            check_time: Time to check against (defaults to now)
            
        Returns:
            List of JobSchedule instances that are due
        """
        try:
            if check_time is None:
                check_time = datetime.now(timezone.utc)
            
            return self.session.query(JobSchedule).filter(
                and_(
                    JobSchedule.is_active == True,
                    JobSchedule.next_run_at <= check_time,
                    JobSchedule.consecutive_failures < JobSchedule.max_consecutive_failures,
                    # Don't schedule if max_runs is reached
                    or_(
                        JobSchedule.max_runs.is_(None),
                        JobSchedule.runs_completed < JobSchedule.max_runs
                    ),
                    # Don't schedule if expired
                    or_(
                        JobSchedule.expires_at.is_(None),
                        JobSchedule.expires_at > check_time
                    )
                )
            ).order_by(JobSchedule.next_run_at).all()
            
        except Exception as e:
            logger.error(f"Failed to get due schedules: {e}")
            return []
    
    def update_schedule_after_run(self, schedule_id: UUID,
                                 run_status: BatchJobStatus,
                                 next_run_at: datetime,
                                 error_message: Optional[str] = None) -> bool:
        """
        Update schedule after a job run.
        
        Args:
            schedule_id: Schedule UUID
            run_status: Status of the completed run
            next_run_at: Next scheduled run time
            error_message: Error message if run failed
            
        Returns:
            True if successful
        """
        try:
            with transaction_scope(self.session) as session:
                schedule = session.query(JobSchedule).filter(
                    JobSchedule.id == schedule_id
                ).first()
                
                if not schedule:
                    return False
                
                schedule.last_run_at = datetime.now(timezone.utc)
                schedule.last_run_status = run_status
                schedule.runs_completed += 1
                schedule.updated_at = datetime.now(timezone.utc)
                
                if run_status == BatchJobStatus.COMPLETED:
                    schedule.consecutive_failures = 0
                    schedule.failure_notification_sent = False
                else:
                    schedule.consecutive_failures += 1
                
                # Update next run time
                schedule.next_run_at = next_run_at
                
                # Deactivate if max runs reached
                if (schedule.max_runs and 
                    schedule.runs_completed >= schedule.max_runs):
                    schedule.is_active = False
                    logger.info(f"Deactivated schedule {schedule_id} - max runs reached")
                
                # Deactivate if too many consecutive failures
                if (schedule.consecutive_failures >= 
                    schedule.max_consecutive_failures):
                    schedule.is_active = False
                    logger.warning(f"Deactivated schedule {schedule_id} - too many failures")
                
                session.flush()
                logger.debug(f"Updated schedule {schedule_id} after run")
                return True
                
        except Exception as e:
            logger.error(f"Failed to update schedule {schedule_id}: {e}")
            return False
    
    def get_schedules_for_job(self, job_id: UUID) -> List[JobSchedule]:
        """
        Get all schedules for a specific job.
        
        Args:
            job_id: Job UUID
            
        Returns:
            List of JobSchedule instances
        """
        try:
            return self.session.query(JobSchedule).filter(
                JobSchedule.job_id == job_id
            ).order_by(desc(JobSchedule.created_at)).all()
            
        except Exception as e:
            logger.error(f"Failed to get schedules for job {job_id}: {e}")
            return []
    
    def get_schedules_for_user(self, user_id: UUID, 
                              active_only: bool = True) -> List[JobSchedule]:
        """
        Get all schedules created by a user.
        
        Args:
            user_id: User UUID
            active_only: Whether to return only active schedules
            
        Returns:
            List of JobSchedule instances
        """
        try:
            query = self.session.query(JobSchedule).filter(
                JobSchedule.created_by == user_id
            )
            
            if active_only:
                query = query.filter(JobSchedule.is_active == True)
            
            return query.order_by(desc(JobSchedule.created_at)).all()
            
        except Exception as e:
            logger.error(f"Failed to get schedules for user {user_id}: {e}")
            return []
    
    def activate_schedule(self, schedule_id: UUID) -> bool:
        """
        Activate a schedule.
        
        Args:
            schedule_id: Schedule UUID
            
        Returns:
            True if successful
        """
        try:
            with transaction_scope(self.session) as session:
                schedule = session.query(JobSchedule).filter(
                    JobSchedule.id == schedule_id
                ).first()
                
                if not schedule:
                    return False
                
                schedule.is_active = True
                schedule.consecutive_failures = 0
                schedule.failure_notification_sent = False
                schedule.updated_at = datetime.now(timezone.utc)
                
                session.flush()
                logger.info(f"Activated schedule {schedule_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to activate schedule {schedule_id}: {e}")
            return False
    
    def deactivate_schedule(self, schedule_id: UUID, reason: str = None) -> bool:
        """
        Deactivate a schedule.
        
        Args:
            schedule_id: Schedule UUID
            reason: Reason for deactivation
            
        Returns:
            True if successful
        """
        try:
            with transaction_scope(self.session) as session:
                schedule = session.query(JobSchedule).filter(
                    JobSchedule.id == schedule_id
                ).first()
                
                if not schedule:
                    return False
                
                schedule.is_active = False
                schedule.updated_at = datetime.now(timezone.utc)
                
                if reason:
                    schedule.description = f"{schedule.description or ''}\nDeactivated: {reason}"
                
                session.flush()
                logger.info(f"Deactivated schedule {schedule_id}: {reason or 'Manual'}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to deactivate schedule {schedule_id}: {e}")
            return False
    
    def get_schedule_statistics(self, created_by: Optional[UUID] = None,
                               days_back: int = 30) -> Dict[str, Any]:
        """
        Get schedule statistics.
        
        Args:
            created_by: Filter by creator (optional)
            days_back: Number of days to look back
            
        Returns:
            Dictionary with schedule statistics
        """
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
            
            query = self.session.query(JobSchedule).filter(
                JobSchedule.created_at >= cutoff_date
            )
            
            if created_by:
                query = query.filter(JobSchedule.created_by == created_by)
            
            schedules = query.all()
            
            stats = {
                "total_schedules": len(schedules),
                "active_schedules": len([s for s in schedules if s.is_active]),
                "inactive_schedules": len([s for s in schedules if not s.is_active]),
                "total_runs": sum(s.runs_completed for s in schedules),
                "failed_schedules": len([s for s in schedules 
                                       if s.consecutive_failures >= s.max_consecutive_failures]),
                "average_runs_per_schedule": 0,
                "schedules_due_soon": 0
            }
            
            if schedules:
                stats["average_runs_per_schedule"] = stats["total_runs"] / len(schedules)
            
            # Count schedules due in next hour
            next_hour = datetime.now(timezone.utc) + timedelta(hours=1)
            stats["schedules_due_soon"] = len([
                s for s in schedules 
                if s.is_active and s.next_run_at <= next_hour
            ])
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get schedule statistics: {e}")
            return {}
    
    def cleanup_expired_schedules(self) -> int:
        """
        Clean up expired schedules.
        
        Returns:
            Number of schedules cleaned up
        """
        try:
            now = datetime.now(timezone.utc)
            
            with transaction_scope(self.session) as session:
                count = session.query(JobSchedule).filter(
                    and_(
                        JobSchedule.expires_at.isnot(None),
                        JobSchedule.expires_at < now
                    )
                ).count()
                
                # Deactivate instead of delete to preserve history
                session.query(JobSchedule).filter(
                    and_(
                        JobSchedule.expires_at.isnot(None),
                        JobSchedule.expires_at < now,
                        JobSchedule.is_active == True
                    )
                ).update(
                    {"is_active": False},
                    synchronize_session=False
                )
                
                logger.info(f"Deactivated {count} expired schedules")
                return count
                
        except Exception as e:
            logger.error(f"Failed to cleanup expired schedules: {e}")
            return 0
    
    # Airflow Integration Methods
    
    def sync_schedules_with_airflow(self) -> Dict[str, int]:
        """
        Synchronize job schedules with Airflow DAG schedules.
        
        Returns:
            Dictionary with synchronization statistics
        """
        try:
            stats = {
                'schedules_checked': 0,
                'airflow_dags_created': 0,
                'schedules_updated': 0,
                'sync_errors': 0
            }
            
            # Get all active schedules
            active_schedules = self.session.query(JobSchedule).filter(
                JobSchedule.is_active == True
            ).all()
            
            for schedule in active_schedules:
                stats['schedules_checked'] += 1
                
                try:
                    # Convert schedule to Airflow DAG configuration
                    dag_config = self._convert_schedule_to_dag_config(schedule)
                    
                    # Create or update Airflow DAG
                    dag_created = self._create_airflow_dag_for_schedule(schedule, dag_config)
                    
                    if dag_created:
                        stats['airflow_dags_created'] += 1
                        
                        # Update schedule with Airflow integration info
                        self._update_schedule_airflow_info(schedule, dag_config)
                        stats['schedules_updated'] += 1
                    
                except Exception as e:
                    logger.error(f"Failed to sync schedule {schedule.id} with Airflow: {e}")
                    stats['sync_errors'] += 1
            
            logger.info(f"Airflow schedule sync completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Failed to sync schedules with Airflow: {e}")
            return {'sync_errors': 1}
    
    def get_airflow_compatible_schedules(self) -> List[JobSchedule]:
        """
        Get schedules that are compatible with Airflow scheduling.
        
        Returns:
            List of JobSchedule instances compatible with Airflow
        """
        try:
            return self.session.query(JobSchedule).filter(
                and_(
                    JobSchedule.is_active == True,
                    JobSchedule.cron_expression.isnot(None),
                    JobSchedule.consecutive_failures < JobSchedule.max_consecutive_failures
                )
            ).all()
            
        except Exception as e:
            logger.error(f"Failed to get Airflow compatible schedules: {e}")
            return []
    
    def create_airflow_scheduled_job(self, job_id: UUID, schedule_config: Dict[str, Any]) -> Optional[JobSchedule]:
        """
        Create a schedule for a job specifically designed for Airflow execution.
        
        Args:
            job_id: Job to schedule
            schedule_config: Schedule configuration with Airflow-specific settings
            
        Returns:
            Created JobSchedule instance or None
        """
        try:
            # Validate Airflow-specific configuration
            required_airflow_fields = ['cron_expression', 'dag_id']
            for field in required_airflow_fields:
                if field not in schedule_config:
                    raise ValueError(f"Missing required Airflow field: {field}")
            
            # Create schedule with Airflow-specific defaults
            schedule_data = {
                'job_id': job_id,
                'schedule_name': schedule_config.get('schedule_name', f"airflow_schedule_{job_id.hex[:8]}"),
                'cron_expression': schedule_config['cron_expression'],
                'timezone': schedule_config.get('timezone', 'UTC'),
                'is_active': True,
                'created_by': schedule_config['created_by'],
                'description': schedule_config.get('description', 'Airflow scheduled job'),
                'max_runs': schedule_config.get('max_runs'),
                'expires_at': schedule_config.get('expires_at')
            }
            
            # Calculate next run time
            schedule_data['next_run_at'] = self._calculate_next_run_time(
                schedule_data['cron_expression'],
                schedule_data['timezone']
            )
            
            schedule = self.create_schedule(schedule_data)
            
            # Add Airflow-specific metadata
            schedule.custom_metadata = {
                'airflow_enabled': True,
                'dag_id': schedule_config['dag_id'],
                'airflow_config': schedule_config.get('airflow_config', {})
            }
            
            self.session.flush()
            
            logger.info(f"Created Airflow scheduled job: {schedule.id}")
            return schedule
            
        except Exception as e:
            logger.error(f"Failed to create Airflow scheduled job: {e}")
            return None
    
    def update_schedule_from_airflow_run(self, schedule_id: UUID, 
                                       dag_run_info: Dict[str, Any]) -> bool:
        """
        Update schedule based on Airflow DAG run results.
        
        Args:
            schedule_id: Schedule UUID
            dag_run_info: Information from Airflow DAG run
            
        Returns:
            True if update successful
        """
        try:
            with transaction_scope(self.session) as session:
                schedule = session.query(JobSchedule).filter(
                    JobSchedule.id == schedule_id
                ).first()
                
                if not schedule:
                    return False
                
                # Extract run information
                run_status = dag_run_info.get('state', 'unknown')
                execution_date = dag_run_info.get('execution_date')
                duration = dag_run_info.get('duration_seconds', 0)
                
                # Update schedule based on run result
                if run_status == 'success':
                    schedule.runs_completed += 1
                    schedule.consecutive_failures = 0
                    schedule.failure_notification_sent = False
                    schedule.last_run_status = BatchJobStatus.COMPLETED
                elif run_status in ['failed', 'up_for_retry']:
                    schedule.consecutive_failures += 1
                    schedule.last_run_status = BatchJobStatus.FAILED
                else:
                    # Running or other states
                    schedule.last_run_status = BatchJobStatus.RUNNING
                
                # Update timing information
                if execution_date:
                    schedule.last_run_at = execution_date
                
                # Calculate next run time
                schedule.next_run_at = self._calculate_next_run_time(
                    schedule.cron_expression,
                    schedule.timezone
                )
                
                # Deactivate if max runs reached or too many failures
                if (schedule.max_runs and schedule.runs_completed >= schedule.max_runs):
                    schedule.is_active = False
                
                if schedule.consecutive_failures >= schedule.max_consecutive_failures:
                    schedule.is_active = False
                
                schedule.updated_at = datetime.now(timezone.utc)
                session.flush()
                
                logger.info(f"Updated schedule {schedule_id} from Airflow run: {run_status}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to update schedule from Airflow run: {e}")
            return False
    
    def get_overdue_schedules(self, threshold_minutes: int = 60) -> List[JobSchedule]:
        """
        Get schedules that are overdue (past their next_run_at time).
        
        Args:
            threshold_minutes: Minutes past due to consider overdue
            
        Returns:
            List of overdue JobSchedule instances
        """
        try:
            threshold_time = datetime.now(timezone.utc) - timedelta(minutes=threshold_minutes)
            
            return self.session.query(JobSchedule).filter(
                and_(
                    JobSchedule.is_active == True,
                    JobSchedule.next_run_at <= threshold_time,
                    JobSchedule.consecutive_failures < JobSchedule.max_consecutive_failures
                )
            ).all()
            
        except Exception as e:
            logger.error(f"Failed to get overdue schedules: {e}")
            return []
    
    # Private helper methods for Airflow integration
    
    def _calculate_next_run_time(self, cron_expression: str, timezone_str: str = 'UTC') -> datetime:
        """
        Calculate next run time based on cron expression.
        
        Args:
            cron_expression: Cron expression
            timezone_str: Timezone string
            
        Returns:
            Next execution datetime
        """
        try:
            import pytz
            
            # Parse timezone
            if timezone_str == 'UTC':
                tz = pytz.UTC
            else:
                tz = pytz.timezone(timezone_str)
            
            # Get current time in the specified timezone
            now = datetime.now(tz)
            
            # Use croniter to calculate next run time
            cron = croniter(cron_expression, now)
            next_run = cron.get_next(datetime)
            
            # Convert to UTC for storage
            return next_run.astimezone(pytz.UTC).replace(tzinfo=timezone.utc)
            
        except Exception as e:
            logger.error(f"Failed to calculate next run time: {e}")
            # Fallback to 1 hour from now
            return datetime.now(timezone.utc) + timedelta(hours=1)
    
    def _convert_schedule_to_dag_config(self, schedule: JobSchedule) -> Dict[str, Any]:
        """Convert JobSchedule to Airflow DAG configuration."""
        return {
            'dag_id': f"scheduled_job_{schedule.job_id.hex[:8]}_{schedule.id.hex[:8]}",
            'schedule_interval': schedule.cron_expression,
            'start_date': schedule.created_at,
            'max_active_runs': 1,
            'catchup': False,
            'default_args': {
                'owner': str(schedule.created_by),
                'retries': 3,
                'retry_delay': timedelta(minutes=5)
            },
            'tags': ['scheduled', 'batch-job'],
            'params': {
                'job_id': str(schedule.job_id),
                'schedule_id': str(schedule.id)
            }
        }
    
    def _create_airflow_dag_for_schedule(self, schedule: JobSchedule, 
                                       dag_config: Dict[str, Any]) -> bool:
        """Create Airflow DAG for a schedule."""
        try:
            # In a real implementation, this would generate and deploy a DAG file
            # For now, we'll just simulate the process
            logger.info(f"Would create Airflow DAG: {dag_config['dag_id']} for schedule {schedule.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to create Airflow DAG: {e}")
            return False
    
    def _update_schedule_airflow_info(self, schedule: JobSchedule, 
                                    dag_config: Dict[str, Any]) -> None:
        """Update schedule with Airflow integration information."""
        if not schedule.description:
            schedule.description = ""
        
        schedule.description += f"\nAirflow DAG: {dag_config['dag_id']}"
        schedule.updated_at = datetime.now(timezone.utc)