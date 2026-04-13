"""
Airflow Synchronization Service

Provides bidirectional synchronization between BatchProcessingEngine
and Apache Airflow, ensuring consistent state across both systems.
"""

import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from uuid import UUID
from dataclasses import dataclass

from sqlalchemy.orm import Session
from airflow.models import DagRun, TaskInstance, DagModel
from airflow.api.client.local_client import Client as AirflowClient
from airflow.utils.state import State

from ..database.session import transaction_scope
from ..database.repositories.batch_job_repository import BatchJobRepository
from ..database.models import BatchJob, BatchJobStatus
from .workflow_models import WorkflowStatus, WorkflowExecution

logger = logging.getLogger(__name__)


@dataclass
class SyncMetrics:
    """Metrics for synchronization operations."""
    total_jobs_synced: int = 0
    jobs_synced_to_airflow: int = 0
    jobs_synced_from_airflow: int = 0
    sync_errors: int = 0
    last_sync_time: Optional[datetime] = None
    sync_duration_ms: float = 0.0


class AirflowSyncService:
    """
    Service for bidirectional synchronization between BatchProcessingEngine and Airflow.
    
    Handles:
    - Job status synchronization
    - DAG run state mapping
    - Task instance status updates
    - Failure recovery and retry logic
    """
    
    def __init__(self, session: Optional[Session] = None):
        self._session = session
        self._job_repository = BatchJobRepository(session)
        self._airflow_client: Optional[AirflowClient] = None
        
        # Sync state tracking
        self._sync_running = False
        self._sync_task: Optional[asyncio.Task] = None
        self._sync_interval = 60  # seconds
        
        # Job mapping (BatchJob ID -> Airflow DAG run info)
        self._job_to_dag_mapping: Dict[UUID, Dict[str, Any]] = {}
        self._dag_to_job_mapping: Dict[str, UUID] = {}
        
        # Metrics
        self._sync_metrics = SyncMetrics()
        
        logger.info("Airflow Sync Service initialized")
    
    @property
    def session(self) -> Session:
        """Get current database session."""
        if self._session:
            return self._session
        from ..database.session import get_db_session
        return get_db_session()
    
    @property
    def airflow_client(self) -> AirflowClient:
        """Get Airflow client instance."""
        if not self._airflow_client:
            try:
                self._airflow_client = AirflowClient(None, None)
            except Exception as e:
                logger.error(f"Failed to initialize Airflow client: {e}")
                raise
        return self._airflow_client
    
    async def start_sync(self) -> None:
        """Start the synchronization service."""
        if self._sync_running:
            logger.warning("Sync service is already running")
            return
        
        try:
            logger.info("Starting Airflow sync service...")
            self._sync_running = True
            
            # Start sync loop
            self._sync_task = asyncio.create_task(self._sync_loop())
            
            logger.info("✅ Airflow sync service started")
            
        except Exception as e:
            logger.error(f"Failed to start sync service: {e}")
            self._sync_running = False
            raise
    
    async def stop_sync(self) -> None:
        """Stop the synchronization service."""
        if not self._sync_running:
            return
        
        logger.info("Stopping Airflow sync service...")
        self._sync_running = False
        
        if self._sync_task and not self._sync_task.done():
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
        
        logger.info("✅ Airflow sync service stopped")
    
    async def sync_job_to_airflow(self, job_id: UUID, dag_id: str, 
                                dag_run_id: str, execution_date: datetime) -> bool:
        """
        Register a batch job with its corresponding Airflow DAG run.
        
        Args:
            job_id: Batch job ID
            dag_id: Airflow DAG ID
            dag_run_id: Airflow DAG run ID
            execution_date: Execution date
            
        Returns:
            True if registration successful
        """
        try:
            # Store mapping
            self._job_to_dag_mapping[job_id] = {
                'dag_id': dag_id,
                'dag_run_id': dag_run_id,
                'execution_date': execution_date,
                'registered_at': datetime.now(timezone.utc)
            }
            
            self._dag_to_job_mapping[dag_run_id] = job_id
            
            logger.info(f"Registered job {job_id} with DAG run {dag_run_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register job-DAG mapping: {e}")
            return False
    
    async def sync_job_status_from_airflow(self, job_id: UUID) -> bool:
        """
        Sync job status from Airflow to BatchProcessingEngine.
        
        Args:
            job_id: Batch job ID to sync
            
        Returns:
            True if sync successful
        """
        try:
            # Get DAG mapping
            dag_info = self._job_to_dag_mapping.get(job_id)
            if not dag_info:
                logger.warning(f"No DAG mapping found for job {job_id}")
                return False
            
            # Get DAG run from Airflow
            dag_run = self._get_dag_run(dag_info['dag_id'], dag_info['execution_date'])
            if not dag_run:
                logger.warning(f"DAG run not found: {dag_info['dag_run_id']}")
                return False
            
            # Map Airflow state to BatchJobStatus
            batch_status = self._map_airflow_state_to_batch_status(dag_run.state)
            
            # Update job status in database
            success = self._job_repository.update_job_status(
                job_id, batch_status, f"Synced from Airflow: {dag_run.state}"
            )
            
            if success:
                self._sync_metrics.jobs_synced_from_airflow += 1
                logger.debug(f"Synced job {job_id} status from Airflow: {batch_status}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to sync job status from Airflow: {e}")
            self._sync_metrics.sync_errors += 1
            return False
    
    async def sync_job_status_to_airflow(self, job_id: UUID) -> bool:
        """
        Sync job status from BatchProcessingEngine to Airflow.
        
        Args:
            job_id: Batch job ID to sync
            
        Returns:
            True if sync successful
        """
        try:
            # Get job from database
            job = self._job_repository.get_job(job_id)
            if not job:
                logger.warning(f"Job not found: {job_id}")
                return False
            
            # Get DAG mapping
            dag_info = self._job_to_dag_mapping.get(job_id)
            if not dag_info:
                logger.warning(f"No DAG mapping found for job {job_id}")
                return False
            
            # Map BatchJobStatus to Airflow state
            airflow_state = self._map_batch_status_to_airflow_state(job.status)
            
            # Update DAG run state in Airflow
            success = self._update_dag_run_state(
                dag_info['dag_id'], 
                dag_info['execution_date'],
                airflow_state
            )
            
            if success:
                self._sync_metrics.jobs_synced_to_airflow += 1
                logger.debug(f"Synced job {job_id} status to Airflow: {airflow_state}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to sync job status to Airflow: {e}")
            self._sync_metrics.sync_errors += 1
            return False
    
    async def sync_all_active_jobs(self) -> Dict[str, int]:
        """
        Sync all active jobs between systems.
        
        Returns:
            Dictionary with sync statistics
        """
        start_time = datetime.now(timezone.utc)
        stats = {
            'jobs_checked': 0,
            'jobs_synced_from_airflow': 0,
            'jobs_synced_to_airflow': 0,
            'sync_errors': 0
        }
        
        try:
            # Get active batch jobs
            active_jobs = self._job_repository.find_jobs(
                status=BatchJobStatus.RUNNING,
                limit=1000
            )
            
            # Sync from Airflow to BatchProcessingEngine
            for job in active_jobs:
                stats['jobs_checked'] += 1
                
                if job.id in self._job_to_dag_mapping:
                    success = await self.sync_job_status_from_airflow(job.id)
                    if success:
                        stats['jobs_synced_from_airflow'] += 1
                    else:
                        stats['sync_errors'] += 1
            
            # Get active Airflow DAG runs and sync to BatchProcessingEngine
            active_dag_runs = self._get_active_dag_runs()
            for dag_run in active_dag_runs:
                if dag_run.run_id in self._dag_to_job_mapping:
                    job_id = self._dag_to_job_mapping[dag_run.run_id]
                    success = await self.sync_job_status_from_airflow(job_id)
                    if success:
                        stats['jobs_synced_from_airflow'] += 1
                    else:
                        stats['sync_errors'] += 1
            
            # Update metrics
            duration = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            self._sync_metrics.sync_duration_ms = duration
            self._sync_metrics.last_sync_time = datetime.now(timezone.utc)
            self._sync_metrics.total_jobs_synced += stats['jobs_synced_from_airflow'] + stats['jobs_synced_to_airflow']
            
            logger.info(f"Sync completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Failed to sync all active jobs: {e}")
            stats['sync_errors'] += 1
            return stats
    
    def get_sync_metrics(self) -> SyncMetrics:
        """Get current synchronization metrics."""
        return self._sync_metrics
    
    def get_job_dag_mapping(self, job_id: UUID) -> Optional[Dict[str, Any]]:
        """Get Airflow DAG information for a job."""
        return self._job_to_dag_mapping.get(job_id)
    
    def get_dag_job_mapping(self, dag_run_id: str) -> Optional[UUID]:
        """Get job ID for an Airflow DAG run."""
        return self._dag_to_job_mapping.get(dag_run_id)
    
    # Private methods
    
    async def _sync_loop(self) -> None:
        """Main synchronization loop."""
        while self._sync_running:
            try:
                await asyncio.sleep(self._sync_interval)
                
                if self._sync_running:
                    await self.sync_all_active_jobs()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in sync loop: {e}")
                await asyncio.sleep(30)  # Wait before retrying
    
    def _get_dag_run(self, dag_id: str, execution_date: datetime) -> Optional[DagRun]:
        """Get DAG run from Airflow."""
        try:
            return self.airflow_client.get_dag_run(dag_id, execution_date)
        except Exception as e:
            logger.error(f"Failed to get DAG run {dag_id}: {e}")
            return None
    
    def _get_active_dag_runs(self) -> List[DagRun]:
        """Get all active DAG runs from Airflow."""
        try:
            # Get all DAG runs in running state
            dag_runs = self.airflow_client.get_dag_runs(
                state=State.RUNNING,
                limit=1000
            )
            return dag_runs or []
        except Exception as e:
            logger.error(f"Failed to get active DAG runs: {e}")
            return []
    
    def _update_dag_run_state(self, dag_id: str, execution_date: datetime, 
                            state: str) -> bool:
        """Update DAG run state in Airflow."""
        try:
            self.airflow_client.set_dag_run_state(dag_id, execution_date, state)
            return True
        except Exception as e:
            logger.error(f"Failed to update DAG run state: {e}")
            return False
    
    def _map_airflow_state_to_batch_status(self, airflow_state: str) -> BatchJobStatus:
        """Map Airflow state to BatchJobStatus."""
        mapping = {
            State.QUEUED: BatchJobStatus.QUEUED,
            State.RUNNING: BatchJobStatus.RUNNING,
            State.SUCCESS: BatchJobStatus.COMPLETED,
            State.FAILED: BatchJobStatus.FAILED,
            State.UP_FOR_RETRY: BatchJobStatus.RUNNING,
            State.UP_FOR_RESCHEDULE: BatchJobStatus.QUEUED,
            State.UPSTREAM_FAILED: BatchJobStatus.FAILED,
            State.SKIPPED: BatchJobStatus.CANCELLED,
            State.REMOVED: BatchJobStatus.CANCELLED,
            State.SCHEDULED: BatchJobStatus.QUEUED,
            State.DEFERRED: BatchJobStatus.PAUSED,
            'killed': BatchJobStatus.CANCELLED
        }
        
        return mapping.get(airflow_state, BatchJobStatus.FAILED)
    
    def _map_batch_status_to_airflow_state(self, batch_status: BatchJobStatus) -> str:
        """Map BatchJobStatus to Airflow state."""
        mapping = {
            BatchJobStatus.PENDING: State.QUEUED,
            BatchJobStatus.QUEUED: State.QUEUED,
            BatchJobStatus.RUNNING: State.RUNNING,
            BatchJobStatus.PAUSED: State.DEFERRED,
            BatchJobStatus.COMPLETED: State.SUCCESS,
            BatchJobStatus.FAILED: State.FAILED,
            BatchJobStatus.CANCELLED: State.REMOVED,
            BatchJobStatus.TIMEOUT: State.FAILED
        }
        
        return mapping.get(batch_status, State.FAILED)
    
    def _map_workflow_status_to_batch_status(self, workflow_status: WorkflowStatus) -> BatchJobStatus:
        """Map WorkflowStatus to BatchJobStatus."""
        mapping = {
            WorkflowStatus.DRAFT: BatchJobStatus.PENDING,
            WorkflowStatus.PENDING: BatchJobStatus.PENDING,
            WorkflowStatus.RUNNING: BatchJobStatus.RUNNING,
            WorkflowStatus.PAUSED: BatchJobStatus.PAUSED,
            WorkflowStatus.COMPLETED: BatchJobStatus.COMPLETED,
            WorkflowStatus.FAILED: BatchJobStatus.FAILED,
            WorkflowStatus.CANCELLED: BatchJobStatus.CANCELLED,
            WorkflowStatus.TIMEOUT: BatchJobStatus.TIMEOUT
        }
        
        return mapping.get(workflow_status, BatchJobStatus.FAILED)


class AirflowCallbackHandler:
    """Handles Airflow callbacks for job state updates."""
    
    def __init__(self, sync_service: AirflowSyncService):
        self.sync_service = sync_service
        self.logger = logging.getLogger(f"{__name__}.CallbackHandler")
    
    def on_dag_run_success(self, context: Dict[str, Any]) -> None:
        """Callback for successful DAG run completion."""
        try:
            dag_run = context['dag_run']
            dag_run_id = dag_run.run_id
            
            # Get corresponding job ID
            job_id = self.sync_service.get_dag_job_mapping(dag_run_id)
            if job_id:
                # Sync job status
                asyncio.create_task(
                    self.sync_service.sync_job_status_from_airflow(job_id)
                )
                self.logger.info(f"DAG run succeeded, syncing job {job_id}")
        
        except Exception as e:
            self.logger.error(f"Error in DAG success callback: {e}")
    
    def on_dag_run_failure(self, context: Dict[str, Any]) -> None:
        """Callback for failed DAG run."""
        try:
            dag_run = context['dag_run']
            dag_run_id = dag_run.run_id
            
            # Get corresponding job ID
            job_id = self.sync_service.get_dag_job_mapping(dag_run_id)
            if job_id:
                # Sync job status
                asyncio.create_task(
                    self.sync_service.sync_job_status_from_airflow(job_id)
                )
                self.logger.info(f"DAG run failed, syncing job {job_id}")
        
        except Exception as e:
            self.logger.error(f"Error in DAG failure callback: {e}")
    
    def on_task_success(self, context: Dict[str, Any]) -> None:
        """Callback for successful task completion."""
        try:
            task_instance = context['task_instance']
            dag_run = context['dag_run']
            
            self.logger.info(f"Task succeeded: {task_instance.task_id} in {dag_run.run_id}")
            
            # Could update individual step status here
        
        except Exception as e:
            self.logger.error(f"Error in task success callback: {e}")
    
    def on_task_failure(self, context: Dict[str, Any]) -> None:
        """Callback for failed task."""
        try:
            task_instance = context['task_instance']
            dag_run = context['dag_run']
            
            self.logger.error(f"Task failed: {task_instance.task_id} in {dag_run.run_id}")
            
            # Could update individual step status here
        
        except Exception as e:
            self.logger.error(f"Error in task failure callback: {e}")


class AirflowHealthMonitor:
    """Monitors Airflow system health and connectivity."""
    
    def __init__(self, sync_service: AirflowSyncService):
        self.sync_service = sync_service
        self.logger = logging.getLogger(f"{__name__}.HealthMonitor")
        
        self._last_health_check = None
        self._airflow_healthy = False
        self._consecutive_failures = 0
        self._max_failures = 5
    
    async def check_airflow_health(self) -> Dict[str, Any]:
        """Check Airflow system health."""
        try:
            start_time = datetime.now(timezone.utc)
            
            # Test basic connectivity
            dags = self.sync_service.airflow_client.list_dags()
            
            # Test DAG run operations
            active_runs = self.sync_service._get_active_dag_runs()
            
            response_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            health_info = {
                'healthy': True,
                'response_time_ms': response_time,
                'total_dags': len(dags) if dags else 0,
                'active_runs': len(active_runs),
                'last_check': datetime.now(timezone.utc).isoformat(),
                'consecutive_failures': 0
            }
            
            self._airflow_healthy = True
            self._consecutive_failures = 0
            self._last_health_check = datetime.now(timezone.utc)
            
            return health_info
            
        except Exception as e:
            self._consecutive_failures += 1
            self._airflow_healthy = False
            
            health_info = {
                'healthy': False,
                'error': str(e),
                'consecutive_failures': self._consecutive_failures,
                'max_failures': self._max_failures,
                'last_check': datetime.now(timezone.utc).isoformat()
            }
            
            self.logger.error(f"Airflow health check failed: {e}")
            return health_info
    
    def is_airflow_healthy(self) -> bool:
        """Check if Airflow is currently healthy."""
        return self._airflow_healthy and self._consecutive_failures < self._max_failures
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status."""
        return {
            'healthy': self.is_airflow_healthy(),
            'consecutive_failures': self._consecutive_failures,
            'last_health_check': self._last_health_check.isoformat() if self._last_health_check else None,
            'sync_metrics': self.sync_service.get_sync_metrics().__dict__
        }