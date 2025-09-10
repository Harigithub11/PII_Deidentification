"""
Fault Tolerance and Recovery Manager

Provides comprehensive fault tolerance, job recovery, and system resilience
for the batch processing system.
"""

import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from uuid import UUID
from enum import Enum
import traceback

from ..database.session import transaction_scope
from ..database.repositories.batch_job_repository import BatchJobRepository
from ..database.repositories.job_result_repository import JobResultRepository  
from ..database.repositories.batch_worker_repository import BatchWorkerRepository
from ..database.models import BatchJobStatus, WorkerStatus
from ..config.settings import get_settings
from ..services.redis_service import get_redis_service

logger = logging.getLogger(__name__)
settings = get_settings()


class RecoveryStrategy(str, Enum):
    """Recovery strategies for different failure types."""
    RETRY_IMMEDIATE = "retry_immediate"
    RETRY_EXPONENTIAL_BACKOFF = "retry_exponential_backoff"
    MOVE_TO_DEAD_LETTER = "move_to_dead_letter"
    REASSIGN_TO_DIFFERENT_WORKER = "reassign_to_different_worker"
    MARK_FAILED = "mark_failed"
    MANUAL_INTERVENTION = "manual_intervention"


class FailureType(str, Enum):
    """Types of failures that can occur."""
    WORKER_DISCONNECT = "worker_disconnect"
    TASK_TIMEOUT = "task_timeout"
    TASK_EXCEPTION = "task_exception"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    DEPENDENCY_FAILURE = "dependency_failure"
    NETWORK_ERROR = "network_error"
    DATABASE_ERROR = "database_error"
    SYSTEM_SHUTDOWN = "system_shutdown"


class RecoveryAction:
    """Represents a recovery action to be taken."""
    
    def __init__(self, job_id: UUID, strategy: RecoveryStrategy, 
                 failure_type: FailureType, retry_count: int = 0,
                 delay_seconds: int = 0, metadata: Dict[str, Any] = None):
        self.job_id = job_id
        self.strategy = strategy
        self.failure_type = failure_type
        self.retry_count = retry_count
        self.delay_seconds = delay_seconds
        self.metadata = metadata or {}
        self.created_at = datetime.now(timezone.utc)


class FaultToleranceManager:
    """
    Manages fault tolerance, recovery strategies, and system resilience.
    """
    
    def __init__(self):
        self._recovery_queue: List[RecoveryAction] = []
        self._is_running = False
        self._recovery_task: Optional[asyncio.Task] = None
        self._health_check_task: Optional[asyncio.Task] = None
        
        # Configuration
        self._max_retries_per_job = getattr(settings, 'batch_max_retries_per_job', 3)
        self._retry_base_delay = getattr(settings, 'batch_retry_base_delay', 60)
        self._max_retry_delay = getattr(settings, 'batch_max_retry_delay', 3600)
        self._health_check_interval = getattr(settings, 'batch_health_check_interval', 30)
        self._recovery_processing_interval = getattr(settings, 'batch_recovery_interval', 10)
        
        # Statistics
        self._recovery_stats = {
            'total_recoveries': 0,
            'successful_recoveries': 0,
            'failed_recoveries': 0,
            'recovery_strategies_used': {},
            'failure_types_encountered': {}
        }
        
        logger.info("Fault Tolerance Manager initialized")
    
    async def start(self) -> None:
        """Start the fault tolerance manager."""
        if self._is_running:
            logger.warning("Fault Tolerance Manager is already running")
            return
        
        logger.info("Starting Fault Tolerance Manager...")
        
        self._is_running = True
        
        # Start background tasks
        self._recovery_task = asyncio.create_task(self._recovery_loop())
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        
        logger.info("✅ Fault Tolerance Manager started")
    
    async def stop(self) -> None:
        """Stop the fault tolerance manager."""
        if not self._is_running:
            return
        
        logger.info("Stopping Fault Tolerance Manager...")
        
        self._is_running = False
        
        # Cancel background tasks
        for task in [self._recovery_task, self._health_check_task]:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        logger.info("✅ Fault Tolerance Manager stopped")
    
    async def handle_job_failure(self, job_id: UUID, failure_type: FailureType,
                                error_info: Dict[str, Any] = None) -> RecoveryAction:
        """
        Handle a job failure and determine recovery strategy.
        
        Args:
            job_id: ID of the failed job
            failure_type: Type of failure that occurred
            error_info: Additional error information
            
        Returns:
            Recovery action to be taken
        """
        try:
            logger.info(f"Handling job failure: {job_id} ({failure_type})")
            
            with transaction_scope() as session:
                repo = BatchJobRepository(session)
                job = repo.get_job(job_id)
                
                if not job:
                    logger.error(f"Job {job_id} not found for failure handling")
                    return None
                
                # Determine recovery strategy
                strategy = self._determine_recovery_strategy(job, failure_type, error_info)
                
                # Calculate retry delay
                delay_seconds = self._calculate_retry_delay(job.retry_count, failure_type)
                
                # Create recovery action
                recovery_action = RecoveryAction(
                    job_id=job_id,
                    strategy=strategy,
                    failure_type=failure_type,
                    retry_count=job.retry_count + 1,
                    delay_seconds=delay_seconds,
                    metadata={
                        'error_info': error_info or {},
                        'original_worker': job.assigned_worker_id,
                        'failure_time': datetime.now(timezone.utc).isoformat()
                    }
                )
                
                # Add to recovery queue
                self._recovery_queue.append(recovery_action)
                
                # Update statistics
                self._update_failure_stats(failure_type, strategy)
                
                logger.info(f"Recovery strategy determined for job {job_id}: {strategy}")
                return recovery_action
                
        except Exception as e:
            logger.error(f"Failed to handle job failure {job_id}: {e}")
            return None
    
    async def recover_system_on_startup(self) -> Dict[str, Any]:
        """
        Perform system recovery on startup, handling interrupted jobs.
        
        Returns:
            Recovery statistics
        """
        try:
            logger.info("Performing system recovery on startup")
            
            with transaction_scope() as session:
                repo = BatchJobRepository(session)
                
                # Find interrupted jobs
                interrupted_jobs = repo.recover_interrupted_jobs()
                
                # Find stale running jobs
                stale_jobs = repo.get_stale_jobs(heartbeat_timeout=300)  # 5 minutes
                
                # Find expired jobs
                expired_jobs = repo.get_expired_jobs()
                
                recovery_stats = {
                    'interrupted_jobs_recovered': len(interrupted_jobs),
                    'stale_jobs_found': len(stale_jobs),
                    'expired_jobs_found': len(expired_jobs),
                    'total_jobs_processed': len(interrupted_jobs) + len(stale_jobs) + len(expired_jobs)
                }
                
                # Handle stale jobs
                for job in stale_jobs:
                    await self.handle_job_failure(
                        job.id, 
                        FailureType.WORKER_DISCONNECT,
                        {'reason': 'stale_heartbeat', 'last_heartbeat': job.last_heartbeat}
                    )
                
                # Handle expired jobs
                for job in expired_jobs:
                    await self.handle_job_failure(
                        job.id,
                        FailureType.TASK_TIMEOUT,
                        {'reason': 'job_timeout', 'started_at': job.started_at}
                    )
                
                # Clean up orphaned workers
                worker_repo = BatchWorkerRepository(session)
                inactive_workers = worker_repo.get_inactive_workers(inactive_timeout=600)  # 10 minutes
                if inactive_workers:
                    worker_ids = [w.id for w in inactive_workers]
                    cleaned_workers = worker_repo.mark_workers_offline(worker_ids)
                    recovery_stats['workers_marked_offline'] = cleaned_workers
                
                logger.info(f"System recovery completed: {recovery_stats}")
                return recovery_stats
                
        except Exception as e:
            logger.error(f"System recovery failed: {e}")
            return {'error': str(e)}
    
    def _determine_recovery_strategy(self, job, failure_type: FailureType,
                                   error_info: Dict[str, Any]) -> RecoveryStrategy:
        """Determine the appropriate recovery strategy for a failed job."""
        
        # Check if job has exceeded max retries
        if job.retry_count >= self._max_retries_per_job:
            return RecoveryStrategy.MARK_FAILED
        
        # Strategy based on failure type
        strategy_map = {
            FailureType.WORKER_DISCONNECT: RecoveryStrategy.REASSIGN_TO_DIFFERENT_WORKER,
            FailureType.TASK_TIMEOUT: RecoveryStrategy.RETRY_EXPONENTIAL_BACKOFF,
            FailureType.TASK_EXCEPTION: RecoveryStrategy.RETRY_EXPONENTIAL_BACKOFF,
            FailureType.RESOURCE_EXHAUSTION: RecoveryStrategy.RETRY_EXPONENTIAL_BACKOFF,
            FailureType.DEPENDENCY_FAILURE: RecoveryStrategy.RETRY_EXPONENTIAL_BACKOFF,
            FailureType.NETWORK_ERROR: RecoveryStrategy.RETRY_IMMEDIATE,
            FailureType.DATABASE_ERROR: RecoveryStrategy.RETRY_EXPONENTIAL_BACKOFF,
            FailureType.SYSTEM_SHUTDOWN: RecoveryStrategy.RETRY_IMMEDIATE
        }
        
        base_strategy = strategy_map.get(failure_type, RecoveryStrategy.RETRY_EXPONENTIAL_BACKOFF)
        
        # Modify strategy based on job characteristics and error patterns
        if job.retry_count >= 2:
            if base_strategy == RecoveryStrategy.RETRY_IMMEDIATE:
                return RecoveryStrategy.RETRY_EXPONENTIAL_BACKOFF
            elif base_strategy == RecoveryStrategy.RETRY_EXPONENTIAL_BACKOFF:
                return RecoveryStrategy.MOVE_TO_DEAD_LETTER
        
        # Critical jobs get different treatment
        if job.priority in ['critical', 'urgent']:
            if base_strategy == RecoveryStrategy.MOVE_TO_DEAD_LETTER:
                return RecoveryStrategy.MANUAL_INTERVENTION
        
        return base_strategy
    
    def _calculate_retry_delay(self, retry_count: int, failure_type: FailureType) -> int:
        """Calculate retry delay based on retry count and failure type."""
        
        if failure_type in [FailureType.NETWORK_ERROR, FailureType.SYSTEM_SHUTDOWN]:
            # Quick retry for transient issues
            return min(self._retry_base_delay // 2, 30)
        
        # Exponential backoff
        delay = self._retry_base_delay * (2 ** retry_count)
        
        # Add jitter (±25%)
        import random
        jitter = random.uniform(0.75, 1.25)
        delay = int(delay * jitter)
        
        return min(delay, self._max_retry_delay)
    
    async def _recovery_loop(self) -> None:
        """Main recovery processing loop."""
        while self._is_running:
            try:
                if not self._recovery_queue:
                    await asyncio.sleep(self._recovery_processing_interval)
                    continue
                
                # Process recovery actions
                actions_to_process = []
                current_time = datetime.now(timezone.utc)
                
                # Find actions ready for processing
                for action in self._recovery_queue[:]:
                    if (current_time - action.created_at).total_seconds() >= action.delay_seconds:
                        actions_to_process.append(action)
                        self._recovery_queue.remove(action)
                
                # Process each action
                for action in actions_to_process:
                    try:
                        success = await self._execute_recovery_action(action)
                        
                        if success:
                            self._recovery_stats['successful_recoveries'] += 1
                            logger.info(f"Recovery successful for job {action.job_id}")
                        else:
                            self._recovery_stats['failed_recoveries'] += 1
                            logger.warning(f"Recovery failed for job {action.job_id}")
                            
                            # Re-queue with different strategy if appropriate
                            await self._handle_recovery_failure(action)
                    
                    except Exception as e:
                        logger.error(f"Recovery action execution failed for job {action.job_id}: {e}")
                        self._recovery_stats['failed_recoveries'] += 1
                
                self._recovery_stats['total_recoveries'] += len(actions_to_process)
                
                await asyncio.sleep(self._recovery_processing_interval)
                
            except Exception as e:
                logger.error(f"Error in recovery loop: {e}")
                await asyncio.sleep(30)
    
    async def _execute_recovery_action(self, action: RecoveryAction) -> bool:
        """Execute a specific recovery action."""
        
        try:
            with transaction_scope() as session:
                repo = BatchJobRepository(session)
                job = repo.get_job(action.job_id)
                
                if not job:
                    logger.error(f"Job {action.job_id} not found for recovery")
                    return False
                
                if action.strategy == RecoveryStrategy.RETRY_IMMEDIATE:
                    return await self._retry_job_immediate(repo, job)
                
                elif action.strategy == RecoveryStrategy.RETRY_EXPONENTIAL_BACKOFF:
                    return await self._retry_job_with_backoff(repo, job, action)
                
                elif action.strategy == RecoveryStrategy.REASSIGN_TO_DIFFERENT_WORKER:
                    return await self._reassign_job_to_different_worker(repo, job, action)
                
                elif action.strategy == RecoveryStrategy.MOVE_TO_DEAD_LETTER:
                    return await self._move_to_dead_letter_queue(repo, job, action)
                
                elif action.strategy == RecoveryStrategy.MARK_FAILED:
                    return await self._mark_job_failed(repo, job, action)
                
                elif action.strategy == RecoveryStrategy.MANUAL_INTERVENTION:
                    return await self._flag_for_manual_intervention(repo, job, action)
                
                else:
                    logger.warning(f"Unknown recovery strategy: {action.strategy}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to execute recovery action: {e}")
            return False
    
    async def _retry_job_immediate(self, repo: BatchJobRepository, job) -> bool:
        """Retry job immediately."""
        return repo.update_job_status(job.id, BatchJobStatus.QUEUED, "Immediate retry")
    
    async def _retry_job_with_backoff(self, repo: BatchJobRepository, job, action: RecoveryAction) -> bool:
        """Retry job with exponential backoff."""
        updates = {
            'status': BatchJobStatus.QUEUED,
            'retry_count': action.retry_count,
            'scheduled_at': datetime.now(timezone.utc) + timedelta(seconds=action.delay_seconds)
        }
        
        updated_job = repo.update_job(job.id, updates, add_audit_entry=True)
        return updated_job is not None
    
    async def _reassign_job_to_different_worker(self, repo: BatchJobRepository, job, action: RecoveryAction) -> bool:
        """Reassign job to a different worker."""
        try:
            # Find available workers (excluding the failed one)
            worker_repo = BatchWorkerRepository(repo.session)
            available_workers = worker_repo.get_available_workers(
                job_type=str(job.job_type)
            )
            
            # Filter out the original worker
            original_worker_id = action.metadata.get('original_worker')
            if original_worker_id:
                available_workers = [w for w in available_workers if w.id != original_worker_id]
            
            if available_workers:
                # Select best worker
                best_worker = worker_repo.get_best_worker_for_job(
                    str(job.job_type),
                    job.memory_limit_mb,
                    float(job.cpu_limit_cores)
                )
                
                if best_worker:
                    updates = {
                        'status': BatchJobStatus.QUEUED,
                        'assigned_worker_id': best_worker.id,
                        'retry_count': action.retry_count
                    }
                    
                    updated_job = repo.update_job(job.id, updates, add_audit_entry=True)
                    return updated_job is not None
            
            # No available workers, fall back to regular retry
            return await self._retry_job_with_backoff(repo, job, action)
            
        except Exception as e:
            logger.error(f"Failed to reassign job {job.id}: {e}")
            return False
    
    async def _move_to_dead_letter_queue(self, repo: BatchJobRepository, job, action: RecoveryAction) -> bool:
        """Move job to dead letter queue."""
        try:
            # Update job status
            repo.update_job_status(job.id, BatchJobStatus.FAILED, "Moved to dead letter queue")
            
            # Move to Redis dead letter queue
            redis_service = get_redis_service()
            if await redis_service.is_connected():
                job_data = {
                    'id': str(job.id),
                    'name': job.name,
                    'job_type': str(job.job_type),
                    'created_by': str(job.created_by),
                    'failure_type': action.failure_type,
                    'retry_count': action.retry_count
                }
                
                await redis_service.move_to_dead_letter_queue(
                    job_data,
                    action.metadata.get('error_info', {})
                )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to move job {job.id} to dead letter queue: {e}")
            return False
    
    async def _mark_job_failed(self, repo: BatchJobRepository, job, action: RecoveryAction) -> bool:
        """Mark job as permanently failed."""
        updates = {
            'status': BatchJobStatus.FAILED,
            'completed_at': datetime.now(timezone.utc),
            'error_message': f"Max retries exceeded ({action.retry_count})",
            'error_details': {
                'failure_type': action.failure_type,
                'retry_count': action.retry_count,
                'original_error': action.metadata.get('error_info', {})
            }
        }
        
        updated_job = repo.update_job(job.id, updates, add_audit_entry=True)
        return updated_job is not None
    
    async def _flag_for_manual_intervention(self, repo: BatchJobRepository, job, action: RecoveryAction) -> bool:
        """Flag job for manual intervention."""
        updates = {
            'status': BatchJobStatus.PAUSED,
            'tags': job.tags + ['manual_intervention_required'] if job.tags else ['manual_intervention_required'],
            'custom_metadata': {
                **job.custom_metadata,
                'manual_intervention': {
                    'required': True,
                    'reason': f"Critical job failed after {action.retry_count} retries",
                    'failure_type': action.failure_type,
                    'flagged_at': datetime.now(timezone.utc).isoformat()
                }
            }
        }
        
        updated_job = repo.update_job(job.id, updates, add_audit_entry=True)
        
        # Send notification (would integrate with notification system)
        logger.critical(f"MANUAL INTERVENTION REQUIRED for job {job.id}: {job.name}")
        
        return updated_job is not None
    
    async def _handle_recovery_failure(self, action: RecoveryAction) -> None:
        """Handle case where recovery action itself fails."""
        
        # If retry failed, try a different strategy
        if action.strategy in [RecoveryStrategy.RETRY_IMMEDIATE, RecoveryStrategy.RETRY_EXPONENTIAL_BACKOFF]:
            # Escalate to reassignment or dead letter
            new_action = RecoveryAction(
                job_id=action.job_id,
                strategy=RecoveryStrategy.REASSIGN_TO_DIFFERENT_WORKER,
                failure_type=action.failure_type,
                retry_count=action.retry_count,
                delay_seconds=60,
                metadata=action.metadata
            )
            self._recovery_queue.append(new_action)
        
        elif action.strategy == RecoveryStrategy.REASSIGN_TO_DIFFERENT_WORKER:
            # Move to dead letter queue
            new_action = RecoveryAction(
                job_id=action.job_id,
                strategy=RecoveryStrategy.MOVE_TO_DEAD_LETTER,
                failure_type=action.failure_type,
                retry_count=action.retry_count,
                delay_seconds=0,
                metadata=action.metadata
            )
            self._recovery_queue.append(new_action)
    
    async def _health_check_loop(self) -> None:
        """Periodic health checks to detect issues proactively."""
        while self._is_running:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self._health_check_interval)
                
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")
                await asyncio.sleep(60)
    
    async def _perform_health_checks(self) -> None:
        """Perform comprehensive health checks."""
        try:
            with transaction_scope() as session:
                repo = BatchJobRepository(session)
                
                # Check for stale jobs
                stale_jobs = repo.get_stale_jobs(heartbeat_timeout=300)
                for job in stale_jobs:
                    await self.handle_job_failure(
                        job.id,
                        FailureType.WORKER_DISCONNECT,
                        {'reason': 'stale_heartbeat_detected'}
                    )
                
                # Check for expired jobs
                expired_jobs = repo.get_expired_jobs()
                for job in expired_jobs:
                    await self.handle_job_failure(
                        job.id,
                        FailureType.TASK_TIMEOUT,
                        {'reason': 'job_timeout_detected'}
                    )
                
                # Check worker health
                worker_repo = BatchWorkerRepository(session)
                inactive_workers = worker_repo.get_inactive_workers(inactive_timeout=300)
                if inactive_workers:
                    worker_ids = [w.id for w in inactive_workers]
                    worker_repo.mark_workers_offline(worker_ids)
                    logger.info(f"Marked {len(worker_ids)} workers as offline during health check")
        
        except Exception as e:
            logger.error(f"Health check failed: {e}")
    
    def _update_failure_stats(self, failure_type: FailureType, strategy: RecoveryStrategy) -> None:
        """Update failure and recovery statistics."""
        
        failure_key = failure_type.value if hasattr(failure_type, 'value') else str(failure_type)
        strategy_key = strategy.value if hasattr(strategy, 'value') else str(strategy)
        
        self._recovery_stats['failure_types_encountered'][failure_key] = \
            self._recovery_stats['failure_types_encountered'].get(failure_key, 0) + 1
        
        self._recovery_stats['recovery_strategies_used'][strategy_key] = \
            self._recovery_stats['recovery_strategies_used'].get(strategy_key, 0) + 1
    
    def get_recovery_stats(self) -> Dict[str, Any]:
        """Get recovery statistics."""
        return {
            **self._recovery_stats,
            'recovery_queue_length': len(self._recovery_queue),
            'is_running': self._is_running
        }
    
    async def retry_dead_letter_jobs(self, max_jobs: int = 10) -> Dict[str, Any]:
        """Retry jobs from dead letter queue."""
        try:
            redis_service = get_redis_service()
            if not await redis_service.is_connected():
                return {'error': 'Redis not connected'}
            
            retried_jobs = await redis_service.retry_dead_letter_jobs(max_jobs)
            
            return {
                'jobs_retried': retried_jobs,
                'max_jobs_requested': max_jobs
            }
            
        except Exception as e:
            logger.error(f"Failed to retry dead letter jobs: {e}")
            return {'error': str(e)}


# Global fault tolerance manager instance
_fault_tolerance_manager: Optional[FaultToleranceManager] = None


def get_fault_tolerance_manager() -> FaultToleranceManager:
    """Get the global fault tolerance manager instance."""
    global _fault_tolerance_manager
    if _fault_tolerance_manager is None:
        _fault_tolerance_manager = FaultToleranceManager()
    return _fault_tolerance_manager


async def initialize_fault_tolerance_manager() -> FaultToleranceManager:
    """Initialize the fault tolerance manager."""
    manager = get_fault_tolerance_manager()
    await manager.start()
    logger.info("Fault Tolerance Manager initialized successfully")
    return manager