"""
Celery Configuration for Distributed Batch Processing

Provides Celery setup and task definitions for distributed
asynchronous job processing.
"""

import os
import logging
from typing import Dict, Any, Optional, List
from datetime import timedelta

from celery import Celery
from celery.signals import (
    task_prerun, task_postrun, task_failure, task_retry,
    worker_ready, worker_shutdown
)
from kombu import Queue

from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


# Celery Configuration
class CeleryConfig:
    """Celery configuration settings."""
    
    # Broker settings (Redis)
    broker_url = f"redis://{getattr(settings, 'redis_host', 'localhost')}:{getattr(settings, 'redis_port', 6379)}/{getattr(settings, 'redis_db', 0)}"
    result_backend = broker_url
    
    # Task settings
    task_serializer = 'json'
    accept_content = ['json']
    result_serializer = 'json'
    timezone = 'UTC'
    enable_utc = True
    
    # Task execution settings
    task_always_eager = getattr(settings, 'celery_always_eager', False)  # For testing
    task_eager_propagates = True
    task_ignore_result = False
    task_store_errors_even_if_ignored = True
    
    # Task routing
    task_routes = {
        'batch.tasks.process_document': {'queue': 'document_processing'},
        'batch.tasks.detect_pii': {'queue': 'pii_detection'},
        'batch.tasks.bulk_redaction': {'queue': 'bulk_redaction'},
        'batch.tasks.compliance_validation': {'queue': 'compliance'},
        'batch.tasks.audit_generation': {'queue': 'audit'},
        'batch.tasks.report_generation': {'queue': 'reporting'},
    }
    
    # Queue definitions
    task_queues = (
        Queue('default', routing_key='default'),
        Queue('document_processing', routing_key='document_processing'),
        Queue('pii_detection', routing_key='pii_detection'),
        Queue('bulk_redaction', routing_key='bulk_redaction'),
        Queue('compliance', routing_key='compliance'),
        Queue('audit', routing_key='audit'),
        Queue('reporting', routing_key='reporting'),
        Queue('high_priority', routing_key='high_priority'),
        Queue('low_priority', routing_key='low_priority'),
    )
    
    # Worker settings
    worker_prefetch_multiplier = 1
    worker_max_tasks_per_child = 1000
    worker_disable_rate_limits = False
    worker_log_format = '[%(asctime)s: %(levelname)s/%(processName)s] %(message)s'
    worker_task_log_format = '[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s'
    
    # Result backend settings
    result_expires = 3600  # 1 hour
    result_persistent = True
    result_backend_max_retries = 10
    result_backend_retry_delay = 1
    
    # Retry settings
    task_acks_late = True
    task_reject_on_worker_lost = True
    task_default_max_retries = 3
    task_default_retry_delay = 60
    
    # Beat schedule (for periodic tasks)
    beat_schedule = {
        'cleanup-expired-jobs': {
            'task': 'batch.tasks.cleanup_expired_jobs',
            'schedule': timedelta(hours=1),
        },
        'update-worker-health': {
            'task': 'batch.tasks.update_worker_health',
            'schedule': timedelta(minutes=5),
        },
        'process-scheduled-jobs': {
            'task': 'batch.tasks.process_scheduled_jobs',
            'schedule': timedelta(minutes=1),
        },
    }
    
    # Security settings
    worker_hijack_root_logger = False
    worker_log_color = False if os.getenv('CELERY_NO_COLOR') else True
    
    # Monitoring settings
    worker_send_task_events = True
    task_send_sent_event = True
    
    # Database settings for result backend
    database_short_lived_sessions = True


# Create Celery app
def create_celery_app(app_name: str = 'batch_processor') -> Celery:
    """Create and configure Celery application."""
    
    celery_app = Celery(app_name)
    celery_app.config_from_object(CeleryConfig)
    
    # Configure logging
    celery_app.log.setup_logging_subsystem(
        loglevel=logging.INFO,
        logfile=None,
        format='[%(asctime)s: %(levelname)s/%(processName)s] %(message)s',
        colorize=True
    )
    
    logger.info(f"Celery app '{app_name}' created and configured")
    return celery_app


# Global Celery app instance
celery_app = create_celery_app()


# Task decorator with common settings
def batch_task(**kwargs):
    """Decorator for batch processing tasks with common settings."""
    default_kwargs = {
        'bind': True,
        'autoretry_for': (Exception,),
        'retry_kwargs': {'max_retries': 3, 'countdown': 60},
        'retry_backoff': True,
        'retry_backoff_max': 600,  # 10 minutes
        'retry_jitter': True,
    }
    default_kwargs.update(kwargs)
    return celery_app.task(**default_kwargs)


# Signal handlers for monitoring and logging
@task_prerun.connect
def task_prerun_handler(task_id, task, *args, **kwargs):
    """Handle task pre-run signals."""
    logger.info(f"Starting task {task.name}[{task_id}]")
    
    # Update database with task start
    try:
        from ..database.repositories.batch_job_repository import BatchJobRepository
        from ..database.session import get_db_session
        
        with get_db_session() as session:
            repo = BatchJobRepository(session)
            
            # Try to find job by task_id in custom metadata
            jobs = repo.find_jobs(limit=1)  # This would need better filtering
            if jobs:
                repo.update_job_status(jobs[0].id, 'running')
                logger.debug(f"Updated job status to running for task {task_id}")
                
    except Exception as e:
        logger.error(f"Failed to update job status on task start: {e}")


@task_postrun.connect
def task_postrun_handler(task_id, task, *args, **kwargs):
    """Handle task post-run signals."""
    state = kwargs.get('state', 'UNKNOWN')
    logger.info(f"Task {task.name}[{task_id}] completed with state: {state}")
    
    # Update database with task completion
    try:
        from ..database.repositories.batch_job_repository import BatchJobRepository
        from ..database.session import get_db_session
        
        with get_db_session() as session:
            repo = BatchJobRepository(session)
            
            # Map Celery states to our job states
            job_status = 'completed' if state == 'SUCCESS' else 'failed'
            
            # This would need better job identification
            jobs = repo.find_jobs(limit=1)
            if jobs:
                repo.update_job_status(jobs[0].id, job_status)
                logger.debug(f"Updated job status to {job_status} for task {task_id}")
                
    except Exception as e:
        logger.error(f"Failed to update job status on task completion: {e}")


@task_failure.connect
def task_failure_handler(task_id, exception, traceback, einfo):
    """Handle task failure signals."""
    logger.error(f"Task {task_id} failed: {exception}")
    logger.debug(f"Task failure traceback: {traceback}")
    
    # Update database with failure info
    try:
        from ..database.repositories.batch_job_repository import BatchJobRepository
        from ..database.session import get_db_session
        
        with get_db_session() as session:
            repo = BatchJobRepository(session)
            
            # This would need better job identification
            jobs = repo.find_jobs(limit=1)
            if jobs:
                repo.update_job(jobs[0].id, {
                    'status': 'failed',
                    'error_message': str(exception),
                    'error_details': {
                        'exception_type': type(exception).__name__,
                        'traceback': traceback
                    }
                })
                logger.debug(f"Updated job with failure info for task {task_id}")
                
    except Exception as e:
        logger.error(f"Failed to update job failure info: {e}")


@task_retry.connect
def task_retry_handler(task_id, reason, einfo):
    """Handle task retry signals."""
    logger.warning(f"Task {task_id} retrying due to: {reason}")
    
    # Update database with retry info
    try:
        from ..database.repositories.batch_job_repository import BatchJobRepository
        from ..database.session import get_db_session
        
        with get_db_session() as session:
            repo = BatchJobRepository(session)
            
            # This would need better job identification
            jobs = repo.find_jobs(limit=1)
            if jobs:
                repo.update_job(jobs[0].id, {
                    'retry_count': jobs[0].retry_count + 1,
                    'status': 'queued'
                })
                logger.debug(f"Updated job retry count for task {task_id}")
                
    except Exception as e:
        logger.error(f"Failed to update job retry info: {e}")


@worker_ready.connect
def worker_ready_handler(sender, **kwargs):
    """Handle worker ready signals."""
    logger.info(f"Celery worker {sender} is ready")
    
    # Register worker in database
    try:
        from ..database.repositories.batch_worker_repository import BatchWorkerRepository
        from ..database.session import get_db_session
        
        with get_db_session() as session:
            repo = BatchWorkerRepository(session)
            
            worker_data = {
                'worker_name': f"celery-worker-{os.getpid()}",
                'hostname': sender.hostname,
                'pid': os.getpid(),
                'worker_type': 'celery',
                'supported_job_types': [
                    'document_processing', 'pii_detection', 'bulk_redaction',
                    'compliance_validation', 'audit_generation', 'report_generation'
                ],
                'max_concurrent_jobs': getattr(sender, 'concurrency', 1),
                'status': 'idle',
                'version': '1.0.0',
                'queue_names': list(sender.task_consumer.queues.keys()) if hasattr(sender, 'task_consumer') else [],
                'tags': ['celery', 'distributed']
            }
            
            worker = repo.register_worker(worker_data)
            logger.info(f"Registered Celery worker: {worker.id}")
            
    except Exception as e:
        logger.error(f"Failed to register Celery worker: {e}")


@worker_shutdown.connect
def worker_shutdown_handler(sender, **kwargs):
    """Handle worker shutdown signals."""
    logger.info(f"Celery worker {sender} is shutting down")
    
    # Update worker status in database
    try:
        from ..database.repositories.batch_worker_repository import BatchWorkerRepository
        from ..database.session import get_db_session
        
        with get_db_session() as session:
            repo = BatchWorkerRepository(session)
            
            # Find and mark worker as offline
            # This would need better worker identification
            inactive_workers = repo.get_inactive_workers(inactive_timeout=0)
            for worker in inactive_workers:
                if worker.hostname == sender.hostname:
                    repo.mark_workers_offline([worker.id])
                    logger.info(f"Marked Celery worker {worker.id} as offline")
                    break
                    
    except Exception as e:
        logger.error(f"Failed to update worker status on shutdown: {e}")


# Health check function
def celery_health_check() -> Dict[str, Any]:
    """Perform Celery health check."""
    try:
        # Check if Celery is responsive
        inspect = celery_app.control.inspect()
        
        # Get active tasks
        active_tasks = inspect.active()
        
        # Get scheduled tasks
        scheduled_tasks = inspect.scheduled()
        
        # Get worker stats
        stats = inspect.stats()
        
        # Count workers
        active_workers = len(active_tasks) if active_tasks else 0
        
        return {
            "status": "healthy",
            "active_workers": active_workers,
            "active_tasks_count": sum(len(tasks) for tasks in (active_tasks or {}).values()),
            "scheduled_tasks_count": sum(len(tasks) for tasks in (scheduled_tasks or {}).values()),
            "worker_stats": stats
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }


# Utility functions
def get_task_info(task_id: str) -> Optional[Dict[str, Any]]:
    """Get information about a specific task."""
    try:
        result = celery_app.AsyncResult(task_id)
        return {
            "task_id": task_id,
            "state": result.state,
            "result": result.result,
            "traceback": result.traceback,
            "successful": result.successful(),
            "failed": result.failed(),
            "ready": result.ready()
        }
    except Exception as e:
        logger.error(f"Failed to get task info for {task_id}: {e}")
        return None


def revoke_task(task_id: str, terminate: bool = False) -> bool:
    """Revoke (cancel) a task."""
    try:
        celery_app.control.revoke(task_id, terminate=terminate)
        logger.info(f"Revoked task {task_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to revoke task {task_id}: {e}")
        return False


def get_queue_info() -> Dict[str, Any]:
    """Get information about Celery queues."""
    try:
        inspect = celery_app.control.inspect()
        
        # Get active queues
        active_queues = inspect.active_queues()
        
        # Get reserved tasks
        reserved = inspect.reserved()
        
        return {
            "active_queues": active_queues,
            "reserved_tasks": reserved
        }
        
    except Exception as e:
        logger.error(f"Failed to get queue info: {e}")
        return {"error": str(e)}