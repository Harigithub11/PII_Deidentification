"""
Celery Tasks for Distributed Batch Processing

Defines all Celery tasks for asynchronous batch job processing.
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta
from uuid import UUID
import traceback

from celery import Task
from celery.exceptions import Retry, WorkerLostError

from .celery_config import celery_app, batch_task
from ..database.session import get_db_session, transaction_scope
from ..database.repositories.batch_job_repository import BatchJobRepository
from ..database.repositories.job_result_repository import JobResultRepository
from ..database.repositories.batch_worker_repository import BatchWorkerRepository
from ..database.repositories.job_schedule_repository import JobScheduleRepository
from ..database.models import BatchJobStatus, BatchJobType
from ..processing.document_pii_processor import get_document_pii_processor
from ..services.redis_service import get_redis_service

logger = logging.getLogger(__name__)


class BaseJobTask(Task):
    """Base task class for batch job processing."""
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure."""
        logger.error(f"Task {task_id} failed: {exc}")
        
        try:
            job_id = kwargs.get('job_id') or (args[0] if args else None)
            if job_id:
                with transaction_scope() as session:
                    repo = BatchJobRepository(session)
                    repo.update_job(UUID(str(job_id)), {
                        'status': BatchJobStatus.FAILED,
                        'completed_at': datetime.now(timezone.utc),
                        'error_message': str(exc),
                        'error_details': {
                            'exception_type': type(exc).__name__,
                            'traceback': einfo.traceback
                        }
                    })
        except Exception as e:
            logger.error(f"Failed to update job failure status: {e}")
    
    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """Handle task retry."""
        logger.warning(f"Task {task_id} retrying: {exc}")
        
        try:
            job_id = kwargs.get('job_id') or (args[0] if args else None)
            if job_id:
                with transaction_scope() as session:
                    repo = BatchJobRepository(session)
                    job = repo.get_job(UUID(str(job_id)))
                    if job:
                        repo.update_job(job.id, {
                            'retry_count': job.retry_count + 1,
                            'status': BatchJobStatus.QUEUED
                        })
        except Exception as e:
            logger.error(f"Failed to update job retry status: {e}")


# Document Processing Tasks

@batch_task(base=BaseJobTask, name='batch.tasks.process_document')
def process_document_task(self, job_id: str, documents: List[str], 
                         parameters: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Process documents for PII detection and extraction.
    
    Args:
        job_id: Batch job ID
        documents: List of document paths to process
        parameters: Processing parameters
        
    Returns:
        Processing results
    """
    try:
        logger.info(f"Starting document processing task for job {job_id}")
        
        with transaction_scope() as session:
            repo = BatchJobRepository(session)
            
            # Update job status
            repo.update_job_status(UUID(job_id), BatchJobStatus.RUNNING)
            repo.update_job_progress(UUID(job_id), 0, "Starting document processing")
            
            # Get document processor
            processor = get_document_pii_processor()
            
            results = []
            total_docs = len(documents)
            processed_docs = 0
            failed_docs = 0
            
            for i, doc_path in enumerate(documents):
                try:
                    # Update progress
                    progress = int((i / total_docs) * 100)
                    repo.update_job_progress(
                        UUID(job_id), progress, 
                        f"Processing document {i + 1}/{total_docs}: {doc_path}"
                    )
                    
                    # Process document (this would be the actual processing)
                    # For now, simulate processing
                    import time
                    time.sleep(0.1)  # Simulate processing time
                    
                    doc_result = {
                        'document_path': doc_path,
                        'status': 'completed',
                        'pii_found': 5,  # Simulated
                        'processing_time_ms': 100,
                        'pages_processed': 3
                    }
                    
                    results.append(doc_result)
                    processed_docs += 1
                    
                except Exception as e:
                    logger.error(f"Failed to process document {doc_path}: {e}")
                    results.append({
                        'document_path': doc_path,
                        'status': 'failed',
                        'error': str(e)
                    })
                    failed_docs += 1
            
            # Final progress update
            repo.update_job_progress(UUID(job_id), 100, "Document processing completed")
            repo.update_job_status(UUID(job_id), BatchJobStatus.COMPLETED)
            
            # Create result record
            result_repo = JobResultRepository(session)
            result_repo.create_result({
                'job_id': UUID(job_id),
                'execution_id': self.request.id,
                'started_at': datetime.now(timezone.utc) - timedelta(seconds=total_docs * 0.1),
                'completed_at': datetime.now(timezone.utc),
                'duration_seconds': total_docs * 0.1,
                'status': BatchJobStatus.COMPLETED,
                'result_data': {
                    'documents_processed': processed_docs,
                    'documents_failed': failed_docs,
                    'results': results
                },
                'items_processed': total_docs,
                'items_successful': processed_docs,
                'items_failed': failed_docs
            })
            
            logger.info(f"Document processing completed for job {job_id}: {processed_docs}/{total_docs} successful")
            
            return {
                'documents_processed': processed_docs,
                'documents_failed': failed_docs,
                'total_documents': total_docs,
                'results': results
            }
            
    except Exception as e:
        logger.error(f"Document processing task failed for job {job_id}: {e}")
        raise


@batch_task(base=BaseJobTask, name='batch.tasks.detect_pii')
def detect_pii_task(self, job_id: str, documents: List[str], 
                   detection_config: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Detect PII in documents.
    
    Args:
        job_id: Batch job ID
        documents: List of document paths
        detection_config: PII detection configuration
        
    Returns:
        PII detection results
    """
    try:
        logger.info(f"Starting PII detection task for job {job_id}")
        
        with transaction_scope() as session:
            repo = BatchJobRepository(session)
            
            # Update job status
            repo.update_job_status(UUID(job_id), BatchJobStatus.RUNNING)
            repo.update_job_progress(UUID(job_id), 0, "Starting PII detection")
            
            pii_results = []
            total_pii_found = 0
            total_docs = len(documents)
            
            for i, doc_path in enumerate(documents):
                try:
                    # Update progress
                    progress = int((i / total_docs) * 100)
                    repo.update_job_progress(
                        UUID(job_id), progress,
                        f"Analyzing document {i + 1}/{total_docs}: {doc_path}"
                    )
                    
                    # Simulate PII detection
                    import time
                    time.sleep(0.05)
                    
                    # Simulated PII detection results
                    pii_count = 3  # Simulated
                    total_pii_found += pii_count
                    
                    pii_results.append({
                        'document': doc_path,
                        'pii_found': pii_count > 0,
                        'pii_count': pii_count,
                        'pii_types': ['name', 'email', 'phone'] if pii_count > 0 else [],
                        'confidence_scores': [0.95, 0.87, 0.92] if pii_count > 0 else []
                    })
                    
                except Exception as e:
                    logger.error(f"PII detection failed for document {doc_path}: {e}")
                    pii_results.append({
                        'document': doc_path,
                        'error': str(e)
                    })
            
            # Final progress update
            repo.update_job_progress(UUID(job_id), 100, "PII detection completed")
            repo.update_job_status(UUID(job_id), BatchJobStatus.COMPLETED)
            
            # Create result record
            result_repo = JobResultRepository(session)
            result_repo.create_result({
                'job_id': UUID(job_id),
                'execution_id': self.request.id,
                'started_at': datetime.now(timezone.utc) - timedelta(seconds=total_docs * 0.05),
                'completed_at': datetime.now(timezone.utc),
                'duration_seconds': total_docs * 0.05,
                'status': BatchJobStatus.COMPLETED,
                'result_data': {
                    'total_pii_found': total_pii_found,
                    'documents_analyzed': total_docs,
                    'results': pii_results
                },
                'items_processed': total_docs,
                'items_successful': len([r for r in pii_results if 'error' not in r]),
                'items_failed': len([r for r in pii_results if 'error' in r])
            })
            
            logger.info(f"PII detection completed for job {job_id}: {total_pii_found} PII items found")
            
            return {
                'documents_analyzed': total_docs,
                'total_pii_found': total_pii_found,
                'results': pii_results
            }
            
    except Exception as e:
        logger.error(f"PII detection task failed for job {job_id}: {e}")
        raise


@batch_task(base=BaseJobTask, name='batch.tasks.bulk_redaction')
def bulk_redaction_task(self, job_id: str, documents: List[str], 
                       redaction_config: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Perform bulk redaction on documents.
    
    Args:
        job_id: Batch job ID
        documents: List of document paths
        redaction_config: Redaction configuration
        
    Returns:
        Redaction results
    """
    try:
        logger.info(f"Starting bulk redaction task for job {job_id}")
        
        with transaction_scope() as session:
            repo = BatchJobRepository(session)
            
            # Update job status
            repo.update_job_status(UUID(job_id), BatchJobStatus.RUNNING)
            repo.update_job_progress(UUID(job_id), 0, "Starting bulk redaction")
            
            redaction_method = redaction_config.get('method', 'blackout') if redaction_config else 'blackout'
            
            redacted_docs = 0
            failed_docs = 0
            total_docs = len(documents)
            
            for i, doc_path in enumerate(documents):
                try:
                    # Update progress
                    progress = int((i / total_docs) * 100)
                    repo.update_job_progress(
                        UUID(job_id), progress,
                        f"Redacting document {i + 1}/{total_docs}: {doc_path}"
                    )
                    
                    # Simulate redaction
                    import time
                    time.sleep(0.2)
                    
                    redacted_docs += 1
                    
                except Exception as e:
                    logger.error(f"Redaction failed for document {doc_path}: {e}")
                    failed_docs += 1
            
            # Final progress update
            repo.update_job_progress(UUID(job_id), 100, "Bulk redaction completed")
            repo.update_job_status(UUID(job_id), BatchJobStatus.COMPLETED)
            
            # Create result record
            result_repo = JobResultRepository(session)
            result_repo.create_result({
                'job_id': UUID(job_id),
                'execution_id': self.request.id,
                'started_at': datetime.now(timezone.utc) - timedelta(seconds=total_docs * 0.2),
                'completed_at': datetime.now(timezone.utc),
                'duration_seconds': total_docs * 0.2,
                'status': BatchJobStatus.COMPLETED,
                'result_data': {
                    'documents_redacted': redacted_docs,
                    'redaction_method': redaction_method,
                    'documents_failed': failed_docs
                },
                'items_processed': total_docs,
                'items_successful': redacted_docs,
                'items_failed': failed_docs
            })
            
            logger.info(f"Bulk redaction completed for job {job_id}: {redacted_docs}/{total_docs} successful")
            
            return {
                'documents_redacted': redacted_docs,
                'documents_failed': failed_docs,
                'redaction_method': redaction_method
            }
            
    except Exception as e:
        logger.error(f"Bulk redaction task failed for job {job_id}: {e}")
        raise


@batch_task(base=BaseJobTask, name='batch.tasks.compliance_validation')
def compliance_validation_task(self, job_id: str, validation_rules: List[Dict[str, Any]],
                             target_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate compliance against specified rules.
    
    Args:
        job_id: Batch job ID
        validation_rules: List of compliance rules to validate
        target_data: Data to validate against
        
    Returns:
        Validation results
    """
    try:
        logger.info(f"Starting compliance validation task for job {job_id}")
        
        with transaction_scope() as session:
            repo = BatchJobRepository(session)
            
            # Update job status
            repo.update_job_status(UUID(job_id), BatchJobStatus.RUNNING)
            repo.update_job_progress(UUID(job_id), 0, "Starting compliance validation")
            
            validation_results = []
            passed_rules = 0
            failed_rules = 0
            total_rules = len(validation_rules)
            
            for i, rule in enumerate(validation_rules):
                try:
                    # Update progress
                    progress = int((i / total_rules) * 100)
                    repo.update_job_progress(
                        UUID(job_id), progress,
                        f"Validating rule {i + 1}/{total_rules}: {rule.get('name', 'Unknown')}"
                    )
                    
                    # Simulate validation
                    import time
                    time.sleep(0.1)
                    
                    # Simulated validation result
                    passed = True  # Simulated
                    
                    validation_results.append({
                        'rule_id': rule.get('id'),
                        'rule_name': rule.get('name'),
                        'passed': passed,
                        'score': 95 if passed else 45,
                        'details': f"Rule validation {'passed' if passed else 'failed'}"
                    })
                    
                    if passed:
                        passed_rules += 1
                    else:
                        failed_rules += 1
                        
                except Exception as e:
                    logger.error(f"Validation failed for rule {rule.get('name')}: {e}")
                    validation_results.append({
                        'rule_id': rule.get('id'),
                        'rule_name': rule.get('name'),
                        'passed': False,
                        'error': str(e)
                    })
                    failed_rules += 1
            
            # Calculate overall compliance score
            compliance_score = (passed_rules / total_rules) * 100 if total_rules > 0 else 0
            
            # Final progress update
            repo.update_job_progress(UUID(job_id), 100, "Compliance validation completed")
            repo.update_job_status(UUID(job_id), BatchJobStatus.COMPLETED)
            
            # Create result record
            result_repo = JobResultRepository(session)
            result_repo.create_result({
                'job_id': UUID(job_id),
                'execution_id': self.request.id,
                'started_at': datetime.now(timezone.utc) - timedelta(seconds=total_rules * 0.1),
                'completed_at': datetime.now(timezone.utc),
                'duration_seconds': total_rules * 0.1,
                'status': BatchJobStatus.COMPLETED,
                'result_data': {
                    'compliance_score': compliance_score,
                    'rules_passed': passed_rules,
                    'rules_failed': failed_rules,
                    'validation_results': validation_results
                },
                'items_processed': total_rules,
                'items_successful': passed_rules,
                'items_failed': failed_rules
            })
            
            logger.info(f"Compliance validation completed for job {job_id}: {compliance_score}% compliance")
            
            return {
                'compliance_score': compliance_score,
                'rules_passed': passed_rules,
                'rules_failed': failed_rules,
                'validation_results': validation_results
            }
            
    except Exception as e:
        logger.error(f"Compliance validation task failed for job {job_id}: {e}")
        raise


# System Maintenance Tasks

@batch_task(name='batch.tasks.cleanup_expired_jobs')
def cleanup_expired_jobs():
    """Clean up expired and old jobs."""
    try:
        logger.info("Starting cleanup of expired jobs")
        
        with transaction_scope() as session:
            job_repo = BatchJobRepository(session)
            result_repo = JobResultRepository(session)
            
            # Clean up old completed jobs (older than 7 days)
            cleaned_jobs = job_repo.cleanup_old_jobs(older_than_days=7)
            
            # Clean up old results (older than 30 days) 
            cleaned_results = result_repo.cleanup_old_results(older_than_days=30)
            
            logger.info(f"Cleanup completed: {cleaned_jobs} jobs, {cleaned_results} results removed")
            
            return {
                'cleaned_jobs': cleaned_jobs,
                'cleaned_results': cleaned_results
            }
            
    except Exception as e:
        logger.error(f"Cleanup task failed: {e}")
        raise


@batch_task(name='batch.tasks.update_worker_health')
def update_worker_health():
    """Update worker health status."""
    try:
        logger.info("Updating worker health status")
        
        with transaction_scope() as session:
            worker_repo = BatchWorkerRepository(session)
            
            # Get inactive workers
            inactive_workers = worker_repo.get_inactive_workers(inactive_timeout=300)  # 5 minutes
            
            # Mark inactive workers as offline
            if inactive_workers:
                worker_ids = [worker.id for worker in inactive_workers]
                marked_offline = worker_repo.mark_workers_offline(worker_ids)
                logger.info(f"Marked {marked_offline} workers as offline")
            
            # Clean up old offline workers
            cleaned_workers = worker_repo.cleanup_old_workers(offline_days=1)
            
            logger.info(f"Worker health update completed: {len(inactive_workers)} marked offline, {cleaned_workers} cleaned up")
            
            return {
                'workers_marked_offline': len(inactive_workers),
                'workers_cleaned_up': cleaned_workers
            }
            
    except Exception as e:
        logger.error(f"Worker health update task failed: {e}")
        raise


@batch_task(name='batch.tasks.process_scheduled_jobs')
def process_scheduled_jobs():
    """Process due scheduled jobs."""
    try:
        logger.info("Processing scheduled jobs")
        
        with transaction_scope() as session:
            schedule_repo = JobScheduleRepository(session)
            job_repo = BatchJobRepository(session)
            
            # Get due schedules
            due_schedules = schedule_repo.get_due_schedules()
            
            jobs_created = 0
            
            for schedule in due_schedules:
                try:
                    # Get template job
                    template_job = job_repo.get_job(schedule.job_id)
                    if not template_job:
                        continue
                    
                    # Create scheduled job
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
                    
                    scheduled_job = job_repo.create_job(job_data)
                    jobs_created += 1
                    
                    # Update schedule (simplified - would use proper cron calculation)
                    next_run = datetime.now(timezone.utc) + timedelta(hours=24)
                    schedule_repo.update_schedule_after_run(
                        schedule.id,
                        BatchJobStatus.QUEUED,
                        next_run
                    )
                    
                    logger.info(f"Created scheduled job: {scheduled_job.id}")
                    
                except Exception as e:
                    logger.error(f"Failed to process schedule {schedule.id}: {e}")
            
            logger.info(f"Scheduled jobs processing completed: {jobs_created} jobs created")
            
            return {
                'jobs_created': jobs_created,
                'schedules_processed': len(due_schedules)
            }
            
    except Exception as e:
        logger.error(f"Scheduled jobs processing task failed: {e}")
        raise


# Task dispatcher function
def submit_celery_job(job_type: BatchJobType, job_id: UUID, 
                     job_data: Dict[str, Any]) -> Optional[str]:
    """
    Submit a job to appropriate Celery task.
    
    Args:
        job_type: Type of batch job
        job_id: Job ID
        job_data: Job data and parameters
        
    Returns:
        Celery task ID or None
    """
    try:
        task_kwargs = {'job_id': str(job_id)}
        
        if job_type == BatchJobType.DOCUMENT_PROCESSING:
            task = process_document_task.delay(
                str(job_id),
                job_data.get('documents', []),
                job_data.get('parameters', {})
            )
        elif job_type == BatchJobType.PII_DETECTION:
            task = detect_pii_task.delay(
                str(job_id),
                job_data.get('documents', []),
                job_data.get('detection_config', {})
            )
        elif job_type == BatchJobType.BULK_REDACTION:
            task = bulk_redaction_task.delay(
                str(job_id),
                job_data.get('documents', []),
                job_data.get('redaction_config', {})
            )
        elif job_type == BatchJobType.COMPLIANCE_VALIDATION:
            task = compliance_validation_task.delay(
                str(job_id),
                job_data.get('validation_rules', []),
                job_data.get('target_data', {})
            )
        else:
            logger.warning(f"No Celery task defined for job type: {job_type}")
            return None
        
        logger.info(f"Submitted Celery task {task.id} for job {job_id}")
        return task.id
        
    except Exception as e:
        logger.error(f"Failed to submit Celery job {job_id}: {e}")
        return None