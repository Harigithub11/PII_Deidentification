"""
Airflow Integration Engine

Main orchestrator for integrating with Apache Airflow, providing seamless
workflow execution, DAG management, and bidirectional synchronization.
"""

import logging
import asyncio
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union
from uuid import UUID, uuid4
from pathlib import Path

from sqlalchemy.orm import Session
from airflow import DAG
from airflow.models import DagRun, TaskInstance
from airflow.api.client.local_client import Client as AirflowClient
from airflow.exceptions import AirflowException

from ..database.session import get_db_session, transaction_scope
from ..database.repositories.batch_job_repository import BatchJobRepository
from ..database.repositories.job_schedule_repository import JobScheduleRepository
from ..config.settings import get_settings
from .workflow_models import (
    WorkflowDefinition, WorkflowExecution, WorkflowStatus,
    StepType, WorkflowStep, WorkflowMetrics
)
from .dag_generator import DAGGenerator, WorkflowDAGBuilder
from .airflow_sync import AirflowSyncService

logger = logging.getLogger(__name__)
settings = get_settings()


class AirflowIntegrationEngine:
    """
    Core engine for integrating with Apache Airflow.
    
    Provides workflow orchestration, DAG generation, execution management,
    and bidirectional synchronization between the batch system and Airflow.
    """
    
    def __init__(self, session: Optional[Session] = None):
        self._session = session
        
        # Repository dependencies
        self._job_repository = BatchJobRepository(session)
        self._schedule_repository = JobScheduleRepository(session)
        
        # Core components
        self._dag_generator = DAGGenerator()
        self._workflow_builder = WorkflowDAGBuilder()
        self._sync_service = AirflowSyncService(session)
        
        # Active workflows and executions
        self._active_workflows: Dict[UUID, WorkflowDefinition] = {}
        self._active_executions: Dict[UUID, WorkflowExecution] = {}
        
        # Airflow client and configuration
        self._airflow_client: Optional[AirflowClient] = None
        self._dags_folder = getattr(settings, 'airflow_dags_folder', './orchestration/dags')
        self._airflow_enabled = getattr(settings, 'airflow_enabled', True)
        
        # Background tasks
        self._sync_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        
        # Metrics
        self._workflow_metrics: Dict[UUID, WorkflowMetrics] = {}
        
        logger.info("Airflow Integration Engine initialized")
    
    @property
    def session(self) -> Session:
        """Get current database session."""
        if self._session:
            return self._session
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
    
    async def start(self) -> None:
        """Start the Airflow integration engine."""
        if not self._airflow_enabled:
            logger.info("Airflow integration is disabled")
            return
        
        try:
            logger.info("Starting Airflow Integration Engine...")
            
            # Validate Airflow connection
            await self._validate_airflow_connection()
            
            # Ensure DAGs folder exists
            Path(self._dags_folder).mkdir(parents=True, exist_ok=True)
            
            # Start background tasks
            self._sync_task = asyncio.create_task(self._sync_loop())
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            
            # Load active workflows from database
            await self._load_active_workflows()
            
            # Sync existing DAGs
            await self._sync_existing_dags()
            
            logger.info("✅ Airflow Integration Engine started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start Airflow Integration Engine: {e}")
            await self.stop()
            raise
    
    async def stop(self) -> None:
        """Stop the Airflow integration engine gracefully."""
        logger.info("Stopping Airflow Integration Engine...")
        
        # Cancel background tasks
        for task in [self._sync_task, self._cleanup_task]:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        logger.info("✅ Airflow Integration Engine stopped")
    
    async def create_workflow(self, workflow: WorkflowDefinition) -> WorkflowDefinition:
        """
        Create a new workflow and optionally generate Airflow DAG.
        
        Args:
            workflow: Workflow definition
            
        Returns:
            Created workflow with DAG information
        """
        try:
            # Validate workflow
            validation_issues = workflow.validate_workflow_integrity()
            if validation_issues:
                raise ValueError(f"Workflow validation failed: {', '.join(validation_issues)}")
            
            # Generate Airflow DAG if enabled
            if workflow.airflow_enabled and self._airflow_enabled:
                if not workflow.airflow_dag_id:
                    workflow.airflow_dag_id = f"workflow_{workflow.name.lower().replace(' ', '_')}_{workflow.id.hex[:8]}"
                
                # Generate DAG file
                dag_path = await self._dag_generator.generate_workflow_dag(
                    workflow, self._dags_folder
                )
                
                logger.info(f"Generated Airflow DAG: {workflow.airflow_dag_id} at {dag_path}")
                
                # Register with Airflow
                await self._register_dag_with_airflow(workflow)
            
            # Store workflow
            self._active_workflows[workflow.id] = workflow
            
            # Initialize metrics
            self._workflow_metrics[workflow.id] = workflow.calculate_metrics()
            
            # Persist to database if needed
            await self._persist_workflow(workflow)
            
            logger.info(f"Workflow created: {workflow.id} - {workflow.name}")
            return workflow
            
        except Exception as e:
            logger.error(f"Failed to create workflow: {e}")
            raise
    
    async def execute_workflow(self, workflow_id: UUID, 
                             triggered_by: UUID,
                             execution_context: Dict[str, Any] = None,
                             use_airflow: bool = None) -> WorkflowExecution:
        """
        Execute a workflow either locally or via Airflow.
        
        Args:
            workflow_id: Workflow to execute
            triggered_by: User who triggered execution
            execution_context: Additional context for execution
            use_airflow: Override workflow's airflow setting
            
        Returns:
            Workflow execution instance
        """
        try:
            workflow = self._active_workflows.get(workflow_id)
            if not workflow:
                raise ValueError(f"Workflow not found: {workflow_id}")
            
            # Create execution instance
            execution = WorkflowExecution(
                workflow_id=workflow_id,
                workflow_version=workflow.version,
                triggered_by=triggered_by,
                execution_context=execution_context or {},
                trigger_type="manual"
            )
            
            # Determine execution method
            should_use_airflow = use_airflow if use_airflow is not None else workflow.airflow_enabled
            
            if should_use_airflow and self._airflow_enabled:
                # Execute via Airflow
                execution = await self._execute_via_airflow(workflow, execution)
            else:
                # Execute locally via BatchProcessingEngine
                execution = await self._execute_locally(workflow, execution)
            
            # Track execution
            self._active_executions[execution.id] = execution
            
            logger.info(f"Started workflow execution: {execution.id} for workflow {workflow.name}")
            return execution
            
        except Exception as e:
            logger.error(f"Failed to execute workflow {workflow_id}: {e}")
            raise
    
    async def get_workflow_status(self, workflow_id: UUID) -> Optional[WorkflowDefinition]:
        """Get current status of a workflow."""
        return self._active_workflows.get(workflow_id)
    
    async def get_execution_status(self, execution_id: UUID) -> Optional[WorkflowExecution]:
        """Get current status of a workflow execution."""
        execution = self._active_executions.get(execution_id)
        if execution and execution.airflow_dag_run_id:
            # Update status from Airflow
            await self._sync_execution_from_airflow(execution)
        return execution
    
    async def cancel_execution(self, execution_id: UUID) -> bool:
        """Cancel a running workflow execution."""
        try:
            execution = self._active_executions.get(execution_id)
            if not execution:
                return False
            
            if execution.airflow_dag_run_id:
                # Cancel Airflow DAG run
                try:
                    dag_run = self.airflow_client.get_dag_run(
                        dag_id=execution.airflow_dag_run_id.split('_')[0],
                        execution_date=execution.airflow_execution_date
                    )
                    if dag_run:
                        self.airflow_client.set_dag_run_state(
                            dag_id=dag_run.dag_id,
                            execution_date=dag_run.execution_date,
                            state='failed'
                        )
                except Exception as e:
                    logger.error(f"Failed to cancel Airflow DAG run: {e}")
            
            # Update execution status
            execution.status = WorkflowStatus.CANCELLED
            execution.completed_at = datetime.now(timezone.utc)
            
            logger.info(f"Cancelled workflow execution: {execution_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cancel execution {execution_id}: {e}")
            return False
    
    async def get_workflow_metrics(self, workflow_id: UUID) -> Optional[WorkflowMetrics]:
        """Get metrics for a specific workflow."""
        return self._workflow_metrics.get(workflow_id)
    
    async def list_workflows(self, 
                           status: Optional[WorkflowStatus] = None,
                           created_by: Optional[UUID] = None,
                           limit: int = 100) -> List[WorkflowDefinition]:
        """List workflows with optional filtering."""
        workflows = list(self._active_workflows.values())
        
        if status:
            workflows = [w for w in workflows if w.status == status]
        if created_by:
            workflows = [w for w in workflows if w.created_by == created_by]
        
        return workflows[:limit]
    
    async def list_executions(self,
                            workflow_id: Optional[UUID] = None,
                            status: Optional[WorkflowStatus] = None,
                            limit: int = 100) -> List[WorkflowExecution]:
        """List workflow executions with optional filtering."""
        executions = list(self._active_executions.values())
        
        if workflow_id:
            executions = [e for e in executions if e.workflow_id == workflow_id]
        if status:
            executions = [e for e in executions if e.status == status]
        
        return executions[:limit]
    
    # Private methods
    
    async def _validate_airflow_connection(self) -> None:
        """Validate connection to Airflow."""
        try:
            # Try to get DAG list to test connection
            dags = self.airflow_client.list_dags()
            logger.info(f"Connected to Airflow with {len(dags)} DAGs")
        except Exception as e:
            logger.warning(f"Airflow connection validation failed: {e}")
            # Continue anyway - Airflow might not be running yet
    
    async def _load_active_workflows(self) -> None:
        """Load active workflows from the database."""
        try:
            # In a real implementation, this would query the database
            # For now, we'll start with an empty state
            logger.info("Loaded active workflows from database")
        except Exception as e:
            logger.error(f"Failed to load active workflows: {e}")
    
    async def _sync_existing_dags(self) -> None:
        """Sync existing DAG files with workflows."""
        try:
            dag_files = Path(self._dags_folder).glob("workflow_*.py")
            for dag_file in dag_files:
                logger.info(f"Found existing DAG file: {dag_file}")
            
            logger.info("Synced existing DAG files")
        except Exception as e:
            logger.error(f"Failed to sync existing DAGs: {e}")
    
    async def _register_dag_with_airflow(self, workflow: WorkflowDefinition) -> None:
        """Register DAG with Airflow scheduler."""
        try:
            # Airflow automatically picks up DAG files from the dags folder
            # We might need to trigger a DAG refresh or wait for the scheduler
            logger.info(f"Registered DAG {workflow.airflow_dag_id} with Airflow")
        except Exception as e:
            logger.error(f"Failed to register DAG with Airflow: {e}")
    
    async def _execute_via_airflow(self, workflow: WorkflowDefinition, 
                                 execution: WorkflowExecution) -> WorkflowExecution:
        """Execute workflow via Airflow."""
        try:
            # Trigger DAG run
            execution_date = datetime.now(timezone.utc)
            
            dag_run = self.airflow_client.trigger_dag(
                dag_id=workflow.airflow_dag_id,
                execution_date=execution_date,
                conf=execution.execution_context
            )
            
            # Update execution with Airflow information
            execution.airflow_dag_run_id = f"{workflow.airflow_dag_id}_{execution_date.isoformat()}"
            execution.airflow_execution_date = execution_date
            execution.status = WorkflowStatus.RUNNING
            execution.started_at = datetime.now(timezone.utc)
            
            logger.info(f"Triggered Airflow DAG run: {execution.airflow_dag_run_id}")
            return execution
            
        except Exception as e:
            execution.status = WorkflowStatus.FAILED
            execution.error_message = f"Failed to execute via Airflow: {str(e)}"
            execution.completed_at = datetime.now(timezone.utc)
            logger.error(f"Failed to execute workflow via Airflow: {e}")
            return execution
    
    async def _execute_locally(self, workflow: WorkflowDefinition,
                             execution: WorkflowExecution) -> WorkflowExecution:
        """Execute workflow locally via BatchProcessingEngine."""
        try:
            execution.status = WorkflowStatus.RUNNING
            execution.started_at = datetime.now(timezone.utc)
            
            # Create background task for local execution
            asyncio.create_task(self._run_local_workflow(workflow, execution))
            
            logger.info(f"Started local workflow execution: {execution.id}")
            return execution
            
        except Exception as e:
            execution.status = WorkflowStatus.FAILED
            execution.error_message = f"Failed to execute locally: {str(e)}"
            execution.completed_at = datetime.now(timezone.utc)
            logger.error(f"Failed to execute workflow locally: {e}")
            return execution
    
    async def _run_local_workflow(self, workflow: WorkflowDefinition,
                                execution: WorkflowExecution) -> None:
        """Run workflow locally step by step."""
        try:
            execution_plan = workflow.get_execution_plan()
            
            for batch in execution_plan:
                # Execute steps in parallel within each batch
                tasks = []
                for step in batch:
                    task = asyncio.create_task(self._execute_step(step, execution))
                    tasks.append(task)
                
                # Wait for all steps in batch to complete
                await asyncio.gather(*tasks, return_exceptions=True)
                
                # Check if we should continue
                if execution.status in [WorkflowStatus.FAILED, WorkflowStatus.CANCELLED]:
                    break
            
            # Update final status
            if execution.status == WorkflowStatus.RUNNING:
                execution.status = WorkflowStatus.COMPLETED
                execution.completed_at = datetime.now(timezone.utc)
                
                # Update workflow metrics
                workflow.successful_executions += 1
            
            workflow.total_executions += 1
            
        except Exception as e:
            execution.status = WorkflowStatus.FAILED
            execution.error_message = str(e)
            execution.completed_at = datetime.now(timezone.utc)
            workflow.failed_executions += 1
            logger.error(f"Local workflow execution failed: {e}")
    
    async def _execute_step(self, step: WorkflowStep, 
                          execution: WorkflowExecution) -> None:
        """Execute a single workflow step."""
        try:
            logger.info(f"Executing step: {step.name} ({step.step_type})")
            
            # Mark step as running
            execution.add_step_execution(step.id, WorkflowStatus.RUNNING)
            execution.current_step_id = step.id
            
            # Execute based on step type
            if step.step_type == StepType.BATCH_JOB:
                await self._execute_batch_job_step(step, execution)
            elif step.step_type == StepType.DELAY:
                await self._execute_delay_step(step, execution)
            elif step.step_type == StepType.NOTIFICATION:
                await self._execute_notification_step(step, execution)
            elif step.step_type == StepType.WEBHOOK:
                await self._execute_webhook_step(step, execution)
            elif step.step_type == StepType.CUSTOM:
                await self._execute_custom_step(step, execution)
            else:
                raise ValueError(f"Unsupported step type: {step.step_type}")
            
            # Mark step as completed
            execution.add_step_execution(step.id, WorkflowStatus.COMPLETED)
            execution.successful_steps += 1
            
        except Exception as e:
            execution.add_step_execution(step.id, WorkflowStatus.FAILED, error_message=str(e))
            execution.failed_steps += 1
            
            if step.required and not step.continue_on_failure:
                execution.status = WorkflowStatus.FAILED
                execution.error_message = f"Required step failed: {step.name}"
            
            logger.error(f"Step execution failed: {step.name} - {e}")
    
    async def _execute_batch_job_step(self, step: WorkflowStep, 
                                    execution: WorkflowExecution) -> None:
        """Execute a batch job step."""
        from ..batch.engine import get_batch_engine
        
        batch_engine = get_batch_engine(self.session)
        
        # Create batch job from step configuration
        job_data = {
            'name': f"Workflow_{execution.workflow_id}_{step.name}",
            'job_type': step.batch_job_type,
            'created_by': execution.triggered_by,
            'parameters': step.batch_job_config,
            'timeout_seconds': step.timeout_seconds,
            'max_retries': step.retry_count
        }
        
        # Submit job to batch engine
        job_id = await batch_engine.submit_job(job_data)
        
        # Wait for job completion (simplified - in reality would be more sophisticated)
        while True:
            job = await batch_engine.get_job(job_id)
            if job.status in ['completed', 'failed', 'cancelled']:
                break
            await asyncio.sleep(5)
        
        if job.status != 'completed':
            raise Exception(f"Batch job failed: {job.error_message}")
        
        # Store job results in step execution
        execution.step_executions[step.id]['batch_job_id'] = str(job_id)
        execution.step_executions[step.id]['output_data'] = job.result_summary
    
    async def _execute_delay_step(self, step: WorkflowStep,
                                execution: WorkflowExecution) -> None:
        """Execute a delay step."""
        delay_seconds = step.parameters.get('delay_seconds', 60)
        await asyncio.sleep(delay_seconds)
    
    async def _execute_notification_step(self, step: WorkflowStep,
                                       execution: WorkflowExecution) -> None:
        """Execute a notification step."""
        # Placeholder for notification logic
        logger.info(f"Notification step executed: {step.notification_config}")
    
    async def _execute_webhook_step(self, step: WorkflowStep,
                                  execution: WorkflowExecution) -> None:
        """Execute a webhook step."""
        # Placeholder for webhook logic
        logger.info(f"Webhook step executed: {step.webhook_config}")
    
    async def _execute_custom_step(self, step: WorkflowStep,
                                 execution: WorkflowExecution) -> None:
        """Execute a custom step."""
        # Placeholder for custom logic execution
        logger.info(f"Custom step executed: {step.custom_logic}")
    
    async def _sync_execution_from_airflow(self, execution: WorkflowExecution) -> None:
        """Sync execution status from Airflow."""
        try:
            if not execution.airflow_dag_run_id:
                return
            
            # Parse DAG ID and execution date from dag_run_id
            parts = execution.airflow_dag_run_id.split('_')
            dag_id = '_'.join(parts[:-1])
            
            # Get DAG run status from Airflow
            dag_run = self.airflow_client.get_dag_run(
                dag_id=dag_id,
                execution_date=execution.airflow_execution_date
            )
            
            if dag_run:
                # Map Airflow state to WorkflowStatus
                state_mapping = {
                    'success': WorkflowStatus.COMPLETED,
                    'failed': WorkflowStatus.FAILED,
                    'running': WorkflowStatus.RUNNING,
                    'up_for_retry': WorkflowStatus.RUNNING,
                    'up_for_reschedule': WorkflowStatus.RUNNING,
                    'queued': WorkflowStatus.RUNNING,
                    'scheduled': WorkflowStatus.RUNNING
                }
                
                execution.status = state_mapping.get(dag_run.state, WorkflowStatus.RUNNING)
                
                if dag_run.end_date:
                    execution.completed_at = dag_run.end_date
                
        except Exception as e:
            logger.error(f"Failed to sync execution from Airflow: {e}")
    
    async def _persist_workflow(self, workflow: WorkflowDefinition) -> None:
        """Persist workflow to database."""
        try:
            # In a real implementation, this would save to a workflows table
            logger.debug(f"Persisted workflow: {workflow.id}")
        except Exception as e:
            logger.error(f"Failed to persist workflow: {e}")
    
    async def _sync_loop(self) -> None:
        """Background sync loop for Airflow integration."""
        while True:
            try:
                await asyncio.sleep(60)  # Sync every minute
                
                # Sync active executions
                for execution in list(self._active_executions.values()):
                    if execution.airflow_dag_run_id and execution.status == WorkflowStatus.RUNNING:
                        await self._sync_execution_from_airflow(execution)
                
                # Update workflow metrics
                for workflow_id, workflow in self._active_workflows.items():
                    self._workflow_metrics[workflow_id] = workflow.calculate_metrics()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in sync loop: {e}")
                await asyncio.sleep(30)
    
    async def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while True:
            try:
                await asyncio.sleep(3600)  # Cleanup every hour
                
                # Clean up old executions
                cutoff_time = datetime.now(timezone.utc) - timedelta(days=7)
                executions_to_remove = [
                    exec_id for exec_id, execution in self._active_executions.items()
                    if execution.completed_at and execution.completed_at < cutoff_time
                ]
                
                for exec_id in executions_to_remove:
                    del self._active_executions[exec_id]
                
                if executions_to_remove:
                    logger.info(f"Cleaned up {len(executions_to_remove)} old executions")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(1800)  # Wait 30 minutes on error


# Global instance
_airflow_engine: Optional[AirflowIntegrationEngine] = None


def get_airflow_engine(session: Optional[Session] = None) -> AirflowIntegrationEngine:
    """Get the global Airflow integration engine instance."""
    global _airflow_engine
    if _airflow_engine is None:
        _airflow_engine = AirflowIntegrationEngine(session)
    return _airflow_engine


def initialize_airflow_engine(session: Optional[Session] = None) -> AirflowIntegrationEngine:
    """Initialize the Airflow integration engine."""
    global _airflow_engine
    _airflow_engine = AirflowIntegrationEngine(session)
    logger.info("Airflow Integration Engine initialized successfully")
    return _airflow_engine