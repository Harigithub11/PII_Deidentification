"""
Workflow Models for Complex Job Orchestration

Defines data models for complex workflows that can be executed
by both the BatchProcessingEngine and Apache Airflow.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union, Set
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field

from pydantic import BaseModel, Field, validator

logger = logging.getLogger(__name__)


class WorkflowStatus(str, Enum):
    """Status of workflow execution."""
    DRAFT = "draft"
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class StepType(str, Enum):
    """Types of workflow steps."""
    BATCH_JOB = "batch_job"
    CONDITION = "condition"
    PARALLEL_GROUP = "parallel_group"
    SEQUENTIAL_GROUP = "sequential_group"
    DELAY = "delay"
    NOTIFICATION = "notification"
    WEBHOOK = "webhook"
    CUSTOM = "custom"


class ConditionOperator(str, Enum):
    """Operators for workflow conditions."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    REGEX_MATCH = "regex_match"


@dataclass
class WorkflowMetrics:
    """Metrics for workflow execution."""
    workflow_id: UUID
    total_steps: int = 0
    completed_steps: int = 0
    failed_steps: int = 0
    skipped_steps: int = 0
    total_execution_time_seconds: float = 0.0
    average_step_time_seconds: float = 0.0
    success_rate: float = 0.0
    retry_count: int = 0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class WorkflowCondition(BaseModel):
    """Defines a condition for workflow branching."""
    
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    
    # Condition logic
    field_path: str = Field(..., description="JSON path to the field to evaluate")
    operator: ConditionOperator
    expected_value: Any = Field(..., description="Value to compare against")
    
    # Advanced options
    case_sensitive: bool = True
    regex_flags: List[str] = Field(default_factory=list)
    custom_logic: Optional[str] = Field(None, description="Custom Python expression")
    
    # Metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: List[str] = Field(default_factory=list)

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """
        Evaluate the condition against the provided context.
        
        Args:
            context: Context data to evaluate against
            
        Returns:
            True if condition is met, False otherwise
        """
        try:
            # Extract field value using JSON path
            field_value = self._extract_field_value(context, self.field_path)
            
            # Apply operator
            if self.operator == ConditionOperator.EQUALS:
                return field_value == self.expected_value
            elif self.operator == ConditionOperator.NOT_EQUALS:
                return field_value != self.expected_value
            elif self.operator == ConditionOperator.GREATER_THAN:
                return field_value > self.expected_value
            elif self.operator == ConditionOperator.LESS_THAN:
                return field_value < self.expected_value
            elif self.operator == ConditionOperator.CONTAINS:
                return self.expected_value in str(field_value)
            elif self.operator == ConditionOperator.NOT_CONTAINS:
                return self.expected_value not in str(field_value)
            elif self.operator == ConditionOperator.EXISTS:
                return field_value is not None
            elif self.operator == ConditionOperator.NOT_EXISTS:
                return field_value is None
            elif self.operator == ConditionOperator.REGEX_MATCH:
                import re
                flags = 0
                for flag in self.regex_flags:
                    flags |= getattr(re, flag.upper(), 0)
                return bool(re.match(self.expected_value, str(field_value), flags))
            
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating condition {self.id}: {e}")
            return False
    
    def _extract_field_value(self, context: Dict[str, Any], path: str) -> Any:
        """Extract field value using dot notation path."""
        keys = path.split('.')
        value = context
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            elif hasattr(value, key):
                value = getattr(value, key)
            else:
                return None
        
        return value


class WorkflowBranch(BaseModel):
    """Defines a conditional branch in the workflow."""
    
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=100)
    condition: WorkflowCondition
    steps: List[UUID] = Field(default_factory=list, description="Step IDs to execute if condition is true")
    else_steps: List[UUID] = Field(default_factory=list, description="Step IDs to execute if condition is false")
    
    # Execution options
    continue_on_failure: bool = False
    timeout_seconds: Optional[int] = None
    
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WorkflowStep(BaseModel):
    """Defines a single step in a workflow."""
    
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    step_type: StepType
    
    # Step configuration
    parameters: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(3600, ge=60, le=86400)
    retry_count: int = Field(0, ge=0, le=10)
    retry_delay_seconds: int = Field(60, ge=30, le=3600)
    
    # Dependencies
    depends_on: List[UUID] = Field(default_factory=list, description="Step IDs this step depends on")
    condition: Optional[WorkflowCondition] = None
    
    # Execution control
    continue_on_failure: bool = False
    required: bool = True
    parallel_group: Optional[str] = None
    
    # Batch job reference (if step_type is BATCH_JOB)
    batch_job_type: Optional[str] = None
    batch_job_config: Dict[str, Any] = Field(default_factory=dict)
    
    # Custom logic (if step_type is CUSTOM)
    custom_logic: Optional[str] = None
    
    # Notification configuration (if step_type is NOTIFICATION)
    notification_config: Dict[str, Any] = Field(default_factory=dict)
    
    # Webhook configuration (if step_type is WEBHOOK)
    webhook_config: Dict[str, Any] = Field(default_factory=dict)
    
    # Runtime information
    status: WorkflowStatus = WorkflowStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    output_data: Dict[str, Any] = Field(default_factory=dict)
    
    # Metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: List[str] = Field(default_factory=list)

    @validator('step_type')
    def validate_step_type_config(cls, v, values):
        """Validate step type specific configuration."""
        if v == StepType.BATCH_JOB and not values.get('batch_job_type'):
            raise ValueError("batch_job_type is required for BATCH_JOB steps")
        if v == StepType.NOTIFICATION and not values.get('notification_config'):
            raise ValueError("notification_config is required for NOTIFICATION steps")
        if v == StepType.WEBHOOK and not values.get('webhook_config'):
            raise ValueError("webhook_config is required for WEBHOOK steps")
        return v

    def can_execute(self, completed_steps: Set[UUID]) -> bool:
        """Check if step can be executed based on dependencies."""
        if not self.depends_on:
            return True
        return all(dep_id in completed_steps for dep_id in self.depends_on)

    def get_runtime_seconds(self) -> float:
        """Get step runtime in seconds."""
        if not self.started_at:
            return 0.0
        end_time = self.completed_at or datetime.now(timezone.utc)
        return (end_time - self.started_at).total_seconds()


class WorkflowDefinition(BaseModel):
    """Defines a complete workflow with steps, conditions, and branches."""
    
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    version: str = Field("1.0.0", regex=r"^\d+\.\d+\.\d+$")
    
    # Workflow structure
    steps: List[WorkflowStep] = Field(default_factory=list)
    branches: List[WorkflowBranch] = Field(default_factory=list)
    
    # Execution configuration
    max_parallel_steps: int = Field(5, ge=1, le=20)
    default_timeout_seconds: int = Field(3600, ge=60, le=86400)
    max_retries: int = Field(3, ge=0, le=10)
    
    # Schedule configuration
    schedule_enabled: bool = False
    cron_expression: Optional[str] = None
    timezone: str = "UTC"
    
    # Airflow configuration
    airflow_dag_id: Optional[str] = None
    airflow_enabled: bool = False
    dag_config: Dict[str, Any] = Field(default_factory=dict)
    
    # Compliance and audit
    compliance_standards: List[str] = Field(default_factory=list)
    audit_enabled: bool = True
    data_retention_days: int = Field(30, ge=1, le=365)
    
    # Owner and permissions
    created_by: UUID
    shared_with: List[UUID] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    
    # Status and execution
    status: WorkflowStatus = WorkflowStatus.DRAFT
    last_execution_id: Optional[UUID] = None
    next_scheduled_run: Optional[datetime] = None
    
    # Metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Runtime metrics
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0

    @validator('steps')
    def validate_steps(cls, v):
        """Validate workflow steps."""
        if len(v) == 0:
            raise ValueError("Workflow must have at least one step")
        
        step_ids = {step.id for step in v}
        
        # Validate dependencies
        for step in v:
            for dep_id in step.depends_on:
                if dep_id not in step_ids:
                    raise ValueError(f"Step {step.id} depends on non-existent step {dep_id}")
        
        return v

    @validator('airflow_dag_id')
    def validate_dag_id(cls, v):
        """Validate Airflow DAG ID format."""
        if v and not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError("DAG ID must contain only alphanumeric characters, hyphens, and underscores")
        return v

    def get_initial_steps(self) -> List[WorkflowStep]:
        """Get steps that have no dependencies and can be executed first."""
        return [step for step in self.steps if not step.depends_on]

    def get_dependent_steps(self, step_id: UUID) -> List[WorkflowStep]:
        """Get steps that depend on the given step."""
        return [step for step in self.steps if step_id in step.depends_on]

    def get_parallel_groups(self) -> Dict[str, List[WorkflowStep]]:
        """Get steps grouped by parallel execution group."""
        groups = {}
        for step in self.steps:
            if step.parallel_group:
                if step.parallel_group not in groups:
                    groups[step.parallel_group] = []
                groups[step.parallel_group].append(step)
        return groups

    def validate_workflow_integrity(self) -> List[str]:
        """Validate workflow for logical consistency and return any issues."""
        issues = []
        
        # Check for circular dependencies
        def has_circular_dependency(step_id: UUID, visited: Set[UUID], path: Set[UUID]) -> bool:
            if step_id in path:
                return True
            if step_id in visited:
                return False
            
            visited.add(step_id)
            path.add(step_id)
            
            step = next((s for s in self.steps if s.id == step_id), None)
            if step:
                for dep_id in step.depends_on:
                    if has_circular_dependency(dep_id, visited, path):
                        return True
            
            path.remove(step_id)
            return False
        
        visited = set()
        for step in self.steps:
            if step.id not in visited:
                if has_circular_dependency(step.id, visited, set()):
                    issues.append(f"Circular dependency detected involving step {step.id}")
        
        # Check for unreachable steps
        reachable_steps = set()
        initial_steps = self.get_initial_steps()
        
        def mark_reachable(step_id: UUID):
            if step_id in reachable_steps:
                return
            reachable_steps.add(step_id)
            for dependent in self.get_dependent_steps(step_id):
                mark_reachable(dependent.id)
        
        for step in initial_steps:
            mark_reachable(step.id)
        
        for step in self.steps:
            if step.id not in reachable_steps:
                issues.append(f"Step {step.id} ({step.name}) is unreachable")
        
        # Validate schedule configuration
        if self.schedule_enabled and not self.cron_expression:
            issues.append("Schedule is enabled but no cron expression provided")
        
        return issues

    def get_execution_plan(self) -> List[List[WorkflowStep]]:
        """
        Generate execution plan as list of step batches that can be executed in parallel.
        
        Returns:
            List of step batches, where each batch contains steps that can run in parallel
        """
        execution_plan = []
        remaining_steps = self.steps.copy()
        completed_step_ids = set()
        
        while remaining_steps:
            # Find steps that can be executed now
            ready_steps = [
                step for step in remaining_steps 
                if step.can_execute(completed_step_ids)
            ]
            
            if not ready_steps:
                # This shouldn't happen with a valid workflow
                break
            
            execution_plan.append(ready_steps)
            
            # Mark these steps as completed for next iteration
            for step in ready_steps:
                completed_step_ids.add(step.id)
                remaining_steps.remove(step)
        
        return execution_plan

    def calculate_metrics(self) -> WorkflowMetrics:
        """Calculate current workflow metrics."""
        total_steps = len(self.steps)
        completed_steps = len([s for s in self.steps if s.status == WorkflowStatus.COMPLETED])
        failed_steps = len([s for s in self.steps if s.status == WorkflowStatus.FAILED])
        
        total_execution_time = sum(step.get_runtime_seconds() for step in self.steps)
        average_step_time = total_execution_time / total_steps if total_steps > 0 else 0
        
        success_rate = 0.0
        if self.total_executions > 0:
            success_rate = self.successful_executions / self.total_executions
        
        return WorkflowMetrics(
            workflow_id=self.id,
            total_steps=total_steps,
            completed_steps=completed_steps,
            failed_steps=failed_steps,
            skipped_steps=0,  # Could be calculated based on conditions
            total_execution_time_seconds=total_execution_time,
            average_step_time_seconds=average_step_time,
            success_rate=success_rate,
            retry_count=sum(step.retry_count for step in self.steps)
        )


class WorkflowExecution(BaseModel):
    """Represents a single execution instance of a workflow."""
    
    id: UUID = Field(default_factory=uuid4)
    workflow_id: UUID
    workflow_version: str
    
    # Execution metadata
    triggered_by: UUID  # User who triggered execution
    trigger_type: str = "manual"  # manual, scheduled, webhook, etc.
    execution_context: Dict[str, Any] = Field(default_factory=dict)
    
    # Status and timing
    status: WorkflowStatus = WorkflowStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Step execution tracking
    step_executions: Dict[UUID, Dict[str, Any]] = Field(default_factory=dict)
    current_step_id: Optional[UUID] = None
    
    # Results and errors
    output_data: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    error_details: Dict[str, Any] = Field(default_factory=dict)
    
    # Airflow integration
    airflow_dag_run_id: Optional[str] = None
    airflow_execution_date: Optional[datetime] = None
    
    # Metrics
    total_steps_executed: int = 0
    successful_steps: int = 0
    failed_steps: int = 0
    retry_count: int = 0
    
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def get_runtime_seconds(self) -> float:
        """Get total execution runtime in seconds."""
        if not self.started_at:
            return 0.0
        end_time = self.completed_at or datetime.now(timezone.utc)
        return (end_time - self.started_at).total_seconds()

    def add_step_execution(self, step_id: UUID, status: WorkflowStatus, 
                          output_data: Dict[str, Any] = None, 
                          error_message: str = None) -> None:
        """Add or update step execution information."""
        self.step_executions[step_id] = {
            "status": status,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "output_data": output_data or {},
            "error_message": error_message,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        if status == WorkflowStatus.COMPLETED:
            self.successful_steps += 1
        elif status == WorkflowStatus.FAILED:
            self.failed_steps += 1