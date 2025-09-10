"""
Airflow DAG Generator

Automatically generates Airflow DAGs from workflow definitions,
supporting complex workflows with conditional branching and parallel execution.
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from uuid import UUID
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, Template

from .workflow_models import (
    WorkflowDefinition, WorkflowStep, WorkflowBranch,
    StepType, ConditionOperator
)

logger = logging.getLogger(__name__)


class DAGGenerator:
    """Generates Airflow DAG files from workflow definitions."""
    
    def __init__(self, templates_dir: Optional[str] = None):
        # Set up Jinja2 environment
        if templates_dir is None:
            templates_dir = Path(__file__).parent / "dag_templates"
        
        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Ensure base templates exist
        self._create_base_templates()
    
    async def generate_workflow_dag(self, workflow: WorkflowDefinition, 
                                  output_dir: str) -> str:
        """
        Generate Airflow DAG file for a workflow.
        
        Args:
            workflow: Workflow definition
            output_dir: Directory to write DAG file
            
        Returns:
            Path to generated DAG file
        """
        try:
            # Create DAG builder
            builder = WorkflowDAGBuilder(workflow)
            
            # Build DAG structure
            dag_config = builder.build_dag_config()
            task_configs = builder.build_task_configs()
            dependencies = builder.build_dependencies()
            
            # Generate DAG code
            dag_code = self._generate_dag_code(
                workflow, dag_config, task_configs, dependencies
            )
            
            # Write to file
            output_path = Path(output_dir) / f"workflow_{workflow.airflow_dag_id}.py"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                f.write(dag_code)
            
            logger.info(f"Generated DAG file: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Failed to generate DAG for workflow {workflow.id}: {e}")
            raise
    
    def _generate_dag_code(self, workflow: WorkflowDefinition,
                          dag_config: Dict[str, Any],
                          task_configs: List[Dict[str, Any]],
                          dependencies: List[Dict[str, Any]]) -> str:
        """Generate the actual DAG Python code."""
        try:
            template = self.jinja_env.get_template('workflow_dag.py.j2')
            
            return template.render(
                workflow=workflow,
                dag_config=dag_config,
                task_configs=task_configs,
                dependencies=dependencies,
                generated_at=datetime.now().isoformat(),
                generator_version="1.0.0"
            )
            
        except Exception as e:
            logger.error(f"Failed to generate DAG code: {e}")
            raise
    
    def _create_base_templates(self) -> None:
        """Create base Jinja2 templates for DAG generation."""
        
        # Main workflow DAG template
        workflow_template = '''"""
Airflow DAG: {{ workflow.name }}
Generated automatically from workflow definition

Workflow ID: {{ workflow.id }}
Generated at: {{ generated_at }}
Generator version: {{ generator_version }}
"""

from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python_operator import PythonOperator
from airflow.operators.bash_operator import BashOperator
from airflow.operators.dummy_operator import DummyOperator
from airflow.operators.branch_python_operator import BranchPythonOperator
from airflow.utils.task_group import TaskGroup
from airflow.utils.trigger_rule import TriggerRule

# Default arguments for all tasks
default_args = {
    'owner': '{{ workflow.created_by }}',
    'depends_on_past': False,
    'start_date': datetime({{ dag_config.start_date.year }}, {{ dag_config.start_date.month }}, {{ dag_config.start_date.day }}),
    'email_on_failure': {{ dag_config.email_on_failure|lower }},
    'email_on_retry': {{ dag_config.email_on_retry|lower }},
    'retries': {{ dag_config.default_retries }},
    'retry_delay': timedelta(minutes={{ dag_config.retry_delay_minutes }}),
    'execution_timeout': timedelta(seconds={{ workflow.default_timeout_seconds }}),
}

# DAG definition
dag = DAG(
    '{{ workflow.airflow_dag_id }}',
    default_args=default_args,
    description='{{ workflow.description or workflow.name }}',
    schedule_interval='{{ workflow.cron_expression or "@once" }}',
    max_active_runs={{ workflow.max_parallel_steps }},
    catchup=False,
    tags=['workflow', 'batch-processing'{% for tag in workflow.tags %}, '{{ tag }}'{% endfor %}],
    params={
        'workflow_id': '{{ workflow.id }}',
        'workflow_version': '{{ workflow.version }}',
    }
)

# Task functions
def execute_batch_job_task(**context):
    """Execute a batch job task."""
    import sys
    import os
    
    # Add the application to Python path
    sys.path.append('/app')
    
    from src.core.batch.engine import get_batch_engine
    from src.core.database.session import get_db_session
    
    task_id = context['task'].task_id
    dag_run = context['dag_run']
    
    # Extract task configuration from DAG params
    task_config = dag_run.conf.get('tasks', {}).get(task_id, {})
    
    # Get batch engine
    with get_db_session() as session:
        batch_engine = get_batch_engine(session)
        
        # Submit batch job
        job_data = {
            'name': f"Airflow_{dag_run.dag_id}_{task_id}",
            'job_type': task_config.get('job_type'),
            'created_by': dag_run.conf.get('triggered_by'),
            'parameters': task_config.get('parameters', {}),
            'timeout_seconds': task_config.get('timeout_seconds', 3600),
            'max_retries': task_config.get('max_retries', 3)
        }
        
        job_id = batch_engine.submit_job(job_data)
        
        # Wait for job completion
        import asyncio
        import time
        
        while True:
            job = batch_engine.get_job(job_id)
            if job.status in ['completed', 'failed', 'cancelled']:
                break
            time.sleep(10)
        
        if job.status != 'completed':
            raise Exception(f"Batch job failed: {job.error_message}")
        
        return {
            'job_id': str(job_id),
            'result_summary': job.result_summary,
            'runtime_seconds': job.get_runtime_seconds()
        }

def evaluate_condition(**context):
    """Evaluate a workflow condition for branching."""
    import sys
    sys.path.append('/app')
    
    from src.core.orchestration.workflow_models import WorkflowCondition
    
    task_id = context['task'].task_id
    dag_run = context['dag_run']
    
    # Get condition configuration
    condition_config = dag_run.conf.get('conditions', {}).get(task_id, {})
    condition = WorkflowCondition(**condition_config)
    
    # Evaluate condition with current context
    result = condition.evaluate(context)
    
    # Return next task based on condition result
    if result:
        return condition_config.get('true_task')
    else:
        return condition_config.get('false_task')

def send_notification(**context):
    """Send workflow notification."""
    # Placeholder for notification logic
    print(f"Notification sent for task: {context['task'].task_id}")

def call_webhook(**context):
    """Call external webhook."""
    import requests
    
    task_id = context['task'].task_id
    dag_run = context['dag_run']
    
    webhook_config = dag_run.conf.get('webhooks', {}).get(task_id, {})
    
    if webhook_config.get('url'):
        response = requests.post(
            webhook_config['url'],
            json={
                'dag_id': dag_run.dag_id,
                'task_id': task_id,
                'execution_date': dag_run.execution_date.isoformat(),
                'context': context.get('params', {})
            },
            timeout=webhook_config.get('timeout', 30)
        )
        response.raise_for_status()
        return response.json()

# Tasks
{% for task_config in task_configs %}
{% if task_config.task_type == 'batch_job' %}
{{ task_config.task_id }} = PythonOperator(
    task_id='{{ task_config.task_id }}',
    python_callable=execute_batch_job_task,
    dag=dag,
    retries={{ task_config.retries }},
    execution_timeout=timedelta(seconds={{ task_config.timeout_seconds }})
)
{% elif task_config.task_type == 'condition' %}
{{ task_config.task_id }} = BranchPythonOperator(
    task_id='{{ task_config.task_id }}',
    python_callable=evaluate_condition,
    dag=dag
)
{% elif task_config.task_type == 'notification' %}
{{ task_config.task_id }} = PythonOperator(
    task_id='{{ task_config.task_id }}',
    python_callable=send_notification,
    dag=dag
)
{% elif task_config.task_type == 'webhook' %}
{{ task_config.task_id }} = PythonOperator(
    task_id='{{ task_config.task_id }}',
    python_callable=call_webhook,
    dag=dag
)
{% elif task_config.task_type == 'delay' %}
{{ task_config.task_id }} = BashOperator(
    task_id='{{ task_config.task_id }}',
    bash_command='sleep {{ task_config.delay_seconds }}',
    dag=dag
)
{% else %}
{{ task_config.task_id }} = DummyOperator(
    task_id='{{ task_config.task_id }}',
    dag=dag
)
{% endif %}

{% endfor %}

# Dependencies
{% for dep in dependencies %}
{% if dep.type == 'simple' %}
{{ dep.upstream }} >> {{ dep.downstream }}
{% elif dep.type == 'branch' %}
{{ dep.condition_task }} >> [{{ dep.true_tasks|join(', ') }}]
{{ dep.condition_task }} >> [{{ dep.false_tasks|join(', ') }}]
{% elif dep.type == 'parallel' %}
[{{ dep.upstream_tasks|join(', ') }}] >> {{ dep.downstream }}
{% endif %}
{% endfor %}
'''
        
        template_path = self.templates_dir / 'workflow_dag.py.j2'
        if not template_path.exists():
            with open(template_path, 'w') as f:
                f.write(workflow_template)


class WorkflowDAGBuilder:
    """Builds DAG configuration from workflow definitions."""
    
    def __init__(self, workflow: WorkflowDefinition):
        self.workflow = workflow
        self._task_id_map: Dict[UUID, str] = {}
        self._build_task_id_map()
    
    def _build_task_id_map(self) -> None:
        """Build mapping from step UUIDs to Airflow task IDs."""
        for i, step in enumerate(self.workflow.steps):
            # Create valid Airflow task ID
            task_id = f"step_{i}_{step.name.lower().replace(' ', '_').replace('-', '_')}"
            # Ensure task ID is unique and valid
            task_id = ''.join(c for c in task_id if c.isalnum() or c == '_')
            if not task_id[0].isalpha():
                task_id = f"task_{task_id}"
            
            self._task_id_map[step.id] = task_id
    
    def build_dag_config(self) -> Dict[str, Any]:
        """Build DAG-level configuration."""
        return {
            'start_date': datetime.now().replace(hour=0, minute=0, second=0, microsecond=0),
            'email_on_failure': True,
            'email_on_retry': False,
            'default_retries': self.workflow.max_retries,
            'retry_delay_minutes': 5,
            'max_active_runs': self.workflow.max_parallel_steps,
            'schedule_interval': self.workflow.cron_expression or '@once',
            'catchup': False
        }
    
    def build_task_configs(self) -> List[Dict[str, Any]]:
        """Build configuration for all tasks."""
        task_configs = []
        
        for step in self.workflow.steps:
            task_config = {
                'task_id': self._task_id_map[step.id],
                'step_id': str(step.id),
                'task_type': self._map_step_type_to_task_type(step.step_type),
                'retries': step.retry_count,
                'timeout_seconds': step.timeout_seconds,
                'continue_on_failure': step.continue_on_failure
            }
            
            # Add step-specific configuration
            if step.step_type == StepType.BATCH_JOB:
                task_config.update({
                    'job_type': step.batch_job_type,
                    'parameters': step.batch_job_config
                })
            elif step.step_type == StepType.DELAY:
                task_config['delay_seconds'] = step.parameters.get('delay_seconds', 60)
            elif step.step_type == StepType.CONDITION:
                task_config['condition'] = step.condition.dict() if step.condition else {}
            elif step.step_type == StepType.NOTIFICATION:
                task_config['notification_config'] = step.notification_config
            elif step.step_type == StepType.WEBHOOK:
                task_config['webhook_config'] = step.webhook_config
            
            task_configs.append(task_config)
        
        return task_configs
    
    def build_dependencies(self) -> List[Dict[str, Any]]:
        """Build task dependencies."""
        dependencies = []
        
        # Simple dependencies
        for step in self.workflow.steps:
            downstream_task = self._task_id_map[step.id]
            
            for dep_id in step.depends_on:
                upstream_task = self._task_id_map[dep_id]
                dependencies.append({
                    'type': 'simple',
                    'upstream': upstream_task,
                    'downstream': downstream_task
                })
        
        # Parallel group dependencies
        parallel_groups = self.workflow.get_parallel_groups()
        for group_name, steps in parallel_groups.items():
            if len(steps) > 1:
                # All steps in group should run in parallel
                step_tasks = [self._task_id_map[step.id] for step in steps]
                
                # Find upstream dependencies for the group
                group_deps = set()
                for step in steps:
                    group_deps.update(step.depends_on)
                
                if group_deps:
                    upstream_tasks = [self._task_id_map[dep_id] for dep_id in group_deps]
                    dependencies.append({
                        'type': 'parallel',
                        'upstream_tasks': upstream_tasks,
                        'downstream': step_tasks[0]  # Start of parallel group
                    })
        
        # Branch dependencies
        for branch in self.workflow.branches:
            condition_task = f"condition_{branch.id.hex[:8]}"
            true_tasks = [self._task_id_map[step_id] for step_id in branch.steps]
            false_tasks = [self._task_id_map[step_id] for step_id in branch.else_steps]
            
            dependencies.append({
                'type': 'branch',
                'condition_task': condition_task,
                'true_tasks': true_tasks,
                'false_tasks': false_tasks
            })
        
        return dependencies
    
    def _map_step_type_to_task_type(self, step_type: StepType) -> str:
        """Map workflow step type to Airflow task type."""
        mapping = {
            StepType.BATCH_JOB: 'batch_job',
            StepType.CONDITION: 'condition',
            StepType.DELAY: 'delay',
            StepType.NOTIFICATION: 'notification',
            StepType.WEBHOOK: 'webhook',
            StepType.CUSTOM: 'custom',
            StepType.PARALLEL_GROUP: 'parallel_group',
            StepType.SEQUENTIAL_GROUP: 'sequential_group'
        }
        return mapping.get(step_type, 'dummy')


class DAGTemplateManager:
    """Manages DAG templates for different job types."""
    
    def __init__(self, templates_dir: str):
        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
    
    def create_job_type_template(self, job_type: str, template_content: str) -> None:
        """Create a template for a specific job type."""
        template_path = self.templates_dir / f"{job_type}_task.py.j2"
        with open(template_path, 'w') as f:
            f.write(template_content)
    
    def get_available_templates(self) -> List[str]:
        """Get list of available templates."""
        return [t.stem for t in self.templates_dir.glob("*.j2")]
    
    def create_default_templates(self) -> None:
        """Create default templates for common job types."""
        
        # Document processing template
        doc_template = '''
def execute_document_processing(**context):
    """Execute document processing batch job."""
    from src.core.batch.document_processor import DocumentBatchProcessor
    
    processor = DocumentBatchProcessor()
    task_config = context['dag_run'].conf.get('tasks', {}).get(context['task'].task_id, {})
    
    documents = task_config.get('documents', [])
    policy_id = task_config.get('policy_id')
    
    results = processor.process_documents(documents, policy_id)
    return results
'''
        
        # PII detection template  
        pii_template = '''
def execute_pii_detection(**context):
    """Execute PII detection batch job."""
    from src.core.processing.pii_batch_analyzer import PIIBatchAnalyzer
    
    analyzer = PIIBatchAnalyzer()
    task_config = context['dag_run'].conf.get('tasks', {}).get(context['task'].task_id, {})
    
    documents = task_config.get('documents', [])
    confidence_threshold = task_config.get('confidence_threshold', 0.8)
    
    results = analyzer.analyze_documents(documents, confidence_threshold)
    return results
'''
        
        self.create_job_type_template('document_processing', doc_template)
        self.create_job_type_template('pii_detection', pii_template)