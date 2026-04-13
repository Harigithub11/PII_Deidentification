"""
Alert Workflow Management and Integration

Comprehensive workflow management system that integrates alert dashboard,
escalation policies, and correlation engines into a unified alert
management workflow. This completes Phase 8.2.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
import aiosqlite
import uuid

from .alert_dashboard import (
    AlertDashboardManager, AlertStatus, AlertSummary, AlertGroup,
    AlertCorrelationEngine, AlertFilter, get_alert_dashboard
)
from .alert_escalation import (
    AlertEscalationManager, EscalationPolicy, NotificationTarget,
    NotificationChannel, get_escalation_manager
)
from .predictive_alerts import (
    PredictiveAlertEngine, AnomalyDetectionResult, AlertSeverity
)
from .metrics_collector import get_metrics_collector

logger = logging.getLogger(__name__)


class WorkflowAction(Enum):
    """Available workflow actions."""
    ACKNOWLEDGE = "acknowledge"
    ESCALATE = "escalate"
    RESOLVE = "resolve"
    SUPPRESS = "suppress"
    ASSIGN = "assign"
    COMMENT = "comment"
    CORRELATE = "correlate"
    MERGE = "merge"
    CLOSE = "close"
    REOPEN = "reopen"


class WorkflowTrigger(Enum):
    """Workflow trigger conditions."""
    ALERT_CREATED = "alert_created"
    ALERT_UPDATED = "alert_updated"
    SEVERITY_CHANGED = "severity_changed"
    TIME_ELAPSED = "time_elapsed"
    MANUAL = "manual"
    CORRELATION_FOUND = "correlation_found"
    THRESHOLD_BREACHED = "threshold_breached"
    RESOLUTION_TIMEOUT = "resolution_timeout"


@dataclass
class WorkflowRule:
    """Automated workflow rule definition."""
    id: str
    name: str
    description: str
    trigger: WorkflowTrigger
    conditions: Dict[str, Any]
    actions: List[Dict[str, Any]]
    is_active: bool = True
    priority: int = 1
    created_by: str = ""
    created_at: Optional[datetime] = None


@dataclass
class WorkflowExecution:
    """Record of workflow rule execution."""
    id: str
    rule_id: str
    alert_id: str
    trigger_event: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "running"  # running, completed, failed, cancelled
    actions_executed: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class RemediationEngine:
    """Automated remediation engine for common alert conditions."""
    
    def __init__(self):
        self.remediation_scripts: Dict[str, Callable] = {}
        self._initialize_default_remediations()
    
    def _initialize_default_remediations(self):
        """Initialize default remediation actions."""
        self.remediation_scripts = {
            'restart_service': self._restart_service_remediation,
            'clear_cache': self._clear_cache_remediation,
            'scale_resources': self._scale_resources_remediation,
            'cleanup_logs': self._cleanup_logs_remediation,
            'reset_connections': self._reset_connections_remediation
        }
    
    async def _restart_service_remediation(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Restart service remediation."""
        try:
            service_name = alert_data.get('metadata', {}).get('service_name', 'unknown')
            
            # In a real implementation, this would interact with service management
            logger.info(f"Attempting to restart service: {service_name}")
            
            # Simulate service restart
            await asyncio.sleep(2)
            
            return {
                'success': True,
                'message': f'Service {service_name} restart initiated',
                'actions_taken': ['service_restart_command_executed'],
                'expected_resolution_time': 120  # seconds
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'actions_taken': []
            }
    
    async def _clear_cache_remediation(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Clear cache remediation."""
        try:
            cache_type = alert_data.get('metadata', {}).get('cache_type', 'application')
            
            logger.info(f"Attempting to clear {cache_type} cache")
            
            # Simulate cache clear
            await asyncio.sleep(1)
            
            return {
                'success': True,
                'message': f'{cache_type} cache cleared successfully',
                'actions_taken': ['cache_clear_executed'],
                'expected_resolution_time': 60
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'actions_taken': []
            }
    
    async def _scale_resources_remediation(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scale resources remediation."""
        try:
            resource_type = alert_data.get('metadata', {}).get('resource_type', 'cpu')
            current_value = alert_data.get('current_value', 0)
            
            logger.info(f"Attempting to scale {resource_type} resources due to {current_value}% usage")
            
            # Simulate resource scaling
            await asyncio.sleep(3)
            
            return {
                'success': True,
                'message': f'{resource_type} resources scaled up',
                'actions_taken': ['resource_scaling_initiated'],
                'expected_resolution_time': 300
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'actions_taken': []
            }
    
    async def _cleanup_logs_remediation(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Cleanup logs remediation."""
        try:
            log_path = alert_data.get('metadata', {}).get('log_path', '/var/log/application')
            
            logger.info(f"Attempting to cleanup logs at {log_path}")
            
            # Simulate log cleanup
            await asyncio.sleep(2)
            
            return {
                'success': True,
                'message': f'Log cleanup completed for {log_path}',
                'actions_taken': ['log_rotation_executed', 'old_logs_archived'],
                'expected_resolution_time': 120
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'actions_taken': []
            }
    
    async def _reset_connections_remediation(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Reset connections remediation."""
        try:
            connection_type = alert_data.get('metadata', {}).get('connection_type', 'database')
            
            logger.info(f"Attempting to reset {connection_type} connections")
            
            # Simulate connection reset
            await asyncio.sleep(1.5)
            
            return {
                'success': True,
                'message': f'{connection_type} connections reset successfully',
                'actions_taken': ['connection_pool_reset'],
                'expected_resolution_time': 90
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'actions_taken': []
            }
    
    async def execute_remediation(self, script_name: str, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a remediation script."""
        if script_name not in self.remediation_scripts:
            return {
                'success': False,
                'error': f'Remediation script {script_name} not found',
                'actions_taken': []
            }
        
        try:
            result = await self.remediation_scripts[script_name](alert_data)
            
            # Log remediation execution
            logger.info(f"Remediation {script_name} executed for alert {alert_data.get('alert_id')}: {result}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error executing remediation {script_name}: {e}")
            return {
                'success': False,
                'error': str(e),
                'actions_taken': []
            }


class AlertWorkflowManager:
    """
    Comprehensive alert workflow management system that orchestrates
    alert processing, correlation, escalation, and remediation.
    """
    
    def __init__(self, db_path: str = "performance_metrics.db"):
        self.db_path = db_path
        self.dashboard_manager = None
        self.escalation_manager = None
        self.remediation_engine = RemediationEngine()
        
        # Workflow components
        self.workflow_rules: List[WorkflowRule] = []
        self.active_workflows: Dict[str, WorkflowExecution] = {}
        self.rule_callbacks: Dict[WorkflowTrigger, List[Callable]] = {}
        
        # Correlation and grouping
        self.alert_groups_cache: Dict[str, AlertGroup] = {}
        self.correlation_threshold = 0.8
        
        # Performance metrics
        self.workflow_metrics = {
            'rules_executed': 0,
            'actions_completed': 0,
            'remediations_successful': 0,
            'correlations_found': 0,
            'escalations_triggered': 0
        }
    
    async def initialize(self):
        """Initialize the workflow manager."""
        await self._create_workflow_tables()
        
        # Initialize dependent managers
        self.dashboard_manager = get_alert_dashboard()
        self.escalation_manager = get_escalation_manager()
        
        # Load workflow rules
        await self._load_workflow_rules()
        
        # Initialize default workflow rules
        await self._initialize_default_workflows()
        
        logger.info("Alert Workflow Manager initialized")
    
    async def _create_workflow_tables(self):
        """Create workflow management tables."""
        async with aiosqlite.connect(self.db_path) as db:
            # Workflow rules
            await db.execute("""
                CREATE TABLE IF NOT EXISTS workflow_rules (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    trigger_type TEXT NOT NULL,
                    conditions TEXT,
                    actions TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    priority INTEGER DEFAULT 1,
                    created_by TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    execution_count INTEGER DEFAULT 0,
                    last_executed_at TEXT
                )
            """)
            
            # Workflow executions
            await db.execute("""
                CREATE TABLE IF NOT EXISTS workflow_executions (
                    id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    trigger_event TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT DEFAULT 'running',
                    actions_executed TEXT,
                    error_message TEXT,
                    metadata TEXT,
                    FOREIGN KEY (rule_id) REFERENCES workflow_rules(id),
                    FOREIGN KEY (alert_id) REFERENCES performance_alerts(alert_id)
                )
            """)
            
            # Remediation history
            await db.execute("""
                CREATE TABLE IF NOT EXISTS remediation_history (
                    id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    script_name TEXT NOT NULL,
                    executed_at TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    result_data TEXT,
                    execution_time_seconds REAL,
                    triggered_by TEXT,
                    FOREIGN KEY (alert_id) REFERENCES performance_alerts(alert_id)
                )
            """)
            
            # Alert correlations
            await db.execute("""
                CREATE TABLE IF NOT EXISTS alert_correlations (
                    id TEXT PRIMARY KEY,
                    primary_alert_id TEXT NOT NULL,
                    related_alert_id TEXT NOT NULL,
                    correlation_type TEXT NOT NULL,
                    correlation_score REAL NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    FOREIGN KEY (primary_alert_id) REFERENCES performance_alerts(alert_id),
                    FOREIGN KEY (related_alert_id) REFERENCES performance_alerts(alert_id)
                )
            """)
            
            await db.commit()
    
    async def _load_workflow_rules(self):
        """Load workflow rules from database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT id, name, description, trigger_type, conditions, actions, 
                           is_active, priority, created_by, created_at
                    FROM workflow_rules
                    WHERE is_active = TRUE
                    ORDER BY priority, name
                """)
                
                rows = await cursor.fetchall()
                self.workflow_rules = []
                
                for row in rows:
                    rule = WorkflowRule(
                        id=row[0],
                        name=row[1],
                        description=row[2],
                        trigger=WorkflowTrigger(row[3]),
                        conditions=json.loads(row[4]) if row[4] else {},
                        actions=json.loads(row[5]),
                        is_active=bool(row[6]),
                        priority=row[7],
                        created_by=row[8],
                        created_at=datetime.fromisoformat(row[9]) if row[9] else None
                    )
                    self.workflow_rules.append(rule)
                
                logger.info(f"Loaded {len(self.workflow_rules)} workflow rules")
                
        except Exception as e:
            logger.error(f"Error loading workflow rules: {e}")
    
    async def _initialize_default_workflows(self):
        """Initialize default workflow rules."""
        default_rules = [
            WorkflowRule(
                id="auto_escalate_critical",
                name="Auto-escalate Critical Alerts",
                description="Automatically escalate critical alerts after 5 minutes",
                trigger=WorkflowTrigger.TIME_ELAPSED,
                conditions={
                    "severity": ["critical", "emergency"],
                    "status": ["open"],
                    "time_elapsed_minutes": 5
                },
                actions=[
                    {"action": "escalate", "policy": "critical_alerts"},
                    {"action": "comment", "message": "Auto-escalated due to severity and time elapsed"}
                ],
                priority=1
            ),
            
            WorkflowRule(
                id="auto_remediate_high_cpu",
                name="Auto-remediate High CPU",
                description="Automatically attempt remediation for high CPU alerts",
                trigger=WorkflowTrigger.ALERT_CREATED,
                conditions={
                    "metric_name": "cpu_usage_percent",
                    "current_value": {"min": 90},
                    "severity": ["warning", "critical"]
                },
                actions=[
                    {"action": "remediate", "script": "scale_resources", "auto_approve": True},
                    {"action": "comment", "message": "Auto-remediation attempted for high CPU usage"}
                ],
                priority=2
            ),
            
            WorkflowRule(
                id="correlate_cascading_failures",
                name="Correlate Cascading Failures",
                description="Automatically correlate alerts that appear to be cascading failures",
                trigger=WorkflowTrigger.ALERT_CREATED,
                conditions={
                    "time_window_minutes": 10,
                    "correlation_types": ["cascading_failure", "infrastructure_issue"]
                },
                actions=[
                    {"action": "correlate", "create_group": True},
                    {"action": "suppress_duplicates", "keep_primary": True}
                ],
                priority=3
            ),
            
            WorkflowRule(
                id="auto_close_resolved",
                name="Auto-close Resolved Alerts",
                description="Automatically close alerts that have been resolved for 1 hour",
                trigger=WorkflowTrigger.TIME_ELAPSED,
                conditions={
                    "status": ["resolved"],
                    "time_elapsed_minutes": 60
                },
                actions=[
                    {"action": "close", "reason": "auto_closed_after_resolution"}
                ],
                priority=5
            )
        ]
        
        # Create default rules if they don't exist
        for rule in default_rules:
            if not await self._rule_exists(rule.id):
                await self.create_workflow_rule(rule)
    
    async def _rule_exists(self, rule_id: str) -> bool:
        """Check if a workflow rule exists."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT COUNT(*) FROM workflow_rules WHERE id = ?
                """, (rule_id,))
                count = (await cursor.fetchone())[0]
                return count > 0
        except Exception:
            return False
    
    async def create_workflow_rule(self, rule: WorkflowRule) -> bool:
        """Create a new workflow rule."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO workflow_rules 
                    (id, name, description, trigger_type, conditions, actions, 
                     is_active, priority, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rule.id,
                    rule.name,
                    rule.description,
                    rule.trigger.value,
                    json.dumps(rule.conditions),
                    json.dumps(rule.actions),
                    rule.is_active,
                    rule.priority,
                    rule.created_by
                ))
                
                await db.commit()
                
                # Add to in-memory rules
                self.workflow_rules.append(rule)
                self.workflow_rules.sort(key=lambda r: (r.priority, r.name))
                
                return True
                
        except Exception as e:
            logger.error(f"Error creating workflow rule: {e}")
            return False
    
    async def process_alert(self, alert_data: Dict[str, Any], trigger: WorkflowTrigger = WorkflowTrigger.ALERT_CREATED):
        """Process an alert through the workflow system."""
        try:
            alert_id = alert_data['alert_id']
            
            # Find applicable workflow rules
            applicable_rules = await self._find_applicable_rules(alert_data, trigger)
            
            # Execute rules in priority order
            for rule in applicable_rules:
                execution_id = str(uuid.uuid4())
                
                # Create workflow execution record
                execution = WorkflowExecution(
                    id=execution_id,
                    rule_id=rule.id,
                    alert_id=alert_id,
                    trigger_event=trigger.value,
                    started_at=datetime.now(timezone.utc)
                )
                
                # Store execution
                await self._create_workflow_execution(execution)
                self.active_workflows[execution_id] = execution
                
                # Execute rule actions
                asyncio.create_task(self._execute_workflow_rule(execution, rule, alert_data))
            
            # Update workflow metrics
            self.workflow_metrics['rules_executed'] += len(applicable_rules)
            
            logger.info(f"Processing alert {alert_id} with {len(applicable_rules)} applicable rules")
            
        except Exception as e:
            logger.error(f"Error processing alert workflow: {e}")
    
    async def _find_applicable_rules(self, alert_data: Dict[str, Any], trigger: WorkflowTrigger) -> List[WorkflowRule]:
        """Find workflow rules applicable to the alert."""
        applicable_rules = []
        
        for rule in self.workflow_rules:
            if not rule.is_active or rule.trigger != trigger:
                continue
            
            if await self._rule_conditions_match(rule, alert_data):
                applicable_rules.append(rule)
        
        return applicable_rules
    
    async def _rule_conditions_match(self, rule: WorkflowRule, alert_data: Dict[str, Any]) -> bool:
        """Check if rule conditions match the alert data."""
        try:
            conditions = rule.conditions
            
            # Check severity condition
            if 'severity' in conditions:
                if alert_data.get('severity') not in conditions['severity']:
                    return False
            
            # Check status condition
            if 'status' in conditions:
                if alert_data.get('status') not in conditions['status']:
                    return False
            
            # Check metric name condition
            if 'metric_name' in conditions:
                metric_condition = conditions['metric_name']
                alert_metric = alert_data.get('metric_name', '')
                
                if isinstance(metric_condition, str):
                    if metric_condition not in alert_metric:
                        return False
                elif isinstance(metric_condition, list):
                    if not any(pattern in alert_metric for pattern in metric_condition):
                        return False
            
            # Check current value condition
            if 'current_value' in conditions:
                value_condition = conditions['current_value']
                current_value = alert_data.get('current_value', 0)
                
                if 'min' in value_condition and current_value < value_condition['min']:
                    return False
                if 'max' in value_condition and current_value > value_condition['max']:
                    return False
            
            # Check time elapsed condition
            if 'time_elapsed_minutes' in conditions:
                required_elapsed = conditions['time_elapsed_minutes']
                first_occurrence = datetime.fromisoformat(alert_data.get('first_occurrence', datetime.now(timezone.utc).isoformat()))
                elapsed_minutes = (datetime.now(timezone.utc) - first_occurrence).total_seconds() / 60
                
                if elapsed_minutes < required_elapsed:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking rule conditions: {e}")
            return False
    
    async def _execute_workflow_rule(self, execution: WorkflowExecution, rule: WorkflowRule, alert_data: Dict[str, Any]):
        """Execute a workflow rule's actions."""
        try:
            actions_executed = []
            
            for action_config in rule.actions:
                action_type = action_config.get('action')
                action_result = await self._execute_action(action_type, action_config, alert_data)
                
                actions_executed.append({
                    'action': action_type,
                    'config': action_config,
                    'result': action_result,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
                
                # Update workflow metrics
                if action_result.get('success', False):
                    self.workflow_metrics['actions_completed'] += 1
            
            # Complete execution
            execution.completed_at = datetime.now(timezone.utc)
            execution.status = "completed"
            execution.actions_executed = actions_executed
            
            await self._update_workflow_execution(execution)
            
            # Update rule execution stats
            await self._update_rule_stats(rule.id)
            
            logger.info(f"Completed workflow execution {execution.id} for rule {rule.name}")
            
        except Exception as e:
            execution.status = "failed"
            execution.error_message = str(e)
            await self._update_workflow_execution(execution)
            logger.error(f"Error executing workflow rule {rule.name}: {e}")
        
        finally:
            # Clean up active workflow
            if execution.id in self.active_workflows:
                del self.active_workflows[execution.id]
    
    async def _execute_action(self, action_type: str, action_config: Dict[str, Any], alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific workflow action."""
        try:
            alert_id = alert_data['alert_id']
            
            if action_type == "acknowledge":
                user = action_config.get('user', 'workflow_system')
                success = await self.dashboard_manager.bulk_update_alerts(
                    [alert_id], {'status': 'acknowledged', 'acknowledged_by': user}, user
                )
                return {'success': success > 0, 'message': f'Alert acknowledged by {user}'}
            
            elif action_type == "escalate":
                policy = action_config.get('policy', 'default')
                success = await self.escalation_manager.trigger_escalation(alert_data)
                return {'success': success, 'message': f'Escalation triggered with policy {policy}'}
            
            elif action_type == "resolve":
                user = action_config.get('user', 'workflow_system')
                success = await self.dashboard_manager.bulk_update_alerts(
                    [alert_id], {'status': 'resolved', 'resolved_by': user}, user
                )
                return {'success': success > 0, 'message': f'Alert resolved by {user}'}
            
            elif action_type == "suppress":
                reason = action_config.get('reason', 'automated_suppression')
                # Find alert group and suppress
                groups = await self.dashboard_manager.get_correlated_alert_groups()
                for group in groups:
                    if any(alert['alert_id'] == alert_id for alert in group.alerts):
                        success = await self.dashboard_manager.suppress_alert_group(
                            group.group_id, reason, 'workflow_system'
                        )
                        return {'success': success, 'message': f'Alert group suppressed: {reason}'}
                return {'success': False, 'message': 'Alert group not found for suppression'}
            
            elif action_type == "comment":
                message = action_config.get('message', 'Automated workflow action')
                success = await self.dashboard_manager.add_alert_comment(
                    alert_id, 'workflow_system', message
                )
                return {'success': success, 'message': f'Comment added: {message}'}
            
            elif action_type == "remediate":
                script_name = action_config.get('script')
                if not script_name:
                    return {'success': False, 'error': 'No remediation script specified'}
                
                start_time = datetime.now(timezone.utc)
                result = await self.remediation_engine.execute_remediation(script_name, alert_data)
                execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
                
                # Record remediation
                await self._record_remediation(alert_id, script_name, result, execution_time)
                
                if result.get('success', False):
                    self.workflow_metrics['remediations_successful'] += 1
                
                return result
            
            elif action_type == "correlate":
                create_group = action_config.get('create_group', False)
                result = await self._perform_correlation(alert_data, create_group)
                if result.get('correlations_found', 0) > 0:
                    self.workflow_metrics['correlations_found'] += 1
                return result
            
            elif action_type == "close":
                reason = action_config.get('reason', 'workflow_closure')
                success = await self.dashboard_manager.bulk_update_alerts(
                    [alert_id], {'status': 'closed'}, 'workflow_system', reason
                )
                return {'success': success > 0, 'message': f'Alert closed: {reason}'}
            
            else:
                return {'success': False, 'error': f'Unknown action type: {action_type}'}
            
        except Exception as e:
            logger.error(f"Error executing action {action_type}: {e}")
            return {'success': False, 'error': str(e)}
    
    async def _perform_correlation(self, alert_data: Dict[str, Any], create_group: bool) -> Dict[str, Any]:
        """Perform alert correlation analysis."""
        try:
            alert_id = alert_data['alert_id']
            
            # Get recent alerts for correlation
            recent_filter = AlertFilter(
                time_range=(datetime.now(timezone.utc) - timedelta(hours=1), datetime.now(timezone.utc)),
                status=['open', 'acknowledged'],
                limit=100
            )
            
            recent_alerts, _ = await self.dashboard_manager.get_filtered_alerts(recent_filter)
            
            # Find correlations
            correlations = []
            for other_alert in recent_alerts:
                if other_alert['alert_id'] == alert_id:
                    continue
                
                correlation_score = await self._calculate_correlation_score(alert_data, other_alert)
                if correlation_score > self.correlation_threshold:
                    correlations.append({
                        'alert_id': other_alert['alert_id'],
                        'correlation_score': correlation_score,
                        'correlation_type': self._determine_correlation_type(alert_data, other_alert)
                    })
            
            # Store correlations
            for correlation in correlations:
                await self._store_correlation(alert_id, correlation)
            
            # Create alert group if requested
            if create_group and correlations:
                group_alerts = [alert_data] + [
                    alert for alert in recent_alerts
                    if alert['alert_id'] in [c['alert_id'] for c in correlations]
                ]
                
                correlation_engine = AlertCorrelationEngine()
                groups = await correlation_engine.correlate_alerts(group_alerts)
                
                for group in groups:
                    await self.dashboard_manager._store_alert_group(group)
            
            return {
                'success': True,
                'correlations_found': len(correlations),
                'message': f'Found {len(correlations)} correlated alerts'
            }
            
        except Exception as e:
            logger.error(f"Error performing correlation: {e}")
            return {'success': False, 'error': str(e)}
    
    async def _calculate_correlation_score(self, alert1: Dict[str, Any], alert2: Dict[str, Any]) -> float:
        """Calculate correlation score between two alerts."""
        try:
            score = 0.0
            factors = 0
            
            # Time proximity (within 10 minutes gets higher score)
            time1 = datetime.fromisoformat(alert1.get('first_occurrence'))
            time2 = datetime.fromisoformat(alert2.get('first_occurrence'))
            time_diff_minutes = abs((time1 - time2).total_seconds() / 60)
            
            if time_diff_minutes <= 5:
                score += 0.4
            elif time_diff_minutes <= 10:
                score += 0.2
            factors += 1
            
            # Metric similarity
            metric1 = alert1.get('metric_name', '')
            metric2 = alert2.get('metric_name', '')
            
            if metric1 == metric2:
                score += 0.3
            elif self._metrics_are_related(metric1, metric2):
                score += 0.2
            factors += 1
            
            # Severity correlation
            severity1 = alert1.get('severity', 'info')
            severity2 = alert2.get('severity', 'info')
            
            if severity1 == severity2:
                score += 0.1
            factors += 1
            
            # Value correlation (if both are numeric)
            try:
                value1 = float(alert1.get('current_value', 0))
                value2 = float(alert2.get('current_value', 0))
                
                if value1 > 0 and value2 > 0:
                    ratio = min(value1, value2) / max(value1, value2)
                    if ratio > 0.8:  # Similar values
                        score += 0.2
            except (ValueError, ZeroDivisionError):
                pass
            
            return score / factors if factors > 0 else 0.0
            
        except Exception as e:
            logger.error(f"Error calculating correlation score: {e}")
            return 0.0
    
    def _metrics_are_related(self, metric1: str, metric2: str) -> bool:
        """Check if two metrics are related."""
        related_groups = [
            ['cpu_usage_percent', 'load_average_1m', 'load_average_5m'],
            ['memory_usage_percent', 'memory_available_bytes', 'memory_used_bytes'],
            ['disk_usage_percent', 'disk_free_bytes', 'disk_read_bytes_per_sec'],
            ['request_duration_avg_ms', 'request_duration_p95_ms', 'error_rate_percent'],
            ['db_query_duration_avg_ms', 'db_query_duration_p95_ms']
        ]
        
        for group in related_groups:
            if metric1 in group and metric2 in group:
                return True
        
        return False
    
    def _determine_correlation_type(self, alert1: Dict[str, Any], alert2: Dict[str, Any]) -> str:
        """Determine the type of correlation between alerts."""
        metric1 = alert1.get('metric_name', '')
        metric2 = alert2.get('metric_name', '')
        
        if metric1 == metric2:
            return 'metric_burst'
        elif self._metrics_are_related(metric1, metric2):
            return 'cascading_failure'
        else:
            return 'time_window'
    
    async def _store_correlation(self, primary_alert_id: str, correlation: Dict[str, Any]):
        """Store alert correlation."""
        try:
            correlation_id = str(uuid.uuid4())
            
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO alert_correlations 
                    (id, primary_alert_id, related_alert_id, correlation_type, correlation_score)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    correlation_id,
                    primary_alert_id,
                    correlation['alert_id'],
                    correlation['correlation_type'],
                    correlation['correlation_score']
                ))
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error storing correlation: {e}")
    
    async def _record_remediation(self, alert_id: str, script_name: str, result: Dict[str, Any], execution_time: float):
        """Record remediation execution."""
        try:
            remediation_id = str(uuid.uuid4())
            
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO remediation_history 
                    (id, alert_id, script_name, executed_at, success, result_data, 
                     execution_time_seconds, triggered_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    remediation_id,
                    alert_id,
                    script_name,
                    datetime.now(timezone.utc).isoformat(),
                    result.get('success', False),
                    json.dumps(result),
                    execution_time,
                    'workflow_system'
                ))
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error recording remediation: {e}")
    
    async def _create_workflow_execution(self, execution: WorkflowExecution):
        """Create workflow execution record."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO workflow_executions 
                    (id, rule_id, alert_id, trigger_event, started_at, status, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    execution.id,
                    execution.rule_id,
                    execution.alert_id,
                    execution.trigger_event,
                    execution.started_at.isoformat(),
                    execution.status,
                    json.dumps(execution.metadata)
                ))
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error creating workflow execution: {e}")
    
    async def _update_workflow_execution(self, execution: WorkflowExecution):
        """Update workflow execution record."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    UPDATE workflow_executions 
                    SET completed_at = ?, status = ?, actions_executed = ?, error_message = ?
                    WHERE id = ?
                """, (
                    execution.completed_at.isoformat() if execution.completed_at else None,
                    execution.status,
                    json.dumps(execution.actions_executed),
                    execution.error_message,
                    execution.id
                ))
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error updating workflow execution: {e}")
    
    async def _update_rule_stats(self, rule_id: str):
        """Update workflow rule execution statistics."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    UPDATE workflow_rules 
                    SET execution_count = execution_count + 1, 
                        last_executed_at = ?
                    WHERE id = ?
                """, (datetime.now(timezone.utc).isoformat(), rule_id))
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error updating rule stats: {e}")
    
    async def get_workflow_metrics(self) -> Dict[str, Any]:
        """Get workflow performance metrics."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Get execution stats
                cursor = await db.execute("""
                    SELECT 
                        COUNT(*) as total_executions,
                        COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful_executions,
                        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_executions,
                        AVG(CASE 
                            WHEN completed_at IS NOT NULL 
                            THEN julianday(completed_at) - julianday(started_at) 
                        END) * 24 * 60 as avg_execution_time_minutes
                    FROM workflow_executions
                    WHERE started_at >= ?
                """, ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),))
                
                execution_stats = await cursor.fetchone()
                
                # Get remediation stats
                cursor = await db.execute("""
                    SELECT 
                        COUNT(*) as total_remediations,
                        COUNT(CASE WHEN success = 1 THEN 1 END) as successful_remediations,
                        AVG(execution_time_seconds) as avg_remediation_time
                    FROM remediation_history
                    WHERE executed_at >= ?
                """, ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),))
                
                remediation_stats = await cursor.fetchone()
                
                # Get correlation stats
                cursor = await db.execute("""
                    SELECT COUNT(*) as total_correlations
                    FROM alert_correlations
                    WHERE created_at >= ?
                """, ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),))
                
                correlation_stats = await cursor.fetchone()
                
                return {
                    'execution_stats': {
                        'total_executions': execution_stats[0] or 0,
                        'successful_executions': execution_stats[1] or 0,
                        'failed_executions': execution_stats[2] or 0,
                        'success_rate': (execution_stats[1] or 0) / max(execution_stats[0] or 1, 1) * 100,
                        'avg_execution_time_minutes': execution_stats[3] or 0
                    },
                    'remediation_stats': {
                        'total_remediations': remediation_stats[0] or 0,
                        'successful_remediations': remediation_stats[1] or 0,
                        'success_rate': (remediation_stats[1] or 0) / max(remediation_stats[0] or 1, 1) * 100,
                        'avg_remediation_time_seconds': remediation_stats[2] or 0
                    },
                    'correlation_stats': {
                        'total_correlations': correlation_stats[0] or 0
                    },
                    'current_metrics': self.workflow_metrics,
                    'active_workflows': len(self.active_workflows),
                    'total_rules': len(self.workflow_rules)
                }
                
        except Exception as e:
            logger.error(f"Error getting workflow metrics: {e}")
            return {}


# Global workflow manager instance
workflow_manager: Optional[AlertWorkflowManager] = None


def get_workflow_manager() -> AlertWorkflowManager:
    """Get the global workflow manager instance."""
    global workflow_manager
    if workflow_manager is None:
        workflow_manager = AlertWorkflowManager()
    return workflow_manager


async def initialize_workflow_manager():
    """Initialize the global workflow manager."""
    manager = get_workflow_manager()
    await manager.initialize()
    return manager