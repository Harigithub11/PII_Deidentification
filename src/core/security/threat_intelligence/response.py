"""
Automated Threat Response System

Provides automated incident response, threat containment, and security orchestration
capabilities for immediate threat mitigation.
"""

import asyncio
import logging
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import uuid
import aiosqlite
from pathlib import Path

from .indicators import ThreatLevel
from .monitoring import SecurityEvent, MonitoringAlert

logger = logging.getLogger(__name__)


class ResponseAction(Enum):
    """Types of automated response actions."""
    BLOCK_IP = "block_ip"
    QUARANTINE_USER = "quarantine_user"
    DISABLE_SESSION = "disable_session"
    RATE_LIMIT = "rate_limit"
    ALERT_ADMIN = "alert_admin"
    LOG_INCIDENT = "log_incident"
    COLLECT_EVIDENCE = "collect_evidence"
    NOTIFY_SECURITY_TEAM = "notify_security_team"
    TEMPORARY_ACCOUNT_LOCK = "temporary_account_lock"
    REVOKE_API_KEY = "revoke_api_key"
    FORCE_PASSWORD_RESET = "force_password_reset"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    BACKUP_LOGS = "backup_logs"
    ESCALATE_TO_HUMAN = "escalate_to_human"


class ResponseStatus(Enum):
    """Status of response actions."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REQUIRES_HUMAN = "requires_human"


class IncidentSeverity(Enum):
    """Incident severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class ResponseTask:
    """Represents an automated response task."""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action: ResponseAction = ResponseAction.LOG_INCIDENT
    status: ResponseStatus = ResponseStatus.PENDING
    priority: int = 5  # 1-10, 10 being highest priority
    target: str = ""  # IP, user_id, session_id, etc.
    parameters: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    result: Dict[str, Any] = field(default_factory=dict)
    retries: int = 0
    max_retries: int = 3
    timeout_seconds: int = 300
    triggered_by: Optional[str] = None  # Event or alert ID that triggered this
    
    def is_ready_to_execute(self) -> bool:
        """Check if task is ready for execution."""
        if self.status != ResponseStatus.PENDING:
            return False
        
        if self.scheduled_at and self.scheduled_at > datetime.now(timezone.utc):
            return False
        
        return True


@dataclass
class Incident:
    """Represents a security incident."""
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: IncidentSeverity = IncidentSeverity.LOW
    status: str = "open"  # open, investigating, contained, resolved, closed
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    assigned_to: Optional[str] = None
    tags: Set[str] = field(default_factory=set)
    affected_systems: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    related_events: List[str] = field(default_factory=list)  # Event IDs
    related_alerts: List[str] = field(default_factory=list)  # Alert IDs
    response_tasks: List[str] = field(default_factory=list)  # Task IDs
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    escalated: bool = False
    containment_status: str = "none"  # none, partial, full
    
    def add_timeline_entry(self, action: str, details: str, actor: str = "system"):
        """Add an entry to the incident timeline."""
        self.timeline.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': action,
            'details': details,
            'actor': actor
        })
        self.updated_at = datetime.now(timezone.utc)


class ResponseExecutor:
    """Executes automated response actions."""
    
    def __init__(self):
        """Initialize response executor."""
        self.action_handlers: Dict[ResponseAction, Callable] = {}
        self.blocked_ips: Set[str] = set()
        self.quarantined_users: Set[str] = set()
        self.disabled_sessions: Set[str] = set()
        self.rate_limited_ips: Dict[str, datetime] = {}
        self._setup_action_handlers()
    
    def _setup_action_handlers(self):
        """Setup response action handlers."""
        self.action_handlers = {
            ResponseAction.BLOCK_IP: self._block_ip,
            ResponseAction.QUARANTINE_USER: self._quarantine_user,
            ResponseAction.DISABLE_SESSION: self._disable_session,
            ResponseAction.RATE_LIMIT: self._apply_rate_limit,
            ResponseAction.ALERT_ADMIN: self._alert_admin,
            ResponseAction.LOG_INCIDENT: self._log_incident,
            ResponseAction.COLLECT_EVIDENCE: self._collect_evidence,
            ResponseAction.NOTIFY_SECURITY_TEAM: self._notify_security_team,
            ResponseAction.TEMPORARY_ACCOUNT_LOCK: self._temporary_account_lock,
            ResponseAction.REVOKE_API_KEY: self._revoke_api_key,
            ResponseAction.FORCE_PASSWORD_RESET: self._force_password_reset,
            ResponseAction.ISOLATE_ENDPOINT: self._isolate_endpoint,
            ResponseAction.BACKUP_LOGS: self._backup_logs,
            ResponseAction.ESCALATE_TO_HUMAN: self._escalate_to_human
        }
    
    async def execute_task(self, task: ResponseTask) -> bool:
        """Execute a response task."""
        try:
            task.status = ResponseStatus.IN_PROGRESS
            task.started_at = datetime.now(timezone.utc)
            
            handler = self.action_handlers.get(task.action)
            if not handler:
                task.error_message = f"No handler for action: {task.action.value}"
                task.status = ResponseStatus.FAILED
                return False
            
            # Execute the handler
            result = await handler(task)
            
            if result:
                task.status = ResponseStatus.COMPLETED
                task.completed_at = datetime.now(timezone.utc)
                logger.info(f"Response task completed: {task.action.value} for {task.target}")
                return True
            else:
                task.status = ResponseStatus.FAILED
                task.completed_at = datetime.now(timezone.utc)
                return False
                
        except Exception as e:
            task.error_message = str(e)
            task.status = ResponseStatus.FAILED
            task.completed_at = datetime.now(timezone.utc)
            logger.error(f"Error executing response task {task.task_id}: {e}")
            return False
    
    async def _block_ip(self, task: ResponseTask) -> bool:
        """Block an IP address."""
        try:
            ip_address = task.target
            duration = task.parameters.get('duration', 3600)  # Default 1 hour
            
            # Add to blocked IPs (in production, this would integrate with firewall/WAF)
            self.blocked_ips.add(ip_address)
            
            # Schedule unblock task
            if duration > 0:
                unblock_time = datetime.now(timezone.utc) + timedelta(seconds=duration)
                # In practice, would schedule an unblock task
                logger.info(f"IP {ip_address} blocked until {unblock_time}")
            
            task.result = {
                'ip_address': ip_address,
                'blocked_at': datetime.now(timezone.utc).isoformat(),
                'duration': duration,
                'reason': task.parameters.get('reason', 'Automated security response')
            }
            
            return True
            
        except Exception as e:
            task.error_message = f"Failed to block IP: {e}"
            return False
    
    async def _quarantine_user(self, task: ResponseTask) -> bool:
        """Quarantine a user account."""
        try:
            user_id = task.target
            duration = task.parameters.get('duration', 7200)  # Default 2 hours
            
            # Add to quarantined users
            self.quarantined_users.add(user_id)
            
            task.result = {
                'user_id': user_id,
                'quarantined_at': datetime.now(timezone.utc).isoformat(),
                'duration': duration,
                'reason': task.parameters.get('reason', 'Security incident')
            }
            
            logger.info(f"User {user_id} quarantined")
            return True
            
        except Exception as e:
            task.error_message = f"Failed to quarantine user: {e}"
            return False
    
    async def _disable_session(self, task: ResponseTask) -> bool:
        """Disable a user session."""
        try:
            session_id = task.target
            
            # Add to disabled sessions
            self.disabled_sessions.add(session_id)
            
            task.result = {
                'session_id': session_id,
                'disabled_at': datetime.now(timezone.utc).isoformat(),
                'reason': task.parameters.get('reason', 'Security incident')
            }
            
            logger.info(f"Session {session_id} disabled")
            return True
            
        except Exception as e:
            task.error_message = f"Failed to disable session: {e}"
            return False
    
    async def _apply_rate_limit(self, task: ResponseTask) -> bool:
        """Apply rate limiting to an IP."""
        try:
            ip_address = task.target
            duration = task.parameters.get('duration', 1800)  # Default 30 minutes
            
            # Add to rate limited IPs
            self.rate_limited_ips[ip_address] = datetime.now(timezone.utc) + timedelta(seconds=duration)
            
            task.result = {
                'ip_address': ip_address,
                'rate_limited_at': datetime.now(timezone.utc).isoformat(),
                'duration': duration
            }
            
            logger.info(f"Rate limiting applied to IP {ip_address}")
            return True
            
        except Exception as e:
            task.error_message = f"Failed to apply rate limit: {e}"
            return False
    
    async def _alert_admin(self, task: ResponseTask) -> bool:
        """Send alert to administrator."""
        try:
            message = task.parameters.get('message', 'Security alert triggered')
            severity = task.parameters.get('severity', 'medium')
            
            # In production, this would send actual notifications (email, SMS, etc.)
            logger.warning(f"ADMIN ALERT ({severity}): {message}")
            
            task.result = {
                'alert_sent_at': datetime.now(timezone.utc).isoformat(),
                'message': message,
                'severity': severity,
                'recipient': 'administrator'
            }
            
            return True
            
        except Exception as e:
            task.error_message = f"Failed to alert admin: {e}"
            return False
    
    async def _log_incident(self, task: ResponseTask) -> bool:
        """Log security incident."""
        try:
            incident_details = task.parameters.get('details', {})
            
            # Create incident log entry
            log_entry = {
                'incident_logged_at': datetime.now(timezone.utc).isoformat(),
                'severity': task.parameters.get('severity', 'medium'),
                'details': incident_details,
                'source': task.parameters.get('source', 'automated_response')
            }
            
            task.result = log_entry
            logger.info(f"Security incident logged: {incident_details}")
            
            return True
            
        except Exception as e:
            task.error_message = f"Failed to log incident: {e}"
            return False
    
    async def _collect_evidence(self, task: ResponseTask) -> bool:
        """Collect forensic evidence."""
        try:
            evidence_types = task.parameters.get('evidence_types', ['logs', 'network'])
            
            # Simulate evidence collection
            collected_evidence = {
                'collection_started': datetime.now(timezone.utc).isoformat(),
                'evidence_types': evidence_types,
                'collection_id': str(uuid.uuid4()),
                'status': 'collecting'
            }
            
            task.result = collected_evidence
            logger.info(f"Evidence collection started: {collected_evidence['collection_id']}")
            
            return True
            
        except Exception as e:
            task.error_message = f"Failed to collect evidence: {e}"
            return False
    
    async def _notify_security_team(self, task: ResponseTask) -> bool:
        """Notify security team."""
        try:
            message = task.parameters.get('message', 'Security incident detected')
            
            # In production, this would integrate with notification systems
            logger.warning(f"SECURITY TEAM NOTIFICATION: {message}")
            
            task.result = {
                'notification_sent_at': datetime.now(timezone.utc).isoformat(),
                'message': message,
                'team': 'security'
            }
            
            return True
            
        except Exception as e:
            task.error_message = f"Failed to notify security team: {e}"
            return False
    
    async def _temporary_account_lock(self, task: ResponseTask) -> bool:
        """Temporarily lock user account."""
        try:
            user_id = task.target
            duration = task.parameters.get('duration', 1800)  # Default 30 minutes
            
            # In production, this would update the user account status
            logger.info(f"Account {user_id} temporarily locked for {duration} seconds")
            
            task.result = {
                'user_id': user_id,
                'locked_at': datetime.now(timezone.utc).isoformat(),
                'duration': duration,
                'reason': task.parameters.get('reason', 'Security incident')
            }
            
            return True
            
        except Exception as e:
            task.error_message = f"Failed to lock account: {e}"
            return False
    
    async def _revoke_api_key(self, task: ResponseTask) -> bool:
        """Revoke API key."""
        try:
            api_key = task.target
            
            # In production, this would update the API key status in database
            logger.info(f"API key revoked: {api_key[:8]}...")
            
            task.result = {
                'api_key_id': api_key,
                'revoked_at': datetime.now(timezone.utc).isoformat(),
                'reason': task.parameters.get('reason', 'Security incident')
            }
            
            return True
            
        except Exception as e:
            task.error_message = f"Failed to revoke API key: {e}"
            return False
    
    async def _force_password_reset(self, task: ResponseTask) -> bool:
        """Force password reset for user."""
        try:
            user_id = task.target
            
            # In production, this would set a flag requiring password reset
            logger.info(f"Password reset forced for user: {user_id}")
            
            task.result = {
                'user_id': user_id,
                'password_reset_forced_at': datetime.now(timezone.utc).isoformat(),
                'reason': task.parameters.get('reason', 'Security incident')
            }
            
            return True
            
        except Exception as e:
            task.error_message = f"Failed to force password reset: {e}"
            return False
    
    async def _isolate_endpoint(self, task: ResponseTask) -> bool:
        """Isolate an endpoint from network."""
        try:
            endpoint = task.target
            
            # In production, this would integrate with network management systems
            logger.warning(f"Endpoint isolated: {endpoint}")
            
            task.result = {
                'endpoint': endpoint,
                'isolated_at': datetime.now(timezone.utc).isoformat(),
                'reason': task.parameters.get('reason', 'Security incident')
            }
            
            return True
            
        except Exception as e:
            task.error_message = f"Failed to isolate endpoint: {e}"
            return False
    
    async def _backup_logs(self, task: ResponseTask) -> bool:
        """Backup system logs."""
        try:
            log_types = task.parameters.get('log_types', ['security', 'audit'])
            
            # In production, this would create actual log backups
            backup_id = str(uuid.uuid4())
            
            task.result = {
                'backup_id': backup_id,
                'backup_started_at': datetime.now(timezone.utc).isoformat(),
                'log_types': log_types
            }
            
            logger.info(f"Log backup started: {backup_id}")
            return True
            
        except Exception as e:
            task.error_message = f"Failed to backup logs: {e}"
            return False
    
    async def _escalate_to_human(self, task: ResponseTask) -> bool:
        """Escalate incident to human operator."""
        try:
            urgency = task.parameters.get('urgency', 'high')
            message = task.parameters.get('message', 'Incident requires human intervention')
            
            # In production, this would integrate with ticketing systems
            logger.critical(f"HUMAN ESCALATION ({urgency}): {message}")
            
            task.result = {
                'escalated_at': datetime.now(timezone.utc).isoformat(),
                'urgency': urgency,
                'message': message,
                'ticket_id': str(uuid.uuid4())
            }
            
            return True
            
        except Exception as e:
            task.error_message = f"Failed to escalate to human: {e}"
            return False
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if an IP is blocked."""
        return ip_address in self.blocked_ips
    
    def is_user_quarantined(self, user_id: str) -> bool:
        """Check if a user is quarantined."""
        return user_id in self.quarantined_users
    
    def is_session_disabled(self, session_id: str) -> bool:
        """Check if a session is disabled."""
        return session_id in self.disabled_sessions
    
    def is_ip_rate_limited(self, ip_address: str) -> bool:
        """Check if an IP is rate limited."""
        if ip_address in self.rate_limited_ips:
            expiry = self.rate_limited_ips[ip_address]
            if datetime.now(timezone.utc) < expiry:
                return True
            else:
                del self.rate_limited_ips[ip_address]
        return False


class AutomatedThreatResponse:
    """Main automated threat response coordinator."""
    
    def __init__(self, db_path: str = "threat_response.db"):
        """Initialize automated threat response system."""
        self.db_path = db_path
        self.executor = ResponseExecutor()
        self.response_queue = asyncio.PriorityQueue()
        self.active_tasks: Dict[str, ResponseTask] = {}
        self.response_rules: Dict[str, List[Dict[str, Any]]] = {}
        self._setup_response_rules()
    
    def _setup_response_rules(self):
        """Setup automated response rules."""
        self.response_rules = {
            'brute_force_attack': [
                {
                    'action': ResponseAction.BLOCK_IP,
                    'priority': 8,
                    'parameters': {'duration': 3600, 'reason': 'Brute force attack detected'},
                    'condition': lambda alert: alert.severity in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
                },
                {
                    'action': ResponseAction.ALERT_ADMIN,
                    'priority': 6,
                    'parameters': {'message': 'Brute force attack detected', 'severity': 'high'}
                }
            ],
            'malicious_user_agent': [
                {
                    'action': ResponseAction.BLOCK_IP,
                    'priority': 9,
                    'parameters': {'duration': 7200, 'reason': 'Malicious user agent detected'}
                },
                {
                    'action': ResponseAction.COLLECT_EVIDENCE,
                    'priority': 5,
                    'parameters': {'evidence_types': ['logs', 'headers']}
                }
            ],
            'potential_data_exfiltration': [
                {
                    'action': ResponseAction.QUARANTINE_USER,
                    'priority': 10,
                    'parameters': {'duration': 3600, 'reason': 'Potential data exfiltration'}
                },
                {
                    'action': ResponseAction.NOTIFY_SECURITY_TEAM,
                    'priority': 9,
                    'parameters': {'message': 'Potential data exfiltration detected'}
                },
                {
                    'action': ResponseAction.COLLECT_EVIDENCE,
                    'priority': 8,
                    'parameters': {'evidence_types': ['logs', 'network', 'files']}
                }
            ],
            'privilege_escalation_attempt': [
                {
                    'action': ResponseAction.QUARANTINE_USER,
                    'priority': 9,
                    'parameters': {'duration': 1800, 'reason': 'Privilege escalation attempt'}
                },
                {
                    'action': ResponseAction.ALERT_ADMIN,
                    'priority': 8,
                    'parameters': {'message': 'Privilege escalation attempt detected', 'severity': 'high'}
                }
            ],
            'malicious_payload_detected': [
                {
                    'action': ResponseAction.BLOCK_IP,
                    'priority': 10,
                    'parameters': {'duration': 7200, 'reason': 'Malicious payload detected'}
                },
                {
                    'action': ResponseAction.COLLECT_EVIDENCE,
                    'priority': 7,
                    'parameters': {'evidence_types': ['logs', 'request_data']}
                }
            ]
        }
    
    async def initialize(self):
        """Initialize the threat response system."""
        try:
            await self._create_database()
            
            # Start background tasks
            asyncio.create_task(self._response_processor())
            asyncio.create_task(self._task_monitor())
            
            logger.info("Automated Threat Response System initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize Automated Threat Response: {e}")
            raise
    
    async def _create_database(self):
        """Create response database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS response_tasks (
                    task_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    target TEXT NOT NULL,
                    parameters TEXT,
                    created_at TEXT NOT NULL,
                    scheduled_at TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    error_message TEXT,
                    result TEXT,
                    retries INTEGER DEFAULT 0,
                    triggered_by TEXT
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    assigned_to TEXT,
                    tags TEXT,
                    affected_systems TEXT,
                    affected_users TEXT,
                    related_events TEXT,
                    related_alerts TEXT,
                    response_tasks TEXT,
                    timeline TEXT,
                    metadata TEXT,
                    escalated INTEGER DEFAULT 0,
                    containment_status TEXT DEFAULT 'none'
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_task_status ON response_tasks(status)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_task_priority ON response_tasks(priority)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_incident_severity ON incidents(severity)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_incident_status ON incidents(status)")
            
            await db.commit()
    
    async def execute_immediate_response(self, threat_context: Any) -> List[ResponseTask]:
        """Execute immediate response to a threat."""
        try:
            response_tasks = []
            
            # Determine appropriate response actions based on threat type
            threat_type = getattr(threat_context, 'threat_type', 'unknown')
            rules = self.response_rules.get(threat_type, [])
            
            for rule in rules:
                # Check if condition is met (if specified)
                condition = rule.get('condition')
                if condition and not condition(threat_context):
                    continue
                
                # Create response task
                task = ResponseTask(
                    action=rule['action'],
                    priority=rule['priority'],
                    target=self._extract_target_from_threat(threat_context, rule['action']),
                    parameters=rule.get('parameters', {}),
                    triggered_by=getattr(threat_context, 'threat_id', 'unknown')
                )
                
                response_tasks.append(task)
                
                # Add to active tasks and queue
                self.active_tasks[task.task_id] = task
                await self.response_queue.put((10 - task.priority, task))  # Higher priority = lower number
                
                # Save task to database
                await self._save_task_to_db(task)
            
            logger.info(f"Scheduled {len(response_tasks)} response tasks for threat: {threat_type}")
            return response_tasks
            
        except Exception as e:
            logger.error(f"Error executing immediate response: {e}")
            return []
    
    def _extract_target_from_threat(self, threat_context: Any, action: ResponseAction) -> str:
        """Extract appropriate target from threat context based on action."""
        metadata = getattr(threat_context, 'metadata', {})
        
        if action in [ResponseAction.BLOCK_IP, ResponseAction.RATE_LIMIT]:
            return metadata.get('source_ip', 'unknown')
        elif action in [ResponseAction.QUARANTINE_USER, ResponseAction.TEMPORARY_ACCOUNT_LOCK, 
                       ResponseAction.FORCE_PASSWORD_RESET]:
            return metadata.get('user_id', 'unknown')
        elif action == ResponseAction.DISABLE_SESSION:
            return metadata.get('session_id', 'unknown')
        elif action == ResponseAction.REVOKE_API_KEY:
            return metadata.get('api_key', 'unknown')
        else:
            return str(threat_context.threat_id) if hasattr(threat_context, 'threat_id') else 'unknown'
    
    async def _response_processor(self):
        """Background processor for response tasks."""
        while True:
            try:
                # Get next task from queue
                priority, task = await asyncio.wait_for(self.response_queue.get(), timeout=1.0)
                
                if task.is_ready_to_execute():
                    success = await self.executor.execute_task(task)
                    
                    if not success and task.retries < task.max_retries:
                        # Retry failed task
                        task.retries += 1
                        task.status = ResponseStatus.PENDING
                        await self.response_queue.put((priority, task))
                        logger.info(f"Retrying task {task.task_id} (attempt {task.retries + 1})")
                    else:
                        # Task completed or max retries reached
                        await self._update_task_in_db(task)
                        
                        if task.status == ResponseStatus.FAILED:
                            logger.error(f"Task {task.task_id} failed after {task.retries} retries")
                else:
                    # Task not ready, put it back in queue
                    await self.response_queue.put((priority, task))
                    await asyncio.sleep(1)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in response processor: {e}")
                await asyncio.sleep(1)
    
    async def _task_monitor(self):
        """Monitor running tasks and handle timeouts."""
        while True:
            try:
                current_time = datetime.now(timezone.utc)
                
                for task_id, task in list(self.active_tasks.items()):
                    # Check for task timeout
                    if (task.status == ResponseStatus.IN_PROGRESS and 
                        task.started_at and
                        (current_time - task.started_at).total_seconds() > task.timeout_seconds):
                        
                        task.status = ResponseStatus.FAILED
                        task.error_message = "Task timeout"
                        task.completed_at = current_time
                        
                        await self._update_task_in_db(task)
                        logger.warning(f"Task {task_id} timed out")
                    
                    # Remove completed tasks from active list
                    if task.status in [ResponseStatus.COMPLETED, ResponseStatus.FAILED, ResponseStatus.CANCELLED]:
                        if task_id in self.active_tasks:
                            del self.active_tasks[task_id]
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in task monitor: {e}")
                await asyncio.sleep(30)
    
    async def _save_task_to_db(self, task: ResponseTask):
        """Save response task to database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO response_tasks (
                        task_id, action, status, priority, target, parameters,
                        created_at, scheduled_at, started_at, completed_at,
                        error_message, result, retries, triggered_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    task.task_id,
                    task.action.value,
                    task.status.value,
                    task.priority,
                    task.target,
                    json.dumps(task.parameters),
                    task.created_at.isoformat(),
                    task.scheduled_at.isoformat() if task.scheduled_at else None,
                    task.started_at.isoformat() if task.started_at else None,
                    task.completed_at.isoformat() if task.completed_at else None,
                    task.error_message,
                    json.dumps(task.result),
                    task.retries,
                    task.triggered_by
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Error saving task to database: {e}")
    
    async def _update_task_in_db(self, task: ResponseTask):
        """Update response task in database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    UPDATE response_tasks SET
                        status = ?, started_at = ?, completed_at = ?,
                        error_message = ?, result = ?, retries = ?
                    WHERE task_id = ?
                """, (
                    task.status.value,
                    task.started_at.isoformat() if task.started_at else None,
                    task.completed_at.isoformat() if task.completed_at else None,
                    task.error_message,
                    json.dumps(task.result),
                    task.retries,
                    task.task_id
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Error updating task in database: {e}")
    
    async def get_response_status(self) -> Dict[str, Any]:
        """Get response system status."""
        try:
            # Count tasks by status
            status_counts = {}
            for status in ResponseStatus:
                status_counts[status.value] = sum(
                    1 for task in self.active_tasks.values() if task.status == status
                )
            
            # Get executor status
            executor_status = {
                'blocked_ips': len(self.executor.blocked_ips),
                'quarantined_users': len(self.executor.quarantined_users),
                'disabled_sessions': len(self.executor.disabled_sessions),
                'rate_limited_ips': len(self.executor.rate_limited_ips)
            }
            
            return {
                'active_tasks': len(self.active_tasks),
                'task_status_distribution': status_counts,
                'queue_size': self.response_queue.qsize(),
                'executor_status': executor_status,
                'response_rules_active': len(self.response_rules)
            }
            
        except Exception as e:
            logger.error(f"Error getting response status: {e}")
            return {}
    
    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending response task."""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            if task.status == ResponseStatus.PENDING:
                task.status = ResponseStatus.CANCELLED
                await self._update_task_in_db(task)
                return True
        return False
    
    async def execute_response(self, response_task: ResponseTask) -> bool:
        """Execute a specific response task."""
        return await self.executor.execute_task(response_task)
    
    async def shutdown(self):
        """Shutdown the threat response system."""
        logger.info("Shutting down Automated Threat Response System")


class IncidentManager:
    """Manages security incidents and their lifecycle."""
    
    def __init__(self, db_path: str = "incidents.db"):
        """Initialize incident manager."""
        self.db_path = db_path
        self.active_incidents: Dict[str, Incident] = {}
    
    async def initialize(self):
        """Initialize the incident manager."""
        logger.info("Incident Manager initialized")
    
    async def create_incident(self, threat_context: Any) -> Incident:
        """Create a new security incident."""
        try:
            incident = Incident(
                title=f"Security Incident: {getattr(threat_context, 'threat_type', 'Unknown')}",
                description=f"Automated incident created for threat: {threat_context}",
                severity=self._threat_to_incident_severity(getattr(threat_context, 'severity', ThreatLevel.LOW)),
                metadata=getattr(threat_context, 'metadata', {})
            )
            
            incident.add_timeline_entry("created", "Incident created by threat intelligence system")
            
            self.active_incidents[incident.incident_id] = incident
            logger.info(f"Created incident: {incident.incident_id}")
            
            return incident
            
        except Exception as e:
            logger.error(f"Error creating incident: {e}")
            return None
    
    def _threat_to_incident_severity(self, threat_level: ThreatLevel) -> IncidentSeverity:
        """Convert threat level to incident severity."""
        mapping = {
            ThreatLevel.INFO: IncidentSeverity.LOW,
            ThreatLevel.LOW: IncidentSeverity.LOW,
            ThreatLevel.MEDIUM: IncidentSeverity.MEDIUM,
            ThreatLevel.HIGH: IncidentSeverity.HIGH,
            ThreatLevel.CRITICAL: IncidentSeverity.CRITICAL
        }
        return mapping.get(threat_level, IncidentSeverity.LOW)
    
    async def update_incident_status(self, incident_id: str, status: str) -> bool:
        """Update incident status."""
        if incident_id in self.active_incidents:
            incident = self.active_incidents[incident_id]
            old_status = incident.status
            incident.status = status
            incident.add_timeline_entry("status_changed", f"Status changed from {old_status} to {status}")
            return True
        return False
    
    async def assign_incident(self, incident_id: str, assignee: str) -> bool:
        """Assign incident to a person."""
        if incident_id in self.active_incidents:
            incident = self.active_incidents[incident_id]
            incident.assigned_to = assignee
            incident.add_timeline_entry("assigned", f"Incident assigned to {assignee}")
            return True
        return False
    
    async def get_incident_summary(self) -> Dict[str, Any]:
        """Get incident summary."""
        try:
            total_incidents = len(self.active_incidents)
            open_incidents = sum(1 for inc in self.active_incidents.values() if inc.status == 'open')
            
            # Count by severity
            severity_counts = {}
            for severity in IncidentSeverity:
                severity_counts[severity.value] = sum(
                    1 for inc in self.active_incidents.values() if inc.severity == severity
                )
            
            return {
                'total_incidents': total_incidents,
                'open_incidents': open_incidents,
                'severity_distribution': severity_counts,
                'escalated_incidents': sum(1 for inc in self.active_incidents.values() if inc.escalated)
            }
            
        except Exception as e:
            logger.error(f"Error getting incident summary: {e}")
            return {}
    
    async def shutdown(self):
        """Shutdown the incident manager."""
        logger.info("Incident Manager shutdown")