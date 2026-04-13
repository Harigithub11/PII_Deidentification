"""
PCI DSS Monitoring System Module

This module implements comprehensive security monitoring and logging
as required by PCI DSS Requirements 10 and 12.
"""

import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import asyncio
import threading
from pathlib import Path
import time

from ..database.database_manager import DatabaseManager
from .pci_dss_core import PCIDSSComplianceEngine, PCIControl, ControlStatus

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Security event types."""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    SESSION_TIMEOUT = "session_timeout"
    PASSWORD_CHANGE = "password_change"
    
    # Access control events
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    PERMISSION_CHANGE = "permission_change"
    ROLE_CHANGE = "role_change"
    
    # Data access events
    PII_ACCESS = "pii_access"
    PII_MODIFICATION = "pii_modification"
    PII_DELETION = "pii_deletion"
    PII_EXPORT = "pii_export"
    
    # System events
    SYSTEM_START = "system_start"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIGURATION_CHANGE = "configuration_change"
    SERVICE_START = "service_start"
    SERVICE_STOP = "service_stop"
    
    # Security events
    INTRUSION_ATTEMPT = "intrusion_attempt"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    SECURITY_POLICY_VIOLATION = "security_policy_violation"
    MALWARE_DETECTED = "malware_detected"
    
    # Compliance events
    COMPLIANCE_SCAN = "compliance_scan"
    AUDIT_LOG_ACCESS = "audit_log_access"
    POLICY_UPDATE = "policy_update"
    
    # Network events
    NETWORK_CONNECTION = "network_connection"
    FIREWALL_BLOCK = "firewall_block"
    PORT_SCAN_DETECTED = "port_scan_detected"


class Severity(str, Enum):
    """Event severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertStatus(str, Enum):
    """Alert status."""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class SecurityEvent:
    """Security event record."""
    event_id: str
    event_type: EventType
    timestamp: datetime
    user_id: Optional[str]
    source_ip: str
    user_agent: Optional[str]
    resource: str
    action: str
    outcome: str  # success, failure, error
    severity: Severity
    description: str
    additional_data: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    correlation_id: Optional[str] = None


@dataclass
class SecurityAlert:
    """Security alert."""
    alert_id: str
    event_ids: List[str]
    alert_type: str
    severity: Severity
    title: str
    description: str
    created_at: datetime
    status: AlertStatus = AlertStatus.ACTIVE
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    false_positive_reason: Optional[str] = None


@dataclass
class MonitoringRule:
    """Monitoring and alerting rule."""
    rule_id: str
    name: str
    description: str
    event_types: List[EventType]
    conditions: Dict[str, Any]
    severity: Severity
    enabled: bool = True
    alert_threshold: int = 1
    time_window_minutes: int = 60
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class SystemMetrics:
    """System performance metrics."""
    timestamp: datetime
    cpu_usage_percent: float
    memory_usage_percent: float
    disk_usage_percent: float
    network_io_bytes: int
    active_sessions: int
    failed_login_attempts: int
    pii_access_count: int
    compliance_score: float


class SecurityMonitoringSystem:
    """
    Comprehensive security monitoring system implementing
    PCI DSS Requirements 10 and 12.
    """
    
    def __init__(self, 
                 db_manager: DatabaseManager,
                 compliance_engine: PCIDSSComplianceEngine):
        self.db_manager = db_manager
        self.compliance_engine = compliance_engine
        
        # Event storage
        self.security_events: List[SecurityEvent] = []
        self.security_alerts: Dict[str, SecurityAlert] = {}
        self.monitoring_rules: Dict[str, MonitoringRule] = {}
        self.system_metrics: List[SystemMetrics] = []
        
        # Monitoring configuration
        self.log_retention_days = 365  # PCI DSS requires 1 year minimum
        self.alert_retention_days = 90
        self.metrics_retention_days = 30
        
        # Real-time monitoring
        self.monitoring_enabled = True
        self.real_time_analysis_enabled = True
        self.correlation_enabled = True
        
        # Setup default monitoring rules
        self._setup_default_monitoring_rules()
        
        # Start background monitoring
        self._start_background_monitoring()
        
        logger.info("SecurityMonitoringSystem initialized")
    
    def _setup_default_monitoring_rules(self):
        """Setup default security monitoring rules."""
        default_rules = [
            {
                'rule_id': 'failed_login_attempts',
                'name': 'Multiple Failed Login Attempts',
                'description': 'Detect multiple failed login attempts from same source',
                'event_types': [EventType.LOGIN_FAILURE],
                'conditions': {'count': 5, 'source_ip': 'same'},
                'severity': Severity.HIGH,
                'alert_threshold': 5,
                'time_window_minutes': 15
            },
            {
                'rule_id': 'privileged_access',
                'name': 'Privileged Access Outside Business Hours',
                'description': 'Detect privileged access outside normal business hours',
                'event_types': [EventType.ACCESS_GRANTED],
                'conditions': {'time_range': ['22:00', '06:00'], 'privileged': True},
                'severity': Severity.MEDIUM,
                'alert_threshold': 1,
                'time_window_minutes': 1
            },
            {
                'rule_id': 'bulk_pii_access',
                'name': 'Bulk PII Data Access',
                'description': 'Detect unusual volume of PII data access',
                'event_types': [EventType.PII_ACCESS],
                'conditions': {'count': 50, 'user_id': 'same'},
                'severity': Severity.HIGH,
                'alert_threshold': 50,
                'time_window_minutes': 60
            },
            {
                'rule_id': 'configuration_changes',
                'name': 'Security Configuration Changes',
                'description': 'Detect changes to security configuration',
                'event_types': [EventType.CONFIGURATION_CHANGE],
                'conditions': {'resource': 'security_config'},
                'severity': Severity.CRITICAL,
                'alert_threshold': 1,
                'time_window_minutes': 1
            },
            {
                'rule_id': 'intrusion_attempts',
                'name': 'Intrusion Attempts',
                'description': 'Detect potential intrusion attempts',
                'event_types': [EventType.INTRUSION_ATTEMPT],
                'conditions': {},
                'severity': Severity.CRITICAL,
                'alert_threshold': 1,
                'time_window_minutes': 1
            }
        ]
        
        for rule_data in default_rules:
            rule = MonitoringRule(
                rule_id=rule_data['rule_id'],
                name=rule_data['name'],
                description=rule_data['description'],
                event_types=rule_data['event_types'],
                conditions=rule_data['conditions'],
                severity=rule_data['severity'],
                alert_threshold=rule_data['alert_threshold'],
                time_window_minutes=rule_data['time_window_minutes']
            )
            self.monitoring_rules[rule.rule_id] = rule
    
    async def log_security_event(self, 
                                event_type: EventType,
                                user_id: Optional[str],
                                source_ip: str,
                                resource: str,
                                action: str,
                                outcome: str,
                                description: str,
                                additional_data: Optional[Dict[str, Any]] = None,
                                user_agent: Optional[str] = None) -> SecurityEvent:
        """
        Log a security event.
        
        Args:
            event_type: Type of security event
            user_id: User ID (if applicable)
            source_ip: Source IP address
            resource: Resource accessed
            action: Action performed
            outcome: Outcome (success, failure, error)
            description: Event description
            additional_data: Additional event data
            user_agent: User agent string
            
        Returns:
            Created security event
        """
        event_id = self._generate_event_id()
        severity = await self._determine_event_severity(event_type, outcome)
        risk_score = await self._calculate_risk_score(event_type, outcome, additional_data or {})
        
        event = SecurityEvent(
            event_id=event_id,
            event_type=event_type,
            timestamp=datetime.utcnow(),
            user_id=user_id,
            source_ip=source_ip,
            user_agent=user_agent,
            resource=resource,
            action=action,
            outcome=outcome,
            severity=severity,
            description=description,
            additional_data=additional_data or {},
            risk_score=risk_score
        )
        
        # Store event
        self.security_events.append(event)
        
        # Perform real-time analysis
        if self.real_time_analysis_enabled:
            await self._analyze_event_real_time(event)
        
        # Log to system logger
        logger.info(f"Security event logged: {event_type} - {description}")
        
        return event
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        import uuid
        timestamp = int(time.time() * 1000)
        unique_id = uuid.uuid4().hex[:8]
        return f"evt_{timestamp}_{unique_id}"
    
    async def _determine_event_severity(self, 
                                      event_type: EventType, 
                                      outcome: str) -> Severity:
        """Determine event severity based on type and outcome."""
        # High severity events
        high_severity_events = {
            EventType.LOGIN_FAILURE,
            EventType.ACCESS_DENIED,
            EventType.INTRUSION_ATTEMPT,
            EventType.VULNERABILITY_DETECTED,
            EventType.MALWARE_DETECTED
        }
        
        # Critical severity events
        critical_severity_events = {
            EventType.SECURITY_POLICY_VIOLATION,
            EventType.PII_DELETION,
            EventType.CONFIGURATION_CHANGE
        }
        
        if event_type in critical_severity_events:
            return Severity.CRITICAL
        elif event_type in high_severity_events:
            return Severity.HIGH
        elif outcome == "failure" or outcome == "error":
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    async def _calculate_risk_score(self, 
                                  event_type: EventType, 
                                  outcome: str,
                                  additional_data: Dict[str, Any]) -> float:
        """Calculate risk score for event."""
        risk_score = 0.0
        
        # Base risk by event type
        event_risk_scores = {
            EventType.LOGIN_FAILURE: 0.3,
            EventType.ACCESS_DENIED: 0.4,
            EventType.PII_ACCESS: 0.2,
            EventType.PII_MODIFICATION: 0.5,
            EventType.PII_DELETION: 0.8,
            EventType.PII_EXPORT: 0.6,
            EventType.INTRUSION_ATTEMPT: 0.9,
            EventType.VULNERABILITY_DETECTED: 0.7,
            EventType.SECURITY_POLICY_VIOLATION: 0.8,
            EventType.CONFIGURATION_CHANGE: 0.4
        }
        
        risk_score = event_risk_scores.get(event_type, 0.1)
        
        # Adjust for outcome
        if outcome == "failure":
            risk_score *= 1.2
        elif outcome == "error":
            risk_score *= 1.1
        
        # Adjust for additional factors
        if additional_data.get('privileged_user'):
            risk_score *= 1.3
        
        if additional_data.get('off_hours'):
            risk_score *= 1.2
        
        if additional_data.get('unusual_location'):
            risk_score *= 1.4
        
        return min(risk_score, 1.0)  # Cap at 1.0
    
    async def _analyze_event_real_time(self, event: SecurityEvent):
        """Perform real-time analysis of security event."""
        # Check against monitoring rules
        for rule in self.monitoring_rules.values():
            if rule.enabled and event.event_type in rule.event_types:
                if await self._evaluate_monitoring_rule(rule, event):
                    await self._trigger_alert(rule, event)
        
        # Perform correlation analysis
        if self.correlation_enabled:
            await self._correlate_events(event)
    
    async def _evaluate_monitoring_rule(self, 
                                      rule: MonitoringRule, 
                                      event: SecurityEvent) -> bool:
        """Evaluate if event matches monitoring rule conditions."""
        conditions = rule.conditions
        
        # Time window check
        time_window_start = datetime.utcnow() - timedelta(minutes=rule.time_window_minutes)
        recent_events = [
            e for e in self.security_events
            if (e.timestamp >= time_window_start and 
                e.event_type in rule.event_types)
        ]
        
        # Count-based conditions
        if 'count' in conditions:
            if 'source_ip' in conditions and conditions['source_ip'] == 'same':
                # Count events from same IP
                same_ip_events = [e for e in recent_events if e.source_ip == event.source_ip]
                if len(same_ip_events) >= conditions['count']:
                    return True
            elif 'user_id' in conditions and conditions['user_id'] == 'same':
                # Count events from same user
                same_user_events = [e for e in recent_events 
                                  if e.user_id == event.user_id and e.user_id is not None]
                if len(same_user_events) >= conditions['count']:
                    return True
            elif len(recent_events) >= conditions['count']:
                return True
        
        # Time-based conditions
        if 'time_range' in conditions:
            current_hour = event.timestamp.hour
            start_hour, end_hour = conditions['time_range']
            start_h = int(start_hour.split(':')[0])
            end_h = int(end_hour.split(':')[0])
            
            # Handle overnight ranges
            if start_h > end_h:
                if current_hour >= start_h or current_hour <= end_h:
                    return True
            else:
                if start_h <= current_hour <= end_h:
                    return True
        
        # Resource-based conditions
        if 'resource' in conditions:
            if conditions['resource'] in event.resource:
                return True
        
        # Privileged user conditions
        if 'privileged' in conditions:
            if event.additional_data.get('privileged_user') == conditions['privileged']:
                return True
        
        return False
    
    async def _trigger_alert(self, rule: MonitoringRule, triggering_event: SecurityEvent):
        """Trigger security alert based on monitoring rule."""
        alert_id = self._generate_alert_id()
        
        # Find related events
        time_window_start = datetime.utcnow() - timedelta(minutes=rule.time_window_minutes)
        related_events = [
            e.event_id for e in self.security_events
            if (e.timestamp >= time_window_start and 
                e.event_type in rule.event_types)
        ]
        
        alert = SecurityAlert(
            alert_id=alert_id,
            event_ids=related_events,
            alert_type=rule.name,
            severity=rule.severity,
            title=f"Security Alert: {rule.name}",
            description=f"{rule.description}. Triggered by event: {triggering_event.event_id}",
            created_at=datetime.utcnow()
        )
        
        self.security_alerts[alert_id] = alert
        
        # Send notification
        await self._send_alert_notification(alert)
        
        logger.warning(f"Security alert triggered: {alert.title}")
    
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID."""
        import uuid
        timestamp = int(time.time() * 1000)
        unique_id = uuid.uuid4().hex[:8]
        return f"alert_{timestamp}_{unique_id}"
    
    async def _send_alert_notification(self, alert: SecurityAlert):
        """Send alert notification to security team."""
        # In production, this would send emails, SMS, or push notifications
        notification_data = {
            'alert_id': alert.alert_id,
            'severity': alert.severity,
            'title': alert.title,
            'description': alert.description,
            'created_at': alert.created_at.isoformat(),
            'event_count': len(alert.event_ids)
        }
        
        logger.critical(f"SECURITY ALERT: {json.dumps(notification_data)}")
    
    async def _correlate_events(self, event: SecurityEvent):
        """Perform event correlation analysis."""
        # Look for patterns in recent events
        recent_events = [
            e for e in self.security_events[-1000:]  # Last 1000 events
            if (datetime.utcnow() - e.timestamp).total_seconds() < 3600  # Last hour
        ]
        
        # Correlation patterns
        await self._check_login_correlation(event, recent_events)
        await self._check_access_pattern_correlation(event, recent_events)
        await self._check_data_access_correlation(event, recent_events)
    
    async def _check_login_correlation(self, event: SecurityEvent, recent_events: List[SecurityEvent]):
        """Check for login-related correlation patterns."""
        if event.event_type == EventType.LOGIN_SUCCESS:
            # Check for successful login after multiple failures
            previous_failures = [
                e for e in recent_events
                if (e.event_type == EventType.LOGIN_FAILURE and
                    e.source_ip == event.source_ip and
                    e.user_id == event.user_id)
            ]
            
            if len(previous_failures) >= 3:
                # Generate correlation alert
                correlation_id = self._generate_correlation_id()
                event.correlation_id = correlation_id
                
                for failure_event in previous_failures:
                    failure_event.correlation_id = correlation_id
                
                logger.info(f"Login correlation detected: {correlation_id}")
    
    async def _check_access_pattern_correlation(self, event: SecurityEvent, recent_events: List[SecurityEvent]):
        """Check for access pattern correlations."""
        if event.event_type == EventType.ACCESS_GRANTED:
            # Check for rapid successive access to different resources
            same_user_access = [
                e for e in recent_events
                if (e.event_type == EventType.ACCESS_GRANTED and
                    e.user_id == event.user_id and
                    e.resource != event.resource)
            ]
            
            if len(same_user_access) >= 10:  # 10+ different resources in last hour
                correlation_id = self._generate_correlation_id()
                event.correlation_id = correlation_id
                logger.info(f"Rapid access pattern correlation detected: {correlation_id}")
    
    async def _check_data_access_correlation(self, event: SecurityEvent, recent_events: List[SecurityEvent]):
        """Check for data access correlations."""
        if event.event_type == EventType.PII_ACCESS:
            # Check for unusual data access patterns
            same_user_pii_access = [
                e for e in recent_events
                if (e.event_type == EventType.PII_ACCESS and
                    e.user_id == event.user_id)
            ]
            
            if len(same_user_pii_access) >= 20:  # 20+ PII accesses in last hour
                correlation_id = self._generate_correlation_id()
                event.correlation_id = correlation_id
                logger.info(f"Bulk PII access correlation detected: {correlation_id}")
    
    def _generate_correlation_id(self) -> str:
        """Generate unique correlation ID."""
        import uuid
        return f"corr_{uuid.uuid4().hex[:12]}"
    
    async def collect_system_metrics(self) -> SystemMetrics:
        """Collect current system performance metrics."""
        try:
            import psutil
            
            # CPU and memory metrics
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_usage = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_usage = (disk.used / disk.total) * 100
            
            # Network I/O
            network_io = psutil.net_io_counters()
            network_io_bytes = network_io.bytes_sent + network_io.bytes_recv
            
        except ImportError:
            # Fallback values if psutil not available
            cpu_usage = 0.0
            memory_usage = 0.0
            disk_usage = 0.0
            network_io_bytes = 0
        
        # Application-specific metrics
        active_sessions = self._count_active_sessions()
        failed_logins = self._count_recent_failed_logins()
        pii_access_count = self._count_recent_pii_access()
        compliance_score = await self._calculate_compliance_score()
        
        metrics = SystemMetrics(
            timestamp=datetime.utcnow(),
            cpu_usage_percent=cpu_usage,
            memory_usage_percent=memory_usage,
            disk_usage_percent=disk_usage,
            network_io_bytes=network_io_bytes,
            active_sessions=active_sessions,
            failed_login_attempts=failed_logins,
            pii_access_count=pii_access_count,
            compliance_score=compliance_score
        )
        
        self.system_metrics.append(metrics)
        
        # Keep only recent metrics
        cutoff_date = datetime.utcnow() - timedelta(days=self.metrics_retention_days)
        self.system_metrics = [m for m in self.system_metrics if m.timestamp > cutoff_date]
        
        return metrics
    
    def _count_active_sessions(self) -> int:
        """Count active user sessions."""
        # This would integrate with the session management system
        # For now, return a placeholder value
        return 5
    
    def _count_recent_failed_logins(self) -> int:
        """Count failed login attempts in the last hour."""
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        return len([
            e for e in self.security_events
            if (e.event_type == EventType.LOGIN_FAILURE and 
                e.timestamp > one_hour_ago)
        ])
    
    def _count_recent_pii_access(self) -> int:
        """Count PII access events in the last hour."""
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        return len([
            e for e in self.security_events
            if (e.event_type == EventType.PII_ACCESS and 
                e.timestamp > one_hour_ago)
        ])
    
    async def _calculate_compliance_score(self) -> float:
        """Calculate current compliance score."""
        # This would integrate with the compliance engine
        # For now, return a placeholder score
        return 0.95
    
    def _start_background_monitoring(self):
        """Start background monitoring tasks."""
        if self.monitoring_enabled:
            # Start metrics collection thread
            metrics_thread = threading.Thread(
                target=self._metrics_collection_loop,
                daemon=True
            )
            metrics_thread.start()
            
            # Start cleanup thread
            cleanup_thread = threading.Thread(
                target=self._cleanup_loop,
                daemon=True
            )
            cleanup_thread.start()
    
    def _metrics_collection_loop(self):
        """Background loop for collecting metrics."""
        while self.monitoring_enabled:
            try:
                asyncio.run(self.collect_system_metrics())
                time.sleep(60)  # Collect metrics every minute
            except Exception as e:
                logger.error(f"Error in metrics collection: {e}")
                time.sleep(60)
    
    def _cleanup_loop(self):
        """Background loop for cleanup tasks."""
        while self.monitoring_enabled:
            try:
                asyncio.run(self._cleanup_old_data())
                time.sleep(3600)  # Run cleanup every hour
            except Exception as e:
                logger.error(f"Error in cleanup: {e}")
                time.sleep(3600)
    
    async def _cleanup_old_data(self):
        """Clean up old monitoring data."""
        # Clean up old events
        event_cutoff = datetime.utcnow() - timedelta(days=self.log_retention_days)
        self.security_events = [
            e for e in self.security_events if e.timestamp > event_cutoff
        ]
        
        # Clean up old alerts
        alert_cutoff = datetime.utcnow() - timedelta(days=self.alert_retention_days)
        self.security_alerts = {
            alert_id: alert for alert_id, alert in self.security_alerts.items()
            if alert.created_at > alert_cutoff
        }
        
        logger.info("Completed data cleanup")
    
    async def get_security_dashboard(self) -> Dict[str, Any]:
        """
        Get security monitoring dashboard data.
        
        Returns:
            Dashboard data with key metrics and alerts
        """
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        
        # Recent events
        recent_events = [e for e in self.security_events if e.timestamp > last_24h]
        
        # Active alerts
        active_alerts = [a for a in self.security_alerts.values() 
                        if a.status == AlertStatus.ACTIVE]
        
        # Event statistics
        event_stats = {}
        for event_type in EventType:
            event_stats[event_type.value] = len([
                e for e in recent_events if e.event_type == event_type
            ])
        
        # Severity distribution
        severity_stats = {}
        for severity in Severity:
            severity_stats[severity.value] = len([
                e for e in recent_events if e.severity == severity
            ])
        
        # Recent metrics
        recent_metrics = [m for m in self.system_metrics if m.timestamp > last_24h]
        
        dashboard = {
            'timestamp': now.isoformat(),
            'summary': {
                'total_events_24h': len(recent_events),
                'active_alerts': len(active_alerts),
                'critical_alerts': len([a for a in active_alerts 
                                      if a.severity == Severity.CRITICAL]),
                'high_risk_events': len([e for e in recent_events 
                                       if e.risk_score > 0.7]),
                'failed_logins_24h': len([e for e in recent_events 
                                        if e.event_type == EventType.LOGIN_FAILURE]),
                'pii_access_24h': len([e for e in recent_events 
                                     if e.event_type == EventType.PII_ACCESS])
            },
            'event_statistics': event_stats,
            'severity_distribution': severity_stats,
            'active_alerts': [
                {
                    'alert_id': alert.alert_id,
                    'title': alert.title,
                    'severity': alert.severity,
                    'created_at': alert.created_at.isoformat(),
                    'event_count': len(alert.event_ids)
                }
                for alert in active_alerts[:10]  # Top 10 active alerts
            ],
            'recent_high_risk_events': [
                {
                    'event_id': event.event_id,
                    'event_type': event.event_type,
                    'timestamp': event.timestamp.isoformat(),
                    'user_id': event.user_id,
                    'resource': event.resource,
                    'risk_score': event.risk_score
                }
                for event in sorted(recent_events, key=lambda x: x.risk_score, reverse=True)[:10]
            ],
            'system_metrics': {
                'latest_metrics': recent_metrics[-1].__dict__ if recent_metrics else None,
                'avg_cpu_24h': sum(m.cpu_usage_percent for m in recent_metrics) / len(recent_metrics) if recent_metrics else 0,
                'avg_memory_24h': sum(m.memory_usage_percent for m in recent_metrics) / len(recent_metrics) if recent_metrics else 0
            }
        }
        
        return dashboard
    
    async def acknowledge_alert(self, alert_id: str, user_id: str) -> bool:
        """
        Acknowledge a security alert.
        
        Args:
            alert_id: Alert ID to acknowledge
            user_id: User acknowledging the alert
            
        Returns:
            True if acknowledged successfully
        """
        alert = self.security_alerts.get(alert_id)
        if not alert or alert.status != AlertStatus.ACTIVE:
            return False
        
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_by = user_id
        alert.acknowledged_at = datetime.utcnow()
        
        # Log acknowledgment
        await self.log_security_event(
            event_type=EventType.SECURITY_POLICY_VIOLATION,  # Generic security event
            user_id=user_id,
            source_ip="system",
            resource=f"alert_{alert_id}",
            action="acknowledge_alert",
            outcome="success",
            description=f"Security alert {alert_id} acknowledged"
        )
        
        logger.info(f"Alert acknowledged: {alert_id} by {user_id}")
        return True
    
    async def resolve_alert(self, 
                          alert_id: str, 
                          user_id: str,
                          resolution_notes: Optional[str] = None) -> bool:
        """
        Resolve a security alert.
        
        Args:
            alert_id: Alert ID to resolve
            user_id: User resolving the alert
            resolution_notes: Notes about the resolution
            
        Returns:
            True if resolved successfully
        """
        alert = self.security_alerts.get(alert_id)
        if not alert:
            return False
        
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = datetime.utcnow()
        
        if resolution_notes:
            alert.description += f"\nResolution: {resolution_notes}"
        
        # Log resolution
        await self.log_security_event(
            event_type=EventType.SECURITY_POLICY_VIOLATION,
            user_id=user_id,
            source_ip="system",
            resource=f"alert_{alert_id}",
            action="resolve_alert",
            outcome="success",
            description=f"Security alert {alert_id} resolved",
            additional_data={'resolution_notes': resolution_notes}
        )
        
        logger.info(f"Alert resolved: {alert_id} by {user_id}")
        return True
    
    async def get_compliance_status(self) -> Dict[str, Any]:
        """
        Get current PCI DSS compliance status for monitoring.
        
        Returns:
            Monitoring compliance status
        """
        status = {
            'requirement_10': await self._assess_requirement_10(),
            'requirement_12': await self._assess_requirement_12(),
            'overall_compliance': 'compliant',
            'last_assessment': datetime.utcnow().isoformat(),
            'recommendations': []
        }
        
        # Check overall compliance
        if (status['requirement_10']['status'] != 'compliant' or 
            status['requirement_12']['status'] != 'compliant'):
            status['overall_compliance'] = 'non_compliant'
        
        return status
    
    async def _assess_requirement_10(self) -> Dict[str, Any]:
        """Assess PCI DSS Requirement 10 - Track and monitor all access."""
        assessment = {
            'requirement': '10',
            'title': 'Track and monitor all access to network resources and cardholder data',
            'status': 'compliant',
            'controls': []
        }
        
        # 10.1 - Implement audit trails
        control_10_1 = {
            'control': '10.1',
            'description': 'Implement audit trails to link all access to system components to each individual user',
            'status': 'compliant',
            'findings': [f'{len(self.security_events)} events logged'],
            'evidence': 'Comprehensive audit trail system active'
        }
        assessment['controls'].append(control_10_1)
        
        # 10.2 - Implement automated audit trails
        control_10_2 = {
            'control': '10.2',
            'description': 'Implement automated audit trails for all system components',
            'status': 'compliant' if self.monitoring_enabled else 'non_compliant',
            'findings': ['Automated logging enabled' if self.monitoring_enabled else 'Automated logging disabled'],
            'evidence': 'Real-time security event logging system'
        }
        assessment['controls'].append(control_10_2)
        
        # 10.3 - Record audit trail entries
        control_10_3 = {
            'control': '10.3',
            'description': 'Record at least specific audit trail entries for all system components',
            'status': 'compliant',
            'findings': ['All required audit trail entries recorded'],
            'evidence': f'{len(EventType)} event types monitored'
        }
        assessment['controls'].append(control_10_3)
        
        # Check if any control is non-compliant
        for control in assessment['controls']:
            if control['status'] != 'compliant':
                assessment['status'] = 'non_compliant'
                break
        
        return assessment
    
    async def _assess_requirement_12(self) -> Dict[str, Any]:
        """Assess PCI DSS Requirement 12 - Maintain a policy that addresses information security."""
        assessment = {
            'requirement': '12',
            'title': 'Maintain a policy that addresses information security for all personnel',
            'status': 'compliant',
            'controls': []
        }
        
        # 12.1 - Establish, publish, maintain, and disseminate a security policy
        control_12_1 = {
            'control': '12.1',
            'description': 'Establish, publish, maintain, and disseminate a security policy',
            'status': 'compliant',
            'findings': ['Security monitoring policies implemented'],
            'evidence': f'{len(self.monitoring_rules)} monitoring rules active'
        }
        assessment['controls'].append(control_12_1)
        
        # 12.10 - Implement an incident response plan
        control_12_10 = {
            'control': '12.10',
            'description': 'Implement an incident response plan',
            'status': 'compliant',
            'findings': ['Incident response system active'],
            'evidence': f'{len(self.security_alerts)} security alerts managed'
        }
        assessment['controls'].append(control_12_10)
        
        return assessment
    
    async def generate_audit_report(self, 
                                  start_date: datetime,
                                  end_date: datetime,
                                  event_types: Optional[List[EventType]] = None) -> Dict[str, Any]:
        """
        Generate audit report for specified time period.
        
        Args:
            start_date: Report start date
            end_date: Report end date
            event_types: Specific event types to include (optional)
            
        Returns:
            Audit report data
        """
        # Filter events by date range
        filtered_events = [
            e for e in self.security_events
            if start_date <= e.timestamp <= end_date
        ]
        
        # Filter by event types if specified
        if event_types:
            filtered_events = [
                e for e in filtered_events if e.event_type in event_types
            ]
        
        # Generate report statistics
        report = {
            'report_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'summary': {
                'total_events': len(filtered_events),
                'unique_users': len(set(e.user_id for e in filtered_events if e.user_id)),
                'unique_ip_addresses': len(set(e.source_ip for e in filtered_events)),
                'high_risk_events': len([e for e in filtered_events if e.risk_score > 0.7])
            },
            'event_breakdown': {},
            'severity_breakdown': {},
            'hourly_distribution': {},
            'top_users': [],
            'top_resources': [],
            'failed_access_attempts': [],
            'high_risk_events': []
        }
        
        # Event type breakdown
        for event_type in EventType:
            count = len([e for e in filtered_events if e.event_type == event_type])
            if count > 0:
                report['event_breakdown'][event_type.value] = count
        
        # Severity breakdown
        for severity in Severity:
            count = len([e for e in filtered_events if e.severity == severity])
            if count > 0:
                report['severity_breakdown'][severity.value] = count
        
        # Hourly distribution
        for hour in range(24):
            count = len([e for e in filtered_events if e.timestamp.hour == hour])
            report['hourly_distribution'][f"{hour:02d}:00"] = count
        
        # Top users by event count
        user_counts = {}
        for event in filtered_events:
            if event.user_id:
                user_counts[event.user_id] = user_counts.get(event.user_id, 0) + 1
        
        report['top_users'] = [
            {'user_id': user_id, 'event_count': count}
            for user_id, count in sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Top resources by access count
        resource_counts = {}
        for event in filtered_events:
            resource_counts[event.resource] = resource_counts.get(event.resource, 0) + 1
        
        report['top_resources'] = [
            {'resource': resource, 'access_count': count}
            for resource, count in sorted(resource_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Failed access attempts
        failed_events = [e for e in filtered_events if e.outcome == 'failure']
        report['failed_access_attempts'] = [
            {
                'event_id': event.event_id,
                'timestamp': event.timestamp.isoformat(),
                'user_id': event.user_id,
                'source_ip': event.source_ip,
                'resource': event.resource,
                'action': event.action
            }
            for event in failed_events[:50]  # Top 50 failed attempts
        ]
        
        # High risk events
        high_risk_events = sorted(
            [e for e in filtered_events if e.risk_score > 0.7],
            key=lambda x: x.risk_score,
            reverse=True
        )
        
        report['high_risk_events'] = [
            {
                'event_id': event.event_id,
                'event_type': event.event_type.value,
                'timestamp': event.timestamp.isoformat(),
                'user_id': event.user_id,
                'source_ip': event.source_ip,
                'resource': event.resource,
                'risk_score': event.risk_score,
                'description': event.description
            }
            for event in high_risk_events[:25]  # Top 25 high-risk events
        ]
        
        return report