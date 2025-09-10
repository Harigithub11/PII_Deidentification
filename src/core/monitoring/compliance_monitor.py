"""
Real-time HIPAA Compliance Monitoring System
Provides continuous monitoring, alerting, and automated response for compliance violations.
"""
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
import asyncio
import threading
import time
import logging
from datetime import datetime, timedelta
import json
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from pathlib import Path
import webhook
import requests

from src.core.reporting.compliance_reporter import (
    ComplianceReporter, ComplianceAlert, AlertSeverity, ComplianceMetric, ComplianceMetricType
)
from src.core.database.db_manager import DatabaseManager


class MonitoringMode(Enum):
    """Monitoring operation modes"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


class NotificationChannel(Enum):
    """Notification delivery channels"""
    EMAIL = "email"
    WEBHOOK = "webhook"
    SMS = "sms"
    SLACK = "slack"
    DASHBOARD = "dashboard"
    LOG = "log"


@dataclass
class MonitoringConfig:
    """Configuration for compliance monitoring"""
    mode: MonitoringMode = MonitoringMode.PRODUCTION
    monitoring_interval: int = 300  # 5 minutes
    alert_cooldown: int = 1800      # 30 minutes
    escalation_threshold: int = 3    # escalate after 3 consecutive alerts
    auto_remediation: bool = False   # Enable automatic remediation
    
    # Notification settings
    notification_channels: List[NotificationChannel] = field(default_factory=lambda: [NotificationChannel.LOG])
    email_config: Optional[Dict[str, str]] = None
    webhook_config: Optional[Dict[str, str]] = None
    slack_config: Optional[Dict[str, str]] = None
    
    # Alert thresholds
    alert_thresholds: Dict[AlertSeverity, Dict[str, Any]] = field(default_factory=lambda: {
        AlertSeverity.LOW: {"notification_delay": 3600},  # 1 hour
        AlertSeverity.MEDIUM: {"notification_delay": 1800},  # 30 minutes
        AlertSeverity.HIGH: {"notification_delay": 300},   # 5 minutes
        AlertSeverity.CRITICAL: {"notification_delay": 0}  # Immediate
    })


@dataclass
class MonitoringRule:
    """Rule for compliance monitoring"""
    id: str
    name: str
    description: str
    metric_type: ComplianceMetricType
    condition: str  # e.g., "< 0.95", "> 30", "== 0"
    alert_severity: AlertSeverity
    enabled: bool = True
    cooldown_minutes: int = 30
    escalation_rules: List[str] = field(default_factory=list)
    remediation_actions: List[str] = field(default_factory=list)
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0


@dataclass
class EscalationRule:
    """Rule for alert escalation"""
    id: str
    trigger_condition: str  # e.g., "consecutive_alerts >= 3"
    escalation_actions: List[str]
    notification_channels: List[NotificationChannel]
    escalation_delay: int = 0  # minutes


class ComplianceMonitor:
    """Real-time HIPAA compliance monitoring system"""
    
    def __init__(self, 
                 compliance_reporter: ComplianceReporter,
                 db_manager: DatabaseManager,
                 config: MonitoringConfig = None):
        self.compliance_reporter = compliance_reporter
        self.db_manager = db_manager
        self.config = config or MonitoringConfig()
        
        self.logger = logging.getLogger(__name__)
        self.is_monitoring = False
        self.monitoring_thread: Optional[threading.Thread] = None
        
        # Monitoring state
        self.monitoring_rules: Dict[str, MonitoringRule] = {}
        self.escalation_rules: Dict[str, EscalationRule] = {}
        self.alert_history: List[ComplianceAlert] = []
        self.notification_queue: List[Dict[str, Any]] = []
        
        # Initialize default monitoring rules
        self._initialize_default_rules()
        
        # Initialize notification handlers
        self._notification_handlers = {
            NotificationChannel.EMAIL: self._send_email_notification,
            NotificationChannel.WEBHOOK: self._send_webhook_notification,
            NotificationChannel.SLACK: self._send_slack_notification,
            NotificationChannel.LOG: self._log_notification,
            NotificationChannel.DASHBOARD: self._update_dashboard_notification
        }
    
    def _initialize_default_rules(self):
        """Initialize default monitoring rules"""
        default_rules = [
            MonitoringRule(
                id="deident_accuracy_low",
                name="De-identification Accuracy Below Threshold",
                description="De-identification accuracy falls below HIPAA requirements",
                metric_type=ComplianceMetricType.DEIDENTIFICATION_ACCURACY,
                condition="< 0.95",
                alert_severity=AlertSeverity.CRITICAL,
                escalation_rules=["accuracy_critical_escalation"],
                remediation_actions=["retrain_models", "audit_recent_processing"]
            ),
            MonitoringRule(
                id="security_score_low",
                name="Security Score Below Acceptable Level",
                description="Security compliance score indicates vulnerability",
                metric_type=ComplianceMetricType.SECURITY_SCORE,
                condition="< 0.80",
                alert_severity=AlertSeverity.HIGH,
                escalation_rules=["security_high_escalation"],
                remediation_actions=["security_assessment", "policy_review"]
            ),
            MonitoringRule(
                id="response_time_high",
                name="Response Time Exceeds Limit",
                description="System response time exceeds performance requirements",
                metric_type=ComplianceMetricType.RESPONSE_TIME,
                condition="> 30.0",
                alert_severity=AlertSeverity.MEDIUM,
                remediation_actions=["performance_analysis", "resource_scaling"]
            ),
            MonitoringRule(
                id="privacy_compliance_low",
                name="Privacy Compliance Rate Low",
                description="Individual rights request compliance rate is insufficient",
                metric_type=ComplianceMetricType.PRIVACY_COMPLIANCE,
                condition="< 0.95",
                alert_severity=AlertSeverity.HIGH,
                escalation_rules=["privacy_high_escalation"]
            ),
            MonitoringRule(
                id="system_availability_low",
                name="System Availability Below SLA",
                description="System availability falls below HIPAA uptime requirements",
                metric_type=ComplianceMetricType.SYSTEM_AVAILABILITY,
                condition="< 0.999",
                alert_severity=AlertSeverity.CRITICAL,
                escalation_rules=["availability_critical_escalation"],
                remediation_actions=["failover_activation", "infrastructure_check"]
            ),
            MonitoringRule(
                id="incident_rate_high",
                name="High Incident Rate Detected",
                description="BAA compliance incident rate exceeds acceptable threshold",
                metric_type=ComplianceMetricType.INCIDENT_RATE,
                condition="> 0.01",
                alert_severity=AlertSeverity.HIGH,
                escalation_rules=["incident_high_escalation"]
            )
        ]
        
        for rule in default_rules:
            self.monitoring_rules[rule.id] = rule
        
        # Default escalation rules
        default_escalations = [
            EscalationRule(
                id="accuracy_critical_escalation",
                trigger_condition="consecutive_alerts >= 2",
                escalation_actions=["notify_compliance_officer", "emergency_meeting"],
                notification_channels=[NotificationChannel.EMAIL, NotificationChannel.SLACK]
            ),
            EscalationRule(
                id="security_high_escalation",
                trigger_condition="consecutive_alerts >= 3",
                escalation_actions=["notify_security_team", "initiate_security_review"],
                notification_channels=[NotificationChannel.EMAIL, NotificationChannel.WEBHOOK]
            ),
            EscalationRule(
                id="privacy_high_escalation",
                trigger_condition="consecutive_alerts >= 2",
                escalation_actions=["notify_privacy_officer", "review_rights_processing"],
                notification_channels=[NotificationChannel.EMAIL]
            ),
            EscalationRule(
                id="availability_critical_escalation",
                trigger_condition="consecutive_alerts >= 1",
                escalation_actions=["activate_incident_response", "notify_operations_team"],
                notification_channels=[NotificationChannel.EMAIL, NotificationChannel.SMS],
                escalation_delay=0
            ),
            EscalationRule(
                id="incident_high_escalation",
                trigger_condition="consecutive_alerts >= 2",
                escalation_actions=["initiate_incident_investigation", "notify_baa_contacts"],
                notification_channels=[NotificationChannel.EMAIL]
            )
        ]
        
        for escalation in default_escalations:
            self.escalation_rules[escalation.id] = escalation
    
    def start_monitoring(self):
        """Start real-time compliance monitoring"""
        if self.is_monitoring:
            self.logger.warning("Monitoring is already running")
            return
        
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        self.logger.info(f"Compliance monitoring started in {self.config.mode.value} mode")
    
    def stop_monitoring(self):
        """Stop compliance monitoring"""
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=10)
        
        self.logger.info("Compliance monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Collect current metrics
                current_time = datetime.now()
                period_start = current_time - timedelta(minutes=self.config.monitoring_interval // 60)
                
                # Get new metrics
                new_metrics = self.compliance_reporter.collect_metrics(period_start, current_time)
                
                # Evaluate monitoring rules
                triggered_alerts = self._evaluate_monitoring_rules(new_metrics)
                
                # Process triggered alerts
                for alert in triggered_alerts:
                    self._process_alert(alert)
                
                # Check for escalations
                self._check_escalations()
                
                # Process notification queue
                self._process_notifications()
                
                # Clean up old alerts
                self._cleanup_old_alerts()
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {str(e)}", exc_info=True)
            
            # Wait for next monitoring cycle
            time.sleep(self.config.monitoring_interval)
    
    def _evaluate_monitoring_rules(self, metrics: List[ComplianceMetric]) -> List[ComplianceAlert]:
        """Evaluate monitoring rules against current metrics"""
        triggered_alerts = []
        current_time = datetime.now()
        
        for rule in self.monitoring_rules.values():
            if not rule.enabled:
                continue
            
            # Check cooldown period
            if (rule.last_triggered and 
                (current_time - rule.last_triggered).total_seconds() < rule.cooldown_minutes * 60):
                continue
            
            # Find relevant metrics
            relevant_metrics = [m for m in metrics if m.metric_type == rule.metric_type]
            
            if not relevant_metrics:
                continue
            
            # Use most recent metric value
            latest_metric = max(relevant_metrics, key=lambda x: x.timestamp)
            
            # Evaluate condition
            if self._evaluate_condition(latest_metric.value, rule.condition):
                alert = self._create_rule_alert(rule, latest_metric)
                triggered_alerts.append(alert)
                
                # Update rule state
                rule.last_triggered = current_time
                rule.trigger_count += 1
        
        return triggered_alerts
    
    def _evaluate_condition(self, value: float, condition: str) -> bool:
        """Evaluate a condition string against a value"""
        try:
            # Parse condition (e.g., "< 0.95", "> 30", "== 0")
            condition = condition.strip()
            
            if condition.startswith('<='):
                threshold = float(condition[2:].strip())
                return value <= threshold
            elif condition.startswith('>='):
                threshold = float(condition[2:].strip())
                return value >= threshold
            elif condition.startswith('<'):
                threshold = float(condition[1:].strip())
                return value < threshold
            elif condition.startswith('>'):
                threshold = float(condition[1:].strip())
                return value > threshold
            elif condition.startswith('=='):
                threshold = float(condition[2:].strip())
                return abs(value - threshold) < 0.001  # Float equality with tolerance
            elif condition.startswith('!='):
                threshold = float(condition[2:].strip())
                return abs(value - threshold) >= 0.001
            else:
                self.logger.error(f"Invalid condition format: {condition}")
                return False
                
        except (ValueError, IndexError) as e:
            self.logger.error(f"Error evaluating condition '{condition}': {str(e)}")
            return False
    
    def _create_rule_alert(self, rule: MonitoringRule, metric: ComplianceMetric) -> ComplianceAlert:
        """Create alert from triggered monitoring rule"""
        alert = ComplianceAlert(
            severity=rule.alert_severity,
            title=rule.name,
            description=f"{rule.description}. Current value: {metric.value:.4f} {metric.unit}",
            metric_type=rule.metric_type,
            trigger_value=metric.value,
            source_system="compliance_monitor",
            affected_components=[metric.source],
            recommended_actions=rule.remediation_actions.copy()
        )
        
        # Add rule-specific metadata
        alert.metadata = {
            'rule_id': rule.id,
            'rule_condition': rule.condition,
            'trigger_count': rule.trigger_count,
            'metric_timestamp': metric.timestamp.isoformat()
        }
        
        return alert
    
    def _process_alert(self, alert: ComplianceAlert):
        """Process a triggered alert"""
        # Add to alert history
        self.alert_history.append(alert)
        
        # Add to compliance reporter's active alerts
        self.compliance_reporter.active_alerts.append(alert)
        
        # Log the alert
        self.logger.warning(f"Compliance alert triggered: {alert.title} (Severity: {alert.severity.value})")
        
        # Queue notifications based on severity
        notification_delay = self.config.alert_thresholds[alert.severity]["notification_delay"]
        
        notification = {
            'alert': alert,
            'channels': self.config.notification_channels.copy(),
            'scheduled_time': datetime.now() + timedelta(seconds=notification_delay),
            'attempts': 0
        }
        
        self.notification_queue.append(notification)
        
        # Trigger automatic remediation if enabled
        if self.config.auto_remediation and alert.recommended_actions:
            self._trigger_auto_remediation(alert)
    
    def _check_escalations(self):
        """Check for alert escalation conditions"""
        current_time = datetime.now()
        
        for escalation_rule in self.escalation_rules.values():
            if self._should_escalate(escalation_rule):
                self._execute_escalation(escalation_rule)
    
    def _should_escalate(self, escalation_rule: EscalationRule) -> bool:
        """Check if escalation conditions are met"""
        # Get recent alerts for escalation analysis
        recent_alerts = [a for a in self.alert_history 
                        if (datetime.now() - a.timestamp).total_seconds() < 3600]  # Last hour
        
        # Check consecutive alerts condition
        if "consecutive_alerts" in escalation_rule.trigger_condition:
            threshold = int(escalation_rule.trigger_condition.split(">=")[1].strip())
            
            # Group alerts by metric type and check for consecutive alerts
            for metric_type in ComplianceMetricType:
                type_alerts = [a for a in recent_alerts if a.metric_type == metric_type]
                if len(type_alerts) >= threshold:
                    return True
        
        return False
    
    def _execute_escalation(self, escalation_rule: EscalationRule):
        """Execute escalation actions"""
        self.logger.critical(f"Escalation triggered: {escalation_rule.id}")
        
        # Create escalation alert
        escalation_alert = ComplianceAlert(
            severity=AlertSeverity.CRITICAL,
            title=f"Compliance Escalation: {escalation_rule.id}",
            description=f"Escalation condition met: {escalation_rule.trigger_condition}",
            source_system="compliance_monitor",
            recommended_actions=escalation_rule.escalation_actions
        )
        
        # Send escalation notifications
        for channel in escalation_rule.notification_channels:
            self._send_notification(escalation_alert, channel, is_escalation=True)
        
        # Execute escalation actions
        for action in escalation_rule.escalation_actions:
            self._execute_escalation_action(action, escalation_alert)
    
    def _execute_escalation_action(self, action: str, alert: ComplianceAlert):
        """Execute specific escalation action"""
        self.logger.info(f"Executing escalation action: {action}")
        
        if action == "notify_compliance_officer":
            self._notify_compliance_officer(alert)
        elif action == "emergency_meeting":
            self._schedule_emergency_meeting(alert)
        elif action == "notify_security_team":
            self._notify_security_team(alert)
        elif action == "initiate_security_review":
            self._initiate_security_review(alert)
        elif action == "notify_privacy_officer":
            self._notify_privacy_officer(alert)
        elif action == "activate_incident_response":
            self._activate_incident_response(alert)
        elif action == "notify_operations_team":
            self._notify_operations_team(alert)
        else:
            self.logger.warning(f"Unknown escalation action: {action}")
    
    def _process_notifications(self):
        """Process pending notifications"""
        current_time = datetime.now()
        processed_notifications = []
        
        for notification in self.notification_queue:
            if current_time >= notification['scheduled_time']:
                # Send notifications through configured channels
                for channel in notification['channels']:
                    try:
                        self._send_notification(notification['alert'], channel)
                        notification['attempts'] += 1
                    except Exception as e:
                        self.logger.error(f"Failed to send notification via {channel.value}: {str(e)}")
                
                processed_notifications.append(notification)
        
        # Remove processed notifications
        for notification in processed_notifications:
            self.notification_queue.remove(notification)
    
    def _send_notification(self, alert: ComplianceAlert, channel: NotificationChannel, is_escalation: bool = False):
        """Send notification through specified channel"""
        handler = self._notification_handlers.get(channel)
        if handler:
            handler(alert, is_escalation)
        else:
            self.logger.error(f"No handler for notification channel: {channel.value}")
    
    def _send_email_notification(self, alert: ComplianceAlert, is_escalation: bool = False):
        """Send email notification"""
        if not self.config.email_config:
            self.logger.warning("Email configuration not provided")
            return
        
        try:
            msg = MimeMultipart()
            msg['From'] = self.config.email_config['from']
            msg['To'] = self.config.email_config['to']
            msg['Subject'] = f"{'ESCALATION: ' if is_escalation else ''}HIPAA Compliance Alert: {alert.title}"
            
            body = f"""
HIPAA Compliance Alert

{'*** ESCALATION ***' if is_escalation else ''}

Alert: {alert.title}
Severity: {alert.severity.value.upper()}
Description: {alert.description}
Timestamp: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Source: {alert.source_system}

Recommended Actions:
{chr(10).join(f"- {action}" for action in alert.recommended_actions)}

Alert ID: {alert.id}
            """
            
            msg.attach(MimeText(body, 'plain'))
            
            server = smtplib.SMTP(self.config.email_config['smtp_server'], 
                                 self.config.email_config.get('smtp_port', 587))
            server.starttls()
            server.login(self.config.email_config['username'], 
                        self.config.email_config['password'])
            
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email notification sent for alert: {alert.id}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email notification: {str(e)}")
    
    def _send_webhook_notification(self, alert: ComplianceAlert, is_escalation: bool = False):
        """Send webhook notification"""
        if not self.config.webhook_config:
            self.logger.warning("Webhook configuration not provided")
            return
        
        try:
            payload = {
                'alert_id': alert.id,
                'title': alert.title,
                'severity': alert.severity.value,
                'description': alert.description,
                'timestamp': alert.timestamp.isoformat(),
                'is_escalation': is_escalation,
                'source': alert.source_system,
                'recommended_actions': alert.recommended_actions
            }
            
            response = requests.post(
                self.config.webhook_config['url'],
                json=payload,
                headers=self.config.webhook_config.get('headers', {}),
                timeout=30
            )
            
            response.raise_for_status()
            self.logger.info(f"Webhook notification sent for alert: {alert.id}")
            
        except Exception as e:
            self.logger.error(f"Failed to send webhook notification: {str(e)}")
    
    def _send_slack_notification(self, alert: ComplianceAlert, is_escalation: bool = False):
        """Send Slack notification"""
        if not self.config.slack_config:
            self.logger.warning("Slack configuration not provided")
            return
        
        try:
            color_map = {
                AlertSeverity.LOW: "#36a64f",
                AlertSeverity.MEDIUM: "#ff9500",
                AlertSeverity.HIGH: "#ff0000",
                AlertSeverity.CRITICAL: "#8B0000"
            }
            
            payload = {
                "attachments": [{
                    "color": color_map.get(alert.severity, "#808080"),
                    "title": f"{'🚨 ESCALATION: ' if is_escalation else ''}HIPAA Compliance Alert",
                    "fields": [
                        {"title": "Alert", "value": alert.title, "short": True},
                        {"title": "Severity", "value": alert.severity.value.upper(), "short": True},
                        {"title": "Description", "value": alert.description, "short": False},
                        {"title": "Timestamp", "value": alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'), "short": True},
                        {"title": "Source", "value": alert.source_system, "short": True}
                    ],
                    "footer": f"Alert ID: {alert.id}"
                }]
            }
            
            response = requests.post(
                self.config.slack_config['webhook_url'],
                json=payload,
                timeout=30
            )
            
            response.raise_for_status()
            self.logger.info(f"Slack notification sent for alert: {alert.id}")
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack notification: {str(e)}")
    
    def _log_notification(self, alert: ComplianceAlert, is_escalation: bool = False):
        """Log notification to system log"""
        log_level = logging.CRITICAL if is_escalation else {
            AlertSeverity.LOW: logging.INFO,
            AlertSeverity.MEDIUM: logging.WARNING,
            AlertSeverity.HIGH: logging.ERROR,
            AlertSeverity.CRITICAL: logging.CRITICAL
        }.get(alert.severity, logging.INFO)
        
        message = f"{'ESCALATION: ' if is_escalation else ''}HIPAA Alert - {alert.title}: {alert.description}"
        self.logger.log(log_level, message)
    
    def _update_dashboard_notification(self, alert: ComplianceAlert, is_escalation: bool = False):
        """Update dashboard with alert information"""
        # This would update a real-time dashboard
        # Implementation depends on dashboard technology used
        pass
    
    def _trigger_auto_remediation(self, alert: ComplianceAlert):
        """Trigger automatic remediation actions"""
        if not self.config.auto_remediation:
            return
        
        self.logger.info(f"Triggering auto-remediation for alert: {alert.id}")
        
        for action in alert.recommended_actions:
            try:
                self._execute_remediation_action(action, alert)
            except Exception as e:
                self.logger.error(f"Auto-remediation action failed: {action} - {str(e)}")
    
    def _execute_remediation_action(self, action: str, alert: ComplianceAlert):
        """Execute specific remediation action"""
        if action == "retrain_models":
            self._retrain_models()
        elif action == "audit_recent_processing":
            self._audit_recent_processing()
        elif action == "security_assessment":
            self._trigger_security_assessment()
        elif action == "performance_analysis":
            self._trigger_performance_analysis()
        elif action == "resource_scaling":
            self._trigger_resource_scaling()
        elif action == "failover_activation":
            self._activate_failover()
        elif action == "infrastructure_check":
            self._check_infrastructure()
        else:
            self.logger.info(f"Manual remediation required for action: {action}")
    
    def _cleanup_old_alerts(self):
        """Clean up old alerts from memory"""
        cutoff_time = datetime.now() - timedelta(days=7)  # Keep alerts for 7 days
        
        self.alert_history = [a for a in self.alert_history if a.timestamp > cutoff_time]
        self.compliance_reporter.active_alerts = [a for a in self.compliance_reporter.active_alerts 
                                                 if a.timestamp > cutoff_time or not a.resolved]
    
    # Placeholder methods for escalation and remediation actions
    def _notify_compliance_officer(self, alert: ComplianceAlert):
        """Notify compliance officer"""
        self.logger.info(f"Notifying compliance officer about alert: {alert.id}")
    
    def _schedule_emergency_meeting(self, alert: ComplianceAlert):
        """Schedule emergency compliance meeting"""
        self.logger.info(f"Scheduling emergency meeting for alert: {alert.id}")
    
    def _notify_security_team(self, alert: ComplianceAlert):
        """Notify security team"""
        self.logger.info(f"Notifying security team about alert: {alert.id}")
    
    def _initiate_security_review(self, alert: ComplianceAlert):
        """Initiate security review process"""
        self.logger.info(f"Initiating security review for alert: {alert.id}")
    
    def _notify_privacy_officer(self, alert: ComplianceAlert):
        """Notify privacy officer"""
        self.logger.info(f"Notifying privacy officer about alert: {alert.id}")
    
    def _activate_incident_response(self, alert: ComplianceAlert):
        """Activate incident response procedures"""
        self.logger.critical(f"Activating incident response for alert: {alert.id}")
    
    def _notify_operations_team(self, alert: ComplianceAlert):
        """Notify operations team"""
        self.logger.info(f"Notifying operations team about alert: {alert.id}")
    
    def _retrain_models(self):
        """Trigger model retraining"""
        self.logger.info("Triggering model retraining")
    
    def _audit_recent_processing(self):
        """Audit recent document processing"""
        self.logger.info("Starting audit of recent processing")
    
    def _trigger_security_assessment(self):
        """Trigger security assessment"""
        self.logger.info("Triggering security assessment")
    
    def _trigger_performance_analysis(self):
        """Trigger performance analysis"""
        self.logger.info("Triggering performance analysis")
    
    def _trigger_resource_scaling(self):
        """Trigger resource scaling"""
        self.logger.info("Triggering resource scaling")
    
    def _activate_failover(self):
        """Activate system failover"""
        self.logger.critical("Activating system failover")
    
    def _check_infrastructure(self):
        """Check infrastructure health"""
        self.logger.info("Checking infrastructure health")
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        return {
            'is_monitoring': self.is_monitoring,
            'mode': self.config.mode.value,
            'monitoring_interval': self.config.monitoring_interval,
            'active_rules': len([r for r in self.monitoring_rules.values() if r.enabled]),
            'total_rules': len(self.monitoring_rules),
            'recent_alerts': len([a for a in self.alert_history 
                                if (datetime.now() - a.timestamp).total_seconds() < 3600]),
            'pending_notifications': len(self.notification_queue),
            'last_monitoring_cycle': datetime.now().isoformat()
        }
    
    def add_monitoring_rule(self, rule: MonitoringRule):
        """Add custom monitoring rule"""
        self.monitoring_rules[rule.id] = rule
        self.logger.info(f"Added monitoring rule: {rule.id}")
    
    def remove_monitoring_rule(self, rule_id: str):
        """Remove monitoring rule"""
        if rule_id in self.monitoring_rules:
            del self.monitoring_rules[rule_id]
            self.logger.info(f"Removed monitoring rule: {rule_id}")
    
    def update_monitoring_rule(self, rule_id: str, updates: Dict[str, Any]):
        """Update existing monitoring rule"""
        if rule_id in self.monitoring_rules:
            rule = self.monitoring_rules[rule_id]
            for key, value in updates.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
            self.logger.info(f"Updated monitoring rule: {rule_id}")
    
    def enable_rule(self, rule_id: str):
        """Enable monitoring rule"""
        if rule_id in self.monitoring_rules:
            self.monitoring_rules[rule_id].enabled = True
            self.logger.info(f"Enabled monitoring rule: {rule_id}")
    
    def disable_rule(self, rule_id: str):
        """Disable monitoring rule"""
        if rule_id in self.monitoring_rules:
            self.monitoring_rules[rule_id].enabled = False
            self.logger.info(f"Disabled monitoring rule: {rule_id}")