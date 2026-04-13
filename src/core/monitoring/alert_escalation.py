"""
Alert Escalation and Notification System

Multi-channel notification routing system with escalation policies,
on-call rotation management, and automated notification delivery.
This completes the notification and escalation components of Phase 8.2.
"""

import asyncio
import logging
import smtplib
import json
import aiohttp
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import aiosqlite
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import hashlib
import uuid

from .alert_dashboard import AlertStatus, AlertSeverity, AlertDashboardManager

logger = logging.getLogger(__name__)


class NotificationChannel(Enum):
    """Available notification channels."""
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SMS = "sms"
    DISCORD = "discord"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"


class EscalationTrigger(Enum):
    """Escalation trigger conditions."""
    TIME_BASED = "time_based"
    SEVERITY_INCREASE = "severity_increase"
    MANUAL = "manual"
    ACKNOWLEDGMENT_TIMEOUT = "acknowledgment_timeout"
    RESOLUTION_TIMEOUT = "resolution_timeout"


@dataclass
class NotificationTemplate:
    """Template for notification messages."""
    name: str
    channel: NotificationChannel
    subject_template: str
    body_template: str
    format: str = "text"  # text, html, json
    variables: List[str] = field(default_factory=list)


@dataclass
class NotificationTarget:
    """Target for notifications."""
    id: str
    name: str
    channel: NotificationChannel
    address: str  # email, webhook URL, phone number, etc.
    is_active: bool = True
    quiet_hours: Optional[Dict[str, Any]] = None
    preferences: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EscalationLevel:
    """Single level in escalation policy."""
    level: int
    targets: List[NotificationTarget]
    delay_minutes: int
    repeat_interval_minutes: Optional[int] = None
    max_repeats: int = 3
    conditions: List[str] = field(default_factory=list)


@dataclass
class EscalationPolicy:
    """Complete escalation policy definition."""
    id: str
    name: str
    description: str
    levels: List[EscalationLevel]
    is_active: bool = True
    applies_to: Dict[str, Any] = field(default_factory=dict)  # severity, metric patterns, etc.
    created_by: str = ""
    created_at: Optional[datetime] = None


@dataclass
class NotificationDelivery:
    """Record of notification delivery attempt."""
    id: str
    alert_id: str
    escalation_policy_id: str
    level: int
    target_id: str
    channel: NotificationChannel
    status: str  # sent, failed, delivered, acknowledged
    sent_at: datetime
    delivered_at: Optional[datetime] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    response_data: Optional[Dict[str, Any]] = None


class NotificationChannelHandler:
    """Base class for notification channel handlers."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('enabled', True)
    
    async def send_notification(self, target: NotificationTarget, template: NotificationTemplate,
                              context: Dict[str, Any]) -> Dict[str, Any]:
        """Send notification through this channel."""
        raise NotImplementedError
    
    def format_message(self, template: NotificationTemplate, context: Dict[str, Any]) -> Dict[str, str]:
        """Format message using template and context."""
        try:
            subject = template.subject_template.format(**context)
            body = template.body_template.format(**context)
            return {'subject': subject, 'body': body}
        except Exception as e:
            logger.error(f"Error formatting message: {e}")
            return {'subject': 'Alert Notification', 'body': str(context)}


class EmailHandler(NotificationChannelHandler):
    """Email notification handler."""
    
    async def send_notification(self, target: NotificationTarget, template: NotificationTemplate,
                              context: Dict[str, Any]) -> Dict[str, Any]:
        """Send email notification."""
        try:
            message_data = self.format_message(template, context)
            
            msg = MIMEMultipart()
            msg['From'] = self.config.get('from_address', 'alerts@system.local')
            msg['To'] = target.address
            msg['Subject'] = message_data['subject']
            
            if template.format == 'html':
                msg.attach(MIMEText(message_data['body'], 'html'))
            else:
                msg.attach(MIMEText(message_data['body'], 'plain'))
            
            # Send via SMTP
            smtp_config = self.config.get('smtp', {})
            with smtplib.SMTP(smtp_config.get('host', 'localhost'), smtp_config.get('port', 587)) as server:
                if smtp_config.get('use_tls', True):
                    server.starttls()
                
                if smtp_config.get('username'):
                    server.login(smtp_config['username'], smtp_config['password'])
                
                server.send_message(msg)
            
            return {'status': 'sent', 'message': 'Email sent successfully'}
            
        except Exception as e:
            logger.error(f"Email sending failed: {e}")
            return {'status': 'failed', 'error': str(e)}


class SlackHandler(NotificationChannelHandler):
    """Slack notification handler."""
    
    async def send_notification(self, target: NotificationTarget, template: NotificationTemplate,
                              context: Dict[str, Any]) -> Dict[str, Any]:
        """Send Slack notification."""
        try:
            message_data = self.format_message(template, context)
            
            webhook_url = target.address
            payload = {
                'text': message_data['subject'],
                'attachments': [
                    {
                        'color': self._get_color_for_severity(context.get('severity', 'info')),
                        'fields': [
                            {
                                'title': 'Alert Details',
                                'value': message_data['body'],
                                'short': False
                            }
                        ],
                        'ts': context.get('timestamp', datetime.now(timezone.utc).timestamp())
                    }
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        return {'status': 'sent', 'message': 'Slack notification sent'}
                    else:
                        error_text = await response.text()
                        return {'status': 'failed', 'error': f'HTTP {response.status}: {error_text}'}
                        
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def _get_color_for_severity(self, severity: str) -> str:
        """Get Slack color for alert severity."""
        colors = {
            'info': '#36a64f',      # Green
            'warning': '#ffaa00',   # Orange
            'critical': '#ff0000',  # Red
            'emergency': '#8b0000'  # Dark Red
        }
        return colors.get(severity.lower(), '#808080')


class WebhookHandler(NotificationChannelHandler):
    """Generic webhook notification handler."""
    
    async def send_notification(self, target: NotificationTarget, template: NotificationTemplate,
                              context: Dict[str, Any]) -> Dict[str, Any]:
        """Send webhook notification."""
        try:
            if template.format == 'json':
                # Send structured JSON payload
                payload = {
                    'alert_id': context.get('alert_id'),
                    'severity': context.get('severity'),
                    'metric_name': context.get('metric_name'),
                    'description': context.get('description'),
                    'timestamp': context.get('timestamp'),
                    'current_value': context.get('current_value'),
                    'metadata': context.get('metadata', {})
                }
            else:
                # Send formatted text
                message_data = self.format_message(template, context)
                payload = {
                    'subject': message_data['subject'],
                    'message': message_data['body'],
                    'timestamp': context.get('timestamp')
                }
            
            async with aiohttp.ClientSession() as session:
                headers = {'Content-Type': 'application/json'}
                
                # Add custom headers if configured
                if 'headers' in self.config:
                    headers.update(self.config['headers'])
                
                async with session.post(target.address, json=payload, headers=headers) as response:
                    response_text = await response.text()
                    
                    if 200 <= response.status < 300:
                        return {
                            'status': 'sent',
                            'message': 'Webhook notification sent',
                            'response': response_text
                        }
                    else:
                        return {
                            'status': 'failed',
                            'error': f'HTTP {response.status}: {response_text}'
                        }
                        
        except Exception as e:
            logger.error(f"Webhook notification failed: {e}")
            return {'status': 'failed', 'error': str(e)}


class PagerDutyHandler(NotificationChannelHandler):
    """PagerDuty integration handler."""
    
    async def send_notification(self, target: NotificationTarget, template: NotificationTemplate,
                              context: Dict[str, Any]) -> Dict[str, Any]:
        """Send PagerDuty event."""
        try:
            # PagerDuty Events API v2
            integration_key = target.address
            
            payload = {
                'routing_key': integration_key,
                'event_action': 'trigger',
                'dedup_key': context.get('alert_id'),
                'payload': {
                    'summary': context.get('description', 'Performance Alert'),
                    'severity': self._map_severity_to_pagerduty(context.get('severity', 'info')),
                    'source': context.get('metric_name', 'monitoring-system'),
                    'component': context.get('component', 'performance-monitor'),
                    'group': context.get('group', 'alerts'),
                    'class': context.get('alert_type', 'performance'),
                    'custom_details': {
                        'metric_name': context.get('metric_name'),
                        'current_value': context.get('current_value'),
                        'threshold_value': context.get('threshold_value'),
                        'first_occurrence': context.get('first_occurrence'),
                        'metadata': context.get('metadata', {})
                    }
                }
            }
            
            async with aiohttp.ClientSession() as session:
                url = 'https://events.pagerduty.com/v2/enqueue'
                headers = {'Content-Type': 'application/json'}
                
                async with session.post(url, json=payload, headers=headers) as response:
                    response_data = await response.json()
                    
                    if response.status == 202:
                        return {
                            'status': 'sent',
                            'message': 'PagerDuty event created',
                            'dedup_key': response_data.get('dedup_key')
                        }
                    else:
                        return {
                            'status': 'failed',
                            'error': f'PagerDuty API error: {response_data}'
                        }
                        
        except Exception as e:
            logger.error(f"PagerDuty notification failed: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def _map_severity_to_pagerduty(self, severity: str) -> str:
        """Map internal severity to PagerDuty severity."""
        mapping = {
            'info': 'info',
            'warning': 'warning',
            'critical': 'error',
            'emergency': 'critical'
        }
        return mapping.get(severity.lower(), 'warning')


class AlertEscalationManager:
    """
    Manages alert escalation policies, notification routing,
    and delivery tracking for the monitoring system.
    """
    
    def __init__(self, db_path: str = "performance_metrics.db"):
        self.db_path = db_path
        self.notification_handlers: Dict[NotificationChannel, NotificationChannelHandler] = {}
        self.active_escalations: Dict[str, asyncio.Task] = {}
        self.templates: Dict[str, NotificationTemplate] = {}
        self.running = False
        
        # Initialize default templates
        self._initialize_default_templates()
    
    async def initialize(self, config: Dict[str, Any]):
        """Initialize the escalation manager."""
        await self._create_escalation_tables()
        await self._initialize_notification_handlers(config)
        logger.info("Alert Escalation Manager initialized")
    
    def _initialize_default_templates(self):
        """Initialize default notification templates."""
        self.templates = {
            'email_alert': NotificationTemplate(
                name='email_alert',
                channel=NotificationChannel.EMAIL,
                subject_template='[{severity}] Alert: {metric_name}',
                body_template='''
Alert Details:
- Metric: {metric_name}
- Severity: {severity}
- Current Value: {current_value}
- Description: {description}
- First Occurrence: {first_occurrence}
- Alert ID: {alert_id}

Please investigate and take appropriate action.
''',
                format='text'
            ),
            
            'slack_alert': NotificationTemplate(
                name='slack_alert',
                channel=NotificationChannel.SLACK,
                subject_template='🚨 Performance Alert: {metric_name}',
                body_template='''
*Severity:* {severity}
*Metric:* {metric_name}
*Current Value:* {current_value}
*Description:* {description}
*Time:* {first_occurrence}
''',
                format='text'
            ),
            
            'webhook_alert': NotificationTemplate(
                name='webhook_alert',
                channel=NotificationChannel.WEBHOOK,
                subject_template='Performance Alert',
                body_template='Alert for {metric_name}: {description}',
                format='json'
            )
        }
    
    async def _create_escalation_tables(self):
        """Create database tables for escalation management."""
        async with aiosqlite.connect(self.db_path) as db:
            # Notification targets
            await db.execute("""
                CREATE TABLE IF NOT EXISTS notification_targets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    address TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    quiet_hours TEXT,
                    preferences TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Escalation policies
            await db.execute("""
                CREATE TABLE IF NOT EXISTS escalation_policies (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    applies_to TEXT,
                    created_by TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    policy_data TEXT NOT NULL
                )
            """)
            
            # Notification deliveries
            await db.execute("""
                CREATE TABLE IF NOT EXISTS notification_deliveries (
                    id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    escalation_policy_id TEXT,
                    level INTEGER,
                    target_id TEXT,
                    channel TEXT NOT NULL,
                    status TEXT NOT NULL,
                    sent_at TEXT NOT NULL,
                    delivered_at TEXT,
                    error_message TEXT,
                    retry_count INTEGER DEFAULT 0,
                    response_data TEXT,
                    FOREIGN KEY (alert_id) REFERENCES performance_alerts(alert_id),
                    FOREIGN KEY (target_id) REFERENCES notification_targets(id),
                    FOREIGN KEY (escalation_policy_id) REFERENCES escalation_policies(id)
                )
            """)
            
            # Active escalations tracking
            await db.execute("""
                CREATE TABLE IF NOT EXISTS active_escalations (
                    id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    current_level INTEGER DEFAULT 0,
                    started_at TEXT NOT NULL,
                    last_notification_at TEXT,
                    status TEXT DEFAULT 'active',
                    FOREIGN KEY (alert_id) REFERENCES performance_alerts(alert_id),
                    FOREIGN KEY (policy_id) REFERENCES escalation_policies(id)
                )
            """)
            
            await db.commit()
    
    async def _initialize_notification_handlers(self, config: Dict[str, Any]):
        """Initialize notification channel handlers."""
        notification_config = config.get('notifications', {})
        
        # Email handler
        if notification_config.get('email', {}).get('enabled', False):
            self.notification_handlers[NotificationChannel.EMAIL] = EmailHandler(
                notification_config['email']
            )
        
        # Slack handler
        if notification_config.get('slack', {}).get('enabled', False):
            self.notification_handlers[NotificationChannel.SLACK] = SlackHandler(
                notification_config['slack']
            )
        
        # Webhook handler
        if notification_config.get('webhook', {}).get('enabled', False):
            self.notification_handlers[NotificationChannel.WEBHOOK] = WebhookHandler(
                notification_config['webhook']
            )
        
        # PagerDuty handler
        if notification_config.get('pagerduty', {}).get('enabled', False):
            self.notification_handlers[NotificationChannel.PAGERDUTY] = PagerDutyHandler(
                notification_config['pagerduty']
            )
        
        logger.info(f"Initialized {len(self.notification_handlers)} notification handlers")
    
    async def create_escalation_policy(self, policy: EscalationPolicy) -> bool:
        """Create a new escalation policy."""
        try:
            policy_data = {
                'levels': [
                    {
                        'level': level.level,
                        'targets': [{'id': t.id, 'name': t.name, 'channel': t.channel.value, 'address': t.address} 
                                   for t in level.targets],
                        'delay_minutes': level.delay_minutes,
                        'repeat_interval_minutes': level.repeat_interval_minutes,
                        'max_repeats': level.max_repeats,
                        'conditions': level.conditions
                    }
                    for level in policy.levels
                ]
            }
            
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO escalation_policies 
                    (id, name, description, is_active, applies_to, created_by, policy_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    policy.id,
                    policy.name,
                    policy.description,
                    policy.is_active,
                    json.dumps(policy.applies_to),
                    policy.created_by,
                    json.dumps(policy_data)
                ))
                
                await db.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error creating escalation policy: {e}")
            return False
    
    async def create_notification_target(self, target: NotificationTarget) -> bool:
        """Create a new notification target."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO notification_targets 
                    (id, name, channel, address, is_active, quiet_hours, preferences)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    target.id,
                    target.name,
                    target.channel.value,
                    target.address,
                    target.is_active,
                    json.dumps(target.quiet_hours) if target.quiet_hours else None,
                    json.dumps(target.preferences)
                ))
                
                await db.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error creating notification target: {e}")
            return False
    
    async def trigger_escalation(self, alert_data: Dict[str, Any]) -> bool:
        """Trigger escalation for an alert."""
        try:
            alert_id = alert_data['alert_id']
            
            # Find applicable escalation policy
            policy = await self._find_applicable_policy(alert_data)
            if not policy:
                logger.warning(f"No applicable escalation policy found for alert {alert_id}")
                return False
            
            # Create active escalation record
            escalation_id = str(uuid.uuid4())
            await self._create_active_escalation(escalation_id, alert_id, policy['id'])
            
            # Start escalation task
            escalation_task = asyncio.create_task(
                self._run_escalation(escalation_id, alert_data, policy)
            )
            self.active_escalations[escalation_id] = escalation_task
            
            logger.info(f"Started escalation {escalation_id} for alert {alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error triggering escalation: {e}")
            return False
    
    async def _find_applicable_policy(self, alert_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Find the most applicable escalation policy for an alert."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT id, name, applies_to, policy_data
                    FROM escalation_policies
                    WHERE is_active = TRUE
                    ORDER BY name
                """)
                
                policies = await cursor.fetchall()
                
                for policy_row in policies:
                    applies_to = json.loads(policy_row[2]) if policy_row[2] else {}
                    
                    # Check if policy applies to this alert
                    if self._policy_matches_alert(applies_to, alert_data):
                        return {
                            'id': policy_row[0],
                            'name': policy_row[1],
                            'applies_to': applies_to,
                            'policy_data': json.loads(policy_row[3])
                        }
                
                # Return default policy if available
                default_cursor = await db.execute("""
                    SELECT id, name, applies_to, policy_data
                    FROM escalation_policies
                    WHERE name = 'default' AND is_active = TRUE
                    LIMIT 1
                """)
                
                default_policy = await default_cursor.fetchone()
                if default_policy:
                    return {
                        'id': default_policy[0],
                        'name': default_policy[1],
                        'applies_to': json.loads(default_policy[2]) if default_policy[2] else {},
                        'policy_data': json.loads(default_policy[3])
                    }
                
                return None
                
        except Exception as e:
            logger.error(f"Error finding applicable policy: {e}")
            return None
    
    def _policy_matches_alert(self, applies_to: Dict[str, Any], alert_data: Dict[str, Any]) -> bool:
        """Check if escalation policy applies to the given alert."""
        if not applies_to:
            return True  # Policy applies to all alerts
        
        # Check severity filter
        if 'severities' in applies_to:
            if alert_data.get('severity') not in applies_to['severities']:
                return False
        
        # Check metric pattern filter
        if 'metric_patterns' in applies_to:
            metric_name = alert_data.get('metric_name', '')
            if not any(pattern in metric_name for pattern in applies_to['metric_patterns']):
                return False
        
        # Check alert type filter
        if 'alert_types' in applies_to:
            if alert_data.get('alert_type') not in applies_to['alert_types']:
                return False
        
        return True
    
    async def _create_active_escalation(self, escalation_id: str, alert_id: str, policy_id: str):
        """Create active escalation record."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO active_escalations 
                (id, alert_id, policy_id, started_at)
                VALUES (?, ?, ?, ?)
            """, (
                escalation_id,
                alert_id,
                policy_id,
                datetime.now(timezone.utc).isoformat()
            ))
            await db.commit()
    
    async def _run_escalation(self, escalation_id: str, alert_data: Dict[str, Any], policy: Dict[str, Any]):
        """Run the escalation process for an alert."""
        try:
            policy_data = policy['policy_data']
            levels = policy_data['levels']
            
            for level_data in levels:
                level = level_data['level']
                delay_minutes = level_data['delay_minutes']
                
                # Wait for delay (skip for first level)
                if level > 1 and delay_minutes > 0:
                    await asyncio.sleep(delay_minutes * 60)
                
                # Check if escalation is still active
                if not await self._is_escalation_active(escalation_id):
                    logger.info(f"Escalation {escalation_id} stopped (alert resolved or acknowledged)")
                    break
                
                # Send notifications for this level
                await self._send_level_notifications(escalation_id, alert_data, level_data)
                
                # Update escalation level
                await self._update_escalation_level(escalation_id, level)
                
                # Handle repeats if configured
                repeat_interval = level_data.get('repeat_interval_minutes')
                max_repeats = level_data.get('max_repeats', 1)
                
                if repeat_interval and max_repeats > 1:
                    for repeat in range(1, max_repeats):
                        await asyncio.sleep(repeat_interval * 60)
                        
                        if not await self._is_escalation_active(escalation_id):
                            break
                        
                        await self._send_level_notifications(escalation_id, alert_data, level_data, repeat)
            
            # Mark escalation as completed
            await self._complete_escalation(escalation_id)
            
        except asyncio.CancelledError:
            logger.info(f"Escalation {escalation_id} was cancelled")
        except Exception as e:
            logger.error(f"Error in escalation {escalation_id}: {e}")
        finally:
            # Clean up
            if escalation_id in self.active_escalations:
                del self.active_escalations[escalation_id]
    
    async def _send_level_notifications(self, escalation_id: str, alert_data: Dict[str, Any], 
                                      level_data: Dict[str, Any], repeat: int = 0):
        """Send notifications for an escalation level."""
        try:
            targets = level_data['targets']
            
            for target_data in targets:
                # Get notification handler
                channel = NotificationChannel(target_data['channel'])
                handler = self.notification_handlers.get(channel)
                
                if not handler:
                    logger.warning(f"No handler available for channel {channel}")
                    continue
                
                # Create target object
                target = NotificationTarget(
                    id=target_data['id'],
                    name=target_data['name'],
                    channel=channel,
                    address=target_data['address']
                )
                
                # Get appropriate template
                template_name = f"{channel.value}_alert"
                template = self.templates.get(template_name)
                
                if not template:
                    logger.warning(f"No template available for channel {channel}")
                    continue
                
                # Prepare notification context
                context = {
                    'alert_id': alert_data['alert_id'],
                    'metric_name': alert_data.get('metric_name', 'Unknown'),
                    'severity': alert_data.get('severity', 'info'),
                    'description': alert_data.get('description', 'No description available'),
                    'current_value': alert_data.get('current_value', 'N/A'),
                    'threshold_value': alert_data.get('threshold_value', 'N/A'),
                    'first_occurrence': alert_data.get('first_occurrence', datetime.now(timezone.utc).isoformat()),
                    'timestamp': datetime.now(timezone.utc).timestamp(),
                    'escalation_level': level_data['level'],
                    'repeat_number': repeat,
                    'metadata': alert_data.get('metadata', {})
                }
                
                # Send notification
                delivery_id = str(uuid.uuid4())
                result = await handler.send_notification(target, template, context)
                
                # Record delivery
                await self._record_notification_delivery(
                    delivery_id, escalation_id, alert_data['alert_id'],
                    level_data['level'], target_data['id'], channel,
                    result
                )
                
        except Exception as e:
            logger.error(f"Error sending level notifications: {e}")
    
    async def _record_notification_delivery(self, delivery_id: str, escalation_id: str, alert_id: str,
                                          level: int, target_id: str, channel: NotificationChannel,
                                          result: Dict[str, Any]):
        """Record notification delivery attempt."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO notification_deliveries 
                    (id, alert_id, escalation_policy_id, level, target_id, channel, 
                     status, sent_at, error_message, response_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    delivery_id,
                    alert_id,
                    escalation_id,
                    level,
                    target_id,
                    channel.value,
                    result.get('status', 'unknown'),
                    datetime.now(timezone.utc).isoformat(),
                    result.get('error'),
                    json.dumps(result.get('response_data', {}))
                ))
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error recording notification delivery: {e}")
    
    async def _is_escalation_active(self, escalation_id: str) -> bool:
        """Check if escalation is still active."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT ae.status, pa.status as alert_status
                    FROM active_escalations ae
                    JOIN performance_alerts pa ON ae.alert_id = pa.alert_id
                    WHERE ae.id = ?
                """, (escalation_id,))
                
                row = await cursor.fetchone()
                if not row:
                    return False
                
                escalation_status, alert_status = row
                return (escalation_status == 'active' and 
                        alert_status in ['open', 'investigating'])
                
        except Exception as e:
            logger.error(f"Error checking escalation status: {e}")
            return False
    
    async def _update_escalation_level(self, escalation_id: str, level: int):
        """Update current escalation level."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    UPDATE active_escalations 
                    SET current_level = ?, last_notification_at = ?
                    WHERE id = ?
                """, (
                    level,
                    datetime.now(timezone.utc).isoformat(),
                    escalation_id
                ))
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error updating escalation level: {e}")
    
    async def _complete_escalation(self, escalation_id: str):
        """Mark escalation as completed."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    UPDATE active_escalations 
                    SET status = 'completed'
                    WHERE id = ?
                """, (escalation_id,))
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error completing escalation: {e}")
    
    async def stop_escalation(self, alert_id: str, reason: str = "manual_stop") -> bool:
        """Stop active escalation for an alert."""
        try:
            # Find active escalation
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT id FROM active_escalations
                    WHERE alert_id = ? AND status = 'active'
                """, (alert_id,))
                
                escalation_row = await cursor.fetchone()
                if not escalation_row:
                    return False
                
                escalation_id = escalation_row[0]
                
                # Cancel escalation task
                if escalation_id in self.active_escalations:
                    self.active_escalations[escalation_id].cancel()
                    del self.active_escalations[escalation_id]
                
                # Update escalation status
                await db.execute("""
                    UPDATE active_escalations 
                    SET status = ?
                    WHERE id = ?
                """, (reason, escalation_id))
                
                await db.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error stopping escalation: {e}")
            return False
    
    async def get_escalation_status(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get escalation status for an alert."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT ae.id, ae.current_level, ae.started_at, ae.last_notification_at,
                           ae.status, ep.name as policy_name
                    FROM active_escalations ae
                    JOIN escalation_policies ep ON ae.policy_id = ep.id
                    WHERE ae.alert_id = ?
                    ORDER BY ae.started_at DESC
                    LIMIT 1
                """, (alert_id,))
                
                row = await cursor.fetchone()
                if not row:
                    return None
                
                return {
                    'escalation_id': row[0],
                    'current_level': row[1],
                    'started_at': row[2],
                    'last_notification_at': row[3],
                    'status': row[4],
                    'policy_name': row[5]
                }
                
        except Exception as e:
            logger.error(f"Error getting escalation status: {e}")
            return None
    
    async def get_notification_history(self, alert_id: str) -> List[Dict[str, Any]]:
        """Get notification delivery history for an alert."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT nd.id, nd.level, nd.channel, nd.status, nd.sent_at,
                           nd.delivered_at, nd.error_message, nt.name as target_name
                    FROM notification_deliveries nd
                    JOIN notification_targets nt ON nd.target_id = nt.id
                    WHERE nd.alert_id = ?
                    ORDER BY nd.sent_at DESC
                """, (alert_id,))
                
                rows = await cursor.fetchall()
                
                return [
                    {
                        'delivery_id': row[0],
                        'level': row[1],
                        'channel': row[2],
                        'status': row[3],
                        'sent_at': row[4],
                        'delivered_at': row[5],
                        'error_message': row[6],
                        'target_name': row[7]
                    }
                    for row in rows
                ]
                
        except Exception as e:
            logger.error(f"Error getting notification history: {e}")
            return []


# Global escalation manager instance
escalation_manager: Optional[AlertEscalationManager] = None


def get_escalation_manager() -> AlertEscalationManager:
    """Get the global escalation manager instance."""
    global escalation_manager
    if escalation_manager is None:
        escalation_manager = AlertEscalationManager()
    return escalation_manager


async def initialize_escalation_manager(config: Dict[str, Any]):
    """Initialize the global escalation manager."""
    manager = get_escalation_manager()
    await manager.initialize(config)
    return manager