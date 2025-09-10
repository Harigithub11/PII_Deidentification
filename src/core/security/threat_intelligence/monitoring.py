"""
Advanced Security Monitoring System

Real-time monitoring, event processing, and threat detection for comprehensive
security coverage across all system components.
"""

import asyncio
import logging
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Callable, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import re
import hashlib
import ipaddress
from pathlib import Path
import aiosqlite

from .indicators import ThreatLevel
from .analytics import Anomaly, AnomalyType

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of security events."""
    LOGIN_ATTEMPT = "login_attempt"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    API_REQUEST = "api_request"
    DATA_ACCESS = "data_access"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    PERMISSION_DENIED = "permission_denied"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SYSTEM_ERROR = "system_error"
    CONFIGURATION_CHANGE = "configuration_change"
    NETWORK_CONNECTION = "network_connection"
    MALWARE_DETECTION = "malware_detection"
    POLICY_VIOLATION = "policy_violation"


class MonitoringRule(Enum):
    """Predefined monitoring rules."""
    BRUTE_FORCE_DETECTION = "brute_force_detection"
    SUSPICIOUS_USER_AGENT = "suspicious_user_agent"
    RAPID_REQUESTS = "rapid_requests"
    UNUSUAL_DATA_ACCESS = "unusual_data_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    MALICIOUS_PAYLOAD = "malicious_payload"
    GEOGRAPHIC_ANOMALY = "geographic_anomaly"
    TIME_BASED_ANOMALY = "time_based_anomaly"
    VOLUME_ANOMALY = "volume_anomaly"


@dataclass
class SecurityEvent:
    """Represents a security event."""
    event_id: str
    event_type: EventType
    timestamp: datetime
    source: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    status_code: Optional[int] = None
    response_time: Optional[float] = None
    request_size: Optional[int] = None
    response_size: Optional[int] = None
    severity: ThreatLevel = ThreatLevel.INFO
    details: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'source_ip': self.source_ip,
            'user_agent': self.user_agent,
            'endpoint': self.endpoint,
            'method': self.method,
            'status_code': self.status_code,
            'response_time': self.response_time,
            'request_size': self.request_size,
            'response_size': self.response_size,
            'severity': self.severity.value,
            'details': self.details,
            'tags': list(self.tags)
        }


@dataclass
class MonitoringAlert:
    """Represents a monitoring alert."""
    alert_id: str
    rule_name: str
    alert_type: str
    severity: ThreatLevel
    confidence: float
    description: str
    triggered_events: List[SecurityEvent] = field(default_factory=list)
    first_occurrence: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_occurrence: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    count: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False
    resolved: bool = False


class SecurityEventProcessor:
    """Processes and enriches security events."""
    
    def __init__(self):
        """Initialize the event processor."""
        self.event_handlers: List[Callable[[SecurityEvent], None]] = []
        self.enrichment_rules: Dict[str, Callable[[SecurityEvent], SecurityEvent]] = {}
        self.event_cache = deque(maxlen=10000)  # Cache recent events
        self.ip_geolocation_cache: Dict[str, Dict[str, Any]] = {}
        self._setup_enrichment_rules()
    
    def _setup_enrichment_rules(self):
        """Setup event enrichment rules."""
        self.enrichment_rules.update({
            'ip_analysis': self._enrich_ip_information,
            'user_agent_analysis': self._enrich_user_agent,
            'endpoint_analysis': self._enrich_endpoint_information,
            'timing_analysis': self._enrich_timing_information,
            'request_analysis': self._enrich_request_information
        })
    
    async def initialize(self):
        """Initialize the event processor."""
        logger.info("Security Event Processor initialized")
    
    async def process_event(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """Process and enrich a raw security event."""
        try:
            # Create SecurityEvent from raw event
            event = self._create_security_event(raw_event)
            
            # Apply enrichment rules
            for rule_name, rule_func in self.enrichment_rules.items():
                try:
                    event = rule_func(event)
                except Exception as e:
                    logger.error(f"Error applying enrichment rule {rule_name}: {e}")
            
            # Cache the event
            self.event_cache.append(event)
            
            # Trigger event handlers
            for handler in self.event_handlers:
                try:
                    await handler(event) if asyncio.iscoroutinefunction(handler) else handler(event)
                except Exception as e:
                    logger.error(f"Error in event handler: {e}")
            
            return event
            
        except Exception as e:
            logger.error(f"Error processing security event: {e}")
            # Return a minimal event in case of error
            return SecurityEvent(
                event_id=f"error_{int(time.time())}",
                event_type=EventType.SYSTEM_ERROR,
                timestamp=datetime.now(timezone.utc),
                source="event_processor",
                details={'error': str(e), 'raw_event': raw_event}
            )
    
    def _create_security_event(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """Create SecurityEvent from raw event data."""
        # Generate event ID if not present
        event_id = raw_event.get('event_id') or f"evt_{int(time.time() * 1000)}"
        
        # Determine event type
        event_type = self._determine_event_type(raw_event)
        
        # Parse timestamp
        timestamp = self._parse_timestamp(raw_event.get('timestamp'))
        
        return SecurityEvent(
            event_id=event_id,
            event_type=event_type,
            timestamp=timestamp,
            source=raw_event.get('source', 'unknown'),
            user_id=raw_event.get('user_id') or raw_event.get('username'),
            session_id=raw_event.get('session_id'),
            source_ip=raw_event.get('source_ip') or raw_event.get('client_ip'),
            user_agent=raw_event.get('user_agent'),
            endpoint=raw_event.get('endpoint') or raw_event.get('path'),
            method=raw_event.get('method'),
            status_code=raw_event.get('status_code'),
            response_time=raw_event.get('response_time'),
            request_size=raw_event.get('request_size'),
            response_size=raw_event.get('response_size'),
            details=raw_event.get('details', {})
        )
    
    def _determine_event_type(self, raw_event: Dict[str, Any]) -> EventType:
        """Determine event type from raw event data."""
        # Check explicit event type
        if 'event_type' in raw_event:
            try:
                return EventType(raw_event['event_type'])
            except ValueError:
                pass
        
        # Infer from endpoint and method
        endpoint = raw_event.get('endpoint', '').lower()
        method = raw_event.get('method', '').upper()
        status_code = raw_event.get('status_code', 200)
        
        if '/login' in endpoint or '/auth/token' in endpoint:
            return EventType.LOGIN_SUCCESS if status_code == 200 else EventType.LOGIN_FAILURE
        elif '/logout' in endpoint:
            return EventType.LOGOUT
        elif '/upload' in endpoint and method == 'POST':
            return EventType.FILE_UPLOAD
        elif '/download' in endpoint or method == 'GET':
            return EventType.FILE_DOWNLOAD
        elif status_code == 403:
            return EventType.PERMISSION_DENIED
        elif status_code >= 500:
            return EventType.SYSTEM_ERROR
        elif method in ['GET', 'POST', 'PUT', 'DELETE']:
            return EventType.API_REQUEST
        else:
            return EventType.API_REQUEST
    
    def _parse_timestamp(self, timestamp_str: Any) -> datetime:
        """Parse timestamp from various formats."""
        if isinstance(timestamp_str, datetime):
            return timestamp_str
        
        if isinstance(timestamp_str, (int, float)):
            return datetime.fromtimestamp(timestamp_str, tz=timezone.utc)
        
        if isinstance(timestamp_str, str):
            try:
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except ValueError:
                pass
        
        return datetime.now(timezone.utc)
    
    def _enrich_ip_information(self, event: SecurityEvent) -> SecurityEvent:
        """Enrich event with IP address information."""
        if not event.source_ip:
            return event
        
        try:
            ip = ipaddress.ip_address(event.source_ip)
            
            # Add IP type information
            event.details['ip_type'] = 'private' if ip.is_private else 'public'
            event.details['ip_version'] = ip.version
            
            # Add geolocation information (placeholder - would integrate with real service)
            if event.source_ip not in self.ip_geolocation_cache:
                # Simulate geolocation lookup
                self.ip_geolocation_cache[event.source_ip] = {
                    'country': 'Unknown',
                    'city': 'Unknown',
                    'organization': 'Unknown'
                }
            
            event.details['geolocation'] = self.ip_geolocation_cache[event.source_ip]
            
            # Check for suspicious IPs (example patterns)
            suspicious_patterns = ['tor-exit', 'proxy', 'vpn']
            if any(pattern in str(event.source_ip).lower() for pattern in suspicious_patterns):
                event.tags.add('suspicious_ip')
                event.severity = max(event.severity, ThreatLevel.MEDIUM)
            
        except ValueError:
            event.details['ip_analysis_error'] = 'Invalid IP address'
        
        return event
    
    def _enrich_user_agent(self, event: SecurityEvent) -> SecurityEvent:
        """Enrich event with user agent analysis."""
        if not event.user_agent:
            return event
        
        user_agent = event.user_agent.lower()
        
        # Detect suspicious user agents
        suspicious_agents = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'dirb', 'dirbuster',
            'burpsuite', 'w3af', 'owasp-zap', 'gobuster', 'ffuf'
        ]
        
        for suspicious_agent in suspicious_agents:
            if suspicious_agent in user_agent:
                event.tags.add('malicious_user_agent')
                event.severity = ThreatLevel.HIGH
                event.details['detected_tool'] = suspicious_agent
                break
        
        # Detect common browsers vs automated tools
        browsers = ['mozilla', 'chrome', 'firefox', 'safari', 'edge']
        if not any(browser in user_agent for browser in browsers):
            event.tags.add('non_browser_user_agent')
        
        return event
    
    def _enrich_endpoint_information(self, event: SecurityEvent) -> SecurityEvent:
        """Enrich event with endpoint analysis."""
        if not event.endpoint:
            return event
        
        endpoint = event.endpoint.lower()
        
        # Detect sensitive endpoints
        sensitive_endpoints = [
            '/admin', '/api/admin', '/auth', '/login', '/upload',
            '/download', '/documents', '/pii', '/sensitive'
        ]
        
        for sensitive_endpoint in sensitive_endpoints:
            if sensitive_endpoint in endpoint:
                event.tags.add('sensitive_endpoint')
                event.details['endpoint_type'] = 'sensitive'
                break
        
        # Detect potential attack patterns in URLs
        attack_patterns = [
            r'\.\./', r'\.\.\x5c', r'\/etc\/passwd', r'\/proc\/',
            r'<script', r'javascript:', r'union\s+select', r'drop\s+table',
            r'exec\s*\(', r'eval\s*\('
        ]
        
        for pattern in attack_patterns:
            if re.search(pattern, endpoint, re.IGNORECASE):
                event.tags.add('malicious_payload')
                event.severity = ThreatLevel.HIGH
                event.details['attack_pattern'] = pattern
                break
        
        return event
    
    def _enrich_timing_information(self, event: SecurityEvent) -> SecurityEvent:
        """Enrich event with timing analysis."""
        # Add time-based tags
        hour = event.timestamp.hour
        
        if hour < 6 or hour > 22:  # Outside business hours
            event.tags.add('off_hours')
        
        if event.timestamp.weekday() >= 5:  # Weekend
            event.tags.add('weekend')
        
        # Flag unusual response times
        if event.response_time:
            if event.response_time > 5000:  # > 5 seconds
                event.tags.add('slow_response')
            elif event.response_time < 10:  # < 10ms (potentially cached or error)
                event.tags.add('fast_response')
        
        return event
    
    def _enrich_request_information(self, event: SecurityEvent) -> SecurityEvent:
        """Enrich event with request analysis."""
        # Analyze request/response sizes
        if event.request_size:
            if event.request_size > 10 * 1024 * 1024:  # > 10MB
                event.tags.add('large_request')
            elif event.request_size == 0:
                event.tags.add('empty_request')
        
        if event.response_size:
            if event.response_size > 100 * 1024 * 1024:  # > 100MB
                event.tags.add('large_response')
                event.tags.add('potential_data_exfiltration')
                event.severity = max(event.severity, ThreatLevel.MEDIUM)
        
        # Analyze status codes
        if event.status_code:
            if event.status_code >= 500:
                event.tags.add('server_error')
                event.severity = max(event.severity, ThreatLevel.LOW)
            elif event.status_code == 404:
                event.tags.add('not_found')
            elif event.status_code == 403:
                event.tags.add('forbidden')
                event.severity = max(event.severity, ThreatLevel.LOW)
            elif event.status_code == 401:
                event.tags.add('unauthorized')
        
        return event
    
    def register_handler(self, handler: Callable[[SecurityEvent], None]):
        """Register an event handler."""
        self.event_handlers.append(handler)
    
    async def get_recent_events(self, limit: int = 100, event_type: Optional[EventType] = None) -> List[SecurityEvent]:
        """Get recent security events."""
        events = list(self.event_cache)
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        return events[-limit:] if limit else events
    
    async def shutdown(self):
        """Shutdown the event processor."""
        logger.info("Security Event Processor shutdown")


class AdvancedSecurityMonitor:
    """Advanced security monitoring with rule-based detection."""
    
    def __init__(self, db_path: str = "security_monitoring.db"):
        """Initialize the security monitor."""
        self.db_path = db_path
        self.event_processor = SecurityEventProcessor()
        self.monitoring_rules: Dict[str, Callable] = {}
        self.active_alerts: Dict[str, MonitoringAlert] = {}
        self.event_counters: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.time_windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._setup_monitoring_rules()
    
    def _setup_monitoring_rules(self):
        """Setup monitoring rules."""
        self.monitoring_rules.update({
            'brute_force_detection': self._detect_brute_force,
            'rapid_requests': self._detect_rapid_requests,
            'suspicious_user_agents': self._detect_suspicious_user_agents,
            'data_exfiltration': self._detect_data_exfiltration,
            'privilege_escalation': self._detect_privilege_escalation,
            'malicious_payloads': self._detect_malicious_payloads,
            'geographic_anomalies': self._detect_geographic_anomalies,
            'volume_anomalies': self._detect_volume_anomalies
        })
    
    async def initialize(self):
        """Initialize the security monitor."""
        try:
            await self._create_database()
            await self.event_processor.initialize()
            
            # Register event handler
            self.event_processor.register_handler(self._process_monitoring_event)
            
            # Start background tasks
            asyncio.create_task(self._alert_cleanup_task())
            asyncio.create_task(self._metrics_update_task())
            
            logger.info("Advanced Security Monitor initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize Advanced Security Monitor: {e}")
            raise
    
    async def _create_database(self):
        """Create monitoring database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS monitoring_alerts (
                    alert_id TEXT PRIMARY KEY,
                    rule_name TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    description TEXT NOT NULL,
                    first_occurrence TEXT NOT NULL,
                    last_occurrence TEXT NOT NULL,
                    count INTEGER DEFAULT 1,
                    metadata TEXT,
                    acknowledged INTEGER DEFAULT 0,
                    resolved INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS security_events_log (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    user_id TEXT,
                    source_ip TEXT,
                    severity TEXT NOT NULL,
                    details TEXT,
                    tags TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_alert_severity ON monitoring_alerts(severity)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_alert_rule ON monitoring_alerts(rule_name)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON security_events_log(event_type)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_event_timestamp ON security_events_log(timestamp)")
            
            await db.commit()
    
    async def _process_monitoring_event(self, event: SecurityEvent):
        """Process event through monitoring rules."""
        try:
            # Apply all monitoring rules
            for rule_name, rule_func in self.monitoring_rules.items():
                try:
                    alerts = rule_func(event)
                    if alerts:
                        for alert in alerts:
                            await self._handle_alert(alert)
                except Exception as e:
                    logger.error(f"Error applying monitoring rule {rule_name}: {e}")
            
            # Log security event
            await self._log_security_event(event)
            
        except Exception as e:
            logger.error(f"Error processing monitoring event: {e}")
    
    def _detect_brute_force(self, event: SecurityEvent) -> List[MonitoringAlert]:
        """Detect brute force attacks."""
        alerts = []
        
        if event.event_type == EventType.LOGIN_FAILURE and event.source_ip:
            # Count failed login attempts from same IP
            key = f"failed_login_{event.source_ip}"
            self.time_windows[key].append(event.timestamp)
            
            # Count failures in last 5 minutes
            cutoff_time = event.timestamp - timedelta(minutes=5)
            recent_failures = sum(1 for ts in self.time_windows[key] if ts > cutoff_time)
            
            if recent_failures >= 5:
                alert_id = f"brute_force_{event.source_ip}_{int(time.time())}"
                
                alert = MonitoringAlert(
                    alert_id=alert_id,
                    rule_name="brute_force_detection",
                    alert_type="brute_force_attack",
                    severity=ThreatLevel.HIGH,
                    confidence=min(0.9, recent_failures / 10),
                    description=f"Brute force attack detected from IP {event.source_ip}",
                    triggered_events=[event],
                    metadata={
                        'source_ip': event.source_ip,
                        'failure_count': recent_failures,
                        'time_window': '5_minutes'
                    }
                )
                
                alerts.append(alert)
        
        return alerts
    
    def _detect_rapid_requests(self, event: SecurityEvent) -> List[MonitoringAlert]:
        """Detect rapid request patterns."""
        alerts = []
        
        if event.source_ip and event.event_type == EventType.API_REQUEST:
            key = f"requests_{event.source_ip}"
            self.time_windows[key].append(event.timestamp)
            
            # Count requests in last 1 minute
            cutoff_time = event.timestamp - timedelta(minutes=1)
            recent_requests = sum(1 for ts in self.time_windows[key] if ts > cutoff_time)
            
            if recent_requests >= 100:  # More than 100 requests per minute
                alert_id = f"rapid_requests_{event.source_ip}_{int(time.time())}"
                
                alert = MonitoringAlert(
                    alert_id=alert_id,
                    rule_name="rapid_requests",
                    alert_type="rate_limit_exceeded",
                    severity=ThreatLevel.MEDIUM,
                    confidence=0.8,
                    description=f"Rapid requests detected from IP {event.source_ip}",
                    triggered_events=[event],
                    metadata={
                        'source_ip': event.source_ip,
                        'request_count': recent_requests,
                        'time_window': '1_minute'
                    }
                )
                
                alerts.append(alert)
        
        return alerts
    
    def _detect_suspicious_user_agents(self, event: SecurityEvent) -> List[MonitoringAlert]:
        """Detect suspicious user agents."""
        alerts = []
        
        if 'malicious_user_agent' in event.tags:
            alert_id = f"suspicious_ua_{hashlib.md5(event.user_agent.encode()).hexdigest()[:8]}"
            
            alert = MonitoringAlert(
                alert_id=alert_id,
                rule_name="suspicious_user_agents",
                alert_type="malicious_user_agent",
                severity=ThreatLevel.HIGH,
                confidence=0.9,
                description=f"Malicious user agent detected: {event.user_agent}",
                triggered_events=[event],
                metadata={
                    'user_agent': event.user_agent,
                    'detected_tool': event.details.get('detected_tool'),
                    'source_ip': event.source_ip
                }
            )
            
            alerts.append(alert)
        
        return alerts
    
    def _detect_data_exfiltration(self, event: SecurityEvent) -> List[MonitoringAlert]:
        """Detect potential data exfiltration."""
        alerts = []
        
        if 'potential_data_exfiltration' in event.tags or 'large_response' in event.tags:
            alert_id = f"data_exfil_{event.user_id or 'unknown'}_{int(time.time())}"
            
            alert = MonitoringAlert(
                alert_id=alert_id,
                rule_name="data_exfiltration",
                alert_type="potential_data_exfiltration",
                severity=ThreatLevel.HIGH,
                confidence=0.7,
                description=f"Potential data exfiltration detected",
                triggered_events=[event],
                metadata={
                    'user_id': event.user_id,
                    'response_size': event.response_size,
                    'endpoint': event.endpoint,
                    'source_ip': event.source_ip
                }
            )
            
            alerts.append(alert)
        
        return alerts
    
    def _detect_privilege_escalation(self, event: SecurityEvent) -> List[MonitoringAlert]:
        """Detect privilege escalation attempts."""
        alerts = []
        
        # Look for admin endpoint access by non-admin users
        if (event.endpoint and '/admin' in event.endpoint.lower() and 
            event.event_type == EventType.PERMISSION_DENIED):
            
            alert_id = f"privesc_{event.user_id or 'anonymous'}_{int(time.time())}"
            
            alert = MonitoringAlert(
                alert_id=alert_id,
                rule_name="privilege_escalation",
                alert_type="privilege_escalation_attempt",
                severity=ThreatLevel.HIGH,
                confidence=0.8,
                description=f"Privilege escalation attempt detected",
                triggered_events=[event],
                metadata={
                    'user_id': event.user_id,
                    'endpoint': event.endpoint,
                    'source_ip': event.source_ip
                }
            )
            
            alerts.append(alert)
        
        return alerts
    
    def _detect_malicious_payloads(self, event: SecurityEvent) -> List[MonitoringAlert]:
        """Detect malicious payloads."""
        alerts = []
        
        if 'malicious_payload' in event.tags:
            alert_id = f"malicious_payload_{int(time.time())}"
            
            alert = MonitoringAlert(
                alert_id=alert_id,
                rule_name="malicious_payloads",
                alert_type="malicious_payload_detected",
                severity=ThreatLevel.HIGH,
                confidence=0.9,
                description=f"Malicious payload detected in request",
                triggered_events=[event],
                metadata={
                    'attack_pattern': event.details.get('attack_pattern'),
                    'endpoint': event.endpoint,
                    'source_ip': event.source_ip,
                    'user_id': event.user_id
                }
            )
            
            alerts.append(alert)
        
        return alerts
    
    def _detect_geographic_anomalies(self, event: SecurityEvent) -> List[MonitoringAlert]:
        """Detect geographic anomalies."""
        alerts = []
        
        # This would integrate with real geolocation services
        # For now, it's a placeholder for the detection logic
        
        return alerts
    
    def _detect_volume_anomalies(self, event: SecurityEvent) -> List[MonitoringAlert]:
        """Detect volume-based anomalies."""
        alerts = []
        
        # Count total events per hour
        hour_key = event.timestamp.strftime('%Y-%m-%d-%H')
        self.event_counters['hourly'][hour_key] += 1
        
        current_hour_count = self.event_counters['hourly'][hour_key]
        
        # Simple threshold-based detection (would be more sophisticated in practice)
        if current_hour_count > 10000:  # More than 10k events per hour
            alert_id = f"volume_anomaly_{hour_key}"
            
            if alert_id not in self.active_alerts:
                alert = MonitoringAlert(
                    alert_id=alert_id,
                    rule_name="volume_anomalies",
                    alert_type="high_volume_detected",
                    severity=ThreatLevel.MEDIUM,
                    confidence=0.7,
                    description=f"High event volume detected: {current_hour_count} events in hour {hour_key}",
                    triggered_events=[event],
                    metadata={
                        'hour': hour_key,
                        'event_count': current_hour_count,
                        'threshold': 10000
                    }
                )
                
                alerts.append(alert)
        
        return alerts
    
    async def _handle_alert(self, alert: MonitoringAlert):
        """Handle a monitoring alert."""
        try:
            # Check if alert already exists
            if alert.alert_id in self.active_alerts:
                existing_alert = self.active_alerts[alert.alert_id]
                existing_alert.count += 1
                existing_alert.last_occurrence = alert.first_occurrence
                existing_alert.triggered_events.extend(alert.triggered_events)
                
                # Update in database
                await self._update_alert_in_db(existing_alert)
            else:
                # New alert
                self.active_alerts[alert.alert_id] = alert
                
                # Save to database
                await self._save_alert_to_db(alert)
                
                logger.warning(f"Security alert triggered: {alert.alert_type} - {alert.description}")
        
        except Exception as e:
            logger.error(f"Error handling alert: {e}")
    
    async def _save_alert_to_db(self, alert: MonitoringAlert):
        """Save alert to database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO monitoring_alerts (
                    alert_id, rule_name, alert_type, severity, confidence, description,
                    first_occurrence, last_occurrence, count, metadata, acknowledged, resolved
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id,
                alert.rule_name,
                alert.alert_type,
                alert.severity.value,
                alert.confidence,
                alert.description,
                alert.first_occurrence.isoformat(),
                alert.last_occurrence.isoformat(),
                alert.count,
                json.dumps(alert.metadata),
                alert.acknowledged,
                alert.resolved
            ))
            await db.commit()
    
    async def _update_alert_in_db(self, alert: MonitoringAlert):
        """Update alert in database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE monitoring_alerts SET
                    last_occurrence = ?, count = ?, metadata = ?, acknowledged = ?, resolved = ?
                WHERE alert_id = ?
            """, (
                alert.last_occurrence.isoformat(),
                alert.count,
                json.dumps(alert.metadata),
                alert.acknowledged,
                alert.resolved,
                alert.alert_id
            ))
            await db.commit()
    
    async def _log_security_event(self, event: SecurityEvent):
        """Log security event to database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO security_events_log (
                        event_id, event_type, timestamp, source, user_id, source_ip,
                        severity, details, tags
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id,
                    event.event_type.value,
                    event.timestamp.isoformat(),
                    event.source,
                    event.user_id,
                    event.source_ip,
                    event.severity.value,
                    json.dumps(event.details),
                    json.dumps(list(event.tags))
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Error logging security event: {e}")
    
    async def _alert_cleanup_task(self):
        """Background task to clean up old alerts."""
        while True:
            try:
                cutoff_time = datetime.now(timezone.utc) - timedelta(days=7)
                
                # Remove old resolved alerts
                alerts_to_remove = []
                for alert_id, alert in self.active_alerts.items():
                    if alert.resolved and alert.last_occurrence < cutoff_time:
                        alerts_to_remove.append(alert_id)
                
                for alert_id in alerts_to_remove:
                    del self.active_alerts[alert_id]
                
                if alerts_to_remove:
                    logger.info(f"Cleaned up {len(alerts_to_remove)} old alerts")
                
                await asyncio.sleep(3600)  # Run every hour
                
            except Exception as e:
                logger.error(f"Error in alert cleanup task: {e}")
                await asyncio.sleep(3600)
    
    async def _metrics_update_task(self):
        """Background task to update monitoring metrics."""
        while True:
            try:
                # Clear old hourly counters
                current_hour = datetime.now(timezone.utc).strftime('%Y-%m-%d-%H')
                hours_to_keep = [
                    (datetime.now(timezone.utc) - timedelta(hours=i)).strftime('%Y-%m-%d-%H')
                    for i in range(24)  # Keep last 24 hours
                ]
                
                # Clean up old counters
                for hour_key in list(self.event_counters['hourly'].keys()):
                    if hour_key not in hours_to_keep:
                        del self.event_counters['hourly'][hour_key]
                
                await asyncio.sleep(3600)  # Run every hour
                
            except Exception as e:
                logger.error(f"Error in metrics update task: {e}")
                await asyncio.sleep(3600)
    
    async def get_monitoring_summary(self) -> Dict[str, Any]:
        """Get monitoring system summary."""
        try:
            total_alerts = len(self.active_alerts)
            unresolved_alerts = sum(1 for alert in self.active_alerts.values() if not alert.resolved)
            
            # Count by severity
            severity_counts = {}
            for severity in ThreatLevel:
                severity_counts[severity.value] = sum(
                    1 for alert in self.active_alerts.values() 
                    if alert.severity == severity and not alert.resolved
                )
            
            # Recent activity
            recent_events = await self.event_processor.get_recent_events(limit=100)
            recent_event_types = {}
            for event_type in EventType:
                recent_event_types[event_type.value] = sum(
                    1 for event in recent_events if event.event_type == event_type
                )
            
            return {
                'total_alerts': total_alerts,
                'unresolved_alerts': unresolved_alerts,
                'alert_severity_distribution': severity_counts,
                'recent_events_count': len(recent_events),
                'recent_event_types': recent_event_types,
                'monitoring_rules_active': len(self.monitoring_rules),
                'active_monitoring': True
            }
            
        except Exception as e:
            logger.error(f"Error getting monitoring summary: {e}")
            return {}
    
    async def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id].acknowledged = True
            await self._update_alert_in_db(self.active_alerts[alert_id])
            return True
        return False
    
    async def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert."""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id].resolved = True
            await self._update_alert_in_db(self.active_alerts[alert_id])
            return True
        return False
    
    async def process_event(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """Process a raw security event."""
        return await self.event_processor.process_event(raw_event)
    
    async def shutdown(self):
        """Shutdown the security monitor."""
        await self.event_processor.shutdown()
        logger.info("Advanced Security Monitor shutdown complete")