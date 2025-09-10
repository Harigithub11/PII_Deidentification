"""
Alert Management Dashboard

Comprehensive alert management system that provides real-time visualization,
management interfaces, and workflow automation for performance alerts.
This component completes Phase 8.2 by providing the missing dashboard
and alert management capabilities.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import aiosqlite
from collections import defaultdict, Counter
import statistics

from .predictive_alerts import (
    AnomalyDetectionResult, PredictionResult, AlertSeverity,
    AnomalyType, PredictiveAlertEngine
)
from .metrics_collector import MetricPoint, MetricScope

logger = logging.getLogger(__name__)


class AlertStatus(Enum):
    """Alert status states."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"
    SUPPRESSED = "suppressed"


class AlertPriority(Enum):
    """Alert priority levels for workflow management."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    URGENT = 4
    CRITICAL = 5


@dataclass
class AlertFilter:
    """Filter criteria for alert queries."""
    severity: Optional[List[str]] = None
    status: Optional[List[str]] = None
    metric_name: Optional[str] = None
    time_range: Optional[Tuple[datetime, datetime]] = None
    tags: Optional[Dict[str, str]] = None
    limit: int = 100
    offset: int = 0
    sort_by: str = "first_occurrence"
    sort_order: str = "desc"


@dataclass
class AlertSummary:
    """Summary statistics for alerts."""
    total_alerts: int
    open_alerts: int
    acknowledged_alerts: int
    resolved_alerts: int
    critical_alerts: int
    alerts_by_severity: Dict[str, int]
    alerts_by_status: Dict[str, int]
    alerts_by_metric: Dict[str, int]
    average_resolution_time: Optional[float]
    alert_trend: Dict[str, int]  # Last 24 hours by hour


@dataclass
class AlertGroup:
    """Grouped alerts for correlation and noise reduction."""
    group_id: str
    alerts: List[Dict[str, Any]]
    correlation_type: str  # "metric_burst", "cascading_failure", "time_window"
    severity: AlertSeverity
    first_occurrence: datetime
    last_occurrence: datetime
    is_suppressed: bool = False
    suppression_reason: Optional[str] = None


class AlertCorrelationEngine:
    """Engine for correlating related alerts and reducing noise."""
    
    def __init__(self, time_window_minutes: int = 5, correlation_threshold: float = 0.8):
        self.time_window_minutes = time_window_minutes
        self.correlation_threshold = correlation_threshold
        self.correlation_rules = self._initialize_correlation_rules()
    
    def _initialize_correlation_rules(self) -> List[Dict[str, Any]]:
        """Initialize alert correlation rules."""
        return [
            {
                "name": "metric_burst",
                "description": "Multiple alerts on the same metric within time window",
                "condition": lambda alerts: len(set(a['metric_name'] for a in alerts)) == 1,
                "priority": 1
            },
            {
                "name": "cascading_failure",
                "description": "Related metrics failing in sequence",
                "condition": self._is_cascading_failure,
                "priority": 2
            },
            {
                "name": "service_degradation",
                "description": "Multiple metrics for same service degrading",
                "condition": self._is_service_degradation,
                "priority": 3
            },
            {
                "name": "infrastructure_issue",
                "description": "System-level metrics indicating infrastructure problems",
                "condition": self._is_infrastructure_issue,
                "priority": 4
            }
        ]
    
    def _is_cascading_failure(self, alerts: List[Dict[str, Any]]) -> bool:
        """Check if alerts represent a cascading failure."""
        # Look for temporal sequence in related metrics
        if len(alerts) < 2:
            return False
        
        # Group by service or component
        service_alerts = defaultdict(list)
        for alert in alerts:
            service = self._extract_service_from_metric(alert['metric_name'])
            service_alerts[service].append(alert)
        
        # Check if failures occurred in logical sequence
        return len(service_alerts) > 1 and self._check_failure_sequence(service_alerts)
    
    def _is_service_degradation(self, alerts: List[Dict[str, Any]]) -> bool:
        """Check if alerts indicate service degradation."""
        # Multiple different metrics for same service/scope
        metrics = [alert['metric_name'] for alert in alerts]
        scopes = set()
        
        for metric in metrics:
            if 'api_' in metric or 'request_' in metric:
                scopes.add('api')
            elif 'db_' in metric or 'database_' in metric:
                scopes.add('database')
            elif 'memory_' in metric or 'cpu_' in metric:
                scopes.add('system')
        
        return len(scopes) == 1 and len(set(metrics)) > 1
    
    def _is_infrastructure_issue(self, alerts: List[Dict[str, Any]]) -> bool:
        """Check if alerts indicate infrastructure issues."""
        infrastructure_metrics = {
            'cpu_usage_percent', 'memory_usage_percent', 'disk_usage_percent',
            'network_bytes_sent_per_sec', 'network_bytes_recv_per_sec',
            'load_average_1m', 'load_average_5m'
        }
        
        alert_metrics = set(alert['metric_name'] for alert in alerts)
        return len(alert_metrics.intersection(infrastructure_metrics)) >= 2
    
    def _extract_service_from_metric(self, metric_name: str) -> str:
        """Extract service name from metric."""
        if 'api_' in metric_name or 'request_' in metric_name:
            return 'api'
        elif 'db_' in metric_name or 'database_' in metric_name:
            return 'database'
        elif 'pii_' in metric_name or 'redaction_' in metric_name:
            return 'processing'
        else:
            return 'system'
    
    def _check_failure_sequence(self, service_alerts: Dict[str, List]) -> bool:
        """Check if failures follow a logical sequence."""
        # Simplified logic - in real implementation, this would be more sophisticated
        services = list(service_alerts.keys())
        if 'system' in services and len(services) > 1:
            return True  # System failures often cascade to other services
        return False
    
    async def correlate_alerts(self, alerts: List[Dict[str, Any]]) -> List[AlertGroup]:
        """Correlate alerts into groups."""
        if not alerts:
            return []
        
        # Sort alerts by occurrence time
        sorted_alerts = sorted(alerts, key=lambda x: x['first_occurrence'])
        
        groups = []
        processed_alert_ids = set()
        
        for alert in sorted_alerts:
            if alert['alert_id'] in processed_alert_ids:
                continue
            
            # Find alerts within time window
            alert_time = datetime.fromisoformat(alert['first_occurrence'])
            window_start = alert_time - timedelta(minutes=self.time_window_minutes)
            window_end = alert_time + timedelta(minutes=self.time_window_minutes)
            
            window_alerts = [
                a for a in sorted_alerts
                if (window_start <= datetime.fromisoformat(a['first_occurrence']) <= window_end
                    and a['alert_id'] not in processed_alert_ids)
            ]
            
            if len(window_alerts) <= 1:
                continue
            
            # Apply correlation rules
            for rule in sorted(self.correlation_rules, key=lambda r: r['priority']):
                if rule['condition'](window_alerts):
                    group_id = f"{rule['name']}_{int(alert_time.timestamp())}"
                    
                    # Determine group severity (highest of member alerts)
                    severity_levels = {'info': 1, 'warning': 2, 'critical': 3, 'emergency': 4}
                    max_severity = max(window_alerts, key=lambda a: severity_levels.get(a['severity'], 0))
                    
                    group = AlertGroup(
                        group_id=group_id,
                        alerts=window_alerts,
                        correlation_type=rule['name'],
                        severity=AlertSeverity(max_severity['severity']),
                        first_occurrence=min(datetime.fromisoformat(a['first_occurrence']) for a in window_alerts),
                        last_occurrence=max(datetime.fromisoformat(a['first_occurrence']) for a in window_alerts)
                    )
                    
                    groups.append(group)
                    processed_alert_ids.update(a['alert_id'] for a in window_alerts)
                    break
        
        return groups


class AlertDashboardManager:
    """
    Comprehensive alert management system that provides dashboard functionality,
    alert grouping, bulk operations, and workflow management.
    """
    
    def __init__(self, db_path: str = "performance_metrics.db"):
        self.db_path = db_path
        self.correlation_engine = AlertCorrelationEngine()
        self.alert_cache = {}
        self.cache_ttl = 300  # 5 minutes
        self.last_cache_update = None
    
    async def initialize(self):
        """Initialize the alert dashboard."""
        await self._create_dashboard_tables()
        logger.info("Alert Dashboard Manager initialized")
    
    async def _create_dashboard_tables(self):
        """Create additional tables for dashboard functionality."""
        async with aiosqlite.connect(self.db_path) as db:
            # Alert groups table for correlation
            await db.execute("""
                CREATE TABLE IF NOT EXISTS alert_groups (
                    group_id TEXT PRIMARY KEY,
                    correlation_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    first_occurrence TEXT NOT NULL,
                    last_occurrence TEXT NOT NULL,
                    is_suppressed BOOLEAN DEFAULT FALSE,
                    suppression_reason TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Alert group members
            await db.execute("""
                CREATE TABLE IF NOT EXISTS alert_group_members (
                    group_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    PRIMARY KEY (group_id, alert_id),
                    FOREIGN KEY (group_id) REFERENCES alert_groups(group_id),
                    FOREIGN KEY (alert_id) REFERENCES performance_alerts(alert_id)
                )
            """)
            
            # Alert actions/comments
            await db.execute("""
                CREATE TABLE IF NOT EXISTS alert_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    user_id TEXT,
                    comment TEXT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT,
                    FOREIGN KEY (alert_id) REFERENCES performance_alerts(alert_id)
                )
            """)
            
            # Alert suppression rules
            await db.execute("""
                CREATE TABLE IF NOT EXISTS alert_suppression_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT UNIQUE NOT NULL,
                    metric_pattern TEXT,
                    severity_threshold TEXT,
                    time_window_minutes INTEGER DEFAULT 60,
                    max_alerts_per_window INTEGER DEFAULT 10,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_by TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.commit()
    
    async def get_alert_summary(self, time_range_hours: int = 24) -> AlertSummary:
        """Get comprehensive alert summary statistics."""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=time_range_hours)
            
            async with aiosqlite.connect(self.db_path) as db:
                # Total and status counts
                cursor = await db.execute("""
                    SELECT 
                        COUNT(*) as total,
                        COUNT(CASE WHEN status = 'open' THEN 1 END) as open_alerts,
                        COUNT(CASE WHEN status = 'acknowledged' THEN 1 END) as acknowledged,
                        COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved,
                        COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical
                    FROM performance_alerts 
                    WHERE first_occurrence >= ?
                """, (cutoff_time.isoformat(),))
                
                counts = await cursor.fetchone()
                
                # Severity distribution
                cursor = await db.execute("""
                    SELECT severity, COUNT(*) 
                    FROM performance_alerts 
                    WHERE first_occurrence >= ?
                    GROUP BY severity
                """, (cutoff_time.isoformat(),))
                
                severity_dist = dict(await cursor.fetchall())
                
                # Status distribution
                cursor = await db.execute("""
                    SELECT status, COUNT(*) 
                    FROM performance_alerts 
                    WHERE first_occurrence >= ?
                    GROUP BY status
                """, (cutoff_time.isoformat(),))
                
                status_dist = dict(await cursor.fetchall())
                
                # Metric distribution
                cursor = await db.execute("""
                    SELECT metric_name, COUNT(*) 
                    FROM performance_alerts 
                    WHERE first_occurrence >= ?
                    GROUP BY metric_name
                    ORDER BY COUNT(*) DESC
                    LIMIT 10
                """, (cutoff_time.isoformat(),))
                
                metric_dist = dict(await cursor.fetchall())
                
                # Hourly trend
                cursor = await db.execute("""
                    SELECT 
                        strftime('%H', first_occurrence) as hour,
                        COUNT(*) 
                    FROM performance_alerts 
                    WHERE first_occurrence >= ?
                    GROUP BY strftime('%H', first_occurrence)
                    ORDER BY hour
                """, (cutoff_time.isoformat(),))
                
                hourly_trend = dict(await cursor.fetchall())
                
                # Average resolution time
                cursor = await db.execute("""
                    SELECT AVG(
                        julianday(resolved_at) - julianday(first_occurrence)
                    ) * 24 * 60 as avg_resolution_minutes
                    FROM performance_alerts 
                    WHERE status = 'resolved' 
                    AND resolved_at IS NOT NULL
                    AND first_occurrence >= ?
                """, (cutoff_time.isoformat(),))
                
                avg_resolution = await cursor.fetchone()
                avg_resolution_time = avg_resolution[0] if avg_resolution[0] else None
                
                return AlertSummary(
                    total_alerts=counts[0] or 0,
                    open_alerts=counts[1] or 0,
                    acknowledged_alerts=counts[2] or 0,
                    resolved_alerts=counts[3] or 0,
                    critical_alerts=counts[4] or 0,
                    alerts_by_severity=severity_dist,
                    alerts_by_status=status_dist,
                    alerts_by_metric=metric_dist,
                    average_resolution_time=avg_resolution_time,
                    alert_trend=hourly_trend
                )
                
        except Exception as e:
            logger.error(f"Error getting alert summary: {e}")
            return AlertSummary(0, 0, 0, 0, 0, {}, {}, {}, None, {})
    
    async def get_filtered_alerts(self, filter_criteria: AlertFilter) -> Tuple[List[Dict[str, Any]], int]:
        """Get alerts based on filter criteria with pagination."""
        try:
            query_parts = ["SELECT * FROM performance_alerts WHERE 1=1"]
            params = []
            
            # Apply filters
            if filter_criteria.severity:
                placeholders = ','.join(['?' for _ in filter_criteria.severity])
                query_parts.append(f"AND severity IN ({placeholders})")
                params.extend(filter_criteria.severity)
            
            if filter_criteria.status:
                placeholders = ','.join(['?' for _ in filter_criteria.status])
                query_parts.append(f"AND status IN ({placeholders})")
                params.extend(filter_criteria.status)
            
            if filter_criteria.metric_name:
                query_parts.append("AND metric_name LIKE ?")
                params.append(f"%{filter_criteria.metric_name}%")
            
            if filter_criteria.time_range:
                query_parts.append("AND first_occurrence BETWEEN ? AND ?")
                params.extend([t.isoformat() for t in filter_criteria.time_range])
            
            # Count query for pagination
            count_query = query_parts[0].replace("SELECT *", "SELECT COUNT(*)") + " " + " ".join(query_parts[1:])
            
            # Main query with sorting and pagination
            query = " ".join(query_parts)
            query += f" ORDER BY {filter_criteria.sort_by} {filter_criteria.sort_order}"
            query += f" LIMIT {filter_criteria.limit} OFFSET {filter_criteria.offset}"
            
            async with aiosqlite.connect(self.db_path) as db:
                # Get total count
                cursor = await db.execute(count_query, params)
                total_count = (await cursor.fetchone())[0]
                
                # Get filtered results
                cursor = await db.execute(query, params)
                rows = await cursor.fetchall()
                
                # Convert to dictionaries
                column_names = [description[0] for description in cursor.description]
                alerts = [dict(zip(column_names, row)) for row in rows]
                
                return alerts, total_count
                
        except Exception as e:
            logger.error(f"Error getting filtered alerts: {e}")
            return [], 0
    
    async def get_correlated_alert_groups(self, time_range_hours: int = 24) -> List[AlertGroup]:
        """Get correlated alert groups for noise reduction."""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=time_range_hours)
            
            # Get recent alerts
            filter_criteria = AlertFilter(
                time_range=(cutoff_time, datetime.now(timezone.utc)),
                status=['open', 'acknowledged'],
                limit=1000
            )
            
            alerts, _ = await self.get_filtered_alerts(filter_criteria)
            
            # Correlate alerts
            alert_groups = await self.correlation_engine.correlate_alerts(alerts)
            
            # Store correlation results
            for group in alert_groups:
                await self._store_alert_group(group)
            
            return alert_groups
            
        except Exception as e:
            logger.error(f"Error getting correlated alert groups: {e}")
            return []
    
    async def _store_alert_group(self, group: AlertGroup):
        """Store alert group correlation results."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Store group
                await db.execute("""
                    INSERT OR REPLACE INTO alert_groups 
                    (group_id, correlation_type, severity, first_occurrence, last_occurrence, is_suppressed)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    group.group_id,
                    group.correlation_type,
                    group.severity.value,
                    group.first_occurrence.isoformat(),
                    group.last_occurrence.isoformat(),
                    group.is_suppressed
                ))
                
                # Store group members
                for alert in group.alerts:
                    await db.execute("""
                        INSERT OR IGNORE INTO alert_group_members (group_id, alert_id)
                        VALUES (?, ?)
                    """, (group.group_id, alert['alert_id']))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error storing alert group: {e}")
    
    async def bulk_update_alerts(self, alert_ids: List[str], updates: Dict[str, Any], 
                               user_id: str, comment: Optional[str] = None) -> int:
        """Perform bulk updates on multiple alerts."""
        try:
            updated_count = 0
            timestamp = datetime.now(timezone.utc).isoformat()
            
            async with aiosqlite.connect(self.db_path) as db:
                for alert_id in alert_ids:
                    # Build update query dynamically
                    set_clauses = []
                    params = []
                    
                    for key, value in updates.items():
                        if key in ['status', 'severity', 'acknowledged_by', 'resolved_by']:
                            set_clauses.append(f"{key} = ?")
                            params.append(value)
                    
                    if set_clauses:
                        set_clauses.append("updated_at = ?")
                        params.extend([timestamp, alert_id])
                        
                        update_query = f"""
                            UPDATE performance_alerts 
                            SET {', '.join(set_clauses)}
                            WHERE alert_id = ?
                        """
                        
                        cursor = await db.execute(update_query, params)
                        if cursor.rowcount > 0:
                            updated_count += 1
                        
                        # Log the action
                        await db.execute("""
                            INSERT INTO alert_actions 
                            (alert_id, action_type, user_id, comment, metadata)
                            VALUES (?, ?, ?, ?, ?)
                        """, (
                            alert_id,
                            'bulk_update',
                            user_id,
                            comment,
                            json.dumps(updates)
                        ))
                
                await db.commit()
                return updated_count
                
        except Exception as e:
            logger.error(f"Error in bulk update: {e}")
            return 0
    
    async def suppress_alert_group(self, group_id: str, reason: str, user_id: str) -> bool:
        """Suppress an alert group to reduce noise."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Update group suppression
                await db.execute("""
                    UPDATE alert_groups 
                    SET is_suppressed = TRUE, suppression_reason = ?, updated_at = ?
                    WHERE group_id = ?
                """, (reason, datetime.now(timezone.utc).isoformat(), group_id))
                
                # Update all member alerts
                await db.execute("""
                    UPDATE performance_alerts 
                    SET status = 'suppressed'
                    WHERE alert_id IN (
                        SELECT alert_id FROM alert_group_members WHERE group_id = ?
                    )
                """, (group_id,))
                
                # Log the action
                await db.execute("""
                    INSERT INTO alert_actions 
                    (alert_id, action_type, user_id, comment)
                    SELECT alert_id, 'suppress_group', ?, ?
                    FROM alert_group_members WHERE group_id = ?
                """, (user_id, f"Group suppressed: {reason}", group_id))
                
                await db.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error suppressing alert group: {e}")
            return False
    
    async def create_suppression_rule(self, rule_name: str, metric_pattern: str,
                                    severity_threshold: str, time_window_minutes: int,
                                    max_alerts_per_window: int, created_by: str) -> bool:
        """Create an alert suppression rule."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO alert_suppression_rules 
                    (rule_name, metric_pattern, severity_threshold, time_window_minutes, 
                     max_alerts_per_window, created_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    rule_name, metric_pattern, severity_threshold,
                    time_window_minutes, max_alerts_per_window, created_by
                ))
                
                await db.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error creating suppression rule: {e}")
            return False
    
    async def get_alert_details(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific alert."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Get alert details
                cursor = await db.execute("""
                    SELECT * FROM performance_alerts WHERE alert_id = ?
                """, (alert_id,))
                
                row = await cursor.fetchone()
                if not row:
                    return None
                
                column_names = [description[0] for description in cursor.description]
                alert_details = dict(zip(column_names, row))
                
                # Get related actions
                cursor = await db.execute("""
                    SELECT action_type, user_id, comment, timestamp, metadata
                    FROM alert_actions 
                    WHERE alert_id = ?
                    ORDER BY timestamp DESC
                """, (alert_id,))
                
                actions = []
                for action_row in await cursor.fetchall():
                    actions.append({
                        'action_type': action_row[0],
                        'user_id': action_row[1],
                        'comment': action_row[2],
                        'timestamp': action_row[3],
                        'metadata': json.loads(action_row[4]) if action_row[4] else {}
                    })
                
                alert_details['actions'] = actions
                
                # Get group information if applicable
                cursor = await db.execute("""
                    SELECT g.group_id, g.correlation_type, g.is_suppressed
                    FROM alert_groups g
                    JOIN alert_group_members m ON g.group_id = m.group_id
                    WHERE m.alert_id = ?
                """, (alert_id,))
                
                group_info = await cursor.fetchone()
                if group_info:
                    alert_details['group'] = {
                        'group_id': group_info[0],
                        'correlation_type': group_info[1],
                        'is_suppressed': group_info[2]
                    }
                
                return alert_details
                
        except Exception as e:
            logger.error(f"Error getting alert details: {e}")
            return None
    
    async def add_alert_comment(self, alert_id: str, user_id: str, comment: str) -> bool:
        """Add a comment to an alert."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO alert_actions 
                    (alert_id, action_type, user_id, comment)
                    VALUES (?, 'comment', ?, ?)
                """, (alert_id, user_id, comment))
                
                await db.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error adding alert comment: {e}")
            return False
    
    async def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get real-time metrics for dashboard display."""
        try:
            summary = await self.get_alert_summary()
            groups = await self.get_correlated_alert_groups()
            
            # Calculate additional metrics
            response_metrics = {
                'mttr': summary.average_resolution_time,  # Mean Time To Resolution
                'alert_velocity': len(groups),  # Rate of new alert groups
                'noise_reduction': len([g for g in groups if g.is_suppressed]),
                'active_incidents': summary.critical_alerts + summary.open_alerts
            }
            
            # Recent activity
            recent_filter = AlertFilter(
                time_range=(datetime.now(timezone.utc) - timedelta(hours=1), datetime.now(timezone.utc)),
                limit=20,
                sort_by="first_occurrence",
                sort_order="desc"
            )
            
            recent_alerts, _ = await self.get_filtered_alerts(recent_filter)
            
            return {
                'summary': summary,
                'groups': len(groups),
                'response_metrics': response_metrics,
                'recent_alerts': recent_alerts[:10],  # Latest 10
                'dashboard_health': {
                    'correlation_engine_status': 'active',
                    'suppression_rules_active': await self._count_active_suppression_rules(),
                    'last_updated': datetime.now(timezone.utc).isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting dashboard metrics: {e}")
            return {}
    
    async def _count_active_suppression_rules(self) -> int:
        """Count active suppression rules."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT COUNT(*) FROM alert_suppression_rules WHERE is_active = TRUE
                """)
                return (await cursor.fetchone())[0]
        except Exception as e:
            logger.error(f"Error counting suppression rules: {e}")
            return 0


# Global alert dashboard manager instance
alert_dashboard: Optional[AlertDashboardManager] = None


def get_alert_dashboard() -> AlertDashboardManager:
    """Get the global alert dashboard manager instance."""
    global alert_dashboard
    if alert_dashboard is None:
        alert_dashboard = AlertDashboardManager()
    return alert_dashboard


async def initialize_alert_dashboard():
    """Initialize the global alert dashboard manager."""
    dashboard = get_alert_dashboard()
    await dashboard.initialize()
    return dashboard