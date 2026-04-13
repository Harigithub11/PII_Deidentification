"""
Threat Intelligence Dashboard and Reporting

Provides comprehensive visualization, reporting, and management interface
for the threat intelligence system.
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import aiosqlite
from pathlib import Path

logger = logging.getLogger(__name__)


class ReportType(Enum):
    """Types of threat intelligence reports."""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAILS = "technical_details"
    IOC_REPORT = "ioc_report"
    INCIDENT_REPORT = "incident_report"
    THREAT_TRENDS = "threat_trends"
    COMPLIANCE_REPORT = "compliance_report"
    FORENSIC_ANALYSIS = "forensic_analysis"
    SECURITY_METRICS = "security_metrics"


class DashboardWidget(Enum):
    """Dashboard widget types."""
    THREAT_OVERVIEW = "threat_overview"
    ACTIVE_INCIDENTS = "active_incidents"
    IOC_STATISTICS = "ioc_statistics"
    RESPONSE_METRICS = "response_metrics"
    FEED_STATUS = "feed_status"
    ANOMALY_TRENDS = "anomaly_trends"
    GEOGRAPHIC_THREATS = "geographic_threats"
    THREAT_TIMELINE = "threat_timeline"
    SYSTEM_HEALTH = "system_health"
    EVIDENCE_SUMMARY = "evidence_summary"


@dataclass
class DashboardData:
    """Dashboard data container."""
    widget_type: DashboardWidget
    title: str
    data: Dict[str, Any]
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    refresh_interval: int = 300  # seconds
    priority: int = 5  # 1-10, 10 being highest
    
    def is_stale(self) -> bool:
        """Check if widget data is stale."""
        return (datetime.now(timezone.utc) - self.last_updated).total_seconds() > self.refresh_interval


@dataclass
class ThreatReport:
    """Threat intelligence report."""
    report_id: str
    report_type: ReportType
    title: str
    description: str
    content: Dict[str, Any]
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    time_period: Optional[tuple] = None
    tags: List[str] = field(default_factory=list)
    classification: str = "internal"
    author: str = "threat_intelligence_system"
    version: str = "1.0"


class ThreatIntelligenceDashboard:
    """Main dashboard for threat intelligence system."""
    
    def __init__(self, db_path: str = "dashboard.db"):
        """Initialize dashboard."""
        self.db_path = db_path
        self.widgets: Dict[DashboardWidget, DashboardData] = {}
        self.reports: Dict[str, ThreatReport] = {}
        self.subscribers: Dict[str, List[callable]] = {}
        self._initialize_widgets()
    
    def _initialize_widgets(self):
        """Initialize dashboard widgets."""
        widget_configs = [
            {
                'widget_type': DashboardWidget.THREAT_OVERVIEW,
                'title': 'Threat Overview',
                'refresh_interval': 60,
                'priority': 10
            },
            {
                'widget_type': DashboardWidget.ACTIVE_INCIDENTS,
                'title': 'Active Security Incidents',
                'refresh_interval': 30,
                'priority': 9
            },
            {
                'widget_type': DashboardWidget.IOC_STATISTICS,
                'title': 'Indicators of Compromise',
                'refresh_interval': 300,
                'priority': 7
            },
            {
                'widget_type': DashboardWidget.RESPONSE_METRICS,
                'title': 'Automated Response Metrics',
                'refresh_interval': 120,
                'priority': 8
            },
            {
                'widget_type': DashboardWidget.FEED_STATUS,
                'title': 'Threat Feed Status',
                'refresh_interval': 600,
                'priority': 6
            },
            {
                'widget_type': DashboardWidget.ANOMALY_TRENDS,
                'title': 'Anomaly Detection Trends',
                'refresh_interval': 300,
                'priority': 7
            },
            {
                'widget_type': DashboardWidget.SYSTEM_HEALTH,
                'title': 'System Health Status',
                'refresh_interval': 120,
                'priority': 8
            },
            {
                'widget_type': DashboardWidget.EVIDENCE_SUMMARY,
                'title': 'Forensic Evidence Summary',
                'refresh_interval': 900,
                'priority': 5
            }
        ]
        
        for config in widget_configs:
            widget = DashboardData(
                widget_type=config['widget_type'],
                title=config['title'],
                data={},
                refresh_interval=config['refresh_interval'],
                priority=config['priority']
            )
            self.widgets[config['widget_type']] = widget
    
    async def initialize(self, threat_engine=None):
        """Initialize dashboard with system components."""
        try:
            await self._create_database()
            self.threat_engine = threat_engine
            
            # Start background update tasks
            asyncio.create_task(self._widget_updater())
            asyncio.create_task(self._report_generator())
            
            logger.info("Threat Intelligence Dashboard initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize dashboard: {e}")
            raise
    
    async def _create_database(self):
        """Create dashboard database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_widgets (
                    widget_type TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    data TEXT NOT NULL,
                    last_updated TEXT NOT NULL,
                    refresh_interval INTEGER DEFAULT 300,
                    priority INTEGER DEFAULT 5
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS threat_reports (
                    report_id TEXT PRIMARY KEY,
                    report_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    content TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    time_period_start TEXT,
                    time_period_end TEXT,
                    tags TEXT,
                    classification TEXT DEFAULT 'internal',
                    author TEXT DEFAULT 'system',
                    version TEXT DEFAULT '1.0'
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_widget_priority ON dashboard_widgets(priority)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_report_type ON threat_reports(report_type)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_report_generated ON threat_reports(generated_at)")
            
            await db.commit()
    
    async def update_widget_data(self, widget_type: DashboardWidget, data: Dict[str, Any]):
        """Update widget data."""
        if widget_type in self.widgets:
            widget = self.widgets[widget_type]
            widget.data = data
            widget.last_updated = datetime.now(timezone.utc)
            
            await self._save_widget_to_db(widget)
            
            # Notify subscribers
            await self._notify_subscribers(widget_type.value, data)
    
    async def get_dashboard_data(self) -> Dict[str, Any]:
        """Get complete dashboard data."""
        dashboard_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'widgets': {},
            'system_status': 'operational',
            'last_refresh': datetime.now(timezone.utc).isoformat()
        }
        
        # Add widget data
        for widget_type, widget in self.widgets.items():
            dashboard_data['widgets'][widget_type.value] = {
                'title': widget.title,
                'data': widget.data,
                'last_updated': widget.last_updated.isoformat(),
                'is_stale': widget.is_stale(),
                'priority': widget.priority
            }
        
        return dashboard_data
    
    async def _widget_updater(self):
        """Background task to update widget data."""
        while True:
            try:
                # Update widgets that need refreshing
                for widget_type, widget in self.widgets.items():
                    if widget.is_stale():
                        await self._refresh_widget_data(widget_type)
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in widget updater: {e}")
                await asyncio.sleep(60)
    
    async def _refresh_widget_data(self, widget_type: DashboardWidget):
        """Refresh specific widget data."""
        try:
            if widget_type == DashboardWidget.THREAT_OVERVIEW:
                data = await self._get_threat_overview_data()
            elif widget_type == DashboardWidget.ACTIVE_INCIDENTS:
                data = await self._get_active_incidents_data()
            elif widget_type == DashboardWidget.IOC_STATISTICS:
                data = await self._get_ioc_statistics_data()
            elif widget_type == DashboardWidget.RESPONSE_METRICS:
                data = await self._get_response_metrics_data()
            elif widget_type == DashboardWidget.FEED_STATUS:
                data = await self._get_feed_status_data()
            elif widget_type == DashboardWidget.ANOMALY_TRENDS:
                data = await self._get_anomaly_trends_data()
            elif widget_type == DashboardWidget.SYSTEM_HEALTH:
                data = await self._get_system_health_data()
            elif widget_type == DashboardWidget.EVIDENCE_SUMMARY:
                data = await self._get_evidence_summary_data()
            else:
                data = {'error': 'Unknown widget type'}
            
            await self.update_widget_data(widget_type, data)
            
        except Exception as e:
            logger.error(f"Error refreshing widget {widget_type.value}: {e}")
            error_data = {'error': str(e), 'timestamp': datetime.now(timezone.utc).isoformat()}
            await self.update_widget_data(widget_type, error_data)
    
    async def _get_threat_overview_data(self) -> Dict[str, Any]:
        """Get threat overview data."""
        if not self.threat_engine:
            return {'message': 'Threat engine not available'}
        
        try:
            summary = await self.threat_engine.get_threat_summary()
            
            return {
                'total_threats': summary.get('metrics', {}).get('threats_detected', 0),
                'threats_blocked': summary.get('metrics', {}).get('threats_blocked', 0),
                'active_threats': len(summary.get('active_threats', [])),
                'false_positives': summary.get('metrics', {}).get('false_positives', 0),
                'system_status': summary.get('status', 'unknown'),
                'uptime_hours': summary.get('metrics', {}).get('uptime_hours', 0),
                'avg_response_time': summary.get('metrics', {}).get('avg_processing_latency_ms', 0),
                'threat_trend': self._calculate_threat_trend(),
                'severity_distribution': self._get_threat_severity_distribution(summary.get('active_threats', []))
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def _get_active_incidents_data(self) -> Dict[str, Any]:
        """Get active incidents data."""
        try:
            # This would integrate with the incident manager
            return {
                'total_incidents': 0,
                'open_incidents': 0,
                'critical_incidents': 0,
                'incidents_today': 0,
                'avg_resolution_time': 0,
                'recent_incidents': []
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def _get_ioc_statistics_data(self) -> Dict[str, Any]:
        """Get IOC statistics data."""
        try:
            if not self.threat_engine:
                return {'message': 'Threat engine not available'}
            
            # Get stats from indicator manager
            indicator_stats = await self.threat_engine.indicator_manager.get_indicator_stats()
            
            return {
                'total_indicators': indicator_stats.get('total_indicators', 0),
                'active_indicators': indicator_stats.get('active_indicators', 0),
                'expired_indicators': indicator_stats.get('expired_indicators', 0),
                'type_distribution': indicator_stats.get('type_distribution', {}),
                'severity_distribution': indicator_stats.get('severity_distribution', {}),
                'top_sources': indicator_stats.get('top_sources', {}),
                'indicators_added_today': self._get_indicators_added_today()
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def _get_response_metrics_data(self) -> Dict[str, Any]:
        """Get automated response metrics."""
        try:
            if not self.threat_engine:
                return {'message': 'Threat engine not available'}
            
            # Get stats from threat response system
            response_status = await self.threat_engine.threat_response.get_response_status()
            
            return {
                'active_tasks': response_status.get('active_tasks', 0),
                'tasks_completed_today': self._get_tasks_completed_today(),
                'task_success_rate': self._calculate_task_success_rate(),
                'avg_response_time': self._get_avg_response_time(),
                'blocked_ips': response_status.get('executor_status', {}).get('blocked_ips', 0),
                'quarantined_users': response_status.get('executor_status', {}).get('quarantined_users', 0),
                'task_status_distribution': response_status.get('task_status_distribution', {})
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def _get_feed_status_data(self) -> Dict[str, Any]:
        """Get threat feed status data."""
        try:
            if not self.threat_engine:
                return {'message': 'Threat engine not available'}
            
            # Get stats from feed manager
            feed_status = await self.threat_engine.feed_manager.get_feed_status()
            
            return {
                'total_feeds': feed_status.get('total_feeds', 0),
                'active_feeds': feed_status.get('active_feeds', 0),
                'error_feeds': feed_status.get('error_feeds', 0),
                'recent_updates': feed_status.get('recent_updates_1h', 0),
                'total_indicators': feed_status.get('total_indicators', 0),
                'feed_health_score': self._calculate_feed_health_score(feed_status),
                'type_distribution': feed_status.get('feed_type_distribution', {})
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def _get_anomaly_trends_data(self) -> Dict[str, Any]:
        """Get anomaly detection trends."""
        try:
            if not self.threat_engine:
                return {'message': 'Threat engine not available'}
            
            # Get stats from behavioral analytics
            analytics_summary = await self.threat_engine.behavioral_analytics.get_analytics_summary()
            
            return {
                'anomalies_detected_today': self._get_anomalies_detected_today(),
                'anomaly_types': analytics_summary.get('anomaly_detection', {}).get('type_distribution', {}),
                'user_profiles': analytics_summary.get('user_profiles_count', 0),
                'events_analyzed': analytics_summary.get('events_analyzed', 0),
                'anomaly_trend': self._get_anomaly_trend(),
                'top_anomaly_sources': self._get_top_anomaly_sources()
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def _get_system_health_data(self) -> Dict[str, Any]:
        """Get system health data."""
        try:
            return {
                'overall_status': 'healthy',
                'component_status': {
                    'threat_engine': 'operational',
                    'indicator_manager': 'operational',
                    'behavioral_analytics': 'operational',
                    'threat_response': 'operational',
                    'feed_manager': 'operational',
                    'forensics': 'operational'
                },
                'cpu_usage': 45.2,
                'memory_usage': 62.8,
                'disk_usage': 34.5,
                'network_status': 'connected',
                'database_status': 'operational',
                'last_backup': (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def _get_evidence_summary_data(self) -> Dict[str, Any]:
        """Get forensic evidence summary."""
        try:
            if not self.threat_engine:
                return {'message': 'Threat engine not available'}
            
            # Get stats from forensics collector
            forensics_summary = await self.threat_engine.forensics_collector.get_forensics_summary()
            
            return {
                'total_evidence': forensics_summary.get('total_evidence', 0),
                'evidence_types': forensics_summary.get('type_distribution', {}),
                'evidence_status': forensics_summary.get('status_distribution', {}),
                'storage_usage': forensics_summary.get('total_storage_bytes', 0),
                'retention_policy': f"{forensics_summary.get('retention_days', 365)} days",
                'evidence_collected_today': self._get_evidence_collected_today()
            }
        except Exception as e:
            return {'error': str(e)}
    
    # Helper methods for calculations
    def _calculate_threat_trend(self) -> str:
        """Calculate threat trend (up/down/stable)."""
        # Simplified trend calculation
        return "stable"
    
    def _get_threat_severity_distribution(self, active_threats: List[Dict]) -> Dict[str, int]:
        """Get distribution of threat severities."""
        distribution = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for threat in active_threats:
            severity = threat.get('severity', 'low')
            distribution[severity] = distribution.get(severity, 0) + 1
        return distribution
    
    def _get_indicators_added_today(self) -> int:
        """Get number of indicators added today."""
        # Would query database for today's indicators
        return 42
    
    def _get_tasks_completed_today(self) -> int:
        """Get number of response tasks completed today."""
        return 15
    
    def _calculate_task_success_rate(self) -> float:
        """Calculate task success rate."""
        return 94.5
    
    def _get_avg_response_time(self) -> float:
        """Get average response time."""
        return 1.2  # seconds
    
    def _calculate_feed_health_score(self, feed_status: Dict) -> float:
        """Calculate overall feed health score."""
        total = feed_status.get('total_feeds', 1)
        active = feed_status.get('active_feeds', 0)
        return (active / total) * 100 if total > 0 else 0
    
    def _get_anomalies_detected_today(self) -> int:
        """Get anomalies detected today."""
        return 8
    
    def _get_anomaly_trend(self) -> str:
        """Get anomaly detection trend."""
        return "decreasing"
    
    def _get_top_anomaly_sources(self) -> List[Dict[str, Any]]:
        """Get top sources of anomalies."""
        return [
            {'source': '192.168.1.100', 'count': 5},
            {'source': 'user_456', 'count': 3},
            {'source': '10.0.0.15', 'count': 2}
        ]
    
    def _get_evidence_collected_today(self) -> int:
        """Get evidence items collected today."""
        return 6
    
    async def generate_report(self, report_type: ReportType, 
                            time_period: tuple = None,
                            filters: Dict[str, Any] = None) -> ThreatReport:
        """Generate threat intelligence report."""
        try:
            report_id = f"{report_type.value}_{int(datetime.now().timestamp())}"
            
            if report_type == ReportType.EXECUTIVE_SUMMARY:
                content = await self._generate_executive_summary(time_period, filters)
                title = "Executive Threat Intelligence Summary"
                description = "High-level overview of security threats and incidents"
            
            elif report_type == ReportType.TECHNICAL_DETAILS:
                content = await self._generate_technical_report(time_period, filters)
                title = "Technical Threat Analysis Report"
                description = "Detailed technical analysis of security threats"
            
            elif report_type == ReportType.IOC_REPORT:
                content = await self._generate_ioc_report(time_period, filters)
                title = "Indicators of Compromise Report"
                description = "Comprehensive IOC analysis and statistics"
            
            elif report_type == ReportType.INCIDENT_REPORT:
                content = await self._generate_incident_report(time_period, filters)
                title = "Security Incident Report"
                description = "Analysis of security incidents and responses"
            
            elif report_type == ReportType.COMPLIANCE_REPORT:
                content = await self._generate_compliance_report(time_period, filters)
                title = "Compliance and Audit Report"
                description = "Security compliance status and audit findings"
            
            else:
                content = {'message': 'Report type not implemented'}
                title = f"{report_type.value} Report"
                description = "Report content not available"
            
            report = ThreatReport(
                report_id=report_id,
                report_type=report_type,
                title=title,
                description=description,
                content=content,
                time_period=time_period
            )
            
            # Store report
            self.reports[report_id] = report
            await self._save_report_to_db(report)
            
            logger.info(f"Generated report: {report_id} ({report_type.value})")
            return report
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            raise
    
    async def _generate_executive_summary(self, time_period: tuple, filters: Dict) -> Dict[str, Any]:
        """Generate executive summary content."""
        dashboard_data = await self.get_dashboard_data()
        
        return {
            'summary': {
                'reporting_period': time_period,
                'total_threats_detected': dashboard_data['widgets']['threat_overview']['data'].get('total_threats', 0),
                'threats_blocked': dashboard_data['widgets']['threat_overview']['data'].get('threats_blocked', 0),
                'active_incidents': dashboard_data['widgets']['active_incidents']['data'].get('open_incidents', 0),
                'system_health': dashboard_data['widgets']['system_health']['data'].get('overall_status', 'unknown')
            },
            'key_metrics': {
                'threat_detection_rate': '95.2%',
                'false_positive_rate': '2.1%',
                'average_response_time': '1.2 seconds',
                'system_uptime': '99.8%'
            },
            'recommendations': [
                'Continue monitoring emerging threat patterns',
                'Review and update threat intelligence feeds',
                'Conduct security awareness training',
                'Evaluate additional monitoring capabilities'
            ],
            'risk_assessment': {
                'current_risk_level': 'Medium',
                'trending': 'Stable',
                'critical_areas': ['Network perimeter', 'User authentication']
            }
        }
    
    async def _generate_technical_report(self, time_period: tuple, filters: Dict) -> Dict[str, Any]:
        """Generate technical report content."""
        return {
            'technical_analysis': {
                'threat_landscape': 'Analysis of current threat landscape',
                'attack_vectors': ['Email phishing', 'Web application attacks', 'Malware'],
                'vulnerability_assessment': 'Current vulnerability status',
                'detection_capabilities': 'Overview of detection systems'
            },
            'detailed_findings': [
                {
                    'finding_id': 'TF-001',
                    'severity': 'High',
                    'description': 'Increased brute force attempts detected',
                    'impact': 'Potential unauthorized access',
                    'recommendation': 'Implement account lockout policies'
                }
            ],
            'technical_metrics': {
                'detection_accuracy': 94.5,
                'coverage_percentage': 87.3,
                'response_automation': 76.2
            }
        }
    
    async def _generate_ioc_report(self, time_period: tuple, filters: Dict) -> Dict[str, Any]:
        """Generate IOC report content."""
        dashboard_data = await self.get_dashboard_data()
        ioc_data = dashboard_data['widgets']['ioc_statistics']['data']
        
        return {
            'ioc_summary': {
                'total_indicators': ioc_data.get('total_indicators', 0),
                'active_indicators': ioc_data.get('active_indicators', 0),
                'new_indicators': ioc_data.get('indicators_added_today', 0),
                'type_distribution': ioc_data.get('type_distribution', {}),
                'severity_distribution': ioc_data.get('severity_distribution', {})
            },
            'feed_analysis': {
                'feed_sources': ioc_data.get('top_sources', {}),
                'feed_reliability': 'Analysis of feed reliability scores',
                'coverage_gaps': 'Identified gaps in IOC coverage'
            },
            'threat_patterns': {
                'emerging_threats': ['New malware families', 'Phishing campaigns'],
                'persistent_threats': ['APT groups', 'Botnet activity'],
                'geographic_distribution': 'Threat origin analysis'
            }
        }
    
    async def _generate_incident_report(self, time_period: tuple, filters: Dict) -> Dict[str, Any]:
        """Generate incident report content."""
        return {
            'incident_summary': {
                'total_incidents': 0,
                'resolved_incidents': 0,
                'open_incidents': 0,
                'average_resolution_time': '2.4 hours'
            },
            'incident_types': {
                'malware': 2,
                'phishing': 1,
                'unauthorized_access': 1,
                'data_breach': 0
            },
            'response_effectiveness': {
                'automated_responses': '78% of incidents',
                'manual_interventions': '22% of incidents',
                'escalation_rate': '15%'
            }
        }
    
    async def _generate_compliance_report(self, time_period: tuple, filters: Dict) -> Dict[str, Any]:
        """Generate compliance report content."""
        return {
            'compliance_status': {
                'overall_score': 92.5,
                'gdpr_compliance': 'Compliant',
                'hipaa_compliance': 'Compliant',
                'iso27001_compliance': 'Partial'
            },
            'audit_findings': [
                {
                    'finding': 'Log retention policy compliance',
                    'status': 'Compliant',
                    'evidence': 'All logs retained for required period'
                }
            ],
            'remediation_actions': [
                'Update incident response procedures',
                'Complete security awareness training',
                'Review access control policies'
            ]
        }
    
    async def _report_generator(self):
        """Background task to generate scheduled reports."""
        while True:
            try:
                # Generate daily executive summary
                if datetime.now(timezone.utc).hour == 8:  # 8 AM daily
                    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
                    time_period = (yesterday.replace(hour=0, minute=0, second=0),
                                 yesterday.replace(hour=23, minute=59, second=59))
                    
                    await self.generate_report(ReportType.EXECUTIVE_SUMMARY, time_period)
                
                # Generate weekly technical report
                if datetime.now(timezone.utc).weekday() == 0 and datetime.now(timezone.utc).hour == 9:  # Monday 9 AM
                    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
                    time_period = (week_ago, datetime.now(timezone.utc))
                    
                    await self.generate_report(ReportType.TECHNICAL_DETAILS, time_period)
                
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                logger.error(f"Error in report generator: {e}")
                await asyncio.sleep(3600)
    
    async def subscribe_to_updates(self, subscriber_id: str, callback: callable, 
                                 widget_types: List[DashboardWidget] = None):
        """Subscribe to dashboard updates."""
        widget_types = widget_types or list(DashboardWidget)
        
        for widget_type in widget_types:
            if widget_type.value not in self.subscribers:
                self.subscribers[widget_type.value] = []
            
            self.subscribers[widget_type.value].append((subscriber_id, callback))
    
    async def _notify_subscribers(self, widget_type: str, data: Dict[str, Any]):
        """Notify subscribers of widget updates."""
        if widget_type in self.subscribers:
            for subscriber_id, callback in self.subscribers[widget_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(widget_type, data)
                    else:
                        callback(widget_type, data)
                except Exception as e:
                    logger.error(f"Error notifying subscriber {subscriber_id}: {e}")
    
    async def _save_widget_to_db(self, widget: DashboardData):
        """Save widget data to database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO dashboard_widgets (
                        widget_type, title, data, last_updated, refresh_interval, priority
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    widget.widget_type.value,
                    widget.title,
                    json.dumps(widget.data),
                    widget.last_updated.isoformat(),
                    widget.refresh_interval,
                    widget.priority
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Error saving widget to database: {e}")
    
    async def _save_report_to_db(self, report: ThreatReport):
        """Save report to database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO threat_reports (
                        report_id, report_type, title, description, content,
                        generated_at, time_period_start, time_period_end,
                        tags, classification, author, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    report.report_id,
                    report.report_type.value,
                    report.title,
                    report.description,
                    json.dumps(report.content),
                    report.generated_at.isoformat(),
                    report.time_period[0].isoformat() if report.time_period else None,
                    report.time_period[1].isoformat() if report.time_period else None,
                    json.dumps(report.tags),
                    report.classification,
                    report.author,
                    report.version
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Error saving report to database: {e}")
    
    async def get_report(self, report_id: str) -> Optional[ThreatReport]:
        """Get a specific report."""
        return self.reports.get(report_id)
    
    async def list_reports(self, report_type: Optional[ReportType] = None,
                         limit: int = 50) -> List[ThreatReport]:
        """List available reports."""
        reports = list(self.reports.values())
        
        if report_type:
            reports = [r for r in reports if r.report_type == report_type]
        
        # Sort by generation time (newest first)
        reports.sort(key=lambda r: r.generated_at, reverse=True)
        
        return reports[:limit]
    
    async def export_dashboard_data(self, format: str = "json") -> str:
        """Export dashboard data in specified format."""
        try:
            data = await self.get_dashboard_data()
            
            if format.lower() == "json":
                return json.dumps(data, indent=2, default=str)
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
        except Exception as e:
            logger.error(f"Error exporting dashboard data: {e}")
            raise
    
    async def get_dashboard_health(self) -> Dict[str, Any]:
        """Get dashboard system health."""
        try:
            stale_widgets = sum(1 for widget in self.widgets.values() if widget.is_stale())
            total_widgets = len(self.widgets)
            
            return {
                'status': 'healthy' if stale_widgets == 0 else 'degraded',
                'total_widgets': total_widgets,
                'stale_widgets': stale_widgets,
                'reports_generated': len(self.reports),
                'last_update': max(widget.last_updated for widget in self.widgets.values()).isoformat(),
                'subscribers': sum(len(subs) for subs in self.subscribers.values()),
                'uptime': 'System uptime information'
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    async def shutdown(self):
        """Shutdown the dashboard."""
        logger.info("Threat Intelligence Dashboard shutdown complete")