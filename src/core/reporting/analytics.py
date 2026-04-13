"""
Analytics Engine for Audit Data Analysis

Provides comprehensive analytics capabilities for audit trails, security events,
user activities, and system performance metrics.
"""

import logging
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from uuid import UUID
from dataclasses import dataclass
from enum import Enum

import pandas as pd
from sqlalchemy import func, and_, or_, text
from sqlalchemy.orm import Session

from ..database.models import (
    AuditEvent, UserActivity, SystemEvent, SecurityEvent, 
    DataProcessingLog, User, Document
)
from ..database.repositories import RepositoryFactory
from .engine import ReportRequest, ReportQuery

logger = logging.getLogger(__name__)


class TrendDirection(str, Enum):
    """Trend direction indicators."""
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    VOLATILE = "volatile"


@dataclass
class TrendAnalysis:
    """Trend analysis result."""
    direction: TrendDirection
    change_percentage: float
    confidence_score: float
    data_points: List[Tuple[datetime, float]]
    anomalies: List[Dict[str, Any]]


@dataclass
class SecurityInsight:
    """Security analysis insight."""
    insight_type: str
    severity: str
    title: str
    description: str
    affected_users: List[UUID]
    affected_resources: List[str]
    recommendations: List[str]
    confidence_score: float


@dataclass
class AnalyticsResult:
    """Result of analytics processing."""
    summary_stats: Dict[str, Any]
    trends: Dict[str, TrendAnalysis]
    insights: List[SecurityInsight]
    charts_data: Dict[str, Any]
    raw_data: List[Dict[str, Any]]


class AuditAnalytics:
    """Analytics engine for audit trail data."""
    
    def __init__(self, session: Session):
        self.session = session
        self.repos = RepositoryFactory(session)
    
    async def generate_audit_trail_report(self, request: ReportRequest, 
                                        query: ReportQuery) -> Dict[str, Any]:
        """
        Generate comprehensive audit trail analytics report.
        
        Args:
            request: Report generation request
            query: Query parameters for data retrieval
            
        Returns:
            Analytics data for report generation
        """
        start_time = datetime.utcnow()
        
        # Get audit events
        audit_events = self._get_audit_events(query)
        
        # Perform various analytics
        summary_stats = self._calculate_summary_stats(audit_events, request)
        event_trends = self._analyze_event_trends(audit_events, request)
        user_activity_analysis = self._analyze_user_activity(audit_events, request)
        security_insights = self._generate_security_insights(audit_events, request)
        charts_data = self._prepare_charts_data(audit_events, request)
        
        # Calculate processing metrics
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        return {
            "metadata": {
                "report_type": "audit_trail",
                "generated_at": datetime.utcnow().isoformat(),
                "time_range": {
                    "start": request.start_date.isoformat(),
                    "end": request.end_date.isoformat(),
                    "days": (request.end_date - request.start_date).days
                },
                "processing_time_ms": int(processing_time),
                "data_points": len(audit_events)
            },
            "summary": summary_stats,
            "trends": event_trends,
            "user_activity": user_activity_analysis,
            "security_insights": security_insights,
            "charts": charts_data,
            "events": [self._serialize_audit_event(event) for event in audit_events[:1000]]  # Limit for report
        }
    
    def _get_audit_events(self, query: ReportQuery) -> List[AuditEvent]:
        """Retrieve audit events based on query parameters."""
        audit_query = self.session.query(AuditEvent).filter(
            AuditEvent.event_timestamp >= query.start_date,
            AuditEvent.event_timestamp <= query.end_date
        )
        
        # Apply filters
        if query.user_ids:
            audit_query = audit_query.filter(AuditEvent.user_id.in_(query.user_ids))
        
        if query.event_types:
            audit_query = audit_query.filter(AuditEvent.event_type.in_(query.event_types))
        
        if query.filters:
            if 'severity' in query.filters:
                audit_query = audit_query.filter(AuditEvent.severity == query.filters['severity'])
            
            if 'outcome' in query.filters:
                audit_query = audit_query.filter(AuditEvent.outcome == query.filters['outcome'])
            
            if 'ip_address' in query.filters:
                audit_query = audit_query.filter(AuditEvent.ip_address == query.filters['ip_address'])
        
        return audit_query.order_by(AuditEvent.event_timestamp.desc()).all()
    
    def _calculate_summary_stats(self, events: List[AuditEvent], 
                                request: ReportRequest) -> Dict[str, Any]:
        """Calculate summary statistics for audit events."""
        if not events:
            return {"total_events": 0}
        
        # Basic counts
        total_events = len(events)
        unique_users = len(set(e.user_id for e in events if e.user_id))
        unique_resources = len(set(e.target_id for e in events if e.target_id))
        
        # Event type distribution
        event_type_counts = Counter(e.event_type for e in events)
        
        # Severity distribution
        severity_counts = Counter(e.severity for e in events)
        
        # Outcome distribution
        outcome_counts = Counter(e.outcome for e in events)
        
        # Time-based stats
        date_range = request.end_date - request.start_date
        events_per_day = total_events / max(date_range.days, 1)
        
        # Risk assessment
        high_risk_events = sum(1 for e in events if e.severity in ['high', 'critical'])
        risk_percentage = (high_risk_events / total_events) * 100 if total_events > 0 else 0
        
        return {
            "total_events": total_events,
            "unique_users": unique_users,
            "unique_resources": unique_resources,
            "events_per_day": round(events_per_day, 2),
            "high_risk_events": high_risk_events,
            "risk_percentage": round(risk_percentage, 2),
            "event_types": dict(event_type_counts.most_common(10)),
            "severity_distribution": dict(severity_counts),
            "outcome_distribution": dict(outcome_counts),
            "date_range_days": date_range.days
        }
    
    def _analyze_event_trends(self, events: List[AuditEvent], 
                            request: ReportRequest) -> Dict[str, Any]:
        """Analyze trends in audit events over time."""
        if not events:
            return {}
        
        # Create daily event counts
        daily_counts = defaultdict(int)
        for event in events:
            date_key = event.event_timestamp.date()
            daily_counts[date_key] += 1
        
        # Convert to sorted time series
        sorted_dates = sorted(daily_counts.keys())
        daily_values = [daily_counts[date] for date in sorted_dates]
        
        # Calculate trend
        trend_analysis = self._calculate_trend(
            dates=sorted_dates,
            values=daily_values,
            metric_name="daily_events"
        )
        
        # Event type trends
        event_type_trends = {}
        for event_type in set(e.event_type for e in events):
            type_events = [e for e in events if e.event_type == event_type]
            if len(type_events) >= 3:  # Need minimum data points
                type_daily_counts = defaultdict(int)
                for event in type_events:
                    date_key = event.event_timestamp.date()
                    type_daily_counts[date_key] += 1
                
                type_values = [type_daily_counts[date] for date in sorted_dates]
                event_type_trends[event_type] = self._calculate_trend(
                    dates=sorted_dates,
                    values=type_values,
                    metric_name=f"{event_type}_events"
                )
        
        return {
            "overall_trend": trend_analysis,
            "event_type_trends": event_type_trends,
            "daily_data": {
                "dates": [d.isoformat() for d in sorted_dates],
                "values": daily_values
            }
        }
    
    def _calculate_trend(self, dates: List, values: List[float], 
                        metric_name: str) -> Dict[str, Any]:
        """Calculate trend analysis for time series data."""
        if len(values) < 2:
            return {"direction": TrendDirection.STABLE, "change_percentage": 0.0}
        
        # Simple linear trend calculation
        n = len(values)
        sum_x = sum(range(n))
        sum_y = sum(values)
        sum_xy = sum(i * values[i] for i in range(n))
        sum_x2 = sum(i * i for i in range(n))
        
        # Calculate slope (trend)
        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            slope = 0
        else:
            slope = (n * sum_xy - sum_x * sum_y) / denominator
        
        # Determine trend direction
        if abs(slope) < 0.1:
            direction = TrendDirection.STABLE
        elif slope > 0:
            direction = TrendDirection.INCREASING
        else:
            direction = TrendDirection.DECREASING
        
        # Calculate percentage change
        start_value = values[0] if values[0] > 0 else 1
        end_value = values[-1]
        change_percentage = ((end_value - start_value) / start_value) * 100
        
        # Detect anomalies (simple outlier detection)
        mean_val = sum(values) / len(values)
        std_dev = (sum((x - mean_val) ** 2 for x in values) / len(values)) ** 0.5
        threshold = mean_val + 2 * std_dev
        
        anomalies = [
            {
                "date": dates[i].isoformat(),
                "value": values[i],
                "deviation": values[i] - mean_val
            }
            for i, val in enumerate(values)
            if val > threshold and len(dates) > i
        ]
        
        return {
            "direction": direction.value,
            "change_percentage": round(change_percentage, 2),
            "slope": round(slope, 4),
            "confidence_score": 0.8,  # Simplified confidence score
            "anomalies": anomalies,
            "statistics": {
                "mean": round(mean_val, 2),
                "std_dev": round(std_dev, 2),
                "min": min(values),
                "max": max(values)
            }
        }
    
    def _analyze_user_activity(self, events: List[AuditEvent], 
                              request: ReportRequest) -> Dict[str, Any]:
        """Analyze user activity patterns."""
        if not events:
            return {}
        
        # User activity counts
        user_activity = defaultdict(int)
        user_risk_scores = defaultdict(list)
        
        for event in events:
            if event.user_id:
                user_activity[event.user_id] += 1
                if event.risk_score:
                    user_risk_scores[event.user_id].append(event.risk_score)
        
        # Top active users
        top_users = sorted(user_activity.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # High-risk users
        high_risk_users = []
        for user_id, risk_scores in user_risk_scores.items():
            if risk_scores:
                avg_risk = sum(risk_scores) / len(risk_scores)
                if avg_risk > 70:  # High risk threshold
                    high_risk_users.append({
                        "user_id": str(user_id),
                        "activity_count": user_activity[user_id],
                        "average_risk_score": round(avg_risk, 2),
                        "max_risk_score": max(risk_scores)
                    })
        
        # Activity by hour analysis
        hourly_activity = defaultdict(int)
        for event in events:
            hour = event.event_timestamp.hour
            hourly_activity[hour] += 1
        
        return {
            "total_active_users": len(user_activity),
            "top_users": [
                {"user_id": str(user_id), "event_count": count}
                for user_id, count in top_users
            ],
            "high_risk_users": high_risk_users,
            "hourly_distribution": dict(hourly_activity),
            "activity_statistics": {
                "mean_events_per_user": round(sum(user_activity.values()) / len(user_activity), 2),
                "median_events_per_user": sorted(user_activity.values())[len(user_activity) // 2],
                "max_events_per_user": max(user_activity.values())
            }
        }
    
    def _generate_security_insights(self, events: List[AuditEvent], 
                                   request: ReportRequest) -> List[Dict[str, Any]]:
        """Generate security insights from audit events."""
        insights = []
        
        # Failed login attempts
        failed_logins = [e for e in events if 'login' in e.event_type and e.outcome == 'failure']
        if failed_logins:
            failed_by_ip = defaultdict(int)
            for event in failed_logins:
                if event.ip_address:
                    failed_by_ip[str(event.ip_address)] += 1
            
            # Identify potential brute force attempts
            suspicious_ips = {ip: count for ip, count in failed_by_ip.items() if count > 5}
            
            if suspicious_ips:
                insights.append({
                    "type": "security_threat",
                    "severity": "high",
                    "title": "Potential Brute Force Attacks Detected",
                    "description": f"Detected {len(suspicious_ips)} IP addresses with multiple failed login attempts",
                    "details": {
                        "suspicious_ips": suspicious_ips,
                        "total_failed_attempts": len(failed_logins)
                    },
                    "recommendations": [
                        "Implement IP-based rate limiting",
                        "Consider blocking suspicious IP addresses",
                        "Enable account lockout policies",
                        "Implement multi-factor authentication"
                    ],
                    "confidence_score": 0.9
                })
        
        # Unusual activity hours
        night_events = [e for e in events if e.event_timestamp.hour < 6 or e.event_timestamp.hour > 22]
        if night_events and len(night_events) > len(events) * 0.1:  # More than 10% of events
            insights.append({
                "type": "anomaly",
                "severity": "medium",
                "title": "Unusual Activity Hours Detected",
                "description": f"Detected {len(night_events)} events during off-hours (10 PM - 6 AM)",
                "details": {
                    "off_hours_events": len(night_events),
                    "percentage": round((len(night_events) / len(events)) * 100, 2)
                },
                "recommendations": [
                    "Review off-hours access patterns",
                    "Implement time-based access controls",
                    "Require additional authentication for off-hours access"
                ],
                "confidence_score": 0.7
            })
        
        # High-risk events
        high_risk_events = [e for e in events if e.severity == 'critical']
        if high_risk_events:
            insights.append({
                "type": "critical_events",
                "severity": "critical",
                "title": f"{len(high_risk_events)} Critical Security Events",
                "description": "Critical security events require immediate attention",
                "details": {
                    "event_types": list(Counter(e.event_type for e in high_risk_events).keys()),
                    "affected_users": len(set(e.user_id for e in high_risk_events if e.user_id))
                },
                "recommendations": [
                    "Investigate all critical events immediately",
                    "Review user access permissions",
                    "Implement additional monitoring"
                ],
                "confidence_score": 1.0
            })
        
        return insights
    
    def _prepare_charts_data(self, events: List[AuditEvent], 
                           request: ReportRequest) -> Dict[str, Any]:
        """Prepare data for chart generation."""
        if not events:
            return {}
        
        # Event timeline data
        daily_counts = defaultdict(int)
        for event in events:
            date_key = event.event_timestamp.date().isoformat()
            daily_counts[date_key] += 1
        
        # Event type pie chart
        event_type_counts = Counter(e.event_type for e in events)
        
        # Severity bar chart
        severity_counts = Counter(e.severity for e in events)
        
        # Hourly heatmap
        hourly_counts = defaultdict(int)
        for event in events:
            hour = event.event_timestamp.hour
            hourly_counts[hour] += 1
        
        return {
            "timeline": {
                "type": "line",
                "data": {
                    "labels": sorted(daily_counts.keys()),
                    "values": [daily_counts[date] for date in sorted(daily_counts.keys())]
                },
                "title": "Events Over Time"
            },
            "event_types": {
                "type": "pie",
                "data": {
                    "labels": list(event_type_counts.keys()),
                    "values": list(event_type_counts.values())
                },
                "title": "Events by Type"
            },
            "severity": {
                "type": "bar",
                "data": {
                    "labels": list(severity_counts.keys()),
                    "values": list(severity_counts.values())
                },
                "title": "Events by Severity"
            },
            "hourly_activity": {
                "type": "heatmap",
                "data": {
                    "hours": list(range(24)),
                    "values": [hourly_counts[hour] for hour in range(24)]
                },
                "title": "Activity by Hour"
            }
        }
    
    def _serialize_audit_event(self, event: AuditEvent) -> Dict[str, Any]:
        """Serialize audit event for report output."""
        return {
            "id": str(event.id),
            "event_type": event.event_type,
            "severity": event.severity,
            "outcome": event.outcome,
            "user_id": str(event.user_id) if event.user_id else None,
            "username": event.username,
            "target_type": event.target_type,
            "target_id": str(event.target_id) if event.target_id else None,
            "description": event.event_description,
            "timestamp": event.event_timestamp.isoformat(),
            "ip_address": str(event.ip_address) if event.ip_address else None,
            "risk_score": event.risk_score,
            "contains_pii": event.contains_pii
        }


class SecurityAnalytics:
    """Specialized analytics for security events and threat detection."""
    
    def __init__(self, session: Session):
        self.session = session
        self.repos = RepositoryFactory(session)
    
    async def analyze_security_threats(self, request: ReportRequest) -> Dict[str, Any]:
        """Analyze security threats and generate threat intelligence."""
        # Get security-related events
        security_events = self._get_security_events(request)
        
        # Analyze different threat vectors
        brute_force_analysis = self._analyze_brute_force_attempts(security_events)
        anomaly_detection = self._detect_anomalies(security_events)
        privilege_escalation = self._detect_privilege_escalation(security_events)
        data_exfiltration = self._analyze_data_access_patterns(security_events)
        
        return {
            "threat_summary": {
                "total_security_events": len(security_events),
                "high_severity_events": sum(1 for e in security_events if e.severity == 'critical'),
                "unique_threat_sources": len(set(str(e.ip_address) for e in security_events if e.ip_address))
            },
            "brute_force": brute_force_analysis,
            "anomalies": anomaly_detection,
            "privilege_escalation": privilege_escalation,
            "data_access": data_exfiltration,
            "recommendations": self._generate_security_recommendations(security_events)
        }
    
    def _get_security_events(self, request: ReportRequest) -> List[AuditEvent]:
        """Get security-related audit events."""
        security_event_types = [
            'user_login', 'user_logout', 'unauthorized_access', 'security_breach',
            'permission_changed', 'api_key_created', 'api_key_revoked',
            'rate_limit_exceeded', 'compliance_violation'
        ]
        
        return self.session.query(AuditEvent).filter(
            AuditEvent.event_timestamp >= request.start_date,
            AuditEvent.event_timestamp <= request.end_date,
            AuditEvent.event_type.in_(security_event_types)
        ).all()
    
    def _analyze_brute_force_attempts(self, events: List[AuditEvent]) -> Dict[str, Any]:
        """Analyze potential brute force attacks."""
        failed_logins = [e for e in events if 'login' in e.event_type and e.outcome == 'failure']
        
        # Group by IP address
        ip_attempts = defaultdict(list)
        for event in failed_logins:
            if event.ip_address:
                ip_attempts[str(event.ip_address)].append(event)
        
        # Identify potential attacks (>5 attempts from same IP)
        potential_attacks = {}
        for ip, attempts in ip_attempts.items():
            if len(attempts) > 5:
                # Check if attempts are within short time window
                attempts.sort(key=lambda x: x.event_timestamp)
                time_span = attempts[-1].event_timestamp - attempts[0].event_timestamp
                
                potential_attacks[ip] = {
                    "attempts": len(attempts),
                    "time_span_minutes": time_span.total_seconds() / 60,
                    "targeted_users": list(set(a.username for a in attempts if a.username)),
                    "first_attempt": attempts[0].event_timestamp.isoformat(),
                    "last_attempt": attempts[-1].event_timestamp.isoformat()
                }
        
        return {
            "total_failed_logins": len(failed_logins),
            "suspicious_ips": len(potential_attacks),
            "attacks": potential_attacks
        }
    
    def _detect_anomalies(self, events: List[AuditEvent]) -> Dict[str, Any]:
        """Detect anomalous behavior patterns."""
        anomalies = []
        
        # Off-hours activity
        business_hours = range(9, 18)  # 9 AM to 6 PM
        off_hours_events = [e for e in events if e.event_timestamp.hour not in business_hours]
        
        if off_hours_events:
            anomalies.append({
                "type": "off_hours_activity",
                "severity": "medium",
                "count": len(off_hours_events),
                "description": f"{len(off_hours_events)} events detected outside business hours"
            })
        
        # Geolocation anomalies (simplified - would need actual geolocation data)
        ip_addresses = [str(e.ip_address) for e in events if e.ip_address]
        unique_ips = set(ip_addresses)
        
        if len(unique_ips) > 10:  # Threshold for multiple locations
            anomalies.append({
                "type": "multiple_locations",
                "severity": "medium",
                "count": len(unique_ips),
                "description": f"Activity detected from {len(unique_ips)} different IP addresses"
            })
        
        return {
            "total_anomalies": len(anomalies),
            "anomalies": anomalies
        }
    
    def _detect_privilege_escalation(self, events: List[AuditEvent]) -> Dict[str, Any]:
        """Detect potential privilege escalation attempts."""
        permission_events = [e for e in events if e.event_type == 'permission_changed']
        
        escalations = []
        for event in permission_events:
            # Simple heuristic: any permission change is potentially suspicious
            escalations.append({
                "user_id": str(event.user_id) if event.user_id else None,
                "timestamp": event.event_timestamp.isoformat(),
                "description": event.event_description
            })
        
        return {
            "potential_escalations": len(escalations),
            "events": escalations
        }
    
    def _analyze_data_access_patterns(self, events: List[AuditEvent]) -> Dict[str, Any]:
        """Analyze data access patterns for potential exfiltration."""
        data_events = [e for e in events if e.event_type in ['data_export', 'document_downloaded']]
        
        # Group by user
        user_access = defaultdict(list)
        for event in data_events:
            if event.user_id:
                user_access[event.user_id].append(event)
        
        # Identify heavy downloaders
        heavy_access = {}
        for user_id, access_events in user_access.items():
            if len(access_events) > 10:  # Threshold for heavy access
                heavy_access[str(user_id)] = {
                    "access_count": len(access_events),
                    "unique_resources": len(set(e.target_id for e in access_events if e.target_id)),
                    "time_span": (
                        access_events[-1].event_timestamp - access_events[0].event_timestamp
                    ).total_seconds() / 3600  # hours
                }
        
        return {
            "total_data_access": len(data_events),
            "heavy_access_users": len(heavy_access),
            "details": heavy_access
        }
    
    def _generate_security_recommendations(self, events: List[AuditEvent]) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        # Basic recommendations based on event patterns
        failed_logins = sum(1 for e in events if 'login' in e.event_type and e.outcome == 'failure')
        if failed_logins > 10:
            recommendations.append("Implement account lockout policies after failed login attempts")
            recommendations.append("Consider implementing multi-factor authentication")
        
        critical_events = sum(1 for e in events if e.severity == 'critical')
        if critical_events > 0:
            recommendations.append("Review and investigate all critical security events")
            recommendations.append("Implement real-time alerting for critical events")
        
        # Always include these general recommendations
        recommendations.extend([
            "Regularly review user access permissions",
            "Implement comprehensive logging for all system activities",
            "Conduct periodic security assessments",
            "Keep all system components updated and patched"
        ])
        
        return recommendations


class UsageAnalytics:
    """Analytics for system usage and performance metrics."""
    
    def __init__(self, session: Session):
        self.session = session
        self.repos = RepositoryFactory(session)
    
    async def analyze_system_usage(self, request: ReportRequest) -> Dict[str, Any]:
        """Analyze system usage patterns and performance metrics."""
        # Get various types of data
        user_activities = self._get_user_activities(request)
        system_events = self._get_system_events(request)
        document_processing = self._get_document_processing_stats(request)
        
        return {
            "usage_summary": self._calculate_usage_summary(user_activities),
            "performance_metrics": self._analyze_performance(system_events),
            "document_processing": document_processing,
            "capacity_analysis": self._analyze_capacity_trends(user_activities, system_events)
        }
    
    def _get_user_activities(self, request: ReportRequest) -> List[UserActivity]:
        """Get user activity data for the specified time range."""
        return self.session.query(UserActivity).filter(
            UserActivity.started_at >= request.start_date,
            UserActivity.started_at <= request.end_date
        ).all()
    
    def _get_system_events(self, request: ReportRequest) -> List[SystemEvent]:
        """Get system events for performance analysis."""
        return self.session.query(SystemEvent).filter(
            SystemEvent.event_timestamp >= request.start_date,
            SystemEvent.event_timestamp <= request.end_date
        ).all()
    
    def _get_document_processing_stats(self, request: ReportRequest) -> Dict[str, Any]:
        """Get document processing statistics."""
        # This would query document processing logs
        # For now, return placeholder data
        return {
            "total_documents_processed": 0,
            "average_processing_time_ms": 0,
            "success_rate": 100.0
        }
    
    def _calculate_usage_summary(self, activities: List[UserActivity]) -> Dict[str, Any]:
        """Calculate usage summary statistics."""
        if not activities:
            return {"total_activities": 0}
        
        # Activity type distribution
        activity_types = Counter(a.activity_type for a in activities)
        
        # Response time analysis
        response_times = [a.response_time_ms for a in activities if a.response_time_ms]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        return {
            "total_activities": len(activities),
            "unique_users": len(set(a.user_id for a in activities)),
            "activity_types": dict(activity_types),
            "average_response_time_ms": round(avg_response_time, 2),
            "peak_hour": self._find_peak_activity_hour(activities)
        }
    
    def _find_peak_activity_hour(self, activities: List[UserActivity]) -> int:
        """Find the hour with most activity."""
        hourly_counts = defaultdict(int)
        for activity in activities:
            hour = activity.started_at.hour
            hourly_counts[hour] += 1
        
        return max(hourly_counts.items(), key=lambda x: x[1])[0] if hourly_counts else 0
    
    def _analyze_performance(self, events: List[SystemEvent]) -> Dict[str, Any]:
        """Analyze system performance metrics."""
        if not events:
            return {}
        
        error_events = [e for e in events if e.severity in ['high', 'critical']]
        
        return {
            "total_system_events": len(events),
            "error_events": len(error_events),
            "error_rate": (len(error_events) / len(events)) * 100 if events else 0,
            "service_availability": self._calculate_availability(events)
        }
    
    def _calculate_availability(self, events: List[SystemEvent]) -> float:
        """Calculate service availability percentage."""
        # Simplified availability calculation
        downtime_events = [e for e in events if 'error' in e.event_type.lower()]
        uptime_percentage = ((len(events) - len(downtime_events)) / len(events)) * 100 if events else 100.0
        return round(uptime_percentage, 2)
    
    def _analyze_capacity_trends(self, activities: List[UserActivity], 
                               events: List[SystemEvent]) -> Dict[str, Any]:
        """Analyze capacity and resource utilization trends."""
        # Memory and CPU usage from system events
        memory_usage = []
        cpu_usage = []
        
        for event in events:
            if event.memory_usage_mb:
                memory_usage.append(event.memory_usage_mb)
            if event.cpu_usage_percent:
                cpu_usage.append(float(event.cpu_usage_percent))
        
        return {
            "resource_utilization": {
                "average_memory_mb": round(sum(memory_usage) / len(memory_usage), 2) if memory_usage else 0,
                "peak_memory_mb": max(memory_usage) if memory_usage else 0,
                "average_cpu_percent": round(sum(cpu_usage) / len(cpu_usage), 2) if cpu_usage else 0,
                "peak_cpu_percent": max(cpu_usage) if cpu_usage else 0
            },
            "growth_indicators": {
                "activity_growth_rate": self._calculate_growth_rate(activities),
                "capacity_recommendations": self._generate_capacity_recommendations(activities, events)
            }
        }
    
    def _calculate_growth_rate(self, activities: List[UserActivity]) -> float:
        """Calculate activity growth rate."""
        # Simplified growth rate calculation
        if len(activities) < 2:
            return 0.0
        
        # Sort by date and compare first half vs second half
        sorted_activities = sorted(activities, key=lambda x: x.started_at)
        mid_point = len(sorted_activities) // 2
        
        first_half = sorted_activities[:mid_point]
        second_half = sorted_activities[mid_point:]
        
        if len(first_half) == 0:
            return 0.0
        
        growth_rate = ((len(second_half) - len(first_half)) / len(first_half)) * 100
        return round(growth_rate, 2)
    
    def _generate_capacity_recommendations(self, activities: List[UserActivity], 
                                         events: List[SystemEvent]) -> List[str]:
        """Generate capacity planning recommendations."""
        recommendations = []
        
        # Memory usage recommendations
        memory_usage = [e.memory_usage_mb for e in events if e.memory_usage_mb]
        if memory_usage:
            avg_memory = sum(memory_usage) / len(memory_usage)
            if avg_memory > 4000:  # 4GB threshold
                recommendations.append("Consider increasing system memory allocation")
        
        # Activity volume recommendations
        if len(activities) > 10000:
            recommendations.append("High activity volume detected - consider scaling infrastructure")
        
        # General recommendations
        recommendations.extend([
            "Monitor resource utilization trends regularly",
            "Implement automated scaling policies",
            "Plan for capacity upgrades based on growth patterns"
        ])
        
        return recommendations