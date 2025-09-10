"""
Enhanced HIPAA Compliance Reporting and Monitoring System
Provides comprehensive reporting, monitoring, and alerting for HIPAA compliance activities.
"""
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import uuid
from datetime import datetime, timedelta
import statistics
from pathlib import Path
import asyncio
import logging
from collections import defaultdict, Counter

from src.core.compliance.hipaa_safe_harbor import SafeHarborProcessor, DeidentificationResult
from src.core.compliance.hipaa_baa import HIPAABAAManager, BusinessAssociate, ComplianceIncident
from src.core.compliance.hipaa_security_rule import HIPAASecurityRuleManager, SecurityAssessment
from src.core.compliance.hipaa_privacy_rule import HIPAAPrivacyRuleManager, IndividualRightsRequest
from src.core.database.db_manager import DatabaseManager


class ComplianceMetricType(Enum):
    """Types of compliance metrics"""
    DEIDENTIFICATION_ACCURACY = "deidentification_accuracy"
    PROCESSING_VOLUME = "processing_volume"
    SECURITY_SCORE = "security_score"
    PRIVACY_COMPLIANCE = "privacy_compliance"
    BAA_COMPLIANCE = "baa_compliance"
    INCIDENT_RATE = "incident_rate"
    AUDIT_TRAIL_COMPLETENESS = "audit_trail_completeness"
    RESPONSE_TIME = "response_time"
    SYSTEM_AVAILABILITY = "system_availability"
    RISK_SCORE = "risk_score"


class ReportType(Enum):
    """Types of compliance reports"""
    DAILY_SUMMARY = "daily_summary"
    WEEKLY_COMPLIANCE = "weekly_compliance"
    MONTHLY_AUDIT = "monthly_audit"
    QUARTERLY_ASSESSMENT = "quarterly_assessment"
    ANNUAL_REVIEW = "annual_review"
    INCIDENT_REPORT = "incident_report"
    SECURITY_ASSESSMENT = "security_assessment"
    PERFORMANCE_METRICS = "performance_metrics"
    REGULATORY_FILING = "regulatory_filing"


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ComplianceMetric:
    """Individual compliance metric"""
    metric_type: ComplianceMetricType
    value: float
    timestamp: datetime
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    threshold_min: Optional[float] = None
    threshold_max: Optional[float] = None
    unit: str = ""
    
    @property
    def is_within_threshold(self) -> bool:
        """Check if metric is within acceptable thresholds"""
        if self.threshold_min is not None and self.value < self.threshold_min:
            return False
        if self.threshold_max is not None and self.value > self.threshold_max:
            return False
        return True
    
    @property
    def threshold_deviation(self) -> Optional[float]:
        """Calculate deviation from thresholds"""
        if self.threshold_min is not None and self.value < self.threshold_min:
            return (self.value - self.threshold_min) / self.threshold_min
        if self.threshold_max is not None and self.value > self.threshold_max:
            return (self.value - self.threshold_max) / self.threshold_max
        return None


@dataclass
class ComplianceAlert:
    """Compliance monitoring alert"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: AlertSeverity = AlertSeverity.LOW
    title: str = ""
    description: str = ""
    metric_type: Optional[ComplianceMetricType] = None
    trigger_value: Optional[float] = None
    threshold_value: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.now)
    source_system: str = ""
    affected_components: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    resolved: bool = False
    resolved_timestamp: Optional[datetime] = None
    resolution_notes: str = ""
    
    def resolve(self, notes: str = ""):
        """Mark alert as resolved"""
        self.resolved = True
        self.resolved_timestamp = datetime.now()
        self.resolution_notes = notes


@dataclass
class ComplianceReport:
    """Comprehensive compliance report"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    report_type: ReportType
    title: str
    description: str
    generated_timestamp: datetime = field(default_factory=datetime.now)
    period_start: datetime
    period_end: datetime
    metrics: List[ComplianceMetric] = field(default_factory=list)
    alerts: List[ComplianceAlert] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    compliance_score: Optional[float] = None
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary for serialization"""
        return {
            'id': self.id,
            'report_type': self.report_type.value,
            'title': self.title,
            'description': self.description,
            'generated_timestamp': self.generated_timestamp.isoformat(),
            'period_start': self.period_start.isoformat(),
            'period_end': self.period_end.isoformat(),
            'metrics': [
                {
                    'type': m.metric_type.value,
                    'value': m.value,
                    'timestamp': m.timestamp.isoformat(),
                    'source': m.source,
                    'unit': m.unit,
                    'within_threshold': m.is_within_threshold,
                    'metadata': m.metadata
                } for m in self.metrics
            ],
            'alerts': [
                {
                    'id': a.id,
                    'severity': a.severity.value,
                    'title': a.title,
                    'description': a.description,
                    'timestamp': a.timestamp.isoformat(),
                    'resolved': a.resolved,
                    'recommended_actions': a.recommended_actions
                } for a in self.alerts
            ],
            'summary': self.summary,
            'recommendations': self.recommendations,
            'compliance_score': self.compliance_score,
            'risk_assessment': self.risk_assessment
        }


class ComplianceReporter:
    """Enhanced HIPAA compliance reporting and monitoring system"""
    
    def __init__(self, 
                 db_manager: DatabaseManager,
                 safe_harbor_processor: SafeHarborProcessor,
                 baa_manager: HIPAABAAManager,
                 security_manager: HIPAASecurityRuleManager,
                 privacy_manager: HIPAAPrivacyRuleManager):
        self.db_manager = db_manager
        self.safe_harbor = safe_harbor_processor
        self.baa_manager = baa_manager
        self.security_manager = security_manager
        self.privacy_manager = privacy_manager
        
        self.logger = logging.getLogger(__name__)
        self.active_alerts: List[ComplianceAlert] = []
        self.metrics_cache: Dict[str, List[ComplianceMetric]] = defaultdict(list)
        
        # Define compliance thresholds
        self.compliance_thresholds = {
            ComplianceMetricType.DEIDENTIFICATION_ACCURACY: {'min': 0.95},
            ComplianceMetricType.SECURITY_SCORE: {'min': 0.80},
            ComplianceMetricType.PRIVACY_COMPLIANCE: {'min': 0.95},
            ComplianceMetricType.BAA_COMPLIANCE: {'min': 1.0},
            ComplianceMetricType.INCIDENT_RATE: {'max': 0.01},  # 1% max
            ComplianceMetricType.AUDIT_TRAIL_COMPLETENESS: {'min': 0.99},
            ComplianceMetricType.RESPONSE_TIME: {'max': 30.0},  # seconds
            ComplianceMetricType.SYSTEM_AVAILABILITY: {'min': 0.999},  # 99.9%
            ComplianceMetricType.RISK_SCORE: {'max': 0.30}  # Low to medium risk
        }
    
    def collect_metrics(self, period_start: datetime, period_end: datetime) -> List[ComplianceMetric]:
        """Collect all compliance metrics for specified period"""
        metrics = []
        
        # De-identification accuracy metrics
        deident_metrics = self._collect_deidentification_metrics(period_start, period_end)
        metrics.extend(deident_metrics)
        
        # Security metrics
        security_metrics = self._collect_security_metrics(period_start, period_end)
        metrics.extend(security_metrics)
        
        # Privacy compliance metrics
        privacy_metrics = self._collect_privacy_metrics(period_start, period_end)
        metrics.extend(privacy_metrics)
        
        # BAA compliance metrics
        baa_metrics = self._collect_baa_metrics(period_start, period_end)
        metrics.extend(baa_metrics)
        
        # System performance metrics
        performance_metrics = self._collect_performance_metrics(period_start, period_end)
        metrics.extend(performance_metrics)
        
        # Risk assessment metrics
        risk_metrics = self._collect_risk_metrics(period_start, period_end)
        metrics.extend(risk_metrics)
        
        # Cache metrics for monitoring
        for metric in metrics:
            self.metrics_cache[metric.metric_type.value].append(metric)
        
        return metrics
    
    def _collect_deidentification_metrics(self, start: datetime, end: datetime) -> List[ComplianceMetric]:
        """Collect de-identification accuracy metrics"""
        metrics = []
        
        # Query processed documents from database
        processed_docs = self.db_manager.query_processed_documents(start, end)
        
        if processed_docs:
            # Calculate accuracy metrics
            total_docs = len(processed_docs)
            compliant_docs = sum(1 for doc in processed_docs 
                               if doc.get('compliance_level') == 'HIPAA_COMPLIANT')
            accuracy = compliant_docs / total_docs if total_docs > 0 else 0.0
            
            # Average confidence score
            confidence_scores = [doc.get('confidence_score', 0.0) for doc in processed_docs]
            avg_confidence = statistics.mean(confidence_scores) if confidence_scores else 0.0
            
            # Processing volume
            volume_metric = ComplianceMetric(
                metric_type=ComplianceMetricType.PROCESSING_VOLUME,
                value=float(total_docs),
                timestamp=datetime.now(),
                source="deidentification_processor",
                unit="documents"
            )
            
            # Accuracy metric
            accuracy_metric = ComplianceMetric(
                metric_type=ComplianceMetricType.DEIDENTIFICATION_ACCURACY,
                value=accuracy,
                timestamp=datetime.now(),
                source="deidentification_processor",
                threshold_min=self.compliance_thresholds[ComplianceMetricType.DEIDENTIFICATION_ACCURACY]['min'],
                unit="percentage",
                metadata={
                    'total_documents': total_docs,
                    'compliant_documents': compliant_docs,
                    'average_confidence': avg_confidence
                }
            )
            
            metrics.extend([volume_metric, accuracy_metric])
        
        return metrics
    
    def _collect_security_metrics(self, start: datetime, end: datetime) -> List[ComplianceMetric]:
        """Collect security compliance metrics"""
        metrics = []
        
        # Get recent security assessments
        security_assessments = self.security_manager.get_assessments_in_period(start, end)
        
        if security_assessments:
            scores = [assessment.overall_score for assessment in security_assessments]
            avg_security_score = statistics.mean(scores)
            
            security_metric = ComplianceMetric(
                metric_type=ComplianceMetricType.SECURITY_SCORE,
                value=avg_security_score,
                timestamp=datetime.now(),
                source="security_rule_manager",
                threshold_min=self.compliance_thresholds[ComplianceMetricType.SECURITY_SCORE]['min'],
                unit="score",
                metadata={
                    'assessments_count': len(security_assessments),
                    'min_score': min(scores),
                    'max_score': max(scores)
                }
            )
            
            metrics.append(security_metric)
        
        return metrics
    
    def _collect_privacy_metrics(self, start: datetime, end: datetime) -> List[ComplianceMetric]:
        """Collect privacy compliance metrics"""
        metrics = []
        
        # Get individual rights requests
        rights_requests = self.privacy_manager.get_requests_in_period(start, end)
        
        if rights_requests:
            total_requests = len(rights_requests)
            completed_requests = sum(1 for req in rights_requests 
                                   if req.status == 'COMPLETED')
            compliance_rate = completed_requests / total_requests if total_requests > 0 else 0.0
            
            privacy_metric = ComplianceMetric(
                metric_type=ComplianceMetricType.PRIVACY_COMPLIANCE,
                value=compliance_rate,
                timestamp=datetime.now(),
                source="privacy_rule_manager",
                threshold_min=self.compliance_thresholds[ComplianceMetricType.PRIVACY_COMPLIANCE]['min'],
                unit="percentage",
                metadata={
                    'total_requests': total_requests,
                    'completed_requests': completed_requests,
                    'request_types': dict(Counter([req.request_type.value for req in rights_requests]))
                }
            )
            
            metrics.append(privacy_metric)
        
        return metrics
    
    def _collect_baa_metrics(self, start: datetime, end: datetime) -> List[ComplianceMetric]:
        """Collect BAA compliance metrics"""
        metrics = []
        
        # Get BAA compliance data
        business_associates = self.baa_manager.get_all_business_associates()
        incidents = self.baa_manager.get_incidents_in_period(start, end)
        
        if business_associates:
            compliant_bas = sum(1 for ba in business_associates 
                              if ba.compliance_status == 'COMPLIANT')
            total_bas = len(business_associates)
            compliance_rate = compliant_bas / total_bas if total_bas > 0 else 0.0
            
            baa_metric = ComplianceMetric(
                metric_type=ComplianceMetricType.BAA_COMPLIANCE,
                value=compliance_rate,
                timestamp=datetime.now(),
                source="baa_manager",
                threshold_min=self.compliance_thresholds[ComplianceMetricType.BAA_COMPLIANCE]['min'],
                unit="percentage",
                metadata={
                    'total_business_associates': total_bas,
                    'compliant_business_associates': compliant_bas,
                    'incidents_count': len(incidents)
                }
            )
            
            metrics.append(baa_metric)
        
        # Incident rate metric
        if incidents:
            incident_rate = len(incidents) / max(1, len(business_associates))
            
            incident_metric = ComplianceMetric(
                metric_type=ComplianceMetricType.INCIDENT_RATE,
                value=incident_rate,
                timestamp=datetime.now(),
                source="baa_manager",
                threshold_max=self.compliance_thresholds[ComplianceMetricType.INCIDENT_RATE]['max'],
                unit="incidents per BA",
                metadata={
                    'total_incidents': len(incidents),
                    'incident_types': dict(Counter([inc.incident_type for inc in incidents]))
                }
            )
            
            metrics.append(incident_metric)
        
        return metrics
    
    def _collect_performance_metrics(self, start: datetime, end: datetime) -> List[ComplianceMetric]:
        """Collect system performance metrics"""
        metrics = []
        
        # Query performance data from database
        performance_logs = self.db_manager.query_performance_logs(start, end)
        
        if performance_logs:
            # Response time metric
            response_times = [log.get('response_time', 0.0) for log in performance_logs]
            avg_response_time = statistics.mean(response_times)
            
            response_metric = ComplianceMetric(
                metric_type=ComplianceMetricType.RESPONSE_TIME,
                value=avg_response_time,
                timestamp=datetime.now(),
                source="performance_monitor",
                threshold_max=self.compliance_thresholds[ComplianceMetricType.RESPONSE_TIME]['max'],
                unit="seconds",
                metadata={
                    'total_requests': len(performance_logs),
                    'min_response_time': min(response_times),
                    'max_response_time': max(response_times),
                    'p95_response_time': statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else max(response_times)
                }
            )
            
            metrics.append(response_metric)
            
            # System availability metric
            uptime_records = [log for log in performance_logs if log.get('status') == 'UP']
            availability = len(uptime_records) / len(performance_logs) if performance_logs else 0.0
            
            availability_metric = ComplianceMetric(
                metric_type=ComplianceMetricType.SYSTEM_AVAILABILITY,
                value=availability,
                timestamp=datetime.now(),
                source="performance_monitor",
                threshold_min=self.compliance_thresholds[ComplianceMetricType.SYSTEM_AVAILABILITY]['min'],
                unit="percentage",
                metadata={
                    'total_checks': len(performance_logs),
                    'uptime_checks': len(uptime_records)
                }
            )
            
            metrics.append(availability_metric)
        
        return metrics
    
    def _collect_risk_metrics(self, start: datetime, end: datetime) -> List[ComplianceMetric]:
        """Collect risk assessment metrics"""
        metrics = []
        
        # Calculate composite risk score
        recent_metrics = []
        for metric_list in self.metrics_cache.values():
            recent_metrics.extend([m for m in metric_list if start <= m.timestamp <= end])
        
        if recent_metrics:
            # Count threshold violations
            threshold_violations = sum(1 for m in recent_metrics if not m.is_within_threshold)
            violation_rate = threshold_violations / len(recent_metrics)
            
            # Calculate weighted risk score based on violations and severity
            risk_score = min(violation_rate * 2, 1.0)  # Cap at 1.0
            
            risk_metric = ComplianceMetric(
                metric_type=ComplianceMetricType.RISK_SCORE,
                value=risk_score,
                timestamp=datetime.now(),
                source="compliance_reporter",
                threshold_max=self.compliance_thresholds[ComplianceMetricType.RISK_SCORE]['max'],
                unit="risk score",
                metadata={
                    'total_metrics': len(recent_metrics),
                    'threshold_violations': threshold_violations,
                    'violation_rate': violation_rate
                }
            )
            
            metrics.append(risk_metric)
        
        return metrics
    
    def monitor_compliance(self) -> List[ComplianceAlert]:
        """Monitor compliance metrics and generate alerts"""
        new_alerts = []
        current_time = datetime.now()
        
        # Check recent metrics for threshold violations
        recent_period = current_time - timedelta(hours=24)
        recent_metrics = self.collect_metrics(recent_period, current_time)
        
        for metric in recent_metrics:
            if not metric.is_within_threshold:
                alert = self._create_threshold_alert(metric)
                new_alerts.append(alert)
                self.logger.warning(f"Compliance threshold violated: {alert.title}")
        
        # Check for trend-based alerts
        trend_alerts = self._check_trend_alerts(recent_metrics)
        new_alerts.extend(trend_alerts)
        
        # Add new alerts to active list
        self.active_alerts.extend(new_alerts)
        
        return new_alerts
    
    def _create_threshold_alert(self, metric: ComplianceMetric) -> ComplianceAlert:
        """Create alert for threshold violation"""
        deviation = metric.threshold_deviation or 0.0
        
        if abs(deviation) > 0.5:  # > 50% deviation
            severity = AlertSeverity.CRITICAL
        elif abs(deviation) > 0.2:  # > 20% deviation
            severity = AlertSeverity.HIGH
        else:
            severity = AlertSeverity.MEDIUM
        
        recommended_actions = []
        if metric.metric_type == ComplianceMetricType.DEIDENTIFICATION_ACCURACY:
            recommended_actions = [
                "Review and retrain de-identification models",
                "Audit recent document processing for accuracy issues",
                "Check for changes in document types or formats"
            ]
        elif metric.metric_type == ComplianceMetricType.SECURITY_SCORE:
            recommended_actions = [
                "Conduct immediate security assessment",
                "Review security control implementations",
                "Check for security policy violations"
            ]
        elif metric.metric_type == ComplianceMetricType.RESPONSE_TIME:
            recommended_actions = [
                "Investigate system performance bottlenecks",
                "Check resource utilization (CPU, memory, disk)",
                "Review recent system changes or deployments"
            ]
        
        alert = ComplianceAlert(
            severity=severity,
            title=f"{metric.metric_type.value.replace('_', ' ').title()} Threshold Violation",
            description=f"Metric value {metric.value:.3f} {metric.unit} violates threshold. Deviation: {deviation:.1%}",
            metric_type=metric.metric_type,
            trigger_value=metric.value,
            threshold_value=metric.threshold_min or metric.threshold_max,
            source_system=metric.source,
            recommended_actions=recommended_actions
        )
        
        return alert
    
    def _check_trend_alerts(self, metrics: List[ComplianceMetric]) -> List[ComplianceAlert]:
        """Check for trending issues across metrics"""
        alerts = []
        
        # Group metrics by type for trend analysis
        metrics_by_type = defaultdict(list)
        for metric in metrics:
            metrics_by_type[metric.metric_type].append(metric)
        
        for metric_type, metric_list in metrics_by_type.items():
            if len(metric_list) >= 3:  # Need at least 3 points for trend
                values = [m.value for m in sorted(metric_list, key=lambda x: x.timestamp)]
                
                # Calculate trend (simple linear)
                n = len(values)
                x_vals = list(range(n))
                trend = sum((x_vals[i] - statistics.mean(x_vals)) * (values[i] - statistics.mean(values))
                           for i in range(n)) / sum((x - statistics.mean(x_vals))**2 for x in x_vals)
                
                # Check for significant negative trends in positive metrics
                if metric_type in [ComplianceMetricType.DEIDENTIFICATION_ACCURACY,
                                  ComplianceMetricType.SECURITY_SCORE,
                                  ComplianceMetricType.PRIVACY_COMPLIANCE] and trend < -0.05:
                    
                    alert = ComplianceAlert(
                        severity=AlertSeverity.MEDIUM,
                        title=f"Declining Trend in {metric_type.value.replace('_', ' ').title()}",
                        description=f"Metric showing declining trend over recent period. Trend coefficient: {trend:.4f}",
                        metric_type=metric_type,
                        source_system="compliance_monitor",
                        recommended_actions=[
                            "Investigate root cause of declining performance",
                            "Review recent system or process changes",
                            "Consider implementing corrective measures"
                        ]
                    )
                    alerts.append(alert)
        
        return alerts
    
    def generate_report(self, 
                       report_type: ReportType,
                       period_start: datetime,
                       period_end: datetime,
                       include_recommendations: bool = True) -> ComplianceReport:
        """Generate comprehensive compliance report"""
        
        # Collect metrics for the period
        metrics = self.collect_metrics(period_start, period_end)
        
        # Get relevant alerts
        period_alerts = [alert for alert in self.active_alerts
                        if period_start <= alert.timestamp <= period_end]
        
        # Generate report based on type
        if report_type == ReportType.DAILY_SUMMARY:
            return self._generate_daily_summary(period_start, period_end, metrics, period_alerts)
        elif report_type == ReportType.WEEKLY_COMPLIANCE:
            return self._generate_weekly_compliance(period_start, period_end, metrics, period_alerts)
        elif report_type == ReportType.MONTHLY_AUDIT:
            return self._generate_monthly_audit(period_start, period_end, metrics, period_alerts)
        elif report_type == ReportType.QUARTERLY_ASSESSMENT:
            return self._generate_quarterly_assessment(period_start, period_end, metrics, period_alerts)
        elif report_type == ReportType.ANNUAL_REVIEW:
            return self._generate_annual_review(period_start, period_end, metrics, period_alerts)
        else:
            return self._generate_generic_report(report_type, period_start, period_end, metrics, period_alerts)
    
    def _generate_daily_summary(self, 
                               start: datetime, 
                               end: datetime,
                               metrics: List[ComplianceMetric],
                               alerts: List[ComplianceAlert]) -> ComplianceReport:
        """Generate daily compliance summary"""
        
        # Calculate overall compliance score
        compliance_score = self._calculate_compliance_score(metrics)
        
        # Summarize key metrics
        summary = {
            'processing_volume': sum(m.value for m in metrics 
                                   if m.metric_type == ComplianceMetricType.PROCESSING_VOLUME),
            'average_accuracy': statistics.mean([m.value for m in metrics 
                                               if m.metric_type == ComplianceMetricType.DEIDENTIFICATION_ACCURACY] or [0]),
            'security_score': statistics.mean([m.value for m in metrics 
                                             if m.metric_type == ComplianceMetricType.SECURITY_SCORE] or [0]),
            'active_alerts': len([a for a in alerts if not a.resolved]),
            'critical_alerts': len([a for a in alerts if a.severity == AlertSeverity.CRITICAL and not a.resolved])
        }
        
        # Generate recommendations
        recommendations = []
        if summary['critical_alerts'] > 0:
            recommendations.append("Address critical alerts immediately to maintain compliance")
        if summary['average_accuracy'] < 0.95:
            recommendations.append("Review de-identification accuracy - below HIPAA requirements")
        if summary['security_score'] < 0.80:
            recommendations.append("Conduct security assessment to improve compliance posture")
        
        report = ComplianceReport(
            report_type=ReportType.DAILY_SUMMARY,
            title=f"Daily HIPAA Compliance Summary - {start.strftime('%Y-%m-%d')}",
            description="Daily overview of HIPAA compliance metrics and system performance",
            period_start=start,
            period_end=end,
            metrics=metrics,
            alerts=alerts,
            summary=summary,
            recommendations=recommendations,
            compliance_score=compliance_score
        )
        
        return report
    
    def _generate_weekly_compliance(self,
                                   start: datetime,
                                   end: datetime,
                                   metrics: List[ComplianceMetric],
                                   alerts: List[ComplianceAlert]) -> ComplianceReport:
        """Generate weekly compliance report"""
        
        compliance_score = self._calculate_compliance_score(metrics)
        
        # Weekly trend analysis
        daily_metrics = defaultdict(list)
        for metric in metrics:
            day_key = metric.timestamp.strftime('%Y-%m-%d')
            daily_metrics[day_key].append(metric)
        
        # Calculate week-over-week changes
        summary = {
            'total_documents_processed': sum(m.value for m in metrics 
                                           if m.metric_type == ComplianceMetricType.PROCESSING_VOLUME),
            'average_daily_processing': statistics.mean([sum(m.value for m in day_metrics 
                                                           if m.metric_type == ComplianceMetricType.PROCESSING_VOLUME)
                                                        for day_metrics in daily_metrics.values()]),
            'compliance_incidents': len([a for a in alerts if a.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]]),
            'system_availability': statistics.mean([m.value for m in metrics 
                                                   if m.metric_type == ComplianceMetricType.SYSTEM_AVAILABILITY] or [0]) * 100,
            'weekly_trends': self._calculate_weekly_trends(daily_metrics)
        }
        
        recommendations = self._generate_weekly_recommendations(summary, alerts)
        
        report = ComplianceReport(
            report_type=ReportType.WEEKLY_COMPLIANCE,
            title=f"Weekly HIPAA Compliance Report - Week of {start.strftime('%Y-%m-%d')}",
            description="Weekly compliance performance analysis and trend monitoring",
            period_start=start,
            period_end=end,
            metrics=metrics,
            alerts=alerts,
            summary=summary,
            recommendations=recommendations,
            compliance_score=compliance_score
        )
        
        return report
    
    def _calculate_compliance_score(self, metrics: List[ComplianceMetric]) -> float:
        """Calculate overall compliance score from metrics"""
        if not metrics:
            return 0.0
        
        # Weight different metric types
        weights = {
            ComplianceMetricType.DEIDENTIFICATION_ACCURACY: 0.3,
            ComplianceMetricType.SECURITY_SCORE: 0.25,
            ComplianceMetricType.PRIVACY_COMPLIANCE: 0.2,
            ComplianceMetricType.BAA_COMPLIANCE: 0.15,
            ComplianceMetricType.AUDIT_TRAIL_COMPLETENESS: 0.1
        }
        
        weighted_scores = []
        for metric_type, weight in weights.items():
            type_metrics = [m for m in metrics if m.metric_type == metric_type]
            if type_metrics:
                avg_score = statistics.mean([m.value for m in type_metrics])
                weighted_scores.append(avg_score * weight)
        
        return sum(weighted_scores) if weighted_scores else 0.0
    
    def _calculate_weekly_trends(self, daily_metrics: Dict[str, List[ComplianceMetric]]) -> Dict[str, str]:
        """Calculate weekly trends for key metrics"""
        trends = {}
        
        metric_types = [ComplianceMetricType.DEIDENTIFICATION_ACCURACY, 
                       ComplianceMetricType.PROCESSING_VOLUME,
                       ComplianceMetricType.SECURITY_SCORE]
        
        for metric_type in metric_types:
            daily_values = []
            for day_metrics in daily_metrics.values():
                day_values = [m.value for m in day_metrics if m.metric_type == metric_type]
                if day_values:
                    daily_values.append(statistics.mean(day_values))
            
            if len(daily_values) >= 2:
                if daily_values[-1] > daily_values[0]:
                    trends[metric_type.value] = "improving"
                elif daily_values[-1] < daily_values[0]:
                    trends[metric_type.value] = "declining"
                else:
                    trends[metric_type.value] = "stable"
            else:
                trends[metric_type.value] = "insufficient_data"
        
        return trends
    
    def _generate_weekly_recommendations(self, 
                                        summary: Dict[str, Any], 
                                        alerts: List[ComplianceAlert]) -> List[str]:
        """Generate weekly recommendations based on performance"""
        recommendations = []
        
        if summary.get('system_availability', 100) < 99.5:
            recommendations.append("Investigate system availability issues to maintain HIPAA uptime requirements")
        
        if summary.get('compliance_incidents', 0) > 2:
            recommendations.append("High number of compliance incidents - review processes and implement preventive measures")
        
        trends = summary.get('weekly_trends', {})
        for metric, trend in trends.items():
            if trend == "declining":
                recommendations.append(f"Address declining trend in {metric.replace('_', ' ')}")
        
        unresolved_criticals = [a for a in alerts 
                              if a.severity == AlertSeverity.CRITICAL and not a.resolved]
        if unresolved_criticals:
            recommendations.append(f"Resolve {len(unresolved_criticals)} critical compliance alerts")
        
        return recommendations
    
    def _generate_generic_report(self,
                                report_type: ReportType,
                                start: datetime,
                                end: datetime,
                                metrics: List[ComplianceMetric],
                                alerts: List[ComplianceAlert]) -> ComplianceReport:
        """Generate generic compliance report"""
        
        compliance_score = self._calculate_compliance_score(metrics)
        
        summary = {
            'period_days': (end - start).days,
            'total_metrics': len(metrics),
            'total_alerts': len(alerts),
            'compliance_score': compliance_score,
            'metrics_by_type': dict(Counter([m.metric_type.value for m in metrics]))
        }
        
        report = ComplianceReport(
            report_type=report_type,
            title=f"HIPAA Compliance Report - {report_type.value.replace('_', ' ').title()}",
            description=f"Compliance analysis for period {start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}",
            period_start=start,
            period_end=end,
            metrics=metrics,
            alerts=alerts,
            summary=summary,
            compliance_score=compliance_score
        )
        
        return report
    
    def export_report(self, report: ComplianceReport, format: str = "json") -> str:
        """Export report in specified format"""
        if format.lower() == "json":
            return json.dumps(report.to_dict(), indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def get_compliance_dashboard_data(self) -> Dict[str, Any]:
        """Get real-time compliance dashboard data"""
        current_time = datetime.now()
        last_24h = current_time - timedelta(hours=24)
        
        recent_metrics = self.collect_metrics(last_24h, current_time)
        active_alerts = [a for a in self.active_alerts if not a.resolved]
        
        dashboard_data = {
            'current_compliance_score': self._calculate_compliance_score(recent_metrics),
            'active_alerts_count': len(active_alerts),
            'critical_alerts_count': len([a for a in active_alerts if a.severity == AlertSeverity.CRITICAL]),
            'system_status': 'healthy' if len(active_alerts) == 0 else 'degraded' if len([a for a in active_alerts if a.severity == AlertSeverity.CRITICAL]) == 0 else 'critical',
            'recent_processing_volume': sum(m.value for m in recent_metrics if m.metric_type == ComplianceMetricType.PROCESSING_VOLUME),
            'current_accuracy': statistics.mean([m.value for m in recent_metrics if m.metric_type == ComplianceMetricType.DEIDENTIFICATION_ACCURACY] or [0]),
            'recent_alerts': [
                {
                    'id': a.id,
                    'severity': a.severity.value,
                    'title': a.title,
                    'timestamp': a.timestamp.isoformat()
                } for a in sorted(active_alerts, key=lambda x: x.timestamp, reverse=True)[:10]
            ],
            'metric_trends': self._get_metric_trends(recent_metrics),
            'last_updated': current_time.isoformat()
        }
        
        return dashboard_data
    
    def _get_metric_trends(self, metrics: List[ComplianceMetric]) -> Dict[str, Any]:
        """Get current metric trends for dashboard"""
        trends = {}
        
        metric_types = [ComplianceMetricType.DEIDENTIFICATION_ACCURACY,
                       ComplianceMetricType.SECURITY_SCORE,
                       ComplianceMetricType.RESPONSE_TIME]
        
        for metric_type in metric_types:
            type_metrics = [m for m in metrics if m.metric_type == metric_type]
            if len(type_metrics) >= 2:
                sorted_metrics = sorted(type_metrics, key=lambda x: x.timestamp)
                recent_avg = statistics.mean([m.value for m in sorted_metrics[-3:]])
                earlier_avg = statistics.mean([m.value for m in sorted_metrics[:3]])
                
                if recent_avg > earlier_avg * 1.05:
                    trend = "up"
                elif recent_avg < earlier_avg * 0.95:
                    trend = "down"
                else:
                    trend = "stable"
                
                trends[metric_type.value] = {
                    'direction': trend,
                    'current_value': recent_avg,
                    'change_percent': ((recent_avg - earlier_avg) / earlier_avg * 100) if earlier_avg > 0 else 0
                }
        
        return trends