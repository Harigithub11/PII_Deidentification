"""
GDPR Compliance Reporter

Implements GDPR-specific compliance reporting including data subject rights,
consent management, breach notifications, and data protection impact assessments.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID
from collections import defaultdict, Counter

from sqlalchemy import and_, or_, func, desc
from sqlalchemy.orm import Session

from ...database.models import AuditEvent, User, Document, DataProcessingLog
from .base import (
    ComplianceReporter, ComplianceStandard, ComplianceViolation, ComplianceMetric,
    ViolationType, ComplianceStatus
)
from ..queries import ReportQuery

logger = logging.getLogger(__name__)


class GDPRArticle:
    """GDPR Articles relevant to compliance monitoring."""
    ARTICLE_5_DATA_MINIMIZATION = "article_5"
    ARTICLE_6_LAWFUL_BASIS = "article_6"
    ARTICLE_7_CONSENT = "article_7"
    ARTICLE_13_INFORMATION_PROVIDED = "article_13"
    ARTICLE_15_ACCESS_RIGHTS = "article_15"
    ARTICLE_16_RECTIFICATION = "article_16"
    ARTICLE_17_ERASURE = "article_17"
    ARTICLE_18_RESTRICTION = "article_18"
    ARTICLE_20_DATA_PORTABILITY = "article_20"
    ARTICLE_25_DATA_PROTECTION_BY_DESIGN = "article_25"
    ARTICLE_32_SECURITY = "article_32"
    ARTICLE_33_BREACH_NOTIFICATION = "article_33"
    ARTICLE_35_DPIA = "article_35"


class GDPRReporter(ComplianceReporter):
    """GDPR-specific compliance reporter."""
    
    @property
    def compliance_standard(self) -> ComplianceStandard:
        return ComplianceStandard.GDPR
    
    @property
    def required_fields(self) -> List[str]:
        return [
            'data_subject_id', 'processing_purpose', 'legal_basis',
            'data_categories', 'retention_period', 'consent_status'
        ]
    
    @property
    def violation_types(self) -> List[ViolationType]:
        return [
            ViolationType.CONSENT_VIOLATION,
            ViolationType.ACCESS_RIGHTS_VIOLATION,
            ViolationType.DATA_PORTABILITY_VIOLATION,
            ViolationType.RETENTION_VIOLATION,
            ViolationType.PROCESSING_VIOLATION,
            ViolationType.NOTIFICATION_VIOLATION,
            ViolationType.DATA_BREACH
        ]
    
    async def _detect_violations(self, events: List[AuditEvent], 
                               query: ReportQuery) -> List[ComplianceViolation]:
        """Detect GDPR-specific violations."""
        violations = []
        
        # Article 17 - Right to erasure violations
        erasure_violations = await self._check_erasure_compliance(events, query)
        violations.extend(erasure_violations)
        
        # Article 15 - Right of access violations
        access_violations = await self._check_access_rights_compliance(events, query)
        violations.extend(access_violations)
        
        # Article 20 - Data portability violations
        portability_violations = await self._check_data_portability_compliance(events, query)
        violations.extend(portability_violations)
        
        # Article 6 - Lawful basis violations
        lawful_basis_violations = await self._check_lawful_basis_compliance(events, query)
        violations.extend(lawful_basis_violations)
        
        # Article 33 - Breach notification violations
        breach_violations = await self._check_breach_notification_compliance(events, query)
        violations.extend(breach_violations)
        
        # Article 5 - Data minimization violations
        minimization_violations = await self._check_data_minimization_compliance(events, query)
        violations.extend(minimization_violations)
        
        return violations
    
    async def _calculate_compliance_metrics(self, events: List[AuditEvent],
                                          query: ReportQuery) -> List[ComplianceMetric]:
        """Calculate GDPR-specific compliance metrics."""
        metrics = []
        
        # Data Subject Rights Response Time
        response_time_metric = await self._calculate_response_time_metric(events, query)
        metrics.append(response_time_metric)
        
        # Consent Management Metrics
        consent_metrics = await self._calculate_consent_metrics(events, query)
        metrics.extend(consent_metrics)
        
        # Data Retention Compliance
        retention_metric = await self._calculate_retention_compliance_metric(events, query)
        metrics.append(retention_metric)
        
        # Breach Response Time
        breach_response_metric = await self._calculate_breach_response_metric(events, query)
        metrics.append(breach_response_metric)
        
        # Data Processing Lawfulness
        lawfulness_metric = await self._calculate_lawfulness_metric(events, query)
        metrics.append(lawfulness_metric)
        
        # Data Minimization Compliance
        minimization_metric = await self._calculate_minimization_metric(events, query)
        metrics.append(minimization_metric)
        
        return metrics
    
    async def _check_erasure_compliance(self, events: List[AuditEvent], 
                                      query: ReportQuery) -> List[ComplianceViolation]:
        """Check compliance with Article 17 (Right to erasure)."""
        violations = []
        
        # Find erasure requests
        erasure_requests = [e for e in events if e.event_type == 'erasure_requested']
        
        for request in erasure_requests:
            # Check if erasure was completed within 30 days
            request_date = request.event_timestamp
            completion_events = [
                e for e in events 
                if e.event_type == 'erasure_completed' 
                and e.target_id == request.target_id
                and e.event_timestamp >= request_date
            ]
            
            if not completion_events:
                # No completion found - check if within deadline
                days_since_request = (datetime.utcnow() - request_date).days
                if days_since_request > 30:
                    violations.append(ComplianceViolation(
                        violation_type=ViolationType.ACCESS_RIGHTS_VIOLATION,
                        severity='high',
                        title=f"Overdue Erasure Request",
                        description=f"Erasure request from {request_date.date()} not completed within 30 days",
                        affected_records=1,
                        affected_users=[request.user_id] if request.user_id else [],
                        detected_at=datetime.utcnow(),
                        legal_basis=GDPRArticle.ARTICLE_17_ERASURE,
                        remediation_required=True,
                        remediation_deadline=request_date + timedelta(days=30),
                        remediation_actions=[
                            "Complete the erasure request immediately",
                            "Verify all personal data has been deleted",
                            "Notify third parties if data was shared",
                            "Document the erasure process"
                        ],
                        evidence=[{
                            "type": "audit_event",
                            "event_id": str(request.id),
                            "timestamp": request_date.isoformat()
                        }],
                        risk_score=85
                    ))
        
        return violations
    
    async def _check_access_rights_compliance(self, events: List[AuditEvent],
                                            query: ReportQuery) -> List[ComplianceViolation]:
        """Check compliance with Article 15 (Right of access)."""
        violations = []
        
        # Find access requests  
        access_requests = [e for e in events if e.event_type == 'access_requested']
        
        for request in access_requests:
            request_date = request.event_timestamp
            
            # Check if response was provided within 30 days
            response_events = [
                e for e in events
                if e.event_type == 'access_provided'
                and e.target_id == request.target_id
                and e.event_timestamp >= request_date
            ]
            
            if not response_events:
                days_since_request = (datetime.utcnow() - request_date).days
                if days_since_request > 30:
                    violations.append(ComplianceViolation(
                        violation_type=ViolationType.ACCESS_RIGHTS_VIOLATION,
                        severity='medium',
                        title="Overdue Access Request",
                        description=f"Access request from {request_date.date()} not responded within 30 days",
                        affected_records=1,
                        affected_users=[request.user_id] if request.user_id else [],
                        detected_at=datetime.utcnow(),
                        legal_basis=GDPRArticle.ARTICLE_15_ACCESS_RIGHTS,
                        remediation_required=True,
                        remediation_deadline=request_date + timedelta(days=30),
                        remediation_actions=[
                            "Provide complete personal data report",
                            "Include processing purposes and legal basis",
                            "Document response and delivery method"
                        ],
                        evidence=[{
                            "type": "access_request",
                            "event_id": str(request.id),
                            "request_date": request_date.isoformat()
                        }],
                        risk_score=70
                    ))
        
        return violations
    
    async def _check_data_portability_compliance(self, events: List[AuditEvent],
                                               query: ReportQuery) -> List[ComplianceViolation]:
        """Check compliance with Article 20 (Data portability)."""
        violations = []
        
        portability_requests = [e for e in events if e.event_type == 'portability_requested']
        
        for request in portability_requests:
            request_date = request.event_timestamp
            
            # Check if data export was provided within 30 days
            export_events = [
                e for e in events
                if e.event_type == 'data_exported'
                and e.target_id == request.target_id
                and e.event_timestamp >= request_date
            ]
            
            if not export_events:
                days_since_request = (datetime.utcnow() - request_date).days
                if days_since_request > 30:
                    violations.append(ComplianceViolation(
                        violation_type=ViolationType.DATA_PORTABILITY_VIOLATION,
                        severity='medium',
                        title="Overdue Data Portability Request",
                        description=f"Data portability request from {request_date.date()} not fulfilled within 30 days",
                        affected_records=1,
                        affected_users=[request.user_id] if request.user_id else [],
                        detected_at=datetime.utcnow(),
                        legal_basis=GDPRArticle.ARTICLE_20_DATA_PORTABILITY,
                        remediation_required=True,
                        remediation_deadline=request_date + timedelta(days=30),
                        remediation_actions=[
                            "Export data in structured, machine-readable format",
                            "Ensure data completeness and accuracy",
                            "Provide secure transmission method"
                        ],
                        evidence=[{
                            "type": "portability_request",
                            "event_id": str(request.id),
                            "request_date": request_date.isoformat()
                        }],
                        risk_score=65
                    ))
        
        return violations
    
    async def _check_lawful_basis_compliance(self, events: List[AuditEvent],
                                           query: ReportQuery) -> List[ComplianceViolation]:
        """Check compliance with Article 6 (Lawful basis)."""
        violations = []
        
        # Find processing events without clear legal basis
        processing_events = [
            e for e in events 
            if e.event_type in ['document_processed', 'pii_detected', 'data_processed']
        ]
        
        missing_basis_events = []
        for event in processing_events:
            # Check if legal basis is documented
            if not event.metadata or 'legal_basis' not in event.metadata:
                missing_basis_events.append(event)
        
        if missing_basis_events:
            affected_users = list(set(e.user_id for e in missing_basis_events if e.user_id))
            
            violations.append(ComplianceViolation(
                violation_type=ViolationType.PROCESSING_VIOLATION,
                severity='high',
                title="Missing Legal Basis for Processing",
                description=f"Found {len(missing_basis_events)} processing events without documented legal basis",
                affected_records=len(missing_basis_events),
                affected_users=affected_users,
                detected_at=datetime.utcnow(),
                legal_basis=GDPRArticle.ARTICLE_6_LAWFUL_BASIS,
                remediation_required=True,
                remediation_deadline=datetime.utcnow() + timedelta(days=7),
                remediation_actions=[
                    "Review all processing activities and document legal basis",
                    "Implement legal basis tracking in system",
                    "Train staff on legal basis requirements",
                    "Update privacy policies with legal basis information"
                ],
                evidence=[{
                    "type": "processing_events",
                    "count": len(missing_basis_events),
                    "sample_events": [str(e.id) for e in missing_basis_events[:5]]
                }],
                risk_score=90
            ))
        
        return violations
    
    async def _check_breach_notification_compliance(self, events: List[AuditEvent],
                                                  query: ReportQuery) -> List[ComplianceViolation]:
        """Check compliance with Article 33 (Breach notification)."""
        violations = []
        
        # Find security breaches
        breach_events = [
            e for e in events 
            if e.event_type in ['security_breach', 'data_breach', 'unauthorized_access']
            and e.severity in ['high', 'critical']
        ]
        
        for breach in breach_events:
            breach_date = breach.event_timestamp
            
            # Check if breach was reported to supervisory authority within 72 hours
            notification_events = [
                e for e in events
                if e.event_type == 'breach_notification_sent'
                and e.metadata
                and e.metadata.get('related_breach_id') == str(breach.id)
            ]
            
            if not notification_events:
                hours_since_breach = (datetime.utcnow() - breach_date).total_seconds() / 3600
                if hours_since_breach > 72:
                    violations.append(ComplianceViolation(
                        violation_type=ViolationType.NOTIFICATION_VIOLATION,
                        severity='critical',
                        title="Overdue Breach Notification",
                        description=f"Security breach from {breach_date} not reported within 72 hours",
                        affected_records=1,
                        affected_users=[breach.user_id] if breach.user_id else [],
                        detected_at=datetime.utcnow(),
                        legal_basis=GDPRArticle.ARTICLE_33_BREACH_NOTIFICATION,
                        remediation_required=True,
                        remediation_deadline=breach_date + timedelta(hours=72),
                        remediation_actions=[
                            "Immediately notify supervisory authority",
                            "Prepare detailed breach report",
                            "Assess if data subjects need notification",
                            "Implement measures to prevent recurrence"
                        ],
                        evidence=[{
                            "type": "security_breach",
                            "event_id": str(breach.id),
                            "breach_date": breach_date.isoformat(),
                            "severity": breach.severity
                        }],
                        risk_score=95
                    ))
        
        return violations
    
    async def _check_data_minimization_compliance(self, events: List[AuditEvent],
                                                query: ReportQuery) -> List[ComplianceViolation]:
        """Check compliance with Article 5 (Data minimization)."""
        violations = []
        
        # Analyze data collection patterns
        collection_events = [e for e in events if e.event_type == 'document_uploaded']
        
        # Group by user and analyze data collection frequency
        user_collections = defaultdict(list)
        for event in collection_events:
            if event.user_id:
                user_collections[event.user_id].append(event)
        
        excessive_collection_users = []
        for user_id, events_list in user_collections.items():
            # Simple heuristic: more than 10 documents per month might be excessive
            if len(events_list) > 10:
                excessive_collection_users.append(user_id)
        
        if excessive_collection_users:
            violations.append(ComplianceViolation(
                violation_type=ViolationType.PROCESSING_VIOLATION,
                severity='medium',
                title="Potential Data Minimization Violation",
                description=f"Detected potentially excessive data collection for {len(excessive_collection_users)} users",
                affected_records=len(excessive_collection_users),
                affected_users=excessive_collection_users,
                detected_at=datetime.utcnow(),
                legal_basis=GDPRArticle.ARTICLE_5_DATA_MINIMIZATION,
                remediation_required=True,
                remediation_deadline=datetime.utcnow() + timedelta(days=30),
                remediation_actions=[
                    "Review data collection practices",
                    "Ensure only necessary data is collected",
                    "Implement data collection limits",
                    "Document business justification for data collection"
                ],
                evidence=[{
                    "type": "collection_analysis",
                    "excessive_collection_users": len(excessive_collection_users)
                }],
                risk_score=60
            ))
        
        return violations
    
    async def _calculate_response_time_metric(self, events: List[AuditEvent],
                                            query: ReportQuery) -> ComplianceMetric:
        """Calculate data subject rights response time metric."""
        rights_requests = [
            e for e in events 
            if e.event_type in ['access_requested', 'erasure_requested', 'portability_requested']
        ]
        
        completed_requests = []
        for request in rights_requests:
            completion_events = [
                e for e in events
                if e.event_type.endswith('_completed')
                and e.target_id == request.target_id
                and e.event_timestamp >= request.event_timestamp
            ]
            
            if completion_events:
                response_time = (completion_events[0].event_timestamp - request.event_timestamp).days
                completed_requests.append(response_time)
        
        if completed_requests:
            avg_response_time = sum(completed_requests) / len(completed_requests)
            status = ComplianceStatus.COMPLIANT if avg_response_time <= 30 else ComplianceStatus.NON_COMPLIANT
        else:
            avg_response_time = 0
            status = ComplianceStatus.NEEDS_REVIEW
        
        return ComplianceMetric(
            metric_name="Data Subject Rights Response Time",
            metric_value=round(avg_response_time, 1),
            target_value=30,
            status=status,
            measurement_date=datetime.utcnow(),
            trend="stable",
            details={
                "unit": "days",
                "requests_analyzed": len(completed_requests),
                "total_requests": len(rights_requests)
            }
        )
    
    async def _calculate_consent_metrics(self, events: List[AuditEvent],
                                       query: ReportQuery) -> List[ComplianceMetric]:
        """Calculate consent management metrics."""
        consent_events = [e for e in events if 'consent' in e.event_type]
        consent_given = [e for e in consent_events if e.event_type == 'consent_given']
        consent_withdrawn = [e for e in consent_events if e.event_type == 'consent_withdrawn']
        
        # Consent rate
        total_users = len(set(e.user_id for e in events if e.user_id))
        consented_users = len(set(e.user_id for e in consent_given if e.user_id))
        consent_rate = (consented_users / total_users) * 100 if total_users > 0 else 0
        
        consent_rate_metric = ComplianceMetric(
            metric_name="Consent Rate",
            metric_value=round(consent_rate, 1),
            target_value=80,
            status=ComplianceStatus.COMPLIANT if consent_rate >= 80 else ComplianceStatus.NEEDS_REVIEW,
            measurement_date=datetime.utcnow(),
            trend="stable",
            details={
                "unit": "percentage",
                "consented_users": consented_users,
                "total_users": total_users
            }
        )
        
        # Consent withdrawal processing
        withdrawn_consents = len(consent_withdrawn)
        withdrawal_metric = ComplianceMetric(
            metric_name="Consent Withdrawals Processed",
            metric_value=withdrawn_consents,
            target_value=withdrawn_consents,  # All withdrawals should be processed
            status=ComplianceStatus.COMPLIANT,
            measurement_date=datetime.utcnow(),
            trend="stable",
            details={
                "unit": "count",
                "processing_required": True
            }
        )
        
        return [consent_rate_metric, withdrawal_metric]
    
    async def _calculate_retention_compliance_metric(self, events: List[AuditEvent],
                                                   query: ReportQuery) -> ComplianceMetric:
        """Calculate data retention compliance metric."""
        retention_check = await self._check_retention_compliance(query)
        
        compliance_percentage = 100.0
        if retention_check['violations']:
            # Decrease percentage based on violations
            violation_impact = min(len(retention_check['violations']) * 10, 100)
            compliance_percentage = max(0, 100 - violation_impact)
        
        status = ComplianceStatus.COMPLIANT if compliance_percentage >= 95 else ComplianceStatus.NON_COMPLIANT
        
        return ComplianceMetric(
            metric_name="Data Retention Compliance",
            metric_value=compliance_percentage,
            target_value=100,
            status=status,
            measurement_date=datetime.utcnow(),
            trend="stable",
            details={
                "unit": "percentage",
                "violations_found": len(retention_check['violations']),
                "policies_checked": retention_check['total_policies_checked']
            }
        )
    
    async def _calculate_breach_response_metric(self, events: List[AuditEvent],
                                              query: ReportQuery) -> ComplianceMetric:
        """Calculate breach response time metric."""
        breach_events = [e for e in events if e.event_type == 'security_breach']
        notification_events = [e for e in events if e.event_type == 'breach_notification_sent']
        
        response_times = []
        for breach in breach_events:
            notifications = [
                n for n in notification_events
                if n.metadata and n.metadata.get('related_breach_id') == str(breach.id)
            ]
            if notifications:
                response_time = (notifications[0].event_timestamp - breach.event_timestamp).total_seconds() / 3600
                response_times.append(response_time)
        
        if response_times:
            avg_response_time = sum(response_times) / len(response_times)
            status = ComplianceStatus.COMPLIANT if avg_response_time <= 72 else ComplianceStatus.NON_COMPLIANT
        else:
            avg_response_time = 0
            status = ComplianceStatus.COMPLIANT
        
        return ComplianceMetric(
            metric_name="Breach Notification Response Time",
            metric_value=round(avg_response_time, 1),
            target_value=72,
            status=status,
            measurement_date=datetime.utcnow(),
            trend="stable",
            details={
                "unit": "hours",
                "breaches_analyzed": len(response_times),
                "total_breaches": len(breach_events)
            }
        )
    
    async def _calculate_lawfulness_metric(self, events: List[AuditEvent],
                                         query: ReportQuery) -> ComplianceMetric:
        """Calculate processing lawfulness metric."""
        processing_events = [
            e for e in events
            if e.event_type in ['document_processed', 'pii_detected', 'data_processed']
        ]
        
        events_with_basis = [
            e for e in processing_events
            if e.metadata and 'legal_basis' in e.metadata
        ]
        
        lawfulness_percentage = (len(events_with_basis) / len(processing_events)) * 100 if processing_events else 100
        status = ComplianceStatus.COMPLIANT if lawfulness_percentage >= 95 else ComplianceStatus.NON_COMPLIANT
        
        return ComplianceMetric(
            metric_name="Processing Lawfulness",
            metric_value=round(lawfulness_percentage, 1),
            target_value=100,
            status=status,
            measurement_date=datetime.utcnow(),
            trend="stable",
            details={
                "unit": "percentage",
                "events_with_basis": len(events_with_basis),
                "total_processing_events": len(processing_events)
            }
        )
    
    async def _calculate_minimization_metric(self, events: List[AuditEvent],
                                           query: ReportQuery) -> ComplianceMetric:
        """Calculate data minimization compliance metric."""
        # This is a simplified metric - in practice, this would require more sophisticated analysis
        collection_events = [e for e in events if e.event_type == 'document_uploaded']
        
        # Assume compliance unless excessive collection is detected
        minimization_score = 95.0  # Base score
        
        # Check for potential over-collection patterns
        user_collections = defaultdict(int)
        for event in collection_events:
            if event.user_id:
                user_collections[event.user_id] += 1
        
        excessive_users = sum(1 for count in user_collections.values() if count > 10)
        if excessive_users > 0:
            minimization_score -= min(excessive_users * 5, 50)
        
        status = ComplianceStatus.COMPLIANT if minimization_score >= 90 else ComplianceStatus.NEEDS_REVIEW
        
        return ComplianceMetric(
            metric_name="Data Minimization Compliance",
            metric_value=minimization_score,
            target_value=95,
            status=status,
            measurement_date=datetime.utcnow(),
            trend="stable",
            details={
                "unit": "score",
                "excessive_collection_users": excessive_users,
                "total_collecting_users": len(user_collections)
            }
        )
    
    async def _generate_recommendations(self, violations: List[ComplianceViolation],
                                      metrics: List[ComplianceMetric]) -> List[str]:
        """Generate GDPR-specific recommendations."""
        recommendations = []
        
        # Check for common violation patterns
        violation_types = Counter(v.violation_type for v in violations)
        
        if ViolationType.ACCESS_RIGHTS_VIOLATION in violation_types:
            recommendations.append(
                "Implement automated data subject rights management system to ensure timely responses"
            )
        
        if ViolationType.NOTIFICATION_VIOLATION in violation_types:
            recommendations.append(
                "Establish incident response procedures with automated breach notification workflows"
            )
        
        if ViolationType.PROCESSING_VIOLATION in violation_types:
            recommendations.append(
                "Document legal basis for all data processing activities and implement tracking systems"
            )
        
        # Check metrics for improvement areas
        for metric in metrics:
            if metric.status == ComplianceStatus.NON_COMPLIANT:
                if "Response Time" in metric.metric_name:
                    recommendations.append(
                        "Optimize data subject rights response processes and consider additional staffing"
                    )
                elif "Consent" in metric.metric_name:
                    recommendations.append(
                        "Review consent collection mechanisms and improve consent management processes"
                    )
                elif "Retention" in metric.metric_name:
                    recommendations.append(
                        "Implement automated data retention policies and regular data purging schedules"
                    )
        
        # Always include general GDPR recommendations
        recommendations.extend([
            "Conduct regular GDPR compliance audits and staff training",
            "Keep detailed records of processing activities (Article 30)",
            "Review and update privacy policies and consent mechanisms",
            "Implement privacy by design principles in system development",
            "Maintain up-to-date data protection impact assessments (DPIA)"
        ])
        
        return list(set(recommendations))  # Remove duplicates