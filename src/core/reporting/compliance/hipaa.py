"""
HIPAA Compliance Reporter

Implements HIPAA-specific compliance reporting for healthcare data protection,
including PHI access controls, audit requirements, and breach notifications.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID
from collections import defaultdict, Counter

from sqlalchemy import and_, or_, func, desc
from sqlalchemy.orm import Session

from ...database.models import AuditEvent, User, Document
from .base import (
    ComplianceReporter, ComplianceStandard, ComplianceViolation, ComplianceMetric,
    ViolationType, ComplianceStatus
)
from ..queries import ReportQuery

logger = logging.getLogger(__name__)


class HIPAASafeguard:
    """HIPAA Safeguards and requirements."""
    ADMINISTRATIVE = "administrative"
    PHYSICAL = "physical" 
    TECHNICAL = "technical"


class HIPAAReporter(ComplianceReporter):
    """HIPAA-specific compliance reporter."""
    
    @property
    def compliance_standard(self) -> ComplianceStandard:
        return ComplianceStandard.HIPAA
    
    @property
    def required_fields(self) -> List[str]:
        return [
            'phi_category', 'access_purpose', 'minimum_necessary',
            'authorization_status', 'covered_entity', 'business_associate'
        ]
    
    @property
    def violation_types(self) -> List[ViolationType]:
        return [
            ViolationType.UNAUTHORIZED_ACCESS,
            ViolationType.DATA_BREACH,
            ViolationType.ACCESS_RIGHTS_VIOLATION,
            ViolationType.NOTIFICATION_VIOLATION
        ]
    
    async def _detect_violations(self, events: List[AuditEvent], 
                               query: ReportQuery) -> List[ComplianceViolation]:
        """Detect HIPAA-specific violations."""
        violations = []
        
        # Unauthorized PHI access
        violations.extend(await self._check_unauthorized_access(events, query))
        
        # Minimum necessary violations
        violations.extend(await self._check_minimum_necessary(events, query))
        
        # Breach notification compliance
        violations.extend(await self._check_breach_notifications(events, query))
        
        return violations
    
    async def _check_unauthorized_access(self, events: List[AuditEvent],
                                       query: ReportQuery) -> List[ComplianceViolation]:
        """Check for unauthorized PHI access."""
        violations = []
        
        # Find failed access attempts to PHI
        failed_phi_access = [
            e for e in events 
            if e.outcome == 'failure' 
            and e.contains_pii == True
            and 'access' in e.event_type.lower()
        ]
        
        if len(failed_phi_access) > 5:  # Threshold for concern
            violations.append(ComplianceViolation(
                violation_type=ViolationType.UNAUTHORIZED_ACCESS,
                severity='high',
                title="Multiple Failed PHI Access Attempts",
                description=f"Detected {len(failed_phi_access)} failed attempts to access PHI",
                affected_records=len(failed_phi_access),
                affected_users=list(set(e.user_id for e in failed_phi_access if e.user_id)),
                detected_at=datetime.utcnow(),
                legal_basis="HIPAA Security Rule §164.312(a)(1)",
                remediation_required=True,
                remediation_deadline=datetime.utcnow() + timedelta(days=7),
                remediation_actions=[
                    "Investigate failed access attempts",
                    "Review user access permissions",
                    "Implement additional access controls",
                    "Train users on proper PHI access"
                ],
                evidence=[{"failed_attempts": len(failed_phi_access)}],
                risk_score=80
            ))
        
        return violations
    
    async def _check_minimum_necessary(self, events: List[AuditEvent],
                                     query: ReportQuery) -> List[ComplianceViolation]:
        """Check minimum necessary standard compliance."""
        violations = []
        
        # Look for potential over-access patterns
        phi_access_events = [e for e in events if e.contains_pii == True and e.outcome == 'success']
        
        # Group by user and check access patterns
        user_access = defaultdict(list)
        for event in phi_access_events:
            if event.user_id:
                user_access[event.user_id].append(event)
        
        excessive_access_users = [
            user_id for user_id, access_list in user_access.items()
            if len(access_list) > 50  # Threshold for review
        ]
        
        if excessive_access_users:
            violations.append(ComplianceViolation(
                violation_type=ViolationType.ACCESS_RIGHTS_VIOLATION,
                severity='medium',
                title="Potential Minimum Necessary Violations",
                description=f"{len(excessive_access_users)} users with potentially excessive PHI access",
                affected_records=len(excessive_access_users),
                affected_users=excessive_access_users,
                detected_at=datetime.utcnow(),
                legal_basis="HIPAA Privacy Rule §164.502(b)",
                remediation_required=True,
                remediation_deadline=datetime.utcnow() + timedelta(days=14),
                remediation_actions=[
                    "Review user access patterns",
                    "Verify minimum necessary compliance",
                    "Adjust user permissions if needed",
                    "Document business justification for access"
                ],
                evidence=[{"excessive_access_users": len(excessive_access_users)}],
                risk_score=60
            ))
        
        return violations
    
    async def _check_breach_notifications(self, events: List[AuditEvent],
                                        query: ReportQuery) -> List[ComplianceViolation]:
        """Check HIPAA breach notification compliance."""
        violations = []
        
        # Find security incidents involving PHI
        phi_incidents = [
            e for e in events
            if e.event_type in ['security_breach', 'data_breach']
            and e.contains_pii == True
            and e.severity in ['high', 'critical']
        ]
        
        for incident in phi_incidents:
            # Check if breach affected 500+ individuals (requires HHS notification)
            affected_count = incident.metadata.get('affected_individuals', 1) if incident.metadata else 1
            
            if affected_count >= 500:
                # Check for HHS notification within 60 days
                notification_events = [
                    e for e in events
                    if e.event_type == 'hhs_notification_sent'
                    and e.metadata
                    and e.metadata.get('related_incident_id') == str(incident.id)
                ]
                
                if not notification_events:
                    days_since_incident = (datetime.utcnow() - incident.event_timestamp).days
                    if days_since_incident > 60:
                        violations.append(ComplianceViolation(
                            violation_type=ViolationType.NOTIFICATION_VIOLATION,
                            severity='critical',
                            title="Overdue HHS Breach Notification",
                            description=f"PHI breach affecting {affected_count} individuals not reported to HHS within 60 days",
                            affected_records=affected_count,
                            affected_users=[incident.user_id] if incident.user_id else [],
                            detected_at=datetime.utcnow(),
                            legal_basis="HIPAA Breach Notification Rule §164.408",
                            remediation_required=True,
                            remediation_deadline=incident.event_timestamp + timedelta(days=60),
                            remediation_actions=[
                                "Immediately notify HHS of the breach",
                                "Prepare detailed breach report",
                                "Notify affected individuals",
                                "Implement corrective measures"
                            ],
                            evidence=[{
                                "incident_id": str(incident.id),
                                "affected_individuals": affected_count,
                                "incident_date": incident.event_timestamp.isoformat()
                            }],
                            risk_score=95
                        ))
        
        return violations
    
    async def _calculate_compliance_metrics(self, events: List[AuditEvent],
                                          query: ReportQuery) -> List[ComplianceMetric]:
        """Calculate HIPAA-specific compliance metrics."""
        metrics = []
        
        # PHI Access Control Metric
        access_control_metric = await self._calculate_access_control_metric(events, query)
        metrics.append(access_control_metric)
        
        # Audit Log Completeness
        audit_completeness_metric = await self._calculate_audit_completeness_metric(events, query)
        metrics.append(audit_completeness_metric)
        
        # Minimum Necessary Compliance
        min_necessary_metric = await self._calculate_minimum_necessary_metric(events, query)
        metrics.append(min_necessary_metric)
        
        return metrics
    
    async def _calculate_access_control_metric(self, events: List[AuditEvent],
                                             query: ReportQuery) -> ComplianceMetric:
        """Calculate PHI access control effectiveness."""
        phi_access_attempts = [e for e in events if e.contains_pii == True and 'access' in e.event_type]
        successful_access = [e for e in phi_access_attempts if e.outcome == 'success']
        
        if phi_access_attempts:
            success_rate = (len(successful_access) / len(phi_access_attempts)) * 100
            # High success rate is good, but 100% might indicate insufficient controls
            status = ComplianceStatus.COMPLIANT if 80 <= success_rate <= 95 else ComplianceStatus.NEEDS_REVIEW
        else:
            success_rate = 100
            status = ComplianceStatus.NEEDS_REVIEW
        
        return ComplianceMetric(
            metric_name="PHI Access Control Effectiveness",
            metric_value=round(success_rate, 1),
            target_value=90,
            status=status,
            measurement_date=datetime.utcnow(),
            trend="stable",
            details={
                "unit": "percentage",
                "total_attempts": len(phi_access_attempts),
                "successful_access": len(successful_access)
            }
        )
    
    async def _calculate_audit_completeness_metric(self, events: List[AuditEvent],
                                                 query: ReportQuery) -> ComplianceMetric:
        """Calculate audit log completeness for PHI access."""
        phi_events = [e for e in events if e.contains_pii == True]
        events_with_complete_info = [
            e for e in phi_events
            if e.user_id and e.event_description and e.ip_address
        ]
        
        if phi_events:
            completeness = (len(events_with_complete_info) / len(phi_events)) * 100
            status = ComplianceStatus.COMPLIANT if completeness >= 95 else ComplianceStatus.NON_COMPLIANT
        else:
            completeness = 100
            status = ComplianceStatus.COMPLIANT
        
        return ComplianceMetric(
            metric_name="Audit Log Completeness",
            metric_value=round(completeness, 1),
            target_value=100,
            status=status,
            measurement_date=datetime.utcnow(),
            trend="stable",
            details={
                "unit": "percentage",
                "total_phi_events": len(phi_events),
                "complete_records": len(events_with_complete_info)
            }
        )
    
    async def _calculate_minimum_necessary_metric(self, events: List[AuditEvent],
                                                query: ReportQuery) -> ComplianceMetric:
        """Calculate minimum necessary compliance metric."""
        # This is simplified - would need more sophisticated analysis in practice
        phi_access_events = [e for e in events if e.contains_pii == True and e.outcome == 'success']
        
        # Assume compliance unless patterns suggest otherwise
        compliance_score = 90.0
        
        # Check for potential over-access
        user_access = defaultdict(int)
        for event in phi_access_events:
            if event.user_id:
                user_access[event.user_id] += 1
        
        high_access_users = sum(1 for count in user_access.values() if count > 50)
        if high_access_users > 0:
            compliance_score -= min(high_access_users * 10, 50)
        
        status = ComplianceStatus.COMPLIANT if compliance_score >= 80 else ComplianceStatus.NEEDS_REVIEW
        
        return ComplianceMetric(
            metric_name="Minimum Necessary Compliance",
            metric_value=compliance_score,
            target_value=95,
            status=status,
            measurement_date=datetime.utcnow(),
            trend="stable",
            details={
                "unit": "score",
                "high_access_users": high_access_users,
                "total_users": len(user_access)
            }
        )
    
    async def _generate_recommendations(self, violations: List[ComplianceViolation],
                                      metrics: List[ComplianceMetric]) -> List[str]:
        """Generate HIPAA-specific recommendations."""
        recommendations = []
        
        violation_types = Counter(v.violation_type for v in violations)
        
        if ViolationType.UNAUTHORIZED_ACCESS in violation_types:
            recommendations.append(
                "Implement stronger authentication controls and regular access reviews"
            )
        
        if ViolationType.NOTIFICATION_VIOLATION in violation_types:
            recommendations.append(
                "Establish automated breach notification procedures with HHS reporting"
            )
        
        recommendations.extend([
            "Conduct regular HIPAA Security Rule compliance assessments",
            "Implement comprehensive PHI access monitoring and alerting",
            "Provide regular HIPAA training for all workforce members",
            "Maintain detailed audit logs for all PHI access and modifications",
            "Review and update business associate agreements regularly"
        ])
        
        return recommendations