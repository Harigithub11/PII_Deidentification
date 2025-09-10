"""
NDHM Compliance Reporter

Implements NDHM (National Digital Health Mission) compliance reporting for 
Indian healthcare data regulations, including health data localization and 
consent framework compliance.
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


class NDHMRequirement:
    """NDHM-specific requirements."""
    DATA_LOCALIZATION = "data_localization"
    CONSENT_FRAMEWORK = "consent_framework"
    INTEROPERABILITY = "interoperability"
    HEALTH_DATA_PROTECTION = "health_data_protection"


class NDHMReporter(ComplianceReporter):
    """NDHM-specific compliance reporter."""
    
    @property
    def compliance_standard(self) -> ComplianceStandard:
        return ComplianceStandard.NDHM
    
    @property
    def required_fields(self) -> List[str]:
        return [
            'health_data_category', 'consent_artifact_id', 'data_location',
            'abha_id', 'healthcare_provider_id', 'purpose_of_use'
        ]
    
    @property
    def violation_types(self) -> List[ViolationType]:
        return [
            ViolationType.CONSENT_VIOLATION,
            ViolationType.DATA_BREACH,
            ViolationType.PROCESSING_VIOLATION,
            ViolationType.ACCESS_RIGHTS_VIOLATION
        ]
    
    async def _detect_violations(self, events: List[AuditEvent], 
                               query: ReportQuery) -> List[ComplianceViolation]:
        """Detect NDHM-specific violations."""
        violations = []
        
        # Data localization violations
        violations.extend(await self._check_data_localization(events, query))
        
        # Consent framework violations  
        violations.extend(await self._check_consent_framework(events, query))
        
        # Health data protection violations
        violations.extend(await self._check_health_data_protection(events, query))
        
        return violations
    
    async def _check_data_localization(self, events: List[AuditEvent],
                                     query: ReportQuery) -> List[ComplianceViolation]:
        """Check data localization compliance."""
        violations = []
        
        # Check for data transfers outside India
        export_events = [e for e in events if e.event_type == 'data_exported']
        
        foreign_exports = []
        for event in export_events:
            if event.metadata:
                destination = event.metadata.get('destination_country')
                if destination and destination.upper() != 'IN':
                    foreign_exports.append(event)
        
        if foreign_exports:
            violations.append(ComplianceViolation(
                violation_type=ViolationType.PROCESSING_VIOLATION,
                severity='critical',
                title="Data Localization Violation",
                description=f"Found {len(foreign_exports)} health data exports outside India",
                affected_records=len(foreign_exports),
                affected_users=list(set(e.user_id for e in foreign_exports if e.user_id)),
                detected_at=datetime.utcnow(),
                legal_basis="NDHM Data Localization Requirements",
                remediation_required=True,
                remediation_deadline=datetime.utcnow() + timedelta(days=3),
                remediation_actions=[
                    "Immediately stop foreign data transfers",
                    "Retrieve data from foreign locations",
                    "Review and update data handling procedures",
                    "Implement technical controls to prevent future violations"
                ],
                evidence=[{
                    "foreign_exports": len(foreign_exports),
                    "destinations": list(set(e.metadata.get('destination_country') for e in foreign_exports if e.metadata))
                }],
                risk_score=95
            ))
        
        return violations
    
    async def _check_consent_framework(self, events: List[AuditEvent],
                                     query: ReportQuery) -> List[ComplianceViolation]:
        """Check NDHM consent framework compliance."""
        violations = []
        
        # Find health data processing without valid consent
        health_processing = [
            e for e in events 
            if e.contains_pii == True 
            and e.event_type in ['document_processed', 'pii_detected']
            and e.metadata 
            and e.metadata.get('data_category') == 'health'
        ]
        
        missing_consent = []
        for event in health_processing:
            if not event.metadata or 'consent_artifact_id' not in event.metadata:
                missing_consent.append(event)
        
        if missing_consent:
            violations.append(ComplianceViolation(
                violation_type=ViolationType.CONSENT_VIOLATION,
                severity='high',
                title="Missing Consent Artifacts",
                description=f"Found {len(missing_consent)} health data processing events without consent artifacts",
                affected_records=len(missing_consent),
                affected_users=list(set(e.user_id for e in missing_consent if e.user_id)),
                detected_at=datetime.utcnow(),
                legal_basis="NDHM Consent Framework",
                remediation_required=True,
                remediation_deadline=datetime.utcnow() + timedelta(days=7),
                remediation_actions=[
                    "Obtain valid consent artifacts for all health data processing",
                    "Implement consent checking in processing workflows",
                    "Document consent basis for all operations",
                    "Train staff on NDHM consent requirements"
                ],
                evidence=[{
                    "missing_consent_events": len(missing_consent),
                    "sample_events": [str(e.id) for e in missing_consent[:5]]
                }],
                risk_score=85
            ))
        
        return violations
    
    async def _check_health_data_protection(self, events: List[AuditEvent],
                                          query: ReportQuery) -> List[ComplianceViolation]:
        """Check health data protection requirements."""
        violations = []
        
        # Check for unauthorized access to health data
        health_access_failures = [
            e for e in events
            if e.outcome == 'failure'
            and e.contains_pii == True
            and e.metadata
            and e.metadata.get('data_category') == 'health'
        ]
        
        if len(health_access_failures) > 3:  # Threshold
            violations.append(ComplianceViolation(
                violation_type=ViolationType.UNAUTHORIZED_ACCESS,
                severity='medium',
                title="Multiple Health Data Access Failures",
                description=f"Detected {len(health_access_failures)} failed attempts to access health data",
                affected_records=len(health_access_failures),
                affected_users=list(set(e.user_id for e in health_access_failures if e.user_id)),
                detected_at=datetime.utcnow(),
                legal_basis="NDHM Health Data Protection Guidelines",
                remediation_required=True,
                remediation_deadline=datetime.utcnow() + timedelta(days=5),
                remediation_actions=[
                    "Investigate failed access attempts",
                    "Review health data access controls",
                    "Strengthen authentication for health data",
                    "Monitor for suspicious access patterns"
                ],
                evidence=[{
                    "failed_attempts": len(health_access_failures)
                }],
                risk_score=70
            ))
        
        return violations
    
    async def _calculate_compliance_metrics(self, events: List[AuditEvent],
                                          query: ReportQuery) -> List[ComplianceMetric]:
        """Calculate NDHM-specific compliance metrics."""
        metrics = []
        
        # Data Localization Compliance
        localization_metric = await self._calculate_localization_metric(events, query)
        metrics.append(localization_metric)
        
        # Consent Framework Compliance
        consent_metric = await self._calculate_consent_compliance_metric(events, query)
        metrics.append(consent_metric)
        
        # Health Data Protection Metric
        protection_metric = await self._calculate_protection_metric(events, query)
        metrics.append(protection_metric)
        
        return metrics
    
    async def _calculate_localization_metric(self, events: List[AuditEvent],
                                           query: ReportQuery) -> ComplianceMetric:
        """Calculate data localization compliance metric."""
        export_events = [e for e in events if e.event_type == 'data_exported']
        
        domestic_exports = []
        foreign_exports = []
        
        for event in export_events:
            if event.metadata:
                destination = event.metadata.get('destination_country', 'IN')
                if destination.upper() == 'IN':
                    domestic_exports.append(event)
                else:
                    foreign_exports.append(event)
        
        if export_events:
            compliance_rate = (len(domestic_exports) / len(export_events)) * 100
            status = ComplianceStatus.COMPLIANT if compliance_rate >= 100 else ComplianceStatus.NON_COMPLIANT
        else:
            compliance_rate = 100
            status = ComplianceStatus.COMPLIANT
        
        return ComplianceMetric(
            metric_name="Data Localization Compliance",
            metric_value=compliance_rate,
            target_value=100,
            status=status,
            measurement_date=datetime.utcnow(),
            trend="stable",
            details={
                "unit": "percentage",
                "total_exports": len(export_events),
                "domestic_exports": len(domestic_exports),
                "foreign_exports": len(foreign_exports)
            }
        )
    
    async def _calculate_consent_compliance_metric(self, events: List[AuditEvent],
                                                 query: ReportQuery) -> ComplianceMetric:
        """Calculate consent framework compliance metric."""
        health_processing = [
            e for e in events
            if e.contains_pii == True
            and e.metadata
            and e.metadata.get('data_category') == 'health'
        ]
        
        events_with_consent = [
            e for e in health_processing
            if e.metadata and 'consent_artifact_id' in e.metadata
        ]
        
        if health_processing:
            consent_rate = (len(events_with_consent) / len(health_processing)) * 100
            status = ComplianceStatus.COMPLIANT if consent_rate >= 95 else ComplianceStatus.NON_COMPLIANT
        else:
            consent_rate = 100
            status = ComplianceStatus.COMPLIANT
        
        return ComplianceMetric(
            metric_name="Consent Framework Compliance",
            metric_value=round(consent_rate, 1),
            target_value=100,
            status=status,
            measurement_date=datetime.utcnow(),
            trend="stable",
            details={
                "unit": "percentage",
                "health_processing_events": len(health_processing),
                "events_with_consent": len(events_with_consent)
            }
        )
    
    async def _calculate_protection_metric(self, events: List[AuditEvent],
                                         query: ReportQuery) -> ComplianceMetric:
        """Calculate health data protection metric."""
        health_events = [
            e for e in events
            if e.contains_pii == True
            and e.metadata
            and e.metadata.get('data_category') == 'health'
        ]
        
        successful_access = [e for e in health_events if e.outcome == 'success']
        
        if health_events:
            protection_rate = (len(successful_access) / len(health_events)) * 100
            # Good protection allows authorized access while preventing unauthorized access
            status = ComplianceStatus.COMPLIANT if 85 <= protection_rate <= 95 else ComplianceStatus.NEEDS_REVIEW
        else:
            protection_rate = 100
            status = ComplianceStatus.COMPLIANT
        
        return ComplianceMetric(
            metric_name="Health Data Protection Effectiveness",
            metric_value=round(protection_rate, 1),
            target_value=90,
            status=status,
            measurement_date=datetime.utcnow(),
            trend="stable",
            details={
                "unit": "percentage",
                "total_health_events": len(health_events),
                "successful_access": len(successful_access)
            }
        )
    
    async def _generate_recommendations(self, violations: List[ComplianceViolation],
                                      metrics: List[ComplianceMetric]) -> List[str]:
        """Generate NDHM-specific recommendations."""
        recommendations = []
        
        violation_types = Counter(v.violation_type for v in violations)
        
        if ViolationType.PROCESSING_VIOLATION in violation_types:
            recommendations.append(
                "Implement strict data localization controls and monitoring systems"
            )
        
        if ViolationType.CONSENT_VIOLATION in violation_types:
            recommendations.append(
                "Establish robust consent management system with NDHM integration"
            )
        
        recommendations.extend([
            "Ensure all health data remains within Indian borders",
            "Implement NDHM-compliant consent artifacts for all health data processing",
            "Establish secure health data exchange protocols",
            "Maintain detailed audit trails for all health data operations",
            "Regular compliance assessments against NDHM guidelines",
            "Train healthcare staff on NDHM compliance requirements"
        ])
        
        return recommendations