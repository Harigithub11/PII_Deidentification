"""
Base Compliance Reporter

Provides the foundation for compliance reporting across different regulatory
frameworks with common patterns and extensible architecture.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from uuid import UUID
from dataclasses import dataclass
from enum import Enum

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc

from ...database.models import (
    AuditEvent, DataProcessingLog, User, Document, Policy, PolicyExecution
)
from ...database.repositories import RepositoryFactory
from ..engine import ReportRequest
from ..queries import QueryBuilder, ReportQuery

logger = logging.getLogger(__name__)


class ComplianceStandard(str, Enum):
    """Supported compliance standards."""
    GDPR = "gdpr"
    HIPAA = "hipaa"
    NDHM = "ndhm"
    PCI_DSS = "pci_dss"
    SOX = "sox"
    CCPA = "ccpa"


class ViolationType(str, Enum):
    """Types of compliance violations."""
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    RETENTION_VIOLATION = "retention_violation"
    CONSENT_VIOLATION = "consent_violation"
    ACCESS_RIGHTS_VIOLATION = "access_rights_violation"
    DATA_PORTABILITY_VIOLATION = "data_portability_violation"
    PROCESSING_VIOLATION = "processing_violation"
    NOTIFICATION_VIOLATION = "notification_violation"


class ComplianceStatus(str, Enum):
    """Compliance status levels."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NEEDS_REVIEW = "needs_review"
    PARTIALLY_COMPLIANT = "partially_compliant"


@dataclass
class ComplianceViolation:
    """Individual compliance violation."""
    violation_type: ViolationType
    severity: str
    title: str
    description: str
    affected_records: int
    affected_users: List[UUID]
    detected_at: datetime
    legal_basis: Optional[str]
    remediation_required: bool
    remediation_deadline: Optional[datetime]
    remediation_actions: List[str]
    evidence: List[Dict[str, Any]]
    risk_score: int


@dataclass 
class ComplianceMetric:
    """Compliance metric measurement."""
    metric_name: str
    metric_value: Union[int, float, str]
    target_value: Union[int, float, str]
    status: ComplianceStatus
    measurement_date: datetime
    trend: str  # improving, declining, stable
    details: Dict[str, Any]


@dataclass
class ComplianceReport:
    """Comprehensive compliance report."""
    standard: ComplianceStandard
    report_period: Dict[str, datetime]
    overall_status: ComplianceStatus
    compliance_score: float  # 0-100
    
    # Metrics and violations
    metrics: List[ComplianceMetric]
    violations: List[ComplianceViolation]
    
    # Data processing summary
    data_subjects_count: int
    processed_records_count: int
    consent_records_count: int
    
    # Recommendations
    recommendations: List[str]
    action_items: List[Dict[str, Any]]
    
    # Additional metadata
    generated_at: datetime
    generated_by: UUID
    evidence_files: List[str]


class ComplianceReporter(ABC):
    """Base class for compliance reporters."""
    
    def __init__(self, session: Session):
        self.session = session
        self.repos = RepositoryFactory(session)
        self.query_builder = QueryBuilder(session)
    
    @property
    @abstractmethod
    def compliance_standard(self) -> ComplianceStandard:
        """Get the compliance standard this reporter handles."""
        pass
    
    @property
    @abstractmethod
    def required_fields(self) -> List[str]:
        """Get required fields for this compliance standard."""
        pass
    
    @property
    @abstractmethod 
    def violation_types(self) -> List[ViolationType]:
        """Get violation types relevant to this standard."""
        pass
    
    async def generate_compliance_report(self, request: ReportRequest, 
                                       query: ReportQuery) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report.
        
        Args:
            request: Report generation request
            query: Query configuration
            
        Returns:
            Compliance report data
        """
        start_time = datetime.utcnow()
        
        try:
            # Collect compliance data
            audit_events = self._get_compliance_events(query)
            violations = await self._detect_violations(audit_events, query)
            metrics = await self._calculate_compliance_metrics(audit_events, query)
            data_processing_summary = await self._analyze_data_processing(query)
            
            # Calculate overall compliance score
            compliance_score = self._calculate_compliance_score(metrics, violations)
            overall_status = self._determine_overall_status(compliance_score, violations)
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(violations, metrics)
            action_items = await self._generate_action_items(violations)
            
            # Processing time
            processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            return {
                "metadata": {
                    "compliance_standard": self.compliance_standard.value,
                    "report_period": {
                        "start": request.start_date.isoformat(),
                        "end": request.end_date.isoformat(),
                        "days": (request.end_date - request.start_date).days
                    },
                    "generated_at": datetime.utcnow().isoformat(),
                    "processing_time_ms": int(processing_time)
                },
                "compliance_summary": {
                    "overall_status": overall_status.value,
                    "compliance_score": round(compliance_score, 2),
                    "total_violations": len(violations),
                    "critical_violations": sum(1 for v in violations if v.severity == 'critical'),
                    "high_violations": sum(1 for v in violations if v.severity == 'high')
                },
                "metrics": [self._serialize_metric(m) for m in metrics],
                "violations": [self._serialize_violation(v) for v in violations],
                "data_processing": data_processing_summary,
                "recommendations": recommendations,
                "action_items": action_items,
                "evidence": await self._collect_evidence(audit_events, violations)
            }
            
        except Exception as e:
            logger.error(f"Compliance report generation failed: {e}")
            raise
    
    def _get_compliance_events(self, query: ReportQuery) -> List[AuditEvent]:
        """Get audit events relevant to compliance."""
        compliance_event_types = [
            'user_created', 'user_updated', 'user_deleted',
            'document_uploaded', 'document_processed', 'document_downloaded',
            'pii_detected', 'pii_redacted', 'data_export', 'data_import',
            'policy_applied', 'consent_given', 'consent_withdrawn'
        ]
        
        return self.session.query(AuditEvent).filter(
            AuditEvent.event_timestamp >= query.start_date,
            AuditEvent.event_timestamp <= query.end_date,
            AuditEvent.event_type.in_(compliance_event_types)
        ).all()
    
    @abstractmethod
    async def _detect_violations(self, events: List[AuditEvent], 
                               query: ReportQuery) -> List[ComplianceViolation]:
        """Detect compliance violations from audit events."""
        pass
    
    @abstractmethod
    async def _calculate_compliance_metrics(self, events: List[AuditEvent],
                                          query: ReportQuery) -> List[ComplianceMetric]:
        """Calculate compliance-specific metrics."""
        pass
    
    async def _analyze_data_processing(self, query: ReportQuery) -> Dict[str, Any]:
        """Analyze data processing activities."""
        # Get data processing logs
        processing_logs = self.session.query(DataProcessingLog).filter(
            DataProcessingLog.created_at >= query.start_date,
            DataProcessingLog.created_at <= query.end_date
        ).all()
        
        # Get document processing data
        documents = self.session.query(Document).filter(
            Document.created_at >= query.start_date,
            Document.created_at <= query.end_date
        ).all()
        
        # Calculate processing metrics
        total_documents = len(documents)
        total_processing_operations = len(processing_logs)
        
        # PII processing analysis
        pii_events = self.session.query(AuditEvent).filter(
            AuditEvent.event_timestamp >= query.start_date,
            AuditEvent.event_timestamp <= query.end_date,
            AuditEvent.contains_pii == True
        ).all()
        
        return {
            "documents_processed": total_documents,
            "processing_operations": total_processing_operations,
            "pii_events": len(pii_events),
            "unique_data_subjects": len(set(e.user_id for e in pii_events if e.user_id)),
            "processing_purposes": self._analyze_processing_purposes(processing_logs),
            "data_categories": self._analyze_data_categories(pii_events),
            "retention_compliance": await self._check_retention_compliance(query)
        }
    
    def _analyze_processing_purposes(self, logs: List[DataProcessingLog]) -> Dict[str, int]:
        """Analyze processing purposes from logs."""
        purposes = {}
        for log in logs:
            if log.processing_purpose:
                purposes[log.processing_purpose] = purposes.get(log.processing_purpose, 0) + 1
        return purposes
    
    def _analyze_data_categories(self, events: List[AuditEvent]) -> Dict[str, int]:
        """Analyze data categories from PII events."""
        categories = {}
        for event in events:
            if event.metadata and 'pii_types' in event.metadata:
                for pii_type in event.metadata['pii_types']:
                    categories[pii_type] = categories.get(pii_type, 0) + 1
        return categories
    
    async def _check_retention_compliance(self, query: ReportQuery) -> Dict[str, Any]:
        """Check data retention compliance."""
        # Get active policies with retention rules
        policies = self.session.query(Policy).filter(
            Policy.is_active == True,
            Policy.max_retention_days.isnot(None)
        ).all()
        
        retention_violations = []
        for policy in policies:
            # Find documents that exceed retention period
            cutoff_date = datetime.utcnow() - timedelta(days=policy.max_retention_days)
            old_documents = self.session.query(Document).filter(
                Document.created_at < cutoff_date,
                Document.status != 'deleted'
            ).all()
            
            if old_documents:
                retention_violations.append({
                    "policy_id": str(policy.id),
                    "policy_name": policy.name,
                    "retention_days": policy.max_retention_days,
                    "overdue_documents": len(old_documents),
                    "oldest_document": min(doc.created_at for doc in old_documents).isoformat()
                })
        
        return {
            "compliant": len(retention_violations) == 0,
            "violations": retention_violations,
            "total_policies_checked": len(policies)
        }
    
    def _calculate_compliance_score(self, metrics: List[ComplianceMetric], 
                                  violations: List[ComplianceViolation]) -> float:
        """Calculate overall compliance score (0-100)."""
        if not metrics:
            return 0.0
        
        # Base score from metrics
        metric_scores = []
        for metric in metrics:
            if metric.status == ComplianceStatus.COMPLIANT:
                metric_scores.append(100)
            elif metric.status == ComplianceStatus.PARTIALLY_COMPLIANT:
                metric_scores.append(75)
            elif metric.status == ComplianceStatus.NEEDS_REVIEW:
                metric_scores.append(50)
            else:
                metric_scores.append(0)
        
        base_score = sum(metric_scores) / len(metric_scores)
        
        # Deduct points for violations
        violation_penalties = {
            'critical': 20,
            'high': 10,
            'medium': 5,
            'low': 2
        }
        
        penalty = sum(violation_penalties.get(v.severity, 5) for v in violations)
        
        final_score = max(0, base_score - penalty)
        return min(100, final_score)
    
    def _determine_overall_status(self, score: float, 
                                violations: List[ComplianceViolation]) -> ComplianceStatus:
        """Determine overall compliance status."""
        critical_violations = sum(1 for v in violations if v.severity == 'critical')
        
        if critical_violations > 0:
            return ComplianceStatus.NON_COMPLIANT
        elif score >= 90:
            return ComplianceStatus.COMPLIANT
        elif score >= 70:
            return ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            return ComplianceStatus.NON_COMPLIANT
    
    @abstractmethod
    async def _generate_recommendations(self, violations: List[ComplianceViolation],
                                      metrics: List[ComplianceMetric]) -> List[str]:
        """Generate compliance recommendations."""
        pass
    
    async def _generate_action_items(self, violations: List[ComplianceViolation]) -> List[Dict[str, Any]]:
        """Generate actionable items from violations."""
        action_items = []
        
        for violation in violations:
            if violation.remediation_required:
                action_items.append({
                    "id": f"action_{len(action_items) + 1}",
                    "title": f"Remediate {violation.title}",
                    "description": violation.description,
                    "priority": violation.severity,
                    "deadline": violation.remediation_deadline.isoformat() if violation.remediation_deadline else None,
                    "actions": violation.remediation_actions,
                    "affected_records": violation.affected_records,
                    "status": "pending"
                })
        
        return action_items
    
    async def _collect_evidence(self, events: List[AuditEvent], 
                              violations: List[ComplianceViolation]) -> List[Dict[str, Any]]:
        """Collect evidence for compliance report."""
        evidence = []
        
        # Sample audit events as evidence
        for event in events[:10]:  # Limit for report size
            evidence.append({
                "type": "audit_event",
                "id": str(event.id),
                "timestamp": event.event_timestamp.isoformat(),
                "event_type": event.event_type,
                "description": event.event_description
            })
        
        # Violation evidence
        for violation in violations:
            for evidence_item in violation.evidence:
                evidence.append({
                    "type": "violation_evidence",
                    "violation_id": violation.title,
                    **evidence_item
                })
        
        return evidence
    
    def _serialize_metric(self, metric: ComplianceMetric) -> Dict[str, Any]:
        """Serialize compliance metric for output."""
        return {
            "name": metric.metric_name,
            "value": metric.metric_value,
            "target": metric.target_value,
            "status": metric.status.value,
            "trend": metric.trend,
            "measured_at": metric.measurement_date.isoformat(),
            "details": metric.details
        }
    
    def _serialize_violation(self, violation: ComplianceViolation) -> Dict[str, Any]:
        """Serialize compliance violation for output."""
        return {
            "type": violation.violation_type.value,
            "severity": violation.severity,
            "title": violation.title,
            "description": violation.description,
            "affected_records": violation.affected_records,
            "affected_users": [str(uid) for uid in violation.affected_users],
            "detected_at": violation.detected_at.isoformat(),
            "legal_basis": violation.legal_basis,
            "remediation_required": violation.remediation_required,
            "remediation_deadline": violation.remediation_deadline.isoformat() if violation.remediation_deadline else None,
            "remediation_actions": violation.remediation_actions,
            "risk_score": violation.risk_score
        }
    
    def validate_compliance_data(self, events: List[AuditEvent]) -> List[str]:
        """Validate that required compliance data is present."""
        issues = []
        
        # Check for required events
        event_types = set(e.event_type for e in events)
        required_events = {'user_created', 'document_processed', 'pii_detected'}
        missing_events = required_events - event_types
        
        if missing_events:
            issues.append(f"Missing required event types: {missing_events}")
        
        # Check for complete user information
        incomplete_events = [e for e in events if not e.user_id and e.event_type != 'system_event']
        if incomplete_events:
            issues.append(f"Found {len(incomplete_events)} events without user information")
        
        return issues