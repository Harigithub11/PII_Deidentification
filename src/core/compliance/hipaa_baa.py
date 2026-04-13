"""
HIPAA Business Associate Agreement (BAA) Support System

This module implements comprehensive BAA management, vendor compliance tracking,
and incident response workflows as required by HIPAA regulations.

Compliance: HIPAA Privacy Rule 45 CFR 164.502(e) and Security Rule 45 CFR 164.308(b)
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from uuid import UUID, uuid4
from dataclasses import dataclass, field
from enum import Enum
import json

logger = logging.getLogger(__name__)


class BAAStatus(Enum):
    """Business Associate Agreement status."""
    DRAFT = "draft"
    PENDING_SIGNATURE = "pending_signature"
    ACTIVE = "active"
    EXPIRED = "expired"
    TERMINATED = "terminated"
    UNDER_REVIEW = "under_review"


class ComplianceLevel(Enum):
    """Vendor compliance assessment levels."""
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"
    UNDER_ASSESSMENT = "under_assessment"


class IncidentSeverity(Enum):
    """HIPAA incident severity levels."""
    LOW = "low"                    # Minor technical violation, no PHI exposure
    MEDIUM = "medium"             # Policy violation, minimal PHI exposure
    HIGH = "high"                 # Significant PHI exposure, reportable
    CRITICAL = "critical"         # Major breach, immediate notification required


@dataclass
class BusinessAssociate:
    """Business Associate information and compliance tracking."""
    
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    organization_type: str = ""
    contact_person: str = ""
    contact_email: str = ""
    contact_phone: str = ""
    
    # BAA Information
    baa_signed_date: Optional[datetime] = None
    baa_expiration_date: Optional[datetime] = None
    baa_status: BAAStatus = BAAStatus.DRAFT
    baa_document_path: Optional[str] = None
    
    # Services and PHI Access
    services_provided: List[str] = field(default_factory=list)
    phi_access_level: str = "none"  # none, limited, full
    phi_categories_accessed: List[str] = field(default_factory=list)
    
    # Compliance Information
    compliance_level: ComplianceLevel = ComplianceLevel.UNKNOWN
    last_assessment_date: Optional[datetime] = None
    compliance_notes: str = ""
    
    # Security Measures
    security_measures: Dict[str, Any] = field(default_factory=dict)
    encryption_required: bool = True
    access_controls_implemented: bool = False
    audit_logging_enabled: bool = False
    
    # Metadata
    created_date: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    created_by: Optional[str] = None


@dataclass
class BAATemplate:
    """BAA template for different types of business associates."""
    
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    description: str = ""
    template_type: str = "standard"  # standard, technology, healthcare, financial
    
    # Required clauses
    required_safeguards: List[str] = field(default_factory=list)
    permitted_uses: List[str] = field(default_factory=list)
    prohibited_activities: List[str] = field(default_factory=list)
    
    # Compliance requirements
    security_requirements: Dict[str, Any] = field(default_factory=dict)
    reporting_requirements: List[str] = field(default_factory=list)
    
    # Template content
    template_content: str = ""
    version: str = "1.0"
    effective_date: datetime = field(default_factory=datetime.now)


@dataclass
class ComplianceIncident:
    """HIPAA compliance incident tracking."""
    
    id: UUID = field(default_factory=uuid4)
    title: str = ""
    description: str = ""
    severity: IncidentSeverity = IncidentSeverity.LOW
    
    # Incident details
    incident_date: datetime = field(default_factory=datetime.now)
    discovered_date: datetime = field(default_factory=datetime.now)
    business_associate_id: Optional[UUID] = None
    
    # Impact assessment
    phi_involved: bool = False
    phi_categories_affected: List[str] = field(default_factory=list)
    individuals_affected: int = 0
    potential_harm_level: str = "low"
    
    # Response tracking
    response_actions: List[Dict[str, Any]] = field(default_factory=list)
    notification_sent: bool = False
    notification_date: Optional[datetime] = None
    resolution_date: Optional[datetime] = None
    
    # Compliance
    breach_notification_required: bool = False
    regulatory_notification_required: bool = False
    
    # Metadata
    reported_by: Optional[str] = None
    assigned_to: Optional[str] = None
    status: str = "open"


class HIPAABAAManager:
    """
    Comprehensive HIPAA Business Associate Agreement management system.
    
    Handles BAA lifecycle, compliance tracking, and incident management.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize storage (in production, this would be database-backed)
        self.business_associates: Dict[UUID, BusinessAssociate] = {}
        self.baa_templates: Dict[UUID, BAATemplate] = {}
        self.incidents: Dict[UUID, ComplianceIncident] = {}
        
        # Initialize default templates
        self._initialize_default_templates()
        
        # Compliance tracking
        self.compliance_metrics = {
            "total_business_associates": 0,
            "active_baas": 0,
            "expired_baas": 0,
            "compliance_rate": 0.0,
            "open_incidents": 0,
            "high_severity_incidents": 0
        }
    
    def _initialize_default_templates(self):
        """Initialize default BAA templates for common scenarios."""
        
        # Standard Technology Services BAA
        tech_template = BAATemplate(
            name="Technology Services BAA Template",
            description="Standard BAA for technology service providers",
            template_type="technology",
            required_safeguards=[
                "Implement appropriate administrative, physical, and technical safeguards",
                "Ensure workforce members access PHI only as necessary",
                "Report security incidents within 72 hours",
                "Return or destroy PHI at termination of agreement"
            ],
            permitted_uses=[
                "Provide services specified in the underlying agreement",
                "Data aggregation services if permitted",
                "Create de-identified health information if specified"
            ],
            prohibited_activities=[
                "Use or disclose PHI other than as permitted",
                "Use PHI for marketing purposes",
                "Sell PHI without authorization"
            ],
            security_requirements={
                "encryption_at_rest": True,
                "encryption_in_transit": True,
                "access_controls": True,
                "audit_logging": True,
                "incident_response": True,
                "vulnerability_management": True,
                "security_assessments": "annual"
            },
            reporting_requirements=[
                "Monthly security status reports",
                "Immediate incident notification",
                "Annual compliance certification",
                "Audit log reviews quarterly"
            ],
            template_content="""
BUSINESS ASSOCIATE AGREEMENT

This Business Associate Agreement ("Agreement") is entered into by and between [COVERED ENTITY] and [BUSINESS ASSOCIATE] to ensure compliance with the Health Insurance Portability and Accountability Act of 1996 ("HIPAA") and its implementing regulations.

DEFINITIONS
For purposes of this Agreement, the following terms shall have the meanings ascribed:
- "Protected Health Information" or "PHI" has the same meaning as in 45 CFR 164.501
- "Business Associate" has the same meaning as in 45 CFR 160.103
- [Additional definitions...]

PERMITTED USES AND DISCLOSURES
Business Associate may use or disclose PHI only:
1. As necessary to provide services specified in the underlying agreement
2. For proper management and administration of Business Associate
3. To carry out legal responsibilities of Business Associate
4. As required by law

PROHIBITED USES AND DISCLOSURES
Business Associate shall not:
1. Use or disclose PHI other than as permitted by this Agreement
2. Use PHI for marketing purposes
3. Sell PHI without prior written authorization

SAFEGUARDS
Business Associate shall implement appropriate administrative, physical, and technical safeguards to prevent unauthorized use or disclosure of PHI.

[Additional clauses...]
            """
        )
        
        self.baa_templates[tech_template.id] = tech_template
        
        # Healthcare Services BAA
        healthcare_template = BAATemplate(
            name="Healthcare Services BAA Template",
            description="BAA template for healthcare service providers",
            template_type="healthcare",
            required_safeguards=[
                "HIPAA-compliant workforce training",
                "Physical safeguards for PHI storage areas",
                "Technical safeguards including encryption and access controls",
                "Regular security risk assessments"
            ],
            permitted_uses=[
                "Treatment, payment, and healthcare operations",
                "Quality assessment and improvement activities",
                "Case management and care coordination"
            ],
            security_requirements={
                "hipaa_training": "required",
                "background_checks": True,
                "facility_security": True,
                "workstation_security": True,
                "device_controls": True
            }
        )
        
        self.baa_templates[healthcare_template.id] = healthcare_template
    
    def create_business_associate(
        self, 
        name: str,
        organization_type: str = "",
        contact_person: str = "",
        contact_email: str = "",
        **kwargs
    ) -> BusinessAssociate:
        """Create a new business associate record."""
        
        ba = BusinessAssociate(
            name=name,
            organization_type=organization_type,
            contact_person=contact_person,
            contact_email=contact_email,
            **kwargs
        )
        
        self.business_associates[ba.id] = ba
        self._update_compliance_metrics()
        
        self.logger.info(f"Created business associate: {name} ({ba.id})")
        return ba
    
    def update_business_associate(
        self, 
        ba_id: UUID, 
        updates: Dict[str, Any]
    ) -> Optional[BusinessAssociate]:
        """Update business associate information."""
        
        if ba_id not in self.business_associates:
            self.logger.error(f"Business associate not found: {ba_id}")
            return None
        
        ba = self.business_associates[ba_id]
        
        for key, value in updates.items():
            if hasattr(ba, key):
                setattr(ba, key, value)
        
        ba.last_updated = datetime.now()
        self._update_compliance_metrics()
        
        self.logger.info(f"Updated business associate: {ba_id}")
        return ba
    
    def execute_baa(
        self, 
        ba_id: UUID,
        template_id: UUID,
        custom_terms: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Execute a BAA using a template."""
        
        if ba_id not in self.business_associates:
            self.logger.error(f"Business associate not found: {ba_id}")
            return False
        
        if template_id not in self.baa_templates:
            self.logger.error(f"BAA template not found: {template_id}")
            return False
        
        ba = self.business_associates[ba_id]
        template = self.baa_templates[template_id]
        
        # Update BAA information
        ba.baa_signed_date = datetime.now()
        ba.baa_expiration_date = datetime.now() + timedelta(days=365 * 2)  # 2 years default
        ba.baa_status = BAAStatus.ACTIVE
        
        # Apply security requirements from template
        ba.security_measures.update(template.security_requirements)
        
        # Log BAA execution
        self.logger.info(f"BAA executed for {ba.name} using template {template.name}")
        
        # Update metrics
        self._update_compliance_metrics()
        
        return True
    
    def assess_compliance(self, ba_id: UUID) -> Dict[str, Any]:
        """Perform compliance assessment for a business associate."""
        
        if ba_id not in self.business_associates:
            return {"error": "Business associate not found"}
        
        ba = self.business_associates[ba_id]
        assessment_results = {
            "business_associate_id": str(ba_id),
            "assessment_date": datetime.now().isoformat(),
            "compliance_score": 0.0,
            "findings": [],
            "recommendations": []
        }
        
        score = 0.0
        max_score = 10.0
        
        # Check BAA status
        if ba.baa_status == BAAStatus.ACTIVE:
            score += 2.0
            assessment_results["findings"].append("✅ Active BAA in place")
        else:
            assessment_results["findings"].append("❌ No active BAA")
            assessment_results["recommendations"].append("Execute current BAA")
        
        # Check expiration
        if ba.baa_expiration_date and ba.baa_expiration_date > datetime.now():
            score += 1.0
            assessment_results["findings"].append("✅ BAA not expired")
        else:
            assessment_results["findings"].append("⚠️ BAA expired or no expiration date")
            assessment_results["recommendations"].append("Renew BAA")
        
        # Check security measures
        required_measures = ["encryption_at_rest", "encryption_in_transit", "access_controls"]
        implemented_measures = 0
        
        for measure in required_measures:
            if ba.security_measures.get(measure, False):
                implemented_measures += 1
                assessment_results["findings"].append(f"✅ {measure.replace('_', ' ').title()} implemented")
            else:
                assessment_results["findings"].append(f"❌ {measure.replace('_', ' ').title()} missing")
                assessment_results["recommendations"].append(f"Implement {measure.replace('_', ' ')}")
        
        score += (implemented_measures / len(required_measures)) * 3.0
        
        # Check audit logging
        if ba.audit_logging_enabled:
            score += 1.0
            assessment_results["findings"].append("✅ Audit logging enabled")
        else:
            assessment_results["findings"].append("❌ Audit logging not enabled")
            assessment_results["recommendations"].append("Enable audit logging")
        
        # Check access controls
        if ba.access_controls_implemented:
            score += 1.0
            assessment_results["findings"].append("✅ Access controls implemented")
        else:
            assessment_results["findings"].append("❌ Access controls not implemented")
            assessment_results["recommendations"].append("Implement access controls")
        
        # Check PHI access level appropriateness
        if ba.phi_access_level in ["none", "limited"]:
            score += 1.0
            assessment_results["findings"].append("✅ Appropriate PHI access level")
        else:
            assessment_results["findings"].append("⚠️ Review PHI access level necessity")
            assessment_results["recommendations"].append("Review and minimize PHI access")
        
        # Check recent assessment
        if ba.last_assessment_date and (datetime.now() - ba.last_assessment_date).days < 365:
            score += 1.0
            assessment_results["findings"].append("✅ Recent compliance assessment completed")
        else:
            assessment_results["findings"].append("❌ Compliance assessment overdue")
            assessment_results["recommendations"].append("Schedule compliance assessment")
        
        # Calculate final score
        compliance_score = (score / max_score) * 100
        assessment_results["compliance_score"] = compliance_score
        
        # Determine compliance level
        if compliance_score >= 90:
            ba.compliance_level = ComplianceLevel.COMPLIANT
        elif compliance_score >= 70:
            ba.compliance_level = ComplianceLevel.PARTIALLY_COMPLIANT
        else:
            ba.compliance_level = ComplianceLevel.NON_COMPLIANT
        
        ba.last_assessment_date = datetime.now()
        
        self.logger.info(f"Compliance assessment completed for {ba.name}: {compliance_score:.1f}%")
        return assessment_results
    
    def create_incident(
        self,
        title: str,
        description: str,
        severity: IncidentSeverity,
        business_associate_id: Optional[UUID] = None,
        phi_involved: bool = False,
        **kwargs
    ) -> ComplianceIncident:
        """Create a new compliance incident."""
        
        incident = ComplianceIncident(
            title=title,
            description=description,
            severity=severity,
            business_associate_id=business_associate_id,
            phi_involved=phi_involved,
            **kwargs
        )
        
        self.incidents[incident.id] = incident
        
        # Automatic breach assessment
        if phi_involved and severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]:
            incident.breach_notification_required = True
            incident.regulatory_notification_required = True
        
        self._update_compliance_metrics()
        
        self.logger.warning(f"Compliance incident created: {title} (Severity: {severity.value})")
        return incident
    
    def process_incident_response(self, incident_id: UUID, action: str, details: Dict[str, Any]) -> bool:
        """Process incident response action."""
        
        if incident_id not in self.incidents:
            self.logger.error(f"Incident not found: {incident_id}")
            return False
        
        incident = self.incidents[incident_id]
        
        response_action = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details,
            "performed_by": details.get("performed_by", "system")
        }
        
        incident.response_actions.append(response_action)
        
        # Handle specific actions
        if action == "breach_notification_sent":
            incident.notification_sent = True
            incident.notification_date = datetime.now()
        elif action == "incident_resolved":
            incident.status = "resolved"
            incident.resolution_date = datetime.now()
        
        self.logger.info(f"Incident response action processed: {action} for incident {incident_id}")
        return True
    
    def generate_compliance_report(self, start_date: Optional[datetime] = None) -> Dict[str, Any]:
        """Generate comprehensive compliance report."""
        
        if not start_date:
            start_date = datetime.now() - timedelta(days=30)
        
        report = {
            "report_date": datetime.now().isoformat(),
            "period_start": start_date.isoformat(),
            "period_end": datetime.now().isoformat(),
            "summary": self.compliance_metrics.copy(),
            "business_associates": [],
            "incidents": [],
            "recommendations": []
        }
        
        # Business Associate Summary
        for ba in self.business_associates.values():
            ba_summary = {
                "id": str(ba.id),
                "name": ba.name,
                "baa_status": ba.baa_status.value,
                "compliance_level": ba.compliance_level.value,
                "phi_access_level": ba.phi_access_level,
                "last_assessment_date": ba.last_assessment_date.isoformat() if ba.last_assessment_date else None
            }
            report["business_associates"].append(ba_summary)
        
        # Recent Incidents
        for incident in self.incidents.values():
            if incident.incident_date >= start_date:
                incident_summary = {
                    "id": str(incident.id),
                    "title": incident.title,
                    "severity": incident.severity.value,
                    "phi_involved": incident.phi_involved,
                    "status": incident.status,
                    "breach_notification_required": incident.breach_notification_required
                }
                report["incidents"].append(incident_summary)
        
        # Generate recommendations
        report["recommendations"] = self._generate_compliance_recommendations()
        
        return report
    
    def _generate_compliance_recommendations(self) -> List[str]:
        """Generate compliance recommendations based on current state."""
        
        recommendations = []
        
        # Check for expired BAAs
        expired_count = sum(
            1 for ba in self.business_associates.values()
            if ba.baa_expiration_date and ba.baa_expiration_date < datetime.now()
        )
        if expired_count > 0:
            recommendations.append(f"Renew {expired_count} expired BAA(s)")
        
        # Check for overdue assessments
        overdue_assessments = sum(
            1 for ba in self.business_associates.values()
            if not ba.last_assessment_date or 
            (datetime.now() - ba.last_assessment_date).days > 365
        )
        if overdue_assessments > 0:
            recommendations.append(f"Complete {overdue_assessments} overdue compliance assessment(s)")
        
        # Check for high-risk business associates
        high_risk = sum(
            1 for ba in self.business_associates.values()
            if ba.compliance_level == ComplianceLevel.NON_COMPLIANT
        )
        if high_risk > 0:
            recommendations.append(f"Address {high_risk} non-compliant business associate(s)")
        
        # Check for open incidents
        open_incidents = sum(
            1 for incident in self.incidents.values()
            if incident.status == "open"
        )
        if open_incidents > 0:
            recommendations.append(f"Resolve {open_incidents} open incident(s)")
        
        return recommendations
    
    def _update_compliance_metrics(self):
        """Update compliance metrics."""
        
        total_bas = len(self.business_associates)
        active_baas = sum(
            1 for ba in self.business_associates.values()
            if ba.baa_status == BAAStatus.ACTIVE
        )
        expired_baas = sum(
            1 for ba in self.business_associates.values()
            if ba.baa_expiration_date and ba.baa_expiration_date < datetime.now()
        )
        
        compliant_bas = sum(
            1 for ba in self.business_associates.values()
            if ba.compliance_level == ComplianceLevel.COMPLIANT
        )
        
        open_incidents = sum(
            1 for incident in self.incidents.values()
            if incident.status == "open"
        )
        
        high_severity_incidents = sum(
            1 for incident in self.incidents.values()
            if incident.severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]
            and incident.status == "open"
        )
        
        self.compliance_metrics.update({
            "total_business_associates": total_bas,
            "active_baas": active_baas,
            "expired_baas": expired_baas,
            "compliance_rate": (compliant_bas / total_bas * 100) if total_bas > 0 else 0.0,
            "open_incidents": open_incidents,
            "high_severity_incidents": high_severity_incidents
        })
    
    def get_expiring_baas(self, days_ahead: int = 30) -> List[BusinessAssociate]:
        """Get BAAs expiring within specified days."""
        
        cutoff_date = datetime.now() + timedelta(days=days_ahead)
        
        expiring = [
            ba for ba in self.business_associates.values()
            if ba.baa_expiration_date and ba.baa_expiration_date <= cutoff_date
            and ba.baa_status == BAAStatus.ACTIVE
        ]
        
        return sorted(expiring, key=lambda x: x.baa_expiration_date)
    
    def get_compliance_metrics(self) -> Dict[str, Any]:
        """Get current compliance metrics."""
        return self.compliance_metrics.copy()


# Global BAA manager instance
baa_manager = HIPAABAAManager()