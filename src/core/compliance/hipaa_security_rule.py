"""
HIPAA Security Rule Implementation

This module implements comprehensive HIPAA Security Rule compliance including
administrative, physical, and technical safeguards as required by 45 CFR 164.308-312.

Compliance Standards:
- Administrative Safeguards (45 CFR 164.308)
- Physical Safeguards (45 CFR 164.310)
- Technical Safeguards (45 CFR 164.312)
- Organizational Requirements (45 CFR 164.314)
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from uuid import UUID, uuid4
from dataclasses import dataclass, field
from enum import Enum
import json
import hashlib
import os

logger = logging.getLogger(__name__)


class SafeguardType(Enum):
    """HIPAA Security Rule safeguard types."""
    ADMINISTRATIVE = "administrative"
    PHYSICAL = "physical"
    TECHNICAL = "technical"
    ORGANIZATIONAL = "organizational"


class ComplianceStatus(Enum):
    """Compliance status for security controls."""
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNDER_REVIEW = "under_review"


class ImplementationSpecification(Enum):
    """HIPAA implementation specification types."""
    REQUIRED = "required"
    ADDRESSABLE = "addressable"


@dataclass
class SecurityControl:
    """Individual HIPAA security control."""
    
    id: str
    name: str
    description: str
    safeguard_type: SafeguardType
    implementation_spec: ImplementationSpecification
    
    # Implementation details
    implemented: bool = False
    implementation_date: Optional[datetime] = None
    implementation_description: str = ""
    
    # Compliance tracking
    compliance_status: ComplianceStatus = ComplianceStatus.NOT_APPLICABLE
    last_assessment_date: Optional[datetime] = None
    assessment_notes: str = ""
    
    # Evidence and documentation
    evidence_documents: List[str] = field(default_factory=list)
    responsible_party: Optional[str] = None
    review_frequency: str = "annual"  # annual, semi-annual, quarterly
    
    # Risk and criticality
    criticality_level: str = "medium"  # low, medium, high, critical
    associated_risks: List[str] = field(default_factory=list)


@dataclass
class SecurityAssessment:
    """Security assessment results."""
    
    id: UUID = field(default_factory=uuid4)
    assessment_date: datetime = field(default_factory=datetime.now)
    assessor: str = ""
    assessment_type: str = "internal"  # internal, external, self-assessment
    
    # Overall results
    overall_compliance_score: float = 0.0
    compliant_controls: int = 0
    total_controls: int = 0
    high_risk_findings: int = 0
    
    # Detailed results
    control_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Remediation tracking
    remediation_plan: List[Dict[str, Any]] = field(default_factory=list)
    next_assessment_date: Optional[datetime] = None


class HIPAASecurityRuleManager:
    """
    Comprehensive HIPAA Security Rule implementation and compliance manager.
    
    Manages all required and addressable implementation specifications
    across administrative, physical, and technical safeguards.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize security controls
        self.security_controls: Dict[str, SecurityControl] = {}
        self._initialize_hipaa_security_controls()
        
        # Assessment tracking
        self.assessments: Dict[UUID, SecurityAssessment] = {}
        
        # Configuration
        self.organization_info = {
            "name": "",
            "security_officer": "",
            "contact_email": "",
            "covered_entity_type": "",
            "workforce_size": 0
        }
        
        # Compliance metrics
        self.compliance_metrics = {
            "overall_compliance_percentage": 0.0,
            "administrative_compliance": 0.0,
            "physical_compliance": 0.0,
            "technical_compliance": 0.0,
            "last_assessment_date": None,
            "high_risk_controls": 0,
            "overdue_reviews": 0
        }
    
    def _initialize_hipaa_security_controls(self):
        """Initialize all HIPAA Security Rule controls."""
        
        # Administrative Safeguards (45 CFR 164.308)
        admin_controls = [
            SecurityControl(
                id="164.308(a)(1)",
                name="Security Officer",
                description="Assign security responsibilities to one individual",
                safeguard_type=SafeguardType.ADMINISTRATIVE,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="critical",
                associated_risks=["Lack of security leadership", "Unclear responsibilities"]
            ),
            SecurityControl(
                id="164.308(a)(2)",
                name="Assigned Security Responsibilities",
                description="Assign security responsibilities to all workforce members",
                safeguard_type=SafeguardType.ADMINISTRATIVE,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="high"
            ),
            SecurityControl(
                id="164.308(a)(3)(i)",
                name="Workforce Training and Access Management",
                description="Implement procedures for authorizing access to ePHI",
                safeguard_type=SafeguardType.ADMINISTRATIVE,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="critical"
            ),
            SecurityControl(
                id="164.308(a)(3)(ii)(A)",
                name="Authorization Procedures",
                description="Procedures for granting access to ePHI",
                safeguard_type=SafeguardType.ADMINISTRATIVE,
                implementation_spec=ImplementationSpecification.ADDRESSABLE,
                criticality_level="high"
            ),
            SecurityControl(
                id="164.308(a)(3)(ii)(B)",
                name="Workforce Clearance Procedures",
                description="Procedures for determining workforce member access",
                safeguard_type=SafeguardType.ADMINISTRATIVE,
                implementation_spec=ImplementationSpecification.ADDRESSABLE,
                criticality_level="medium"
            ),
            SecurityControl(
                id="164.308(a)(3)(ii)(C)",
                name="Termination Procedures",
                description="Procedures for terminating access to ePHI",
                safeguard_type=SafeguardType.ADMINISTRATIVE,
                implementation_spec=ImplementationSpecification.ADDRESSABLE,
                criticality_level="high"
            ),
            SecurityControl(
                id="164.308(a)(4)(i)",
                name="Information Access Management",
                description="Implement policies and procedures for authorizing access",
                safeguard_type=SafeguardType.ADMINISTRATIVE,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="critical"
            ),
            SecurityControl(
                id="164.308(a)(5)(i)",
                name="Security Awareness Training",
                description="Implement security awareness and training program",
                safeguard_type=SafeguardType.ADMINISTRATIVE,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="high"
            ),
            SecurityControl(
                id="164.308(a)(6)(i)",
                name="Security Incident Procedures",
                description="Implement procedures to address security incidents",
                safeguard_type=SafeguardType.ADMINISTRATIVE,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="critical"
            ),
            SecurityControl(
                id="164.308(a)(7)(i)",
                name="Contingency Plan",
                description="Establish procedures for responding to emergencies",
                safeguard_type=SafeguardType.ADMINISTRATIVE,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="critical"
            ),
            SecurityControl(
                id="164.308(a)(8)",
                name="Administrative Safeguards Evaluation",
                description="Periodically review and update administrative safeguards",
                safeguard_type=SafeguardType.ADMINISTRATIVE,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="medium",
                review_frequency="annual"
            )
        ]
        
        # Physical Safeguards (45 CFR 164.310)
        physical_controls = [
            SecurityControl(
                id="164.310(a)(1)",
                name="Facility Access Controls",
                description="Limit physical access to facilities with ePHI systems",
                safeguard_type=SafeguardType.PHYSICAL,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="high"
            ),
            SecurityControl(
                id="164.310(a)(2)(i)",
                name="Contingency Operations",
                description="Procedures allowing facility access for data restoration",
                safeguard_type=SafeguardType.PHYSICAL,
                implementation_spec=ImplementationSpecification.ADDRESSABLE,
                criticality_level="medium"
            ),
            SecurityControl(
                id="164.310(a)(2)(ii)",
                name="Facility Security Plan",
                description="Procedures to safeguard the facility and equipment",
                safeguard_type=SafeguardType.PHYSICAL,
                implementation_spec=ImplementationSpecification.ADDRESSABLE,
                criticality_level="high"
            ),
            SecurityControl(
                id="164.310(a)(2)(iii)",
                name="Access Control and Validation Procedures",
                description="Procedures for controlling and validating access",
                safeguard_type=SafeguardType.PHYSICAL,
                implementation_spec=ImplementationSpecification.ADDRESSABLE,
                criticality_level="high"
            ),
            SecurityControl(
                id="164.310(a)(2)(iv)",
                name="Maintenance Records",
                description="Procedures for maintenance records and modifications",
                safeguard_type=SafeguardType.PHYSICAL,
                implementation_spec=ImplementationSpecification.ADDRESSABLE,
                criticality_level="medium"
            ),
            SecurityControl(
                id="164.310(b)",
                name="Workstation Use",
                description="Implement policies for workstation use and access",
                safeguard_type=SafeguardType.PHYSICAL,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="high"
            ),
            SecurityControl(
                id="164.310(c)",
                name="Device and Media Controls",
                description="Implement policies for receipt and removal of hardware/software",
                safeguard_type=SafeguardType.PHYSICAL,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="high"
            )
        ]
        
        # Technical Safeguards (45 CFR 164.312)
        technical_controls = [
            SecurityControl(
                id="164.312(a)(1)",
                name="Access Control",
                description="Assign unique user identification and authentication",
                safeguard_type=SafeguardType.TECHNICAL,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="critical"
            ),
            SecurityControl(
                id="164.312(a)(2)(i)",
                name="Unique User Identification",
                description="Assign unique name/number for user identification",
                safeguard_type=SafeguardType.TECHNICAL,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="critical"
            ),
            SecurityControl(
                id="164.312(a)(2)(ii)",
                name="Emergency Access Procedures",
                description="Procedures for obtaining ePHI during emergency",
                safeguard_type=SafeguardType.TECHNICAL,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="high"
            ),
            SecurityControl(
                id="164.312(a)(2)(iii)",
                name="Automatic Logoff",
                description="Terminate session after predetermined time of inactivity",
                safeguard_type=SafeguardType.TECHNICAL,
                implementation_spec=ImplementationSpecification.ADDRESSABLE,
                criticality_level="medium"
            ),
            SecurityControl(
                id="164.312(a)(2)(iv)",
                name="Encryption and Decryption",
                description="Encrypt and decrypt ePHI",
                safeguard_type=SafeguardType.TECHNICAL,
                implementation_spec=ImplementationSpecification.ADDRESSABLE,
                criticality_level="critical"
            ),
            SecurityControl(
                id="164.312(b)",
                name="Audit Controls",
                description="Implement audit controls to record access to ePHI",
                safeguard_type=SafeguardType.TECHNICAL,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="critical"
            ),
            SecurityControl(
                id="164.312(c)(1)",
                name="Integrity",
                description="Protect ePHI from improper alteration or destruction",
                safeguard_type=SafeguardType.TECHNICAL,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="high"
            ),
            SecurityControl(
                id="164.312(c)(2)",
                name="Mechanism to Authenticate ePHI",
                description="Implement electronic mechanisms to corroborate ePHI integrity",
                safeguard_type=SafeguardType.TECHNICAL,
                implementation_spec=ImplementationSpecification.ADDRESSABLE,
                criticality_level="medium"
            ),
            SecurityControl(
                id="164.312(d)",
                name="Person or Entity Authentication",
                description="Verify person or entity seeking access is who they claim to be",
                safeguard_type=SafeguardType.TECHNICAL,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="critical"
            ),
            SecurityControl(
                id="164.312(e)(1)",
                name="Transmission Security",
                description="Guard against unauthorized access to ePHI during transmission",
                safeguard_type=SafeguardType.TECHNICAL,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="critical"
            ),
            SecurityControl(
                id="164.312(e)(2)(i)",
                name="Integrity Controls",
                description="Ensure ePHI is not improperly modified during transmission",
                safeguard_type=SafeguardType.TECHNICAL,
                implementation_spec=ImplementationSpecification.ADDRESSABLE,
                criticality_level="high"
            ),
            SecurityControl(
                id="164.312(e)(2)(ii)",
                name="Encryption",
                description="Encrypt ePHI whenever appropriate",
                safeguard_type=SafeguardType.TECHNICAL,
                implementation_spec=ImplementationSpecification.ADDRESSABLE,
                criticality_level="critical"
            )
        ]
        
        # Organizational Requirements (45 CFR 164.314)
        organizational_controls = [
            SecurityControl(
                id="164.314(a)(1)",
                name="Business Associate Contracts",
                description="Ensure business associate agreements contain security requirements",
                safeguard_type=SafeguardType.ORGANIZATIONAL,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="critical"
            ),
            SecurityControl(
                id="164.314(b)(1)",
                name="Requirements for Group Health Plans",
                description="Ensure plan documents incorporate security requirements",
                safeguard_type=SafeguardType.ORGANIZATIONAL,
                implementation_spec=ImplementationSpecification.REQUIRED,
                criticality_level="medium"
            )
        ]
        
        # Add all controls to the main dictionary
        all_controls = admin_controls + physical_controls + technical_controls + organizational_controls
        for control in all_controls:
            self.security_controls[control.id] = control
    
    def implement_control(
        self, 
        control_id: str, 
        implementation_description: str,
        responsible_party: str,
        evidence_documents: Optional[List[str]] = None
    ) -> bool:
        """Mark a security control as implemented."""
        
        if control_id not in self.security_controls:
            self.logger.error(f"Security control not found: {control_id}")
            return False
        
        control = self.security_controls[control_id]
        control.implemented = True
        control.implementation_date = datetime.now()
        control.implementation_description = implementation_description
        control.responsible_party = responsible_party
        control.compliance_status = ComplianceStatus.COMPLIANT
        
        if evidence_documents:
            control.evidence_documents.extend(evidence_documents)
        
        self.logger.info(f"Security control implemented: {control_id}")
        self._update_compliance_metrics()
        return True
    
    def assess_control_compliance(
        self, 
        control_id: str, 
        compliance_status: ComplianceStatus,
        assessment_notes: str = "",
        assessor: str = ""
    ) -> bool:
        """Assess compliance status of a security control."""
        
        if control_id not in self.security_controls:
            self.logger.error(f"Security control not found: {control_id}")
            return False
        
        control = self.security_controls[control_id]
        control.compliance_status = compliance_status
        control.last_assessment_date = datetime.now()
        control.assessment_notes = assessment_notes
        
        # If marked as compliant but not implemented, mark as implemented
        if compliance_status == ComplianceStatus.COMPLIANT and not control.implemented:
            control.implemented = True
            control.implementation_date = datetime.now()
        
        self.logger.info(f"Control {control_id} assessed as {compliance_status.value}")
        self._update_compliance_metrics()
        return True
    
    def conduct_security_assessment(
        self, 
        assessor: str,
        assessment_type: str = "internal"
    ) -> SecurityAssessment:
        """Conduct comprehensive security assessment."""
        
        assessment = SecurityAssessment(
            assessor=assessor,
            assessment_type=assessment_type
        )
        
        total_controls = len(self.security_controls)
        compliant_controls = 0
        high_risk_findings = 0
        
        for control_id, control in self.security_controls.items():
            # Assess each control
            control_result = {
                "control_id": control_id,
                "control_name": control.name,
                "safeguard_type": control.safeguard_type.value,
                "implementation_spec": control.implementation_spec.value,
                "implemented": control.implemented,
                "compliance_status": control.compliance_status.value,
                "criticality_level": control.criticality_level,
                "last_assessment": control.last_assessment_date.isoformat() if control.last_assessment_date else None
            }
            
            # Check compliance
            if control.compliance_status == ComplianceStatus.COMPLIANT:
                compliant_controls += 1
            elif control.compliance_status in [ComplianceStatus.NON_COMPLIANT, ComplianceStatus.PARTIALLY_COMPLIANT]:
                if control.criticality_level in ["high", "critical"]:
                    high_risk_findings += 1
                    
                    # Add finding
                    finding = {
                        "control_id": control_id,
                        "finding_type": "non_compliance",
                        "severity": control.criticality_level,
                        "description": f"Control {control_id} ({control.name}) is not compliant",
                        "recommendation": self._get_control_recommendation(control)
                    }
                    assessment.findings.append(finding)
            
            assessment.control_results[control_id] = control_result
        
        # Calculate overall compliance score
        assessment.total_controls = total_controls
        assessment.compliant_controls = compliant_controls
        assessment.high_risk_findings = high_risk_findings
        assessment.overall_compliance_score = (compliant_controls / total_controls) * 100
        
        # Generate recommendations
        assessment.recommendations = self._generate_assessment_recommendations(assessment)
        
        # Create remediation plan
        assessment.remediation_plan = self._create_remediation_plan(assessment)
        
        # Set next assessment date
        assessment.next_assessment_date = datetime.now() + timedelta(days=365)
        
        # Store assessment
        self.assessments[assessment.id] = assessment
        
        self.logger.info(
            f"Security assessment completed: {assessment.overall_compliance_score:.1f}% compliance, "
            f"{high_risk_findings} high-risk findings"
        )
        
        return assessment
    
    def _get_control_recommendation(self, control: SecurityControl) -> str:
        """Get implementation recommendation for a control."""
        
        recommendations = {
            "164.308(a)(1)": "Designate a Security Officer and document their responsibilities",
            "164.308(a)(3)(i)": "Implement workforce training and access management procedures",
            "164.308(a)(4)(i)": "Develop information access management policies and procedures",
            "164.308(a)(5)(i)": "Implement comprehensive security awareness training program",
            "164.308(a)(6)(i)": "Establish incident response procedures and team",
            "164.308(a)(7)(i)": "Develop and test business continuity/disaster recovery plan",
            "164.310(a)(1)": "Implement physical access controls for facilities",
            "164.310(b)": "Establish workstation use policies and monitoring",
            "164.310(c)": "Implement device and media control procedures",
            "164.312(a)(1)": "Implement role-based access controls with unique user IDs",
            "164.312(a)(2)(iv)": "Implement encryption for ePHI at rest and in transit",
            "164.312(b)": "Deploy comprehensive audit logging and monitoring",
            "164.312(c)(1)": "Implement data integrity controls and monitoring",
            "164.312(d)": "Implement multi-factor authentication",
            "164.312(e)(1)": "Implement secure transmission protocols (TLS/HTTPS)",
            "164.314(a)(1)": "Ensure all BAAs contain required security provisions"
        }
        
        return recommendations.get(
            control.id, 
            f"Implement appropriate controls for {control.name}"
        )
    
    def _generate_assessment_recommendations(self, assessment: SecurityAssessment) -> List[str]:
        """Generate high-level recommendations based on assessment results."""
        
        recommendations = []
        
        if assessment.overall_compliance_score < 70:
            recommendations.append("Urgent: Overall compliance below 70% - immediate remediation required")
        
        if assessment.high_risk_findings > 5:
            recommendations.append("High priority: Multiple critical controls non-compliant")
        
        # Safeguard-specific recommendations
        admin_compliance = self._calculate_safeguard_compliance(SafeguardType.ADMINISTRATIVE, assessment)
        if admin_compliance < 80:
            recommendations.append("Focus on administrative safeguards - policies and procedures need attention")
        
        physical_compliance = self._calculate_safeguard_compliance(SafeguardType.PHYSICAL, assessment)
        if physical_compliance < 80:
            recommendations.append("Strengthen physical safeguards - facility and device security")
        
        technical_compliance = self._calculate_safeguard_compliance(SafeguardType.TECHNICAL, assessment)
        if technical_compliance < 80:
            recommendations.append("Enhance technical safeguards - access controls and encryption")
        
        # Critical control checks
        critical_controls = [
            "164.308(a)(1)",  # Security Officer
            "164.312(a)(1)",  # Access Control
            "164.312(b)",     # Audit Controls
            "164.312(d)",     # Authentication
            "164.312(e)(1)"   # Transmission Security
        ]
        
        non_compliant_critical = [
            control_id for control_id in critical_controls
            if control_id in assessment.control_results
            and assessment.control_results[control_id]["compliance_status"] != "compliant"
        ]
        
        if non_compliant_critical:
            recommendations.append(
                f"Critical: {len(non_compliant_critical)} critical controls non-compliant - "
                "immediate attention required"
            )
        
        return recommendations
    
    def _calculate_safeguard_compliance(
        self, 
        safeguard_type: SafeguardType, 
        assessment: SecurityAssessment
    ) -> float:
        """Calculate compliance percentage for a specific safeguard type."""
        
        relevant_controls = [
            result for result in assessment.control_results.values()
            if result["safeguard_type"] == safeguard_type.value
        ]
        
        if not relevant_controls:
            return 100.0
        
        compliant_controls = [
            control for control in relevant_controls
            if control["compliance_status"] == "compliant"
        ]
        
        return (len(compliant_controls) / len(relevant_controls)) * 100
    
    def _create_remediation_plan(self, assessment: SecurityAssessment) -> List[Dict[str, Any]]:
        """Create prioritized remediation plan based on assessment findings."""
        
        remediation_items = []
        
        # Sort findings by severity and implementation priority
        high_priority_findings = [
            f for f in assessment.findings
            if f["severity"] in ["critical", "high"]
        ]
        
        for finding in high_priority_findings:
            control_id = finding["control_id"]
            control = self.security_controls.get(control_id)
            
            if control:
                remediation_item = {
                    "control_id": control_id,
                    "control_name": control.name,
                    "priority": "high" if control.criticality_level == "critical" else "medium",
                    "estimated_effort": self._estimate_implementation_effort(control),
                    "target_completion": self._calculate_target_completion(control),
                    "responsible_party": control.responsible_party or "To Be Assigned",
                    "recommendation": finding["recommendation"],
                    "status": "planned"
                }
                remediation_items.append(remediation_item)
        
        # Sort by priority and estimated effort
        remediation_items.sort(key=lambda x: (
            0 if x["priority"] == "high" else 1,
            x["estimated_effort"]
        ))
        
        return remediation_items
    
    def _estimate_implementation_effort(self, control: SecurityControl) -> int:
        """Estimate implementation effort in days."""
        
        effort_estimates = {
            "164.308(a)(1)": 5,   # Security Officer designation
            "164.308(a)(3)(i)": 15,  # Workforce training
            "164.308(a)(4)(i)": 10,  # Access management
            "164.308(a)(5)(i)": 20,  # Security training program
            "164.308(a)(6)(i)": 15,  # Incident procedures
            "164.308(a)(7)(i)": 30,  # Contingency plan
            "164.310(a)(1)": 10,  # Facility access controls
            "164.310(b)": 7,      # Workstation use
            "164.310(c)": 10,     # Device controls
            "164.312(a)(1)": 20,  # Access control system
            "164.312(a)(2)(iv)": 15,  # Encryption
            "164.312(b)": 10,     # Audit controls
            "164.312(c)(1)": 7,   # Integrity controls
            "164.312(d)": 10,     # Authentication
            "164.312(e)(1)": 7,   # Transmission security
            "164.314(a)(1)": 5    # BAA requirements
        }
        
        return effort_estimates.get(control.id, 10)  # Default 10 days
    
    def _calculate_target_completion(self, control: SecurityControl) -> datetime:
        """Calculate target completion date based on criticality."""
        
        days_ahead = {
            "critical": 30,
            "high": 60,
            "medium": 90,
            "low": 120
        }
        
        return datetime.now() + timedelta(days=days_ahead[control.criticality_level])
    
    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate comprehensive HIPAA Security Rule compliance report."""
        
        # Get latest assessment
        latest_assessment = None
        if self.assessments:
            latest_assessment = max(self.assessments.values(), key=lambda x: x.assessment_date)
        
        report = {
            "report_date": datetime.now().isoformat(),
            "organization": self.organization_info,
            "executive_summary": self._generate_executive_summary(latest_assessment),
            "compliance_overview": self.compliance_metrics,
            "safeguard_analysis": self._analyze_safeguards(),
            "control_summary": self._summarize_controls(),
            "risk_analysis": self._analyze_risks(),
            "recommendations": [],
            "remediation_status": self._get_remediation_status(),
            "next_steps": []
        }
        
        if latest_assessment:
            report["latest_assessment"] = {
                "assessment_id": str(latest_assessment.id),
                "assessment_date": latest_assessment.assessment_date.isoformat(),
                "assessor": latest_assessment.assessor,
                "overall_score": latest_assessment.overall_compliance_score,
                "findings_count": len(latest_assessment.findings),
                "high_risk_findings": latest_assessment.high_risk_findings
            }
            report["recommendations"] = latest_assessment.recommendations
        
        # Generate next steps
        report["next_steps"] = self._generate_next_steps(latest_assessment)
        
        return report
    
    def _generate_executive_summary(self, assessment: Optional[SecurityAssessment]) -> str:
        """Generate executive summary for compliance report."""
        
        if not assessment:
            return "No security assessment completed. Initial assessment required."
        
        compliance_score = assessment.overall_compliance_score
        
        if compliance_score >= 90:
            status = "Excellent"
            concern_level = "low"
        elif compliance_score >= 80:
            status = "Good"
            concern_level = "moderate"
        elif compliance_score >= 70:
            status = "Acceptable"
            concern_level = "moderate"
        else:
            status = "Needs Improvement"
            concern_level = "high"
        
        summary = f"""
        HIPAA Security Rule Compliance Status: {status} ({compliance_score:.1f}%)
        
        As of {assessment.assessment_date.strftime('%B %d, %Y')}, the organization has achieved 
        {compliance_score:.1f}% compliance with HIPAA Security Rule requirements. 
        
        Key Metrics:
        - Total Controls Assessed: {assessment.total_controls}
        - Compliant Controls: {assessment.compliant_controls}
        - High-Risk Findings: {assessment.high_risk_findings}
        - Risk Level: {concern_level.title()}
        
        {len(assessment.recommendations)} recommendations have been identified for continued improvement.
        """
        
        return summary.strip()
    
    def _analyze_safeguards(self) -> Dict[str, Any]:
        """Analyze compliance by safeguard type."""
        
        safeguard_analysis = {}
        
        for safeguard_type in SafeguardType:
            controls = [
                control for control in self.security_controls.values()
                if control.safeguard_type == safeguard_type
            ]
            
            total_controls = len(controls)
            compliant_controls = len([
                c for c in controls 
                if c.compliance_status == ComplianceStatus.COMPLIANT
            ])
            
            compliance_percentage = (compliant_controls / total_controls * 100) if total_controls > 0 else 0
            
            safeguard_analysis[safeguard_type.value] = {
                "total_controls": total_controls,
                "compliant_controls": compliant_controls,
                "compliance_percentage": compliance_percentage,
                "critical_controls": len([c for c in controls if c.criticality_level == "critical"]),
                "high_priority_controls": len([c for c in controls if c.criticality_level == "high"])
            }
        
        return safeguard_analysis
    
    def _summarize_controls(self) -> Dict[str, Any]:
        """Summarize control implementation status."""
        
        status_counts = {}
        for status in ComplianceStatus:
            status_counts[status.value] = len([
                c for c in self.security_controls.values()
                if c.compliance_status == status
            ])
        
        return {
            "total_controls": len(self.security_controls),
            "implemented_controls": len([
                c for c in self.security_controls.values() if c.implemented
            ]),
            "status_distribution": status_counts,
            "overdue_reviews": len([
                c for c in self.security_controls.values()
                if c.last_assessment_date and 
                (datetime.now() - c.last_assessment_date).days > 365
            ])
        }
    
    def _analyze_risks(self) -> Dict[str, Any]:
        """Analyze security risks based on control compliance."""
        
        high_risk_controls = [
            control for control in self.security_controls.values()
            if control.criticality_level in ["critical", "high"]
            and control.compliance_status != ComplianceStatus.COMPLIANT
        ]
        
        risk_categories = {}
        for control in high_risk_controls:
            category = control.safeguard_type.value
            if category not in risk_categories:
                risk_categories[category] = []
            risk_categories[category].append({
                "control_id": control.id,
                "control_name": control.name,
                "criticality": control.criticality_level,
                "status": control.compliance_status.value
            })
        
        return {
            "high_risk_control_count": len(high_risk_controls),
            "risk_categories": risk_categories,
            "overall_risk_level": self._calculate_overall_risk_level()
        }
    
    def _calculate_overall_risk_level(self) -> str:
        """Calculate overall organizational risk level."""
        
        critical_non_compliant = len([
            c for c in self.security_controls.values()
            if c.criticality_level == "critical" 
            and c.compliance_status != ComplianceStatus.COMPLIANT
        ])
        
        if critical_non_compliant > 3:
            return "Critical"
        elif critical_non_compliant > 0:
            return "High"
        elif self.compliance_metrics["overall_compliance_percentage"] < 70:
            return "Medium"
        else:
            return "Low"
    
    def _get_remediation_status(self) -> Dict[str, Any]:
        """Get status of ongoing remediation efforts."""
        
        # This would track actual remediation progress in a full implementation
        return {
            "active_remediation_items": 0,
            "completed_items": 0,
            "overdue_items": 0,
            "target_completion_date": None
        }
    
    def _generate_next_steps(self, assessment: Optional[SecurityAssessment]) -> List[str]:
        """Generate recommended next steps."""
        
        next_steps = []
        
        if not assessment:
            next_steps.append("Conduct initial HIPAA Security Rule assessment")
            next_steps.append("Designate Security Officer and define responsibilities")
            next_steps.append("Implement critical technical safeguards (access control, encryption)")
            return next_steps
        
        if assessment.overall_compliance_score < 70:
            next_steps.append("Address critical and high-priority findings immediately")
        
        if assessment.high_risk_findings > 0:
            next_steps.append("Focus on high-risk findings in remediation plan")
        
        # Check for specific critical controls
        critical_controls_needed = []
        critical_control_ids = ["164.308(a)(1)", "164.312(a)(1)", "164.312(b)", "164.312(d)"]
        
        for control_id in critical_control_ids:
            if (control_id in assessment.control_results and 
                assessment.control_results[control_id]["compliance_status"] != "compliant"):
                critical_controls_needed.append(control_id)
        
        if critical_controls_needed:
            next_steps.append(f"Implement critical controls: {', '.join(critical_controls_needed)}")
        
        # Assessment follow-up
        days_since_assessment = (datetime.now() - assessment.assessment_date).days
        if days_since_assessment > 365:
            next_steps.append("Schedule annual compliance assessment")
        elif days_since_assessment > 180:
            next_steps.append("Begin preparing for next annual assessment")
        
        next_steps.append("Continue monitoring and maintaining implemented controls")
        
        return next_steps
    
    def _update_compliance_metrics(self):
        """Update overall compliance metrics."""
        
        total_controls = len(self.security_controls)
        compliant_controls = len([
            c for c in self.security_controls.values()
            if c.compliance_status == ComplianceStatus.COMPLIANT
        ])
        
        # Calculate safeguard-specific compliance
        admin_compliance = self._calculate_safeguard_compliance_simple(SafeguardType.ADMINISTRATIVE)
        physical_compliance = self._calculate_safeguard_compliance_simple(SafeguardType.PHYSICAL)
        technical_compliance = self._calculate_safeguard_compliance_simple(SafeguardType.TECHNICAL)
        
        high_risk_controls = len([
            c for c in self.security_controls.values()
            if c.criticality_level in ["critical", "high"]
            and c.compliance_status != ComplianceStatus.COMPLIANT
        ])
        
        overdue_reviews = len([
            c for c in self.security_controls.values()
            if c.last_assessment_date and 
            (datetime.now() - c.last_assessment_date).days > 365
        ])
        
        self.compliance_metrics.update({
            "overall_compliance_percentage": (compliant_controls / total_controls * 100) if total_controls > 0 else 0,
            "administrative_compliance": admin_compliance,
            "physical_compliance": physical_compliance,
            "technical_compliance": technical_compliance,
            "last_assessment_date": datetime.now().isoformat(),
            "high_risk_controls": high_risk_controls,
            "overdue_reviews": overdue_reviews
        })
    
    def _calculate_safeguard_compliance_simple(self, safeguard_type: SafeguardType) -> float:
        """Calculate compliance percentage for safeguard type (simple version)."""
        
        controls = [
            c for c in self.security_controls.values()
            if c.safeguard_type == safeguard_type
        ]
        
        if not controls:
            return 100.0
        
        compliant = [
            c for c in controls
            if c.compliance_status == ComplianceStatus.COMPLIANT
        ]
        
        return (len(compliant) / len(controls)) * 100
    
    def get_control_details(self, control_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific control."""
        
        if control_id not in self.security_controls:
            return None
        
        control = self.security_controls[control_id]
        
        return {
            "id": control.id,
            "name": control.name,
            "description": control.description,
            "safeguard_type": control.safeguard_type.value,
            "implementation_spec": control.implementation_spec.value,
            "implemented": control.implemented,
            "implementation_date": control.implementation_date.isoformat() if control.implementation_date else None,
            "implementation_description": control.implementation_description,
            "compliance_status": control.compliance_status.value,
            "last_assessment_date": control.last_assessment_date.isoformat() if control.last_assessment_date else None,
            "assessment_notes": control.assessment_notes,
            "evidence_documents": control.evidence_documents,
            "responsible_party": control.responsible_party,
            "review_frequency": control.review_frequency,
            "criticality_level": control.criticality_level,
            "associated_risks": control.associated_risks
        }
    
    def get_compliance_dashboard_data(self) -> Dict[str, Any]:
        """Get data for compliance dashboard."""
        
        return {
            "overall_metrics": self.compliance_metrics,
            "safeguard_breakdown": self._analyze_safeguards(),
            "control_summary": self._summarize_controls(),
            "recent_assessments": [
                {
                    "id": str(a.id),
                    "date": a.assessment_date.isoformat(),
                    "score": a.overall_compliance_score,
                    "assessor": a.assessor
                }
                for a in sorted(self.assessments.values(), key=lambda x: x.assessment_date, reverse=True)[:5]
            ],
            "upcoming_reviews": [
                {
                    "control_id": c.id,
                    "control_name": c.name,
                    "last_review": c.last_assessment_date.isoformat() if c.last_assessment_date else None,
                    "due_date": (c.last_assessment_date + timedelta(days=365)).isoformat() if c.last_assessment_date else "Overdue"
                }
                for c in self.security_controls.values()
                if not c.last_assessment_date or (datetime.now() - c.last_assessment_date).days > 300
            ][:10]
        }


# Global instance
security_rule_manager = HIPAASecurityRuleManager()