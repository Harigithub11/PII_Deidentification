"""
GDPR Breach Management System (Articles 33-34)
Enhanced data breach detection, assessment, notification, and management
"""
from typing import Dict, List, Optional, Any, Union, Set
from dataclasses import dataclass, field
from enum import Enum
import uuid
import json
from datetime import datetime, timedelta
import logging
import hashlib
from pathlib import Path
import asyncio
from collections import defaultdict

from ..database.db_manager import DatabaseManager
from ..security.encryption_manager import EncryptionManager
from ..config.settings import get_settings


logger = logging.getLogger(__name__)
settings = get_settings()


class BreachSeverity(Enum):
    """Breach severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BreachType(Enum):
    """Types of data breaches"""
    CONFIDENTIALITY_BREACH = "confidentiality_breach"  # Unauthorized access
    INTEGRITY_BREACH = "integrity_breach"  # Data alteration
    AVAILABILITY_BREACH = "availability_breach"  # Data unavailability
    COMBINED_BREACH = "combined_breach"  # Multiple types


class BreachStatus(Enum):
    """Breach investigation status"""
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    ASSESSED = "assessed"
    NOTIFIED_AUTHORITY = "notified_authority"
    NOTIFIED_INDIVIDUALS = "notified_individuals"
    RESOLVED = "resolved"
    CLOSED = "closed"


class NotificationStatus(Enum):
    """Notification status for authorities and individuals"""
    NOT_REQUIRED = "not_required"
    REQUIRED = "required"
    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    DELAYED = "delayed"
    FAILED = "failed"


class RiskLevel(Enum):
    """Risk to rights and freedoms of individuals"""
    NO_RISK = "no_risk"
    LOW_RISK = "low_risk"
    HIGH_RISK = "high_risk"
    CRITICAL_RISK = "critical_risk"


@dataclass
class AffectedDataSubject:
    """Information about affected data subjects"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    data_subject_id: Optional[str] = None
    categories: List[str] = field(default_factory=list)  # Personal data categories affected
    sensitivity_level: str = "normal"  # normal, sensitive, special_category
    estimated_records: int = 0
    contact_information: Dict[str, str] = field(default_factory=dict)
    notification_required: bool = False
    notification_sent: bool = False
    notification_timestamp: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "data_subject_id": self.data_subject_id,
            "categories": self.categories,
            "sensitivity_level": self.sensitivity_level,
            "estimated_records": self.estimated_records,
            "contact_information": self.contact_information,
            "notification_required": self.notification_required,
            "notification_sent": self.notification_sent,
            "notification_timestamp": self.notification_timestamp.isoformat() if self.notification_timestamp else None
        }


@dataclass
class BreachAssessment:
    """Breach risk assessment and impact analysis"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    breach_id: str = ""
    assessor: str = ""
    assessment_timestamp: datetime = field(default_factory=datetime.now)
    
    # Impact assessment
    risk_level: RiskLevel = RiskLevel.LOW_RISK
    likelihood_of_harm: str = "low"  # low, medium, high
    severity_of_harm: str = "low"
    impact_factors: List[str] = field(default_factory=list)
    
    # Data categories affected
    affected_data_categories: List[str] = field(default_factory=list)
    special_categories_affected: bool = False
    vulnerable_groups_affected: bool = False
    
    # Technical assessment
    security_measures_in_place: List[str] = field(default_factory=list)
    additional_measures_taken: List[str] = field(default_factory=list)
    
    # Notification requirements
    authority_notification_required: bool = True
    individual_notification_required: bool = False
    notification_reasoning: str = ""
    
    # Mitigation measures
    immediate_actions: List[str] = field(default_factory=list)
    long_term_measures: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "breach_id": self.breach_id,
            "assessor": self.assessor,
            "assessment_timestamp": self.assessment_timestamp.isoformat(),
            "risk_level": self.risk_level.value,
            "likelihood_of_harm": self.likelihood_of_harm,
            "severity_of_harm": self.severity_of_harm,
            "impact_factors": self.impact_factors,
            "affected_data_categories": self.affected_data_categories,
            "special_categories_affected": self.special_categories_affected,
            "vulnerable_groups_affected": self.vulnerable_groups_affected,
            "security_measures_in_place": self.security_measures_in_place,
            "additional_measures_taken": self.additional_measures_taken,
            "authority_notification_required": self.authority_notification_required,
            "individual_notification_required": self.individual_notification_required,
            "notification_reasoning": self.notification_reasoning,
            "immediate_actions": self.immediate_actions,
            "long_term_measures": self.long_term_measures
        }


@dataclass
class BreachNotification:
    """Breach notification record"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    breach_id: str = ""
    notification_type: str = ""  # authority, individuals, media
    recipient: str = ""
    notification_timestamp: datetime = field(default_factory=datetime.now)
    notification_method: str = ""  # email, letter, phone, web
    
    # Notification content
    notification_content: Dict[str, Any] = field(default_factory=dict)
    language: str = "en"
    
    # Response tracking
    acknowledgment_required: bool = True
    acknowledgment_received: bool = False
    acknowledgment_timestamp: Optional[datetime] = None
    response_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "breach_id": self.breach_id,
            "notification_type": self.notification_type,
            "recipient": self.recipient,
            "notification_timestamp": self.notification_timestamp.isoformat(),
            "notification_method": self.notification_method,
            "notification_content": self.notification_content,
            "language": self.language,
            "acknowledgment_required": self.acknowledgment_required,
            "acknowledgment_received": self.acknowledgment_received,
            "acknowledgment_timestamp": self.acknowledgment_timestamp.isoformat() if self.acknowledgment_timestamp else None,
            "response_data": self.response_data
        }


@dataclass
class DataBreach:
    """Data breach incident record"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    breach_type: BreachType = BreachType.CONFIDENTIALITY_BREACH
    severity: BreachSeverity = BreachSeverity.MEDIUM
    status: BreachStatus = BreachStatus.DETECTED
    
    # Temporal information
    detected_timestamp: datetime = field(default_factory=datetime.now)
    occurred_timestamp: Optional[datetime] = None
    resolved_timestamp: Optional[datetime] = None
    
    # Detection information
    detection_method: str = ""  # automated, manual, third_party, data_subject
    detected_by: str = ""
    detection_source: str = ""
    
    # Incident details
    affected_systems: List[str] = field(default_factory=list)
    affected_data_categories: List[str] = field(default_factory=list)
    estimated_affected_records: int = 0
    affected_data_subjects: List[AffectedDataSubject] = field(default_factory=list)
    
    # Cause analysis
    root_cause: str = ""
    contributing_factors: List[str] = field(default_factory=list)
    human_error_involved: bool = False
    technical_failure_involved: bool = False
    malicious_activity_involved: bool = False
    
    # Containment and response
    containment_measures: List[str] = field(default_factory=list)
    containment_timestamp: Optional[datetime] = None
    
    # Assessment and notifications
    breach_assessment: Optional[BreachAssessment] = None
    notifications: List[BreachNotification] = field(default_factory=list)
    
    # Compliance tracking
    authority_notification_deadline: Optional[datetime] = None
    authority_notified: bool = False
    individual_notification_required: bool = False
    individuals_notified: bool = False
    
    # Investigation tracking
    investigation_team: List[str] = field(default_factory=list)
    investigation_notes: List[str] = field(default_factory=list)
    evidence_collected: List[str] = field(default_factory=list)
    forensic_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Legal and regulatory
    regulatory_reporting_required: bool = True
    legal_counsel_involved: bool = False
    law_enforcement_notified: bool = False
    insurance_claim_filed: bool = False
    
    # Lessons learned and improvements
    lessons_learned: List[str] = field(default_factory=list)
    preventive_measures: List[str] = field(default_factory=list)
    policy_updates_required: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.occurred_timestamp:
            self.occurred_timestamp = self.detected_timestamp
        if not self.authority_notification_deadline:
            self.authority_notification_deadline = self.detected_timestamp + timedelta(hours=72)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "breach_type": self.breach_type.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "detected_timestamp": self.detected_timestamp.isoformat(),
            "occurred_timestamp": self.occurred_timestamp.isoformat() if self.occurred_timestamp else None,
            "resolved_timestamp": self.resolved_timestamp.isoformat() if self.resolved_timestamp else None,
            "detection_method": self.detection_method,
            "detected_by": self.detected_by,
            "detection_source": self.detection_source,
            "affected_systems": self.affected_systems,
            "affected_data_categories": self.affected_data_categories,
            "estimated_affected_records": self.estimated_affected_records,
            "affected_data_subjects": [ds.to_dict() for ds in self.affected_data_subjects],
            "root_cause": self.root_cause,
            "contributing_factors": self.contributing_factors,
            "human_error_involved": self.human_error_involved,
            "technical_failure_involved": self.technical_failure_involved,
            "malicious_activity_involved": self.malicious_activity_involved,
            "containment_measures": self.containment_measures,
            "containment_timestamp": self.containment_timestamp.isoformat() if self.containment_timestamp else None,
            "breach_assessment": self.breach_assessment.to_dict() if self.breach_assessment else None,
            "notifications": [n.to_dict() for n in self.notifications],
            "authority_notification_deadline": self.authority_notification_deadline.isoformat() if self.authority_notification_deadline else None,
            "authority_notified": self.authority_notified,
            "individual_notification_required": self.individual_notification_required,
            "individuals_notified": self.individuals_notified,
            "investigation_team": self.investigation_team,
            "investigation_notes": self.investigation_notes,
            "evidence_collected": self.evidence_collected,
            "forensic_analysis": self.forensic_analysis,
            "regulatory_reporting_required": self.regulatory_reporting_required,
            "legal_counsel_involved": self.legal_counsel_involved,
            "law_enforcement_notified": self.law_enforcement_notified,
            "insurance_claim_filed": self.insurance_claim_filed,
            "lessons_learned": self.lessons_learned,
            "preventive_measures": self.preventive_measures,
            "policy_updates_required": self.policy_updates_required
        }


class BreachManager:
    """Enhanced GDPR breach management system (Articles 33-34)"""
    
    def __init__(self,
                 db_manager: DatabaseManager,
                 encryption_manager: EncryptionManager):
        self.db_manager = db_manager
        self.encryption_manager = encryption_manager
        self.logger = logging.getLogger(__name__)
        
        # Storage
        self.active_breaches: Dict[str, DataBreach] = {}
        self.notification_templates: Dict[str, Dict[str, Any]] = {}
        
        # Configuration
        self.notification_deadlines = {
            "authority": 72,  # hours
            "individuals": 30 * 24  # hours (30 days)
        }
        
        self.risk_assessment_matrix = {
            ("high", "high"): RiskLevel.CRITICAL_RISK,
            ("high", "medium"): RiskLevel.HIGH_RISK,
            ("high", "low"): RiskLevel.HIGH_RISK,
            ("medium", "high"): RiskLevel.HIGH_RISK,
            ("medium", "medium"): RiskLevel.HIGH_RISK,
            ("medium", "low"): RiskLevel.LOW_RISK,
            ("low", "high"): RiskLevel.LOW_RISK,
            ("low", "medium"): RiskLevel.LOW_RISK,
            ("low", "low"): RiskLevel.NO_RISK
        }
        
        # Initialize templates and monitoring
        self._initialize_notification_templates()
        self._start_breach_monitoring()
    
    def _initialize_notification_templates(self):
        """Initialize notification templates for different types"""
        
        # Supervisory Authority notification template
        self.notification_templates["authority"] = {
            "subject": "GDPR Article 33 Data Breach Notification - {breach_id}",
            "template": """
Data Breach Notification - Article 33 GDPR

Breach Reference: {breach_id}
Date of Notification: {notification_date}
Data Controller: {controller_name}

1. BREACH DETAILS
Description: {description}
Breach Type: {breach_type}
Detection Date: {detection_date}
Estimated Occurrence Date: {occurrence_date}

2. AFFECTED DATA
Data Categories: {data_categories}
Number of Records: {affected_records}
Number of Data Subjects: {affected_subjects}

3. RISK ASSESSMENT
Risk Level: {risk_level}
Likely Consequences: {consequences}

4. CONTAINMENT MEASURES
Measures Taken: {containment_measures}
Current Status: {status}

5. CONTACT INFORMATION
Data Protection Officer: {dpo_contact}
Contact Details: {contact_details}

This notification is made in compliance with Article 33 of the GDPR.
""",
            "required_fields": [
                "breach_id", "notification_date", "controller_name", "description",
                "breach_type", "detection_date", "occurrence_date", "data_categories",
                "affected_records", "affected_subjects", "risk_level", "consequences",
                "containment_measures", "status", "dpo_contact", "contact_details"
            ]
        }
        
        # Data Subject notification template
        self.notification_templates["individuals"] = {
            "subject": "Important Security Notice - Your Personal Data",
            "template": """
Dear {data_subject_name},

We are writing to inform you of a security incident that may have affected your personal data.

WHAT HAPPENED:
{incident_description}

WHAT INFORMATION WAS INVOLVED:
{affected_data_types}

WHAT WE ARE DOING:
{response_measures}

WHAT YOU CAN DO:
{recommended_actions}

If you have any questions or concerns, please contact us immediately:
Email: {contact_email}
Phone: {contact_phone}

We sincerely apologize for this incident and any inconvenience it may cause.

Sincerely,
{organization_name}
Data Protection Team
""",
            "required_fields": [
                "data_subject_name", "incident_description", "affected_data_types",
                "response_measures", "recommended_actions", "contact_email",
                "contact_phone", "organization_name"
            ]
        }
    
    def _start_breach_monitoring(self):
        """Start background breach monitoring and deadline tracking"""
        # In production, this would start background tasks for:
        # 1. Deadline monitoring
        # 2. Status updates
        # 3. Automated notifications
        pass
    
    async def report_breach(self, breach_data: Dict[str, Any]) -> DataBreach:
        """Report new data breach incident"""
        
        # Create breach record
        breach = DataBreach(
            title=breach_data.get("title", "Data Breach Incident"),
            description=breach_data.get("description", ""),
            breach_type=BreachType(breach_data.get("breach_type", "confidentiality_breach")),
            severity=BreachSeverity(breach_data.get("severity", "medium")),
            detection_method=breach_data.get("detection_method", "manual"),
            detected_by=breach_data.get("detected_by", "system_administrator"),
            detection_source=breach_data.get("detection_source", "internal_monitoring"),
            affected_systems=breach_data.get("affected_systems", []),
            affected_data_categories=breach_data.get("affected_data_categories", []),
            estimated_affected_records=breach_data.get("estimated_affected_records", 0),
            root_cause=breach_data.get("root_cause", "under_investigation"),
            contributing_factors=breach_data.get("contributing_factors", [])
        )
        
        # Set occurred timestamp if provided
        if breach_data.get("occurred_timestamp"):
            breach.occurred_timestamp = datetime.fromisoformat(breach_data["occurred_timestamp"])
        
        # Add affected data subjects
        for subject_data in breach_data.get("affected_data_subjects", []):
            affected_subject = AffectedDataSubject(**subject_data)
            breach.affected_data_subjects.append(affected_subject)
        
        # Store breach
        self.active_breaches[breach.id] = breach
        
        # Log breach detection
        await self._log_breach_event(breach, "breach_detected")
        
        # Start immediate response workflow
        await self._initiate_breach_response(breach)
        
        self.logger.critical(f"Data breach reported: {breach.id} - {breach.title}")
        
        return breach
    
    async def _initiate_breach_response(self, breach: DataBreach):
        """Initiate immediate breach response procedures"""
        
        # Update status to investigating
        breach.status = BreachStatus.INVESTIGATING
        
        # Assign investigation team (in production, this would be more sophisticated)
        breach.investigation_team = ["incident_commander", "security_team", "legal_team", "privacy_team"]
        
        # Start containment measures
        await self._initiate_containment(breach)
        
        # Schedule assessment within 24 hours
        await self._schedule_breach_assessment(breach)
        
        # Check for immediate notification requirements
        await self._check_immediate_notifications(breach)
        
        await self._log_breach_event(breach, "breach_response_initiated")
    
    async def _initiate_containment(self, breach: DataBreach):
        """Initiate breach containment measures"""
        
        containment_measures = []
        
        # Standard containment based on breach type
        if breach.breach_type == BreachType.CONFIDENTIALITY_BREACH:
            containment_measures.extend([
                "Revoke unauthorized access credentials",
                "Change passwords for affected accounts",
                "Review and strengthen access controls",
                "Monitor for further unauthorized access"
            ])
        
        elif breach.breach_type == BreachType.INTEGRITY_BREACH:
            containment_measures.extend([
                "Isolate affected systems",
                "Restore data from clean backups",
                "Verify data integrity across systems",
                "Implement additional integrity controls"
            ])
        
        elif breach.breach_type == BreachType.AVAILABILITY_BREACH:
            containment_measures.extend([
                "Activate backup systems",
                "Implement temporary workarounds",
                "Restore affected services",
                "Monitor system availability"
            ])
        
        # Apply containment measures
        breach.containment_measures = containment_measures
        breach.containment_timestamp = datetime.now()
        
        await self._log_breach_event(breach, "containment_initiated", {
            "measures": containment_measures
        })
    
    async def _schedule_breach_assessment(self, breach: DataBreach):
        """Schedule formal breach assessment"""
        
        # In production, this would schedule assessment with appropriate team
        self.logger.info(f"Breach assessment scheduled for {breach.id}")
        
        # For demo, perform immediate preliminary assessment
        await self._perform_preliminary_assessment(breach)
    
    async def _perform_preliminary_assessment(self, breach: DataBreach):
        """Perform preliminary breach assessment"""
        
        # Create preliminary assessment
        assessment = BreachAssessment(
            breach_id=breach.id,
            assessor="privacy_team",
            affected_data_categories=breach.affected_data_categories,
            special_categories_affected=self._check_special_categories(breach.affected_data_categories),
            vulnerable_groups_affected=self._check_vulnerable_groups(breach.affected_data_subjects)
        )
        
        # Assess risk level
        likelihood = self._assess_likelihood_of_harm(breach)
        severity = self._assess_severity_of_harm(breach)
        assessment.likelihood_of_harm = likelihood
        assessment.severity_of_harm = severity
        assessment.risk_level = self.risk_assessment_matrix.get((likelihood, severity), RiskLevel.LOW_RISK)
        
        # Determine notification requirements
        assessment.authority_notification_required = True  # Always required under GDPR Article 33
        assessment.individual_notification_required = (
            assessment.risk_level in [RiskLevel.HIGH_RISK, RiskLevel.CRITICAL_RISK]
            or assessment.special_categories_affected
            or assessment.vulnerable_groups_affected
        )
        
        # Set immediate actions
        assessment.immediate_actions = [
            "Continue containment measures",
            "Preserve evidence for investigation",
            "Notify supervisory authority within 72 hours",
            "Prepare detailed incident report"
        ]
        
        if assessment.individual_notification_required:
            assessment.immediate_actions.append("Prepare individual notifications")
        
        # Attach assessment to breach
        breach.breach_assessment = assessment
        breach.status = BreachStatus.ASSESSED
        
        await self._log_breach_event(breach, "preliminary_assessment_completed", {
            "risk_level": assessment.risk_level.value,
            "authority_notification_required": assessment.authority_notification_required,
            "individual_notification_required": assessment.individual_notification_required
        })
    
    def _check_special_categories(self, data_categories: List[str]) -> bool:
        """Check if special categories of personal data are affected"""
        
        special_categories = [
            "health_data", "genetic_data", "biometric_data", "racial_ethnic_data",
            "political_opinions", "religious_beliefs", "philosophical_beliefs",
            "trade_union_membership", "sexual_orientation", "criminal_data"
        ]
        
        return any(category in special_categories for category in data_categories)
    
    def _check_vulnerable_groups(self, affected_subjects: List[AffectedDataSubject]) -> bool:
        """Check if vulnerable groups are affected"""
        
        vulnerable_categories = ["children", "elderly", "disabled", "patients", "employees"]
        
        return any(
            any(cat in vulnerable_categories for cat in subject.categories)
            for subject in affected_subjects
        )
    
    def _assess_likelihood_of_harm(self, breach: DataBreach) -> str:
        """Assess likelihood of harm to individuals"""
        
        score = 0
        
        # Factors increasing likelihood
        if breach.malicious_activity_involved:
            score += 2
        if breach.affected_data_categories:
            score += len(breach.affected_data_categories) // 2
        if breach.estimated_affected_records > 1000:
            score += 2
        elif breach.estimated_affected_records > 100:
            score += 1
        
        # Security measures can reduce likelihood
        if "encryption" in " ".join(breach.containment_measures).lower():
            score -= 1
        if "pseudonymization" in " ".join(breach.containment_measures).lower():
            score -= 1
        
        if score >= 4:
            return "high"
        elif score >= 2:
            return "medium"
        else:
            return "low"
    
    def _assess_severity_of_harm(self, breach: DataBreach) -> str:
        """Assess severity of potential harm"""
        
        score = 0
        
        # Special categories increase severity
        if self._check_special_categories(breach.affected_data_categories):
            score += 3
        
        # Vulnerable groups increase severity
        if self._check_vulnerable_groups(breach.affected_data_subjects):
            score += 2
        
        # Financial data
        if any("financial" in cat.lower() for cat in breach.affected_data_categories):
            score += 2
        
        # Identity data
        if any("identity" in cat.lower() for cat in breach.affected_data_categories):
            score += 1
        
        if score >= 5:
            return "high"
        elif score >= 2:
            return "medium"
        else:
            return "low"
    
    async def _check_immediate_notifications(self, breach: DataBreach):
        """Check if immediate notifications are required"""
        
        # Check if 72-hour deadline is approaching
        hours_since_detection = (datetime.now() - breach.detected_timestamp).total_seconds() / 3600
        
        if hours_since_detection >= 48:  # 24 hours before deadline
            await self._send_urgent_notification_reminder(breach)
    
    async def _send_urgent_notification_reminder(self, breach: DataBreach):
        """Send urgent notification reminder to response team"""
        
        self.logger.warning(f"Urgent: Authority notification deadline approaching for breach {breach.id}")
        
        # In production, this would send actual notifications to incident response team
        await self._log_breach_event(breach, "urgent_notification_reminder")
    
    async def notify_supervisory_authority(self, breach_id: str, additional_details: Dict[str, Any] = None) -> BreachNotification:
        """Send Article 33 notification to supervisory authority"""
        
        breach = self.active_breaches.get(breach_id)
        if not breach:
            raise ValueError(f"Breach {breach_id} not found")
        
        if not breach.breach_assessment:
            raise ValueError("Breach assessment required before authority notification")
        
        # Check if within 72-hour deadline
        hours_since_detection = (datetime.now() - breach.detected_timestamp).total_seconds() / 3600
        if hours_since_detection > 72:
            self.logger.warning(f"Authority notification for breach {breach_id} is past 72-hour deadline")
        
        # Generate notification content
        notification_content = self._generate_authority_notification_content(breach, additional_details)
        
        # Create notification record
        notification = BreachNotification(
            breach_id=breach_id,
            notification_type="authority",
            recipient="data_protection_authority",
            notification_method="secure_portal",
            notification_content=notification_content
        )
        
        # Send notification (in production, this would integrate with authority systems)
        await self._send_notification(notification)
        
        # Update breach status
        breach.notifications.append(notification)
        breach.authority_notified = True
        breach.status = BreachStatus.NOTIFIED_AUTHORITY
        
        await self._log_breach_event(breach, "authority_notified", {
            "notification_id": notification.id,
            "hours_after_detection": hours_since_detection
        })
        
        self.logger.info(f"Supervisory authority notified for breach {breach_id}")
        
        return notification
    
    async def notify_affected_individuals(self, breach_id: str, custom_message: str = None) -> List[BreachNotification]:
        """Send Article 34 notifications to affected individuals"""
        
        breach = self.active_breaches.get(breach_id)
        if not breach:
            raise ValueError(f"Breach {breach_id} not found")
        
        if not breach.breach_assessment or not breach.breach_assessment.individual_notification_required:
            raise ValueError("Individual notification not required for this breach")
        
        notifications = []
        
        for affected_subject in breach.affected_data_subjects:
            if not affected_subject.notification_required:
                continue
            
            # Generate personalized notification content
            notification_content = self._generate_individual_notification_content(
                breach, affected_subject, custom_message
            )
            
            # Create notification record
            notification = BreachNotification(
                breach_id=breach_id,
                notification_type="individuals",
                recipient=affected_subject.data_subject_id or f"subject_{affected_subject.id}",
                notification_method="email",
                notification_content=notification_content
            )
            
            # Send notification
            await self._send_notification(notification)
            
            notifications.append(notification)
            
            # Update affected subject record
            affected_subject.notification_sent = True
            affected_subject.notification_timestamp = datetime.now()
        
        # Update breach status
        breach.notifications.extend(notifications)
        breach.individuals_notified = True
        if breach.status == BreachStatus.NOTIFIED_AUTHORITY:
            breach.status = BreachStatus.NOTIFIED_INDIVIDUALS
        
        await self._log_breach_event(breach, "individuals_notified", {
            "notification_count": len(notifications)
        })
        
        self.logger.info(f"Individual notifications sent for breach {breach_id} ({len(notifications)} notifications)")
        
        return notifications
    
    def _generate_authority_notification_content(self, breach: DataBreach, additional_details: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate notification content for supervisory authority"""
        
        template = self.notification_templates["authority"]
        
        content = {
            "breach_id": breach.id,
            "notification_date": datetime.now().isoformat(),
            "controller_name": "De-identification System Company",
            "description": breach.description,
            "breach_type": breach.breach_type.value,
            "detection_date": breach.detected_timestamp.isoformat(),
            "occurrence_date": breach.occurred_timestamp.isoformat() if breach.occurred_timestamp else "Unknown",
            "data_categories": ", ".join(breach.affected_data_categories),
            "affected_records": str(breach.estimated_affected_records),
            "affected_subjects": str(len(breach.affected_data_subjects)),
            "risk_level": breach.breach_assessment.risk_level.value if breach.breach_assessment else "Under assessment",
            "consequences": ", ".join(breach.breach_assessment.impact_factors) if breach.breach_assessment else "Under assessment",
            "containment_measures": ", ".join(breach.containment_measures),
            "status": breach.status.value,
            "dpo_contact": "dpo@company.com",
            "contact_details": "Phone: +1-555-123-4567, Email: privacy@company.com"
        }
        
        # Add additional details if provided
        if additional_details:
            content.update(additional_details)
        
        # Format notification using template
        formatted_notification = template["template"].format(**content)
        
        return {
            "subject": template["subject"].format(**content),
            "body": formatted_notification,
            "structured_data": content,
            "template_used": "authority"
        }
    
    def _generate_individual_notification_content(self, 
                                                 breach: DataBreach, 
                                                 affected_subject: AffectedDataSubject,
                                                 custom_message: str = None) -> Dict[str, Any]:
        """Generate notification content for affected individuals"""
        
        template = self.notification_templates["individuals"]
        
        # Determine affected data types for this subject
        affected_data_types = ", ".join(affected_subject.categories) if affected_subject.categories else "Personal data"
        
        content = {
            "data_subject_name": affected_subject.contact_information.get("name", "Valued Customer"),
            "incident_description": breach.description or "A security incident occurred that may have affected your personal data.",
            "affected_data_types": affected_data_types,
            "response_measures": ", ".join(breach.containment_measures) if breach.containment_measures else "We have taken immediate steps to secure our systems.",
            "recommended_actions": self._get_recommended_actions_for_subject(breach, affected_subject),
            "contact_email": "privacy@company.com",
            "contact_phone": "+1-555-123-4567",
            "organization_name": "De-identification System Company"
        }
        
        # Add custom message if provided
        if custom_message:
            content["custom_message"] = custom_message
            template_body = template["template"] + "\n\nADDITIONAL INFORMATION:\n{custom_message}"
        else:
            template_body = template["template"]
        
        # Format notification using template
        formatted_notification = template_body.format(**content)
        
        return {
            "subject": template["subject"],
            "body": formatted_notification,
            "structured_data": content,
            "template_used": "individuals",
            "personalization": {
                "subject_id": affected_subject.data_subject_id,
                "categories": affected_subject.categories,
                "sensitivity_level": affected_subject.sensitivity_level
            }
        }
    
    def _get_recommended_actions_for_subject(self, breach: DataBreach, affected_subject: AffectedDataSubject) -> str:
        """Get personalized recommended actions for affected data subject"""
        
        actions = []
        
        # Standard actions
        actions.append("Monitor your accounts for any unusual activity")
        actions.append("Contact us immediately if you notice any suspicious activity")
        
        # Category-specific actions
        if "financial_data" in affected_subject.categories:
            actions.append("Review your financial statements and credit reports")
            actions.append("Consider placing a fraud alert on your credit file")
        
        if "credentials" in affected_subject.categories or "authentication" in affected_subject.categories:
            actions.append("Change your passwords for our services immediately")
            actions.append("Enable two-factor authentication if available")
        
        if "identity_data" in affected_subject.categories:
            actions.append("Be cautious of phishing attempts using your personal information")
            actions.append("Verify the authenticity of any communications claiming to be from us")
        
        if affected_subject.sensitivity_level == "special_category":
            actions.append("Contact us to discuss additional support measures available to you")
        
        return ". ".join(actions) + "."
    
    async def _send_notification(self, notification: BreachNotification):
        """Send breach notification (mock implementation)"""
        
        # In production, this would integrate with actual notification systems
        # (email, SMS, postal mail, secure portals, etc.)
        
        self.logger.info(f"Sending {notification.notification_type} notification to {notification.recipient}")
        
        # Simulate notification delivery
        await asyncio.sleep(0.1)  # Simulate network delay
        
        # For demo, we'll just log the notification
        if notification.notification_type == "authority":
            self.logger.info(f"Authority notification sent: {notification.notification_content['subject']}")
        else:
            self.logger.info(f"Individual notification sent to {notification.recipient}")
    
    async def update_breach_status(self, breach_id: str, new_status: BreachStatus, notes: str = "") -> bool:
        """Update breach investigation status"""
        
        breach = self.active_breaches.get(breach_id)
        if not breach:
            return False
        
        old_status = breach.status
        breach.status = new_status
        
        if notes:
            breach.investigation_notes.append(f"{datetime.now().isoformat()}: {notes}")
        
        # Handle status-specific actions
        if new_status == BreachStatus.RESOLVED:
            breach.resolved_timestamp = datetime.now()
            await self._handle_breach_resolution(breach)
        
        elif new_status == BreachStatus.CLOSED:
            await self._handle_breach_closure(breach)
        
        await self._log_breach_event(breach, "status_updated", {
            "old_status": old_status.value,
            "new_status": new_status.value,
            "notes": notes
        })
        
        self.logger.info(f"Breach {breach_id} status updated: {old_status.value} -> {new_status.value}")
        
        return True
    
    async def _handle_breach_resolution(self, breach: DataBreach):
        """Handle actions when breach is resolved"""
        
        # Generate lessons learned
        if not breach.lessons_learned:
            breach.lessons_learned = await self._generate_lessons_learned(breach)
        
        # Schedule post-incident review
        await self._schedule_post_incident_review(breach)
        
        await self._log_breach_event(breach, "breach_resolved")
    
    async def _generate_lessons_learned(self, breach: DataBreach) -> List[str]:
        """Generate lessons learned from the breach"""
        
        lessons = []
        
        # Root cause based lessons
        if "human_error" in breach.root_cause.lower():
            lessons.append("Enhance staff training on data handling procedures")
            lessons.append("Implement additional approval workflows for sensitive operations")
        
        if "technical_failure" in breach.root_cause.lower():
            lessons.append("Improve system monitoring and alerting")
            lessons.append("Review and update system maintenance procedures")
        
        if "malicious" in breach.root_cause.lower():
            lessons.append("Strengthen access controls and authentication")
            lessons.append("Enhance threat detection and response capabilities")
        
        # Detection method based lessons
        if breach.detection_method == "third_party":
            lessons.append("Improve internal detection capabilities")
            lessons.append("Implement proactive monitoring systems")
        
        # Response time based lessons
        hours_to_containment = 0
        if breach.containment_timestamp:
            hours_to_containment = (breach.containment_timestamp - breach.detected_timestamp).total_seconds() / 3600
        
        if hours_to_containment > 4:
            lessons.append("Improve incident response time through better procedures and training")
        
        # General lessons
        lessons.append("Regular review and testing of incident response procedures")
        lessons.append("Continuous improvement of security measures based on threat landscape")
        
        return lessons
    
    async def _schedule_post_incident_review(self, breach: DataBreach):
        """Schedule post-incident review meeting"""
        
        self.logger.info(f"Post-incident review scheduled for breach {breach.id}")
        
        # In production, this would schedule actual review meetings
        await self._log_breach_event(breach, "post_incident_review_scheduled")
    
    async def _handle_breach_closure(self, breach: DataBreach):
        """Handle actions when breach is closed"""
        
        # Final documentation
        await self._generate_final_breach_report(breach)
        
        # Archive breach data
        await self._archive_breach_data(breach)
        
        await self._log_breach_event(breach, "breach_closed")
    
    async def _generate_final_breach_report(self, breach: DataBreach):
        """Generate final comprehensive breach report"""
        
        report_data = {
            "breach_summary": breach.to_dict(),
            "timeline": self._generate_breach_timeline(breach),
            "impact_analysis": self._generate_impact_analysis(breach),
            "response_analysis": self._generate_response_analysis(breach),
            "lessons_learned": breach.lessons_learned,
            "preventive_measures": breach.preventive_measures,
            "compliance_status": self._assess_compliance_status(breach)
        }
        
        # In production, this would generate and store the actual report
        self.logger.info(f"Final breach report generated for {breach.id}")
        
        return report_data
    
    def _generate_breach_timeline(self, breach: DataBreach) -> List[Dict[str, Any]]:
        """Generate chronological timeline of breach events"""
        
        timeline = []
        
        if breach.occurred_timestamp:
            timeline.append({
                "timestamp": breach.occurred_timestamp.isoformat(),
                "event": "Breach occurred",
                "description": "Estimated time of initial security incident"
            })
        
        timeline.append({
            "timestamp": breach.detected_timestamp.isoformat(),
            "event": "Breach detected",
            "description": f"Detected by {breach.detected_by} via {breach.detection_method}"
        })
        
        if breach.containment_timestamp:
            timeline.append({
                "timestamp": breach.containment_timestamp.isoformat(),
                "event": "Containment initiated",
                "description": "Initial containment measures implemented"
            })
        
        # Add notification events
        for notification in breach.notifications:
            timeline.append({
                "timestamp": notification.notification_timestamp.isoformat(),
                "event": f"Notification sent - {notification.notification_type}",
                "description": f"Notified {notification.recipient}"
            })
        
        if breach.resolved_timestamp:
            timeline.append({
                "timestamp": breach.resolved_timestamp.isoformat(),
                "event": "Breach resolved",
                "description": "All issues resolved and systems restored"
            })
        
        return sorted(timeline, key=lambda x: x["timestamp"])
    
    def _generate_impact_analysis(self, breach: DataBreach) -> Dict[str, Any]:
        """Generate impact analysis summary"""
        
        return {
            "affected_records": breach.estimated_affected_records,
            "affected_subjects": len(breach.affected_data_subjects),
            "data_categories": breach.affected_data_categories,
            "special_categories_involved": self._check_special_categories(breach.affected_data_categories),
            "vulnerable_groups_involved": self._check_vulnerable_groups(breach.affected_data_subjects),
            "systems_affected": breach.affected_systems,
            "business_impact": self._assess_business_impact(breach),
            "regulatory_impact": self._assess_regulatory_impact(breach)
        }
    
    def _generate_response_analysis(self, breach: DataBreach) -> Dict[str, Any]:
        """Generate response effectiveness analysis"""
        
        detection_time = "Unknown"
        if breach.occurred_timestamp:
            detection_hours = (breach.detected_timestamp - breach.occurred_timestamp).total_seconds() / 3600
            detection_time = f"{detection_hours:.1f} hours"
        
        containment_time = "Unknown"
        if breach.containment_timestamp:
            containment_hours = (breach.containment_timestamp - breach.detected_timestamp).total_seconds() / 3600
            containment_time = f"{containment_hours:.1f} hours"
        
        resolution_time = "Ongoing"
        if breach.resolved_timestamp:
            resolution_hours = (breach.resolved_timestamp - breach.detected_timestamp).total_seconds() / 3600
            resolution_time = f"{resolution_hours:.1f} hours"
        
        # Check notification compliance
        notification_compliance = {}
        if breach.authority_notified:
            hours_to_notification = min(
                (notif.notification_timestamp - breach.detected_timestamp).total_seconds() / 3600
                for notif in breach.notifications
                if notif.notification_type == "authority"
            )
            notification_compliance["authority"] = {
                "compliant": hours_to_notification <= 72,
                "time_taken": f"{hours_to_notification:.1f} hours"
            }
        
        return {
            "detection_time": detection_time,
            "containment_time": containment_time,
            "resolution_time": resolution_time,
            "notification_compliance": notification_compliance,
            "containment_measures_applied": len(breach.containment_measures),
            "investigation_team_size": len(breach.investigation_team),
            "notifications_sent": len(breach.notifications)
        }
    
    def _assess_business_impact(self, breach: DataBreach) -> Dict[str, Any]:
        """Assess business impact of the breach"""
        
        impact = {
            "operational_disruption": "medium" if len(breach.affected_systems) > 1 else "low",
            "reputation_risk": "high" if breach.individual_notification_required else "medium",
            "financial_impact": "under_assessment",
            "customer_trust_impact": "medium"
        }
        
        if breach.estimated_affected_records > 10000:
            impact["reputation_risk"] = "high"
            impact["customer_trust_impact"] = "high"
        
        return impact
    
    def _assess_regulatory_impact(self, breach: DataBreach) -> Dict[str, Any]:
        """Assess regulatory compliance impact"""
        
        return {
            "gdpr_compliance": self._assess_gdpr_compliance(breach),
            "other_regulations": ["Data Protection Act", "Sector-specific regulations"],
            "potential_fines": "under_assessment",
            "regulatory_actions": "notification_completed" if breach.authority_notified else "pending"
        }
    
    def _assess_gdpr_compliance(self, breach: DataBreach) -> Dict[str, Any]:
        """Assess GDPR compliance status"""
        
        compliance = {
            "article_33_compliance": False,
            "article_34_compliance": False,
            "documentation_compliance": True,
            "overall_status": "non_compliant"
        }
        
        # Article 33 - Authority notification
        if breach.authority_notified:
            hours_to_notification = min(
                (notif.notification_timestamp - breach.detected_timestamp).total_seconds() / 3600
                for notif in breach.notifications
                if notif.notification_type == "authority"
            )
            compliance["article_33_compliance"] = hours_to_notification <= 72
        
        # Article 34 - Individual notification
        if breach.individual_notification_required:
            compliance["article_34_compliance"] = breach.individuals_notified
        else:
            compliance["article_34_compliance"] = True  # Not required
        
        # Overall compliance
        if compliance["article_33_compliance"] and compliance["article_34_compliance"]:
            compliance["overall_status"] = "compliant"
        elif compliance["article_33_compliance"] or compliance["article_34_compliance"]:
            compliance["overall_status"] = "partially_compliant"
        
        return compliance
    
    def _assess_compliance_status(self, breach: DataBreach) -> Dict[str, Any]:
        """Assess overall compliance status"""
        
        return {
            "gdpr_compliance": self._assess_gdpr_compliance(breach),
            "internal_policy_compliance": True,
            "industry_standards_compliance": "under_review",
            "regulatory_requirements_met": breach.authority_notified and (
                not breach.individual_notification_required or breach.individuals_notified
            )
        }
    
    async def _archive_breach_data(self, breach: DataBreach):
        """Archive completed breach data"""
        
        # In production, this would move data to long-term storage
        self.logger.info(f"Breach data archived for {breach.id}")
        
        await self._log_breach_event(breach, "breach_archived")
    
    async def monitor_breach_deadlines(self) -> Dict[str, Any]:
        """Monitor breach notification deadlines and compliance"""
        
        monitoring_results = {
            "active_breaches": len(self.active_breaches),
            "deadline_warnings": [],
            "overdue_notifications": [],
            "compliance_issues": []
        }
        
        current_time = datetime.now()
        
        for breach in self.active_breaches.values():
            # Check authority notification deadline (72 hours)
            hours_since_detection = (current_time - breach.detected_timestamp).total_seconds() / 3600
            
            if not breach.authority_notified:
                if hours_since_detection >= 72:
                    monitoring_results["overdue_notifications"].append({
                        "breach_id": breach.id,
                        "type": "authority",
                        "hours_overdue": hours_since_detection - 72
                    })
                elif hours_since_detection >= 48:  # 24 hours before deadline
                    monitoring_results["deadline_warnings"].append({
                        "breach_id": breach.id,
                        "type": "authority",
                        "hours_remaining": 72 - hours_since_detection
                    })
            
            # Check individual notification requirements
            if (breach.breach_assessment and 
                breach.breach_assessment.individual_notification_required and 
                not breach.individuals_notified):
                
                # Individual notifications should be "without undue delay" - typically within 30 days
                days_since_detection = hours_since_detection / 24
                if days_since_detection >= 30:
                    monitoring_results["overdue_notifications"].append({
                        "breach_id": breach.id,
                        "type": "individuals",
                        "days_overdue": days_since_detection - 30
                    })
                elif days_since_detection >= 25:  # 5 days before typical deadline
                    monitoring_results["deadline_warnings"].append({
                        "breach_id": breach.id,
                        "type": "individuals",
                        "days_remaining": 30 - days_since_detection
                    })
        
        return monitoring_results
    
    async def generate_breach_statistics(self, 
                                       start_date: Optional[datetime] = None,
                                       end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """Generate breach statistics and analytics"""
        
        if not start_date:
            start_date = datetime.now() - timedelta(days=90)  # Last 90 days
        if not end_date:
            end_date = datetime.now()
        
        # Filter breaches by date range
        filtered_breaches = [
            breach for breach in self.active_breaches.values()
            if start_date <= breach.detected_timestamp <= end_date
        ]
        
        stats = {
            "total_breaches": len(filtered_breaches),
            "by_severity": defaultdict(int),
            "by_type": defaultdict(int),
            "by_status": defaultdict(int),
            "by_detection_method": defaultdict(int),
            "notification_compliance": {
                "authority_notifications": {
                    "total": 0,
                    "on_time": 0,
                    "late": 0
                },
                "individual_notifications": {
                    "required": 0,
                    "sent": 0,
                    "pending": 0
                }
            },
            "impact_analysis": {
                "total_affected_records": 0,
                "total_affected_subjects": 0,
                "special_categories_breaches": 0,
                "vulnerable_groups_breaches": 0
            },
            "resolution_metrics": {
                "average_detection_time_hours": 0,
                "average_containment_time_hours": 0,
                "average_resolution_time_hours": 0
            }
        }
        
        # Analyze breaches
        total_detection_time = 0
        total_containment_time = 0
        total_resolution_time = 0
        valid_detection_times = 0
        valid_containment_times = 0
        valid_resolution_times = 0
        
        for breach in filtered_breaches:
            # Basic counts
            stats["by_severity"][breach.severity.value] += 1
            stats["by_type"][breach.breach_type.value] += 1
            stats["by_status"][breach.status.value] += 1
            stats["by_detection_method"][breach.detection_method] += 1
            
            # Impact metrics
            stats["impact_analysis"]["total_affected_records"] += breach.estimated_affected_records
            stats["impact_analysis"]["total_affected_subjects"] += len(breach.affected_data_subjects)
            
            if self._check_special_categories(breach.affected_data_categories):
                stats["impact_analysis"]["special_categories_breaches"] += 1
            
            if self._check_vulnerable_groups(breach.affected_data_subjects):
                stats["impact_analysis"]["vulnerable_groups_breaches"] += 1
            
            # Notification compliance
            if breach.authority_notified:
                stats["notification_compliance"]["authority_notifications"]["total"] += 1
                
                # Check if notified within 72 hours
                authority_notifications = [
                    n for n in breach.notifications
                    if n.notification_type == "authority"
                ]
                
                if authority_notifications:
                    hours_to_notification = (
                        authority_notifications[0].notification_timestamp - breach.detected_timestamp
                    ).total_seconds() / 3600
                    
                    if hours_to_notification <= 72:
                        stats["notification_compliance"]["authority_notifications"]["on_time"] += 1
                    else:
                        stats["notification_compliance"]["authority_notifications"]["late"] += 1
            
            if (breach.breach_assessment and 
                breach.breach_assessment.individual_notification_required):
                stats["notification_compliance"]["individual_notifications"]["required"] += 1
                
                if breach.individuals_notified:
                    stats["notification_compliance"]["individual_notifications"]["sent"] += 1
                else:
                    stats["notification_compliance"]["individual_notifications"]["pending"] += 1
            
            # Resolution metrics
            if breach.occurred_timestamp:
                detection_time = (breach.detected_timestamp - breach.occurred_timestamp).total_seconds() / 3600
                total_detection_time += detection_time
                valid_detection_times += 1
            
            if breach.containment_timestamp:
                containment_time = (breach.containment_timestamp - breach.detected_timestamp).total_seconds() / 3600
                total_containment_time += containment_time
                valid_containment_times += 1
            
            if breach.resolved_timestamp:
                resolution_time = (breach.resolved_timestamp - breach.detected_timestamp).total_seconds() / 3600
                total_resolution_time += resolution_time
                valid_resolution_times += 1
        
        # Calculate averages
        if valid_detection_times > 0:
            stats["resolution_metrics"]["average_detection_time_hours"] = total_detection_time / valid_detection_times
        
        if valid_containment_times > 0:
            stats["resolution_metrics"]["average_containment_time_hours"] = total_containment_time / valid_containment_times
        
        if valid_resolution_times > 0:
            stats["resolution_metrics"]["average_resolution_time_hours"] = total_resolution_time / valid_resolution_times
        
        # Convert defaultdicts to regular dicts
        stats["by_severity"] = dict(stats["by_severity"])
        stats["by_type"] = dict(stats["by_type"])
        stats["by_status"] = dict(stats["by_status"])
        stats["by_detection_method"] = dict(stats["by_detection_method"])
        
        return stats
    
    async def _log_breach_event(self, breach: DataBreach, event_type: str, metadata: Dict[str, Any] = None):
        """Log breach events for audit trail"""
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "breach_id": breach.id,
            "event_type": event_type,
            "breach_status": breach.status.value,
            "metadata": metadata or {}
        }
        
        self.logger.info(f"Breach Event: {event_type} for breach {breach.id}")
        
        # In production, this would write to audit database
    
    # Management and query methods
    def get_breach(self, breach_id: str) -> Optional[DataBreach]:
        """Get breach by ID"""
        return self.active_breaches.get(breach_id)
    
    def list_breaches(self, status: Optional[BreachStatus] = None) -> List[DataBreach]:
        """List breaches, optionally filtered by status"""
        if status:
            return [b for b in self.active_breaches.values() if b.status == status]
        return list(self.active_breaches.values())
    
    def get_breaches_by_severity(self, severity: BreachSeverity) -> List[DataBreach]:
        """Get breaches by severity level"""
        return [b for b in self.active_breaches.values() if b.severity == severity]
    
    def get_active_breaches(self) -> List[DataBreach]:
        """Get all active (non-closed) breaches"""
        return [
            b for b in self.active_breaches.values()
            if b.status != BreachStatus.CLOSED
        ]
    
    async def export_breach_data(self, breach_id: str) -> Dict[str, Any]:
        """Export comprehensive breach data for reporting"""
        
        breach = self.active_breaches.get(breach_id)
        if not breach:
            return {"error": "Breach not found"}
        
        export_data = {
            "breach_details": breach.to_dict(),
            "timeline": self._generate_breach_timeline(breach),
            "impact_analysis": self._generate_impact_analysis(breach),
            "response_analysis": self._generate_response_analysis(breach),
            "compliance_status": self._assess_compliance_status(breach),
            "export_timestamp": datetime.now().isoformat()
        }
        
        return export_data