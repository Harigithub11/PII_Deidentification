"""
GDPR Records of Processing Activities (Article 30)
Comprehensive system for maintaining and managing processing activity records
"""
from typing import Dict, List, Optional, Any, Union, Set
from dataclasses import dataclass, field
from enum import Enum
import uuid
import json
from datetime import datetime, timedelta
import logging
from pathlib import Path
import hashlib
from collections import defaultdict

from ..database.db_manager import DatabaseManager
from ..security.encryption_manager import EncryptionManager
from ..config.settings import get_settings


logger = logging.getLogger(__name__)
settings = get_settings()


class ProcessingRole(Enum):
    """Role in data processing"""
    CONTROLLER = "controller"
    PROCESSOR = "processor"
    JOINT_CONTROLLER = "joint_controller"


class LegalBasis(Enum):
    """GDPR Article 6 legal bases for processing"""
    CONSENT = "consent"  # Article 6(1)(a)
    CONTRACT = "contract"  # Article 6(1)(b)
    LEGAL_OBLIGATION = "legal_obligation"  # Article 6(1)(c)
    VITAL_INTERESTS = "vital_interests"  # Article 6(1)(d)
    PUBLIC_TASK = "public_task"  # Article 6(1)(e)
    LEGITIMATE_INTERESTS = "legitimate_interests"  # Article 6(1)(f)


class SpecialCategoryBasis(Enum):
    """GDPR Article 9 legal bases for special categories"""
    EXPLICIT_CONSENT = "explicit_consent"  # Article 9(2)(a)
    EMPLOYMENT_SOCIAL_SECURITY = "employment_social_security"  # Article 9(2)(b)
    VITAL_INTERESTS_UNABLE_CONSENT = "vital_interests_unable_consent"  # Article 9(2)(c)
    LEGITIMATE_ACTIVITIES = "legitimate_activities"  # Article 9(2)(d)
    PUBLIC_DISCLOSURE = "public_disclosure"  # Article 9(2)(e)
    LEGAL_CLAIMS = "legal_claims"  # Article 9(2)(f)
    SUBSTANTIAL_PUBLIC_INTEREST = "substantial_public_interest"  # Article 9(2)(g)
    HEALTH_CARE = "health_care"  # Article 9(2)(h)
    PUBLIC_HEALTH = "public_health"  # Article 9(2)(i)
    ARCHIVING_RESEARCH = "archiving_research"  # Article 9(2)(j)


class DataCategory(Enum):
    """Categories of personal data"""
    IDENTIFICATION_DATA = "identification_data"
    CONTACT_INFORMATION = "contact_information"
    FINANCIAL_DATA = "financial_data"
    EMPLOYMENT_DATA = "employment_data"
    EDUCATION_DATA = "education_data"
    HEALTH_DATA = "health_data"
    BIOMETRIC_DATA = "biometric_data"
    GENETIC_DATA = "genetic_data"
    CRIMINAL_DATA = "criminal_data"
    LOCATION_DATA = "location_data"
    BEHAVIORAL_DATA = "behavioral_data"
    USAGE_DATA = "usage_data"
    TECHNICAL_DATA = "technical_data"
    PREFERENCES_DATA = "preferences_data"
    COMMUNICATION_DATA = "communication_data"


class DataSubjectCategory(Enum):
    """Categories of data subjects"""
    CUSTOMERS = "customers"
    EMPLOYEES = "employees"
    PROSPECTS = "prospects"
    SUPPLIERS = "suppliers"
    PARTNERS = "partners"
    VISITORS = "visitors"
    PATIENTS = "patients"
    STUDENTS = "students"
    CHILDREN = "children"
    VULNERABLE_ADULTS = "vulnerable_adults"


class RetentionBasis(Enum):
    """Basis for data retention"""
    LEGAL_REQUIREMENT = "legal_requirement"
    CONTRACTUAL_OBLIGATION = "contractual_obligation"
    BUSINESS_NECESSITY = "business_necessity"
    CONSENT_DURATION = "consent_duration"
    LEGITIMATE_INTERESTS = "legitimate_interests"
    REGULATORY_REQUIREMENT = "regulatory_requirement"


@dataclass
class DataTransfer:
    """Details of data transfers to third parties"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    recipient_name: str = ""
    recipient_type: str = ""  # controller, processor, authority
    recipient_country: str = ""
    transfer_mechanism: str = ""  # adequacy_decision, sccs, bcrs, derogations
    transfer_purpose: str = ""
    data_categories: List[DataCategory] = field(default_factory=list)
    safeguards: List[str] = field(default_factory=list)
    frequency: str = "as_needed"  # as_needed, daily, weekly, monthly
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "recipient_name": self.recipient_name,
            "recipient_type": self.recipient_type,
            "recipient_country": self.recipient_country,
            "transfer_mechanism": self.transfer_mechanism,
            "transfer_purpose": self.transfer_purpose,
            "data_categories": [cat.value for cat in self.data_categories],
            "safeguards": self.safeguards,
            "frequency": self.frequency
        }


@dataclass
class SecurityMeasure:
    """Technical and organizational security measures"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    measure_type: str = ""  # technical, organizational
    category: str = ""  # access_control, encryption, backup, etc.
    description: str = ""
    implementation_status: str = "implemented"  # implemented, planned, partial
    responsible_party: str = ""
    review_frequency: str = "annually"
    last_review_date: Optional[datetime] = None
    next_review_date: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "measure_type": self.measure_type,
            "category": self.category,
            "description": self.description,
            "implementation_status": self.implementation_status,
            "responsible_party": self.responsible_party,
            "review_frequency": self.review_frequency,
            "last_review_date": self.last_review_date.isoformat() if self.last_review_date else None,
            "next_review_date": self.next_review_date.isoformat() if self.next_review_date else None
        }


@dataclass
class RetentionSchedule:
    """Data retention schedule"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    data_category: DataCategory = DataCategory.IDENTIFICATION_DATA
    retention_period: int = 365  # days
    retention_basis: RetentionBasis = RetentionBasis.LEGAL_REQUIREMENT
    retention_criteria: str = ""
    disposal_method: str = "secure_deletion"
    responsible_party: str = ""
    exceptions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "data_category": self.data_category.value,
            "retention_period": self.retention_period,
            "retention_basis": self.retention_basis.value,
            "retention_criteria": self.retention_criteria,
            "disposal_method": self.disposal_method,
            "responsible_party": self.responsible_party,
            "exceptions": self.exceptions
        }


@dataclass
class ProcessingActivity:
    """Record of processing activities (Article 30)"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # Basic information
    name: str = ""
    description: str = ""
    processing_role: ProcessingRole = ProcessingRole.CONTROLLER
    status: str = "active"  # active, inactive, planned, suspended
    
    # Controller/Processor information
    controller_name: str = ""
    controller_contact: str = ""
    processor_name: Optional[str] = None
    processor_contact: Optional[str] = None
    joint_controllers: List[str] = field(default_factory=list)
    
    # Data Protection Officer
    dpo_name: Optional[str] = None
    dpo_contact: Optional[str] = None
    
    # Processing details
    purposes: List[str] = field(default_factory=list)
    legal_basis: List[LegalBasis] = field(default_factory=list)
    legal_basis_details: str = ""
    
    # Special categories
    special_categories: List[DataCategory] = field(default_factory=list)
    special_category_basis: List[SpecialCategoryBasis] = field(default_factory=list)
    special_category_details: str = ""
    
    # Criminal data
    criminal_data_processed: bool = False
    criminal_data_authority: str = ""
    
    # Data subjects and categories
    data_subject_categories: List[DataSubjectCategory] = field(default_factory=list)
    data_categories: List[DataCategory] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    
    # Data volumes
    estimated_data_subjects: int = 0
    data_volume_description: str = ""
    
    # Data transfers
    transfers: List[DataTransfer] = field(default_factory=list)
    
    # Retention
    retention_schedules: List[RetentionSchedule] = field(default_factory=list)
    general_retention_period: Optional[int] = None  # days
    
    # Security measures
    security_measures: List[SecurityMeasure] = field(default_factory=list)
    
    # Automated processing
    automated_processing: bool = False
    automated_decision_making: bool = False
    profiling: bool = False
    automated_processing_description: str = ""
    
    # Risk assessment
    risk_assessment_conducted: bool = False
    risk_assessment_date: Optional[datetime] = None
    risk_level: str = "low"  # low, medium, high
    
    # DPIA
    dpia_required: bool = False
    dpia_conducted: bool = False
    dpia_date: Optional[datetime] = None
    dpia_reference: str = ""
    
    # Compliance tracking
    created_date: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    created_by: str = ""
    last_updated_by: str = ""
    version: int = 1
    
    # Review and monitoring
    next_review_date: Optional[datetime] = None
    review_frequency: str = "annually"
    compliance_status: str = "compliant"
    
    # Additional metadata
    business_area: str = ""
    system_applications: List[str] = field(default_factory=list)
    data_flows: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.next_review_date:
            self.next_review_date = self.created_date + timedelta(days=365)  # Annual review
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "processing_role": self.processing_role.value,
            "status": self.status,
            "controller_name": self.controller_name,
            "controller_contact": self.controller_contact,
            "processor_name": self.processor_name,
            "processor_contact": self.processor_contact,
            "joint_controllers": self.joint_controllers,
            "dpo_name": self.dpo_name,
            "dpo_contact": self.dpo_contact,
            "purposes": self.purposes,
            "legal_basis": [basis.value for basis in self.legal_basis],
            "legal_basis_details": self.legal_basis_details,
            "special_categories": [cat.value for cat in self.special_categories],
            "special_category_basis": [basis.value for basis in self.special_category_basis],
            "special_category_details": self.special_category_details,
            "criminal_data_processed": self.criminal_data_processed,
            "criminal_data_authority": self.criminal_data_authority,
            "data_subject_categories": [cat.value for cat in self.data_subject_categories],
            "data_categories": [cat.value for cat in self.data_categories],
            "data_sources": self.data_sources,
            "estimated_data_subjects": self.estimated_data_subjects,
            "data_volume_description": self.data_volume_description,
            "transfers": [transfer.to_dict() for transfer in self.transfers],
            "retention_schedules": [schedule.to_dict() for schedule in self.retention_schedules],
            "general_retention_period": self.general_retention_period,
            "security_measures": [measure.to_dict() for measure in self.security_measures],
            "automated_processing": self.automated_processing,
            "automated_decision_making": self.automated_decision_making,
            "profiling": self.profiling,
            "automated_processing_description": self.automated_processing_description,
            "risk_assessment_conducted": self.risk_assessment_conducted,
            "risk_assessment_date": self.risk_assessment_date.isoformat() if self.risk_assessment_date else None,
            "risk_level": self.risk_level,
            "dpia_required": self.dpia_required,
            "dpia_conducted": self.dpia_conducted,
            "dpia_date": self.dpia_date.isoformat() if self.dpia_date else None,
            "dpia_reference": self.dpia_reference,
            "created_date": self.created_date.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "created_by": self.created_by,
            "last_updated_by": self.last_updated_by,
            "version": self.version,
            "next_review_date": self.next_review_date.isoformat() if self.next_review_date else None,
            "review_frequency": self.review_frequency,
            "compliance_status": self.compliance_status,
            "business_area": self.business_area,
            "system_applications": self.system_applications,
            "data_flows": self.data_flows
        }


@dataclass
class ProcessingRecord:
    """Collection of processing activities for an organization"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_name: str = ""
    organization_contact: str = ""
    organization_address: str = ""
    
    # DPO information
    dpo_name: str = ""
    dpo_contact: str = ""
    dpo_address: str = ""
    
    # Representative information (for non-EU organizations)
    representative_name: Optional[str] = None
    representative_contact: Optional[str] = None
    representative_address: Optional[str] = None
    
    # Processing activities
    activities: Dict[str, ProcessingActivity] = field(default_factory=dict)
    
    # Record metadata
    created_date: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    version: str = "1.0"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "organization_name": self.organization_name,
            "organization_contact": self.organization_contact,
            "organization_address": self.organization_address,
            "dpo_name": self.dpo_name,
            "dpo_contact": self.dpo_contact,
            "dpo_address": self.dpo_address,
            "representative_name": self.representative_name,
            "representative_contact": self.representative_contact,
            "representative_address": self.representative_address,
            "activities": {k: v.to_dict() for k, v in self.activities.items()},
            "created_date": self.created_date.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "version": self.version,
            "total_activities": len(self.activities)
        }


class ProcessingRecordsManager:
    """Manager for GDPR Article 30 Records of Processing Activities"""
    
    def __init__(self,
                 db_manager: DatabaseManager,
                 encryption_manager: EncryptionManager):
        self.db_manager = db_manager
        self.encryption_manager = encryption_manager
        self.logger = logging.getLogger(__name__)
        
        # Storage
        self.processing_records: Dict[str, ProcessingRecord] = {}
        self.processing_activities: Dict[str, ProcessingActivity] = {}
        
        # Templates and standards
        self.activity_templates: Dict[str, Dict[str, Any]] = {}
        
        # Initialize templates and default records
        self._initialize_activity_templates()
        self._create_default_processing_record()
    
    def _initialize_activity_templates(self):
        """Initialize processing activity templates"""
        
        # PII De-identification Processing Template
        self.activity_templates["pii_deidentification"] = {
            "name": "PII De-identification Processing",
            "description": "Processing personal data for de-identification purposes",
            "purposes": ["De-identification", "Privacy protection", "Data utility preservation"],
            "legal_basis": [LegalBasis.CONSENT, LegalBasis.LEGITIMATE_INTERESTS],
            "data_categories": [
                DataCategory.IDENTIFICATION_DATA,
                DataCategory.CONTACT_INFORMATION,
                DataCategory.HEALTH_DATA,
                DataCategory.FINANCIAL_DATA
            ],
            "data_subject_categories": [
                DataSubjectCategory.CUSTOMERS,
                DataSubjectCategory.PATIENTS
            ],
            "security_measures": [
                {
                    "measure_type": "technical",
                    "category": "encryption",
                    "description": "AES-256 encryption for data at rest and in transit"
                },
                {
                    "measure_type": "technical",
                    "category": "pseudonymization",
                    "description": "Automatic pseudonymization of direct identifiers"
                },
                {
                    "measure_type": "organizational",
                    "category": "access_control",
                    "description": "Role-based access control with need-to-know principle"
                }
            ]
        }
        
        # Analytics Processing Template
        self.activity_templates["analytics_processing"] = {
            "name": "Data Analytics Processing",
            "description": "Processing personal data for analytics and reporting purposes",
            "purposes": ["Analytics", "Reporting", "Business intelligence"],
            "legal_basis": [LegalBasis.LEGITIMATE_INTERESTS],
            "data_categories": [
                DataCategory.USAGE_DATA,
                DataCategory.BEHAVIORAL_DATA,
                DataCategory.TECHNICAL_DATA
            ],
            "data_subject_categories": [
                DataSubjectCategory.CUSTOMERS,
                DataSubjectCategory.VISITORS
            ]
        }
        
        # Document Processing Template
        self.activity_templates["document_processing"] = {
            "name": "Document Processing",
            "description": "Processing personal data contained in documents",
            "purposes": ["Document analysis", "Information extraction", "Content processing"],
            "legal_basis": [LegalBasis.CONSENT, LegalBasis.CONTRACT],
            "data_categories": [
                DataCategory.IDENTIFICATION_DATA,
                DataCategory.CONTACT_INFORMATION,
                DataCategory.COMMUNICATION_DATA
            ],
            "data_subject_categories": [
                DataSubjectCategory.CUSTOMERS,
                DataSubjectCategory.EMPLOYEES
            ]
        }
    
    def _create_default_processing_record(self):
        """Create default processing record for the organization"""
        
        default_record = ProcessingRecord(
            organization_name="De-identification System Company",
            organization_contact="privacy@deidentification-system.com",
            organization_address="123 Privacy Street, Data City, DC 12345",
            dpo_name="Data Protection Officer",
            dpo_contact="dpo@deidentification-system.com",
            dpo_address="123 Privacy Street, Data City, DC 12345"
        )
        
        # Create default processing activities
        for template_name, template_data in self.activity_templates.items():
            activity = self._create_activity_from_template(template_name, template_data, "system_admin")
            default_record.activities[activity.id] = activity
            self.processing_activities[activity.id] = activity
        
        self.processing_records[default_record.id] = default_record
        
        self.logger.info(f"Created default processing record with {len(default_record.activities)} activities")
    
    def _create_activity_from_template(self, template_name: str, template_data: Dict[str, Any], created_by: str) -> ProcessingActivity:
        """Create processing activity from template"""
        
        activity = ProcessingActivity(
            name=template_data["name"],
            description=template_data["description"],
            processing_role=ProcessingRole.CONTROLLER,
            controller_name="De-identification System Company",
            controller_contact="privacy@deidentification-system.com",
            dpo_name="Data Protection Officer",
            dpo_contact="dpo@deidentification-system.com",
            purposes=template_data["purposes"],
            legal_basis=template_data["legal_basis"],
            data_categories=template_data["data_categories"],
            data_subject_categories=template_data["data_subject_categories"],
            created_by=created_by,
            business_area="Privacy Technology"
        )
        
        # Add security measures if provided in template
        if "security_measures" in template_data:
            for measure_data in template_data["security_measures"]:
                security_measure = SecurityMeasure(**measure_data)
                security_measure.responsible_party = "Security Team"
                security_measure.last_review_date = datetime.now()
                security_measure.next_review_date = datetime.now() + timedelta(days=365)
                activity.security_measures.append(security_measure)
        
        # Add default retention schedules
        for data_category in activity.data_categories:
            retention_period = self._get_default_retention_period(data_category)
            retention_schedule = RetentionSchedule(
                data_category=data_category,
                retention_period=retention_period,
                retention_basis=RetentionBasis.BUSINESS_NECESSITY,
                retention_criteria=f"Retain for {retention_period} days for business purposes",
                responsible_party="Data Management Team"
            )
            activity.retention_schedules.append(retention_schedule)
        
        return activity
    
    def _get_default_retention_period(self, data_category: DataCategory) -> int:
        """Get default retention period for data category"""
        
        default_periods = {
            DataCategory.IDENTIFICATION_DATA: 2555,  # 7 years
            DataCategory.CONTACT_INFORMATION: 1095,  # 3 years
            DataCategory.FINANCIAL_DATA: 2555,  # 7 years
            DataCategory.HEALTH_DATA: 3650,  # 10 years
            DataCategory.EMPLOYMENT_DATA: 2555,  # 7 years
            DataCategory.USAGE_DATA: 365,  # 1 year
            DataCategory.BEHAVIORAL_DATA: 730,  # 2 years
            DataCategory.TECHNICAL_DATA: 365,  # 1 year
        }
        
        return default_periods.get(data_category, 1095)  # Default 3 years
    
    async def create_processing_activity(self, activity_data: Dict[str, Any], created_by: str = "admin") -> ProcessingActivity:
        """Create new processing activity"""
        
        # Use template if specified
        template_name = activity_data.get("template")
        if template_name and template_name in self.activity_templates:
            template = self.activity_templates[template_name]
            activity = self._create_activity_from_template(template_name, template, created_by)
            
            # Override with provided data
            for key, value in activity_data.items():
                if key != "template" and hasattr(activity, key):
                    setattr(activity, key, value)
        else:
            # Create from scratch
            activity = ProcessingActivity(
                name=activity_data.get("name", "New Processing Activity"),
                description=activity_data.get("description", ""),
                created_by=created_by,
                **{k: v for k, v in activity_data.items() if hasattr(ProcessingActivity, k)}
            )
        
        # Store activity
        self.processing_activities[activity.id] = activity
        
        # Add to default processing record
        if self.processing_records:
            default_record = list(self.processing_records.values())[0]
            default_record.activities[activity.id] = activity
            default_record.last_updated = datetime.now()
        
        # Assess if DPIA is required
        activity.dpia_required = await self._assess_dpia_requirement(activity)
        
        await self._log_processing_event(activity, "processing_activity_created")
        
        self.logger.info(f"Created processing activity: {activity.name} (ID: {activity.id})")
        
        return activity
    
    async def update_processing_activity(self, 
                                       activity_id: str, 
                                       updates: Dict[str, Any], 
                                       updated_by: str = "admin") -> Optional[ProcessingActivity]:
        """Update existing processing activity"""
        
        activity = self.processing_activities.get(activity_id)
        if not activity:
            return None
        
        # Track changes for audit
        changes = {}
        
        for key, value in updates.items():
            if hasattr(activity, key):
                old_value = getattr(activity, key)
                if old_value != value:
                    changes[key] = {"old": old_value, "new": value}
                    setattr(activity, key, value)
        
        # Update metadata
        activity.last_updated = datetime.now()
        activity.last_updated_by = updated_by
        activity.version += 1
        
        # Re-assess DPIA requirement if relevant fields changed
        dpia_relevant_fields = ["data_categories", "special_categories", "automated_processing", "profiling"]
        if any(field in changes for field in dpia_relevant_fields):
            activity.dpia_required = await self._assess_dpia_requirement(activity)
        
        await self._log_processing_event(activity, "processing_activity_updated", {
            "changes": changes,
            "updated_by": updated_by
        })
        
        self.logger.info(f"Updated processing activity: {activity.name} (Version: {activity.version})")
        
        return activity
    
    async def _assess_dpia_requirement(self, activity: ProcessingActivity) -> bool:
        """Assess if Data Protection Impact Assessment is required"""
        
        # DPIA required for high risk processing (Article 35)
        
        # Special categories of data
        if activity.special_categories:
            return True
        
        # Large scale processing
        if activity.estimated_data_subjects > 10000:
            return True
        
        # Automated decision-making with legal effects
        if activity.automated_decision_making:
            return True
        
        # Systematic monitoring
        if "monitoring" in " ".join(activity.purposes).lower():
            return True
        
        # Vulnerable data subjects
        vulnerable_categories = [DataSubjectCategory.CHILDREN, DataSubjectCategory.VULNERABLE_ADULTS, DataSubjectCategory.PATIENTS]
        if any(cat in vulnerable_categories for cat in activity.data_subject_categories):
            return True
        
        # Innovative technology usage
        if "ai" in activity.description.lower() or "machine_learning" in activity.description.lower():
            return True
        
        # Profiling
        if activity.profiling:
            return True
        
        # Cross-border data transfers to non-adequate countries
        non_adequate_transfers = [
            transfer for transfer in activity.transfers
            if transfer.transfer_mechanism not in ["adequacy_decision"]
        ]
        if non_adequate_transfers:
            return True
        
        return False
    
    async def add_data_transfer(self, activity_id: str, transfer_data: Dict[str, Any]) -> Optional[DataTransfer]:
        """Add data transfer to processing activity"""
        
        activity = self.processing_activities.get(activity_id)
        if not activity:
            return None
        
        transfer = DataTransfer(**transfer_data)
        activity.transfers.append(transfer)
        activity.last_updated = datetime.now()
        activity.version += 1
        
        # Re-assess DPIA requirement due to new transfer
        activity.dpia_required = await self._assess_dpia_requirement(activity)
        
        await self._log_processing_event(activity, "data_transfer_added", {
            "transfer_id": transfer.id,
            "recipient": transfer.recipient_name,
            "country": transfer.recipient_country
        })
        
        self.logger.info(f"Added data transfer to {activity.name}: {transfer.recipient_name}")
        
        return transfer
    
    async def add_security_measure(self, activity_id: str, measure_data: Dict[str, Any]) -> Optional[SecurityMeasure]:
        """Add security measure to processing activity"""
        
        activity = self.processing_activities.get(activity_id)
        if not activity:
            return None
        
        measure = SecurityMeasure(**measure_data)
        measure.last_review_date = datetime.now()
        
        # Set next review date based on frequency
        frequency_days = {
            "monthly": 30,
            "quarterly": 90,
            "semi-annually": 180,
            "annually": 365
        }
        days = frequency_days.get(measure.review_frequency, 365)
        measure.next_review_date = datetime.now() + timedelta(days=days)
        
        activity.security_measures.append(measure)
        activity.last_updated = datetime.now()
        activity.version += 1
        
        await self._log_processing_event(activity, "security_measure_added", {
            "measure_id": measure.id,
            "measure_type": measure.measure_type,
            "category": measure.category
        })
        
        self.logger.info(f"Added security measure to {activity.name}: {measure.category}")
        
        return measure
    
    async def add_retention_schedule(self, activity_id: str, schedule_data: Dict[str, Any]) -> Optional[RetentionSchedule]:
        """Add retention schedule to processing activity"""
        
        activity = self.processing_activities.get(activity_id)
        if not activity:
            return None
        
        schedule = RetentionSchedule(**schedule_data)
        activity.retention_schedules.append(schedule)
        activity.last_updated = datetime.now()
        activity.version += 1
        
        await self._log_processing_event(activity, "retention_schedule_added", {
            "schedule_id": schedule.id,
            "data_category": schedule.data_category.value,
            "retention_period": schedule.retention_period
        })
        
        self.logger.info(f"Added retention schedule to {activity.name}: {schedule.data_category.value} for {schedule.retention_period} days")
        
        return schedule
    
    async def conduct_processing_audit(self) -> Dict[str, Any]:
        """Conduct comprehensive audit of processing activities"""
        
        audit_results = {
            "audit_date": datetime.now().isoformat(),
            "total_activities": len(self.processing_activities),
            "compliance_summary": {
                "compliant": 0,
                "non_compliant": 0,
                "requires_attention": 0
            },
            "dpia_summary": {
                "required": 0,
                "conducted": 0,
                "overdue": 0
            },
            "retention_compliance": {
                "schedules_defined": 0,
                "schedules_missing": 0
            },
            "security_measures": {
                "total_measures": 0,
                "review_overdue": 0
            },
            "detailed_findings": [],
            "recommendations": []
        }
        
        for activity in self.processing_activities.values():
            # Compliance assessment
            compliance_issues = await self._assess_activity_compliance(activity)
            
            if not compliance_issues:
                audit_results["compliance_summary"]["compliant"] += 1
            elif len(compliance_issues) > 3:
                audit_results["compliance_summary"]["non_compliant"] += 1
            else:
                audit_results["compliance_summary"]["requires_attention"] += 1
            
            # DPIA assessment
            if activity.dpia_required:
                audit_results["dpia_summary"]["required"] += 1
                
                if activity.dpia_conducted:
                    audit_results["dpia_summary"]["conducted"] += 1
                    
                    # Check if DPIA is overdue for review (2 years)
                    if activity.dpia_date:
                        days_since_dpia = (datetime.now() - activity.dpia_date).days
                        if days_since_dpia > 730:  # 2 years
                            audit_results["dpia_summary"]["overdue"] += 1
                            compliance_issues.append("DPIA review overdue")
            
            # Retention compliance
            if activity.retention_schedules:
                audit_results["retention_compliance"]["schedules_defined"] += 1
            else:
                audit_results["retention_compliance"]["schedules_missing"] += 1
                compliance_issues.append("Retention schedules missing")
            
            # Security measures
            audit_results["security_measures"]["total_measures"] += len(activity.security_measures)
            
            for measure in activity.security_measures:
                if measure.next_review_date and datetime.now() > measure.next_review_date:
                    audit_results["security_measures"]["review_overdue"] += 1
                    compliance_issues.append(f"Security measure review overdue: {measure.category}")
            
            # Record detailed findings
            if compliance_issues:
                audit_results["detailed_findings"].append({
                    "activity_id": activity.id,
                    "activity_name": activity.name,
                    "issues": compliance_issues,
                    "risk_level": activity.risk_level,
                    "last_updated": activity.last_updated.isoformat()
                })
        
        # Generate recommendations
        audit_results["recommendations"] = await self._generate_audit_recommendations(audit_results)
        
        return audit_results
    
    async def _assess_activity_compliance(self, activity: ProcessingActivity) -> List[str]:
        """Assess compliance of a single processing activity"""
        
        issues = []
        
        # Basic information completeness
        if not activity.purposes:
            issues.append("Processing purposes not defined")
        
        if not activity.legal_basis:
            issues.append("Legal basis not specified")
        
        if not activity.data_categories:
            issues.append("Data categories not specified")
        
        if not activity.data_subject_categories:
            issues.append("Data subject categories not specified")
        
        # Special categories compliance
        if activity.special_categories and not activity.special_category_basis:
            issues.append("Special category legal basis not specified")
        
        # DPO information
        if not activity.dpo_name or not activity.dpo_contact:
            issues.append("DPO information missing or incomplete")
        
        # DPIA compliance
        if activity.dpia_required and not activity.dpia_conducted:
            issues.append("Required DPIA not conducted")
        
        # Security measures
        if not activity.security_measures:
            issues.append("No security measures documented")
        else:
            # Check for basic security measures
            measure_categories = [m.category for m in activity.security_measures]
            required_categories = ["encryption", "access_control", "backup"]
            
            for required_cat in required_categories:
                if not any(cat in required_cat for cat in measure_categories):
                    issues.append(f"Missing required security measure: {required_cat}")
        
        # Retention schedules
        if not activity.retention_schedules and not activity.general_retention_period:
            issues.append("Retention period not specified")
        
        # Data transfer compliance
        for transfer in activity.transfers:
            if transfer.recipient_country and not transfer.transfer_mechanism:
                issues.append(f"Transfer mechanism not specified for {transfer.recipient_name}")
            
            # Check for adequate transfer mechanisms
            if transfer.recipient_country and transfer.recipient_country not in ["AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK"]:  # EU countries
                if transfer.transfer_mechanism not in ["adequacy_decision", "sccs", "bcrs"]:
                    issues.append(f"Inadequate transfer mechanism for non-EU transfer to {transfer.recipient_country}")
        
        # Review schedule compliance
        if activity.next_review_date and datetime.now() > activity.next_review_date:
            issues.append("Activity review overdue")
        
        return issues
    
    async def _generate_audit_recommendations(self, audit_results: Dict[str, Any]) -> List[str]:
        """Generate audit recommendations based on findings"""
        
        recommendations = []
        
        # Compliance recommendations
        non_compliant = audit_results["compliance_summary"]["non_compliant"]
        requires_attention = audit_results["compliance_summary"]["requires_attention"]
        
        if non_compliant > 0:
            recommendations.append(f"Address {non_compliant} non-compliant processing activities immediately")
            recommendations.append("Conduct detailed review of legal basis and documentation")
            recommendations.append("Consider engaging legal counsel for compliance assessment")
        
        if requires_attention > 0:
            recommendations.append(f"Review and improve {requires_attention} processing activities")
        
        # DPIA recommendations
        dpia_required = audit_results["dpia_summary"]["required"]
        dpia_conducted = audit_results["dpia_summary"]["conducted"]
        dpia_overdue = audit_results["dpia_summary"]["overdue"]
        
        if dpia_required > dpia_conducted:
            recommendations.append(f"Conduct {dpia_required - dpia_conducted} outstanding DPIAs")
        
        if dpia_overdue > 0:
            recommendations.append(f"Review {dpia_overdue} overdue DPIAs")
        
        # Retention recommendations
        missing_schedules = audit_results["retention_compliance"]["schedules_missing"]
        if missing_schedules > 0:
            recommendations.append(f"Define retention schedules for {missing_schedules} activities")
        
        # Security recommendations
        overdue_reviews = audit_results["security_measures"]["review_overdue"]
        if overdue_reviews > 0:
            recommendations.append(f"Complete {overdue_reviews} overdue security measure reviews")
        
        # General recommendations
        recommendations.extend([
            "Establish regular review schedule for all processing activities",
            "Implement automated compliance monitoring",
            "Provide GDPR training for all staff involved in data processing",
            "Consider appointment of additional DPO support if needed"
        ])
        
        return recommendations
    
    async def generate_processing_report(self, 
                                       format: str = "json", 
                                       include_details: bool = True) -> Dict[str, Any]:
        """Generate comprehensive processing activities report"""
        
        report = {
            "report_date": datetime.now().isoformat(),
            "organization_info": {},
            "executive_summary": {},
            "processing_activities": [],
            "compliance_status": {},
            "statistics": {}
        }
        
        # Organization information
        if self.processing_records:
            default_record = list(self.processing_records.values())[0]
            report["organization_info"] = {
                "name": default_record.organization_name,
                "contact": default_record.organization_contact,
                "dpo_name": default_record.dpo_name,
                "dpo_contact": default_record.dpo_contact,
                "total_activities": len(default_record.activities)
            }
        
        # Executive summary
        total_activities = len(self.processing_activities)
        active_activities = len([a for a in self.processing_activities.values() if a.status == "active"])
        dpia_required = len([a for a in self.processing_activities.values() if a.dpia_required])
        high_risk_activities = len([a for a in self.processing_activities.values() if a.risk_level == "high"])
        
        report["executive_summary"] = {
            "total_processing_activities": total_activities,
            "active_activities": active_activities,
            "dpia_required_activities": dpia_required,
            "high_risk_activities": high_risk_activities,
            "compliance_overview": "See detailed compliance status section"
        }
        
        # Processing activities
        for activity in self.processing_activities.values():
            activity_report = {
                "id": activity.id,
                "name": activity.name,
                "status": activity.status,
                "processing_role": activity.processing_role.value,
                "purposes": activity.purposes,
                "legal_basis": [basis.value for basis in activity.legal_basis],
                "data_categories": [cat.value for cat in activity.data_categories],
                "data_subject_categories": [cat.value for cat in activity.data_subject_categories],
                "estimated_data_subjects": activity.estimated_data_subjects,
                "risk_level": activity.risk_level,
                "dpia_required": activity.dpia_required,
                "dpia_conducted": activity.dpia_conducted,
                "last_updated": activity.last_updated.isoformat(),
                "version": activity.version
            }
            
            if include_details:
                activity_report.update({
                    "description": activity.description,
                    "special_categories": [cat.value for cat in activity.special_categories],
                    "transfers": [t.to_dict() for t in activity.transfers],
                    "security_measures": [m.to_dict() for m in activity.security_measures],
                    "retention_schedules": [r.to_dict() for r in activity.retention_schedules],
                    "automated_processing": activity.automated_processing,
                    "profiling": activity.profiling,
                    "data_sources": activity.data_sources,
                    "system_applications": activity.system_applications
                })
            
            report["processing_activities"].append(activity_report)
        
        # Compliance status
        audit_results = await self.conduct_processing_audit()
        report["compliance_status"] = audit_results
        
        # Statistics
        report["statistics"] = await self._generate_processing_statistics()
        
        return report
    
    async def _generate_processing_statistics(self) -> Dict[str, Any]:
        """Generate processing activities statistics"""
        
        stats = {
            "by_status": defaultdict(int),
            "by_role": defaultdict(int),
            "by_risk_level": defaultdict(int),
            "by_legal_basis": defaultdict(int),
            "by_business_area": defaultdict(int),
            "data_categories_frequency": defaultdict(int),
            "data_subject_categories_frequency": defaultdict(int),
            "transfer_statistics": {
                "total_transfers": 0,
                "by_country": defaultdict(int),
                "by_mechanism": defaultdict(int)
            },
            "security_measures_statistics": {
                "total_measures": 0,
                "by_type": defaultdict(int),
                "by_category": defaultdict(int)
            },
            "temporal_statistics": {
                "activities_created_last_30_days": 0,
                "activities_updated_last_30_days": 0,
                "average_age_days": 0
            }
        }
        
        thirty_days_ago = datetime.now() - timedelta(days=30)
        total_age_days = 0
        
        for activity in self.processing_activities.values():
            # Basic statistics
            stats["by_status"][activity.status] += 1
            stats["by_role"][activity.processing_role.value] += 1
            stats["by_risk_level"][activity.risk_level] += 1
            stats["by_business_area"][activity.business_area] += 1
            
            # Legal basis statistics
            for basis in activity.legal_basis:
                stats["by_legal_basis"][basis.value] += 1
            
            # Data categories
            for category in activity.data_categories:
                stats["data_categories_frequency"][category.value] += 1
            
            # Data subject categories
            for category in activity.data_subject_categories:
                stats["data_subject_categories_frequency"][category.value] += 1
            
            # Transfer statistics
            stats["transfer_statistics"]["total_transfers"] += len(activity.transfers)
            for transfer in activity.transfers:
                stats["transfer_statistics"]["by_country"][transfer.recipient_country] += 1
                stats["transfer_statistics"]["by_mechanism"][transfer.transfer_mechanism] += 1
            
            # Security measures statistics
            stats["security_measures_statistics"]["total_measures"] += len(activity.security_measures)
            for measure in activity.security_measures:
                stats["security_measures_statistics"]["by_type"][measure.measure_type] += 1
                stats["security_measures_statistics"]["by_category"][measure.category] += 1
            
            # Temporal statistics
            if activity.created_date > thirty_days_ago:
                stats["temporal_statistics"]["activities_created_last_30_days"] += 1
            
            if activity.last_updated > thirty_days_ago:
                stats["temporal_statistics"]["activities_updated_last_30_days"] += 1
            
            age_days = (datetime.now() - activity.created_date).days
            total_age_days += age_days
        
        # Calculate averages
        if self.processing_activities:
            stats["temporal_statistics"]["average_age_days"] = total_age_days / len(self.processing_activities)
        
        # Convert defaultdicts to regular dicts
        for key in ["by_status", "by_role", "by_risk_level", "by_legal_basis", "by_business_area", 
                   "data_categories_frequency", "data_subject_categories_frequency"]:
            stats[key] = dict(stats[key])
        
        for key in ["by_country", "by_mechanism"]:
            stats["transfer_statistics"][key] = dict(stats["transfer_statistics"][key])
        
        for key in ["by_type", "by_category"]:
            stats["security_measures_statistics"][key] = dict(stats["security_measures_statistics"][key])
        
        return stats
    
    async def schedule_activity_reviews(self) -> Dict[str, Any]:
        """Schedule and track processing activity reviews"""
        
        review_schedule = {
            "review_date": datetime.now().isoformat(),
            "overdue_reviews": [],
            "upcoming_reviews": [],
            "recently_reviewed": [],
            "schedule_summary": {
                "total_activities": len(self.processing_activities),
                "overdue": 0,
                "due_within_30_days": 0,
                "due_within_90_days": 0
            }
        }
        
        now = datetime.now()
        thirty_days = now + timedelta(days=30)
        ninety_days = now + timedelta(days=90)
        
        for activity in self.processing_activities.values():
            if not activity.next_review_date:
                # Set review date if not set
                activity.next_review_date = activity.created_date + timedelta(days=365)
            
            if activity.next_review_date < now:
                # Overdue
                review_schedule["overdue_reviews"].append({
                    "activity_id": activity.id,
                    "activity_name": activity.name,
                    "due_date": activity.next_review_date.isoformat(),
                    "days_overdue": (now - activity.next_review_date).days,
                    "risk_level": activity.risk_level
                })
                review_schedule["schedule_summary"]["overdue"] += 1
            
            elif activity.next_review_date <= thirty_days:
                # Due within 30 days
                review_schedule["upcoming_reviews"].append({
                    "activity_id": activity.id,
                    "activity_name": activity.name,
                    "due_date": activity.next_review_date.isoformat(),
                    "days_until_due": (activity.next_review_date - now).days,
                    "priority": "high"
                })
                review_schedule["schedule_summary"]["due_within_30_days"] += 1
            
            elif activity.next_review_date <= ninety_days:
                # Due within 90 days
                review_schedule["upcoming_reviews"].append({
                    "activity_id": activity.id,
                    "activity_name": activity.name,
                    "due_date": activity.next_review_date.isoformat(),
                    "days_until_due": (activity.next_review_date - now).days,
                    "priority": "medium"
                })
                review_schedule["schedule_summary"]["due_within_90_days"] += 1
            
            # Check for recently reviewed activities
            if activity.last_updated > (now - timedelta(days=30)):
                review_schedule["recently_reviewed"].append({
                    "activity_id": activity.id,
                    "activity_name": activity.name,
                    "last_reviewed": activity.last_updated.isoformat(),
                    "reviewed_by": activity.last_updated_by
                })
        
        # Sort lists by priority/date
        review_schedule["overdue_reviews"].sort(key=lambda x: x["days_overdue"], reverse=True)
        review_schedule["upcoming_reviews"].sort(key=lambda x: x["days_until_due"])
        
        return review_schedule
    
    async def _log_processing_event(self, activity: ProcessingActivity, event_type: str, metadata: Dict[str, Any] = None):
        """Log processing activity events for audit trail"""
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "activity_id": activity.id,
            "activity_name": activity.name,
            "event_type": event_type,
            "metadata": metadata or {}
        }
        
        self.logger.info(f"Processing Event: {event_type} for activity {activity.id}")
        
        # In production, this would write to audit database
    
    # Management and query methods
    def get_processing_activity(self, activity_id: str) -> Optional[ProcessingActivity]:
        """Get processing activity by ID"""
        return self.processing_activities.get(activity_id)
    
    def list_processing_activities(self, 
                                 status: Optional[str] = None,
                                 business_area: Optional[str] = None,
                                 risk_level: Optional[str] = None) -> List[ProcessingActivity]:
        """List processing activities with optional filters"""
        
        activities = list(self.processing_activities.values())
        
        if status:
            activities = [a for a in activities if a.status == status]
        
        if business_area:
            activities = [a for a in activities if a.business_area == business_area]
        
        if risk_level:
            activities = [a for a in activities if a.risk_level == risk_level]
        
        return activities
    
    def get_activities_by_legal_basis(self, legal_basis: LegalBasis) -> List[ProcessingActivity]:
        """Get activities using specific legal basis"""
        return [a for a in self.processing_activities.values() if legal_basis in a.legal_basis]
    
    def get_activities_with_special_categories(self) -> List[ProcessingActivity]:
        """Get activities processing special categories of data"""
        return [a for a in self.processing_activities.values() if a.special_categories]
    
    def get_activities_requiring_dpia(self) -> List[ProcessingActivity]:
        """Get activities requiring DPIA"""
        return [a for a in self.processing_activities.values() if a.dpia_required]
    
    def get_processing_record(self, record_id: str) -> Optional[ProcessingRecord]:
        """Get processing record by ID"""
        return self.processing_records.get(record_id)
    
    def list_processing_records(self) -> List[ProcessingRecord]:
        """List all processing records"""
        return list(self.processing_records.values())
    
    async def export_processing_activities(self, format: str = "json") -> Dict[str, Any]:
        """Export all processing activities in specified format"""
        
        export_data = {
            "export_date": datetime.now().isoformat(),
            "export_format": format,
            "organization": {},
            "processing_activities": []
        }
        
        # Organization information
        if self.processing_records:
            default_record = list(self.processing_records.values())[0]
            export_data["organization"] = {
                "name": default_record.organization_name,
                "contact": default_record.organization_contact,
                "dpo_name": default_record.dpo_name,
                "dpo_contact": default_record.dpo_contact
            }
        
        # Processing activities
        for activity in self.processing_activities.values():
            export_data["processing_activities"].append(activity.to_dict())
        
        return export_data
    
    async def delete_processing_activity(self, activity_id: str) -> bool:
        """Delete processing activity"""
        
        activity = self.processing_activities.get(activity_id)
        if not activity:
            return False
        
        # Remove from storage
        del self.processing_activities[activity_id]
        
        # Remove from processing records
        for record in self.processing_records.values():
            if activity_id in record.activities:
                del record.activities[activity_id]
                record.last_updated = datetime.now()
        
        await self._log_processing_event(activity, "processing_activity_deleted")
        
        self.logger.info(f"Deleted processing activity: {activity.name}")
        
        return True