"""
GDPR Consent Management Platform (Articles 6-7)
Comprehensive consent collection, management, and compliance system
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

from ..database.db_manager import DatabaseManager
from ..security.encryption_manager import EncryptionManager
from ..config.settings import get_settings


logger = logging.getLogger(__name__)
settings = get_settings()


class ConsentStatus(Enum):
    """Consent status options"""
    GIVEN = "given"
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"
    INVALID = "invalid"
    PENDING = "pending"


class ConsentType(Enum):
    """Types of consent"""
    EXPLICIT = "explicit"  # Article 7 - clear affirmative action
    IMPLIED = "implied"    # Not recommended for GDPR
    OPT_IN = "opt_in"     # Active consent
    OPT_OUT = "opt_out"   # Not compliant with GDPR for most purposes


class ProcessingPurpose(Enum):
    """Processing purposes for consent"""
    MARKETING = "marketing"
    PROFILING = "profiling"
    ANALYTICS = "analytics"
    PERSONALIZATION = "personalization"
    COMMUNICATIONS = "communications"
    SERVICE_IMPROVEMENT = "service_improvement"
    RESEARCH = "research"
    THIRD_PARTY_SHARING = "third_party_sharing"
    AUTOMATED_DECISION_MAKING = "automated_decision_making"


class ConsentMethod(Enum):
    """Method of consent collection"""
    WEB_FORM = "web_form"
    CHECKBOX = "checkbox"
    BUTTON_CLICK = "button_click"
    ORAL = "oral"
    WRITTEN = "written"
    DIGITAL_SIGNATURE = "digital_signature"
    API = "api"


class LegalBasis(Enum):
    """GDPR Article 6 legal bases"""
    CONSENT = "consent"  # Article 6(1)(a)
    CONTRACT = "contract"  # Article 6(1)(b)
    LEGAL_OBLIGATION = "legal_obligation"  # Article 6(1)(c)
    VITAL_INTERESTS = "vital_interests"  # Article 6(1)(d)
    PUBLIC_TASK = "public_task"  # Article 6(1)(e)
    LEGITIMATE_INTERESTS = "legitimate_interests"  # Article 6(1)(f)


@dataclass
class ConsentPurpose:
    """Individual consent purpose with granular control"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    purpose: ProcessingPurpose = ProcessingPurpose.MARKETING
    description: str = ""
    data_categories: List[str] = field(default_factory=list)
    retention_period: int = 365  # days
    third_parties: List[str] = field(default_factory=list)
    automated_decision_making: bool = False
    profiling: bool = False
    required: bool = False  # Whether consent is required for service
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "purpose": self.purpose.value,
            "description": self.description,
            "data_categories": self.data_categories,
            "retention_period": self.retention_period,
            "third_parties": self.third_parties,
            "automated_decision_making": self.automated_decision_making,
            "profiling": self.profiling,
            "required": self.required
        }


@dataclass
class ConsentRecord:
    """Individual consent record"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    data_subject_id: str = ""
    purposes: Dict[str, ConsentStatus] = field(default_factory=dict)  # purpose_id -> status
    consent_timestamp: datetime = field(default_factory=datetime.now)
    expiry_date: Optional[datetime] = None
    withdrawal_timestamp: Optional[datetime] = None
    consent_method: ConsentMethod = ConsentMethod.WEB_FORM
    consent_version: str = "1.0"
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    consent_text: str = ""
    consent_evidence: Dict[str, Any] = field(default_factory=dict)
    
    # Consent proof-of-concept
    consent_hash: Optional[str] = None
    digital_signature: Optional[str] = None
    
    # Granular purpose consents
    purpose_consents: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Withdrawal information
    withdrawal_method: Optional[ConsentMethod] = None
    withdrawal_reason: Optional[str] = None
    withdrawal_evidence: Dict[str, Any] = field(default_factory=dict)
    
    # Renewal information
    renewal_required: bool = False
    renewal_date: Optional[datetime] = None
    renewal_sent: bool = False
    
    def __post_init__(self):
        if not self.consent_hash:
            self.consent_hash = self._generate_consent_hash()
    
    def _generate_consent_hash(self) -> str:
        """Generate hash for consent integrity"""
        consent_data = f"{self.data_subject_id}{self.consent_timestamp.isoformat()}{self.consent_text}"
        return hashlib.sha256(consent_data.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "data_subject_id": self.data_subject_id,
            "purposes": {k: v.value for k, v in self.purposes.items()},
            "consent_timestamp": self.consent_timestamp.isoformat(),
            "expiry_date": self.expiry_date.isoformat() if self.expiry_date else None,
            "withdrawal_timestamp": self.withdrawal_timestamp.isoformat() if self.withdrawal_timestamp else None,
            "consent_method": self.consent_method.value,
            "consent_version": self.consent_version,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "consent_text": self.consent_text,
            "consent_hash": self.consent_hash,
            "purpose_consents": self.purpose_consents,
            "withdrawal_method": self.withdrawal_method.value if self.withdrawal_method else None,
            "withdrawal_reason": self.withdrawal_reason,
            "renewal_required": self.renewal_required,
            "renewal_date": self.renewal_date.isoformat() if self.renewal_date else None,
            "renewal_sent": self.renewal_sent
        }


@dataclass
class ConsentTemplate:
    """Consent form template"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    version: str = "1.0"
    language: str = "en"
    purposes: List[ConsentPurpose] = field(default_factory=list)
    consent_text_template: str = ""
    privacy_policy_url: str = ""
    data_controller_info: Dict[str, str] = field(default_factory=dict)
    legal_basis: LegalBasis = LegalBasis.CONSENT
    
    # Template configuration
    allow_granular_consent: bool = True
    require_positive_action: bool = True
    show_withdrawal_info: bool = True
    consent_expiry_period: int = 365  # days
    
    # Age and capacity verification
    minimum_age: int = 16
    require_parental_consent: bool = False
    age_verification_required: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "language": self.language,
            "purposes": [p.to_dict() for p in self.purposes],
            "consent_text_template": self.consent_text_template,
            "privacy_policy_url": self.privacy_policy_url,
            "data_controller_info": self.data_controller_info,
            "legal_basis": self.legal_basis.value,
            "allow_granular_consent": self.allow_granular_consent,
            "require_positive_action": self.require_positive_action,
            "show_withdrawal_info": self.show_withdrawal_info,
            "consent_expiry_period": self.consent_expiry_period,
            "minimum_age": self.minimum_age,
            "require_parental_consent": self.require_parental_consent,
            "age_verification_required": self.age_verification_required
        }


@dataclass
class ConsentAnalytics:
    """Consent analytics and reporting data"""
    total_consents: int = 0
    consent_rate: float = 0.0
    withdrawal_rate: float = 0.0
    consent_by_purpose: Dict[str, int] = field(default_factory=dict)
    consent_by_method: Dict[str, int] = field(default_factory=dict)
    consent_trends: Dict[str, List[float]] = field(default_factory=dict)
    renewal_due: int = 0
    expired_consents: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_consents": self.total_consents,
            "consent_rate": self.consent_rate,
            "withdrawal_rate": self.withdrawal_rate,
            "consent_by_purpose": self.consent_by_purpose,
            "consent_by_method": self.consent_by_method,
            "consent_trends": self.consent_trends,
            "renewal_due": self.renewal_due,
            "expired_consents": self.expired_consents
        }


class ConsentManager:
    """Comprehensive GDPR consent management system"""
    
    def __init__(self,
                 db_manager: DatabaseManager,
                 encryption_manager: EncryptionManager):
        self.db_manager = db_manager
        self.encryption_manager = encryption_manager
        self.logger = logging.getLogger(__name__)
        
        # In-memory storage (in production, this would be database-backed)
        self.consent_records: Dict[str, ConsentRecord] = {}
        self.consent_templates: Dict[str, ConsentTemplate] = {}
        self.consent_purposes: Dict[str, ConsentPurpose] = {}
        
        # Initialize default purposes and templates
        self._initialize_default_purposes()
        self._initialize_default_templates()
    
    def _initialize_default_purposes(self):
        """Initialize default consent purposes"""
        
        default_purposes = [
            ConsentPurpose(
                purpose=ProcessingPurpose.MARKETING,
                description="Send you marketing communications and promotional offers",
                data_categories=["email", "name", "preferences"],
                retention_period=1095,  # 3 years
                required=False
            ),
            ConsentPurpose(
                purpose=ProcessingPurpose.ANALYTICS,
                description="Analyze usage patterns to improve our services",
                data_categories=["usage_data", "device_info"],
                retention_period=730,  # 2 years
                required=False
            ),
            ConsentPurpose(
                purpose=ProcessingPurpose.PERSONALIZATION,
                description="Personalize your experience and recommendations",
                data_categories=["preferences", "behavior_data"],
                retention_period=365,  # 1 year
                profiling=True,
                required=False
            ),
            ConsentPurpose(
                purpose=ProcessingPurpose.THIRD_PARTY_SHARING,
                description="Share your data with trusted partners for enhanced services",
                data_categories=["contact_info", "preferences"],
                third_parties=["partner_1", "partner_2"],
                retention_period=365,
                required=False
            ),
            ConsentPurpose(
                purpose=ProcessingPurpose.AUTOMATED_DECISION_MAKING,
                description="Make automated decisions affecting your service experience",
                data_categories=["behavior_data", "preferences"],
                automated_decision_making=True,
                retention_period=730,
                required=False
            )
        ]
        
        for purpose in default_purposes:
            self.consent_purposes[purpose.id] = purpose
    
    def _initialize_default_templates(self):
        """Initialize default consent templates"""
        
        # Standard marketing consent template
        marketing_template = ConsentTemplate(
            name="Standard Marketing Consent",
            version="1.0",
            language="en",
            purposes=list(self.consent_purposes.values()),
            consent_text_template="""
We would like to process your personal data for the following purposes:

{purposes_list}

You can withdraw your consent at any time by contacting us at privacy@company.com or through your account settings.

For more information about how we process your data, please see our Privacy Policy: {privacy_policy_url}
""",
            privacy_policy_url="https://company.com/privacy-policy",
            data_controller_info={
                "name": "De-identification System Company",
                "contact": "privacy@company.com",
                "address": "123 Privacy Street, Data City, DC 12345"
            },
            allow_granular_consent=True,
            consent_expiry_period=730  # 2 years
        )
        
        self.consent_templates[marketing_template.id] = marketing_template
    
    async def create_consent_template(self, template_data: Dict[str, Any]) -> ConsentTemplate:
        """Create new consent template"""
        
        template = ConsentTemplate(**template_data)
        self.consent_templates[template.id] = template
        
        self.logger.info(f"Created consent template: {template.name} (ID: {template.id})")
        
        return template
    
    async def update_consent_template(self, template_id: str, updates: Dict[str, Any]) -> Optional[ConsentTemplate]:
        """Update existing consent template"""
        
        if template_id not in self.consent_templates:
            return None
        
        template = self.consent_templates[template_id]
        
        for key, value in updates.items():
            if hasattr(template, key):
                setattr(template, key, value)
        
        # Increment version for tracking
        version_parts = template.version.split('.')
        version_parts[-1] = str(int(version_parts[-1]) + 1)
        template.version = '.'.join(version_parts)
        
        self.logger.info(f"Updated consent template: {template.name} (Version: {template.version})")
        
        return template
    
    async def collect_consent(self,
                            data_subject_id: str,
                            template_id: str,
                            purpose_consents: Dict[str, bool],
                            consent_method: ConsentMethod = ConsentMethod.WEB_FORM,
                            ip_address: Optional[str] = None,
                            user_agent: Optional[str] = None,
                            additional_evidence: Dict[str, Any] = None) -> ConsentRecord:
        """Collect consent from data subject"""
        
        template = self.consent_templates.get(template_id)
        if not template:
            raise ValueError(f"Consent template {template_id} not found")
        
        # Validate consent requirements
        await self._validate_consent_collection(template, purpose_consents)
        
        # Create consent record
        consent_record = ConsentRecord(
            data_subject_id=data_subject_id,
            consent_method=consent_method,
            consent_version=template.version,
            ip_address=ip_address,
            user_agent=user_agent,
            consent_text=self._generate_consent_text(template, purpose_consents),
            expiry_date=datetime.now() + timedelta(days=template.consent_expiry_period),
            consent_evidence=additional_evidence or {}
        )
        
        # Set purpose-specific consents
        for purpose_id, consented in purpose_consents.items():
            status = ConsentStatus.GIVEN if consented else ConsentStatus.WITHDRAWN
            consent_record.purposes[purpose_id] = status
            
            # Store detailed purpose consent
            if consented and purpose_id in self.consent_purposes:
                purpose = self.consent_purposes[purpose_id]
                consent_record.purpose_consents[purpose_id] = {
                    "purpose": purpose.purpose.value,
                    "description": purpose.description,
                    "consented": True,
                    "consent_timestamp": datetime.now().isoformat(),
                    "data_categories": purpose.data_categories,
                    "retention_period": purpose.retention_period,
                    "third_parties": purpose.third_parties
                }
        
        # Store consent record
        self.consent_records[consent_record.id] = consent_record
        
        # Log consent collection
        await self._log_consent_event(consent_record, "consent_collected")
        
        # Schedule consent renewal if needed
        await self._schedule_consent_renewal(consent_record, template)
        
        self.logger.info(f"Consent collected for data subject {data_subject_id} (Record ID: {consent_record.id})")
        
        return consent_record
    
    async def withdraw_consent(self,
                             data_subject_id: str,
                             purposes: List[str] = None,
                             withdrawal_method: ConsentMethod = ConsentMethod.WEB_FORM,
                             withdrawal_reason: str = "",
                             additional_evidence: Dict[str, Any] = None) -> List[ConsentRecord]:
        """Withdraw consent for data subject"""
        
        # Find active consent records for data subject
        subject_records = [
            record for record in self.consent_records.values()
            if record.data_subject_id == data_subject_id
            and any(status == ConsentStatus.GIVEN for status in record.purposes.values())
        ]
        
        if not subject_records:
            raise ValueError(f"No active consents found for data subject {data_subject_id}")
        
        withdrawn_records = []
        
        for record in subject_records:
            # Withdraw all purposes if not specified
            purposes_to_withdraw = purposes or list(record.purposes.keys())
            
            # Update consent statuses
            for purpose_id in purposes_to_withdraw:
                if purpose_id in record.purposes and record.purposes[purpose_id] == ConsentStatus.GIVEN:
                    record.purposes[purpose_id] = ConsentStatus.WITHDRAWN
                    
                    # Update purpose consent details
                    if purpose_id in record.purpose_consents:
                        record.purpose_consents[purpose_id].update({
                            "consented": False,
                            "withdrawal_timestamp": datetime.now().isoformat(),
                            "withdrawal_reason": withdrawal_reason
                        })
            
            # Update withdrawal information
            record.withdrawal_timestamp = datetime.now()
            record.withdrawal_method = withdrawal_method
            record.withdrawal_reason = withdrawal_reason
            record.withdrawal_evidence = additional_evidence or {}
            
            withdrawn_records.append(record)
            
            # Log withdrawal
            await self._log_consent_event(record, "consent_withdrawn", {
                "withdrawn_purposes": purposes_to_withdraw,
                "reason": withdrawal_reason
            })
        
        # Trigger data processing stop for withdrawn purposes
        await self._stop_processing_for_withdrawn_consent(data_subject_id, purposes_to_withdraw)
        
        self.logger.info(f"Consent withdrawn for data subject {data_subject_id} (Purposes: {purposes_to_withdraw})")
        
        return withdrawn_records
    
    async def update_consent(self,
                           consent_record_id: str,
                           purpose_updates: Dict[str, bool]) -> Optional[ConsentRecord]:
        """Update existing consent record"""
        
        record = self.consent_records.get(consent_record_id)
        if not record:
            return None
        
        original_purposes = record.purposes.copy()
        
        # Update purpose consents
        for purpose_id, consented in purpose_updates.items():
            new_status = ConsentStatus.GIVEN if consented else ConsentStatus.WITHDRAWN
            
            if purpose_id in record.purposes:
                record.purposes[purpose_id] = new_status
                
                # Update purpose consent details
                if purpose_id in record.purpose_consents:
                    record.purpose_consents[purpose_id].update({
                        "consented": consented,
                        "last_updated": datetime.now().isoformat()
                    })
        
        # Log consent update
        await self._log_consent_event(record, "consent_updated", {
            "original_purposes": {k: v.value for k, v in original_purposes.items()},
            "updated_purposes": {k: v.value for k, v in record.purposes.items()}
        })
        
        self.logger.info(f"Consent updated for record {consent_record_id}")
        
        return record
    
    async def check_consent_status(self, 
                                 data_subject_id: str, 
                                 purpose: ProcessingPurpose) -> Dict[str, Any]:
        """Check consent status for specific purpose"""
        
        # Find all consent records for data subject
        subject_records = [
            record for record in self.consent_records.values()
            if record.data_subject_id == data_subject_id
        ]
        
        if not subject_records:
            return {
                "has_consent": False,
                "status": "no_records",
                "message": "No consent records found for data subject"
            }
        
        # Find purpose-specific consent
        purpose_consent = None
        for record in subject_records:
            for purpose_id, purpose_data in record.purpose_consents.items():
                if purpose_data.get("purpose") == purpose.value:
                    purpose_consent = {
                        "record_id": record.id,
                        "status": record.purposes.get(purpose_id, ConsentStatus.WITHDRAWN),
                        "consent_timestamp": purpose_data.get("consent_timestamp"),
                        "expiry_date": record.expiry_date,
                        "data": purpose_data
                    }
                    break
            if purpose_consent:
                break
        
        if not purpose_consent:
            return {
                "has_consent": False,
                "status": "purpose_not_found",
                "message": f"No consent found for purpose: {purpose.value}"
            }
        
        # Check if consent is valid
        is_expired = (record.expiry_date and datetime.now() > record.expiry_date)
        is_given = purpose_consent["status"] == ConsentStatus.GIVEN
        
        return {
            "has_consent": is_given and not is_expired,
            "status": purpose_consent["status"].value,
            "consent_timestamp": purpose_consent["consent_timestamp"],
            "expiry_date": record.expiry_date.isoformat() if record.expiry_date else None,
            "expired": is_expired,
            "record_id": purpose_consent["record_id"],
            "purpose_data": purpose_consent["data"]
        }
    
    async def get_consent_proof(self, consent_record_id: str) -> Optional[Dict[str, Any]]:
        """Get proof of consent for auditing purposes"""
        
        record = self.consent_records.get(consent_record_id)
        if not record:
            return None
        
        proof = {
            "record_id": record.id,
            "data_subject_id": record.data_subject_id,
            "consent_timestamp": record.consent_timestamp.isoformat(),
            "consent_method": record.consent_method.value,
            "consent_version": record.consent_version,
            "consent_hash": record.consent_hash,
            "consent_text": record.consent_text,
            "ip_address": record.ip_address,
            "user_agent": record.user_agent,
            "digital_signature": record.digital_signature,
            "purposes_consented": {
                purpose_id: {
                    "status": status.value,
                    "details": record.purpose_consents.get(purpose_id, {})
                }
                for purpose_id, status in record.purposes.items()
            },
            "evidence": record.consent_evidence,
            "integrity_verified": self._verify_consent_integrity(record)
        }
        
        return proof
    
    def _verify_consent_integrity(self, record: ConsentRecord) -> bool:
        """Verify consent record integrity using hash"""
        
        expected_hash = hashlib.sha256(
            f"{record.data_subject_id}{record.consent_timestamp.isoformat()}{record.consent_text}".encode()
        ).hexdigest()
        
        return expected_hash == record.consent_hash
    
    async def manage_consent_renewals(self) -> Dict[str, Any]:
        """Manage consent renewals and expiry"""
        
        now = datetime.now()
        renewal_results = {
            "expired_consents": [],
            "renewal_due": [],
            "renewal_sent": [],
            "errors": []
        }
        
        for record in self.consent_records.values():
            # Check for expired consents
            if record.expiry_date and now > record.expiry_date:
                # Mark as expired
                for purpose_id in record.purposes:
                    if record.purposes[purpose_id] == ConsentStatus.GIVEN:
                        record.purposes[purpose_id] = ConsentStatus.EXPIRED
                
                renewal_results["expired_consents"].append(record.id)
                
                # Log expiry
                await self._log_consent_event(record, "consent_expired")
            
            # Check for renewal due (30 days before expiry)
            elif record.expiry_date and now > (record.expiry_date - timedelta(days=30)):
                if not record.renewal_sent:
                    try:
                        await self._send_consent_renewal(record)
                        record.renewal_sent = True
                        renewal_results["renewal_sent"].append(record.id)
                    except Exception as e:
                        renewal_results["errors"].append({
                            "record_id": record.id,
                            "error": str(e)
                        })
                else:
                    renewal_results["renewal_due"].append(record.id)
        
        return renewal_results
    
    async def _send_consent_renewal(self, record: ConsentRecord):
        """Send consent renewal notification"""
        
        renewal_data = {
            "data_subject_id": record.data_subject_id,
            "record_id": record.id,
            "expiry_date": record.expiry_date.isoformat() if record.expiry_date else None,
            "renewal_url": f"https://company.com/consent-renewal/{record.id}",
            "purposes": record.purpose_consents
        }
        
        # In production, this would send actual renewal notifications
        self.logger.info(f"Consent renewal notification sent for record {record.id}")
        
        await self._log_consent_event(record, "renewal_notification_sent")
    
    async def get_consent_analytics(self, 
                                  start_date: Optional[datetime] = None, 
                                  end_date: Optional[datetime] = None) -> ConsentAnalytics:
        """Generate consent analytics and reporting data"""
        
        if not start_date:
            start_date = datetime.now() - timedelta(days=30)
        if not end_date:
            end_date = datetime.now()
        
        # Filter records by date range
        filtered_records = [
            record for record in self.consent_records.values()
            if start_date <= record.consent_timestamp <= end_date
        ]
        
        analytics = ConsentAnalytics()
        analytics.total_consents = len(filtered_records)
        
        if filtered_records:
            # Calculate consent rates
            given_consents = sum(
                1 for record in filtered_records
                if any(status == ConsentStatus.GIVEN for status in record.purposes.values())
            )
            withdrawn_consents = sum(
                1 for record in filtered_records
                if any(status == ConsentStatus.WITHDRAWN for status in record.purposes.values())
            )
            
            analytics.consent_rate = given_consents / len(filtered_records)
            analytics.withdrawal_rate = withdrawn_consents / len(filtered_records) if given_consents > 0 else 0
            
            # Consent by purpose
            for record in filtered_records:
                for purpose_id, status in record.purposes.items():
                    purpose_name = self.consent_purposes.get(purpose_id, ConsentPurpose()).purpose.value
                    if status == ConsentStatus.GIVEN:
                        analytics.consent_by_purpose[purpose_name] = analytics.consent_by_purpose.get(purpose_name, 0) + 1
            
            # Consent by method
            for record in filtered_records:
                method = record.consent_method.value
                analytics.consent_by_method[method] = analytics.consent_by_method.get(method, 0) + 1
            
            # Count renewal due and expired
            now = datetime.now()
            for record in self.consent_records.values():  # Check all records, not just filtered
                if record.expiry_date:
                    if now > record.expiry_date:
                        analytics.expired_consents += 1
                    elif now > (record.expiry_date - timedelta(days=30)):
                        analytics.renewal_due += 1
        
        return analytics
    
    async def export_consent_data(self, 
                                data_subject_id: str, 
                                format: str = "json") -> Dict[str, Any]:
        """Export consent data for data subject (Article 20 - Data Portability)"""
        
        # Find all consent records for data subject
        subject_records = [
            record for record in self.consent_records.values()
            if record.data_subject_id == data_subject_id
        ]
        
        if not subject_records:
            return {"error": "No consent records found for data subject"}
        
        export_data = {
            "data_subject_id": data_subject_id,
            "export_timestamp": datetime.now().isoformat(),
            "consent_records": [],
            "consent_summary": {
                "total_records": len(subject_records),
                "active_consents": 0,
                "withdrawn_consents": 0,
                "expired_consents": 0
            }
        }
        
        for record in subject_records:
            record_data = record.to_dict()
            
            # Add purpose details
            record_data["purpose_details"] = {}
            for purpose_id in record.purposes:
                if purpose_id in self.consent_purposes:
                    purpose = self.consent_purposes[purpose_id]
                    record_data["purpose_details"][purpose_id] = purpose.to_dict()
            
            export_data["consent_records"].append(record_data)
            
            # Update summary
            for status in record.purposes.values():
                if status == ConsentStatus.GIVEN:
                    export_data["consent_summary"]["active_consents"] += 1
                elif status == ConsentStatus.WITHDRAWN:
                    export_data["consent_summary"]["withdrawn_consents"] += 1
                elif status == ConsentStatus.EXPIRED:
                    export_data["consent_summary"]["expired_consents"] += 1
        
        return export_data
    
    async def _validate_consent_collection(self, 
                                         template: ConsentTemplate, 
                                         purpose_consents: Dict[str, bool]):
        """Validate consent collection requirements"""
        
        # Check age requirements
        if template.age_verification_required:
            # In production, this would check actual age verification
            pass
        
        # Check required consents
        for purpose in template.purposes:
            if purpose.required and not purpose_consents.get(purpose.id, False):
                raise ValueError(f"Required consent not provided for purpose: {purpose.description}")
        
        # Validate GDPR requirements
        if template.legal_basis == LegalBasis.CONSENT:
            # Ensure at least one purpose has consent
            if not any(purpose_consents.values()):
                raise ValueError("At least one purpose must have consent when legal basis is consent")
    
    def _generate_consent_text(self, template: ConsentTemplate, purpose_consents: Dict[str, bool]) -> str:
        """Generate consent text based on template and selected purposes"""
        
        consented_purposes = []
        for purpose_id, consented in purpose_consents.items():
            if consented and purpose_id in self.consent_purposes:
                purpose = self.consent_purposes[purpose_id]
                consented_purposes.append(f"- {purpose.description}")
        
        purposes_list = "\n".join(consented_purposes) if consented_purposes else "No purposes selected"
        
        consent_text = template.consent_text_template.format(
            purposes_list=purposes_list,
            privacy_policy_url=template.privacy_policy_url
        )
        
        return consent_text
    
    async def _schedule_consent_renewal(self, record: ConsentRecord, template: ConsentTemplate):
        """Schedule consent renewal reminder"""
        
        if record.expiry_date:
            record.renewal_date = record.expiry_date - timedelta(days=30)  # 30 days before expiry
            record.renewal_required = True
        
        # In production, this would schedule actual renewal tasks
    
    async def _stop_processing_for_withdrawn_consent(self, 
                                                   data_subject_id: str, 
                                                   withdrawn_purposes: List[str]):
        """Stop data processing for withdrawn consent purposes"""
        
        # This would integrate with the main processing system to stop
        # processing activities that were based on the withdrawn consent
        
        self.logger.info(f"Processing stopped for data subject {data_subject_id} for withdrawn purposes: {withdrawn_purposes}")
        
        # In production, this would:
        # 1. Stop automated processing
        # 2. Update processing flags
        # 3. Notify relevant systems
        # 4. Archive or delete data if required
    
    async def _log_consent_event(self, record: ConsentRecord, event_type: str, metadata: Dict[str, Any] = None):
        """Log consent events for audit trail"""
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "consent_record_id": record.id,
            "data_subject_id": record.data_subject_id,
            "consent_method": record.consent_method.value,
            "metadata": metadata or {}
        }
        
        self.logger.info(f"Consent event: {event_type} for record {record.id}")
        
        # In production, this would write to audit database
    
    # Management methods
    def get_consent_record(self, record_id: str) -> Optional[ConsentRecord]:
        """Get consent record by ID"""
        return self.consent_records.get(record_id)
    
    def get_consent_records_by_subject(self, data_subject_id: str) -> List[ConsentRecord]:
        """Get all consent records for data subject"""
        return [
            record for record in self.consent_records.values()
            if record.data_subject_id == data_subject_id
        ]
    
    def get_consent_template(self, template_id: str) -> Optional[ConsentTemplate]:
        """Get consent template by ID"""
        return self.consent_templates.get(template_id)
    
    def list_consent_templates(self) -> List[ConsentTemplate]:
        """List all consent templates"""
        return list(self.consent_templates.values())
    
    def get_consent_purpose(self, purpose_id: str) -> Optional[ConsentPurpose]:
        """Get consent purpose by ID"""
        return self.consent_purposes.get(purpose_id)
    
    def list_consent_purposes(self) -> List[ConsentPurpose]:
        """List all consent purposes"""
        return list(self.consent_purposes.values())
    
    async def delete_consent_data(self, data_subject_id: str) -> Dict[str, Any]:
        """Delete all consent data for data subject (Article 17 - Right to Erasure)"""
        
        subject_records = [
            record for record in self.consent_records.values()
            if record.data_subject_id == data_subject_id
        ]
        
        deleted_records = []
        for record in subject_records:
            deleted_records.append(record.id)
            del self.consent_records[record.id]
            
            # Log deletion
            await self._log_consent_event(record, "consent_data_deleted")
        
        return {
            "deleted_records": deleted_records,
            "total_deleted": len(deleted_records)
        }