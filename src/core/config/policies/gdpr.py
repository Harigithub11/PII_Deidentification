"""
GDPR Compliance Policy for PII De-identification System

This module implements the General Data Protection Regulation (GDPR) compliance
requirements for handling personal data in the European Union.
"""

from typing import Dict, List, Optional, Set, Any
from .base import BasePolicy, PolicyRule, PIIType, RedactionMethod


class GDPRPolicy(BasePolicy):
    """GDPR compliance policy implementation."""
    
    def __init__(self, **data):
        super().__init__(**data)
        self.name = "GDPR Compliance Policy"
        self.description = "Policy for handling personal data under GDPR regulations"
        self.compliance_standard = "GDPR"
        self.effective_date = "2024-01-01"
        
        # Initialize GDPR-specific rules
        self._initialize_gdpr_rules()
    
    def _initialize_gdpr_rules(self):
        """Initialize GDPR-specific policy rules."""
        
        # Personal Data Categories
        self.rules = [
            # Basic Personal Data
            PolicyRule(
                pii_type=PIIType.NAME,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.9,
                retention_period_days=1095,  # 3 years
                metadata={"gdpr_category": "basic_personal_data", "legal_basis": "legitimate_interest"}
            ),
            
            # Contact Information
            PolicyRule(
                pii_type=PIIType.EMAIL,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.8,
                retention_period_days=1095,
                metadata={"gdpr_category": "contact_data", "legal_basis": "consent"}
            ),
            
            PolicyRule(
                pii_type=PIIType.PHONE,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.8,
                retention_period_days=1095,
                metadata={"gdpr_category": "contact_data", "legal_basis": "consent"}
            ),
            
            PolicyRule(
                pii_type=PIIType.ADDRESS,
                redaction_method=RedactionMethod.GENERALIZE,
                confidence_threshold=0.8,
                retention_period_days=1095,
                metadata={"gdpr_category": "location_data", "legal_basis": "legitimate_interest"}
            ),
            
            # Identification Data
            PolicyRule(
                pii_type=PIIType.PASSPORT,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.95,
                retention_period_days=1095,
                metadata={"gdpr_category": "identification_data", "legal_basis": "legal_obligation"}
            ),
            
            PolicyRule(
                pii_type=PIIType.DRIVER_LICENSE,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.95,
                retention_period_days=1095,
                metadata={"gdpr_category": "identification_data", "legal_basis": "legal_obligation"}
            ),
            
            PolicyRule(
                pii_type=PIIType.NATIONAL_ID,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.95,
                retention_period_days=1095,
                metadata={"gdpr_category": "identification_data", "legal_basis": "legal_obligation"}
            ),
            
            # Financial Data
            PolicyRule(
                pii_type=PIIType.CREDIT_CARD,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.95,
                retention_period_days=1095,
                metadata={"gdpr_category": "financial_data", "legal_basis": "contract"}
            ),
            
            PolicyRule(
                pii_type=PIIType.BANK_ACCOUNT,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.95,
                retention_period_days=1095,
                metadata={"gdpr_category": "financial_data", "legal_basis": "contract"}
            ),
            
            PolicyRule(
                pii_type=PIIType.IBAN,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.95,
                retention_period_days=1095,
                metadata={"gdpr_category": "financial_data", "legal_basis": "contract"}
            ),
            
            # Sensitive Personal Data (Article 9)
            PolicyRule(
                pii_type=PIIType.DATE_OF_BIRTH,
                redaction_method=RedactionMethod.GENERALIZE,
                confidence_threshold=0.9,
                retention_period_days=1095,
                metadata={"gdpr_category": "sensitive_data", "legal_basis": "explicit_consent"}
            ),
            
            PolicyRule(
                pii_type=PIIType.AGE,
                redaction_method=RedactionMethod.GENERALIZE,
                confidence_threshold=0.9,
                retention_period_days=1095,
                metadata={"gdpr_category": "sensitive_data", "legal_basis": "explicit_consent"}
            ),
            
            PolicyRule(
                pii_type=PIIType.GENDER,
                redaction_method=RedactionMethod.GENERALIZE,
                confidence_threshold=0.9,
                retention_period_days=1095,
                metadata={"gdpr_category": "sensitive_data", "legal_basis": "explicit_consent"}
            ),
            
            # Biometric Data
            PolicyRule(
                pii_type=PIIType.PHOTO,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.9,
                retention_period_days=1095,
                metadata={"gdpr_category": "biometric_data", "legal_basis": "explicit_consent"}
            ),
            
            # Location Data
            PolicyRule(
                pii_type=PIIType.LOCATION,
                redaction_method=RedactionMethod.GENERALIZE,
                confidence_threshold=0.8,
                retention_period_days=1095,
                metadata={"gdpr_category": "location_data", "legal_basis": "legitimate_interest"}
            ),
            
            # IP Address
            PolicyRule(
                pii_type=PIIType.IP_ADDRESS,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.8,
                retention_period_days=1095,
                metadata={"gdpr_category": "technical_data", "legal_basis": "legitimate_interest"}
            ),
        ]
        
        # GDPR-specific settings
        self.strict_mode = True
        self.require_approval = True
        self.allow_pseudonymization = True
        self.allow_generalization = True
        self.max_retention_days = 1095  # 3 years
    
    def validate_document(self, document_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate document against GDPR requirements."""
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "required_fields": [],
            "prohibited_fields": [],
            "gdpr_compliance": {}
        }
        
        # Check for required GDPR fields
        required_fields = self.get_required_fields()
        for field in required_fields:
            if field not in document_data:
                validation_result["errors"].append(f"Required GDPR field missing: {field}")
                validation_result["valid"] = False
        
        # Check for prohibited data
        prohibited_fields = self.get_prohibited_fields()
        for field in prohibited_fields:
            if field in document_data:
                validation_result["warnings"].append(f"Prohibited data field found: {field}")
                validation_result["prohibited_fields"].append(field)
        
        # GDPR-specific validations
        gdpr_validation = self._validate_gdpr_principles(document_data)
        validation_result["gdpr_compliance"] = gdpr_validation
        
        if not gdpr_validation["principles_met"]:
            validation_result["valid"] = False
        
        return validation_result
    
    def get_required_fields(self) -> Set[str]:
        """Get required fields for GDPR compliance."""
        return {
            "legal_basis",
            "data_subject_rights",
            "retention_policy",
            "data_processing_purpose",
            "data_controller_info",
            "data_processor_info"
        }
    
    def get_prohibited_fields(self) -> Set[str]:
        """Get prohibited fields under GDPR."""
        return {
            "unlawful_processing",
            "excessive_data",
            "incompatible_purpose",
            "inadequate_security"
        }
    
    def _validate_gdpr_principles(self, document_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate GDPR principles."""
        principles = {
            "lawfulness": self._validate_lawfulness(document_data),
            "fairness": self._validate_fairness(document_data),
            "transparency": self._validate_transparency(document_data),
            "purpose_limitation": self._validate_purpose_limitation(document_data),
            "data_minimization": self._validate_data_minimization(document_data),
            "accuracy": self._validate_accuracy(document_data),
            "storage_limitation": self._validate_storage_limitation(document_data),
            "integrity_confidentiality": self._validate_integrity_confidentiality(document_data),
            "accountability": self._validate_accountability(document_data)
        }
        
        return {
            "principles_met": all(principles.values()),
            "principles": principles
        }
    
    def _validate_lawfulness(self, document_data: Dict[str, Any]) -> bool:
        """Validate lawfulness principle."""
        legal_bases = ["consent", "contract", "legal_obligation", "vital_interests", 
                      "public_task", "legitimate_interests"]
        return "legal_basis" in document_data and document_data["legal_basis"] in legal_bases
    
    def _validate_fairness(self, document_data: Dict[str, Any]) -> bool:
        """Validate fairness principle."""
        return "data_subject_rights" in document_data and "processing_purpose" in document_data
    
    def _validate_transparency(self, document_data: Dict[str, Any]) -> bool:
        """Validate transparency principle."""
        required_info = ["data_controller_info", "data_processing_purpose", "data_subject_rights"]
        return all(field in document_data for field in required_info)
    
    def _validate_purpose_limitation(self, document_data: Dict[str, Any]) -> bool:
        """Validate purpose limitation principle."""
        return "data_processing_purpose" in document_data and "purpose_compatibility" in document_data
    
    def _validate_data_minimization(self, document_data: Dict[str, Any]) -> bool:
        """Validate data minimization principle."""
        return "data_minimization_justification" in document_data
    
    def _validate_accuracy(self, document_data: Dict[str, Any]) -> bool:
        """Validate accuracy principle."""
        return "data_accuracy_measures" in document_data
    
    def _validate_storage_limitation(self, document_data: Dict[str, Any]) -> bool:
        """Validate storage limitation principle."""
        return "retention_policy" in document_data and "deletion_schedule" in document_data
    
    def _validate_integrity_confidentiality(self, document_data: Dict[str, Any]) -> bool:
        """Validate integrity and confidentiality principle."""
        security_measures = ["encryption", "access_controls", "security_policies"]
        return any(measure in document_data for measure in security_measures)
    
    def _validate_accountability(self, document_data: Dict[str, Any]) -> bool:
        """Validate accountability principle."""
        accountability_measures = ["data_protection_officer", "audit_logs", "training_records"]
        return any(measure in document_data for measure in accountability_measures)
    
    def get_data_subject_rights(self) -> Dict[str, Any]:
        """Get data subject rights under GDPR."""
        return {
            "right_to_be_informed": "Information about data processing",
            "right_of_access": "Access to personal data",
            "right_to_rectification": "Correct inaccurate data",
            "right_to_erasure": "Right to be forgotten",
            "right_to_restrict_processing": "Limit data processing",
            "right_to_data_portability": "Receive data in portable format",
            "right_to_object": "Object to data processing",
            "right_to_automated_decision_making": "Human review of automated decisions"
        }
    
    def get_legal_bases(self) -> Dict[str, Any]:
        """Get legal bases for data processing under GDPR."""
        return {
            "consent": "Explicit consent from data subject",
            "contract": "Processing necessary for contract performance",
            "legal_obligation": "Processing required by law",
            "vital_interests": "Protection of vital interests",
            "public_task": "Processing in public interest",
            "legitimate_interests": "Legitimate interests of controller"
        }
    
    def get_breach_notification_requirements(self) -> Dict[str, Any]:
        """Get breach notification requirements under GDPR."""
        return {
            "timeline": "Within 72 hours of discovery",
            "notification_authority": "Supervisory Authority",
            "notification_data_subjects": "Without undue delay if high risk",
            "documentation": [
                "Nature of personal data breach",
                "Categories and number of data subjects affected",
                "Categories and number of personal data records affected",
                "Likely consequences of the breach",
                "Measures taken to address the breach",
                "Contact details of Data Protection Officer"
            ]
        }
    
    def is_sensitive_data(self, data_type: str) -> bool:
        """Check if data type is considered sensitive under GDPR."""
        sensitive_types = [
            "racial_ethnic_origin", "political_opinions", "religious_beliefs",
            "trade_union_membership", "genetic_data", "biometric_data",
            "health_data", "sex_life", "sexual_orientation"
        ]
        return data_type.lower() in sensitive_types
