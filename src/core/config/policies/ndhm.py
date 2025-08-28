"""
NDHM Compliance Policy for PII De-identification System

This module implements the National Digital Health Mission (NDHM) compliance
requirements for handling health data in India.
"""

from typing import Dict, List, Optional, Set, Any
from .base import BasePolicy, PolicyRule, PIIType, RedactionMethod


class NDHMPolicy(BasePolicy):
    """NDHM compliance policy implementation."""
    
    def __init__(self, **data):
        super().__init__(**data)
        self.name = "NDHM Compliance Policy"
        self.description = "Policy for handling health data under NDHM regulations in India"
        self.compliance_standard = "NDHM"
        self.effective_date = "2024-01-01"
        
        # Initialize NDHM-specific rules
        self._initialize_ndhm_rules()
    
    def _initialize_ndhm_rules(self):
        """Initialize NDHM-specific policy rules."""
        
        # Health Data Categories
        self.rules = [
            # Personal Identifiers
            PolicyRule(
                pii_type=PIIType.NAME,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.9,
                retention_period_days=2555,  # 7 years
                metadata={"ndhm_category": "personal_identifier", "consent_required": True}
            ),
            
            # Aadhar Number (Unique Health ID)
            PolicyRule(
                pii_type=PIIType.AADHAR,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.95,
                retention_period_days=2555,
                metadata={"ndhm_category": "unique_identifier", "consent_required": True}
            ),
            
            # PAN Number
            PolicyRule(
                pii_type=PIIType.PAN,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.95,
                retention_period_days=2555,
                metadata={"ndhm_category": "financial_identifier", "consent_required": True}
            ),
            
            # Contact Information
            PolicyRule(
                pii_type=PIIType.PHONE,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.8,
                retention_period_days=2555,
                metadata={"ndhm_category": "contact_info", "consent_required": True}
            ),
            
            PolicyRule(
                pii_type=PIIType.EMAIL,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.8,
                retention_period_days=2555,
                metadata={"ndhm_category": "contact_info", "consent_required": True}
            ),
            
            # Address Information
            PolicyRule(
                pii_type=PIIType.ADDRESS,
                redaction_method=RedactionMethod.GENERALIZE,
                confidence_threshold=0.8,
                retention_period_days=2555,
                metadata={"ndhm_category": "location_info", "consent_required": True}
            ),
            
            PolicyRule(
                pii_type=PIIType.PINCODE,
                redaction_method=RedactionMethod.GENERALIZE,
                confidence_threshold=0.8,
                retention_period_days=2555,
                metadata={"ndhm_category": "location_info", "consent_required": True}
            ),
            
            # Date of Birth
            PolicyRule(
                pii_type=PIIType.DATE_OF_BIRTH,
                redaction_method=RedactionMethod.GENERALIZE,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"ndhm_category": "demographic_info", "consent_required": True}
            ),
            
            # Age
            PolicyRule(
                pii_type=PIIType.AGE,
                redaction_method=RedactionMethod.GENERALIZE,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"ndhm_category": "demographic_info", "consent_required": True}
            ),
            
            # Gender
            PolicyRule(
                pii_type=PIIType.GENDER,
                redaction_method=RedactionMethod.GENERALIZE,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"ndhm_category": "demographic_info", "consent_required": True}
            ),
            
            # Medical Information
            PolicyRule(
                pii_type=PIIType.MEDICAL_RECORD,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"ndhm_category": "health_data", "consent_required": True}
            ),
            
            PolicyRule(
                pii_type=PIIType.DIAGNOSIS,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"ndhm_category": "health_data", "consent_required": True}
            ),
            
            PolicyRule(
                pii_type=PIIType.MEDICATION,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"ndhm_category": "health_data", "consent_required": True}
            ),
            
            PolicyRule(
                pii_type=PIIType.TREATMENT,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"ndhm_category": "health_data", "consent_required": True}
            ),
            
            # Financial Information
            PolicyRule(
                pii_type=PIIType.BANK_ACCOUNT,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.95,
                retention_period_days=2555,
                metadata={"ndhm_category": "financial_info", "consent_required": True}
            ),
            
            PolicyRule(
                pii_type=PIIType.CREDIT_CARD,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.95,
                retention_period_days=2555,
                metadata={"ndhm_category": "financial_info", "consent_required": True}
            ),
            
            # Photos and Biometrics
            PolicyRule(
                pii_type=PIIType.PHOTO,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"ndhm_category": "biometric_data", "consent_required": True}
            ),
            
            # Signatures
            PolicyRule(
                pii_type=PIIType.SIGNATURE,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"ndhm_category": "biometric_data", "consent_required": True}
            ),
        ]
        
        # NDHM-specific settings
        self.strict_mode = True
        self.require_approval = True
        self.allow_pseudonymization = True
        self.allow_generalization = True
        self.max_retention_days = 2555  # 7 years
    
    def validate_document(self, document_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate document against NDHM requirements."""
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "required_fields": [],
            "prohibited_fields": [],
            "ndhm_compliance": {}
        }
        
        # Check for required NDHM fields
        required_fields = self.get_required_fields()
        for field in required_fields:
            if field not in document_data:
                validation_result["errors"].append(f"Required NDHM field missing: {field}")
                validation_result["valid"] = False
        
        # Check for prohibited data
        prohibited_fields = self.get_prohibited_fields()
        for field in prohibited_fields:
            if field in document_data:
                validation_result["warnings"].append(f"Prohibited data field found: {field}")
                validation_result["prohibited_fields"].append(field)
        
        # NDHM-specific validations
        ndhm_validation = self._validate_ndhm_principles(document_data)
        validation_result["ndhm_compliance"] = ndhm_validation
        
        if not ndhm_validation["principles_met"]:
            validation_result["valid"] = False
        
        return validation_result
    
    def get_required_fields(self) -> Set[str]:
        """Get required fields for NDHM compliance."""
        return {
            "patient_consent",
            "health_id_consent",
            "data_sharing_consent",
            "purpose_of_data_use",
            "data_retention_policy",
            "data_security_measures",
            "healthcare_provider_info",
            "data_controller_info"
        }
    
    def get_prohibited_fields(self) -> Set[str]:
        """Get prohibited fields under NDHM."""
        return {
            "unauthorized_health_data",
            "genetic_data_without_consent",
            "mental_health_data_without_consent",
            "reproductive_health_data_without_consent",
            "hiv_status_without_consent"
        }
    
    def _validate_ndhm_principles(self, document_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate NDHM principles."""
        principles = {
            "consent_management": self._validate_consent_management(document_data),
            "data_minimization": self._validate_data_minimization(document_data),
            "purpose_limitation": self._validate_purpose_limitation(document_data),
            "data_security": self._validate_data_security(document_data),
            "data_quality": self._validate_data_quality(document_data),
            "accountability": self._validate_accountability(document_data),
            "transparency": self._validate_transparency(document_data),
            "data_portability": self._validate_data_portability(document_data)
        }
        
        return {
            "principles_met": all(principles.values()),
            "principles": principles
        }
    
    def _validate_consent_management(self, document_data: Dict[str, Any]) -> bool:
        """Validate consent management principle."""
        consent_fields = ["patient_consent", "health_id_consent", "data_sharing_consent"]
        return all(field in document_data for field in consent_fields)
    
    def _validate_data_minimization(self, document_data: Dict[str, Any]) -> bool:
        """Validate data minimization principle."""
        return "data_minimization_justification" in document_data
    
    def _validate_purpose_limitation(self, document_data: Dict[str, Any]) -> bool:
        """Validate purpose limitation principle."""
        return "purpose_of_data_use" in document_data and "purpose_compatibility" in document_data
    
    def _validate_data_security(self, document_data: Dict[str, Any]) -> bool:
        """Validate data security principle."""
        security_measures = ["encryption", "access_controls", "audit_logs", "data_backup"]
        return any(measure in document_data for measure in security_measures)
    
    def _validate_data_quality(self, document_data: Dict[str, Any]) -> bool:
        """Validate data quality principle."""
        quality_measures = ["data_validation", "accuracy_checks", "completeness_verification"]
        return any(measure in document_data for measure in quality_measures)
    
    def _validate_accountability(self, document_data: Dict[str, Any]) -> bool:
        """Validate accountability principle."""
        accountability_measures = ["data_controller_info", "data_processor_info", "audit_trails"]
        return any(measure in document_data for measure in accountability_measures)
    
    def _validate_transparency(self, document_data: Dict[str, Any]) -> bool:
        """Validate transparency principle."""
        transparency_measures = ["privacy_policy", "data_usage_notice", "rights_information"]
        return any(measure in document_data for measure in transparency_measures)
    
    def _validate_data_portability(self, document_data: Dict[str, Any]) -> bool:
        """Validate data portability principle."""
        return "data_portability_format" in document_data and "export_capability" in document_data
    
    def get_health_data_categories(self) -> Dict[str, Any]:
        """Get NDHM health data categories."""
        return {
            "personal_identifier": "Basic identification information",
            "unique_identifier": "Aadhar, PAN, etc.",
            "contact_info": "Phone, email, address",
            "location_info": "Address, pincode, coordinates",
            "demographic_info": "Age, gender, date of birth",
            "health_data": "Medical records, diagnosis, treatment",
            "financial_info": "Bank details, insurance",
            "biometric_data": "Photos, signatures, fingerprints"
        }
    
    def get_consent_types(self) -> Dict[str, Any]:
        """Get NDHM consent types."""
        return {
            "patient_consent": "General consent for healthcare",
            "health_id_consent": "Consent for Health ID creation",
            "data_sharing_consent": "Consent for data sharing",
            "research_consent": "Consent for research purposes",
            "emergency_consent": "Consent for emergency situations"
        }
    
    def get_data_rights(self) -> Dict[str, Any]:
        """Get NDHM data subject rights."""
        return {
            "right_to_access": "Access personal health data",
            "right_to_correction": "Correct inaccurate data",
            "right_to_deletion": "Request data deletion",
            "right_to_portability": "Receive data in portable format",
            "right_to_withdraw_consent": "Withdraw consent at any time",
            "right_to_complaint": "File complaints with authorities"
        }
    
    def get_breach_notification_requirements(self) -> Dict[str, Any]:
        """Get breach notification requirements under NDHM."""
        return {
            "timeline": "Within 72 hours of discovery",
            "notification_authority": "NDHM Authority",
            "notification_data_subjects": "Without undue delay if high risk",
            "documentation": [
                "Nature of health data breach",
                "Categories and number of individuals affected",
                "Categories and number of health records affected",
                "Likely consequences of the breach",
                "Measures taken to address the breach",
                "Contact details of Data Protection Officer",
                "Health ID impact assessment"
            ]
        }
    
    def is_sensitive_health_data(self, data_type: str) -> bool:
        """Check if data type is considered sensitive health data under NDHM."""
        sensitive_types = [
            "mental_health", "reproductive_health", "hiv_status", "genetic_data",
            "substance_abuse", "psychiatric_treatment", "sexual_health"
        ]
        return data_type.lower() in sensitive_types
    
    def get_health_id_requirements(self) -> Dict[str, Any]:
        """Get Health ID requirements under NDHM."""
        return {
            "mandatory_fields": [
                "name", "date_of_birth", "gender", "mobile_number", "email"
            ],
            "optional_fields": [
                "address", "photo", "biometric_data", "emergency_contact"
            ],
            "verification_required": [
                "aadhar_verification", "mobile_verification", "email_verification"
            ]
        }
