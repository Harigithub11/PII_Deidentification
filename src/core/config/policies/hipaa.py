"""
HIPAA Compliance Policy for PII De-identification System

This module implements the Health Insurance Portability and Accountability Act (HIPAA)
compliance requirements for handling Protected Health Information (PHI).
"""

from typing import Dict, List, Optional, Set, Any
from .base import BasePolicy, PolicyRule, PIIType, RedactionMethod


class HIPAAPolicy(BasePolicy):
    """HIPAA compliance policy implementation."""
    
    def __init__(self, **data):
        super().__init__(**data)
        self.name = "HIPAA Compliance Policy"
        self.description = "Policy for handling Protected Health Information (PHI) under HIPAA regulations"
        self.compliance_standard = "HIPAA"
        self.effective_date = "2024-01-01"
        
        # Initialize HIPAA-specific rules
        self._initialize_hipaa_rules()
    
    def _initialize_hipaa_rules(self):
        """Initialize HIPAA-specific policy rules."""
        
        # Patient Identifiers (18 identifiers that must be protected)
        self.rules = [
            # Names
            PolicyRule(
                pii_type=PIIType.NAME,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.9,
                retention_period_days=2555,  # 7 years
                metadata={"hipaa_category": "patient_identifier"}
            ),
            
            # Geographic subdivisions smaller than a state
            PolicyRule(
                pii_type=PIIType.ADDRESS,
                redaction_method=RedactionMethod.GENERALIZE,
                confidence_threshold=0.8,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier"}
            ),
            
            # Dates related to an individual
            PolicyRule(
                pii_type=PIIType.DATE_OF_BIRTH,
                redaction_method=RedactionMethod.GENERALIZE,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier"}
            ),
            
            # Phone numbers
            PolicyRule(
                pii_type=PIIType.PHONE,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.8,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier"}
            ),
            
            # Fax numbers
            PolicyRule(
                pii_type=PIIType.PHONE,  # Using phone type for fax
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.8,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier", "subtype": "fax"}
            ),
            
            # Email addresses
            PolicyRule(
                pii_type=PIIType.EMAIL,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.8,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier"}
            ),
            
            # Social Security numbers
            PolicyRule(
                pii_type=PIIType.SSN,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.95,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier"}
            ),
            
            # Medical record numbers
            PolicyRule(
                pii_type=PIIType.MEDICAL_RECORD,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier"}
            ),
            
            # Health plan beneficiary numbers
            PolicyRule(
                pii_type=PIIType.MEDICAL_RECORD,  # Using medical record type
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier", "subtype": "beneficiary_number"}
            ),
            
            # Account numbers
            PolicyRule(
                pii_type=PIIType.BANK_ACCOUNT,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier"}
            ),
            
            # Certificate/license numbers
            PolicyRule(
                pii_type=PIIType.DRIVER_LICENSE,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier"}
            ),
            
            # Vehicle identifiers and serial numbers
            PolicyRule(
                pii_type=PIIType.NATIONAL_ID,  # Using national ID type
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.8,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier", "subtype": "vehicle"}
            ),
            
            # Device identifiers and serial numbers
            PolicyRule(
                pii_type=PIIType.NATIONAL_ID,  # Using national ID type
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.8,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier", "subtype": "device"}
            ),
            
            # Web Universal Resource Locators (URLs)
            PolicyRule(
                pii_type=PIIType.IP_ADDRESS,  # Using IP address type
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.8,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier", "subtype": "url"}
            ),
            
            # Internet Protocol (IP) address numbers
            PolicyRule(
                pii_type=PIIType.IP_ADDRESS,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.8,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier"}
            ),
            
            # Biometric identifiers
            PolicyRule(
                pii_type=PIIType.PHOTO,  # Using photo type for biometrics
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier", "subtype": "biometric"}
            ),
            
            # Full face photographic images
            PolicyRule(
                pii_type=PIIType.PHOTO,
                redaction_method=RedactionMethod.BLACKOUT,
                confidence_threshold=0.9,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier", "subtype": "face"}
            ),
            
            # Any other unique identifying number, characteristic, or code
            PolicyRule(
                pii_type=PIIType.NATIONAL_ID,
                redaction_method=RedactionMethod.PSEUDONYMIZE,
                confidence_threshold=0.8,
                retention_period_days=2555,
                metadata={"hipaa_category": "patient_identifier", "subtype": "other"}
            ),
        ]
        
        # Additional HIPAA-specific settings
        self.strict_mode = True
        self.require_approval = True
        self.allow_pseudonymization = True
        self.allow_generalization = True
        self.max_retention_days = 2555  # 7 years
    
    def validate_document(self, document_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate document against HIPAA requirements."""
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "required_fields": [],
            "prohibited_fields": []
        }
        
        # Check for required HIPAA fields
        required_fields = self.get_required_fields()
        for field in required_fields:
            if field not in document_data:
                validation_result["errors"].append(f"Required HIPAA field missing: {field}")
                validation_result["valid"] = False
        
        # Check for prohibited PHI
        prohibited_fields = self.get_prohibited_fields()
        for field in prohibited_fields:
            if field in document_data:
                validation_result["warnings"].append(f"Prohibited PHI field found: {field}")
                validation_result["prohibited_fields"].append(field)
        
        # HIPAA-specific validations
        if "medical_diagnosis" in document_data:
            if not self._validate_diagnosis_consent(document_data):
                validation_result["errors"].append("Medical diagnosis without proper consent")
                validation_result["valid"] = False
        
        if "treatment_plan" in document_data:
            if not self._validate_treatment_consent(document_data):
                validation_result["errors"].append("Treatment plan without proper consent")
                validation_result["valid"] = False
        
        return validation_result
    
    def get_required_fields(self) -> Set[str]:
        """Get required fields for HIPAA compliance."""
        return {
            "patient_consent",
            "privacy_notice",
            "authorization_form",
            "minimum_necessary_standard"
        }
    
    def get_prohibited_fields(self) -> Set[str]:
        """Get prohibited fields under HIPAA."""
        return {
            "unnecessary_phi",
            "genetic_information",
            "psychotherapy_notes",
            "substance_abuse_records"
        }
    
    def _validate_diagnosis_consent(self, document_data: Dict[str, Any]) -> bool:
        """Validate that medical diagnosis has proper consent."""
        consent_fields = ["patient_consent", "authorization_form", "minimum_necessary"]
        return any(field in document_data for field in consent_fields)
    
    def _validate_treatment_consent(self, document_data: Dict[str, Any]) -> bool:
        """Validate that treatment plan has proper consent."""
        consent_fields = ["treatment_consent", "informed_consent", "authorization_form"]
        return any(field in document_data for field in consent_fields)
    
    def get_phi_categories(self) -> List[str]:
        """Get HIPAA PHI categories."""
        return [
            "patient_identifier",
            "medical_diagnosis",
            "treatment_information",
            "billing_information",
            "research_data"
        ]
    
    def is_phi_field(self, field_name: str) -> bool:
        """Check if a field contains PHI."""
        phi_keywords = [
            "patient", "medical", "health", "diagnosis", "treatment",
            "medication", "symptom", "condition", "prescription"
        ]
        return any(keyword in field_name.lower() for keyword in phi_keywords)
    
    def get_minimum_necessary_standard(self) -> Dict[str, Any]:
        """Get minimum necessary standard requirements."""
        return {
            "description": "Only the minimum PHI necessary should be used or disclosed",
            "criteria": [
                "Limited to what is needed for the intended purpose",
                "No unnecessary PHI should be included",
                "Regular review of PHI usage",
                "Documentation of PHI access and use"
            ],
            "exceptions": [
                "Treatment purposes",
                "Required by law",
                "Patient authorization",
                "Public health activities"
            ]
        }
    
    def get_breach_notification_requirements(self) -> Dict[str, Any]:
        """Get breach notification requirements."""
        return {
            "timeline": "Within 60 days of discovery",
            "notification_methods": [
                "Individual notification",
                "Media notification (if >500 affected)",
                "HHS Secretary notification",
                "Business associate notification"
            ],
            "documentation": [
                "Breach description",
                "Types of PHI involved",
                "Steps taken to mitigate harm",
                "Corrective actions taken"
            ]
        }
