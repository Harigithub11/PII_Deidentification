"""
Base policy class for PII De-identification System

This module provides the foundation for all compliance policies.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Any
from enum import Enum
from pydantic import BaseModel, Field


class RedactionMethod(str, Enum):
    """Comprehensive redaction methods for text and visual PII."""
    
    # Text Redaction Methods
    DELETE = "delete"                    # Complete removal
    MASK_ASTERISK = "mask_asterisk"     # Replace with ***
    MASK_X = "mask_x"                   # Replace with XXX
    MASK_HASH = "mask_hash"             # Replace with ###
    REDACTED_LABEL = "redacted_label"   # Replace with [REDACTED]
    PLACEHOLDER = "placeholder"         # Replace with custom placeholder
    PARTIAL_MASK = "partial_mask"       # Show first/last chars, mask middle
    WHITESPACE = "whitespace"           # Replace with spaces
    
    # Advanced Text Methods
    PSEUDONYMIZE = "pseudonymize"       # Replace with consistent fake data
    GENERALIZE = "generalize"          # Replace with generalized category
    HASH = "hash"                      # Replace with hash value
    ENCRYPT = "encrypt"                # Replace with encrypted value
    
    # Visual Redaction Methods
    BLACKOUT = "blackout"              # Black solid fill
    WHITEOUT = "whiteout"              # White solid fill
    BLUR = "blur"                      # Standard blur
    GAUSSIAN_BLUR = "gaussian_blur"     # Gaussian blur
    PIXELATE = "pixelate"              # Pixelation effect
    MOSAIC = "mosaic"                  # Mosaic tiles
    SOLID_COLOR = "solid_color"        # Custom color fill
    
    # Advanced Visual Methods
    PATTERN_FILL = "pattern_fill"       # Pattern overlay
    DISTORT = "distort"                # Geometric distortion
    NOISE = "noise"                    # Random noise overlay
    INVERT = "invert"                  # Color inversion
    
    # Document-Specific Methods
    CROP_OUT = "crop_out"              # Remove region entirely
    MARGIN_NOTE = "margin_note"        # Add redaction note in margin


class PIIType(str, Enum):
    """Common PII types."""
    # Personal Information
    NAME = "name"
    ADDRESS = "address"
    PHONE = "phone"
    EMAIL = "email"
    DATE_OF_BIRTH = "date_of_birth"
    AGE = "age"
    GENDER = "gender"
    
    # Identification
    SSN = "ssn"
    PASSPORT = "passport"
    DRIVER_LICENSE = "driver_license"
    NATIONAL_ID = "national_id"
    AADHAR = "aadhar"
    PAN = "pan"
    
    # Financial
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT = "bank_account"
    ROUTING_NUMBER = "routing_number"
    IBAN = "iban"
    INCOME = "income"
    
    # Medical
    MEDICAL_RECORD = "medical_record"
    MEDICAL_LICENSE = "medical_license"
    DIAGNOSIS = "diagnosis"
    MEDICATION = "medication"
    TREATMENT = "treatment"
    
    # Technology & Digital
    IP_ADDRESS = "ip_address"
    URL = "url"
    CRYPTO_ADDRESS = "crypto_address"
    
    # Business & Organization
    ORGANIZATION = "organization"
    FINANCIAL = "financial"
    NUMBER = "number"
    
    # Other
    LOCATION = "location"
    SIGNATURE = "signature"
    PHOTO = "photo"


class PolicyRule(BaseModel):
    """Individual policy rule definition."""
    
    pii_type: PIIType
    redaction_method: RedactionMethod
    confidence_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    retention_period_days: Optional[int] = Field(default=None, ge=0)
    exceptions: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BasePolicy(ABC, BaseModel):
    """Base class for all compliance policies."""
    
    name: str
    description: str
    version: str = "1.0.0"
    compliance_standard: str
    effective_date: str
    
    # Policy Rules
    rules: List[PolicyRule] = Field(default_factory=list)
    
    # Redaction Settings
    default_redaction_method: RedactionMethod = RedactionMethod.BLACKOUT
    enable_audit_logging: bool = True
    require_approval: bool = False
    
    # Data Handling
    allow_pseudonymization: bool = True
    allow_generalization: bool = True
    max_retention_days: Optional[int] = None
    
    # Validation
    strict_mode: bool = False
    validation_required: bool = True
    
    class Config:
        use_enum_values = True
    
    @abstractmethod
    def validate_document(self, document_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate document against policy requirements."""
        pass
    
    @abstractmethod
    def get_required_fields(self) -> Set[str]:
        """Get required fields for this policy."""
        pass
    
    @abstractmethod
    def get_prohibited_fields(self) -> Set[str]:
        """Get prohibited fields for this policy."""
        pass
    
    def add_rule(self, rule: PolicyRule) -> None:
        """Add a new policy rule."""
        self.rules.append(rule)
    
    def remove_rule(self, pii_type: PIIType) -> bool:
        """Remove a policy rule by PII type."""
        initial_count = len(self.rules)
        self.rules = [rule for rule in self.rules if rule.pii_type != pii_type]
        return len(self.rules) < initial_count
    
    def get_rule(self, pii_type: PIIType) -> Optional[PolicyRule]:
        """Get a policy rule by PII type."""
        for rule in self.rules:
            if rule.pii_type == pii_type:
                return rule
        return None
    
    def get_redaction_method(self, pii_type: PIIType) -> RedactionMethod:
        """Get the redaction method for a specific PII type."""
        rule = self.get_rule(pii_type)
        if rule:
            return rule.redaction_method
        return self.default_redaction_method
    
    def is_pii_allowed(self, pii_type: PIIType, context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if a PII type is allowed in the given context."""
        rule = self.get_rule(pii_type)
        if not rule:
            return False
        
        # Check exceptions
        if context and rule.exceptions:
            for exception in rule.exceptions:
                if self._check_exception(exception, context):
                    return True
        
        return True
    
    def _check_exception(self, exception: str, context: Dict[str, Any]) -> bool:
        """Check if an exception applies to the given context."""
        # Simple exception checking - can be extended for complex logic
        if exception in context:
            return bool(context[exception])
        return False
    
    def get_retention_period(self, pii_type: PIIType) -> Optional[int]:
        """Get the retention period for a specific PII type."""
        rule = self.get_rule(pii_type)
        if rule and rule.retention_period_days:
            return rule.retention_period_days
        return self.max_retention_days
    
    def validate_policy(self) -> List[str]:
        """Validate the policy configuration and return any errors."""
        errors = []
        
        # Check for duplicate PII types
        pii_types = [rule.pii_type for rule in self.rules]
        if len(pii_types) != len(set(pii_types)):
            errors.append("Duplicate PII types found in rules")
        
        # Check confidence thresholds
        for rule in self.rules:
            if rule.confidence_threshold < 0 or rule.confidence_threshold > 1:
                errors.append(f"Invalid confidence threshold for {rule.pii_type}")
        
        # Check retention periods
        for rule in self.rules:
            if rule.retention_period_days and rule.retention_period_days < 0:
                errors.append(f"Invalid retention period for {rule.pii_type}")
        
        return errors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary representation."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "compliance_standard": self.compliance_standard,
            "effective_date": self.effective_date,
            "rules": [rule.dict() for rule in self.rules],
            "default_redaction_method": self.default_redaction_method,
            "enable_audit_logging": self.enable_audit_logging,
            "require_approval": self.require_approval,
            "allow_pseudonymization": self.allow_pseudonymization,
            "allow_generalization": self.allow_generalization,
            "max_retention_days": self.max_retention_days,
            "strict_mode": self.strict_mode,
            "validation_required": self.validation_required,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BasePolicy":
        """Create policy from dictionary representation."""
        # This is a simplified version - subclasses should implement their own logic
        return cls(**data)
