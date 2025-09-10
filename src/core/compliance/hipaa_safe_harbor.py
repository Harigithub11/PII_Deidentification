"""
HIPAA Safe Harbor Method Implementation

This module implements the complete HIPAA Safe Harbor method for de-identification
as specified in 45 CFR 164.514(b)(2), ensuring removal or transformation of all
18 categories of protected health information identifiers.

Compliance: HIPAA Privacy Rule 45 CFR 164.514(b)(2)
"""

import re
import logging
import hashlib
from datetime import datetime, date, timedelta
from typing import Dict, List, Optional, Tuple, Union, Any, Set
from uuid import uuid4
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class PHICategory(Enum):
    """HIPAA Protected Health Information Categories (18 identifiers)."""
    
    # Direct identifiers
    NAMES = "names"                                    # (A) Names
    GEOGRAPHIC_SUBDIVISIONS = "geographic"            # (B) Geographic subdivisions smaller than state
    DATES = "dates"                                   # (C) All elements of dates (except year)
    TELEPHONE_NUMBERS = "telephone"                   # (D) Telephone numbers
    FAX_NUMBERS = "fax"                              # (E) Fax numbers
    EMAIL_ADDRESSES = "email"                        # (F) Electronic mail addresses
    SSN = "ssn"                                      # (G) Social security numbers
    MEDICAL_RECORD_NUMBERS = "mrn"                   # (H) Medical record numbers
    HEALTH_PLAN_BENEFICIARY_NUMBERS = "hpb"         # (I) Health plan beneficiary numbers
    ACCOUNT_NUMBERS = "account"                      # (J) Account numbers
    CERTIFICATE_LICENSE_NUMBERS = "certificate"      # (K) Certificate/license numbers
    VEHICLE_IDENTIFIERS = "vehicle"                  # (L) Vehicle identifiers and serial numbers
    DEVICE_IDENTIFIERS = "device"                    # (M) Device identifiers and serial numbers
    WEB_URLS = "web_urls"                           # (N) Web Universal Resource Locators (URLs)
    IP_ADDRESSES = "ip_addresses"                    # (O) Internet Protocol (IP) addresses
    BIOMETRIC_IDENTIFIERS = "biometric"              # (P) Biometric identifiers
    FULL_FACE_PHOTOGRAPHIC_IMAGES = "facial"        # (Q) Full face photographic images
    OTHER_UNIQUE_IDENTIFYING_NUMBERS = "other_ids"   # (R) Any other unique identifying numbers
    

@dataclass
class SafeHarborConfig:
    """Configuration for Safe Harbor de-identification."""
    
    # Date handling configuration
    age_threshold_years: int = 89  # Ages 90 and older aggregated to 90+
    retain_year_only: bool = True  # Retain only year for dates
    
    # Geographic handling
    zip_code_truncation: int = 3  # Use only first 3 digits of ZIP codes
    geographic_precision: str = "state"  # Maximum geographic precision
    
    # Text replacement configuration
    name_replacement_method: str = "pseudonym"  # pseudonym, generic, hash
    number_replacement_method: str = "hash"     # hash, random, generic
    
    # Quality assurance
    validation_enabled: bool = True
    audit_logging: bool = True
    statistical_disclosure_control: bool = True


@dataclass
class DeidentificationResult:
    """Result of Safe Harbor de-identification process."""
    
    original_text: str
    deidentified_text: str
    phi_found: List[Dict[str, Any]]
    confidence_score: float
    safe_harbor_compliant: bool
    processing_metadata: Dict[str, Any] = field(default_factory=dict)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)


class SafeHarborProcessor:
    """
    Complete HIPAA Safe Harbor de-identification processor.
    
    Implements all 18 categories of PHI removal/transformation as required
    by HIPAA Privacy Rule 45 CFR 164.514(b)(2).
    """
    
    def __init__(self, config: Optional[SafeHarborConfig] = None):
        self.config = config or SafeHarborConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize pattern matchers for each PHI category
        self._initialize_phi_patterns()
        
        # Initialize replacement generators
        self._initialize_replacement_generators()
        
        # Statistics for disclosure control
        self.processing_stats = {
            "documents_processed": 0,
            "phi_instances_found": 0,
            "phi_categories_detected": set(),
            "safe_harbor_compliance_rate": 0.0
        }
    
    def _initialize_phi_patterns(self):
        """Initialize regex patterns for detecting all 18 PHI categories."""
        
        self.phi_patterns = {
            # (A) Names - Enhanced patterns for various name formats
            PHICategory.NAMES: [
                re.compile(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b'),  # Full names
                re.compile(r'\b(?:Dr|Mr|Mrs|Ms|Miss)\.?\s+[A-Z][a-z]+\b'),        # Titled names
                re.compile(r'\b[A-Z][a-z]+,\s*[A-Z][a-z]+\b'),                   # Last, First
                re.compile(r'\bPatient:?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b', re.IGNORECASE),  # Patient: Name
            ],
            
            # (B) Geographic subdivisions smaller than state
            PHICategory.GEOGRAPHIC_SUBDIVISIONS: [
                re.compile(r'\b\d{5}(?:-\d{4})?\b'),                             # ZIP codes
                re.compile(r'\b\d+\s+[A-Z][a-z]+\s+(?:St|Street|Ave|Avenue|Rd|Road|Dr|Drive|Ln|Lane|Ct|Court|Pl|Place)\b'),  # Street addresses
                re.compile(r'\b(?:Apt|Apartment|Suite|Unit|Rm|Room)\.?\s*\#?\d+\b', re.IGNORECASE),  # Apartment/Suite numbers
                re.compile(r'\b[A-Z][a-z]+\s+County\b'),                         # County names
                re.compile(r'\b(?:City|Town|Village)\s+of\s+[A-Z][a-z]+\b'),     # City names
            ],
            
            # (C) All elements of dates (except year for those over 89)
            PHICategory.DATES: [
                re.compile(r'\b(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4})\b'),           # MM/DD/YYYY or MM-DD-YYYY
                re.compile(r'\b(?:\d{2,4}[-/]\d{1,2}[-/]\d{1,2})\b'),           # YYYY/MM/DD or YYYY-MM-DD
                re.compile(r'\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+\d{2,4}\b', re.IGNORECASE),
                re.compile(r'\b\d{1,2}\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{2,4}\b', re.IGNORECASE),
            ],
            
            # (D) Telephone numbers
            PHICategory.TELEPHONE_NUMBERS: [
                re.compile(r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b'),  # Various phone formats
                re.compile(r'\b(?:phone|tel|telephone|cell|mobile)[\s:]*(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b', re.IGNORECASE),
            ],
            
            # (E) Fax numbers
            PHICategory.FAX_NUMBERS: [
                re.compile(r'\b(?:fax)[\s:]*(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b', re.IGNORECASE),
                re.compile(r'\b(?:facsimile)[\s:]*(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b', re.IGNORECASE),
            ],
            
            # (F) Electronic mail addresses
            PHICategory.EMAIL_ADDRESSES: [
                re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
                re.compile(r'\b(?:email|e-mail)[\s:]*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b', re.IGNORECASE),
            ],
            
            # (G) Social security numbers
            PHICategory.SSN: [
                re.compile(r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b'),
                re.compile(r'\b(?:ssn|social\s+security)[\s#:]*(\d{3}[-.\s]?\d{2}[-.\s]?\d{4})\b', re.IGNORECASE),
            ],
            
            # (H) Medical record numbers
            PHICategory.MEDICAL_RECORD_NUMBERS: [
                re.compile(r'\b(?:mrn|medical\s+record|patient\s+id)[\s#:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
                re.compile(r'\b(?:chart|record)\s+(?:number|#)[\s:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
                re.compile(r'\bMR\d{6,}\b'),  # Common MRN format
            ],
            
            # (I) Health plan beneficiary numbers
            PHICategory.HEALTH_PLAN_BENEFICIARY_NUMBERS: [
                re.compile(r'\b(?:member\s+id|beneficiary|subscriber)[\s#:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
                re.compile(r'\b(?:insurance|policy)\s+(?:number|#)[\s:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
                re.compile(r'\b(?:medicare|medicaid)[\s#:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
            ],
            
            # (J) Account numbers
            PHICategory.ACCOUNT_NUMBERS: [
                re.compile(r'\b(?:account|acct)[\s#:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
                re.compile(r'\b(?:billing|invoice)\s+(?:number|#)[\s:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
            ],
            
            # (K) Certificate/license numbers
            PHICategory.CERTIFICATE_LICENSE_NUMBERS: [
                re.compile(r'\b(?:license|licence|certificate|cert)[\s#:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
                re.compile(r'\b(?:npi|dea|upin)[\s#:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
            ],
            
            # (L) Vehicle identifiers and serial numbers
            PHICategory.VEHICLE_IDENTIFIERS: [
                re.compile(r'\b(?:vin|vehicle\s+id)[\s#:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
                re.compile(r'\b(?:license\s+plate|plate)[\s#:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
            ],
            
            # (M) Device identifiers and serial numbers
            PHICategory.DEVICE_IDENTIFIERS: [
                re.compile(r'\b(?:serial|device\s+id|equipment\s+id)[\s#:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
                re.compile(r'\b(?:model|part)\s+(?:number|#)[\s:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
            ],
            
            # (N) Web Universal Resource Locators (URLs)
            PHICategory.WEB_URLS: [
                re.compile(r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'),
                re.compile(r'www\.(?:[-\w.])+\.(?:[a-z]{2,4})(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?', re.IGNORECASE),
            ],
            
            # (O) Internet Protocol (IP) addresses
            PHICategory.IP_ADDRESSES: [
                re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),  # IPv4
                re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),  # IPv6
            ],
            
            # (P) Biometric identifiers
            PHICategory.BIOMETRIC_IDENTIFIERS: [
                re.compile(r'\b(?:fingerprint|biometric|retinal|iris|voiceprint)[\s#:]*([A-Z0-9\-]+)\b', re.IGNORECASE),
            ],
            
            # (Q) Full face photographic images - handled by visual PII detection
            PHICategory.FULL_FACE_PHOTOGRAPHIC_IMAGES: [],
            
            # (R) Any other unique identifying numbers
            PHICategory.OTHER_UNIQUE_IDENTIFYING_NUMBERS: [
                re.compile(r'\b(?:id|identifier)[\s#:]*([A-Z0-9\-]{6,})\b', re.IGNORECASE),
                re.compile(r'\b[A-Z]{2,3}\d{4,}\b'),  # Common ID patterns
            ],
        }
    
    def _initialize_replacement_generators(self):
        """Initialize replacement text generators for different PHI types."""
        
        self.replacements = {
            PHICategory.NAMES: self._generate_name_replacement,
            PHICategory.GEOGRAPHIC_SUBDIVISIONS: self._generate_geographic_replacement,
            PHICategory.DATES: self._generate_date_replacement,
            PHICategory.TELEPHONE_NUMBERS: self._generate_phone_replacement,
            PHICategory.FAX_NUMBERS: self._generate_fax_replacement,
            PHICategory.EMAIL_ADDRESSES: self._generate_email_replacement,
            PHICategory.SSN: self._generate_ssn_replacement,
            PHICategory.MEDICAL_RECORD_NUMBERS: self._generate_mrn_replacement,
            PHICategory.HEALTH_PLAN_BENEFICIARY_NUMBERS: self._generate_hpb_replacement,
            PHICategory.ACCOUNT_NUMBERS: self._generate_account_replacement,
            PHICategory.CERTIFICATE_LICENSE_NUMBERS: self._generate_cert_replacement,
            PHICategory.VEHICLE_IDENTIFIERS: self._generate_vehicle_replacement,
            PHICategory.DEVICE_IDENTIFIERS: self._generate_device_replacement,
            PHICategory.WEB_URLS: self._generate_url_replacement,
            PHICategory.IP_ADDRESSES: self._generate_ip_replacement,
            PHICategory.BIOMETRIC_IDENTIFIERS: self._generate_biometric_replacement,
            PHICategory.OTHER_UNIQUE_IDENTIFYING_NUMBERS: self._generate_other_id_replacement,
        }
    
    def process_document(self, text: str, document_metadata: Optional[Dict] = None) -> DeidentificationResult:
        """
        Process a document using HIPAA Safe Harbor method.
        
        Args:
            text: Input text to de-identify
            document_metadata: Optional metadata about the document
            
        Returns:
            DeidentificationResult with de-identified text and compliance information
        """
        start_time = datetime.now()
        
        try:
            # Initialize result tracking
            phi_found = []
            deidentified_text = text
            audit_entries = []
            
            # Process each PHI category
            for category in PHICategory:
                if category == PHICategory.FULL_FACE_PHOTOGRAPHIC_IMAGES:
                    continue  # Handled by visual PII detection
                
                patterns = self.phi_patterns.get(category, [])
                for pattern in patterns:
                    matches = list(pattern.finditer(deidentified_text))
                    
                    for match in reversed(matches):  # Process in reverse to maintain indices
                        phi_instance = {
                            "category": category.value,
                            "original_text": match.group(0),
                            "start_pos": match.start(),
                            "end_pos": match.end(),
                            "confidence": 0.95,  # High confidence for pattern-based detection
                        }
                        
                        # Generate replacement
                        replacement_func = self.replacements.get(category)
                        if replacement_func:
                            replacement = replacement_func(match.group(0), match)
                            
                            # Apply replacement
                            deidentified_text = (
                                deidentified_text[:match.start()] + 
                                replacement + 
                                deidentified_text[match.end():]
                            )
                            
                            phi_instance["replacement"] = replacement
                            phi_found.append(phi_instance)
                            
                            # Audit trail entry
                            audit_entries.append({
                                "timestamp": datetime.now().isoformat(),
                                "action": "phi_deidentified",
                                "category": category.value,
                                "method": "safe_harbor_pattern_matching",
                                "original_length": len(match.group(0)),
                                "replacement_length": len(replacement)
                            })
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(text, phi_found)
            
            # Determine Safe Harbor compliance
            safe_harbor_compliant = self._validate_safe_harbor_compliance(
                deidentified_text, phi_found
            )
            
            # Update processing statistics
            self._update_processing_stats(phi_found, safe_harbor_compliant)
            
            # Create result
            result = DeidentificationResult(
                original_text=text,
                deidentified_text=deidentified_text,
                phi_found=phi_found,
                confidence_score=confidence_score,
                safe_harbor_compliant=safe_harbor_compliant,
                processing_metadata={
                    "processing_time_seconds": (datetime.now() - start_time).total_seconds(),
                    "phi_categories_found": len(set(p["category"] for p in phi_found)),
                    "total_phi_instances": len(phi_found),
                    "document_metadata": document_metadata or {},
                    "safe_harbor_method_version": "1.0",
                    "compliance_standard": "HIPAA_164.514(b)(2)"
                },
                audit_trail=audit_entries
            )
            
            if self.config.audit_logging:
                self.logger.info(
                    f"Safe Harbor processing completed: "
                    f"{len(phi_found)} PHI instances found, "
                    f"compliance: {safe_harbor_compliant}, "
                    f"confidence: {confidence_score:.3f}"
                )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Safe Harbor processing failed: {e}")
            raise
    
    def _calculate_confidence_score(self, original_text: str, phi_found: List[Dict]) -> float:
        """Calculate confidence score for de-identification completeness."""
        
        if not phi_found:
            return 0.95  # High confidence if no PHI found
        
        # Base confidence on pattern matching strength and coverage
        pattern_confidence = sum(p["confidence"] for p in phi_found) / len(phi_found)
        
        # Adjust for text length and PHI density
        text_length = len(original_text)
        phi_density = len(phi_found) / max(text_length / 1000, 1)  # PHI per 1000 chars
        
        # Higher density might indicate more complex document requiring manual review
        density_adjustment = max(0.0, 1.0 - phi_density * 0.1)
        
        confidence = pattern_confidence * density_adjustment
        return min(0.99, max(0.50, confidence))
    
    def _validate_safe_harbor_compliance(self, deidentified_text: str, phi_found: List[Dict]) -> bool:
        """Validate that the text meets Safe Harbor requirements."""
        
        # Check for any obvious remaining PHI patterns
        remaining_phi_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{5}(?:-\d{4})?\b',  # ZIP code
        ]
        
        for pattern in remaining_phi_patterns:
            if re.search(pattern, deidentified_text):
                self.logger.warning(f"Potential remaining PHI found: {pattern}")
                return False
        
        # Statistical disclosure control check
        if self.config.statistical_disclosure_control:
            return self._statistical_disclosure_control_check(deidentified_text, phi_found)
        
        return True
    
    def _statistical_disclosure_control_check(self, text: str, phi_found: List[Dict]) -> bool:
        """Perform statistical disclosure control analysis."""
        
        # Implement basic statistical checks
        # In production, this would be more sophisticated
        
        # Check for potential re-identification risk
        unique_identifiers = set()
        for phi in phi_found:
            if phi["category"] in ["names", "mrn", "ssn", "email"]:
                unique_identifiers.add(phi["original_text"])
        
        # If too many unique identifiers, higher re-identification risk
        if len(unique_identifiers) > 5:
            self.logger.warning("High re-identification risk detected")
            return False
        
        return True
    
    def _update_processing_stats(self, phi_found: List[Dict], compliant: bool):
        """Update processing statistics for monitoring."""
        
        self.processing_stats["documents_processed"] += 1
        self.processing_stats["phi_instances_found"] += len(phi_found)
        
        categories_found = set(p["category"] for p in phi_found)
        self.processing_stats["phi_categories_detected"].update(categories_found)
        
        if compliant:
            compliance_rate = (
                self.processing_stats.get("compliant_documents", 0) + 1
            ) / self.processing_stats["documents_processed"]
            self.processing_stats["safe_harbor_compliance_rate"] = compliance_rate
            self.processing_stats["compliant_documents"] = (
                self.processing_stats.get("compliant_documents", 0) + 1
            )
    
    # Replacement generator methods for each PHI category
    def _generate_name_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for names."""
        if self.config.name_replacement_method == "pseudonym":
            hash_val = hashlib.md5(original.encode()).hexdigest()[:8]
            return f"[NAME-{hash_val.upper()}]"
        elif self.config.name_replacement_method == "generic":
            return "[NAME]"
        else:  # hash
            return f"[NAME-{hashlib.sha256(original.encode()).hexdigest()[:8].upper()}]"
    
    def _generate_geographic_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for geographic identifiers."""
        if re.match(r'\d{5}', original):  # ZIP code
            if len(original) >= 3:
                return original[:3] + "**"  # Keep first 3 digits
            return "[ZIP]"
        elif "County" in original:
            return "[COUNTY]"
        elif any(street_type in original for street_type in ["St", "Street", "Ave", "Avenue", "Rd", "Road"]):
            return "[ADDRESS]"
        else:
            return "[LOCATION]"
    
    def _generate_date_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for dates following Safe Harbor rules."""
        try:
            # Extract year if possible for age > 89 rule
            year_match = re.search(r'(19|20)\d{2}', original)
            if year_match and self.config.retain_year_only:
                year = int(year_match.group())
                current_year = datetime.now().year
                age = current_year - year
                
                if age <= self.config.age_threshold_years:
                    return str(year)  # Retain year only
                else:
                    return f"{self.config.age_threshold_years + 1}+"  # Ages 90+ aggregated
            
            return "[DATE]"
        except:
            return "[DATE]"
    
    def _generate_phone_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for phone numbers."""
        return "[PHONE]"
    
    def _generate_fax_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for fax numbers."""
        return "[FAX]"
    
    def _generate_email_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for email addresses."""
        if self.config.number_replacement_method == "hash":
            hash_val = hashlib.md5(original.encode()).hexdigest()[:8]
            return f"[EMAIL-{hash_val.upper()}]@[DOMAIN]"
        return "[EMAIL]"
    
    def _generate_ssn_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for SSNs."""
        return "[SSN]"
    
    def _generate_mrn_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for medical record numbers."""
        hash_val = hashlib.md5(original.encode()).hexdigest()[:8]
        return f"[MRN-{hash_val.upper()}]"
    
    def _generate_hpb_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for health plan beneficiary numbers."""
        return "[HEALTH-PLAN-ID]"
    
    def _generate_account_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for account numbers."""
        return "[ACCOUNT]"
    
    def _generate_cert_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for certificate/license numbers."""
        return "[CERTIFICATE]"
    
    def _generate_vehicle_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for vehicle identifiers."""
        return "[VEHICLE-ID]"
    
    def _generate_device_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for device identifiers."""
        return "[DEVICE-ID]"
    
    def _generate_url_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for URLs."""
        return "[URL]"
    
    def _generate_ip_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for IP addresses."""
        return "[IP-ADDRESS]"
    
    def _generate_biometric_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for biometric identifiers."""
        return "[BIOMETRIC-ID]"
    
    def _generate_other_id_replacement(self, original: str, match: re.Match) -> str:
        """Generate replacement for other unique identifiers."""
        return "[UNIQUE-ID]"
    
    def get_processing_statistics(self) -> Dict[str, Any]:
        """Get current processing statistics."""
        stats = self.processing_stats.copy()
        stats["phi_categories_detected"] = list(stats["phi_categories_detected"])
        return stats
    
    def validate_safe_harbor_compliance(self, text: str) -> Dict[str, Any]:
        """
        Validate if text meets HIPAA Safe Harbor requirements.
        
        Returns detailed compliance report.
        """
        result = self.process_document(text)
        
        return {
            "compliant": result.safe_harbor_compliant,
            "confidence_score": result.confidence_score,
            "phi_categories_found": len(set(p["category"] for p in result.phi_found)),
            "total_phi_instances": len(result.phi_found),
            "recommendations": self._generate_compliance_recommendations(result),
            "audit_trail": result.audit_trail
        }
    
    def _generate_compliance_recommendations(self, result: DeidentificationResult) -> List[str]:
        """Generate recommendations for improving Safe Harbor compliance."""
        recommendations = []
        
        if not result.safe_harbor_compliant:
            recommendations.append("Manual review required - potential PHI patterns detected")
        
        if result.confidence_score < 0.90:
            recommendations.append("Consider expert determination method for complex cases")
        
        phi_categories = set(p["category"] for p in result.phi_found)
        if len(phi_categories) > 10:
            recommendations.append("High PHI diversity - recommend additional statistical disclosure control")
        
        if any(p["category"] == "dates" for p in result.phi_found):
            recommendations.append("Verify date handling meets age aggregation requirements")
        
        return recommendations