"""
Pseudonymization and Generalization Service

This module provides advanced anonymization techniques including consistent pseudonymization,
data generalization, and format-preserving transformations for PII de-identification.
"""

import logging
import hashlib
import secrets
import uuid
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import re

from ..config.policies.base import PIIType
from ..config.settings import get_settings
from ..security.encryption import encryption_manager

logger = logging.getLogger(__name__)
settings = get_settings()


class PseudonymizationMethod(str, Enum):
    """Methods for generating pseudonyms."""
    CONSISTENT_HASH = "consistent_hash"
    DETERMINISTIC_MAPPING = "deterministic_mapping"
    FORMAT_PRESERVING = "format_preserving"
    SYNTHETIC_DATA = "synthetic_data"
    STATISTICAL_REPLACEMENT = "statistical_replacement"


class GeneralizationLevel(str, Enum):
    """Levels of data generalization."""
    MINIMAL = "minimal"        # Minor generalization
    MODERATE = "moderate"      # Standard generalization
    HIGH = "high"             # Strong generalization
    MAXIMUM = "maximum"       # Full category replacement


@dataclass
class PseudonymizationConfig:
    """Configuration for pseudonymization operations."""
    method: PseudonymizationMethod = PseudonymizationMethod.CONSISTENT_HASH
    preserve_format: bool = True
    preserve_length: bool = True
    consistency_key: Optional[str] = None
    domain_specific: bool = True
    quality_level: str = "high"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GeneralizationConfig:
    """Configuration for generalization operations."""
    level: GeneralizationLevel = GeneralizationLevel.MODERATE
    preserve_utility: bool = True
    custom_categories: Optional[Dict[str, List[str]]] = None
    statistical_accuracy: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnonymizationResult:
    """Result of anonymization operation."""
    success: bool
    original_value: str
    anonymized_value: str
    method_used: str
    quality_score: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


class PseudonymDataGenerator:
    """Generator for realistic pseudonymized data."""
    
    def __init__(self):
        self.fake_names = [
            "Alex Johnson", "Taylor Smith", "Morgan Davis", "Casey Brown", "Jordan Wilson",
            "Riley Chen", "Avery Martinez", "Blake Anderson", "Cameron White", "Drew Garcia",
            "Emery Rodriguez", "Finley Thompson", "Harper Lee", "Indigo Kim", "Jules Park"
        ]
        
        self.fake_companies = [
            "Tech Solutions Inc", "Global Systems Ltd", "Innovation Corp", "Digital Works",
            "Advanced Technologies", "Modern Enterprises", "Future Systems", "Prime Solutions"
        ]
        
        self.fake_domains = [
            "example.com", "testmail.org", "sample.net", "demo.co", "placeholder.info"
        ]
        
        self.street_names = [
            "Main St", "Oak Ave", "Park Rd", "First St", "Elm Dr", "Cedar Ln", "Pine Way"
        ]
        
        self.cities = [
            "Springfield", "Franklin", "Georgetown", "Madison", "Clayton", "Monroe", "Jackson"
        ]
        
        self.states = [
            "CA", "NY", "TX", "FL", "IL", "PA", "OH", "MI", "NC", "GA"
        ]
        
        logger.debug("Initialized PseudonymDataGenerator")
    
    def generate_name(self, seed: str) -> str:
        """Generate consistent fake name."""
        hash_val = self._hash_seed(seed)
        return self.fake_names[hash_val % len(self.fake_names)]
    
    def generate_email(self, seed: str, preserve_domain: bool = False) -> str:
        """Generate fake email address."""
        hash_val = self._hash_seed(seed)
        
        if preserve_domain:
            # Try to extract and preserve original domain
            original_parts = seed.split('@')
            if len(original_parts) == 2:
                domain = original_parts[1]
            else:
                domain = self.fake_domains[hash_val % len(self.fake_domains)]
        else:
            domain = self.fake_domains[hash_val % len(self.fake_domains)]
        
        username = f"user{hash_val % 10000:04d}"
        return f"{username}@{domain}"
    
    def generate_phone(self, seed: str, preserve_format: bool = True) -> str:
        """Generate fake phone number."""
        hash_val = self._hash_seed(seed)
        
        if preserve_format:
            # Generate with standard US format
            area_code = (hash_val % 800) + 200  # 200-999
            exchange = (hash_val % 800) + 200
            number = hash_val % 10000
            return f"({area_code:03d}) {exchange:03d}-{number:04d}"
        else:
            return f"{hash_val % 10**10:010d}"
    
    def generate_address(self, seed: str) -> str:
        """Generate fake address."""
        hash_val = self._hash_seed(seed)
        
        street_num = (hash_val % 9999) + 1
        street = self.street_names[hash_val % len(self.street_names)]
        city = self.cities[(hash_val >> 8) % len(self.cities)]
        state = self.states[(hash_val >> 16) % len(self.states)]
        zip_code = f"{(hash_val % 90000) + 10000:05d}"
        
        return f"{street_num} {street}, {city}, {state} {zip_code}"
    
    def generate_company(self, seed: str) -> str:
        """Generate fake company name."""
        hash_val = self._hash_seed(seed)
        return self.fake_companies[hash_val % len(self.fake_companies)]
    
    def generate_id_number(self, seed: str, format_pattern: str = "###-##-####") -> str:
        """Generate fake ID number with specified format."""
        hash_val = self._hash_seed(seed)
        
        result = ""
        digit_count = 0
        for char in format_pattern:
            if char == '#':
                result += str((hash_val >> digit_count) % 10)
                digit_count += 1
            else:
                result += char
        
        return result
    
    def _hash_seed(self, seed: str) -> int:
        """Generate deterministic hash from seed."""
        return int(hashlib.md5(seed.encode()).hexdigest(), 16)


class DataGeneralizer:
    """Service for data generalization operations."""
    
    def __init__(self):
        self.age_brackets = {
            GeneralizationLevel.MINIMAL: [(0, 17, "Under 18"), (18, 64, "18-64"), (65, 120, "65+")],
            GeneralizationLevel.MODERATE: [(0, 24, "Under 25"), (25, 54, "25-54"), (55, 120, "55+")],
            GeneralizationLevel.HIGH: [(0, 39, "Under 40"), (40, 120, "40+")],
            GeneralizationLevel.MAXIMUM: [(0, 120, "Adult")]
        }
        
        self.income_brackets = {
            GeneralizationLevel.MINIMAL: [
                (0, 30000, "Under $30K"), (30000, 60000, "$30K-$60K"),
                (60000, 100000, "$60K-$100K"), (100000, float('inf'), "Over $100K")
            ],
            GeneralizationLevel.MODERATE: [
                (0, 50000, "Under $50K"), (50000, 100000, "$50K-$100K"),
                (100000, float('inf'), "Over $100K")
            ],
            GeneralizationLevel.HIGH: [
                (0, 75000, "Below Median"), (75000, float('inf'), "Above Median")
            ],
            GeneralizationLevel.MAXIMUM: [
                (0, float('inf'), "Income Range")
            ]
        }
        
        logger.debug("Initialized DataGeneralizer")
    
    def generalize_age(self, age: Union[int, str], level: GeneralizationLevel) -> str:
        """Generalize age into brackets."""
        try:
            age_val = int(str(age).strip())
            brackets = self.age_brackets[level]
            
            for min_age, max_age, label in brackets:
                if min_age <= age_val <= max_age:
                    return label
            
            return "Age Group"
        
        except ValueError:
            return "Age Group"
    
    def generalize_income(self, income: Union[int, float, str], level: GeneralizationLevel) -> str:
        """Generalize income into brackets."""
        try:
            # Clean income string and convert to float
            income_str = str(income).replace('$', '').replace(',', '').strip()
            income_val = float(income_str)
            
            brackets = self.income_brackets[level]
            
            for min_income, max_income, label in brackets:
                if min_income <= income_val < max_income:
                    return label
            
            return "Income Range"
        
        except ValueError:
            return "Income Range"
    
    def generalize_date(self, date_str: str, level: GeneralizationLevel) -> str:
        """Generalize dates to broader time periods."""
        try:
            # Try to parse common date formats
            for fmt in ["%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y", "%Y"]:
                try:
                    date_obj = datetime.strptime(date_str, fmt)
                    break
                except ValueError:
                    continue
            else:
                return "Date Range"
            
            if level == GeneralizationLevel.MINIMAL:
                return f"{date_obj.year}-Q{(date_obj.month - 1) // 3 + 1}"
            elif level == GeneralizationLevel.MODERATE:
                return str(date_obj.year)
            elif level == GeneralizationLevel.HIGH:
                decade = (date_obj.year // 10) * 10
                return f"{decade}s"
            else:  # MAXIMUM
                century = ((date_obj.year - 1) // 100 + 1)
                return f"{century}th Century"
        
        except Exception:
            return "Date Range"
    
    def generalize_location(self, location: str, level: GeneralizationLevel) -> str:
        """Generalize location information."""
        if level == GeneralizationLevel.MINIMAL:
            # Remove street address, keep city/state
            parts = location.split(',')
            if len(parts) >= 2:
                return ', '.join(parts[1:]).strip()
            return "City Area"
        
        elif level == GeneralizationLevel.MODERATE:
            # Keep only state/province level
            parts = location.split(',')
            if len(parts) >= 3:
                return parts[-2].strip()  # Usually state
            return "State/Province"
        
        elif level == GeneralizationLevel.HIGH:
            return "Geographic Region"
        
        else:  # MAXIMUM
            return "Location"


class PseudonymizationService:
    """Main service for pseudonymization and generalization operations."""
    
    def __init__(self, consistency_key: Optional[str] = None):
        self.consistency_key = consistency_key or secrets.token_hex(32)
        self.pseudonym_generator = PseudonymDataGenerator()
        self.generalizer = DataGeneralizer()
        self.mapping_cache = {}
        
        logger.info("Initialized PseudonymizationService")
    
    def pseudonymize(
        self,
        value: str,
        pii_type: PIIType,
        config: Optional[PseudonymizationConfig] = None
    ) -> AnonymizationResult:
        """Pseudonymize a value based on its PII type."""
        if config is None:
            config = PseudonymizationConfig()
        
        try:
            # Create cache key for consistency
            cache_key = f"{pii_type.value}_{value}_{config.consistency_key or self.consistency_key}"
            
            if cache_key in self.mapping_cache:
                pseudonym = self.mapping_cache[cache_key]
            else:
                pseudonym = self._generate_pseudonym(value, pii_type, config)
                self.mapping_cache[cache_key] = pseudonym
            
            return AnonymizationResult(
                success=True,
                original_value=value,
                anonymized_value=pseudonym,
                method_used=f"pseudonymize_{config.method.value}",
                metadata={
                    "pii_type": pii_type.value,
                    "preserve_format": config.preserve_format,
                    "preserve_length": config.preserve_length
                }
            )
        
        except Exception as e:
            logger.error(f"Pseudonymization failed for {pii_type}: {e}")
            return AnonymizationResult(
                success=False,
                original_value=value,
                anonymized_value=value,
                method_used="pseudonymize_failed",
                error_message=str(e)
            )
    
    def generalize(
        self,
        value: str,
        pii_type: PIIType,
        config: Optional[GeneralizationConfig] = None
    ) -> AnonymizationResult:
        """Generalize a value into broader categories."""
        if config is None:
            config = GeneralizationConfig()
        
        try:
            generalized_value = self._apply_generalization(value, pii_type, config)
            
            return AnonymizationResult(
                success=True,
                original_value=value,
                anonymized_value=generalized_value,
                method_used=f"generalize_{config.level.value}",
                metadata={
                    "pii_type": pii_type.value,
                    "level": config.level.value,
                    "preserve_utility": config.preserve_utility
                }
            )
        
        except Exception as e:
            logger.error(f"Generalization failed for {pii_type}: {e}")
            return AnonymizationResult(
                success=False,
                original_value=value,
                anonymized_value=value,
                method_used="generalize_failed",
                error_message=str(e)
            )
    
    def _generate_pseudonym(
        self,
        value: str,
        pii_type: PIIType,
        config: PseudonymizationConfig
    ) -> str:
        """Generate appropriate pseudonym based on PII type."""
        seed = f"{value}_{config.consistency_key or self.consistency_key}"
        
        if pii_type == PIIType.NAME:
            return self.pseudonym_generator.generate_name(seed)
        
        elif pii_type == PIIType.EMAIL:
            return self.pseudonym_generator.generate_email(seed, config.preserve_format)
        
        elif pii_type == PIIType.PHONE:
            return self.pseudonym_generator.generate_phone(seed, config.preserve_format)
        
        elif pii_type == PIIType.ADDRESS:
            return self.pseudonym_generator.generate_address(seed)
        
        elif pii_type == PIIType.ORGANIZATION:
            return self.pseudonym_generator.generate_company(seed)
        
        elif pii_type in [PIIType.SSN, PIIType.NATIONAL_ID]:
            return self.pseudonym_generator.generate_id_number(seed, "###-##-####")
        
        elif pii_type == PIIType.CREDIT_CARD:
            return self.pseudonym_generator.generate_id_number(seed, "####-####-####-####")
        
        elif pii_type == PIIType.PASSPORT:
            return self.pseudonym_generator.generate_id_number(seed, "A########")
        
        elif pii_type == PIIType.DRIVER_LICENSE:
            return self.pseudonym_generator.generate_id_number(seed, "D########")
        
        else:
            # Generic pseudonymization using hash
            hash_val = self.pseudonym_generator._hash_seed(seed)
            
            if config.preserve_length:
                length = len(value)
                return f"PSEUDO{hash_val % (10**(length-6)):0{length-6}d}" if length > 6 else f"{hash_val % 1000:03d}"
            else:
                return f"PSEUDO_{hash_val % 100000:05d}"
    
    def _apply_generalization(
        self,
        value: str,
        pii_type: PIIType,
        config: GeneralizationConfig
    ) -> str:
        """Apply generalization based on PII type."""
        
        if pii_type == PIIType.AGE:
            return self.generalizer.generalize_age(value, config.level)
        
        elif pii_type == PIIType.INCOME:
            return self.generalizer.generalize_income(value, config.level)
        
        elif pii_type == PIIType.DATE_OF_BIRTH:
            return self.generalizer.generalize_date(value, config.level)
        
        elif pii_type == PIIType.ADDRESS:
            return self.generalizer.generalize_location(value, config.level)
        
        elif pii_type == PIIType.GENDER:
            if config.level == GeneralizationLevel.MAXIMUM:
                return "Person"
            else:
                return value  # Keep original for lower levels
        
        else:
            # Generic generalization
            if config.level == GeneralizationLevel.MINIMAL:
                return f"{pii_type.value.replace('_', ' ').title()} Category"
            elif config.level == GeneralizationLevel.MODERATE:
                return f"{pii_type.value.split('_')[0].title()} Type"
            elif config.level == GeneralizationLevel.HIGH:
                return "Sensitive Information"
            else:  # MAXIMUM
                return "Data"
    
    def get_mapping_stats(self) -> Dict[str, Any]:
        """Get statistics about mapping cache."""
        return {
            "total_mappings": len(self.mapping_cache),
            "cache_size_mb": len(str(self.mapping_cache)) / (1024 * 1024),
        }
    
    def clear_mapping_cache(self):
        """Clear the pseudonymization mapping cache."""
        self.mapping_cache.clear()
        logger.info("Cleared pseudonymization mapping cache")
    
    def export_mappings(self, file_path: Path, encrypted: bool = True) -> bool:
        """Export pseudonymization mappings to file."""
        try:
            data = {
                "consistency_key": self.consistency_key,
                "mappings": self.mapping_cache,
                "export_timestamp": datetime.utcnow().isoformat()
            }
            
            json_data = json.dumps(data, indent=2)
            
            if encrypted and encryption_manager:
                encrypted_data = encryption_manager.encrypt(json_data.encode())
                file_path.write_bytes(encrypted_data)
            else:
                file_path.write_text(json_data)
            
            logger.info(f"Exported {len(self.mapping_cache)} mappings to {file_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to export mappings: {e}")
            return False
    
    def import_mappings(self, file_path: Path, encrypted: bool = True) -> bool:
        """Import pseudonymization mappings from file."""
        try:
            if encrypted and encryption_manager:
                encrypted_data = file_path.read_bytes()
                json_data = encryption_manager.decrypt(encrypted_data).decode()
            else:
                json_data = file_path.read_text()
            
            data = json.loads(json_data)
            
            self.consistency_key = data.get("consistency_key", self.consistency_key)
            imported_mappings = data.get("mappings", {})
            
            self.mapping_cache.update(imported_mappings)
            
            logger.info(f"Imported {len(imported_mappings)} mappings from {file_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to import mappings: {e}")
            return False


# Global service instance
_default_pseudonymization_service = None

def get_pseudonymization_service() -> PseudonymizationService:
    """Get or create the default pseudonymization service instance."""
    global _default_pseudonymization_service
    
    if _default_pseudonymization_service is None:
        _default_pseudonymization_service = PseudonymizationService()
    
    return _default_pseudonymization_service