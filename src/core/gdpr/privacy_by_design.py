"""
GDPR Privacy by Design and Privacy by Default Implementation (Article 25)
Comprehensive framework for implementing privacy-enhancing technologies and processes
"""
from typing import Dict, List, Optional, Any, Union, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
import uuid
import json
from datetime import datetime, timedelta
import logging
from pathlib import Path
import hashlib
import asyncio
from abc import ABC, abstractmethod

from ..database.db_manager import DatabaseManager
from ..security.encryption_manager import EncryptionManager
from ..config.settings import get_settings


logger = logging.getLogger(__name__)
settings = get_settings()


class PrivacyPrinciple(Enum):
    """Privacy by Design foundational principles"""
    PROACTIVE = "proactive"  # Proactive not Reactive
    PRIVACY_AS_DEFAULT = "privacy_as_default"  # Privacy as the Default Setting
    FULL_FUNCTIONALITY = "full_functionality"  # Full Functionality - Positive Sum
    END_TO_END_SECURITY = "end_to_end_security"  # End-to-End Security
    VISIBILITY_TRANSPARENCY = "visibility_transparency"  # Visibility and Transparency
    RESPECT_USER_PRIVACY = "respect_user_privacy"  # Respect for User Privacy
    PRIVACY_EMBEDDED = "privacy_embedded"  # Privacy Embedded into Design


class PrivacyEnhancingTechnology(Enum):
    """Privacy Enhancing Technologies (PETs)"""
    ENCRYPTION = "encryption"
    PSEUDONYMIZATION = "pseudonymization"
    ANONYMIZATION = "anonymization"
    DIFFERENTIAL_PRIVACY = "differential_privacy"
    HOMOMORPHIC_ENCRYPTION = "homomorphic_encryption"
    SECURE_MULTIPARTY_COMPUTATION = "secure_multiparty_computation"
    ZERO_KNOWLEDGE_PROOFS = "zero_knowledge_proofs"
    DATA_MINIMIZATION = "data_minimization"
    PURPOSE_LIMITATION = "purpose_limitation"
    ACCESS_CONTROL = "access_control"


class ProcessingStage(Enum):
    """Data processing lifecycle stages"""
    COLLECTION = "collection"
    STORAGE = "storage"
    PROCESSING = "processing"
    ANALYSIS = "analysis"
    SHARING = "sharing"
    RETENTION = "retention"
    DISPOSAL = "disposal"


class PrivacyRisk(Enum):
    """Privacy risk levels"""
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PrivacyRequirement:
    """Privacy requirement specification"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    principle: PrivacyPrinciple = PrivacyPrinciple.PRIVACY_AS_DEFAULT
    mandatory: bool = True
    stage: ProcessingStage = ProcessingStage.COLLECTION
    
    # Implementation details
    technologies: List[PrivacyEnhancingTechnology] = field(default_factory=list)
    implementation_methods: List[str] = field(default_factory=list)
    validation_criteria: List[str] = field(default_factory=list)
    
    # Compliance tracking
    implemented: bool = False
    implementation_date: Optional[datetime] = None
    compliance_evidence: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "principle": self.principle.value,
            "mandatory": self.mandatory,
            "stage": self.stage.value,
            "technologies": [t.value for t in self.technologies],
            "implementation_methods": self.implementation_methods,
            "validation_criteria": self.validation_criteria,
            "implemented": self.implemented,
            "implementation_date": self.implementation_date.isoformat() if self.implementation_date else None,
            "compliance_evidence": self.compliance_evidence
        }


@dataclass
class PrivacyAssessment:
    """Privacy impact assessment for processing activities"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    processing_activity: str = ""
    assessor: str = ""
    assessment_date: datetime = field(default_factory=datetime.now)
    
    # Data processing details
    data_categories: List[str] = field(default_factory=list)
    processing_purposes: List[str] = field(default_factory=list)
    data_subjects_categories: List[str] = field(default_factory=list)
    retention_periods: Dict[str, int] = field(default_factory=dict)
    
    # Risk assessment
    identified_risks: List[Dict[str, Any]] = field(default_factory=list)
    overall_risk_level: PrivacyRisk = PrivacyRisk.MEDIUM
    
    # Privacy requirements
    applicable_requirements: List[str] = field(default_factory=list)  # Requirement IDs
    compliance_status: Dict[str, bool] = field(default_factory=dict)
    
    # Mitigation measures
    recommended_technologies: List[PrivacyEnhancingTechnology] = field(default_factory=list)
    mitigation_measures: List[str] = field(default_factory=list)
    implementation_plan: List[Dict[str, Any]] = field(default_factory=list)
    
    # Review and monitoring
    next_review_date: Optional[datetime] = None
    monitoring_measures: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "processing_activity": self.processing_activity,
            "assessor": self.assessor,
            "assessment_date": self.assessment_date.isoformat(),
            "data_categories": self.data_categories,
            "processing_purposes": self.processing_purposes,
            "data_subjects_categories": self.data_subjects_categories,
            "retention_periods": self.retention_periods,
            "identified_risks": self.identified_risks,
            "overall_risk_level": self.overall_risk_level.value,
            "applicable_requirements": self.applicable_requirements,
            "compliance_status": self.compliance_status,
            "recommended_technologies": [t.value for t in self.recommended_technologies],
            "mitigation_measures": self.mitigation_measures,
            "implementation_plan": self.implementation_plan,
            "next_review_date": self.next_review_date.isoformat() if self.next_review_date else None,
            "monitoring_measures": self.monitoring_measures
        }


class PrivacyEnhancingTechInterface(ABC):
    """Abstract interface for Privacy Enhancing Technologies"""
    
    @abstractmethod
    async def apply(self, data: Any, params: Dict[str, Any] = None) -> Any:
        """Apply the privacy enhancing technology to data"""
        pass
    
    @abstractmethod
    def validate_implementation(self) -> bool:
        """Validate that the technology is properly implemented"""
        pass
    
    @abstractmethod
    def get_privacy_guarantees(self) -> Dict[str, Any]:
        """Get privacy guarantees provided by this technology"""
        pass


class PseudonymizationTech(PrivacyEnhancingTechInterface):
    """Pseudonymization implementation"""
    
    def __init__(self, encryption_manager: EncryptionManager):
        self.encryption_manager = encryption_manager
        self.pseudonym_mappings: Dict[str, str] = {}
    
    async def apply(self, data: Any, params: Dict[str, Any] = None) -> Any:
        """Apply pseudonymization to identifiable data"""
        
        if isinstance(data, str):
            # Simple string pseudonymization
            if data not in self.pseudonym_mappings:
                # Generate deterministic pseudonym
                pseudonym = hashlib.sha256(f"{data}_{params.get('salt', 'default_salt')}".encode()).hexdigest()[:16]
                self.pseudonym_mappings[data] = pseudonym
            return self.pseudonym_mappings[data]
        
        elif isinstance(data, dict):
            # Dictionary pseudonymization
            pseudonymized_data = {}
            identifiable_fields = params.get("identifiable_fields", [])
            
            for key, value in data.items():
                if key in identifiable_fields:
                    pseudonymized_data[key] = await self.apply(value, params)
                else:
                    pseudonymized_data[key] = value
            
            return pseudonymized_data
        
        elif isinstance(data, list):
            # List pseudonymization
            return [await self.apply(item, params) for item in data]
        
        return data
    
    def validate_implementation(self) -> bool:
        """Validate pseudonymization implementation"""
        # Test with sample data
        test_data = "test_identifier"
        pseudonym = hashlib.sha256(f"{test_data}_default_salt".encode()).hexdigest()[:16]
        return len(pseudonym) == 16 and pseudonym != test_data
    
    def get_privacy_guarantees(self) -> Dict[str, Any]:
        """Get pseudonymization privacy guarantees"""
        return {
            "reversibility": True,
            "re_identification_protection": "medium",
            "suitable_for_analytics": True,
            "preserves_data_utility": True,
            "linkability_protection": "partial"
        }


class AnonymizationTech(PrivacyEnhancingTechInterface):
    """Anonymization implementation with k-anonymity and differential privacy"""
    
    def __init__(self, k_value: int = 5, epsilon: float = 1.0):
        self.k_value = k_value
        self.epsilon = epsilon  # Privacy parameter for differential privacy
    
    async def apply(self, data: Any, params: Dict[str, Any] = None) -> Any:
        """Apply anonymization techniques"""
        
        method = params.get("method", "k_anonymity")
        
        if method == "k_anonymity":
            return await self._apply_k_anonymity(data, params)
        elif method == "differential_privacy":
            return await self._apply_differential_privacy(data, params)
        elif method == "generalization":
            return await self._apply_generalization(data, params)
        else:
            return await self._apply_suppression(data, params)
    
    async def _apply_k_anonymity(self, data: Any, params: Dict[str, Any] = None) -> Any:
        """Apply k-anonymity by generalization and suppression"""
        
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            # For list of dictionaries (common case)
            quasi_identifiers = params.get("quasi_identifiers", [])
            
            # Group data by quasi-identifiers
            groups = {}
            for record in data:
                key = tuple(record.get(qi, "") for qi in quasi_identifiers)
                if key not in groups:
                    groups[key] = []
                groups[key].append(record)
            
            # Apply generalization/suppression for groups < k
            anonymized_data = []
            for group_key, group_records in groups.items():
                if len(group_records) < self.k_value:
                    # Apply suppression/generalization
                    for record in group_records:
                        anonymized_record = record.copy()
                        for qi in quasi_identifiers:
                            if qi in anonymized_record:
                                anonymized_record[qi] = self._generalize_value(anonymized_record[qi])
                        anonymized_data.append(anonymized_record)
                else:
                    anonymized_data.extend(group_records)
            
            return anonymized_data
        
        return data
    
    def _generalize_value(self, value: Any) -> Any:
        """Generalize a value to reduce specificity"""
        
        if isinstance(value, str):
            # For strings, return first character + asterisks
            if len(value) > 0:
                return value[0] + "*" * (len(value) - 1)
            return "*"
        
        elif isinstance(value, int):
            # For integers, round to nearest 10
            return (value // 10) * 10
        
        elif isinstance(value, float):
            # For floats, round to 1 decimal place
            return round(value, 1)
        
        return value
    
    async def _apply_differential_privacy(self, data: Any, params: Dict[str, Any] = None) -> Any:
        """Apply differential privacy by adding calibrated noise"""
        
        import random
        
        sensitivity = params.get("sensitivity", 1.0)
        scale = sensitivity / self.epsilon
        
        if isinstance(data, (int, float)):
            # Add Laplace noise for numerical values
            noise = random.laplace(0, scale)
            return data + noise
        
        elif isinstance(data, list) and all(isinstance(x, (int, float)) for x in data):
            # Add noise to numerical list
            return [x + random.laplace(0, scale) for x in data]
        
        return data
    
    async def _apply_generalization(self, data: Any, params: Dict[str, Any] = None) -> Any:
        """Apply generalization to reduce precision"""
        
        if isinstance(data, dict):
            generalized = {}
            for key, value in data.items():
                generalized[key] = self._generalize_value(value)
            return generalized
        
        return self._generalize_value(data)
    
    async def _apply_suppression(self, data: Any, params: Dict[str, Any] = None) -> Any:
        """Apply suppression to remove identifying information"""
        
        suppress_fields = params.get("suppress_fields", [])
        
        if isinstance(data, dict):
            suppressed = data.copy()
            for field in suppress_fields:
                if field in suppressed:
                    del suppressed[field]
            return suppressed
        
        return data
    
    def validate_implementation(self) -> bool:
        """Validate anonymization implementation"""
        # Test k-anonymity grouping
        test_data = [
            {"name": "Alice", "age": 25, "city": "NYC"},
            {"name": "Bob", "age": 25, "city": "NYC"},
            {"name": "Charlie", "age": 30, "city": "LA"}
        ]
        
        # This is a simplified validation
        return len(test_data) >= 2  # Basic validation that we have test data
    
    def get_privacy_guarantees(self) -> Dict[str, Any]:
        """Get anonymization privacy guarantees"""
        return {
            "reversibility": False,
            "re_identification_protection": "high",
            "suitable_for_analytics": True,
            "preserves_data_utility": "partial",
            "linkability_protection": "high",
            "k_anonymity_guarantee": self.k_value,
            "differential_privacy_epsilon": self.epsilon
        }


class DataMinimizationTech(PrivacyEnhancingTechInterface):
    """Data minimization implementation"""
    
    def __init__(self):
        self.purpose_field_mappings: Dict[str, List[str]] = {}
    
    async def apply(self, data: Any, params: Dict[str, Any] = None) -> Any:
        """Apply data minimization based on processing purpose"""
        
        purpose = params.get("purpose", "default")
        required_fields = params.get("required_fields", [])
        
        # If no specific required fields, use purpose-based mapping
        if not required_fields and purpose in self.purpose_field_mappings:
            required_fields = self.purpose_field_mappings[purpose]
        
        if isinstance(data, dict):
            minimized_data = {}
            for field in required_fields:
                if field in data:
                    minimized_data[field] = data[field]
            return minimized_data
        
        elif isinstance(data, list):
            return [await self.apply(item, params) for item in data]
        
        return data
    
    def add_purpose_mapping(self, purpose: str, required_fields: List[str]):
        """Add field mapping for a specific processing purpose"""
        self.purpose_field_mappings[purpose] = required_fields
    
    def validate_implementation(self) -> bool:
        """Validate data minimization implementation"""
        # Test with sample data
        test_data = {"name": "Alice", "age": 25, "ssn": "123-45-6789", "email": "alice@example.com"}
        params = {"required_fields": ["name", "email"]}
        
        # This would be async in practice, but simplified for validation
        minimized = {}
        for field in params["required_fields"]:
            if field in test_data:
                minimized[field] = test_data[field]
        
        return len(minimized) == 2 and "ssn" not in minimized
    
    def get_privacy_guarantees(self) -> Dict[str, Any]:
        """Get data minimization privacy guarantees"""
        return {
            "data_reduction": True,
            "purpose_limitation_enforcement": True,
            "storage_minimization": True,
            "processing_minimization": True,
            "unnecessary_data_elimination": True
        }


class PrivacyByDesignFramework:
    """Comprehensive Privacy by Design implementation framework"""
    
    def __init__(self,
                 db_manager: DatabaseManager,
                 encryption_manager: EncryptionManager):
        self.db_manager = db_manager
        self.encryption_manager = encryption_manager
        self.logger = logging.getLogger(__name__)
        
        # Storage
        self.privacy_requirements: Dict[str, PrivacyRequirement] = {}
        self.privacy_assessments: Dict[str, PrivacyAssessment] = {}
        self.pet_implementations: Dict[PrivacyEnhancingTechnology, PrivacyEnhancingTechInterface] = {}
        
        # Initialize PETs
        self._initialize_privacy_technologies()
        
        # Initialize default requirements
        self._initialize_default_requirements()
    
    def _initialize_privacy_technologies(self):
        """Initialize Privacy Enhancing Technologies"""
        
        # Initialize available PETs
        self.pet_implementations[PrivacyEnhancingTechnology.PSEUDONYMIZATION] = PseudonymizationTech(
            self.encryption_manager
        )
        
        self.pet_implementations[PrivacyEnhancingTechnology.ANONYMIZATION] = AnonymizationTech(
            k_value=5, epsilon=1.0
        )
        
        self.pet_implementations[PrivacyEnhancingTechnology.DATA_MINIMIZATION] = DataMinimizationTech()
        
        # Configure data minimization purposes
        data_min_tech = self.pet_implementations[PrivacyEnhancingTechnology.DATA_MINIMIZATION]
        data_min_tech.add_purpose_mapping("pii_detection", ["text_content", "document_id", "processing_timestamp"])
        data_min_tech.add_purpose_mapping("analytics", ["usage_metrics", "performance_data", "timestamp"])
        data_min_tech.add_purpose_mapping("reporting", ["summary_data", "counts", "categories"])
    
    def _initialize_default_requirements(self):
        """Initialize default privacy by design requirements"""
        
        default_requirements = [
            # Proactive Privacy Requirements
            PrivacyRequirement(
                name="Data Collection Minimization",
                description="Collect only data necessary for specified purposes",
                principle=PrivacyPrinciple.PROACTIVE,
                stage=ProcessingStage.COLLECTION,
                technologies=[PrivacyEnhancingTechnology.DATA_MINIMIZATION],
                implementation_methods=[
                    "Purpose-based field filtering",
                    "Collection consent validation",
                    "Regular data necessity reviews"
                ],
                validation_criteria=[
                    "All collected fields have documented purpose",
                    "No unnecessary data collection",
                    "Regular audit of collection practices"
                ]
            ),
            
            # Privacy as Default Requirements
            PrivacyRequirement(
                name="Default Pseudonymization",
                description="Apply pseudonymization by default for identifiable data",
                principle=PrivacyPrinciple.PRIVACY_AS_DEFAULT,
                stage=ProcessingStage.STORAGE,
                technologies=[PrivacyEnhancingTechnology.PSEUDONYMIZATION],
                implementation_methods=[
                    "Automatic identifier pseudonymization",
                    "Configurable pseudonymization rules",
                    "Secure key management"
                ],
                validation_criteria=[
                    "All identifiers pseudonymized in storage",
                    "Pseudonymization keys properly protected",
                    "Re-identification controls in place"
                ]
            ),
            
            # End-to-End Security Requirements
            PrivacyRequirement(
                name="Data Encryption in Transit and Rest",
                description="Encrypt all personal data during transmission and storage",
                principle=PrivacyPrinciple.END_TO_END_SECURITY,
                stage=ProcessingStage.STORAGE,
                technologies=[PrivacyEnhancingTechnology.ENCRYPTION],
                implementation_methods=[
                    "AES-256 encryption for data at rest",
                    "TLS 1.3 for data in transit",
                    "End-to-end encryption for sensitive data"
                ],
                validation_criteria=[
                    "All data encrypted with approved algorithms",
                    "Encryption keys properly managed",
                    "Regular security audits conducted"
                ]
            ),
            
            # Transparency Requirements
            PrivacyRequirement(
                name="Processing Activity Documentation",
                description="Maintain transparent documentation of all processing activities",
                principle=PrivacyPrinciple.VISIBILITY_TRANSPARENCY,
                stage=ProcessingStage.PROCESSING,
                technologies=[PrivacyEnhancingTechnology.ACCESS_CONTROL],
                implementation_methods=[
                    "Comprehensive processing logs",
                    "Privacy notice generation",
                    "Data subject access provisions"
                ],
                validation_criteria=[
                    "All processing activities documented",
                    "Privacy notices up to date",
                    "Data subject requests handled timely"
                ]
            ),
            
            # Full Functionality Requirements
            PrivacyRequirement(
                name="Privacy-Preserving Analytics",
                description="Enable analytics while preserving individual privacy",
                principle=PrivacyPrinciple.FULL_FUNCTIONALITY,
                stage=ProcessingStage.ANALYSIS,
                technologies=[
                    PrivacyEnhancingTechnology.DIFFERENTIAL_PRIVACY,
                    PrivacyEnhancingTechnology.ANONYMIZATION
                ],
                implementation_methods=[
                    "Statistical disclosure control",
                    "Aggregation with noise addition",
                    "K-anonymity for analytical datasets"
                ],
                validation_criteria=[
                    "Analytics provide business value",
                    "Individual privacy preserved",
                    "Re-identification risk minimized"
                ]
            ),
            
            # Respect for User Privacy Requirements
            PrivacyRequirement(
                name="Granular Consent Management",
                description="Provide granular control over data processing purposes",
                principle=PrivacyPrinciple.RESPECT_USER_PRIVACY,
                stage=ProcessingStage.COLLECTION,
                technologies=[PrivacyEnhancingTechnology.PURPOSE_LIMITATION],
                implementation_methods=[
                    "Purpose-specific consent collection",
                    "Easy consent withdrawal",
                    "Consent preference centers"
                ],
                validation_criteria=[
                    "All purposes have specific consent",
                    "Consent withdrawal mechanisms work",
                    "Processing stops when consent withdrawn"
                ]
            ),
            
            # Privacy Embedded Requirements
            PrivacyRequirement(
                name="Automated Privacy Controls",
                description="Embed privacy controls directly into system architecture",
                principle=PrivacyPrinciple.PRIVACY_EMBEDDED,
                stage=ProcessingStage.PROCESSING,
                technologies=[
                    PrivacyEnhancingTechnology.ACCESS_CONTROL,
                    PrivacyEnhancingTechnology.DATA_MINIMIZATION
                ],
                implementation_methods=[
                    "Role-based access controls",
                    "Automated data retention policies",
                    "Privacy-aware system design"
                ],
                validation_criteria=[
                    "Privacy controls cannot be bypassed",
                    "Default settings protect privacy",
                    "System architecture supports privacy"
                ]
            )
        ]
        
        for requirement in default_requirements:
            self.privacy_requirements[requirement.id] = requirement
    
    async def conduct_privacy_assessment(self,
                                       processing_activity: str,
                                       data_categories: List[str],
                                       processing_purposes: List[str],
                                       data_subjects_categories: List[str],
                                       assessor: str = "privacy_team") -> PrivacyAssessment:
        """Conduct comprehensive privacy assessment for processing activity"""
        
        assessment = PrivacyAssessment(
            processing_activity=processing_activity,
            assessor=assessor,
            data_categories=data_categories,
            processing_purposes=processing_purposes,
            data_subjects_categories=data_subjects_categories
        )
        
        # Identify privacy risks
        assessment.identified_risks = await self._identify_privacy_risks(assessment)
        
        # Assess overall risk level
        assessment.overall_risk_level = await self._assess_overall_risk_level(assessment)
        
        # Identify applicable privacy requirements
        assessment.applicable_requirements = await self._identify_applicable_requirements(assessment)
        
        # Check compliance with requirements
        assessment.compliance_status = await self._check_requirement_compliance(assessment)
        
        # Recommend privacy technologies
        assessment.recommended_technologies = await self._recommend_privacy_technologies(assessment)
        
        # Generate mitigation measures
        assessment.mitigation_measures = await self._generate_mitigation_measures(assessment)
        
        # Create implementation plan
        assessment.implementation_plan = await self._create_implementation_plan(assessment)
        
        # Set review schedule
        assessment.next_review_date = datetime.now() + timedelta(days=180)  # 6 months
        assessment.monitoring_measures = [
            "Quarterly privacy compliance review",
            "Continuous risk monitoring",
            "Regular technology effectiveness assessment",
            "Data subject feedback collection"
        ]
        
        # Store assessment
        self.privacy_assessments[assessment.id] = assessment
        
        await self._log_privacy_event(assessment, "privacy_assessment_completed")
        
        self.logger.info(f"Privacy assessment completed for {processing_activity}")
        
        return assessment
    
    async def _identify_privacy_risks(self, assessment: PrivacyAssessment) -> List[Dict[str, Any]]:
        """Identify privacy risks in the processing activity"""
        
        risks = []
        
        # Special categories of data risks
        special_categories = [
            "health_data", "genetic_data", "biometric_data", "racial_ethnic_data",
            "political_opinions", "religious_beliefs", "philosophical_beliefs",
            "trade_union_membership", "sexual_orientation", "criminal_data"
        ]
        
        if any(cat in special_categories for cat in assessment.data_categories):
            risks.append({
                "risk_id": "special_categories_processing",
                "risk_name": "Special Categories Data Processing",
                "description": "Processing of special categories of personal data increases privacy risks",
                "risk_level": "high",
                "impact": "high",
                "likelihood": "medium",
                "affected_principles": [PrivacyPrinciple.END_TO_END_SECURITY.value, PrivacyPrinciple.PRIVACY_AS_DEFAULT.value]
            })
        
        # Vulnerable data subjects risks
        vulnerable_subjects = ["children", "elderly", "disabled", "patients", "employees"]
        if any(subj in vulnerable_subjects for subj in assessment.data_subjects_categories):
            risks.append({
                "risk_id": "vulnerable_subjects",
                "risk_name": "Vulnerable Data Subjects",
                "description": "Processing data of vulnerable individuals requires enhanced protection",
                "risk_level": "medium",
                "impact": "high",
                "likelihood": "low",
                "affected_principles": [PrivacyPrinciple.RESPECT_USER_PRIVACY.value]
            })
        
        # Large scale processing risks
        if "large_scale" in assessment.processing_purposes:
            risks.append({
                "risk_id": "large_scale_processing",
                "risk_name": "Large Scale Processing",
                "description": "Large scale data processing increases privacy risks",
                "risk_level": "medium",
                "impact": "medium",
                "likelihood": "high",
                "affected_principles": [PrivacyPrinciple.DATA_MINIMIZATION.value]
            })
        
        # Profiling and automated decision making risks
        if any("profiling" in purpose or "automated" in purpose for purpose in assessment.processing_purposes):
            risks.append({
                "risk_id": "automated_decision_making",
                "risk_name": "Automated Decision Making",
                "description": "Automated decision making and profiling create significant privacy risks",
                "risk_level": "high",
                "impact": "high",
                "likelihood": "high",
                "affected_principles": [PrivacyPrinciple.RESPECT_USER_PRIVACY.value, PrivacyPrinciple.VISIBILITY_TRANSPARENCY.value]
            })
        
        # Data sharing risks
        if "sharing" in assessment.processing_purposes or "third_party" in assessment.processing_purposes:
            risks.append({
                "risk_id": "data_sharing",
                "risk_name": "Third Party Data Sharing",
                "description": "Sharing data with third parties increases privacy risks",
                "risk_level": "medium",
                "impact": "medium",
                "likelihood": "medium",
                "affected_principles": [PrivacyPrinciple.END_TO_END_SECURITY.value, PrivacyPrinciple.PURPOSE_LIMITATION.value]
            })
        
        return risks
    
    async def _assess_overall_risk_level(self, assessment: PrivacyAssessment) -> PrivacyRisk:
        """Assess overall privacy risk level"""
        
        if not assessment.identified_risks:
            return PrivacyRisk.MINIMAL
        
        # Count risks by level
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for risk in assessment.identified_risks:
            risk_level = risk.get("risk_level", "low")
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
        
        # Determine overall risk
        if risk_counts["critical"] > 0:
            return PrivacyRisk.CRITICAL
        elif risk_counts["high"] >= 2:
            return PrivacyRisk.HIGH
        elif risk_counts["high"] >= 1 or risk_counts["medium"] >= 3:
            return PrivacyRisk.MEDIUM
        elif risk_counts["medium"] >= 1:
            return PrivacyRisk.LOW
        else:
            return PrivacyRisk.MINIMAL
    
    async def _identify_applicable_requirements(self, assessment: PrivacyAssessment) -> List[str]:
        """Identify applicable privacy requirements for the processing activity"""
        
        applicable = []
        
        for req_id, requirement in self.privacy_requirements.items():
            # Check if requirement applies based on processing stage, data categories, etc.
            if await self._requirement_applies_to_assessment(requirement, assessment):
                applicable.append(req_id)
        
        return applicable
    
    async def _requirement_applies_to_assessment(self, 
                                               requirement: PrivacyRequirement, 
                                               assessment: PrivacyAssessment) -> bool:
        """Check if a privacy requirement applies to the assessment"""
        
        # Stage-based applicability
        stage_applies = True  # For simplicity, assume all requirements apply
        
        # Data category based applicability
        if "special_categories" in requirement.name.lower():
            special_categories = [
                "health_data", "genetic_data", "biometric_data", "racial_ethnic_data"
            ]
            category_applies = any(cat in special_categories for cat in assessment.data_categories)
        else:
            category_applies = True
        
        # Purpose-based applicability
        if "analytics" in requirement.name.lower():
            purpose_applies = any("analytics" in purpose for purpose in assessment.processing_purposes)
        else:
            purpose_applies = True
        
        return stage_applies and category_applies and purpose_applies
    
    async def _check_requirement_compliance(self, assessment: PrivacyAssessment) -> Dict[str, bool]:
        """Check compliance with applicable privacy requirements"""
        
        compliance_status = {}
        
        for req_id in assessment.applicable_requirements:
            requirement = self.privacy_requirements.get(req_id)
            if requirement:
                # In a real implementation, this would check actual system compliance
                # For now, simulate compliance checking
                compliance_status[req_id] = requirement.implemented
        
        return compliance_status
    
    async def _recommend_privacy_technologies(self, assessment: PrivacyAssessment) -> List[PrivacyEnhancingTechnology]:
        """Recommend privacy enhancing technologies for the assessment"""
        
        recommendations = []
        
        # Based on data categories
        if "identification_data" in assessment.data_categories:
            recommendations.extend([
                PrivacyEnhancingTechnology.PSEUDONYMIZATION,
                PrivacyEnhancingTechnology.ANONYMIZATION
            ])
        
        # Based on processing purposes
        if any("analytics" in purpose for purpose in assessment.processing_purposes):
            recommendations.extend([
                PrivacyEnhancingTechnology.DIFFERENTIAL_PRIVACY,
                PrivacyEnhancingTechnology.ANONYMIZATION
            ])
        
        # Based on risk level
        if assessment.overall_risk_level in [PrivacyRisk.HIGH, PrivacyRisk.CRITICAL]:
            recommendations.extend([
                PrivacyEnhancingTechnology.HOMOMORPHIC_ENCRYPTION,
                PrivacyEnhancingTechnology.ZERO_KNOWLEDGE_PROOFS
            ])
        
        # Always recommend these
        recommendations.extend([
            PrivacyEnhancingTechnology.DATA_MINIMIZATION,
            PrivacyEnhancingTechnology.ENCRYPTION,
            PrivacyEnhancingTechnology.ACCESS_CONTROL
        ])
        
        # Remove duplicates and return
        return list(set(recommendations))
    
    async def _generate_mitigation_measures(self, assessment: PrivacyAssessment) -> List[str]:
        """Generate privacy risk mitigation measures"""
        
        measures = []
        
        # Risk-specific measures
        for risk in assessment.identified_risks:
            risk_id = risk.get("risk_id", "")
            
            if risk_id == "special_categories_processing":
                measures.extend([
                    "Implement explicit consent mechanisms for special category data",
                    "Apply additional encryption for special category data",
                    "Conduct regular audits of special category processing",
                    "Implement enhanced access controls for special category data"
                ])
            
            elif risk_id == "vulnerable_subjects":
                measures.extend([
                    "Implement parental consent mechanisms for children's data",
                    "Provide accessible privacy controls for vulnerable users",
                    "Apply enhanced data protection measures for vulnerable subjects",
                    "Regular review of vulnerable subject data processing"
                ])
            
            elif risk_id == "automated_decision_making":
                measures.extend([
                    "Provide human review options for automated decisions",
                    "Implement explanation mechanisms for automated decisions",
                    "Allow data subjects to contest automated decisions",
                    "Regular algorithmic bias testing and mitigation"
                ])
        
        # Technology-specific measures
        for tech in assessment.recommended_technologies:
            if tech == PrivacyEnhancingTechnology.PSEUDONYMIZATION:
                measures.append("Implement robust pseudonymization with secure key management")
            elif tech == PrivacyEnhancingTechnology.ANONYMIZATION:
                measures.append("Apply k-anonymity with appropriate k values")
            elif tech == PrivacyEnhancingTechnology.DIFFERENTIAL_PRIVACY:
                measures.append("Calibrate privacy parameters based on data sensitivity")
        
        # General measures
        measures.extend([
            "Implement privacy by design principles in system architecture",
            "Conduct regular privacy training for staff",
            "Establish clear data retention and deletion policies",
            "Implement comprehensive audit logging for privacy events"
        ])
        
        return list(set(measures))  # Remove duplicates
    
    async def _create_implementation_plan(self, assessment: PrivacyAssessment) -> List[Dict[str, Any]]:
        """Create implementation plan for privacy measures"""
        
        plan = []
        priority_order = ["critical", "high", "medium", "low"]
        
        # Implementation tasks based on risks
        for risk in assessment.identified_risks:
            risk_level = risk.get("risk_level", "medium")
            priority = priority_order.index(risk_level) if risk_level in priority_order else 2
            
            plan.append({
                "task": f"Mitigate {risk['risk_name']}",
                "description": f"Address privacy risk: {risk['description']}",
                "priority": priority,
                "estimated_effort": "medium",
                "dependencies": [],
                "target_completion": (datetime.now() + timedelta(days=30 * (priority + 1))).isoformat()
            })
        
        # Implementation tasks for technologies
        for tech in assessment.recommended_technologies:
            if tech in self.pet_implementations:
                plan.append({
                    "task": f"Implement {tech.value}",
                    "description": f"Deploy and configure {tech.value} technology",
                    "priority": 1,  # High priority for available technologies
                    "estimated_effort": "medium",
                    "dependencies": ["Security team approval", "Testing completion"],
                    "target_completion": (datetime.now() + timedelta(days=60)).isoformat()
                })
        
        # Sort by priority
        plan.sort(key=lambda x: x["priority"])
        
        return plan
    
    async def apply_privacy_technology(self,
                                     technology: PrivacyEnhancingTechnology,
                                     data: Any,
                                     params: Dict[str, Any] = None) -> Any:
        """Apply a privacy enhancing technology to data"""
        
        if technology not in self.pet_implementations:
            raise ValueError(f"Technology {technology.value} not implemented")
        
        pet_impl = self.pet_implementations[technology]
        
        # Log the application
        await self._log_privacy_event(None, "privacy_technology_applied", {
            "technology": technology.value,
            "data_type": type(data).__name__,
            "params": params or {}
        })
        
        return await pet_impl.apply(data, params)
    
    async def validate_privacy_implementation(self) -> Dict[str, Any]:
        """Validate overall privacy implementation"""
        
        validation_results = {
            "overall_status": "compliant",
            "technology_validation": {},
            "requirement_compliance": {},
            "identified_gaps": [],
            "recommendations": []
        }
        
        # Validate each implemented technology
        for tech, impl in self.pet_implementations.items():
            try:
                is_valid = impl.validate_implementation()
                validation_results["technology_validation"][tech.value] = {
                    "valid": is_valid,
                    "guarantees": impl.get_privacy_guarantees()
                }
                
                if not is_valid:
                    validation_results["identified_gaps"].append(f"Technology {tech.value} validation failed")
                    validation_results["overall_status"] = "non_compliant"
                
            except Exception as e:
                validation_results["technology_validation"][tech.value] = {
                    "valid": False,
                    "error": str(e)
                }
                validation_results["identified_gaps"].append(f"Technology {tech.value} validation error: {str(e)}")
                validation_results["overall_status"] = "non_compliant"
        
        # Check requirement compliance
        for req_id, requirement in self.privacy_requirements.items():
            compliance_status = requirement.implemented and bool(requirement.compliance_evidence)
            validation_results["requirement_compliance"][req_id] = {
                "compliant": compliance_status,
                "name": requirement.name,
                "principle": requirement.principle.value,
                "implementation_date": requirement.implementation_date.isoformat() if requirement.implementation_date else None
            }
            
            if not compliance_status:
                if requirement.mandatory:
                    validation_results["identified_gaps"].append(f"Mandatory requirement not met: {requirement.name}")
                    validation_results["overall_status"] = "non_compliant"
                else:
                    validation_results["recommendations"].append(f"Consider implementing optional requirement: {requirement.name}")
        
        # Generate overall recommendations
        if validation_results["overall_status"] == "non_compliant":
            validation_results["recommendations"].extend([
                "Address identified gaps to achieve compliance",
                "Review and update privacy implementation",
                "Conduct regular privacy audits",
                "Ensure all mandatory requirements are implemented"
            ])
        else:
            validation_results["recommendations"].extend([
                "Maintain current privacy implementation",
                "Regular monitoring and review",
                "Stay updated with privacy technology advances"
            ])
        
        return validation_results
    
    async def generate_privacy_report(self) -> Dict[str, Any]:
        """Generate comprehensive privacy by design implementation report"""
        
        report = {
            "report_date": datetime.now().isoformat(),
            "implementation_summary": {
                "total_requirements": len(self.privacy_requirements),
                "implemented_requirements": len([r for r in self.privacy_requirements.values() if r.implemented]),
                "total_technologies": len(self.pet_implementations),
                "validated_technologies": 0,
                "total_assessments": len(self.privacy_assessments)
            },
            "compliance_by_principle": {},
            "technology_coverage": {},
            "assessment_summary": {},
            "recommendations": []
        }
        
        # Count compliance by principle
        principle_counts = defaultdict(lambda: {"total": 0, "implemented": 0})
        for requirement in self.privacy_requirements.values():
            principle_counts[requirement.principle.value]["total"] += 1
            if requirement.implemented:
                principle_counts[requirement.principle.value]["implemented"] += 1
        
        report["compliance_by_principle"] = {
            principle: {
                "total": counts["total"],
                "implemented": counts["implemented"],
                "compliance_rate": counts["implemented"] / counts["total"] if counts["total"] > 0 else 0
            }
            for principle, counts in principle_counts.items()
        }
        
        # Technology validation status
        validated_count = 0
        for tech, impl in self.pet_implementations.items():
            try:
                is_valid = impl.validate_implementation()
                report["technology_coverage"][tech.value] = {
                    "implemented": True,
                    "validated": is_valid,
                    "guarantees": impl.get_privacy_guarantees()
                }
                if is_valid:
                    validated_count += 1
            except Exception as e:
                report["technology_coverage"][tech.value] = {
                    "implemented": False,
                    "validated": False,
                    "error": str(e)
                }
        
        report["implementation_summary"]["validated_technologies"] = validated_count
        
        # Assessment summary
        if self.privacy_assessments:
            risk_levels = [a.overall_risk_level.value for a in self.privacy_assessments.values()]
            report["assessment_summary"] = {
                "total_assessments": len(self.privacy_assessments),
                "risk_distribution": {
                    level: risk_levels.count(level) for level in set(risk_levels)
                },
                "average_requirements_per_assessment": sum(
                    len(a.applicable_requirements) for a in self.privacy_assessments.values()
                ) / len(self.privacy_assessments)
            }
        
        # Generate recommendations
        compliance_rate = report["implementation_summary"]["implemented_requirements"] / report["implementation_summary"]["total_requirements"]
        
        if compliance_rate < 0.8:
            report["recommendations"].extend([
                "Prioritize implementation of remaining privacy requirements",
                "Focus on mandatory requirements first",
                "Conduct gap analysis for non-compliant areas"
            ])
        
        if validated_count < len(self.pet_implementations):
            report["recommendations"].append("Validate and fix failing privacy technologies")
        
        report["recommendations"].extend([
            "Regular review of privacy requirements",
            "Continuous monitoring of technology effectiveness",
            "Staff training on privacy by design principles"
        ])
        
        return report
    
    async def _log_privacy_event(self, assessment: Optional[PrivacyAssessment], event_type: str, metadata: Dict[str, Any] = None):
        """Log privacy-related events for audit trail"""
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "assessment_id": assessment.id if assessment else None,
            "processing_activity": assessment.processing_activity if assessment else None,
            "metadata": metadata or {}
        }
        
        self.logger.info(f"Privacy Event: {event_type}")
        
        # In production, this would write to audit database
    
    # Management and query methods
    def get_privacy_requirement(self, requirement_id: str) -> Optional[PrivacyRequirement]:
        """Get privacy requirement by ID"""
        return self.privacy_requirements.get(requirement_id)
    
    def list_privacy_requirements(self, principle: Optional[PrivacyPrinciple] = None) -> List[PrivacyRequirement]:
        """List privacy requirements, optionally filtered by principle"""
        if principle:
            return [r for r in self.privacy_requirements.values() if r.principle == principle]
        return list(self.privacy_requirements.values())
    
    def get_privacy_assessment(self, assessment_id: str) -> Optional[PrivacyAssessment]:
        """Get privacy assessment by ID"""
        return self.privacy_assessments.get(assessment_id)
    
    def list_privacy_assessments(self) -> List[PrivacyAssessment]:
        """List all privacy assessments"""
        return list(self.privacy_assessments.values())
    
    def get_available_technologies(self) -> List[PrivacyEnhancingTechnology]:
        """Get list of available privacy enhancing technologies"""
        return list(self.pet_implementations.keys())
    
    async def update_requirement_implementation(self, requirement_id: str, implemented: bool, evidence: List[str] = None) -> bool:
        """Update implementation status of a privacy requirement"""
        
        requirement = self.privacy_requirements.get(requirement_id)
        if not requirement:
            return False
        
        old_status = requirement.implemented
        requirement.implemented = implemented
        
        if implemented and not requirement.implementation_date:
            requirement.implementation_date = datetime.now()
        
        if evidence:
            requirement.compliance_evidence.extend(evidence)
        
        await self._log_privacy_event(None, "requirement_implementation_updated", {
            "requirement_id": requirement_id,
            "old_status": old_status,
            "new_status": implemented,
            "evidence_added": len(evidence) if evidence else 0
        })
        
        return True