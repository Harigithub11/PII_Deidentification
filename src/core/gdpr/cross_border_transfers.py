"""
GDPR Cross-Border Data Transfer Controls (Articles 44-49)
Comprehensive system for managing international data transfers and ensuring GDPR compliance
"""
from typing import Dict, List, Optional, Any, Union, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import uuid
import json
from datetime import datetime, timedelta
import logging
from pathlib import Path
import requests
import asyncio
from ipaddress import ip_address, AddressValueError

from ..database.db_manager import DatabaseManager
from ..security.encryption_manager import EncryptionManager
from ..config.settings import get_settings


logger = logging.getLogger(__name__)
settings = get_settings()


class TransferMechanism(Enum):
    """Transfer mechanisms under GDPR Chapter V"""
    ADEQUACY_DECISION = "adequacy_decision"  # Article 45
    APPROPRIATE_SAFEGUARDS = "appropriate_safeguards"  # Article 46
    BINDING_CORPORATE_RULES = "binding_corporate_rules"  # Article 47
    CODES_OF_CONDUCT = "codes_of_conduct"  # Article 40
    CERTIFICATION = "certification"  # Article 42
    STANDARD_CONTRACTUAL_CLAUSES = "standard_contractual_clauses"  # Article 46(2)(c)
    DEROGATIONS = "derogations"  # Article 49


class AdequacyStatus(Enum):
    """Adequacy decision status"""
    ADEQUATE = "adequate"
    NOT_ADEQUATE = "not_adequate"
    PARTIALLY_ADEQUATE = "partially_adequate"
    PENDING_REVIEW = "pending_review"
    SUSPENDED = "suspended"


class TransferType(Enum):
    """Types of data transfers"""
    CONTROLLER_TO_CONTROLLER = "controller_to_controller"
    CONTROLLER_TO_PROCESSOR = "controller_to_processor"
    PROCESSOR_TO_PROCESSOR = "processor_to_processor"
    PROCESSOR_TO_CONTROLLER = "processor_to_controller"
    ONWARD_TRANSFER = "onward_transfer"


class TransferStatus(Enum):
    """Status of transfer requests"""
    PENDING_ASSESSMENT = "pending_assessment"
    APPROVED = "approved"
    CONDITIONALLY_APPROVED = "conditionally_approved"
    REJECTED = "rejected"
    SUSPENDED = "suspended"
    UNDER_REVIEW = "under_review"


@dataclass
class Country:
    """Country information for transfer assessment"""
    code: str  # ISO 3166-1 alpha-2
    name: str
    adequacy_status: AdequacyStatus = AdequacyStatus.NOT_ADEQUATE
    adequacy_decision_date: Optional[datetime] = None
    adequacy_scope: List[str] = field(default_factory=list)  # Commercial, public sector, etc.
    adequacy_limitations: List[str] = field(default_factory=list)
    privacy_laws: List[str] = field(default_factory=list)
    data_protection_authority: Optional[str] = None
    last_assessment_date: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "name": self.name,
            "adequacy_status": self.adequacy_status.value,
            "adequacy_decision_date": self.adequacy_decision_date.isoformat() if self.adequacy_decision_date else None,
            "adequacy_scope": self.adequacy_scope,
            "adequacy_limitations": self.adequacy_limitations,
            "privacy_laws": self.privacy_laws,
            "data_protection_authority": self.data_protection_authority,
            "last_assessment_date": self.last_assessment_date.isoformat() if self.last_assessment_date else None
        }


@dataclass
class TransferParty:
    """Data transfer party (sender or recipient)"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    organization_type: str = ""  # controller, processor
    contact_person: str = ""
    email: str = ""
    phone: str = ""
    address: str = ""
    country_code: str = ""
    role: str = ""  # data_controller, data_processor, joint_controller
    
    # Certification and compliance
    certifications: List[str] = field(default_factory=list)
    privacy_policies: List[str] = field(default_factory=list)
    security_measures: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "organization_type": self.organization_type,
            "contact_person": self.contact_person,
            "email": self.email,
            "phone": self.phone,
            "address": self.address,
            "country_code": self.country_code,
            "role": self.role,
            "certifications": self.certifications,
            "privacy_policies": self.privacy_policies,
            "security_measures": self.security_measures
        }


@dataclass
class StandardContractualClauses:
    """Standard Contractual Clauses (SCCs) implementation"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scc_version: str = "2021"  # EU Commission 2021 SCCs
    scc_type: str = ""  # controller-controller, controller-processor, processor-processor
    effective_date: datetime = field(default_factory=datetime.now)
    parties: List[TransferParty] = field(default_factory=list)
    
    # Module selection (for 2021 SCCs)
    module_one: bool = False  # Controller to controller
    module_two: bool = False  # Controller to processor
    module_three: bool = False  # Processor to processor
    module_four: bool = False  # Processor to controller
    
    # Additional safeguards
    additional_measures: List[str] = field(default_factory=list)
    technical_measures: List[str] = field(default_factory=list)
    organizational_measures: List[str] = field(default_factory=list)
    
    # Monitoring and compliance
    audit_requirements: List[str] = field(default_factory=list)
    breach_notification_procedures: List[str] = field(default_factory=list)
    data_subject_rights_procedures: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scc_version": self.scc_version,
            "scc_type": self.scc_type,
            "effective_date": self.effective_date.isoformat(),
            "parties": [p.to_dict() for p in self.parties],
            "module_one": self.module_one,
            "module_two": self.module_two,
            "module_three": self.module_three,
            "module_four": self.module_four,
            "additional_measures": self.additional_measures,
            "technical_measures": self.technical_measures,
            "organizational_measures": self.organizational_measures,
            "audit_requirements": self.audit_requirements,
            "breach_notification_procedures": self.breach_notification_procedures,
            "data_subject_rights_procedures": self.data_subject_rights_procedures
        }


@dataclass
class TransferImpactAssessment:
    """Transfer Impact Assessment (TIA) for cross-border transfers"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    transfer_id: str = ""
    assessment_date: datetime = field(default_factory=datetime.now)
    assessor: str = ""
    
    # Legal framework assessment
    destination_laws: List[str] = field(default_factory=list)
    conflicting_obligations: List[str] = field(default_factory=list)
    government_access_laws: List[str] = field(default_factory=list)
    surveillance_laws: List[str] = field(default_factory=list)
    
    # Risk assessment
    identified_risks: List[str] = field(default_factory=list)
    risk_level: str = "medium"
    risk_mitigation_measures: List[str] = field(default_factory=list)
    
    # Supplementary measures
    supplementary_measures_required: bool = False
    technical_supplementary_measures: List[str] = field(default_factory=list)
    organizational_supplementary_measures: List[str] = field(default_factory=list)
    contractual_supplementary_measures: List[str] = field(default_factory=list)
    
    # Conclusion
    transfer_permitted: bool = False
    conditions: List[str] = field(default_factory=list)
    monitoring_requirements: List[str] = field(default_factory=list)
    review_date: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "transfer_id": self.transfer_id,
            "assessment_date": self.assessment_date.isoformat(),
            "assessor": self.assessor,
            "destination_laws": self.destination_laws,
            "conflicting_obligations": self.conflicting_obligations,
            "government_access_laws": self.government_access_laws,
            "surveillance_laws": self.surveillance_laws,
            "identified_risks": self.identified_risks,
            "risk_level": self.risk_level,
            "risk_mitigation_measures": self.risk_mitigation_measures,
            "supplementary_measures_required": self.supplementary_measures_required,
            "technical_supplementary_measures": self.technical_supplementary_measures,
            "organizational_supplementary_measures": self.organizational_supplementary_measures,
            "contractual_supplementary_measures": self.contractual_supplementary_measures,
            "transfer_permitted": self.transfer_permitted,
            "conditions": self.conditions,
            "monitoring_requirements": self.monitoring_requirements,
            "review_date": self.review_date.isoformat() if self.review_date else None
        }


@dataclass
class DataTransfer:
    """Cross-border data transfer record"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    status: TransferStatus = TransferStatus.PENDING_ASSESSMENT
    
    # Transfer details
    transfer_type: TransferType = TransferType.CONTROLLER_TO_PROCESSOR
    data_exporter: Optional[TransferParty] = None
    data_importer: Optional[TransferParty] = None
    destination_country: Optional[Country] = None
    
    # Data and processing details
    data_categories: List[str] = field(default_factory=list)
    data_subjects_categories: List[str] = field(default_factory=list)
    processing_purposes: List[str] = field(default_factory=list)
    retention_period: int = 365  # days
    
    # Transfer mechanism
    transfer_mechanism: TransferMechanism = TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES
    adequacy_decision_reference: Optional[str] = None
    scc_details: Optional[StandardContractualClauses] = None
    bcr_reference: Optional[str] = None
    certification_reference: Optional[str] = None
    
    # Impact assessment
    tia_required: bool = True
    tia_assessment: Optional[TransferImpactAssessment] = None
    
    # Approval and monitoring
    approved_date: Optional[datetime] = None
    approved_by: Optional[str] = None
    conditions: List[str] = field(default_factory=list)
    monitoring_measures: List[str] = field(default_factory=list)
    next_review_date: Optional[datetime] = None
    
    # Transfer tracking
    transfer_start_date: Optional[datetime] = None
    transfer_end_date: Optional[datetime] = None
    transfer_frequency: str = "one-time"  # one-time, ongoing, periodic
    data_volume: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "transfer_type": self.transfer_type.value,
            "data_exporter": self.data_exporter.to_dict() if self.data_exporter else None,
            "data_importer": self.data_importer.to_dict() if self.data_importer else None,
            "destination_country": self.destination_country.to_dict() if self.destination_country else None,
            "data_categories": self.data_categories,
            "data_subjects_categories": self.data_subjects_categories,
            "processing_purposes": self.processing_purposes,
            "retention_period": self.retention_period,
            "transfer_mechanism": self.transfer_mechanism.value,
            "adequacy_decision_reference": self.adequacy_decision_reference,
            "scc_details": self.scc_details.to_dict() if self.scc_details else None,
            "bcr_reference": self.bcr_reference,
            "certification_reference": self.certification_reference,
            "tia_required": self.tia_required,
            "tia_assessment": self.tia_assessment.to_dict() if self.tia_assessment else None,
            "approved_date": self.approved_date.isoformat() if self.approved_date else None,
            "approved_by": self.approved_by,
            "conditions": self.conditions,
            "monitoring_measures": self.monitoring_measures,
            "next_review_date": self.next_review_date.isoformat() if self.next_review_date else None,
            "transfer_start_date": self.transfer_start_date.isoformat() if self.transfer_start_date else None,
            "transfer_end_date": self.transfer_end_date.isoformat() if self.transfer_end_date else None,
            "transfer_frequency": self.transfer_frequency,
            "data_volume": self.data_volume
        }


class CrossBorderTransferManager:
    """Comprehensive cross-border data transfer management system"""
    
    def __init__(self,
                 db_manager: DatabaseManager,
                 encryption_manager: EncryptionManager):
        self.db_manager = db_manager
        self.encryption_manager = encryption_manager
        self.logger = logging.getLogger(__name__)
        
        # Storage for transfer data
        self.transfers: Dict[str, DataTransfer] = {}
        self.countries: Dict[str, Country] = {}
        self.transfer_parties: Dict[str, TransferParty] = {}
        self.scc_agreements: Dict[str, StandardContractualClauses] = {}
        
        # Initialize adequacy decisions and country data
        self._initialize_adequacy_decisions()
        self._initialize_transfer_mechanisms()
    
    def _initialize_adequacy_decisions(self):
        """Initialize current EU adequacy decisions"""
        
        # Countries with adequacy decisions (as of 2024)
        adequate_countries = [
            {
                "code": "AD", "name": "Andorra", 
                "decision_date": datetime(2010, 10, 19),
                "scope": ["commercial"],
                "limitations": []
            },
            {
                "code": "AR", "name": "Argentina", 
                "decision_date": datetime(2003, 6, 30),
                "scope": ["commercial"],
                "limitations": ["public sector excluded"]
            },
            {
                "code": "CA", "name": "Canada", 
                "decision_date": datetime(2001, 12, 20),
                "scope": ["commercial"],
                "limitations": ["PIPEDA scope only"]
            },
            {
                "code": "CH", "name": "Switzerland", 
                "decision_date": datetime(2000, 7, 26),
                "scope": ["commercial", "public"],
                "limitations": []
            },
            {
                "code": "FO", "name": "Faroe Islands", 
                "decision_date": datetime(2010, 3, 5),
                "scope": ["commercial"],
                "limitations": []
            },
            {
                "code": "GG", "name": "Guernsey", 
                "decision_date": datetime(2003, 11, 21),
                "scope": ["commercial"],
                "limitations": []
            },
            {
                "code": "IL", "name": "Israel", 
                "decision_date": datetime(2011, 1, 31),
                "scope": ["commercial"],
                "limitations": []
            },
            {
                "code": "IM", "name": "Isle of Man", 
                "decision_date": datetime(2004, 4, 28),
                "scope": ["commercial"],
                "limitations": []
            },
            {
                "code": "JE", "name": "Jersey", 
                "decision_date": datetime(2008, 5, 8),
                "scope": ["commercial"],
                "limitations": []
            },
            {
                "code": "JP", "name": "Japan", 
                "decision_date": datetime(2019, 1, 23),
                "scope": ["commercial"],
                "limitations": ["specific sectors only"]
            },
            {
                "code": "KR", "name": "South Korea", 
                "decision_date": datetime(2021, 12, 17),
                "scope": ["commercial"],
                "limitations": ["PIPA scope only"]
            },
            {
                "code": "NZ", "name": "New Zealand", 
                "decision_date": datetime(2012, 12, 19),
                "scope": ["commercial"],
                "limitations": []
            },
            {
                "code": "UY", "name": "Uruguay", 
                "decision_date": datetime(2012, 8, 21),
                "scope": ["commercial"],
                "limitations": []
            },
            {
                "code": "GB", "name": "United Kingdom", 
                "decision_date": datetime(2021, 6, 28),
                "scope": ["commercial", "public"],
                "limitations": ["transitional arrangement"]
            }
        ]
        
        for country_data in adequate_countries:
            country = Country(
                code=country_data["code"],
                name=country_data["name"],
                adequacy_status=AdequacyStatus.ADEQUATE,
                adequacy_decision_date=country_data["decision_date"],
                adequacy_scope=country_data["scope"],
                adequacy_limitations=country_data["limitations"]
            )
            self.countries[country.code] = country
        
        # Add some non-adequate countries for testing
        non_adequate_countries = [
            {"code": "US", "name": "United States"},
            {"code": "CN", "name": "China"},
            {"code": "IN", "name": "India"},
            {"code": "BR", "name": "Brazil"},
            {"code": "RU", "name": "Russia"}
        ]
        
        for country_data in non_adequate_countries:
            country = Country(
                code=country_data["code"],
                name=country_data["name"],
                adequacy_status=AdequacyStatus.NOT_ADEQUATE
            )
            self.countries[country.code] = country
    
    def _initialize_transfer_mechanisms(self):
        """Initialize standard transfer mechanisms and templates"""
        
        # Create standard SCC template
        standard_scc = StandardContractualClauses(
            scc_version="2021",
            scc_type="controller_to_processor",
            module_two=True,  # Controller to processor
            additional_measures=[
                "End-to-end encryption of data in transit and at rest",
                "Regular security assessments and audits",
                "Data localization where required",
                "Restricted government access procedures"
            ],
            technical_measures=[
                "AES-256 encryption",
                "TLS 1.3 for data transmission",
                "Multi-factor authentication",
                "Regular security monitoring"
            ],
            organizational_measures=[
                "Staff training on data protection",
                "Access controls and authorization procedures",
                "Incident response procedures",
                "Regular compliance audits"
            ]
        )
        
        self.scc_agreements[standard_scc.id] = standard_scc
    
    async def assess_transfer_requirement(self, 
                                        destination_country_code: str,
                                        data_categories: List[str],
                                        processing_purposes: List[str]) -> Dict[str, Any]:
        """Assess if a cross-border transfer requires special mechanisms"""
        
        destination = self.countries.get(destination_country_code.upper())
        if not destination:
            return {
                "transfer_required": True,
                "adequacy_status": "unknown",
                "mechanism_required": True,
                "recommended_mechanism": TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES.value,
                "assessment_required": True
            }
        
        assessment = {
            "transfer_required": True,
            "destination_country": destination.to_dict(),
            "adequacy_status": destination.adequacy_status.value,
            "mechanism_required": destination.adequacy_status != AdequacyStatus.ADEQUATE,
            "assessment_required": True
        }
        
        if destination.adequacy_status == AdequacyStatus.ADEQUATE:
            # Check if transfer falls within adequacy scope
            assessment["mechanism_required"] = False
            assessment["recommended_mechanism"] = TransferMechanism.ADEQUACY_DECISION.value
            assessment["assessment_required"] = False
        else:
            # Non-adequate country requires transfer mechanism
            assessment["recommended_mechanism"] = TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES.value
            
            # Check for high-risk data categories
            high_risk_categories = ["health_data", "biometric_data", "genetic_data", "financial_data"]
            if any(cat in data_categories for cat in high_risk_categories):
                assessment["supplementary_measures_required"] = True
                assessment["tia_required"] = True
        
        return assessment
    
    async def create_transfer_request(self, 
                                    transfer_data: Dict[str, Any]) -> DataTransfer:
        """Create new cross-border transfer request"""
        
        # Create transfer parties
        exporter_data = transfer_data.get("data_exporter", {})
        data_exporter = TransferParty(**exporter_data) if exporter_data else None
        
        importer_data = transfer_data.get("data_importer", {})
        data_importer = TransferParty(**importer_data) if importer_data else None
        
        # Get destination country
        country_code = transfer_data.get("destination_country_code", "")
        destination_country = self.countries.get(country_code.upper())
        
        # Create transfer record
        transfer = DataTransfer(
            title=transfer_data.get("title", ""),
            description=transfer_data.get("description", ""),
            transfer_type=TransferType(transfer_data.get("transfer_type", "controller_to_processor")),
            data_exporter=data_exporter,
            data_importer=data_importer,
            destination_country=destination_country,
            data_categories=transfer_data.get("data_categories", []),
            data_subjects_categories=transfer_data.get("data_subjects_categories", []),
            processing_purposes=transfer_data.get("processing_purposes", []),
            retention_period=transfer_data.get("retention_period", 365),
            transfer_frequency=transfer_data.get("transfer_frequency", "one-time"),
            data_volume=transfer_data.get("data_volume", "")
        )
        
        # Store transfer parties
        if data_exporter:
            self.transfer_parties[data_exporter.id] = data_exporter
        if data_importer:
            self.transfer_parties[data_importer.id] = data_importer
        
        # Determine transfer mechanism
        transfer_mechanism = await self._determine_transfer_mechanism(transfer)
        transfer.transfer_mechanism = transfer_mechanism
        
        # Determine if TIA is required
        transfer.tia_required = self._requires_tia(transfer)
        
        # Store transfer
        self.transfers[transfer.id] = transfer
        
        # Log transfer creation
        await self._log_transfer_event(transfer, "transfer_request_created")
        
        self.logger.info(f"Transfer request created: {transfer.id} to {country_code}")
        
        return transfer
    
    async def _determine_transfer_mechanism(self, transfer: DataTransfer) -> TransferMechanism:
        """Determine appropriate transfer mechanism for the transfer"""
        
        if not transfer.destination_country:
            return TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES
        
        # Check adequacy decision
        if transfer.destination_country.adequacy_status == AdequacyStatus.ADEQUATE:
            return TransferMechanism.ADEQUACY_DECISION
        
        # For non-adequate countries, default to SCCs
        # In production, this would consider other factors like:
        # - Organization's BCR status
        # - Available certifications
        # - Specific sector codes of conduct
        
        return TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES
    
    def _requires_tia(self, transfer: DataTransfer) -> bool:
        """Determine if Transfer Impact Assessment is required"""
        
        # TIA always required for non-adequate countries
        if (not transfer.destination_country or 
            transfer.destination_country.adequacy_status != AdequacyStatus.ADEQUATE):
            return True
        
        # TIA required for sensitive data categories even to adequate countries
        sensitive_categories = [
            "health_data", "biometric_data", "genetic_data", 
            "criminal_data", "financial_data"
        ]
        
        if any(cat in transfer.data_categories for cat in sensitive_categories):
            return True
        
        # TIA required for vulnerable data subjects
        vulnerable_subjects = ["children", "patients", "employees"]
        if any(subj in transfer.data_subjects_categories for subj in vulnerable_subjects):
            return True
        
        return False
    
    async def conduct_transfer_impact_assessment(self, 
                                               transfer_id: str,
                                               assessor: str = "") -> Optional[TransferImpactAssessment]:
        """Conduct Transfer Impact Assessment (TIA)"""
        
        transfer = self.transfers.get(transfer_id)
        if not transfer:
            return None
        
        if not transfer.tia_required:
            self.logger.info(f"TIA not required for transfer {transfer_id}")
            return None
        
        # Create TIA
        tia = TransferImpactAssessment(
            transfer_id=transfer_id,
            assessor=assessor or "Privacy Team"
        )
        
        # Assess destination country laws
        if transfer.destination_country:
            tia = await self._assess_destination_laws(tia, transfer.destination_country)
        
        # Assess risks
        tia = await self._assess_transfer_risks(tia, transfer)
        
        # Determine supplementary measures
        tia = await self._determine_supplementary_measures(tia, transfer)
        
        # Make transfer decision
        tia.transfer_permitted = self._evaluate_transfer_permission(tia)
        
        # Set review date
        tia.review_date = datetime.now() + timedelta(days=365)  # Annual review
        
        # Update transfer with TIA
        transfer.tia_assessment = tia
        
        await self._log_transfer_event(transfer, "tia_completed", {
            "transfer_permitted": tia.transfer_permitted,
            "risk_level": tia.risk_level,
            "supplementary_measures_required": tia.supplementary_measures_required
        })
        
        self.logger.info(f"TIA completed for transfer {transfer_id}: {tia.transfer_permitted}")
        
        return tia
    
    async def _assess_destination_laws(self, 
                                     tia: TransferImpactAssessment, 
                                     country: Country) -> TransferImpactAssessment:
        """Assess destination country laws and regulations"""
        
        # This would integrate with legal databases or expert assessments
        # For now, simulate assessment based on country
        
        country_assessments = {
            "US": {
                "destination_laws": ["FISA", "CLOUD Act", "USA PATRIOT Act"],
                "government_access_laws": ["FISA Section 702", "CLOUD Act"],
                "surveillance_laws": ["NSA surveillance programs"],
                "conflicting_obligations": ["US government access vs GDPR data subject rights"]
            },
            "CN": {
                "destination_laws": ["Cybersecurity Law", "Data Security Law", "PIPL"],
                "government_access_laws": ["National Intelligence Law"],
                "surveillance_laws": ["Social Credit System"],
                "conflicting_obligations": ["Data localization requirements"]
            },
            "IN": {
                "destination_laws": ["IT Act 2000", "Draft Data Protection Bill"],
                "government_access_laws": ["IT Act Section 69"],
                "surveillance_laws": ["Central Monitoring System"],
                "conflicting_obligations": ["Government access procedures"]
            }
        }
        
        assessment = country_assessments.get(country.code, {
            "destination_laws": ["General privacy laws"],
            "government_access_laws": ["Standard government access procedures"],
            "surveillance_laws": ["Standard surveillance framework"],
            "conflicting_obligations": ["May conflict with GDPR requirements"]
        })
        
        tia.destination_laws = assessment["destination_laws"]
        tia.government_access_laws = assessment["government_access_laws"]
        tia.surveillance_laws = assessment["surveillance_laws"]
        tia.conflicting_obligations = assessment["conflicting_obligations"]
        
        return tia
    
    async def _assess_transfer_risks(self, 
                                   tia: TransferImpactAssessment, 
                                   transfer: DataTransfer) -> TransferImpactAssessment:
        """Assess risks associated with the transfer"""
        
        risks = []
        risk_score = 0
        
        # Assess data sensitivity
        sensitive_data_categories = ["health_data", "biometric_data", "genetic_data", "financial_data"]
        if any(cat in transfer.data_categories for cat in sensitive_data_categories):
            risks.append("High sensitivity personal data involved")
            risk_score += 3
        
        # Assess vulnerable subjects
        if "children" in transfer.data_subjects_categories:
            risks.append("Children's data involved")
            risk_score += 2
        
        # Assess destination country risks
        if transfer.destination_country and transfer.destination_country.adequacy_status != AdequacyStatus.ADEQUATE:
            risks.append("Transfer to non-adequate country")
            risk_score += 2
        
        # Assess government access risks
        if tia.government_access_laws:
            risks.append("Government access laws may apply")
            risk_score += 1
        
        # Assess data volume and retention
        if transfer.transfer_frequency == "ongoing":
            risks.append("Ongoing data transfers increase exposure")
            risk_score += 1
        
        if transfer.retention_period > 1095:  # > 3 years
            risks.append("Long retention period increases risk")
            risk_score += 1
        
        tia.identified_risks = risks
        
        # Determine risk level
        if risk_score <= 2:
            tia.risk_level = "low"
        elif risk_score <= 4:
            tia.risk_level = "medium"
        elif risk_score <= 6:
            tia.risk_level = "high"
        else:
            tia.risk_level = "very_high"
        
        return tia
    
    async def _determine_supplementary_measures(self, 
                                              tia: TransferImpactAssessment, 
                                              transfer: DataTransfer) -> TransferImpactAssessment:
        """Determine required supplementary measures"""
        
        if tia.risk_level in ["high", "very_high"]:
            tia.supplementary_measures_required = True
            
            # Technical measures
            tia.technical_supplementary_measures = [
                "End-to-end encryption with EU-controlled keys",
                "Pseudonymization or anonymization where possible",
                "Secure multi-party computation for data processing",
                "Data localization for most sensitive processing",
                "Regular security audits and penetration testing"
            ]
            
            # Organizational measures
            tia.organizational_supplementary_measures = [
                "Enhanced staff training on data protection",
                "Strict access controls with need-to-know principle",
                "Regular compliance monitoring and reporting",
                "Incident response procedures for government access",
                "Data subject notification procedures"
            ]
            
            # Contractual measures
            tia.contractual_supplementary_measures = [
                "Enhanced data protection clauses in contracts",
                "Government access notification requirements",
                "Data subject rights implementation procedures",
                "Regular compliance certifications",
                "Liability and indemnification clauses"
            ]
        
        return tia
    
    def _evaluate_transfer_permission(self, tia: TransferImpactAssessment) -> bool:
        """Evaluate whether transfer should be permitted based on TIA"""
        
        # Transfer denied for very high risk without adequate supplementary measures
        if tia.risk_level == "very_high" and not tia.supplementary_measures_required:
            return False
        
        # Transfer denied if conflicting obligations cannot be resolved
        critical_conflicts = [
            "mandatory government access without judicial oversight",
            "data localization requirements conflict with business needs",
            "surveillance laws prevent effective data protection"
        ]
        
        if any(conflict in " ".join(tia.conflicting_obligations).lower() 
               for conflict in critical_conflicts):
            return False
        
        # Otherwise, transfer can be permitted with appropriate safeguards
        return True
    
    async def implement_standard_contractual_clauses(self, 
                                                   transfer_id: str,
                                                   scc_config: Dict[str, Any]) -> Optional[StandardContractualClauses]:
        """Implement Standard Contractual Clauses for transfer"""
        
        transfer = self.transfers.get(transfer_id)
        if not transfer:
            return None
        
        # Create SCC agreement
        scc = StandardContractualClauses(
            scc_version=scc_config.get("version", "2021"),
            scc_type=scc_config.get("type", "controller_to_processor"),
            effective_date=datetime.now()
        )
        
        # Add parties
        if transfer.data_exporter:
            scc.parties.append(transfer.data_exporter)
        if transfer.data_importer:
            scc.parties.append(transfer.data_importer)
        
        # Set appropriate modules
        if transfer.transfer_type == TransferType.CONTROLLER_TO_CONTROLLER:
            scc.module_one = True
        elif transfer.transfer_type == TransferType.CONTROLLER_TO_PROCESSOR:
            scc.module_two = True
        elif transfer.transfer_type == TransferType.PROCESSOR_TO_PROCESSOR:
            scc.module_three = True
        elif transfer.transfer_type == TransferType.PROCESSOR_TO_CONTROLLER:
            scc.module_four = True
        
        # Add supplementary measures if required by TIA
        if (transfer.tia_assessment and 
            transfer.tia_assessment.supplementary_measures_required):
            scc.additional_measures.extend(
                transfer.tia_assessment.technical_supplementary_measures +
                transfer.tia_assessment.organizational_supplementary_measures +
                transfer.tia_assessment.contractual_supplementary_measures
            )
        
        # Store SCC agreement
        self.scc_agreements[scc.id] = scc
        
        # Update transfer with SCC details
        transfer.scc_details = scc
        transfer.transfer_mechanism = TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES
        
        await self._log_transfer_event(transfer, "scc_implemented", {
            "scc_id": scc.id,
            "scc_version": scc.scc_version,
            "scc_type": scc.scc_type
        })
        
        self.logger.info(f"SCCs implemented for transfer {transfer_id}")
        
        return scc
    
    async def approve_transfer(self, 
                             transfer_id: str,
                             approver: str,
                             conditions: List[str] = None) -> bool:
        """Approve cross-border transfer"""
        
        transfer = self.transfers.get(transfer_id)
        if not transfer:
            return False
        
        # Check if all requirements are met
        if transfer.tia_required and not transfer.tia_assessment:
            self.logger.error(f"Cannot approve transfer {transfer_id}: TIA required but not completed")
            return False
        
        if (transfer.tia_assessment and 
            not transfer.tia_assessment.transfer_permitted):
            self.logger.error(f"Cannot approve transfer {transfer_id}: TIA indicates transfer not permitted")
            return False
        
        # Approve transfer
        transfer.status = TransferStatus.APPROVED
        transfer.approved_date = datetime.now()
        transfer.approved_by = approver
        transfer.conditions = conditions or []
        
        # Set monitoring and review schedule
        transfer.monitoring_measures = [
            "Monthly compliance reviews",
            "Quarterly risk assessments",
            "Annual TIA reviews",
            "Incident monitoring and reporting"
        ]
        
        transfer.next_review_date = datetime.now() + timedelta(days=365)
        
        await self._log_transfer_event(transfer, "transfer_approved", {
            "approved_by": approver,
            "conditions": conditions or []
        })
        
        self.logger.info(f"Transfer approved: {transfer_id} by {approver}")
        
        return True
    
    async def monitor_ongoing_transfers(self) -> Dict[str, Any]:
        """Monitor ongoing transfers for compliance"""
        
        monitoring_results = {
            "total_transfers": len(self.transfers),
            "active_transfers": 0,
            "transfers_due_review": [],
            "compliance_issues": [],
            "risk_changes": []
        }
        
        current_date = datetime.now()
        
        for transfer in self.transfers.values():
            if transfer.status == TransferStatus.APPROVED:
                monitoring_results["active_transfers"] += 1
                
                # Check review dates
                if (transfer.next_review_date and 
                    current_date >= transfer.next_review_date):
                    monitoring_results["transfers_due_review"].append(transfer.id)
                
                # Check compliance with conditions
                compliance_issues = await self._check_transfer_compliance(transfer)
                if compliance_issues:
                    monitoring_results["compliance_issues"].extend(compliance_issues)
                
                # Check for risk changes
                risk_changes = await self._assess_risk_changes(transfer)
                if risk_changes:
                    monitoring_results["risk_changes"].extend(risk_changes)
        
        return monitoring_results
    
    async def _check_transfer_compliance(self, transfer: DataTransfer) -> List[Dict[str, Any]]:
        """Check compliance issues for a transfer"""
        
        issues = []
        
        # Check SCC compliance
        if (transfer.transfer_mechanism == TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES and
            transfer.scc_details):
            # In production, this would check actual compliance metrics
            pass
        
        # Check TIA requirements
        if (transfer.tia_assessment and 
            transfer.tia_assessment.supplementary_measures_required):
            # Verify supplementary measures are implemented
            pass
        
        return issues
    
    async def _assess_risk_changes(self, transfer: DataTransfer) -> List[Dict[str, Any]]:
        """Assess if risks have changed for a transfer"""
        
        risk_changes = []
        
        # Check for adequacy decision changes
        if (transfer.destination_country and 
            transfer.destination_country.adequacy_status == AdequacyStatus.ADEQUATE):
            # Check if adequacy decision has been suspended or revoked
            pass
        
        # Check for legal framework changes in destination country
        # This would integrate with legal monitoring services
        
        return risk_changes
    
    async def handle_adequacy_decision_change(self, 
                                            country_code: str, 
                                            new_status: AdequacyStatus) -> Dict[str, Any]:
        """Handle changes in adequacy decisions"""
        
        country = self.countries.get(country_code.upper())
        if not country:
            return {"error": "Country not found"}
        
        old_status = country.adequacy_status
        country.adequacy_status = new_status
        country.last_assessment_date = datetime.now()
        
        # Find affected transfers
        affected_transfers = [
            transfer for transfer in self.transfers.values()
            if (transfer.destination_country and 
                transfer.destination_country.code == country_code.upper())
        ]
        
        results = {
            "country": country_code,
            "old_status": old_status.value,
            "new_status": new_status.value,
            "affected_transfers": len(affected_transfers),
            "actions_required": []
        }
        
        # Handle status downgrade (adequate -> non-adequate)
        if (old_status == AdequacyStatus.ADEQUATE and 
            new_status != AdequacyStatus.ADEQUATE):
            
            for transfer in affected_transfers:
                if transfer.status == TransferStatus.APPROVED:
                    # Suspend transfer and require new mechanism
                    transfer.status = TransferStatus.SUSPENDED
                    results["actions_required"].append({
                        "transfer_id": transfer.id,
                        "action": "implement_transfer_mechanism",
                        "reason": "adequacy_decision_revoked"
                    })
                    
                    await self._log_transfer_event(transfer, "transfer_suspended", {
                        "reason": "adequacy_decision_revoked",
                        "country": country_code
                    })
        
        # Handle status upgrade (non-adequate -> adequate)
        elif (old_status != AdequacyStatus.ADEQUATE and 
              new_status == AdequacyStatus.ADEQUATE):
            
            for transfer in affected_transfers:
                # Transfers can potentially be simplified
                results["actions_required"].append({
                    "transfer_id": transfer.id,
                    "action": "review_transfer_mechanism",
                    "reason": "adequacy_decision_granted"
                })
        
        await self._log_transfer_event(None, "adequacy_decision_changed", {
            "country": country_code,
            "old_status": old_status.value,
            "new_status": new_status.value,
            "affected_transfers": len(affected_transfers)
        })
        
        return results
    
    async def _log_transfer_event(self, 
                                transfer: Optional[DataTransfer], 
                                event_type: str, 
                                metadata: Dict[str, Any] = None):
        """Log transfer events for audit trail"""
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "transfer_id": transfer.id if transfer else None,
            "transfer_title": transfer.title if transfer else None,
            "metadata": metadata or {}
        }
        
        self.logger.info(f"Transfer Event: {event_type}" + (f" for {transfer.id}" if transfer else ""))
        
        # In production, this would write to audit database
    
    # Management and query methods
    def get_transfer(self, transfer_id: str) -> Optional[DataTransfer]:
        """Get transfer by ID"""
        return self.transfers.get(transfer_id)
    
    def list_transfers(self, status: Optional[TransferStatus] = None) -> List[DataTransfer]:
        """List transfers, optionally filtered by status"""
        if status:
            return [t for t in self.transfers.values() if t.status == status]
        return list(self.transfers.values())
    
    def get_transfers_by_country(self, country_code: str) -> List[DataTransfer]:
        """Get transfers to specific country"""
        return [
            t for t in self.transfers.values()
            if (t.destination_country and 
                t.destination_country.code == country_code.upper())
        ]
    
    def get_country(self, country_code: str) -> Optional[Country]:
        """Get country information"""
        return self.countries.get(country_code.upper())
    
    def list_adequate_countries(self) -> List[Country]:
        """List countries with adequacy decisions"""
        return [
            c for c in self.countries.values()
            if c.adequacy_status == AdequacyStatus.ADEQUATE
        ]
    
    def get_scc_agreement(self, scc_id: str) -> Optional[StandardContractualClauses]:
        """Get SCC agreement by ID"""
        return self.scc_agreements.get(scc_id)
    
    async def get_transfer_statistics(self) -> Dict[str, Any]:
        """Get transfer statistics"""
        
        total_transfers = len(self.transfers)
        by_status = {}
        by_mechanism = {}
        by_country = {}
        
        for transfer in self.transfers.values():
            # By status
            status = transfer.status.value
            by_status[status] = by_status.get(status, 0) + 1
            
            # By mechanism
            mechanism = transfer.transfer_mechanism.value
            by_mechanism[mechanism] = by_mechanism.get(mechanism, 0) + 1
            
            # By country
            if transfer.destination_country:
                country = transfer.destination_country.name
                by_country[country] = by_country.get(country, 0) + 1
        
        return {
            "total_transfers": total_transfers,
            "by_status": by_status,
            "by_mechanism": by_mechanism,
            "by_country": by_country,
            "adequate_countries": len(self.list_adequate_countries()),
            "transfers_requiring_review": len([
                t for t in self.transfers.values()
                if t.next_review_date and datetime.now() >= t.next_review_date
            ])
        }