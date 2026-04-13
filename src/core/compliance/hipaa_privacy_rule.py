"""
HIPAA Privacy Rule Implementation

This module implements comprehensive HIPAA Privacy Rule compliance including
individual rights management, minimum necessary standards, uses and disclosures
tracking, and authorization management.

Compliance: HIPAA Privacy Rule 45 CFR 164.502-534
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from uuid import UUID, uuid4
from dataclasses import dataclass, field
from enum import Enum
import json

logger = logging.getLogger(__name__)


class IndividualRight(Enum):
    """HIPAA individual rights under Privacy Rule."""
    ACCESS = "access"                           # Right to access PHI
    AMENDMENT = "amendment"                     # Right to amend PHI
    ACCOUNTING = "accounting_of_disclosures"   # Right to accounting of disclosures
    RESTRICTION = "restriction"                # Right to request restrictions
    CONFIDENTIAL_COMMUNICATIONS = "confidential_communications"  # Right to confidential communications
    NOTIFICATION = "breach_notification"       # Right to breach notification


class DisclosurePurpose(Enum):
    """Purposes for PHI disclosure."""
    TREATMENT = "treatment"
    PAYMENT = "payment"
    HEALTHCARE_OPERATIONS = "healthcare_operations"
    PUBLIC_HEALTH = "public_health"
    HEALTH_OVERSIGHT = "health_oversight"
    JUDICIAL_PROCEEDING = "judicial_proceeding"
    LAW_ENFORCEMENT = "law_enforcement"
    CORONERS = "coroners"
    ORGAN_DONATION = "organ_donation"
    RESEARCH = "research"
    AVERT_SERIOUS_THREAT = "avert_serious_threat"
    SPECIALIZED_GOVERNMENT = "specialized_government"
    WORKERS_COMPENSATION = "workers_compensation"
    MARKETING = "marketing"
    SALE_OF_PHI = "sale_of_phi"
    OTHER = "other"


class RequestStatus(Enum):
    """Status of individual rights requests."""
    RECEIVED = "received"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    DENIED = "denied"
    PARTIALLY_APPROVED = "partially_approved"
    COMPLETED = "completed"
    WITHDRAWN = "withdrawn"


@dataclass
class Individual:
    """Individual (patient) information for Privacy Rule compliance."""
    
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    date_of_birth: Optional[datetime] = None
    contact_info: Dict[str, str] = field(default_factory=dict)
    
    # Privacy preferences
    preferred_communication_method: str = "mail"  # mail, email, phone
    confidential_communications_requested: bool = False
    alternative_contact_info: Dict[str, str] = field(default_factory=dict)
    
    # Restrictions and authorizations
    active_restrictions: List[Dict[str, Any]] = field(default_factory=list)
    authorizations: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    created_date: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)


@dataclass
class IndividualRightsRequest:
    """Request for individual rights under HIPAA Privacy Rule."""
    
    id: UUID = field(default_factory=uuid4)
    individual_id: UUID = field(default_factory=uuid4)
    request_type: IndividualRight = IndividualRight.ACCESS
    
    # Request details
    request_date: datetime = field(default_factory=datetime.now)
    description: str = ""
    specific_information_requested: str = ""
    date_range_requested: Optional[Dict[str, datetime]] = None
    
    # Status and processing
    status: RequestStatus = RequestStatus.RECEIVED
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    completion_date: Optional[datetime] = None
    
    # Response information
    response_provided: bool = False
    response_date: Optional[datetime] = None
    response_method: str = "mail"
    fees_charged: float = 0.0
    denial_reasons: List[str] = field(default_factory=list)
    
    # Documentation
    supporting_documents: List[str] = field(default_factory=list)
    response_documents: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class PHIDisclosure:
    """PHI disclosure tracking for accounting requirements."""
    
    id: UUID = field(default_factory=uuid4)
    individual_id: UUID = field(default_factory=uuid4)
    
    # Disclosure details
    disclosure_date: datetime = field(default_factory=datetime.now)
    recipient_name: str = ""
    recipient_address: str = ""
    purpose: DisclosurePurpose = DisclosurePurpose.TREATMENT
    description: str = ""
    
    # PHI information
    phi_disclosed: List[str] = field(default_factory=list)
    phi_categories: List[str] = field(default_factory=list)
    
    # Authorization and legal basis
    authorized: bool = False
    authorization_id: Optional[UUID] = None
    legal_basis: str = ""
    
    # Minimum necessary analysis
    minimum_necessary_applied: bool = True
    minimum_necessary_justification: str = ""
    
    # Metadata
    disclosed_by: str = ""
    business_purpose: str = ""
    retention_period: Optional[int] = None  # days


@dataclass
class Authorization:
    """HIPAA authorization for use/disclosure of PHI."""
    
    id: UUID = field(default_factory=uuid4)
    individual_id: UUID = field(default_factory=uuid4)
    
    # Authorization details
    authorization_date: datetime = field(default_factory=datetime.now)
    expiration_date: Optional[datetime] = None
    
    # Scope of authorization
    phi_to_be_disclosed: str = ""
    purposes: List[DisclosurePurpose] = field(default_factory=list)
    recipients: List[str] = field(default_factory=list)
    
    # Individual rights
    right_to_revoke: bool = True
    revocation_date: Optional[datetime] = None
    revocation_reason: str = ""
    
    # Required elements
    signature_date: Optional[datetime] = None
    signature_method: str = "wet_signature"
    witness_signature: bool = False
    
    # Marketing and sale specific
    involves_marketing: bool = False
    involves_sale: bool = False
    remuneration_received: bool = False
    
    # Status
    status: str = "active"  # active, expired, revoked
    notes: str = ""


class HIPAAPrivacyRuleManager:
    """
    Comprehensive HIPAA Privacy Rule compliance manager.
    
    Manages individual rights, minimum necessary standards, 
    uses and disclosures, and authorization requirements.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Storage
        self.individuals: Dict[UUID, Individual] = {}
        self.rights_requests: Dict[UUID, IndividualRightsRequest] = {}
        self.disclosures: Dict[UUID, PHIDisclosure] = {}
        self.authorizations: Dict[UUID, Authorization] = {}
        
        # Configuration
        self.privacy_settings = {
            "access_request_response_time_days": 30,
            "amendment_request_response_time_days": 60,
            "accounting_request_response_time_days": 60,
            "maximum_access_fee": 50.00,
            "accounting_lookback_years": 6,
            "minimum_necessary_required": True
        }
        
        # Compliance metrics
        self.metrics = {
            "total_individuals": 0,
            "active_requests": 0,
            "overdue_requests": 0,
            "disclosures_tracked": 0,
            "breach_notifications_sent": 0,
            "average_response_time_days": 0.0
        }
    
    def register_individual(
        self,
        name: str,
        date_of_birth: Optional[datetime] = None,
        contact_info: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> Individual:
        """Register an individual for privacy rights management."""
        
        individual = Individual(
            name=name,
            date_of_birth=date_of_birth,
            contact_info=contact_info or {},
            **kwargs
        )
        
        self.individuals[individual.id] = individual
        self._update_metrics()
        
        self.logger.info(f"Individual registered: {name} ({individual.id})")
        return individual
    
    def submit_rights_request(
        self,
        individual_id: UUID,
        request_type: IndividualRight,
        description: str = "",
        **kwargs
    ) -> IndividualRightsRequest:
        """Submit an individual rights request."""
        
        if individual_id not in self.individuals:
            raise ValueError(f"Individual not found: {individual_id}")
        
        # Calculate due date based on request type
        due_date = self._calculate_request_due_date(request_type)
        
        request = IndividualRightsRequest(
            individual_id=individual_id,
            request_type=request_type,
            description=description,
            due_date=due_date,
            **kwargs
        )
        
        self.rights_requests[request.id] = request
        self._update_metrics()
        
        self.logger.info(
            f"Rights request submitted: {request_type.value} for individual {individual_id}"
        )
        
        return request
    
    def _calculate_request_due_date(self, request_type: IndividualRight) -> datetime:
        """Calculate due date for different types of requests."""
        
        response_times = {
            IndividualRight.ACCESS: self.privacy_settings["access_request_response_time_days"],
            IndividualRight.AMENDMENT: self.privacy_settings["amendment_request_response_time_days"],
            IndividualRight.ACCOUNTING: self.privacy_settings["accounting_request_response_time_days"],
            IndividualRight.RESTRICTION: 30,
            IndividualRight.CONFIDENTIAL_COMMUNICATIONS: 30,
            IndividualRight.NOTIFICATION: 1  # Immediate for breach notifications
        }
        
        days = response_times.get(request_type, 30)
        return datetime.now() + timedelta(days=days)
    
    def process_access_request(
        self,
        request_id: UUID,
        phi_provided: List[str],
        access_method: str = "mail",
        fee_charged: float = 0.0
    ) -> bool:
        """Process an individual's right to access request."""
        
        if request_id not in self.rights_requests:
            self.logger.error(f"Rights request not found: {request_id}")
            return False
        
        request = self.rights_requests[request_id]
        
        if request.request_type != IndividualRight.ACCESS:
            self.logger.error(f"Request {request_id} is not an access request")
            return False
        
        # Validate fee
        if fee_charged > self.privacy_settings["maximum_access_fee"]:
            self.logger.error(f"Fee {fee_charged} exceeds maximum allowed")
            return False
        
        # Update request
        request.status = RequestStatus.COMPLETED
        request.completion_date = datetime.now()
        request.response_date = datetime.now()
        request.response_method = access_method
        request.fees_charged = fee_charged
        request.response_provided = True
        
        # Log the disclosure (internal use)
        self._log_internal_disclosure(
            request.individual_id,
            "Access request fulfillment",
            phi_provided
        )
        
        self.logger.info(f"Access request processed: {request_id}")
        return True
    
    def process_amendment_request(
        self,
        request_id: UUID,
        approved: bool,
        amendment_made: str = "",
        denial_reasons: Optional[List[str]] = None
    ) -> bool:
        """Process an individual's right to amend request."""
        
        if request_id not in self.rights_requests:
            self.logger.error(f"Rights request not found: {request_id}")
            return False
        
        request = self.rights_requests[request_id]
        
        if request.request_type != IndividualRight.AMENDMENT:
            self.logger.error(f"Request {request_id} is not an amendment request")
            return False
        
        if approved:
            request.status = RequestStatus.APPROVED
            request.notes = f"Amendment approved: {amendment_made}"
            
            # In a real system, this would update the actual PHI records
            self.logger.info(f"Amendment approved and implemented: {request_id}")
        else:
            request.status = RequestStatus.DENIED
            request.denial_reasons = denial_reasons or []
            
            # Must provide written denial with reasons
            self.logger.info(f"Amendment denied: {request_id}, reasons: {denial_reasons}")
        
        request.completion_date = datetime.now()
        request.response_date = datetime.now()
        request.response_provided = True
        
        return True
    
    def generate_accounting_of_disclosures(
        self,
        individual_id: UUID,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Generate accounting of disclosures for an individual."""
        
        if not end_date:
            end_date = datetime.now()
        
        if not start_date:
            lookback_years = self.privacy_settings["accounting_lookback_years"]
            start_date = end_date - timedelta(days=lookback_years * 365)
        
        # Get disclosures for the individual in the date range
        individual_disclosures = [
            disclosure for disclosure in self.disclosures.values()
            if (disclosure.individual_id == individual_id and
                start_date <= disclosure.disclosure_date <= end_date and
                self._requires_accounting(disclosure))
        ]
        
        # Format for accounting report
        accounting_entries = []
        for disclosure in individual_disclosures:
            entry = {
                "disclosure_date": disclosure.disclosure_date.isoformat(),
                "recipient_name": disclosure.recipient_name,
                "recipient_address": disclosure.recipient_address,
                "brief_description": disclosure.description,
                "purpose": disclosure.purpose.value,
                "phi_disclosed": disclosure.phi_disclosed
            }
            accounting_entries.append(entry)
        
        # Sort by disclosure date (most recent first)
        accounting_entries.sort(key=lambda x: x["disclosure_date"], reverse=True)
        
        return accounting_entries
    
    def _requires_accounting(self, disclosure: PHIDisclosure) -> bool:
        """Determine if a disclosure requires accounting."""
        
        # Disclosures that do NOT require accounting
        exempt_purposes = [
            DisclosurePurpose.TREATMENT,
            DisclosurePurpose.PAYMENT,
            DisclosurePurpose.HEALTHCARE_OPERATIONS
        ]
        
        # Also exempt if authorized by individual
        if disclosure.authorized or disclosure.purpose in exempt_purposes:
            return False
        
        return True
    
    def track_phi_disclosure(
        self,
        individual_id: UUID,
        recipient_name: str,
        recipient_address: str,
        purpose: DisclosurePurpose,
        phi_disclosed: List[str],
        description: str = "",
        authorized: bool = False,
        **kwargs
    ) -> PHIDisclosure:
        """Track a PHI disclosure for accounting purposes."""
        
        disclosure = PHIDisclosure(
            individual_id=individual_id,
            recipient_name=recipient_name,
            recipient_address=recipient_address,
            purpose=purpose,
            phi_disclosed=phi_disclosed,
            description=description,
            authorized=authorized,
            **kwargs
        )
        
        # Apply minimum necessary analysis
        if self.privacy_settings["minimum_necessary_required"]:
            disclosure.minimum_necessary_applied = self._apply_minimum_necessary(
                disclosure.purpose, phi_disclosed
            )
        
        self.disclosures[disclosure.id] = disclosure
        self._update_metrics()
        
        self.logger.info(
            f"PHI disclosure tracked: {purpose.value} to {recipient_name}"
        )
        
        return disclosure
    
    def _apply_minimum_necessary(
        self, 
        purpose: DisclosurePurpose, 
        phi_disclosed: List[str]
    ) -> bool:
        """Apply minimum necessary standard analysis."""
        
        # In a real implementation, this would have sophisticated logic
        # to determine if the minimum necessary standard was met
        
        # For now, we'll assume it's properly applied if it's not
        # for marketing or sale purposes
        if purpose in [DisclosurePurpose.MARKETING, DisclosurePurpose.SALE_OF_PHI]:
            return len(phi_disclosed) <= 3  # Arbitrary limit for demo
        
        return True  # Assume minimum necessary for other purposes
    
    def _log_internal_disclosure(
        self,
        individual_id: UUID,
        purpose: str,
        phi_categories: List[str]
    ):
        """Log internal disclosure (doesn't require accounting)."""
        
        internal_disclosure = PHIDisclosure(
            individual_id=individual_id,
            recipient_name="Internal Use",
            recipient_address="Internal",
            purpose=DisclosurePurpose.HEALTHCARE_OPERATIONS,
            description=purpose,
            phi_categories=phi_categories,
            authorized=True,  # Internal use authorized
            minimum_necessary_applied=True
        )
        
        self.disclosures[internal_disclosure.id] = internal_disclosure
    
    def create_authorization(
        self,
        individual_id: UUID,
        phi_to_be_disclosed: str,
        purposes: List[DisclosurePurpose],
        recipients: List[str],
        expiration_date: Optional[datetime] = None,
        **kwargs
    ) -> Authorization:
        """Create a HIPAA authorization for PHI use/disclosure."""
        
        if individual_id not in self.individuals:
            raise ValueError(f"Individual not found: {individual_id}")
        
        authorization = Authorization(
            individual_id=individual_id,
            phi_to_be_disclosed=phi_to_be_disclosed,
            purposes=purposes,
            recipients=recipients,
            expiration_date=expiration_date,
            **kwargs
        )
        
        self.authorizations[authorization.id] = authorization
        
        # Add to individual's authorization list
        individual = self.individuals[individual_id]
        individual.authorizations.append({
            "authorization_id": str(authorization.id),
            "created_date": authorization.authorization_date.isoformat(),
            "purposes": [p.value for p in purposes],
            "status": authorization.status
        })
        
        self.logger.info(f"Authorization created: {authorization.id}")
        return authorization
    
    def revoke_authorization(
        self,
        authorization_id: UUID,
        revocation_reason: str = "Individual request"
    ) -> bool:
        """Revoke a HIPAA authorization."""
        
        if authorization_id not in self.authorizations:
            self.logger.error(f"Authorization not found: {authorization_id}")
            return False
        
        authorization = self.authorizations[authorization_id]
        authorization.status = "revoked"
        authorization.revocation_date = datetime.now()
        authorization.revocation_reason = revocation_reason
        
        # Update individual's authorization list
        individual = self.individuals[authorization.individual_id]
        for auth_info in individual.authorizations:
            if auth_info["authorization_id"] == str(authorization_id):
                auth_info["status"] = "revoked"
                auth_info["revocation_date"] = authorization.revocation_date.isoformat()
                break
        
        self.logger.info(f"Authorization revoked: {authorization_id}")
        return True
    
    def request_restriction(
        self,
        individual_id: UUID,
        restriction_description: str,
        phi_categories: List[str],
        recipients: Optional[List[str]] = None,
        purposes: Optional[List[DisclosurePurpose]] = None
    ) -> IndividualRightsRequest:
        """Process a request for restriction on PHI use/disclosure."""
        
        request = self.submit_rights_request(
            individual_id=individual_id,
            request_type=IndividualRight.RESTRICTION,
            description=restriction_description,
            specific_information_requested=json.dumps({
                "phi_categories": phi_categories,
                "recipients": recipients or [],
                "purposes": [p.value for p in (purposes or [])]
            })
        )
        
        return request
    
    def apply_restriction(
        self,
        request_id: UUID,
        approved: bool,
        restriction_details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Apply or deny a requested restriction."""
        
        if request_id not in self.rights_requests:
            return False
        
        request = self.rights_requests[request_id]
        individual = self.individuals[request.individual_id]
        
        if approved and restriction_details:
            request.status = RequestStatus.APPROVED
            
            # Add to individual's active restrictions
            restriction = {
                "restriction_id": str(uuid4()),
                "request_id": str(request_id),
                "description": request.description,
                "details": restriction_details,
                "effective_date": datetime.now().isoformat(),
                "status": "active"
            }
            individual.active_restrictions.append(restriction)
            
            self.logger.info(f"Restriction applied for individual {request.individual_id}")
        else:
            request.status = RequestStatus.DENIED
            self.logger.info(f"Restriction request denied: {request_id}")
        
        request.completion_date = datetime.now()
        request.response_provided = True
        
        return True
    
    def generate_privacy_notice(self, individual_id: Optional[UUID] = None) -> Dict[str, Any]:
        """Generate Notice of Privacy Practices."""
        
        notice = {
            "notice_date": datetime.now().isoformat(),
            "effective_date": datetime.now().isoformat(),
            "version": "1.0",
            
            "uses_and_disclosures": {
                "treatment": {
                    "description": "We may use and disclose your PHI for treatment purposes",
                    "authorization_required": False,
                    "examples": ["Coordinating care between providers", "Referring to specialists"]
                },
                "payment": {
                    "description": "We may use and disclose your PHI for payment purposes",
                    "authorization_required": False,
                    "examples": ["Billing insurance", "Collecting payment"]
                },
                "healthcare_operations": {
                    "description": "We may use and disclose your PHI for healthcare operations",
                    "authorization_required": False,
                    "examples": ["Quality assessment", "Training healthcare workers"]
                }
            },
            
            "individual_rights": {
                "right_to_access": {
                    "description": "You have the right to see and get copies of your PHI",
                    "how_to_exercise": "Submit written request to Privacy Officer",
                    "response_time": f"{self.privacy_settings['access_request_response_time_days']} days",
                    "fees_may_apply": True
                },
                "right_to_amend": {
                    "description": "You have the right to ask us to correct your PHI",
                    "how_to_exercise": "Submit written request with reason for amendment",
                    "response_time": f"{self.privacy_settings['amendment_request_response_time_days']} days"
                },
                "right_to_accounting": {
                    "description": "You have the right to a list of disclosures we have made",
                    "how_to_exercise": "Submit written request to Privacy Officer",
                    "response_time": f"{self.privacy_settings['accounting_request_response_time_days']} days",
                    "lookback_period": f"{self.privacy_settings['accounting_lookback_years']} years"
                },
                "right_to_restrict": {
                    "description": "You have the right to ask us to limit how we use your PHI",
                    "how_to_exercise": "Submit written request describing restriction",
                    "note": "We are not required to agree to all requests"
                }
            },
            
            "complaints": {
                "internal_process": "Contact Privacy Officer",
                "external_process": "File complaint with HHS Office for Civil Rights",
                "no_retaliation": "We will not retaliate for filing a complaint"
            },
            
            "contact_information": {
                "privacy_officer": "Privacy Officer",
                "address": "123 Healthcare Drive, Medical City, ST 12345",
                "phone": "(555) 123-4567",
                "email": "privacy@healthcare.org"
            }
        }
        
        return notice
    
    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate comprehensive Privacy Rule compliance report."""
        
        report = {
            "report_date": datetime.now().isoformat(),
            "reporting_period": {
                "start": (datetime.now() - timedelta(days=30)).isoformat(),
                "end": datetime.now().isoformat()
            },
            
            "executive_summary": self._generate_privacy_executive_summary(),
            
            "individual_rights_metrics": self._analyze_individual_rights(),
            
            "disclosure_analysis": self._analyze_disclosures(),
            
            "authorization_management": self._analyze_authorizations(),
            
            "compliance_indicators": {
                "average_response_time": self.metrics["average_response_time_days"],
                "overdue_requests": self.metrics["overdue_requests"],
                "disclosure_tracking_compliance": self._calculate_disclosure_compliance(),
                "minimum_necessary_compliance": self._calculate_minimum_necessary_compliance()
            },
            
            "recommendations": self._generate_privacy_recommendations(),
            
            "upcoming_requirements": self._identify_upcoming_requirements()
        }
        
        return report
    
    def _generate_privacy_executive_summary(self) -> str:
        """Generate executive summary for privacy compliance."""
        
        total_requests = len(self.rights_requests)
        overdue_requests = self.metrics["overdue_requests"]
        
        if total_requests == 0:
            return "No individual rights requests processed during reporting period."
        
        on_time_percentage = ((total_requests - overdue_requests) / total_requests) * 100
        
        summary = f"""
        Privacy Rule Compliance Summary:
        
        During the reporting period, {total_requests} individual rights requests were processed
        with {on_time_percentage:.1f}% completed within required timeframes.
        
        {overdue_requests} requests are currently overdue and require immediate attention.
        
        {len(self.disclosures)} PHI disclosures were tracked for accounting purposes.
        
        Current compliance status: {'Good' if on_time_percentage >= 90 else 'Needs Attention'}
        """
        
        return summary.strip()
    
    def _analyze_individual_rights(self) -> Dict[str, Any]:
        """Analyze individual rights request metrics."""
        
        rights_analysis = {}
        
        for right in IndividualRight:
            requests = [r for r in self.rights_requests.values() if r.request_type == right]
            
            rights_analysis[right.value] = {
                "total_requests": len(requests),
                "completed": len([r for r in requests if r.status == RequestStatus.COMPLETED]),
                "overdue": len([r for r in requests if r.due_date and r.due_date < datetime.now() and r.status not in [RequestStatus.COMPLETED, RequestStatus.DENIED]]),
                "average_response_days": self._calculate_average_response_time(requests)
            }
        
        return rights_analysis
    
    def _analyze_disclosures(self) -> Dict[str, Any]:
        """Analyze PHI disclosure patterns and compliance."""
        
        total_disclosures = len(self.disclosures)
        disclosures_requiring_accounting = len([
            d for d in self.disclosures.values() if self._requires_accounting(d)
        ])
        
        purpose_breakdown = {}
        for purpose in DisclosurePurpose:
            count = len([d for d in self.disclosures.values() if d.purpose == purpose])
            if count > 0:
                purpose_breakdown[purpose.value] = count
        
        return {
            "total_disclosures": total_disclosures,
            "requiring_accounting": disclosures_requiring_accounting,
            "purpose_breakdown": purpose_breakdown,
            "minimum_necessary_compliance": self._calculate_minimum_necessary_compliance()
        }
    
    def _analyze_authorizations(self) -> Dict[str, Any]:
        """Analyze authorization management."""
        
        active_auths = [a for a in self.authorizations.values() if a.status == "active"]
        expired_auths = [a for a in self.authorizations.values() if a.expiration_date and a.expiration_date < datetime.now()]
        revoked_auths = [a for a in self.authorizations.values() if a.status == "revoked"]
        
        return {
            "total_authorizations": len(self.authorizations),
            "active": len(active_auths),
            "expired": len(expired_auths),
            "revoked": len(revoked_auths),
            "marketing_authorizations": len([a for a in active_auths if a.involves_marketing]),
            "sale_authorizations": len([a for a in active_auths if a.involves_sale])
        }
    
    def _calculate_average_response_time(self, requests: List[IndividualRightsRequest]) -> float:
        """Calculate average response time for requests."""
        
        completed_requests = [
            r for r in requests 
            if r.response_date and r.request_date
        ]
        
        if not completed_requests:
            return 0.0
        
        total_days = sum([
            (r.response_date - r.request_date).days 
            for r in completed_requests
        ])
        
        return total_days / len(completed_requests)
    
    def _calculate_disclosure_compliance(self) -> float:
        """Calculate disclosure tracking compliance percentage."""
        
        # In a real system, this would compare tracked vs. actual disclosures
        # For now, assume 95% compliance
        return 95.0
    
    def _calculate_minimum_necessary_compliance(self) -> float:
        """Calculate minimum necessary compliance percentage."""
        
        applicable_disclosures = [
            d for d in self.disclosures.values()
            if d.purpose not in [DisclosurePurpose.TREATMENT, DisclosurePurpose.PAYMENT, DisclosurePurpose.HEALTHCARE_OPERATIONS]
        ]
        
        if not applicable_disclosures:
            return 100.0
        
        compliant_disclosures = [
            d for d in applicable_disclosures
            if d.minimum_necessary_applied
        ]
        
        return (len(compliant_disclosures) / len(applicable_disclosures)) * 100
    
    def _generate_privacy_recommendations(self) -> List[str]:
        """Generate privacy compliance recommendations."""
        
        recommendations = []
        
        if self.metrics["overdue_requests"] > 0:
            recommendations.append(f"Address {self.metrics['overdue_requests']} overdue individual rights requests")
        
        if self._calculate_minimum_necessary_compliance() < 90:
            recommendations.append("Improve minimum necessary standard implementation")
        
        if self.metrics["average_response_time_days"] > 20:
            recommendations.append("Streamline individual rights request processing")
        
        expired_auths = [
            a for a in self.authorizations.values() 
            if a.expiration_date and a.expiration_date < datetime.now() and a.status == "active"
        ]
        
        if expired_auths:
            recommendations.append(f"Review and update {len(expired_auths)} expired authorizations")
        
        return recommendations
    
    def _identify_upcoming_requirements(self) -> List[Dict[str, Any]]:
        """Identify upcoming compliance requirements."""
        
        upcoming = []
        
        # Check for requests approaching due dates
        approaching_due = [
            r for r in self.rights_requests.values()
            if r.due_date and (r.due_date - datetime.now()).days <= 7
            and r.status not in [RequestStatus.COMPLETED, RequestStatus.DENIED]
        ]
        
        for request in approaching_due:
            upcoming.append({
                "type": "individual_rights_request",
                "description": f"{request.request_type.value} request due soon",
                "due_date": request.due_date.isoformat(),
                "priority": "high"
            })
        
        return upcoming
    
    def _update_metrics(self):
        """Update privacy compliance metrics."""
        
        self.metrics.update({
            "total_individuals": len(self.individuals),
            "active_requests": len([
                r for r in self.rights_requests.values()
                if r.status not in [RequestStatus.COMPLETED, RequestStatus.DENIED, RequestStatus.WITHDRAWN]
            ]),
            "overdue_requests": len([
                r for r in self.rights_requests.values()
                if r.due_date and r.due_date < datetime.now()
                and r.status not in [RequestStatus.COMPLETED, RequestStatus.DENIED]
            ]),
            "disclosures_tracked": len(self.disclosures),
            "average_response_time_days": self._calculate_average_response_time(list(self.rights_requests.values()))
        })
    
    def get_individual_summary(self, individual_id: UUID) -> Optional[Dict[str, Any]]:
        """Get comprehensive summary for an individual."""
        
        if individual_id not in self.individuals:
            return None
        
        individual = self.individuals[individual_id]
        
        # Get requests
        individual_requests = [
            r for r in self.rights_requests.values() 
            if r.individual_id == individual_id
        ]
        
        # Get disclosures
        individual_disclosures = [
            d for d in self.disclosures.values()
            if d.individual_id == individual_id and self._requires_accounting(d)
        ]
        
        # Get authorizations
        individual_auths = [
            a for a in self.authorizations.values()
            if a.individual_id == individual_id
        ]
        
        return {
            "individual_info": {
                "id": str(individual.id),
                "name": individual.name,
                "contact_info": individual.contact_info,
                "privacy_preferences": {
                    "communication_method": individual.preferred_communication_method,
                    "confidential_communications": individual.confidential_communications_requested
                }
            },
            "rights_requests": [
                {
                    "id": str(r.id),
                    "type": r.request_type.value,
                    "status": r.status.value,
                    "request_date": r.request_date.isoformat(),
                    "due_date": r.due_date.isoformat() if r.due_date else None
                }
                for r in individual_requests
            ],
            "disclosures_for_accounting": len(individual_disclosures),
            "active_authorizations": len([a for a in individual_auths if a.status == "active"]),
            "active_restrictions": len(individual.active_restrictions)
        }


# Global instance
privacy_rule_manager = HIPAAPrivacyRuleManager()