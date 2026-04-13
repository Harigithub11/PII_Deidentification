"""
GDPR Data Protection Impact Assessment (DPIA) System (Article 35)
Comprehensive DPIA automation, risk assessment, and compliance management
"""
from typing import Dict, List, Optional, Any, Union, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import uuid
import json
from datetime import datetime, timedelta
import logging
from pathlib import Path
import asyncio

from ..database.db_manager import DatabaseManager
from ..security.encryption_manager import EncryptionManager
from ..config.settings import get_settings


logger = logging.getLogger(__name__)
settings = get_settings()


class DPIATrigger(Enum):
    """DPIA trigger criteria under Article 35"""
    SYSTEMATIC_MONITORING = "systematic_monitoring"
    LARGE_SCALE_SENSITIVE_DATA = "large_scale_sensitive_data"
    SYSTEMATIC_EVALUATION = "systematic_evaluation"
    AUTOMATED_DECISION_MAKING = "automated_decision_making"
    BIOMETRIC_DATA = "biometric_data"
    GENETIC_DATA = "genetic_data"
    VULNERABLE_INDIVIDUALS = "vulnerable_individuals"
    INNOVATIVE_TECHNOLOGY = "innovative_technology"
    CROSS_BORDER_TRANSFER = "cross_border_transfer"
    DATA_MATCHING = "data_matching"
    HIGH_RISK_PROCESSING = "high_risk_processing"


class RiskLevel(Enum):
    """Risk assessment levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class DPIAStatus(Enum):
    """DPIA process status"""
    DRAFT = "draft"
    UNDER_REVIEW = "under_review"
    STAKEHOLDER_CONSULTATION = "stakeholder_consultation"
    DPO_REVIEW = "dpo_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    REQUIRES_CONSULTATION = "requires_consultation"  # Supervisory Authority consultation
    COMPLETED = "completed"


class ProcessingCategory(Enum):
    """Categories of personal data processing"""
    IDENTIFICATION_DATA = "identification_data"
    CONTACT_INFORMATION = "contact_information"
    FINANCIAL_DATA = "financial_data"
    HEALTH_DATA = "health_data"
    BIOMETRIC_DATA = "biometric_data"
    GENETIC_DATA = "genetic_data"
    LOCATION_DATA = "location_data"
    BEHAVIORAL_DATA = "behavioral_data"
    COMMUNICATIONS_DATA = "communications_data"
    EMPLOYMENT_DATA = "employment_data"
    EDUCATION_DATA = "education_data"
    CRIMINAL_DATA = "criminal_data"


@dataclass
class RiskFactor:
    """Individual risk factor in DPIA"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: str = ""
    description: str = ""
    likelihood: RiskLevel = RiskLevel.LOW
    impact: RiskLevel = RiskLevel.LOW
    risk_score: float = 0.0
    mitigation_measures: List[str] = field(default_factory=list)
    residual_risk: RiskLevel = RiskLevel.LOW
    
    def calculate_risk_score(self) -> float:
        """Calculate numeric risk score from likelihood and impact"""
        likelihood_values = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.VERY_HIGH: 4
        }
        
        impact_values = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.VERY_HIGH: 4
        }
        
        self.risk_score = likelihood_values[self.likelihood] * impact_values[self.impact]
        return self.risk_score
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "description": self.description,
            "likelihood": self.likelihood.value,
            "impact": self.impact.value,
            "risk_score": self.risk_score,
            "mitigation_measures": self.mitigation_measures,
            "residual_risk": self.residual_risk.value
        }


@dataclass
class ProcessingOperation:
    """Processing operation details for DPIA"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    purpose: str = ""
    legal_basis: str = ""
    data_categories: List[ProcessingCategory] = field(default_factory=list)
    data_subjects: List[str] = field(default_factory=list)  # Categories of data subjects
    recipients: List[str] = field(default_factory=list)
    retention_period: int = 365  # days
    transfers: List[str] = field(default_factory=list)  # Third countries/organizations
    automated_decision_making: bool = False
    profiling: bool = False
    large_scale: bool = False
    vulnerable_subjects: bool = False
    innovative_technology: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "purpose": self.purpose,
            "legal_basis": self.legal_basis,
            "data_categories": [cat.value for cat in self.data_categories],
            "data_subjects": self.data_subjects,
            "recipients": self.recipients,
            "retention_period": self.retention_period,
            "transfers": self.transfers,
            "automated_decision_making": self.automated_decision_making,
            "profiling": self.profiling,
            "large_scale": self.large_scale,
            "vulnerable_subjects": self.vulnerable_subjects,
            "innovative_technology": self.innovative_technology
        }


@dataclass
class StakeholderInput:
    """Stakeholder consultation input"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    stakeholder_name: str = ""
    stakeholder_role: str = ""
    contact_info: str = ""
    consultation_date: datetime = field(default_factory=datetime.now)
    input_method: str = "written"  # written, meeting, survey, etc.
    concerns_raised: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    privacy_expectations: List[str] = field(default_factory=list)
    mitigation_recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "stakeholder_name": self.stakeholder_name,
            "stakeholder_role": self.stakeholder_role,
            "contact_info": self.contact_info,
            "consultation_date": self.consultation_date.isoformat(),
            "input_method": self.input_method,
            "concerns_raised": self.concerns_raised,
            "suggestions": self.suggestions,
            "privacy_expectations": self.privacy_expectations,
            "mitigation_recommendations": self.mitigation_recommendations
        }


@dataclass
class DPIAAssessment:
    """Complete DPIA assessment"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    status: DPIAStatus = DPIAStatus.DRAFT
    created_date: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    completion_date: Optional[datetime] = None
    
    # Assessment team
    data_controller: str = ""
    data_protection_officer: str = ""
    assessor: str = ""
    reviewers: List[str] = field(default_factory=list)
    
    # Processing operation
    processing_operation: Optional[ProcessingOperation] = None
    triggers: List[DPIATrigger] = field(default_factory=list)
    
    # Risk assessment
    risk_factors: List[RiskFactor] = field(default_factory=list)
    overall_risk_level: RiskLevel = RiskLevel.LOW
    residual_risk_level: RiskLevel = RiskLevel.LOW
    
    # Stakeholder consultation
    stakeholder_consultation_required: bool = False
    stakeholder_inputs: List[StakeholderInput] = field(default_factory=list)
    
    # Mitigation measures
    mitigation_measures: List[str] = field(default_factory=list)
    implementation_timeline: Dict[str, datetime] = field(default_factory=dict)
    responsible_parties: Dict[str, str] = field(default_factory=dict)
    
    # Supervisory Authority consultation
    sa_consultation_required: bool = False
    sa_consultation_date: Optional[datetime] = None
    sa_response_date: Optional[datetime] = None
    sa_recommendations: List[str] = field(default_factory=list)
    
    # Review and monitoring
    review_date: Optional[datetime] = None
    monitoring_measures: List[str] = field(default_factory=list)
    
    # Documentation
    supporting_documents: List[str] = field(default_factory=list)
    version: str = "1.0"
    
    def calculate_overall_risk(self):
        """Calculate overall risk level from individual risk factors"""
        if not self.risk_factors:
            self.overall_risk_level = RiskLevel.LOW
            return
        
        # Calculate average risk score
        total_score = sum(rf.calculate_risk_score() for rf in self.risk_factors)
        avg_score = total_score / len(self.risk_factors)
        
        # Map to risk level
        if avg_score <= 4:
            self.overall_risk_level = RiskLevel.LOW
        elif avg_score <= 8:
            self.overall_risk_level = RiskLevel.MEDIUM
        elif avg_score <= 12:
            self.overall_risk_level = RiskLevel.HIGH
        else:
            self.overall_risk_level = RiskLevel.VERY_HIGH
        
        # Check if Supervisory Authority consultation is required
        if self.overall_risk_level in [RiskLevel.HIGH, RiskLevel.VERY_HIGH]:
            self.sa_consultation_required = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "created_date": self.created_date.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "completion_date": self.completion_date.isoformat() if self.completion_date else None,
            "data_controller": self.data_controller,
            "data_protection_officer": self.data_protection_officer,
            "assessor": self.assessor,
            "reviewers": self.reviewers,
            "processing_operation": self.processing_operation.to_dict() if self.processing_operation else None,
            "triggers": [trigger.value for trigger in self.triggers],
            "risk_factors": [rf.to_dict() for rf in self.risk_factors],
            "overall_risk_level": self.overall_risk_level.value,
            "residual_risk_level": self.residual_risk_level.value,
            "stakeholder_consultation_required": self.stakeholder_consultation_required,
            "stakeholder_inputs": [si.to_dict() for si in self.stakeholder_inputs],
            "mitigation_measures": self.mitigation_measures,
            "sa_consultation_required": self.sa_consultation_required,
            "sa_consultation_date": self.sa_consultation_date.isoformat() if self.sa_consultation_date else None,
            "sa_response_date": self.sa_response_date.isoformat() if self.sa_response_date else None,
            "sa_recommendations": self.sa_recommendations,
            "review_date": self.review_date.isoformat() if self.review_date else None,
            "monitoring_measures": self.monitoring_measures,
            "supporting_documents": self.supporting_documents,
            "version": self.version
        }


class DPIASystem:
    """Comprehensive DPIA management system"""
    
    def __init__(self,
                 db_manager: DatabaseManager,
                 encryption_manager: EncryptionManager):
        self.db_manager = db_manager
        self.encryption_manager = encryption_manager
        self.logger = logging.getLogger(__name__)
        
        # In-memory storage (in production, this would be database-backed)
        self.assessments: Dict[str, DPIAAssessment] = {}
        self.assessment_templates: Dict[str, Dict[str, Any]] = {}
        
        # Initialize assessment templates
        self._initialize_assessment_templates()
    
    def _initialize_assessment_templates(self):
        """Initialize DPIA assessment templates"""
        
        # Standard DPIA template
        standard_template = {
            "name": "Standard DPIA Template",
            "description": "Standard DPIA template for general processing operations",
            "sections": [
                {
                    "title": "Processing Operation Description",
                    "questions": [
                        "What is the nature, scope, context and purposes of the processing?",
                        "What personal data will be processed?",
                        "Who are the data subjects?",
                        "What is the legal basis for processing?",
                        "How long will data be retained?"
                    ]
                },
                {
                    "title": "Necessity and Proportionality",
                    "questions": [
                        "Is the processing necessary for the stated purpose?",
                        "Are the data minimization principles applied?",
                        "Is the processing proportionate to the purpose?",
                        "Could the purpose be achieved with less intrusive means?"
                    ]
                },
                {
                    "title": "Risk Assessment",
                    "questions": [
                        "What are the potential risks to data subjects?",
                        "What is the likelihood of these risks occurring?",
                        "What would be the impact if these risks occurred?",
                        "Are vulnerable groups particularly affected?"
                    ]
                },
                {
                    "title": "Risk Mitigation",
                    "questions": [
                        "What measures can be implemented to mitigate risks?",
                        "How will technical and organizational measures be implemented?",
                        "What safeguards will protect data subjects' rights?",
                        "How will the effectiveness of measures be monitored?"
                    ]
                }
            ]
        }
        
        self.assessment_templates["standard"] = standard_template
        
        # High-risk processing template
        high_risk_template = {
            "name": "High-Risk Processing DPIA Template",
            "description": "Enhanced DPIA template for high-risk processing operations",
            "sections": standard_template["sections"] + [
                {
                    "title": "Automated Decision-Making and Profiling",
                    "questions": [
                        "Does the processing involve automated decision-making?",
                        "What is the logic behind automated decisions?",
                        "What safeguards exist for data subjects?",
                        "How can data subjects challenge decisions?"
                    ]
                },
                {
                    "title": "Data Transfers",
                    "questions": [
                        "Will data be transferred outside the EEA?",
                        "What are the adequacy arrangements or appropriate safeguards?",
                        "What additional risks does the transfer create?",
                        "How will international transfer compliance be maintained?"
                    ]
                },
                {
                    "title": "Stakeholder Consultation",
                    "questions": [
                        "Which stakeholders should be consulted?",
                        "What are their main concerns and expectations?",
                        "How will their views be incorporated?",
                        "What ongoing engagement is planned?"
                    ]
                }
            ]
        }
        
        self.assessment_templates["high_risk"] = high_risk_template
    
    async def trigger_dpia_assessment(self, processing_operation: ProcessingOperation) -> Optional[str]:
        """Determine if DPIA is required and trigger assessment"""
        
        triggers = self._identify_dpia_triggers(processing_operation)
        
        if not triggers:
            self.logger.info(f"No DPIA triggers identified for operation: {processing_operation.name}")
            return None
        
        # Create DPIA assessment
        assessment = DPIAAssessment(
            title=f"DPIA for {processing_operation.name}",
            description=f"Data Protection Impact Assessment for {processing_operation.description}",
            processing_operation=processing_operation,
            triggers=triggers,
            data_controller="De-identification System Organization",
            assessor="Privacy Team"
        )
        
        # Determine if stakeholder consultation is required
        assessment.stakeholder_consultation_required = self._requires_stakeholder_consultation(triggers)
        
        # Store assessment
        self.assessments[assessment.id] = assessment
        
        # Log DPIA initiation
        await self._log_dpia_event(assessment, "dpia_initiated", {
            "triggers": [trigger.value for trigger in triggers]
        })
        
        self.logger.info(f"DPIA assessment initiated: {assessment.id} for operation: {processing_operation.name}")
        
        return assessment.id
    
    def _identify_dpia_triggers(self, operation: ProcessingOperation) -> List[DPIATrigger]:
        """Identify DPIA trigger criteria for processing operation"""
        
        triggers = []
        
        # Check for systematic monitoring
        if "monitoring" in operation.description.lower() or "tracking" in operation.description.lower():
            triggers.append(DPIATrigger.SYSTEMATIC_MONITORING)
        
        # Check for large-scale sensitive data processing
        sensitive_categories = [
            ProcessingCategory.HEALTH_DATA,
            ProcessingCategory.BIOMETRIC_DATA,
            ProcessingCategory.GENETIC_DATA,
            ProcessingCategory.CRIMINAL_DATA
        ]
        
        if (operation.large_scale and 
            any(cat in operation.data_categories for cat in sensitive_categories)):
            triggers.append(DPIATrigger.LARGE_SCALE_SENSITIVE_DATA)
        
        # Check for automated decision-making
        if operation.automated_decision_making:
            triggers.append(DPIATrigger.AUTOMATED_DECISION_MAKING)
        
        # Check for profiling
        if operation.profiling:
            triggers.append(DPIATrigger.SYSTEMATIC_EVALUATION)
        
        # Check for biometric data
        if ProcessingCategory.BIOMETRIC_DATA in operation.data_categories:
            triggers.append(DPIATrigger.BIOMETRIC_DATA)
        
        # Check for genetic data
        if ProcessingCategory.GENETIC_DATA in operation.data_categories:
            triggers.append(DPIATrigger.GENETIC_DATA)
        
        # Check for vulnerable individuals
        if operation.vulnerable_subjects or "children" in operation.data_subjects:
            triggers.append(DPIATrigger.VULNERABLE_INDIVIDUALS)
        
        # Check for innovative technology
        if operation.innovative_technology:
            triggers.append(DPIATrigger.INNOVATIVE_TECHNOLOGY)
        
        # Check for cross-border transfers
        if operation.transfers:
            triggers.append(DPIATrigger.CROSS_BORDER_TRANSFER)
        
        return triggers
    
    def _requires_stakeholder_consultation(self, triggers: List[DPIATrigger]) -> bool:
        """Determine if stakeholder consultation is required"""
        
        high_impact_triggers = [
            DPIATrigger.SYSTEMATIC_MONITORING,
            DPIATrigger.VULNERABLE_INDIVIDUALS,
            DPIATrigger.AUTOMATED_DECISION_MAKING,
            DPIATrigger.LARGE_SCALE_SENSITIVE_DATA
        ]
        
        return any(trigger in triggers for trigger in high_impact_triggers)
    
    async def conduct_risk_assessment(self, assessment_id: str, risk_factors: List[Dict[str, Any]]) -> bool:
        """Conduct risk assessment for DPIA"""
        
        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return False
        
        # Create risk factor objects
        assessment.risk_factors = []
        for rf_data in risk_factors:
            risk_factor = RiskFactor(
                category=rf_data.get("category", ""),
                description=rf_data.get("description", ""),
                likelihood=RiskLevel(rf_data.get("likelihood", "low")),
                impact=RiskLevel(rf_data.get("impact", "low")),
                mitigation_measures=rf_data.get("mitigation_measures", [])
            )
            risk_factor.calculate_risk_score()
            assessment.risk_factors.append(risk_factor)
        
        # Calculate overall risk
        assessment.calculate_overall_risk()
        
        # Update status
        assessment.status = DPIAStatus.UNDER_REVIEW
        assessment.last_updated = datetime.now()
        
        await self._log_dpia_event(assessment, "risk_assessment_completed", {
            "overall_risk_level": assessment.overall_risk_level.value,
            "risk_factors_count": len(assessment.risk_factors)
        })
        
        self.logger.info(f"Risk assessment completed for DPIA {assessment_id}: {assessment.overall_risk_level.value}")
        
        return True
    
    async def conduct_stakeholder_consultation(self, 
                                             assessment_id: str, 
                                             consultation_plan: Dict[str, Any]) -> bool:
        """Conduct stakeholder consultation for DPIA"""
        
        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return False
        
        if not assessment.stakeholder_consultation_required:
            self.logger.info(f"Stakeholder consultation not required for DPIA {assessment_id}")
            return True
        
        assessment.status = DPIAStatus.STAKEHOLDER_CONSULTATION
        assessment.last_updated = datetime.now()
        
        # In production, this would manage actual consultation process
        # For now, simulate consultation
        
        stakeholders = consultation_plan.get("stakeholders", [])
        consultation_method = consultation_plan.get("method", "written")
        consultation_period = consultation_plan.get("period_days", 30)
        
        # Create stakeholder input records
        for stakeholder in stakeholders:
            stakeholder_input = StakeholderInput(
                stakeholder_name=stakeholder.get("name", ""),
                stakeholder_role=stakeholder.get("role", ""),
                contact_info=stakeholder.get("contact", ""),
                input_method=consultation_method,
                concerns_raised=stakeholder.get("concerns", []),
                suggestions=stakeholder.get("suggestions", []),
                privacy_expectations=stakeholder.get("expectations", [])
            )
            assessment.stakeholder_inputs.append(stakeholder_input)
        
        await self._log_dpia_event(assessment, "stakeholder_consultation_conducted", {
            "stakeholders_consulted": len(stakeholders),
            "consultation_method": consultation_method,
            "consultation_period": consultation_period
        })
        
        self.logger.info(f"Stakeholder consultation conducted for DPIA {assessment_id}")
        
        return True
    
    async def implement_mitigation_measures(self, 
                                          assessment_id: str, 
                                          mitigation_plan: Dict[str, Any]) -> bool:
        """Implement risk mitigation measures"""
        
        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return False
        
        # Add mitigation measures
        assessment.mitigation_measures = mitigation_plan.get("measures", [])
        assessment.implementation_timeline = {
            measure: datetime.now() + timedelta(days=mitigation_plan.get("timeline_days", 90))
            for measure in assessment.mitigation_measures
        }
        assessment.responsible_parties = mitigation_plan.get("responsible_parties", {})
        
        # Calculate residual risk after mitigation
        self._calculate_residual_risk(assessment)
        
        assessment.last_updated = datetime.now()
        
        await self._log_dpia_event(assessment, "mitigation_measures_implemented", {
            "measures_count": len(assessment.mitigation_measures),
            "residual_risk_level": assessment.residual_risk_level.value
        })
        
        self.logger.info(f"Mitigation measures implemented for DPIA {assessment_id}")
        
        return True
    
    def _calculate_residual_risk(self, assessment: DPIAAssessment):
        """Calculate residual risk after mitigation measures"""
        
        # Apply mitigation impact to risk factors
        for risk_factor in assessment.risk_factors:
            if risk_factor.mitigation_measures:
                # Reduce risk level based on mitigation measures
                # This is a simplified calculation - in practice, this would be more sophisticated
                if risk_factor.impact == RiskLevel.VERY_HIGH:
                    risk_factor.residual_risk = RiskLevel.HIGH
                elif risk_factor.impact == RiskLevel.HIGH:
                    risk_factor.residual_risk = RiskLevel.MEDIUM
                elif risk_factor.impact == RiskLevel.MEDIUM:
                    risk_factor.residual_risk = RiskLevel.LOW
                else:
                    risk_factor.residual_risk = RiskLevel.LOW
            else:
                risk_factor.residual_risk = risk_factor.impact
        
        # Calculate overall residual risk
        if assessment.risk_factors:
            residual_scores = []
            for rf in assessment.risk_factors:
                likelihood_val = {"low": 1, "medium": 2, "high": 3, "very_high": 4}[rf.likelihood.value]
                impact_val = {"low": 1, "medium": 2, "high": 3, "very_high": 4}[rf.residual_risk.value]
                residual_scores.append(likelihood_val * impact_val)
            
            avg_residual = sum(residual_scores) / len(residual_scores)
            
            if avg_residual <= 4:
                assessment.residual_risk_level = RiskLevel.LOW
            elif avg_residual <= 8:
                assessment.residual_risk_level = RiskLevel.MEDIUM
            elif avg_residual <= 12:
                assessment.residual_risk_level = RiskLevel.HIGH
            else:
                assessment.residual_risk_level = RiskLevel.VERY_HIGH
        else:
            assessment.residual_risk_level = RiskLevel.LOW
    
    async def request_supervisory_authority_consultation(self, assessment_id: str) -> bool:
        """Request consultation with supervisory authority if required"""
        
        assessment = self.assessments.get(assessment_id)
        if not assessment or not assessment.sa_consultation_required:
            return False
        
        assessment.status = DPIAStatus.REQUIRES_CONSULTATION
        assessment.sa_consultation_date = datetime.now()
        assessment.last_updated = datetime.now()
        
        # In production, this would submit to actual supervisory authority
        consultation_package = {
            "assessment_id": assessment.id,
            "processing_operation": assessment.processing_operation.to_dict() if assessment.processing_operation else None,
            "risk_assessment": {
                "overall_risk": assessment.overall_risk_level.value,
                "residual_risk": assessment.residual_risk_level.value,
                "risk_factors": [rf.to_dict() for rf in assessment.risk_factors]
            },
            "mitigation_measures": assessment.mitigation_measures,
            "stakeholder_consultation": [si.to_dict() for si in assessment.stakeholder_inputs]
        }
        
        await self._log_dpia_event(assessment, "sa_consultation_requested", {
            "consultation_date": assessment.sa_consultation_date.isoformat()
        })
        
        self.logger.info(f"Supervisory authority consultation requested for DPIA {assessment_id}")
        
        return True
    
    async def finalize_dpia(self, assessment_id: str, approval_data: Dict[str, Any]) -> bool:
        """Finalize and approve DPIA"""
        
        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return False
        
        # Set completion details
        assessment.status = DPIAStatus.COMPLETED
        assessment.completion_date = datetime.now()
        assessment.data_protection_officer = approval_data.get("dpo", "")
        assessment.reviewers = approval_data.get("reviewers", [])
        
        # Set review schedule
        review_period_months = approval_data.get("review_period_months", 12)
        assessment.review_date = datetime.now() + timedelta(days=review_period_months * 30)
        
        # Set monitoring measures
        assessment.monitoring_measures = approval_data.get("monitoring_measures", [])
        
        assessment.last_updated = datetime.now()
        
        await self._log_dpia_event(assessment, "dpia_completed", {
            "completion_date": assessment.completion_date.isoformat(),
            "approved_by": assessment.data_protection_officer,
            "review_date": assessment.review_date.isoformat() if assessment.review_date else None
        })
        
        self.logger.info(f"DPIA completed and approved: {assessment_id}")
        
        return True
    
    async def review_dpia(self, assessment_id: str, review_data: Dict[str, Any]) -> bool:
        """Conduct periodic DPIA review"""
        
        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return False
        
        # Update version
        version_parts = assessment.version.split('.')
        version_parts[-1] = str(int(version_parts[-1]) + 1)
        assessment.version = '.'.join(version_parts)
        
        # Update review information
        assessment.last_updated = datetime.now()
        
        # Check if processing operation has changed
        operation_changes = review_data.get("operation_changes", [])
        if operation_changes:
            assessment.status = DPIAStatus.UNDER_REVIEW
            # In practice, this would trigger re-assessment
        
        # Set next review date
        review_period_months = review_data.get("next_review_months", 12)
        assessment.review_date = datetime.now() + timedelta(days=review_period_months * 30)
        
        await self._log_dpia_event(assessment, "dpia_reviewed", {
            "version": assessment.version,
            "operation_changes": operation_changes,
            "next_review_date": assessment.review_date.isoformat() if assessment.review_date else None
        })
        
        self.logger.info(f"DPIA reviewed: {assessment_id} (Version: {assessment.version})")
        
        return True
    
    async def generate_dpia_report(self, assessment_id: str, format: str = "json") -> Optional[Dict[str, Any]]:
        """Generate comprehensive DPIA report"""
        
        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return None
        
        report = {
            "dpia_assessment": assessment.to_dict(),
            "executive_summary": {
                "title": assessment.title,
                "overall_risk": assessment.overall_risk_level.value,
                "residual_risk": assessment.residual_risk_level.value,
                "consultation_required": assessment.sa_consultation_required,
                "status": assessment.status.value,
                "completion_status": "completed" if assessment.completion_date else "in_progress"
            },
            "processing_details": assessment.processing_operation.to_dict() if assessment.processing_operation else {},
            "risk_analysis": {
                "triggers": [trigger.value for trigger in assessment.triggers],
                "risk_factors": [rf.to_dict() for rf in assessment.risk_factors],
                "overall_assessment": assessment.overall_risk_level.value,
                "mitigation_effectiveness": self._assess_mitigation_effectiveness(assessment)
            },
            "stakeholder_engagement": {
                "consultation_required": assessment.stakeholder_consultation_required,
                "stakeholders_consulted": len(assessment.stakeholder_inputs),
                "key_concerns": self._extract_key_concerns(assessment.stakeholder_inputs),
                "recommendations": self._extract_stakeholder_recommendations(assessment.stakeholder_inputs)
            },
            "compliance_measures": {
                "mitigation_measures": assessment.mitigation_measures,
                "monitoring_measures": assessment.monitoring_measures,
                "implementation_timeline": {k: v.isoformat() for k, v in assessment.implementation_timeline.items()},
                "responsible_parties": assessment.responsible_parties
            },
            "ongoing_obligations": {
                "review_date": assessment.review_date.isoformat() if assessment.review_date else None,
                "monitoring_required": len(assessment.monitoring_measures) > 0,
                "sa_consultation_status": "required" if assessment.sa_consultation_required else "not_required"
            },
            "report_metadata": {
                "generated_date": datetime.now().isoformat(),
                "format": format,
                "version": assessment.version
            }
        }
        
        return report
    
    def _assess_mitigation_effectiveness(self, assessment: DPIAAssessment) -> str:
        """Assess effectiveness of mitigation measures"""
        
        if not assessment.risk_factors or not assessment.mitigation_measures:
            return "not_assessed"
        
        # Compare original risk to residual risk
        original_risk_level = assessment.overall_risk_level
        residual_risk_level = assessment.residual_risk_level
        
        risk_levels = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.VERY_HIGH]
        
        original_index = risk_levels.index(original_risk_level)
        residual_index = risk_levels.index(residual_risk_level)
        
        reduction = original_index - residual_index
        
        if reduction >= 2:
            return "highly_effective"
        elif reduction == 1:
            return "effective"
        elif reduction == 0:
            return "minimal_effect"
        else:
            return "ineffective"
    
    def _extract_key_concerns(self, stakeholder_inputs: List[StakeholderInput]) -> List[str]:
        """Extract key concerns from stakeholder consultation"""
        
        all_concerns = []
        for input in stakeholder_inputs:
            all_concerns.extend(input.concerns_raised)
        
        # Count frequency and return most common concerns
        concern_counts = {}
        for concern in all_concerns:
            concern_counts[concern] = concern_counts.get(concern, 0) + 1
        
        # Return top 5 concerns
        sorted_concerns = sorted(concern_counts.items(), key=lambda x: x[1], reverse=True)
        return [concern for concern, count in sorted_concerns[:5]]
    
    def _extract_stakeholder_recommendations(self, stakeholder_inputs: List[StakeholderInput]) -> List[str]:
        """Extract recommendations from stakeholder consultation"""
        
        all_recommendations = []
        for input in stakeholder_inputs:
            all_recommendations.extend(input.suggestions)
            all_recommendations.extend(input.mitigation_recommendations)
        
        return list(set(all_recommendations))  # Remove duplicates
    
    async def _log_dpia_event(self, assessment: DPIAAssessment, event_type: str, metadata: Dict[str, Any] = None):
        """Log DPIA events for audit trail"""
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "dpia_id": assessment.id,
            "dpia_title": assessment.title,
            "status": assessment.status.value,
            "metadata": metadata or {}
        }
        
        self.logger.info(f"DPIA Event: {event_type} for assessment {assessment.id}")
        
        # In production, this would write to audit database
    
    # Management and query methods
    def get_assessment(self, assessment_id: str) -> Optional[DPIAAssessment]:
        """Get DPIA assessment by ID"""
        return self.assessments.get(assessment_id)
    
    def list_assessments(self, status: Optional[DPIAStatus] = None) -> List[DPIAAssessment]:
        """List DPIA assessments, optionally filtered by status"""
        if status:
            return [a for a in self.assessments.values() if a.status == status]
        return list(self.assessments.values())
    
    def get_assessments_due_for_review(self) -> List[DPIAAssessment]:
        """Get assessments due for review"""
        now = datetime.now()
        return [
            a for a in self.assessments.values()
            if a.review_date and now >= a.review_date
        ]
    
    def get_assessments_requiring_sa_consultation(self) -> List[DPIAAssessment]:
        """Get assessments requiring supervisory authority consultation"""
        return [
            a for a in self.assessments.values()
            if a.sa_consultation_required and a.status != DPIAStatus.COMPLETED
        ]
    
    async def get_dpia_statistics(self) -> Dict[str, Any]:
        """Get DPIA system statistics"""
        
        total_assessments = len(self.assessments)
        by_status = {}
        by_risk_level = {}
        
        for assessment in self.assessments.values():
            status = assessment.status.value
            by_status[status] = by_status.get(status, 0) + 1
            
            risk_level = assessment.overall_risk_level.value
            by_risk_level[risk_level] = by_risk_level.get(risk_level, 0) + 1
        
        return {
            "total_assessments": total_assessments,
            "by_status": by_status,
            "by_risk_level": by_risk_level,
            "requiring_sa_consultation": len(self.get_assessments_requiring_sa_consultation()),
            "due_for_review": len(self.get_assessments_due_for_review()),
            "completed_assessments": len([a for a in self.assessments.values() if a.status == DPIAStatus.COMPLETED])
        }