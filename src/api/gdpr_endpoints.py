"""
GDPR API Endpoints
RESTful API endpoints for GDPR compliance management
"""
from fastapi import APIRouter, HTTPException, Depends, Query, Path, Body, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum
import logging

from ..core.gdpr.data_subject_rights import DataSubjectRightsManager, DataSubjectRightType, RequestStatus, DataSubjectIdentity
from ..core.gdpr.consent_management import ConsentManager, ProcessingPurpose, ConsentMethod
from ..core.gdpr.cross_border_transfers import CrossBorderTransferManager, TransferMechanism, AdequacyStatus
from ..core.gdpr.breach_management import BreachManager, BreachSeverity, BreachType, BreachStatus
from ..core.gdpr.privacy_by_design import PrivacyByDesignFramework, PrivacyPrinciple, PrivacyEnhancingTechnology
from ..core.gdpr.processing_records import ProcessingRecordsManager, ProcessingRole, LegalBasis
from ..core.database.db_manager import DatabaseManager
from ..core.security.encryption_manager import EncryptionManager


logger = logging.getLogger(__name__)

# Create router
gdpr_router = APIRouter(prefix="/api/v1/gdpr", tags=["GDPR Compliance"])


# Pydantic Models for API
class DataSubjectIdentityModel(BaseModel):
    email: Optional[str] = None
    name: Optional[str] = None
    phone: Optional[str] = None
    identification_number: Optional[str] = None
    additional_identifiers: Dict[str, str] = Field(default_factory=dict)
    verification_method: str = "email"


class DataSubjectRightsRequestModel(BaseModel):
    request_type: DataSubjectRightType
    data_subject: DataSubjectIdentityModel
    description: str = ""
    additional_information: Dict[str, Any] = Field(default_factory=dict)
    rectification_details: Optional[Dict[str, Any]] = None
    erasure_reason: Optional[str] = None
    restriction_reason: Optional[str] = None
    objection_reason: Optional[str] = None
    portability_format: str = "json"


class ConsentCollectionModel(BaseModel):
    data_subject_id: str
    template_id: str
    purpose_consents: Dict[str, bool]
    consent_method: ConsentMethod = ConsentMethod.WEB_FORM
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    additional_evidence: Dict[str, Any] = Field(default_factory=dict)


class ConsentWithdrawalModel(BaseModel):
    data_subject_id: str
    purposes: Optional[List[str]] = None
    withdrawal_method: ConsentMethod = ConsentMethod.WEB_FORM
    withdrawal_reason: str = ""
    additional_evidence: Dict[str, Any] = Field(default_factory=dict)


class DataTransferModel(BaseModel):
    title: str
    description: str
    transfer_type: str = "controller_to_processor"
    destination_country_code: str
    data_exporter: Dict[str, Any]
    data_importer: Dict[str, Any]
    data_categories: List[str]
    data_subjects_categories: List[str]
    processing_purposes: List[str]
    retention_period: int = 365
    transfer_frequency: str = "one-time"
    data_volume: str = ""


class BreachReportModel(BaseModel):
    title: str
    description: str
    breach_type: BreachType = BreachType.CONFIDENTIALITY_BREACH
    severity: BreachSeverity = BreachSeverity.MEDIUM
    detection_method: str = "manual"
    detected_by: str = "system_administrator"
    detection_source: str = "internal_monitoring"
    occurred_timestamp: Optional[datetime] = None
    affected_systems: List[str] = Field(default_factory=list)
    affected_data_categories: List[str] = Field(default_factory=list)
    estimated_affected_records: int = 0
    affected_data_subjects: List[Dict[str, Any]] = Field(default_factory=list)
    root_cause: str = "under_investigation"
    contributing_factors: List[str] = Field(default_factory=list)


class PrivacyAssessmentModel(BaseModel):
    processing_activity: str
    data_categories: List[str]
    processing_purposes: List[str]
    data_subjects_categories: List[str]
    assessor: str = "privacy_team"


class ProcessingActivityModel(BaseModel):
    name: str
    description: str
    processing_role: ProcessingRole = ProcessingRole.CONTROLLER
    purposes: List[str]
    legal_basis: List[LegalBasis]
    data_categories: List[str]
    data_subject_categories: List[str]
    business_area: str = ""
    estimated_data_subjects: int = 0
    template: Optional[str] = None


# Dependency to get GDPR managers
async def get_gdpr_managers():
    """Get GDPR manager instances"""
    # In production, these would be properly initialized with dependencies
    db_manager = DatabaseManager()  # Mock initialization
    encryption_manager = EncryptionManager()  # Mock initialization
    
    return {
        "dsr_manager": DataSubjectRightsManager(db_manager, encryption_manager),
        "consent_manager": ConsentManager(db_manager, encryption_manager),
        "transfer_manager": CrossBorderTransferManager(db_manager, encryption_manager),
        "breach_manager": BreachManager(db_manager, encryption_manager),
        "privacy_framework": PrivacyByDesignFramework(db_manager, encryption_manager),
        "records_manager": ProcessingRecordsManager(db_manager, encryption_manager)
    }


# Data Subject Rights Endpoints
@gdpr_router.post("/data-subject-rights/requests", status_code=status.HTTP_201_CREATED)
async def submit_data_subject_rights_request(
    request: DataSubjectRightsRequestModel,
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Submit a new data subject rights request"""
    
    try:
        dsr_manager = managers["dsr_manager"]
        
        # Convert Pydantic model to domain object
        data_subject_identity = DataSubjectIdentity(
            email=request.data_subject.email,
            name=request.data_subject.name,
            phone=request.data_subject.phone,
            identification_number=request.data_subject.identification_number,
            additional_identifiers=request.data_subject.additional_identifiers,
            verification_method=request.data_subject.verification_method
        )
        
        # Submit request
        dsr_request = await dsr_manager.submit_rights_request(
            request_type=request.request_type,
            data_subject=data_subject_identity,
            description=request.description,
            additional_info=request.additional_information
        )
        
        # Set request-specific details
        if request.rectification_details:
            dsr_request.rectification_details = request.rectification_details
        if request.erasure_reason:
            dsr_request.erasure_reason = request.erasure_reason
        if request.restriction_reason:
            dsr_request.restriction_reason = request.restriction_reason
        if request.objection_reason:
            dsr_request.objection_reason = request.objection_reason
        if request.portability_format:
            dsr_request.portability_format = request.portability_format
        
        return {
            "request_id": dsr_request.id,
            "status": dsr_request.status.value,
            "submitted_timestamp": dsr_request.submitted_timestamp.isoformat(),
            "due_date": dsr_request.due_date.isoformat(),
            "message": "Data subject rights request submitted successfully"
        }
        
    except Exception as e:
        logger.error(f"Error submitting DSR request: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to submit request: {str(e)}")


@gdpr_router.get("/data-subject-rights/requests/{request_id}")
async def get_data_subject_rights_request(
    request_id: str = Path(..., description="Request ID"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Get data subject rights request by ID"""
    
    dsr_manager = managers["dsr_manager"]
    request = dsr_manager.get_request(request_id)
    
    if not request:
        raise HTTPException(status_code=404, detail="Request not found")
    
    return request.to_dict()


@gdpr_router.get("/data-subject-rights/requests")
async def list_data_subject_rights_requests(
    status: Optional[RequestStatus] = Query(None, description="Filter by status"),
    data_subject_id: Optional[str] = Query(None, description="Filter by data subject ID"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """List data subject rights requests with optional filters"""
    
    dsr_manager = managers["dsr_manager"]
    
    if status:
        requests = dsr_manager.get_requests_by_status(status)
    elif data_subject_id:
        requests = dsr_manager.get_requests_by_data_subject(data_subject_id)
    else:
        requests = list(dsr_manager.active_requests.values())
    
    return {
        "total_requests": len(requests),
        "requests": [request.to_dict() for request in requests]
    }


@gdpr_router.get("/data-subject-rights/statistics")
async def get_dsr_statistics(
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Get data subject rights processing statistics"""
    
    dsr_manager = managers["dsr_manager"]
    return await dsr_manager.get_processing_statistics()


# Consent Management Endpoints
@gdpr_router.post("/consent/collect", status_code=status.HTTP_201_CREATED)
async def collect_consent(
    consent_data: ConsentCollectionModel,
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Collect consent from data subject"""
    
    try:
        consent_manager = managers["consent_manager"]
        
        consent_record = await consent_manager.collect_consent(
            data_subject_id=consent_data.data_subject_id,
            template_id=consent_data.template_id,
            purpose_consents=consent_data.purpose_consents,
            consent_method=consent_data.consent_method,
            ip_address=consent_data.ip_address,
            user_agent=consent_data.user_agent,
            additional_evidence=consent_data.additional_evidence
        )
        
        return {
            "consent_record_id": consent_record.id,
            "data_subject_id": consent_record.data_subject_id,
            "consent_timestamp": consent_record.consent_timestamp.isoformat(),
            "purposes": {k: v.value for k, v in consent_record.purposes.items()},
            "message": "Consent collected successfully"
        }
        
    except Exception as e:
        logger.error(f"Error collecting consent: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to collect consent: {str(e)}")


@gdpr_router.post("/consent/withdraw")
async def withdraw_consent(
    withdrawal_data: ConsentWithdrawalModel,
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Withdraw consent for data subject"""
    
    try:
        consent_manager = managers["consent_manager"]
        
        withdrawn_records = await consent_manager.withdraw_consent(
            data_subject_id=withdrawal_data.data_subject_id,
            purposes=withdrawal_data.purposes,
            withdrawal_method=withdrawal_data.withdrawal_method,
            withdrawal_reason=withdrawal_data.withdrawal_reason,
            additional_evidence=withdrawal_data.additional_evidence
        )
        
        return {
            "withdrawn_records": len(withdrawn_records),
            "record_ids": [record.id for record in withdrawn_records],
            "withdrawal_timestamp": datetime.now().isoformat(),
            "message": "Consent withdrawn successfully"
        }
        
    except Exception as e:
        logger.error(f"Error withdrawing consent: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to withdraw consent: {str(e)}")


@gdpr_router.get("/consent/check/{data_subject_id}/{purpose}")
async def check_consent_status(
    data_subject_id: str = Path(..., description="Data subject ID"),
    purpose: ProcessingPurpose = Path(..., description="Processing purpose"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Check consent status for specific purpose"""
    
    consent_manager = managers["consent_manager"]
    status = await consent_manager.check_consent_status(data_subject_id, purpose)
    
    return status


@gdpr_router.get("/consent/analytics")
async def get_consent_analytics(
    start_date: Optional[datetime] = Query(None, description="Start date for analytics"),
    end_date: Optional[datetime] = Query(None, description="End date for analytics"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Get consent analytics and reporting data"""
    
    consent_manager = managers["consent_manager"]
    analytics = await consent_manager.get_consent_analytics(start_date, end_date)
    
    return analytics.to_dict()


@gdpr_router.get("/consent/templates")
async def list_consent_templates(
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """List available consent templates"""
    
    consent_manager = managers["consent_manager"]
    templates = consent_manager.list_consent_templates()
    
    return {
        "total_templates": len(templates),
        "templates": [template.to_dict() for template in templates]
    }


# Cross-Border Transfer Endpoints
@gdpr_router.post("/transfers", status_code=status.HTTP_201_CREATED)
async def create_data_transfer(
    transfer_data: DataTransferModel,
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Create new cross-border data transfer"""
    
    try:
        transfer_manager = managers["transfer_manager"]
        
        transfer = await transfer_manager.create_transfer_request(transfer_data.dict())
        
        return {
            "transfer_id": transfer.id,
            "title": transfer.title,
            "status": transfer.status.value,
            "transfer_mechanism": transfer.transfer_mechanism.value,
            "tia_required": transfer.tia_required,
            "message": "Data transfer created successfully"
        }
        
    except Exception as e:
        logger.error(f"Error creating data transfer: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create transfer: {str(e)}")


@gdpr_router.get("/transfers/{transfer_id}")
async def get_data_transfer(
    transfer_id: str = Path(..., description="Transfer ID"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Get data transfer by ID"""
    
    transfer_manager = managers["transfer_manager"]
    transfer = transfer_manager.get_transfer(transfer_id)
    
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")
    
    return transfer.to_dict()


@gdpr_router.post("/transfers/{transfer_id}/tia")
async def conduct_transfer_impact_assessment(
    transfer_id: str = Path(..., description="Transfer ID"),
    assessor: str = Query("privacy_team", description="Assessor name"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Conduct Transfer Impact Assessment"""
    
    transfer_manager = managers["transfer_manager"]
    
    tia = await transfer_manager.conduct_transfer_impact_assessment(transfer_id, assessor)
    
    if not tia:
        raise HTTPException(status_code=404, detail="Transfer not found or TIA not required")
    
    return tia.to_dict()


@gdpr_router.get("/transfers/adequacy/{country_code}")
async def check_adequacy_status(
    country_code: str = Path(..., description="Country code (ISO 3166-1 alpha-2)"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Check adequacy decision status for country"""
    
    transfer_manager = managers["transfer_manager"]
    country = transfer_manager.get_country(country_code)
    
    if not country:
        return {
            "country_code": country_code.upper(),
            "adequacy_status": "unknown",
            "message": "Country not found in adequacy database"
        }
    
    return country.to_dict()


@gdpr_router.get("/transfers/statistics")
async def get_transfer_statistics(
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Get transfer statistics"""
    
    transfer_manager = managers["transfer_manager"]
    return await transfer_manager.get_transfer_statistics()


# Breach Management Endpoints
@gdpr_router.post("/breaches", status_code=status.HTTP_201_CREATED)
async def report_data_breach(
    breach_data: BreachReportModel,
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Report new data breach incident"""
    
    try:
        breach_manager = managers["breach_manager"]
        
        breach = await breach_manager.report_breach(breach_data.dict())
        
        return {
            "breach_id": breach.id,
            "title": breach.title,
            "status": breach.status.value,
            "severity": breach.severity.value,
            "authority_notification_deadline": breach.authority_notification_deadline.isoformat(),
            "message": "Breach reported successfully"
        }
        
    except Exception as e:
        logger.error(f"Error reporting breach: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to report breach: {str(e)}")


@gdpr_router.get("/breaches/{breach_id}")
async def get_data_breach(
    breach_id: str = Path(..., description="Breach ID"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Get data breach by ID"""
    
    breach_manager = managers["breach_manager"]
    breach = breach_manager.get_breach(breach_id)
    
    if not breach:
        raise HTTPException(status_code=404, detail="Breach not found")
    
    return breach.to_dict()


@gdpr_router.post("/breaches/{breach_id}/notify-authority")
async def notify_supervisory_authority(
    breach_id: str = Path(..., description="Breach ID"),
    additional_details: Dict[str, Any] = Body(default={}),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Send Article 33 notification to supervisory authority"""
    
    try:
        breach_manager = managers["breach_manager"]
        
        notification = await breach_manager.notify_supervisory_authority(
            breach_id, additional_details
        )
        
        return {
            "notification_id": notification.id,
            "breach_id": breach_id,
            "notification_timestamp": notification.notification_timestamp.isoformat(),
            "recipient": notification.recipient,
            "message": "Supervisory authority notified successfully"
        }
        
    except Exception as e:
        logger.error(f"Error notifying authority: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to notify authority: {str(e)}")


@gdpr_router.post("/breaches/{breach_id}/notify-individuals")
async def notify_affected_individuals(
    breach_id: str = Path(..., description="Breach ID"),
    custom_message: Optional[str] = Body(None, embed=True),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Send Article 34 notifications to affected individuals"""
    
    try:
        breach_manager = managers["breach_manager"]
        
        notifications = await breach_manager.notify_affected_individuals(
            breach_id, custom_message
        )
        
        return {
            "notifications_sent": len(notifications),
            "notification_ids": [n.id for n in notifications],
            "message": "Individual notifications sent successfully"
        }
        
    except Exception as e:
        logger.error(f"Error notifying individuals: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to notify individuals: {str(e)}")


@gdpr_router.get("/breaches")
async def list_data_breaches(
    status: Optional[BreachStatus] = Query(None, description="Filter by status"),
    severity: Optional[BreachSeverity] = Query(None, description="Filter by severity"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """List data breaches with optional filters"""
    
    breach_manager = managers["breach_manager"]
    
    if status:
        breaches = breach_manager.list_breaches(status)
    elif severity:
        breaches = breach_manager.get_breaches_by_severity(severity)
    else:
        breaches = breach_manager.list_breaches()
    
    return {
        "total_breaches": len(breaches),
        "breaches": [breach.to_dict() for breach in breaches]
    }


@gdpr_router.get("/breaches/statistics")
async def get_breach_statistics(
    start_date: Optional[datetime] = Query(None, description="Start date for statistics"),
    end_date: Optional[datetime] = Query(None, description="End date for statistics"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Get breach statistics and analytics"""
    
    breach_manager = managers["breach_manager"]
    return await breach_manager.generate_breach_statistics(start_date, end_date)


@gdpr_router.get("/breaches/deadlines")
async def monitor_breach_deadlines(
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Monitor breach notification deadlines"""
    
    breach_manager = managers["breach_manager"]
    return await breach_manager.monitor_breach_deadlines()


# Privacy by Design Endpoints
@gdpr_router.post("/privacy-assessments", status_code=status.HTTP_201_CREATED)
async def conduct_privacy_assessment(
    assessment_data: PrivacyAssessmentModel,
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Conduct privacy assessment for processing activity"""
    
    try:
        privacy_framework = managers["privacy_framework"]
        
        assessment = await privacy_framework.conduct_privacy_assessment(
            processing_activity=assessment_data.processing_activity,
            data_categories=assessment_data.data_categories,
            processing_purposes=assessment_data.processing_purposes,
            data_subjects_categories=assessment_data.data_subjects_categories,
            assessor=assessment_data.assessor
        )
        
        return {
            "assessment_id": assessment.id,
            "processing_activity": assessment.processing_activity,
            "overall_risk_level": assessment.overall_risk_level.value,
            "identified_risks": len(assessment.identified_risks),
            "recommended_technologies": [tech.value for tech in assessment.recommended_technologies],
            "message": "Privacy assessment completed successfully"
        }
        
    except Exception as e:
        logger.error(f"Error conducting privacy assessment: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to conduct assessment: {str(e)}")


@gdpr_router.get("/privacy-assessments/{assessment_id}")
async def get_privacy_assessment(
    assessment_id: str = Path(..., description="Assessment ID"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Get privacy assessment by ID"""
    
    privacy_framework = managers["privacy_framework"]
    assessment = privacy_framework.get_privacy_assessment(assessment_id)
    
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    
    return assessment.to_dict()


@gdpr_router.post("/privacy-technologies/apply")
async def apply_privacy_technology(
    technology: PrivacyEnhancingTechnology = Body(..., description="Privacy technology to apply"),
    data: Any = Body(..., description="Data to process"),
    params: Dict[str, Any] = Body(default={}, description="Technology parameters"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Apply privacy enhancing technology to data"""
    
    try:
        privacy_framework = managers["privacy_framework"]
        
        processed_data = await privacy_framework.apply_privacy_technology(
            technology, data, params
        )
        
        return {
            "technology": technology.value,
            "original_data_type": type(data).__name__,
            "processed_data": processed_data,
            "parameters_used": params,
            "message": "Privacy technology applied successfully"
        }
        
    except Exception as e:
        logger.error(f"Error applying privacy technology: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to apply technology: {str(e)}")


@gdpr_router.get("/privacy-requirements")
async def list_privacy_requirements(
    principle: Optional[PrivacyPrinciple] = Query(None, description="Filter by privacy principle"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """List privacy by design requirements"""
    
    privacy_framework = managers["privacy_framework"]
    requirements = privacy_framework.list_privacy_requirements(principle)
    
    return {
        "total_requirements": len(requirements),
        "requirements": [req.to_dict() for req in requirements]
    }


@gdpr_router.get("/privacy-validation")
async def validate_privacy_implementation(
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Validate overall privacy implementation"""
    
    privacy_framework = managers["privacy_framework"]
    return await privacy_framework.validate_privacy_implementation()


@gdpr_router.get("/privacy-report")
async def generate_privacy_report(
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Generate comprehensive privacy by design report"""
    
    privacy_framework = managers["privacy_framework"]
    return await privacy_framework.generate_privacy_report()


# Processing Records Endpoints
@gdpr_router.post("/processing-activities", status_code=status.HTTP_201_CREATED)
async def create_processing_activity(
    activity_data: ProcessingActivityModel,
    created_by: str = Query("api_user", description="Creator name"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Create new processing activity"""
    
    try:
        records_manager = managers["records_manager"]
        
        activity = await records_manager.create_processing_activity(
            activity_data.dict(), created_by
        )
        
        return {
            "activity_id": activity.id,
            "name": activity.name,
            "processing_role": activity.processing_role.value,
            "dpia_required": activity.dpia_required,
            "created_date": activity.created_date.isoformat(),
            "message": "Processing activity created successfully"
        }
        
    except Exception as e:
        logger.error(f"Error creating processing activity: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create activity: {str(e)}")


@gdpr_router.get("/processing-activities/{activity_id}")
async def get_processing_activity(
    activity_id: str = Path(..., description="Activity ID"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Get processing activity by ID"""
    
    records_manager = managers["records_manager"]
    activity = records_manager.get_processing_activity(activity_id)
    
    if not activity:
        raise HTTPException(status_code=404, detail="Processing activity not found")
    
    return activity.to_dict()


@gdpr_router.get("/processing-activities")
async def list_processing_activities(
    status: Optional[str] = Query(None, description="Filter by status"),
    business_area: Optional[str] = Query(None, description="Filter by business area"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """List processing activities with optional filters"""
    
    records_manager = managers["records_manager"]
    activities = records_manager.list_processing_activities(status, business_area, risk_level)
    
    return {
        "total_activities": len(activities),
        "activities": [activity.to_dict() for activity in activities]
    }


@gdpr_router.put("/processing-activities/{activity_id}")
async def update_processing_activity(
    activity_id: str = Path(..., description="Activity ID"),
    updates: Dict[str, Any] = Body(..., description="Updates to apply"),
    updated_by: str = Query("api_user", description="Updater name"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Update existing processing activity"""
    
    records_manager = managers["records_manager"]
    activity = await records_manager.update_processing_activity(activity_id, updates, updated_by)
    
    if not activity:
        raise HTTPException(status_code=404, detail="Processing activity not found")
    
    return {
        "activity_id": activity.id,
        "name": activity.name,
        "version": activity.version,
        "last_updated": activity.last_updated.isoformat(),
        "last_updated_by": activity.last_updated_by,
        "message": "Processing activity updated successfully"
    }


@gdpr_router.post("/processing-activities/{activity_id}/transfers")
async def add_data_transfer_to_activity(
    activity_id: str = Path(..., description="Activity ID"),
    transfer_data: Dict[str, Any] = Body(..., description="Transfer details"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Add data transfer to processing activity"""
    
    records_manager = managers["records_manager"]
    transfer = await records_manager.add_data_transfer(activity_id, transfer_data)
    
    if not transfer:
        raise HTTPException(status_code=404, detail="Processing activity not found")
    
    return {
        "transfer_id": transfer.id,
        "activity_id": activity_id,
        "recipient_name": transfer.recipient_name,
        "recipient_country": transfer.recipient_country,
        "message": "Data transfer added successfully"
    }


@gdpr_router.post("/processing-activities/{activity_id}/security-measures")
async def add_security_measure_to_activity(
    activity_id: str = Path(..., description="Activity ID"),
    measure_data: Dict[str, Any] = Body(..., description="Security measure details"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Add security measure to processing activity"""
    
    records_manager = managers["records_manager"]
    measure = await records_manager.add_security_measure(activity_id, measure_data)
    
    if not measure:
        raise HTTPException(status_code=404, detail="Processing activity not found")
    
    return {
        "measure_id": measure.id,
        "activity_id": activity_id,
        "measure_type": measure.measure_type,
        "category": measure.category,
        "message": "Security measure added successfully"
    }


@gdpr_router.get("/processing-activities/audit")
async def conduct_processing_audit(
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Conduct comprehensive audit of processing activities"""
    
    records_manager = managers["records_manager"]
    return await records_manager.conduct_processing_audit()


@gdpr_router.get("/processing-activities/report")
async def generate_processing_report(
    format: str = Query("json", description="Report format"),
    include_details: bool = Query(True, description="Include detailed information"),
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Generate comprehensive processing activities report"""
    
    records_manager = managers["records_manager"]
    return await records_manager.generate_processing_report(format, include_details)


@gdpr_router.get("/processing-activities/reviews")
async def schedule_activity_reviews(
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Schedule and track processing activity reviews"""
    
    records_manager = managers["records_manager"]
    return await records_manager.schedule_activity_reviews()


# General GDPR Endpoints
@gdpr_router.get("/compliance-overview")
async def get_compliance_overview(
    managers: dict = Depends(get_gdpr_managers)
) -> Dict[str, Any]:
    """Get overall GDPR compliance overview"""
    
    try:
        # Get overview from all managers
        dsr_stats = await managers["dsr_manager"].get_processing_statistics()
        consent_analytics = await managers["consent_manager"].get_consent_analytics()
        transfer_stats = await managers["transfer_manager"].get_transfer_statistics()
        breach_stats = await managers["breach_manager"].generate_breach_statistics()
        privacy_validation = await managers["privacy_framework"].validate_privacy_implementation()
        processing_audit = await managers["records_manager"].conduct_processing_audit()
        
        return {
            "overview_date": datetime.now().isoformat(),
            "data_subject_rights": {
                "total_requests": dsr_stats["total_requests"],
                "by_status": dsr_stats["by_status"],
                "by_type": dsr_stats["by_type"],
                "average_processing_time": dsr_stats["average_processing_time_days"]
            },
            "consent_management": {
                "total_consents": consent_analytics.total_consents,
                "consent_rate": consent_analytics.consent_rate,
                "withdrawal_rate": consent_analytics.withdrawal_rate,
                "renewal_due": consent_analytics.renewal_due,
                "expired_consents": consent_analytics.expired_consents
            },
            "data_transfers": {
                "total_transfers": transfer_stats["total_transfers"],
                "by_status": transfer_stats["by_status"],
                "by_mechanism": transfer_stats["by_mechanism"],
                "by_country": transfer_stats["by_country"],
                "adequate_countries": transfer_stats["adequate_countries"]
            },
            "breach_management": {
                "total_breaches": breach_stats["total_breaches"],
                "by_severity": breach_stats["by_severity"],
                "by_type": breach_stats["by_type"],
                "notification_compliance": breach_stats["notification_compliance"]
            },
            "privacy_by_design": {
                "overall_status": privacy_validation["overall_status"],
                "technology_validation": len(privacy_validation["technology_validation"]),
                "requirement_compliance": len(privacy_validation["requirement_compliance"]),
                "identified_gaps": len(privacy_validation["identified_gaps"])
            },
            "processing_records": {
                "total_activities": processing_audit["total_activities"],
                "compliance_summary": processing_audit["compliance_summary"],
                "dpia_summary": processing_audit["dpia_summary"],
                "retention_compliance": processing_audit["retention_compliance"]
            }
        }
        
    except Exception as e:
        logger.error(f"Error generating compliance overview: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate overview: {str(e)}")


@gdpr_router.get("/health")
async def gdpr_health_check() -> Dict[str, str]:
    """GDPR system health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }


# Export the router
__all__ = ["gdpr_router"]