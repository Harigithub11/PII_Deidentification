"""
Compliance & Audit API Endpoints

Comprehensive compliance management, audit trail querying,
and regulatory compliance validation endpoints.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, status, Query, Path, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func, between

from ..core.database.session import get_db_session
from ..core.database.models import (
    AuditEvent, AuditEventDetail, UserActivity, SystemEvent, 
    ComplianceStandard, CompliancePolicy, PolicyApplication,
    AuditEventType, AuditSeverity, AuditOutcome, User
)
from ..core.security.dependencies import (
    get_current_active_user,
    get_current_admin_user,
    require_permissions,
    AuditLogDependency
)

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/compliance", tags=["Compliance & Audit"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class ComplianceStandardResponse(BaseModel):
    """Compliance standard response model."""
    id: UUID
    code: str
    name: str
    description: Optional[str]
    jurisdiction: Optional[str]
    version: Optional[str]
    effective_date: Optional[datetime]
    website_url: Optional[str]
    documentation_url: Optional[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class AuditEventResponse(BaseModel):
    """Audit event response model."""
    id: UUID
    event_id: str
    event_type: str
    severity: str
    outcome: str
    user_id: Optional[UUID]
    username: Optional[str]
    session_id: Optional[UUID]
    target_type: Optional[str]
    target_id: Optional[UUID]
    target_name: Optional[str]
    event_description: str
    event_summary: Optional[str]
    request_method: Optional[str]
    request_url: Optional[str]
    response_status: Optional[int]
    ip_address: Optional[str]
    user_agent: Optional[str]
    location_country: Optional[str]
    location_city: Optional[str]
    event_timestamp: datetime
    duration_ms: Optional[int]
    compliance_standards: List[str]
    risk_score: Optional[int]
    contains_pii: bool
    data_classification: str
    tags: List[str]
    
    class Config:
        from_attributes = True


class AuditEventDetailResponse(BaseModel):
    """Detailed audit event response model."""
    id: UUID
    detail_type: str
    detail_key: str
    detail_value: Dict[str, Any]
    is_sensitive: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class SystemEventResponse(BaseModel):
    """System event response model."""
    id: UUID
    event_type: str
    severity: str
    event_name: str
    event_description: str
    error_code: Optional[str]
    error_message: Optional[str]
    service_name: Optional[str]
    service_version: Optional[str]
    server_hostname: Optional[str]
    cpu_usage_percent: Optional[float]
    memory_usage_mb: Optional[int]
    event_timestamp: datetime
    event_duration_ms: Optional[int]
    requires_attention: bool
    is_resolved: bool
    resolved_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class AuditSearchRequest(BaseModel):
    """Audit search request model."""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    event_types: Optional[List[str]] = None
    severities: Optional[List[str]] = None
    outcomes: Optional[List[str]] = None
    user_ids: Optional[List[UUID]] = None
    target_types: Optional[List[str]] = None
    ip_addresses: Optional[List[str]] = None
    contains_pii: Optional[bool] = None
    risk_score_min: Optional[int] = Field(None, ge=0, le=100)
    risk_score_max: Optional[int] = Field(None, ge=0, le=100)
    compliance_standards: Optional[List[str]] = None
    search_text: Optional[str] = None


class ComplianceReportRequest(BaseModel):
    """Compliance report request model."""
    report_type: str = Field(..., description="Type of compliance report")
    compliance_standard: str = Field(..., description="Compliance standard code")
    start_date: datetime = Field(..., description="Report start date")
    end_date: datetime = Field(..., description="Report end date")
    include_details: bool = Field(True, description="Include detailed audit data")
    format: str = Field("pdf", regex="^(pdf|xlsx|csv)$", description="Report format")
    
    @validator('report_type')
    def validate_report_type(cls, v):
        valid_types = ["audit_summary", "compliance_validation", "risk_assessment", 
                      "data_processing", "user_activity", "system_events"]
        if v not in valid_types:
            raise ValueError(f'Report type must be one of: {valid_types}')
        return v


class ComplianceStatsResponse(BaseModel):
    """Compliance statistics response model."""
    total_audit_events: int
    events_by_severity: Dict[str, int]
    events_by_outcome: Dict[str, int]
    high_risk_events: int
    compliance_violations: int
    unresolved_incidents: int
    average_risk_score: float
    data_processing_events: int
    pii_access_events: int
    failed_access_attempts: int


class PaginatedAuditResponse(BaseModel):
    """Paginated audit response model."""
    items: List[AuditEventResponse]
    total: int
    page: int
    per_page: int
    pages: int
    has_next: bool
    has_prev: bool


# =============================================================================
# COMPLIANCE STANDARDS MANAGEMENT
# =============================================================================

@router.get("/standards", response_model=List[ComplianceStandardResponse])
async def list_compliance_standards(
    active_only: bool = Query(True, description="Filter active standards only"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """List compliance standards."""
    
    query = db.query(ComplianceStandard)
    
    if active_only:
        query = query.filter(ComplianceStandard.is_active == True)
    
    standards = query.order_by(ComplianceStandard.name).all()
    
    return [ComplianceStandardResponse.from_orm(standard) for standard in standards]


@router.get("/standards/{standard_id}", response_model=ComplianceStandardResponse)
async def get_compliance_standard(
    standard_id: UUID = Path(..., description="Standard ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """Get compliance standard details."""
    
    standard = db.query(ComplianceStandard).filter(
        ComplianceStandard.id == standard_id
    ).first()
    
    if not standard:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Compliance standard not found"
        )
    
    return ComplianceStandardResponse.from_orm(standard)


# =============================================================================
# AUDIT EVENT QUERYING
# =============================================================================

@router.get("/audit/events", response_model=PaginatedAuditResponse)
async def search_audit_events(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=1000, description="Items per page"),
    start_date: Optional[datetime] = Query(None, description="Start date filter"),
    end_date: Optional[datetime] = Query(None, description="End date filter"),
    event_type: Optional[str] = Query(None, description="Event type filter"),
    severity: Optional[str] = Query(None, description="Severity filter"),
    outcome: Optional[str] = Query(None, description="Outcome filter"),
    user_id: Optional[UUID] = Query(None, description="User ID filter"),
    target_type: Optional[str] = Query(None, description="Target type filter"),
    contains_pii: Optional[bool] = Query(None, description="Contains PII filter"),
    risk_score_min: Optional[int] = Query(None, ge=0, le=100, description="Minimum risk score"),
    search_text: Optional[str] = Query(None, description="Search in descriptions"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """Search audit events with comprehensive filtering."""
    
    # Check permissions - only admins and auditors can access full audit logs
    if current_user.role not in ["admin", "auditor"]:
        # Regular users can only see their own events
        user_id = current_user.id
    
    query = db.query(AuditEvent)
    
    # Apply filters
    if start_date:
        query = query.filter(AuditEvent.event_timestamp >= start_date)
    
    if end_date:
        query = query.filter(AuditEvent.event_timestamp <= end_date)
    
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    
    if severity:
        query = query.filter(AuditEvent.severity == severity)
    
    if outcome:
        query = query.filter(AuditEvent.outcome == outcome)
    
    if user_id:
        query = query.filter(AuditEvent.user_id == user_id)
    
    if target_type:
        query = query.filter(AuditEvent.target_type == target_type)
    
    if contains_pii is not None:
        query = query.filter(AuditEvent.contains_pii == contains_pii)
    
    if risk_score_min is not None:
        query = query.filter(AuditEvent.risk_score >= risk_score_min)
    
    if search_text:
        search_term = f"%{search_text}%"
        query = query.filter(
            or_(
                AuditEvent.event_description.ilike(search_term),
                AuditEvent.event_summary.ilike(search_term),
                AuditEvent.target_name.ilike(search_term)
            )
        )
    
    # Get total count
    total = query.count()
    
    # Apply pagination and ordering
    offset = (page - 1) * per_page
    events = query.order_by(desc(AuditEvent.event_timestamp))\
                 .offset(offset)\
                 .limit(per_page)\
                 .all()
    
    # Calculate pagination info
    pages = (total + per_page - 1) // per_page
    has_next = page < pages
    has_prev = page > 1
    
    items = [AuditEventResponse.from_orm(event) for event in events]
    
    return PaginatedAuditResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
        has_next=has_next,
        has_prev=has_prev
    )


@router.post("/audit/search", response_model=PaginatedAuditResponse)
async def advanced_audit_search(
    request: AuditSearchRequest,
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=1000, description="Items per page"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """Advanced audit event search with complex filtering."""
    
    # Check permissions
    if current_user.role not in ["admin", "auditor"]:
        if not request.user_ids:
            request.user_ids = [current_user.id]
        elif current_user.id not in request.user_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to search other users' audit events"
            )
    
    query = db.query(AuditEvent)
    
    # Apply date range
    if request.start_date:
        query = query.filter(AuditEvent.event_timestamp >= request.start_date)
    
    if request.end_date:
        query = query.filter(AuditEvent.event_timestamp <= request.end_date)
    
    # Apply list filters
    if request.event_types:
        query = query.filter(AuditEvent.event_type.in_(request.event_types))
    
    if request.severities:
        query = query.filter(AuditEvent.severity.in_(request.severities))
    
    if request.outcomes:
        query = query.filter(AuditEvent.outcome.in_(request.outcomes))
    
    if request.user_ids:
        query = query.filter(AuditEvent.user_id.in_(request.user_ids))
    
    if request.target_types:
        query = query.filter(AuditEvent.target_type.in_(request.target_types))
    
    if request.ip_addresses:
        query = query.filter(AuditEvent.ip_address.in_(request.ip_addresses))
    
    if request.compliance_standards:
        for standard in request.compliance_standards:
            query = query.filter(AuditEvent.compliance_standards.contains([standard]))
    
    # Apply boolean and range filters
    if request.contains_pii is not None:
        query = query.filter(AuditEvent.contains_pii == request.contains_pii)
    
    if request.risk_score_min is not None and request.risk_score_max is not None:
        query = query.filter(
            between(AuditEvent.risk_score, request.risk_score_min, request.risk_score_max)
        )
    elif request.risk_score_min is not None:
        query = query.filter(AuditEvent.risk_score >= request.risk_score_min)
    elif request.risk_score_max is not None:
        query = query.filter(AuditEvent.risk_score <= request.risk_score_max)
    
    # Apply text search
    if request.search_text:
        search_term = f"%{request.search_text}%"
        query = query.filter(
            or_(
                AuditEvent.event_description.ilike(search_term),
                AuditEvent.event_summary.ilike(search_term),
                AuditEvent.target_name.ilike(search_term),
                AuditEvent.username.ilike(search_term)
            )
        )
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * per_page
    events = query.order_by(desc(AuditEvent.event_timestamp))\
                 .offset(offset)\
                 .limit(per_page)\
                 .all()
    
    # Calculate pagination info
    pages = (total + per_page - 1) // per_page
    has_next = page < pages
    has_prev = page > 1
    
    items = [AuditEventResponse.from_orm(event) for event in events]
    
    return PaginatedAuditResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
        has_next=has_next,
        has_prev=has_prev
    )


@router.get("/audit/events/{event_id}", response_model=Dict[str, Any])
async def get_audit_event_details(
    event_id: UUID = Path(..., description="Audit event ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """Get detailed audit event information."""
    
    # Get audit event
    event = db.query(AuditEvent).filter(AuditEvent.id == event_id).first()
    
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit event not found"
        )
    
    # Check permissions
    if (current_user.role not in ["admin", "auditor"] and 
        event.user_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this audit event"
        )
    
    # Get event details
    details = db.query(AuditEventDetail).filter(
        AuditEventDetail.audit_event_id == event_id
    ).all()
    
    event_data = AuditEventResponse.from_orm(event).dict()
    event_data["details"] = [AuditEventDetailResponse.from_orm(detail) for detail in details]
    
    return event_data


# =============================================================================
# SYSTEM EVENT MONITORING
# =============================================================================

@router.get("/system/events", response_model=List[SystemEventResponse])
async def get_system_events(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=200, description="Items per page"),
    event_type: Optional[str] = Query(None, description="Event type filter"),
    severity: Optional[str] = Query(None, description="Severity filter"),
    requires_attention: Optional[bool] = Query(None, description="Filter by attention required"),
    unresolved_only: bool = Query(False, description="Show only unresolved events"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    """Get system events (Admin only)."""
    
    query = db.query(SystemEvent)
    
    # Apply filters
    if event_type:
        query = query.filter(SystemEvent.event_type == event_type)
    
    if severity:
        query = query.filter(SystemEvent.severity == severity)
    
    if requires_attention is not None:
        query = query.filter(SystemEvent.requires_attention == requires_attention)
    
    if unresolved_only:
        query = query.filter(SystemEvent.is_resolved == False)
    
    # Apply pagination
    offset = (page - 1) * per_page
    events = query.order_by(desc(SystemEvent.event_timestamp))\
                 .offset(offset)\
                 .limit(per_page)\
                 .all()
    
    return [SystemEventResponse.from_orm(event) for event in events]


@router.post("/system/events/{event_id}/resolve")
async def resolve_system_event(
    event_id: UUID = Path(..., description="System event ID"),
    resolution_notes: str = Field(..., description="Resolution notes"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("system_event_resolve"))
):
    """Resolve a system event (Admin only)."""
    
    event = db.query(SystemEvent).filter(SystemEvent.id == event_id).first()
    
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System event not found"
        )
    
    if event.is_resolved:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="System event is already resolved"
        )
    
    # Resolve event
    event.is_resolved = True
    event.resolved_at = datetime.utcnow()
    event.resolved_by = current_user.id
    event.resolution_notes = resolution_notes
    
    db.commit()
    
    logger.info(f"System event resolved: {event_id} by {current_user.username}")
    
    return {"message": "System event resolved successfully"}


# =============================================================================
# COMPLIANCE STATISTICS
# =============================================================================

@router.get("/stats", response_model=ComplianceStatsResponse)
async def get_compliance_statistics(
    start_date: Optional[datetime] = Query(None, description="Statistics start date"),
    end_date: Optional[datetime] = Query(None, description="Statistics end date"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """Get compliance and audit statistics."""
    
    # Default to last 30 days if no date range specified
    if not start_date:
        start_date = datetime.utcnow() - timedelta(days=30)
    if not end_date:
        end_date = datetime.utcnow()
    
    # Check permissions
    if current_user.role not in ["admin", "auditor"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view compliance statistics"
        )
    
    base_query = db.query(AuditEvent).filter(
        between(AuditEvent.event_timestamp, start_date, end_date)
    )
    
    # Total audit events
    total_audit_events = base_query.count()
    
    # Events by severity
    severity_stats = db.query(
        AuditEvent.severity, func.count(AuditEvent.id)
    ).filter(
        between(AuditEvent.event_timestamp, start_date, end_date)
    ).group_by(AuditEvent.severity).all()
    
    events_by_severity = {severity: count for severity, count in severity_stats}
    
    # Events by outcome
    outcome_stats = db.query(
        AuditEvent.outcome, func.count(AuditEvent.id)
    ).filter(
        between(AuditEvent.event_timestamp, start_date, end_date)
    ).group_by(AuditEvent.outcome).all()
    
    events_by_outcome = {outcome: count for outcome, count in outcome_stats}
    
    # High risk events
    high_risk_events = base_query.filter(AuditEvent.risk_score >= 80).count()
    
    # Compliance violations
    compliance_violations = base_query.filter(
        AuditEvent.outcome == AuditOutcome.FAILURE
    ).count()
    
    # Unresolved system events
    unresolved_incidents = db.query(SystemEvent).filter(
        and_(
            SystemEvent.is_resolved == False,
            SystemEvent.requires_attention == True,
            between(SystemEvent.event_timestamp, start_date, end_date)
        )
    ).count()
    
    # Average risk score
    avg_risk_score = db.query(func.avg(AuditEvent.risk_score)).filter(
        and_(
            between(AuditEvent.event_timestamp, start_date, end_date),
            AuditEvent.risk_score.isnot(None)
        )
    ).scalar() or 0.0
    
    # Data processing events
    data_processing_events = base_query.filter(
        AuditEvent.event_type.in_([
            AuditEventType.DOCUMENT_UPLOADED,
            AuditEventType.DOCUMENT_PROCESSED,
            AuditEventType.PII_DETECTED,
            AuditEventType.PII_REDACTED
        ])
    ).count()
    
    # PII access events
    pii_access_events = base_query.filter(AuditEvent.contains_pii == True).count()
    
    # Failed access attempts
    failed_access_attempts = base_query.filter(
        and_(
            AuditEvent.event_type == AuditEventType.USER_LOGIN,
            AuditEvent.outcome == AuditOutcome.FAILURE
        )
    ).count()
    
    return ComplianceStatsResponse(
        total_audit_events=total_audit_events,
        events_by_severity=events_by_severity,
        events_by_outcome=events_by_outcome,
        high_risk_events=high_risk_events,
        compliance_violations=compliance_violations,
        unresolved_incidents=unresolved_incidents,
        average_risk_score=round(float(avg_risk_score), 2),
        data_processing_events=data_processing_events,
        pii_access_events=pii_access_events,
        failed_access_attempts=failed_access_attempts
    )


@router.get("/overview")
async def get_compliance_overview(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """Get compliance overview for dashboard."""
    try:
        # Calculate date ranges
        now = datetime.utcnow()
        thirty_days_ago = now - timedelta(days=30)

        # GDPR Compliance Status
        gdpr_documents_processed = db.query(func.count(AuditEvent.id)).filter(
            and_(
                AuditEvent.event_type.in_(['document_processed', 'pii_detected']),
                AuditEvent.event_timestamp >= thirty_days_ago
            )
        ).scalar() or 0

        gdpr_violations = db.query(func.count(AuditEvent.id)).filter(
            and_(
                AuditEvent.compliance_status == 'violation',
                AuditEvent.event_timestamp >= thirty_days_ago
            )
        ).scalar() or 0

        gdpr_compliance_score = max(0, (gdpr_documents_processed - gdpr_violations) / max(gdpr_documents_processed, 1)) * 100

        # Data Retention Compliance
        retention_policies_active = db.query(func.count(CompliancePolicy.id)).filter(
            CompliancePolicy.is_active == True
        ).scalar() or 0

        # Audit Trail Coverage
        total_events = db.query(func.count(AuditEvent.id)).filter(
            AuditEvent.event_timestamp >= thirty_days_ago
        ).scalar() or 0

        audited_events = db.query(func.count(AuditEvent.id)).filter(
            and_(
                AuditEvent.event_timestamp >= thirty_days_ago,
                AuditEvent.audit_trail_complete == True
            )
        ).scalar() or 0

        audit_coverage = (audited_events / max(total_events, 1)) * 100

        # Risk Assessment
        high_risk_events = db.query(func.count(AuditEvent.id)).filter(
            and_(
                AuditEvent.risk_score >= 80,
                AuditEvent.event_timestamp >= thirty_days_ago
            )
        ).scalar() or 0

        # Overall compliance score
        overall_score = (gdpr_compliance_score + audit_coverage) / 2

        # Determine status
        if overall_score >= 95:
            compliance_status = "excellent"
        elif overall_score >= 85:
            compliance_status = "good"
        elif overall_score >= 70:
            compliance_status = "satisfactory"
        else:
            compliance_status = "needs_attention"

        return {
            "overall_compliance_score": round(overall_score, 1),
            "compliance_status": compliance_status,
            "gdpr_compliance": {
                "score": round(gdpr_compliance_score, 1),
                "documents_processed": gdpr_documents_processed,
                "violations": gdpr_violations,
                "status": "compliant" if gdpr_compliance_score >= 90 else "needs_review"
            },
            "data_retention": {
                "active_policies": retention_policies_active,
                "status": "active" if retention_policies_active > 0 else "inactive"
            },
            "audit_trail": {
                "coverage_percentage": round(audit_coverage, 1),
                "total_events": total_events,
                "audited_events": audited_events,
                "status": "complete" if audit_coverage >= 95 else "partial"
            },
            "risk_assessment": {
                "high_risk_events": high_risk_events,
                "status": "low" if high_risk_events < 5 else "moderate" if high_risk_events < 20 else "high"
            },
            "recent_activities": [
                {
                    "type": "compliance_check",
                    "message": f"Processed {gdpr_documents_processed} documents with GDPR compliance",
                    "timestamp": now.isoformat(),
                    "status": "success"
                },
                {
                    "type": "audit_trail",
                    "message": f"Maintained audit trail for {audited_events} events",
                    "timestamp": (now - timedelta(hours=6)).isoformat(),
                    "status": "info"
                }
            ]
        }

    except Exception as e:
        logger.error(f"Failed to get compliance overview: {e}")
        # Return fallback data
        return {
            "overall_compliance_score": 0.0,
            "compliance_status": "unknown",
            "gdpr_compliance": {
                "score": 0.0,
                "documents_processed": 0,
                "violations": 0,
                "status": "unknown"
            },
            "data_retention": {
                "active_policies": 0,
                "status": "inactive"
            },
            "audit_trail": {
                "coverage_percentage": 0.0,
                "total_events": 0,
                "audited_events": 0,
                "status": "unknown"
            },
            "risk_assessment": {
                "high_risk_events": 0,
                "status": "unknown"
            },
            "recent_activities": []
        }


# =============================================================================
# COMPLIANCE REPORTING
# =============================================================================

@router.post("/reports", response_model=Dict[str, Any])
async def generate_compliance_report(
    request: ComplianceReportRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("compliance_report_generate"))
):
    """Generate compliance report (Admin/Auditor only)."""
    
    if current_user.role not in ["admin", "auditor", "compliance_officer"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to generate compliance reports"
        )
    
    # Generate report ID
    report_id = uuid4()
    
    # Add background task to generate report
    background_tasks.add_task(
        _generate_compliance_report_task,
        report_id,
        request,
        current_user.id,
        db
    )
    
    logger.info(f"Compliance report generation started: {report_id} by {current_user.username}")
    
    return {
        "report_id": str(report_id),
        "message": "Compliance report generation started",
        "status": "processing",
        "estimated_completion": datetime.utcnow() + timedelta(minutes=5)
    }


async def _generate_compliance_report_task(
    report_id: UUID,
    request: ComplianceReportRequest,
    user_id: UUID,
    db: Session
):
    """Background task to generate compliance report."""
    
    try:
        # This would contain the actual report generation logic
        # For now, we'll simulate the process
        
        logger.info(f"Generating {request.report_type} report for {request.compliance_standard}")
        
        # Simulate report generation time
        import asyncio
        await asyncio.sleep(2)
        
        # Report generation logic would go here
        # - Query relevant audit events
        # - Format data according to compliance standard
        # - Generate PDF/Excel/CSV output
        # - Store in secure location
        
        report_path = f"/reports/compliance_{report_id}.{request.format}"
        
        logger.info(f"Compliance report generated: {report_id}")
        
    except Exception as e:
        logger.error(f"Failed to generate compliance report {report_id}: {e}")


@router.get("/reports/{report_id}/status")
async def get_report_status(
    report_id: UUID = Path(..., description="Report ID"),
    current_user: User = Depends(get_current_active_user)
):
    """Get compliance report generation status."""
    
    # This would check the actual report status
    # For now, we'll return a mock response
    
    return {
        "report_id": str(report_id),
        "status": "completed",
        "progress": 100,
        "created_at": datetime.utcnow() - timedelta(minutes=2),
        "completed_at": datetime.utcnow(),
        "file_size": 1024576,  # 1MB
        "download_url": f"/api/v1/compliance/reports/{report_id}/download"
    }


@router.get("/reports/{report_id}/download")
async def download_compliance_report(
    report_id: UUID = Path(..., description="Report ID"),
    current_user: User = Depends(get_current_active_user),
    audit_log = Depends(AuditLogDependency("compliance_report_download"))
):
    """Download compliance report."""
    
    # This would return the actual report file
    # For now, we'll return a placeholder response
    
    report_path = f"/reports/compliance_{report_id}.pdf"
    
    # Check if file exists and user has permission
    # Return FileResponse for actual file download
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Report file not found or not ready"
    )


# =============================================================================
# DATA RETENTION & CLEANUP
# =============================================================================

@router.post("/audit/cleanup")
async def cleanup_audit_data(
    days_to_keep: int = Query(90, ge=30, le=365, description="Days of audit data to keep"),
    dry_run: bool = Query(True, description="Perform dry run without actual deletion"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("audit_cleanup"))
):
    """Cleanup old audit data (Admin only)."""
    
    cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
    
    # Count events to be deleted
    events_to_delete = db.query(AuditEvent).filter(
        AuditEvent.event_timestamp < cutoff_date
    ).count()
    
    if dry_run:
        return {
            "message": "Dry run completed",
            "events_to_delete": events_to_delete,
            "cutoff_date": cutoff_date.isoformat(),
            "action": "none"
        }
    
    # Perform actual cleanup
    deleted_count = db.query(AuditEvent).filter(
        AuditEvent.event_timestamp < cutoff_date
    ).delete()
    
    db.commit()
    
    logger.info(f"Audit data cleanup: deleted {deleted_count} events older than {cutoff_date}")
    
    return {
        "message": "Audit cleanup completed",
        "events_deleted": deleted_count,
        "cutoff_date": cutoff_date.isoformat(),
        "action": "deleted"
    }


# =============================================================================
# POLICY APPLICATIONS TRACKING
# =============================================================================

@router.get("/policy-applications", response_model=List[Dict[str, Any]])
async def get_policy_applications(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=200, description="Items per page"),
    policy_id: Optional[UUID] = Query(None, description="Filter by policy ID"),
    status: Optional[str] = Query(None, description="Filter by application status"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """Get policy application history."""
    
    query = db.query(PolicyApplication)
    
    # Apply filters
    if policy_id:
        query = query.filter(PolicyApplication.policy_id == policy_id)
    
    if status:
        query = query.filter(PolicyApplication.application_status == status)
    
    # Apply pagination
    offset = (page - 1) * per_page
    applications = query.order_by(desc(PolicyApplication.started_at))\
                       .offset(offset)\
                       .limit(per_page)\
                       .all()
    
    # Convert to dict format
    results = []
    for app in applications:
        results.append({
            "id": str(app.id),
            "policy_id": str(app.policy_id),
            "target_type": app.target_type,
            "target_id": str(app.target_id),
            "target_name": app.target_name,
            "application_status": app.application_status,
            "rules_applied": app.rules_applied,
            "rules_failed": app.rules_failed,
            "pii_items_processed": app.pii_items_processed,
            "pii_items_redacted": app.pii_items_redacted,
            "compliance_score": app.compliance_score,
            "started_at": app.started_at,
            "completed_at": app.completed_at,
            "duration_seconds": app.duration_seconds,
            "processing_summary": app.processing_summary
        })
    
    return results