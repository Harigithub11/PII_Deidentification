"""
Reporting API Endpoints

Provides REST API endpoints for report generation, template management,
audit trail reporting, and compliance documentation.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from uuid import UUID, uuid4
import asyncio
from io import BytesIO
import zipfile

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks, UploadFile, File
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.database.session import get_db_session
from ..core.reporting import (
    ReportingEngine, ReportRequest, ReportResult, ReportType,
    ReportStatus, ReportPriority, get_reporting_engine
)
from ..core.security.auth import get_current_user, User
from ..core.config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/api/v1/reports", tags=["Reporting & Analytics"])


# Request/Response Models

class CreateReportRequest(BaseModel):
    """Request model for creating a report."""
    report_type: ReportType
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    
    # Time range
    start_date: datetime
    end_date: datetime
    
    # Filtering
    filters: Dict[str, Any] = Field(default_factory=dict)
    user_ids: List[UUID] = Field(default_factory=list)
    resource_types: List[str] = Field(default_factory=list)
    event_types: List[str] = Field(default_factory=list)
    
    # Output options
    output_format: str = "pdf"  # pdf, excel, json, csv
    include_details: bool = True
    include_charts: bool = True
    
    # Processing options
    priority: ReportPriority = ReportPriority.NORMAL
    async_processing: bool = False
    
    # Compliance settings
    compliance_standards: List[str] = Field(default_factory=list)
    data_classification: str = "internal"


class ReportResponse(BaseModel):
    """Response model for report operations."""
    id: UUID
    request_id: UUID
    status: ReportStatus
    title: str
    report_type: ReportType
    generated_at: datetime
    generated_by: UUID
    file_path: Optional[str]
    file_size_bytes: Optional[int]
    data_points_count: int
    generation_time_ms: int
    error_message: Optional[str]
    contains_sensitive_data: bool
    expires_at: Optional[datetime]


class ReportListResponse(BaseModel):
    """Response model for listing reports."""
    reports: List[ReportResponse]
    total_count: int
    page: int
    page_size: int
    has_more: bool


class ReportTemplateRequest(BaseModel):
    """Request model for creating report template."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    report_type: ReportType
    template_content: str
    variables: Dict[str, Any] = Field(default_factory=dict)
    styling: Dict[str, Any] = Field(default_factory=dict)
    is_public: bool = False
    category: str = "custom"
    tags: List[str] = Field(default_factory=list)


class ReportTemplateResponse(BaseModel):
    """Response model for report template."""
    id: UUID
    name: str
    description: Optional[str]
    report_type: ReportType
    created_by: UUID
    created_at: datetime
    updated_at: datetime
    is_public: bool
    category: str
    tags: List[str]
    usage_count: int = 0


# Report Generation Endpoints

@router.post("/", response_model=ReportResponse)
async def create_report(
    request: CreateReportRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Create and generate a new report."""
    try:
        # Create report request
        report_request = ReportRequest(
            report_type=request.report_type,
            title=request.title,
            description=request.description,
            start_date=request.start_date,
            end_date=request.end_date,
            filters=request.filters,
            user_ids=request.user_ids,
            resource_types=request.resource_types,
            event_types=request.event_types,
            output_format=request.output_format,
            include_details=request.include_details,
            include_charts=request.include_charts,
            priority=request.priority,
            async_processing=request.async_processing,
            requested_by=current_user.id,
            compliance_standards=request.compliance_standards,
            data_classification=request.data_classification
        )
        
        # Get reporting engine
        reporting_engine = get_reporting_engine(db)
        
        if request.async_processing:
            # Queue for background processing
            background_tasks.add_task(
                _process_report_async,
                reporting_engine,
                report_request
            )
            
            # Return immediate response
            return ReportResponse(
                id=uuid4(),
                request_id=report_request.id,
                status=ReportStatus.PENDING,
                title=report_request.title,
                report_type=report_request.report_type,
                generated_at=datetime.utcnow(),
                generated_by=current_user.id,
                file_path=None,
                file_size_bytes=None,
                data_points_count=0,
                generation_time_ms=0,
                error_message=None,
                contains_sensitive_data=False,
                expires_at=None
            )
        else:
            # Generate report synchronously
            result = await reporting_engine.generate_report(report_request)
            
            return ReportResponse(
                id=result.id,
                request_id=result.request_id,
                status=result.status,
                title=result.title,
                report_type=result.report_type,
                generated_at=result.generated_at,
                generated_by=result.generated_by,
                file_path=result.file_path,
                file_size_bytes=result.file_size_bytes,
                data_points_count=result.data_points_count,
                generation_time_ms=result.generation_time_ms,
                error_message=result.error_message,
                contains_sensitive_data=result.contains_sensitive_data,
                expires_at=result.expires_at
            )
        
    except Exception as e:
        logger.error(f"Failed to create report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create report: {str(e)}")


@router.get("/", response_model=ReportListResponse)
async def list_reports(
    report_type: Optional[ReportType] = None,
    status: Optional[ReportStatus] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """List reports with optional filtering."""
    try:
        # In a real implementation, this would query the database
        # For now, return sample reports
        
        sample_reports = [
            ReportResponse(
                id=uuid4(),
                request_id=uuid4(),
                status=ReportStatus.COMPLETED,
                title="Security Audit Report",
                report_type=ReportType.AUDIT_TRAIL,
                generated_at=datetime.utcnow() - timedelta(hours=2),
                generated_by=current_user.id,
                file_path="/reports/security_audit_20240101.pdf",
                file_size_bytes=2048576,
                data_points_count=1500,
                generation_time_ms=5432,
                error_message=None,
                contains_sensitive_data=True,
                expires_at=datetime.utcnow() + timedelta(days=30)
            ),
            ReportResponse(
                id=uuid4(),
                request_id=uuid4(),
                status=ReportStatus.COMPLETED,
                title="Compliance Report Q4",
                report_type=ReportType.COMPLIANCE,
                generated_at=datetime.utcnow() - timedelta(days=1),
                generated_by=current_user.id,
                file_path="/reports/compliance_q4_2024.pdf",
                file_size_bytes=3145728,
                data_points_count=2800,
                generation_time_ms=8765,
                error_message=None,
                contains_sensitive_data=False,
                expires_at=datetime.utcnow() + timedelta(days=90)
            ),
            ReportResponse(
                id=uuid4(),
                request_id=uuid4(),
                status=ReportStatus.PROCESSING,
                title="User Activity Analysis",
                report_type=ReportType.USER_ACTIVITY,
                generated_at=datetime.utcnow(),
                generated_by=current_user.id,
                file_path=None,
                file_size_bytes=None,
                data_points_count=0,
                generation_time_ms=0,
                error_message=None,
                contains_sensitive_data=False,
                expires_at=None
            )
        ]
        
        # Apply filters
        filtered_reports = sample_reports
        if report_type:
            filtered_reports = [r for r in filtered_reports if r.report_type == report_type]
        if status:
            filtered_reports = [r for r in filtered_reports if r.status == status]
        
        # Pagination
        offset = (page - 1) * page_size
        paginated_reports = filtered_reports[offset:offset + page_size]
        
        return ReportListResponse(
            reports=paginated_reports,
            total_count=len(filtered_reports),
            page=page,
            page_size=page_size,
            has_more=offset + page_size < len(filtered_reports)
        )
        
    except Exception as e:
        logger.error(f"Failed to list reports: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list reports: {str(e)}")


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Get report details by ID."""
    try:
        # In a real implementation, this would query the database
        # For now, return sample report
        
        return ReportResponse(
            id=report_id,
            request_id=uuid4(),
            status=ReportStatus.COMPLETED,
            title="Sample Report",
            report_type=ReportType.AUDIT_TRAIL,
            generated_at=datetime.utcnow() - timedelta(hours=1),
            generated_by=current_user.id,
            file_path=f"/reports/report_{report_id}.pdf",
            file_size_bytes=1024000,
            data_points_count=500,
            generation_time_ms=3000,
            error_message=None,
            contains_sensitive_data=False,
            expires_at=datetime.utcnow() + timedelta(days=30)
        )
        
    except Exception as e:
        logger.error(f"Failed to get report {report_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get report: {str(e)}")


@router.delete("/{report_id}")
async def delete_report(
    report_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Delete a report."""
    try:
        # In a real implementation, this would delete from database and filesystem
        
        return {
            "message": "Report deleted successfully",
            "report_id": str(report_id),
            "deleted_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to delete report {report_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete report: {str(e)}")


# Report Download Endpoints

@router.get("/{report_id}/download")
async def download_report(
    report_id: UUID,
    format: Optional[str] = Query(None, regex="^(pdf|excel|json|csv)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Download report file."""
    try:
        # In a real implementation, this would:
        # 1. Verify report exists and user has access
        # 2. Get file from storage
        # 3. Return file stream
        
        # For now, return sample file response
        filename = f"report_{report_id}.pdf"
        
        # Create a simple PDF-like response
        content = f"Sample report content for {report_id}".encode()
        
        return StreamingResponse(
            BytesIO(content),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        logger.error(f"Failed to download report {report_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to download report: {str(e)}")


@router.post("/{report_id}/export")
async def export_report(
    report_id: UUID,
    export_formats: List[str],
    include_attachments: bool = False,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Export report in multiple formats as ZIP archive."""
    try:
        # Create ZIP file in memory
        zip_buffer = BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for format_type in export_formats:
                # Generate content for each format
                if format_type == "pdf":
                    content = f"PDF report content for {report_id}".encode()
                    zip_file.writestr(f"report_{report_id}.pdf", content)
                elif format_type == "excel":
                    content = f"Excel report content for {report_id}".encode()
                    zip_file.writestr(f"report_{report_id}.xlsx", content)
                elif format_type == "json":
                    content = f'{{"report_id": "{report_id}", "data": "sample"}}'.encode()
                    zip_file.writestr(f"report_{report_id}.json", content)
                elif format_type == "csv":
                    content = f"Column1,Column2\nValue1,Value2\n".encode()
                    zip_file.writestr(f"report_{report_id}.csv", content)
            
            if include_attachments:
                # Add sample attachment
                attachment_content = f"Attachment data for {report_id}".encode()
                zip_file.writestr(f"attachments/data_{report_id}.txt", attachment_content)
        
        zip_buffer.seek(0)
        
        return StreamingResponse(
            BytesIO(zip_buffer.getvalue()),
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename=report_{report_id}_export.zip"}
        )
        
    except Exception as e:
        logger.error(f"Failed to export report {report_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to export report: {str(e)}")


# Report Template Management

@router.post("/templates", response_model=ReportTemplateResponse)
async def create_report_template(
    request: ReportTemplateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Create a new report template."""
    try:
        template_id = uuid4()
        
        # In a real implementation, this would save to database
        
        return ReportTemplateResponse(
            id=template_id,
            name=request.name,
            description=request.description,
            report_type=request.report_type,
            created_by=current_user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            is_public=request.is_public,
            category=request.category,
            tags=request.tags,
            usage_count=0
        )
        
    except Exception as e:
        logger.error(f"Failed to create report template: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create template: {str(e)}")


@router.get("/templates", response_model=List[ReportTemplateResponse])
async def list_report_templates(
    report_type: Optional[ReportType] = None,
    category: Optional[str] = None,
    include_public: bool = True,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """List available report templates."""
    try:
        # Return sample templates
        templates = [
            ReportTemplateResponse(
                id=uuid4(),
                name="Standard Audit Template",
                description="Standard template for audit trail reports",
                report_type=ReportType.AUDIT_TRAIL,
                created_by=current_user.id,
                created_at=datetime.utcnow() - timedelta(days=30),
                updated_at=datetime.utcnow() - timedelta(days=10),
                is_public=True,
                category="audit",
                tags=["standard", "audit", "compliance"],
                usage_count=45
            ),
            ReportTemplateResponse(
                id=uuid4(),
                name="Executive Summary Template",
                description="Executive-level summary report template",
                report_type=ReportType.COMPLIANCE,
                created_by=current_user.id,
                created_at=datetime.utcnow() - timedelta(days=60),
                updated_at=datetime.utcnow() - timedelta(days=5),
                is_public=True,
                category="executive",
                tags=["executive", "summary", "high-level"],
                usage_count=23
            )
        ]
        
        # Apply filters
        if report_type:
            templates = [t for t in templates if t.report_type == report_type]
        if category:
            templates = [t for t in templates if t.category == category]
        if not include_public:
            templates = [t for t in templates if not t.is_public or t.created_by == current_user.id]
        
        return templates
        
    except Exception as e:
        logger.error(f"Failed to list report templates: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list templates: {str(e)}")


@router.get("/templates/{template_id}", response_model=ReportTemplateResponse)
async def get_report_template(
    template_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Get report template details."""
    try:
        return ReportTemplateResponse(
            id=template_id,
            name="Sample Template",
            description="Sample template description",
            report_type=ReportType.AUDIT_TRAIL,
            created_by=current_user.id,
            created_at=datetime.utcnow() - timedelta(days=30),
            updated_at=datetime.utcnow() - timedelta(days=10),
            is_public=True,
            category="audit",
            tags=["sample", "template"],
            usage_count=15
        )
        
    except Exception as e:
        logger.error(f"Failed to get report template {template_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get template: {str(e)}")


@router.post("/templates/{template_id}/generate", response_model=ReportResponse)
async def generate_from_template(
    template_id: UUID,
    template_variables: Dict[str, Any],
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Generate report using a template."""
    try:
        # In a real implementation, this would:
        # 1. Load template from database
        # 2. Apply variables to template
        # 3. Generate report
        
        report_id = uuid4()
        
        # Queue for background processing
        background_tasks.add_task(
            _generate_template_report_async,
            template_id,
            template_variables,
            current_user.id
        )
        
        return ReportResponse(
            id=report_id,
            request_id=uuid4(),
            status=ReportStatus.PROCESSING,
            title=f"Report from Template {template_id}",
            report_type=ReportType.CUSTOM,
            generated_at=datetime.utcnow(),
            generated_by=current_user.id,
            file_path=None,
            file_size_bytes=None,
            data_points_count=0,
            generation_time_ms=0,
            error_message=None,
            contains_sensitive_data=False,
            expires_at=None
        )
        
    except Exception as e:
        logger.error(f"Failed to generate from template {template_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate from template: {str(e)}")


# Report Analytics and Statistics

@router.get("/analytics/summary")
async def get_report_analytics(
    time_range_days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Get report generation analytics and statistics."""
    try:
        # In a real implementation, this would query actual analytics data
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=time_range_days)
        
        analytics = {
            "time_range": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": time_range_days
            },
            "report_counts": {
                "total_generated": 156,
                "by_type": {
                    ReportType.AUDIT_TRAIL.value: 45,
                    ReportType.COMPLIANCE.value: 32,
                    ReportType.SECURITY.value: 28,
                    ReportType.PERFORMANCE.value: 21,
                    ReportType.USER_ACTIVITY.value: 18,
                    ReportType.CUSTOM.value: 12
                },
                "by_status": {
                    ReportStatus.COMPLETED.value: 142,
                    ReportStatus.FAILED.value: 8,
                    ReportStatus.PROCESSING.value: 4,
                    ReportStatus.PENDING.value: 2
                }
            },
            "performance_metrics": {
                "avg_generation_time_ms": 4532,
                "total_data_points": 125000,
                "avg_file_size_mb": 2.8,
                "cache_hit_ratio": 0.67
            },
            "usage_trends": [
                {"date": "2024-01-01", "count": 12},
                {"date": "2024-01-02", "count": 8},
                {"date": "2024-01-03", "count": 15}
            ],
            "top_templates": [
                {"template_id": str(uuid4()), "name": "Standard Audit", "usage_count": 45},
                {"template_id": str(uuid4()), "name": "Compliance Summary", "usage_count": 32}
            ]
        }
        
        return analytics
        
    except Exception as e:
        logger.error(f"Failed to get report analytics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get analytics: {str(e)}")


# Background Task Functions

async def _process_report_async(reporting_engine: ReportingEngine, request: ReportRequest):
    """Background task for processing reports asynchronously."""
    try:
        result = await reporting_engine.generate_report(request)
        logger.info(f"Background report generated: {result.id}")
    except Exception as e:
        logger.error(f"Background report generation failed: {e}")


async def _generate_template_report_async(template_id: UUID, variables: Dict[str, Any], user_id: UUID):
    """Background task for generating reports from templates."""
    try:
        # Simulate template report generation
        await asyncio.sleep(5)  # Simulate processing time
        logger.info(f"Template report generated: {template_id} for user {user_id}")
    except Exception as e:
        logger.error(f"Template report generation failed: {e}")


# Health Check

@router.get("/health")
async def reporting_health():
    """Get reporting system health status."""
    try:
        reporting_engine = get_reporting_engine()
        
        # Get active reports
        active_reports = reporting_engine.get_active_reports()
        
        # Get cache stats (if available)
        cache_stats = {}
        if hasattr(reporting_engine, 'get_cache_stats'):
            cache_stats = reporting_engine.get_cache_stats()
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "active_reports": len(active_reports),
            "cache_stats": cache_stats,
            "version": "1.0.0"
        }
        
    except Exception as e:
        logger.error(f"Reporting health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }