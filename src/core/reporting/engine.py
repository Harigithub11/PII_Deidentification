"""
Core Reporting Engine

Provides the main interface for generating reports, managing report requests,
and coordinating between different reporting components.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field

from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session

from ..database.session import transaction_scope, get_db_session
from ..database.repositories import RepositoryFactory
from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class ReportStatus(str, Enum):
    """Report generation status."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReportType(str, Enum):
    """Types of reports that can be generated."""
    AUDIT_TRAIL = "audit_trail"
    COMPLIANCE = "compliance"
    SECURITY = "security"
    PERFORMANCE = "performance"
    USER_ACTIVITY = "user_activity"
    SYSTEM_HEALTH = "system_health"
    DATA_PROCESSING = "data_processing"
    RISK_ASSESSMENT = "risk_assessment"
    CUSTOM = "custom"


class ReportPriority(str, Enum):
    """Report generation priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ReportMetrics:
    """Metrics about report generation."""
    generation_time_ms: int
    data_points: int
    query_count: int
    cache_hits: int
    cache_misses: int
    memory_usage_mb: float
    file_size_bytes: Optional[int] = None


class ReportRequest(BaseModel):
    """Request model for report generation."""
    
    id: UUID = Field(default_factory=uuid4)
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
    cache_enabled: bool = True
    
    # Requester information
    requested_by: UUID
    requested_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Compliance and security
    compliance_standards: List[str] = Field(default_factory=list)
    data_classification: str = "internal"
    access_restrictions: List[str] = Field(default_factory=list)
    
    @validator('end_date')
    def end_date_after_start_date(cls, v, values):
        if 'start_date' in values and v <= values['start_date']:
            raise ValueError('end_date must be after start_date')
        return v
    
    @validator('start_date', 'end_date')
    def dates_not_future(cls, v):
        if v > datetime.utcnow():
            raise ValueError('dates cannot be in the future')
        return v


class ReportResult(BaseModel):
    """Result model for generated reports."""
    
    id: UUID
    request_id: UUID
    status: ReportStatus
    
    # Report metadata
    title: str
    report_type: ReportType
    generated_at: datetime
    generated_by: UUID
    
    # Content
    file_path: Optional[str] = None
    file_size_bytes: Optional[int] = None
    file_hash: Optional[str] = None
    
    # Statistics
    data_points_count: int = 0
    time_range_days: int = 0
    
    # Performance metrics
    generation_time_ms: int = 0
    query_execution_time_ms: int = 0
    
    # Error information
    error_message: Optional[str] = None
    error_details: Dict[str, Any] = Field(default_factory=dict)
    
    # Security and compliance
    contains_sensitive_data: bool = False
    encryption_key_id: Optional[str] = None
    access_restrictions: List[str] = Field(default_factory=list)
    
    # Expiry and cleanup
    expires_at: Optional[datetime] = None
    auto_delete: bool = True


class ReportingEngine:
    """Main reporting engine for coordinating report generation."""
    
    def __init__(self, session: Optional[Session] = None):
        self._session = session
        self._active_reports: Dict[UUID, ReportRequest] = {}
        self._report_cache: Dict[str, ReportResult] = {}
        
    @property
    def session(self) -> Session:
        """Get current database session."""
        if self._session:
            return self._session
        # In practice, this would use dependency injection
        raise RuntimeError("No database session available")
    
    async def generate_report(self, request: ReportRequest) -> ReportResult:
        """
        Generate a report based on the request.
        
        Args:
            request: Report generation request
            
        Returns:
            Report result with metadata and file information
        """
        start_time = datetime.utcnow()
        
        try:
            # Validate request
            self._validate_request(request)
            
            # Check cache first
            if request.cache_enabled:
                cached_result = self._check_cache(request)
                if cached_result:
                    logger.info(f"Returning cached report: {request.id}")
                    return cached_result
            
            # Track active report
            self._active_reports[request.id] = request
            
            # Generate report based on type
            result = await self._generate_by_type(request)
            
            # Update result with timing information
            generation_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            result.generation_time_ms = int(generation_time)
            result.generated_at = datetime.utcnow()
            result.status = ReportStatus.COMPLETED
            
            # Cache result if enabled
            if request.cache_enabled:
                self._cache_result(request, result)
            
            logger.info(f"Report generated successfully: {request.id} in {generation_time}ms")
            return result
            
        except Exception as e:
            logger.error(f"Report generation failed: {request.id} - {e}")
            
            # Create error result
            error_result = ReportResult(
                id=uuid4(),
                request_id=request.id,
                status=ReportStatus.FAILED,
                title=request.title,
                report_type=request.report_type,
                generated_at=datetime.utcnow(),
                generated_by=request.requested_by,
                error_message=str(e),
                error_details={"exception_type": type(e).__name__}
            )
            
            return error_result
            
        finally:
            # Clean up active report tracking
            self._active_reports.pop(request.id, None)
    
    def _validate_request(self, request: ReportRequest) -> None:
        """Validate report request."""
        # Check date range limits
        date_range = request.end_date - request.start_date
        max_range_days = settings.max_report_date_range_days if hasattr(settings, 'max_report_date_range_days') else 365
        
        if date_range.days > max_range_days:
            raise ValueError(f"Date range cannot exceed {max_range_days} days")
        
        # Check user permissions (in a real implementation)
        # This would check if the requesting user has permission to generate this type of report
        
        # Validate filters
        if request.filters:
            self._validate_filters(request.filters)
    
    def _validate_filters(self, filters: Dict[str, Any]) -> None:
        """Validate report filters."""
        allowed_filter_keys = {
            'severity', 'outcome', 'event_type', 'user_role', 'ip_address',
            'compliance_standard', 'risk_score_min', 'risk_score_max'
        }
        
        for key in filters.keys():
            if key not in allowed_filter_keys:
                raise ValueError(f"Invalid filter key: {key}")
    
    def _check_cache(self, request: ReportRequest) -> Optional[ReportResult]:
        """Check if a similar report is cached."""
        cache_key = self._generate_cache_key(request)
        return self._report_cache.get(cache_key)
    
    def _cache_result(self, request: ReportRequest, result: ReportResult) -> None:
        """Cache report result."""
        cache_key = self._generate_cache_key(request)
        
        # Set expiry based on report type
        cache_expiry_hours = {
            ReportType.AUDIT_TRAIL: 1,
            ReportType.COMPLIANCE: 24,
            ReportType.SECURITY: 6,
            ReportType.PERFORMANCE: 12,
            ReportType.USER_ACTIVITY: 2,
        }.get(request.report_type, 6)
        
        result.expires_at = datetime.utcnow() + timedelta(hours=cache_expiry_hours)
        self._report_cache[cache_key] = result
    
    def _generate_cache_key(self, request: ReportRequest) -> str:
        """Generate cache key for report request."""
        import hashlib
        
        cache_data = {
            'report_type': request.report_type.value,
            'start_date': request.start_date.isoformat(),
            'end_date': request.end_date.isoformat(),
            'filters': request.filters,
            'user_ids': [str(uid) for uid in request.user_ids],
            'resource_types': request.resource_types,
            'event_types': request.event_types,
        }
        
        cache_string = str(sorted(cache_data.items()))
        return hashlib.md5(cache_string.encode()).hexdigest()
    
    async def _generate_by_type(self, request: ReportRequest) -> ReportResult:
        """Generate report based on type."""
        from .analytics import AuditAnalytics
        from .generator import ReportGenerator
        from .queries import QueryBuilder
        
        # Create result object
        result = ReportResult(
            id=uuid4(),
            request_id=request.id,
            status=ReportStatus.PROCESSING,
            title=request.title,
            report_type=request.report_type,
            generated_by=request.requested_by
        )
        
        # Build query based on request
        query_builder = QueryBuilder(self.session)
        report_query = query_builder.build_audit_query(
            start_date=request.start_date,
            end_date=request.end_date,
            filters=request.filters,
            user_ids=request.user_ids,
            resource_types=request.resource_types,
            event_types=request.event_types
        )
        
        # Get data based on report type
        if request.report_type == ReportType.AUDIT_TRAIL:
            analytics = AuditAnalytics(self.session)
            data = await analytics.generate_audit_trail_report(request, report_query)
            
        elif request.report_type == ReportType.COMPLIANCE:
            from .compliance.base import ComplianceReporter
            reporter = ComplianceReporter(self.session)
            data = await reporter.generate_compliance_report(request, report_query)
            
        elif request.report_type == ReportType.SECURITY:
            from .security.threats import ThreatDetector
            detector = ThreatDetector(self.session)
            data = await detector.generate_security_report(request, report_query)
            
        else:
            # Default audit trail report
            analytics = AuditAnalytics(self.session)
            data = await analytics.generate_audit_trail_report(request, report_query)
        
        # Generate report file
        generator = ReportGenerator()
        file_info = await generator.generate_report_file(
            data=data,
            request=request,
            template_name=f"{request.report_type.value}_template"
        )
        
        # Update result with file information
        result.file_path = file_info.get("file_path")
        result.file_size_bytes = file_info.get("file_size")
        result.file_hash = file_info.get("file_hash")
        result.data_points_count = len(data.get("events", []))
        result.time_range_days = (request.end_date - request.start_date).days
        
        return result
    
    def get_active_reports(self) -> List[Dict[str, Any]]:
        """Get information about currently active reports."""
        return [
            {
                "id": str(request.id),
                "type": request.report_type.value,
                "title": request.title,
                "requested_by": str(request.requested_by),
                "requested_at": request.requested_at.isoformat(),
                "priority": request.priority.value
            }
            for request in self._active_reports.values()
        ]
    
    def cancel_report(self, report_id: UUID) -> bool:
        """Cancel an active report generation."""
        if report_id in self._active_reports:
            del self._active_reports[report_id]
            logger.info(f"Report cancelled: {report_id}")
            return True
        return False
    
    def cleanup_cache(self) -> int:
        """Clean up expired cache entries."""
        current_time = datetime.utcnow()
        expired_keys = [
            key for key, result in self._report_cache.items()
            if result.expires_at and result.expires_at <= current_time
        ]
        
        for key in expired_keys:
            del self._report_cache[key]
        
        logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
        return len(expired_keys)
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_entries = len(self._report_cache)
        expired_entries = sum(
            1 for result in self._report_cache.values()
            if result.expires_at and result.expires_at <= datetime.utcnow()
        )
        
        return {
            "total_entries": total_entries,
            "active_entries": total_entries - expired_entries,
            "expired_entries": expired_entries,
            "cache_memory_estimate_mb": total_entries * 0.5  # Rough estimate
        }


# Global reporting engine instance
_reporting_engine: Optional[ReportingEngine] = None


def get_reporting_engine(session: Optional[Session] = None) -> ReportingEngine:
    """Get the global reporting engine instance."""
    global _reporting_engine
    if _reporting_engine is None:
        _reporting_engine = ReportingEngine(session)
    return _reporting_engine


def initialize_reporting_engine(session: Optional[Session] = None) -> ReportingEngine:
    """Initialize the reporting engine."""
    global _reporting_engine
    _reporting_engine = ReportingEngine(session)
    logger.info("Reporting engine initialized successfully")
    return _reporting_engine