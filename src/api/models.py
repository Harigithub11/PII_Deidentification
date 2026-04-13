"""
Standardized API Response Models

Common response models, error schemas, and data transfer objects
for consistent API responses across the De-identification System.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Generic, TypeVar, Union
from uuid import UUID
from enum import Enum

from pydantic import BaseModel, Field, validator
from pydantic.generics import GenericModel

# Type variable for generic responses
DataType = TypeVar('DataType')


# =============================================================================
# STANDARD RESPONSE ENVELOPES
# =============================================================================

class APIStatus(str, Enum):
    """API response status values."""
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    PARTIAL = "partial"


class APIResponse(GenericModel, Generic[DataType]):
    """Standard API response wrapper."""
    status: APIStatus = Field(..., description="Response status")
    message: str = Field(..., description="Human-readable message")
    data: Optional[DataType] = Field(None, description="Response data")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")
    request_id: Optional[str] = Field(None, description="Request correlation ID")
    
    class Config:
        use_enum_values = True


class APIError(BaseModel):
    """Standard API error response."""
    status: APIStatus = APIStatus.ERROR
    message: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Specific error code")
    error_details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
    request_id: Optional[str] = Field(None, description="Request correlation ID")
    
    class Config:
        use_enum_values = True


class ValidationError(BaseModel):
    """Validation error details."""
    field: str = Field(..., description="Field that failed validation")
    message: str = Field(..., description="Validation error message")
    rejected_value: Optional[Any] = Field(None, description="Value that was rejected")


class ValidationErrorResponse(BaseModel):
    """Response for validation errors."""
    status: APIStatus = APIStatus.ERROR
    message: str = "Validation failed"
    validation_errors: List[ValidationError] = Field(..., description="List of validation errors")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_id: Optional[str] = Field(None, description="Request correlation ID")


# =============================================================================
# PAGINATION MODELS
# =============================================================================

class PaginationMetadata(BaseModel):
    """Pagination metadata."""
    page: int = Field(..., ge=1, description="Current page number")
    per_page: int = Field(..., ge=1, description="Items per page")
    total_items: int = Field(..., ge=0, description="Total number of items")
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    has_next: bool = Field(..., description="Whether there is a next page")
    has_prev: bool = Field(..., description="Whether there is a previous page")
    next_page: Optional[int] = Field(None, description="Next page number")
    prev_page: Optional[int] = Field(None, description="Previous page number")


class PaginatedResponse(GenericModel, Generic[DataType]):
    """Paginated response wrapper."""
    status: APIStatus = APIStatus.SUCCESS
    message: str = "Data retrieved successfully"
    data: List[DataType] = Field(..., description="Paginated data items")
    pagination: PaginationMetadata = Field(..., description="Pagination information")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_id: Optional[str] = Field(None, description="Request correlation ID")
    
    class Config:
        use_enum_values = True


# =============================================================================
# OPERATION RESULT MODELS
# =============================================================================

class OperationResult(BaseModel):
    """Standard operation result."""
    success: bool = Field(..., description="Whether operation succeeded")
    message: str = Field(..., description="Operation result message")
    operation_id: Optional[UUID] = Field(None, description="Unique operation identifier")
    resource_id: Optional[UUID] = Field(None, description="ID of affected resource")
    affected_count: Optional[int] = Field(None, description="Number of affected items")
    duration_ms: Optional[float] = Field(None, description="Operation duration in milliseconds")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional operation details")


class BulkOperationResult(BaseModel):
    """Result of bulk operations."""
    success: bool = Field(..., description="Overall operation success")
    message: str = Field(..., description="Overall operation message")
    total_items: int = Field(..., ge=0, description="Total items processed")
    successful_items: int = Field(..., ge=0, description="Successfully processed items")
    failed_items: int = Field(..., ge=0, description="Failed items")
    skipped_items: int = Field(0, ge=0, description="Skipped items")
    success_rate: float = Field(..., ge=0, le=100, description="Success rate percentage")
    operation_id: UUID = Field(..., description="Bulk operation identifier")
    started_at: datetime = Field(..., description="Operation start time")
    completed_at: Optional[datetime] = Field(None, description="Operation completion time")
    duration_seconds: Optional[float] = Field(None, description="Total operation duration")
    errors: List[Dict[str, Any]] = Field(default_factory=list, description="Error details")
    
    @validator('success_rate', always=True)
    def calculate_success_rate(cls, v, values):
        total = values.get('total_items', 0)
        successful = values.get('successful_items', 0)
        return round((successful / total * 100) if total > 0 else 0, 2)


# =============================================================================
# PROCESSING STATUS MODELS
# =============================================================================

class ProcessingStatus(str, Enum):
    """Processing status values."""
    PENDING = "pending"
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    PAUSED = "paused"


class ProcessingProgress(BaseModel):
    """Processing progress information."""
    status: ProcessingStatus = Field(..., description="Current processing status")
    progress_percentage: float = Field(..., ge=0, le=100, description="Completion percentage")
    current_step: str = Field(..., description="Current processing step")
    steps_completed: int = Field(..., ge=0, description="Number of completed steps")
    total_steps: int = Field(..., ge=0, description="Total number of steps")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion time")
    started_at: Optional[datetime] = Field(None, description="Processing start time")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update time")
    
    class Config:
        use_enum_values = True


class JobStatusResponse(BaseModel):
    """Job status response model."""
    job_id: UUID = Field(..., description="Job identifier")
    job_name: str = Field(..., description="Job name")
    job_type: str = Field(..., description="Type of job")
    status: ProcessingStatus = Field(..., description="Current job status")
    progress: ProcessingProgress = Field(..., description="Processing progress")
    created_by: UUID = Field(..., description="User who created the job")
    created_at: datetime = Field(..., description="Job creation time")
    priority: str = Field(..., description="Job priority level")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    result_summary: Optional[Dict[str, Any]] = Field(None, description="Job results summary")
    
    class Config:
        use_enum_values = True


# =============================================================================
# RESOURCE MODELS
# =============================================================================

class ResourceIdentifier(BaseModel):
    """Standard resource identifier."""
    id: UUID = Field(..., description="Resource unique identifier")
    name: str = Field(..., description="Resource name")
    type: str = Field(..., description="Resource type")
    created_at: datetime = Field(..., description="Resource creation time")
    updated_at: datetime = Field(..., description="Resource last update time")


class ResourceStats(BaseModel):
    """Resource statistics."""
    total_count: int = Field(..., ge=0, description="Total resource count")
    active_count: int = Field(..., ge=0, description="Active resource count")
    inactive_count: int = Field(..., ge=0, description="Inactive resource count")
    created_today: int = Field(..., ge=0, description="Resources created today")
    updated_today: int = Field(..., ge=0, description="Resources updated today")
    average_processing_time: Optional[float] = Field(None, description="Average processing time")
    success_rate: Optional[float] = Field(None, ge=0, le=100, description="Success rate percentage")


# =============================================================================
# SEARCH AND FILTER MODELS
# =============================================================================

class SortOrder(str, Enum):
    """Sort order options."""
    ASC = "asc"
    DESC = "desc"


class SearchCriteria(BaseModel):
    """Generic search criteria."""
    query: Optional[str] = Field(None, description="Search query string")
    fields: Optional[List[str]] = Field(None, description="Fields to search in")
    filters: Optional[Dict[str, Any]] = Field(None, description="Additional filters")
    sort_by: Optional[str] = Field(None, description="Field to sort by")
    sort_order: SortOrder = Field(SortOrder.DESC, description="Sort order")
    date_from: Optional[datetime] = Field(None, description="Filter from date")
    date_to: Optional[datetime] = Field(None, description="Filter to date")
    
    class Config:
        use_enum_values = True


class SearchResult(GenericModel, Generic[DataType]):
    """Generic search result."""
    items: List[DataType] = Field(..., description="Search result items")
    total_matches: int = Field(..., ge=0, description="Total number of matches")
    query_time_ms: float = Field(..., description="Query execution time")
    search_criteria: SearchCriteria = Field(..., description="Applied search criteria")
    facets: Optional[Dict[str, List[Dict[str, Any]]]] = Field(None, description="Search facets")


# =============================================================================
# HEALTH AND MONITORING MODELS
# =============================================================================

class HealthStatus(str, Enum):
    """Health status values."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ComponentHealth(BaseModel):
    """Individual component health."""
    name: str = Field(..., description="Component name")
    status: HealthStatus = Field(..., description="Component health status")
    response_time_ms: Optional[float] = Field(None, description="Response time in milliseconds")
    error_message: Optional[str] = Field(None, description="Error message if unhealthy")
    last_checked: datetime = Field(default_factory=datetime.utcnow, description="Last health check time")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional health details")
    
    class Config:
        use_enum_values = True


class SystemHealth(BaseModel):
    """Overall system health."""
    status: HealthStatus = Field(..., description="Overall system health")
    components: List[ComponentHealth] = Field(..., description="Individual component health")
    uptime_seconds: float = Field(..., description="System uptime in seconds")
    version: str = Field(..., description="System version")
    environment: str = Field(..., description="Environment name")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Health check timestamp")
    
    class Config:
        use_enum_values = True


# =============================================================================
# METRICS AND ANALYTICS MODELS
# =============================================================================

class MetricValue(BaseModel):
    """Single metric value."""
    name: str = Field(..., description="Metric name")
    value: Union[int, float, str] = Field(..., description="Metric value")
    unit: Optional[str] = Field(None, description="Metric unit")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Metric timestamp")
    tags: Optional[Dict[str, str]] = Field(None, description="Metric tags")


class TimeSeries(BaseModel):
    """Time series data point."""
    timestamp: datetime = Field(..., description="Data point timestamp")
    value: Union[int, float] = Field(..., description="Data point value")
    labels: Optional[Dict[str, str]] = Field(None, description="Data point labels")


class MetricsResponse(BaseModel):
    """Metrics response model."""
    metrics: List[MetricValue] = Field(..., description="Current metrics")
    time_series: Optional[List[TimeSeries]] = Field(None, description="Historical time series data")
    period_start: Optional[datetime] = Field(None, description="Metrics period start")
    period_end: Optional[datetime] = Field(None, description="Metrics period end")
    collected_at: datetime = Field(default_factory=datetime.utcnow, description="Collection timestamp")


# =============================================================================
# FILE AND DOCUMENT MODELS
# =============================================================================

class FileInfo(BaseModel):
    """File information."""
    filename: str = Field(..., description="Original filename")
    size_bytes: int = Field(..., ge=0, description="File size in bytes")
    mime_type: str = Field(..., description="MIME type")
    checksum_md5: Optional[str] = Field(None, description="MD5 checksum")
    checksum_sha256: Optional[str] = Field(None, description="SHA256 checksum")
    upload_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Upload timestamp")


class ProcessingResult(BaseModel):
    """Generic processing result."""
    success: bool = Field(..., description="Processing success status")
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")
    input_info: FileInfo = Field(..., description="Input file information")
    output_info: Optional[FileInfo] = Field(None, description="Output file information")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Processing metadata")
    warnings: List[str] = Field(default_factory=list, description="Processing warnings")
    errors: List[str] = Field(default_factory=list, description="Processing errors")


# =============================================================================
# AUDIT AND COMPLIANCE MODELS
# =============================================================================

class AuditAction(str, Enum):
    """Audit action types."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    ACCESS = "access"
    EXPORT = "export"
    IMPORT = "import"
    CONFIGURE = "configure"


class AuditEntry(BaseModel):
    """Standard audit entry."""
    id: UUID = Field(..., description="Audit entry ID")
    user_id: Optional[UUID] = Field(None, description="User who performed the action")
    username: Optional[str] = Field(None, description="Username")
    action: AuditAction = Field(..., description="Action performed")
    resource_type: str = Field(..., description="Type of resource affected")
    resource_id: Optional[UUID] = Field(None, description="ID of affected resource")
    resource_name: Optional[str] = Field(None, description="Name of affected resource")
    timestamp: datetime = Field(..., description="When the action occurred")
    ip_address: Optional[str] = Field(None, description="Source IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    success: bool = Field(..., description="Whether the action succeeded")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional audit details")
    
    class Config:
        use_enum_values = True


# =============================================================================
# NOTIFICATION MODELS
# =============================================================================

class NotificationType(str, Enum):
    """Notification types."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    SUCCESS = "success"


class Notification(BaseModel):
    """System notification."""
    id: UUID = Field(..., description="Notification ID")
    type: NotificationType = Field(..., description="Notification type")
    title: str = Field(..., description="Notification title")
    message: str = Field(..., description="Notification message")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    read: bool = Field(False, description="Whether notification has been read")
    action_url: Optional[str] = Field(None, description="Optional action URL")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    
    class Config:
        use_enum_values = True


# =============================================================================
# HELPER FUNCTIONS FOR RESPONSE CREATION
# =============================================================================

def create_success_response(
    data: Any = None,
    message: str = "Operation completed successfully",
    request_id: Optional[str] = None
) -> APIResponse:
    """Create a standard success response."""
    return APIResponse(
        status=APIStatus.SUCCESS,
        message=message,
        data=data,
        request_id=request_id
    )


def create_error_response(
    message: str,
    error_code: Optional[str] = None,
    error_details: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None
) -> APIError:
    """Create a standard error response."""
    return APIError(
        message=message,
        error_code=error_code,
        error_details=error_details,
        request_id=request_id
    )


def create_paginated_response(
    items: List[Any],
    page: int,
    per_page: int,
    total_items: int,
    message: str = "Data retrieved successfully",
    request_id: Optional[str] = None
) -> PaginatedResponse:
    """Create a paginated response."""
    total_pages = (total_items + per_page - 1) // per_page
    has_next = page < total_pages
    has_prev = page > 1
    
    pagination = PaginationMetadata(
        page=page,
        per_page=per_page,
        total_items=total_items,
        total_pages=total_pages,
        has_next=has_next,
        has_prev=has_prev,
        next_page=page + 1 if has_next else None,
        prev_page=page - 1 if has_prev else None
    )
    
    return PaginatedResponse(
        message=message,
        data=items,
        pagination=pagination,
        request_id=request_id
    )


def create_processing_status(
    status: ProcessingStatus,
    progress_percentage: float,
    current_step: str,
    steps_completed: int,
    total_steps: int,
    started_at: Optional[datetime] = None
) -> ProcessingProgress:
    """Create a processing progress status."""
    return ProcessingProgress(
        status=status,
        progress_percentage=progress_percentage,
        current_step=current_step,
        steps_completed=steps_completed,
        total_steps=total_steps,
        started_at=started_at
    )