"""
Pydantic models for API request/response validation
"""
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, validator


class DocumentBase(BaseModel):
    """Base document model"""
    original_filename: str = Field(..., max_length=255)
    file_size: int = Field(..., gt=0)
    mime_type: str = Field(..., max_length=100)


class DocumentCreate(DocumentBase):
    """Document creation model"""
    file_path: str = Field(..., max_length=500)


class DocumentResponse(DocumentBase):
    """Document response model"""
    id: UUID
    file_path: str
    upload_timestamp: datetime
    status: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class DocumentStatusUpdate(BaseModel):
    """Document status update model"""
    status: str = Field(..., regex=r'^(uploaded|processing|completed|failed)$')


class ProcessingJobBase(BaseModel):
    """Base processing job model"""
    job_type: str = Field(..., regex=r'^(ocr|pii_detection|redaction)$')
    document_id: UUID


class ProcessingJobCreate(ProcessingJobBase):
    """Processing job creation model"""
    pass


class ProcessingJobResponse(ProcessingJobBase):
    """Processing job response model"""
    id: UUID
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    result_data: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ProcessingJobUpdate(BaseModel):
    """Processing job update model"""
    status: str = Field(..., regex=r'^(pending|running|completed|failed)$')
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    result_data: Optional[Dict[str, Any]] = None


class PIIDetectionBase(BaseModel):
    """Base PII detection model"""
    detection_type: str = Field(..., max_length=100)
    detected_text: str
    confidence_score: Decimal = Field(..., ge=0.0, le=1.0)
    start_position: int = Field(..., ge=0)
    end_position: int = Field(..., gt=0)
    page_number: Optional[int] = None
    bounding_box: Optional[Dict[str, Any]] = None
    
    @validator('end_position')
    def validate_positions(cls, v, values):
        if 'start_position' in values and v <= values['start_position']:
            raise ValueError('end_position must be greater than start_position')
        return v


class PIIDetectionCreate(PIIDetectionBase):
    """PII detection creation model"""
    document_id: UUID


class PIIDetectionResponse(PIIDetectionBase):
    """PII detection response model"""
    id: UUID
    document_id: UUID
    redaction_applied: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class PIIDetectionUpdate(BaseModel):
    """PII detection update model"""
    redaction_applied: bool = False


class RedactedDocumentBase(BaseModel):
    """Base redacted document model"""
    redacted_file_path: str = Field(..., max_length=500)
    redaction_method: str = Field(..., regex=r'^(mask|replace|delete)$')
    total_redactions: int = Field(..., ge=0)
    redaction_summary: Optional[Dict[str, Any]] = None


class RedactedDocumentCreate(RedactedDocumentBase):
    """Redacted document creation model"""
    original_document_id: UUID


class RedactedDocumentResponse(RedactedDocumentBase):
    """Redacted document response model"""
    id: UUID
    original_document_id: UUID
    created_at: datetime
    
    class Config:
        from_attributes = True


class PolicyBase(BaseModel):
    """Base policy model"""
    policy_name: str = Field(..., max_length=100)
    description: Optional[str] = None
    pii_types: List[str] = Field(..., min_items=1)
    confidence_threshold: Decimal = Field(..., ge=0.0, le=1.0)
    redaction_method: str = Field(..., regex=r'^(mask|replace|delete)$')
    is_active: bool = True


class PolicyCreate(PolicyBase):
    """Policy creation model"""
    pass


class PolicyResponse(PolicyBase):
    """Policy response model"""
    id: UUID
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class PolicyUpdate(BaseModel):
    """Policy update model"""
    description: Optional[str] = None
    pii_types: Optional[List[str]] = Field(None, min_items=1)
    confidence_threshold: Optional[Decimal] = Field(None, ge=0.0, le=1.0)
    redaction_method: Optional[str] = Field(None, regex=r'^(mask|replace|delete)$')
    is_active: Optional[bool] = None


class AuditLogBase(BaseModel):
    """Base audit log model"""
    action: str = Field(..., max_length=100)
    user_id: Optional[str] = Field(None, max_length=100)
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class AuditLogCreate(AuditLogBase):
    """Audit log creation model"""
    document_id: Optional[UUID] = None


class AuditLogResponse(AuditLogBase):
    """Audit log response model"""
    id: UUID
    document_id: Optional[UUID] = None
    timestamp: datetime
    
    class Config:
        from_attributes = True


class PerformanceMetricBase(BaseModel):
    """Base performance metric model"""
    processing_stage: str = Field(..., max_length=50)
    duration_ms: int = Field(..., gt=0)
    memory_usage_mb: Optional[int] = None
    cpu_usage_percent: Optional[Decimal] = Field(None, ge=0.0, le=100.0)
    success: bool


class PerformanceMetricCreate(PerformanceMetricBase):
    """Performance metric creation model"""
    document_id: Optional[UUID] = None


class PerformanceMetricResponse(PerformanceMetricBase):
    """Performance metric response model"""
    id: UUID
    document_id: Optional[UUID] = None
    timestamp: datetime
    
    class Config:
        from_attributes = True


# Upload and processing response models
class FileUploadResponse(BaseModel):
    """File upload response model"""
    message: str
    document_id: UUID
    filename: str
    file_size: int
    status: str


class ProcessingStatus(BaseModel):
    """Processing status model"""
    document_id: UUID
    overall_status: str
    jobs: List[ProcessingJobResponse]
    progress_percentage: int = Field(..., ge=0, le=100)
    estimated_completion: Optional[datetime] = None


class RedactionPreview(BaseModel):
    """Redaction preview model"""
    document_id: UUID
    total_detections: int
    detections_by_type: Dict[str, int]
    confidence_distribution: Dict[str, int]
    preview_text: str


class SystemHealth(BaseModel):
    """System health model"""
    database: bool
    redis: bool
    ocr_service: bool
    pii_service: bool
    disk_space_gb: float
    memory_usage_percent: float
    timestamp: datetime


class APIError(BaseModel):
    """API error response model"""
    error: str
    detail: Optional[str] = None
    timestamp: datetime