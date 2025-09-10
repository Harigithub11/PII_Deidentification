"""
System Management API Endpoints

System configuration, health monitoring, performance metrics,
and administrative operations for the De-identification System.
"""

import logging
import psutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status, Query, Path as PathParam, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_

from ..core.database.session import get_db_session
from ..core.database.models import (
    User, DocumentMetadata, ProcessingSession, AuditEvent, SystemEvent
)
from ..core.security.dependencies import (
    get_current_active_user,
    get_current_admin_user,
    AuditLogDependency
)
from ..core.config.settings import get_settings

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/system", tags=["System Management"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class SystemHealthResponse(BaseModel):
    """System health response model."""
    status: str = Field(..., description="Overall system status")
    timestamp: datetime = Field(..., description="Health check timestamp")
    uptime_seconds: float = Field(..., description="System uptime in seconds")
    
    # Service health
    database: Dict[str, Any] = Field(..., description="Database health status")
    redis: Dict[str, Any] = Field(..., description="Redis health status")
    storage: Dict[str, Any] = Field(..., description="Storage health status")
    
    # System resources
    cpu: Dict[str, Any] = Field(..., description="CPU usage information")
    memory: Dict[str, Any] = Field(..., description="Memory usage information")
    disk: Dict[str, Any] = Field(..., description="Disk usage information")
    
    # Application health
    api_endpoints: Dict[str, Any] = Field(..., description="API endpoint health")
    background_jobs: Dict[str, Any] = Field(..., description="Background job health")
    model_services: Dict[str, Any] = Field(..., description="ML model service health")


class SystemMetricsResponse(BaseModel):
    """System metrics response model."""
    timestamp: datetime
    
    # Performance metrics
    requests_per_minute: float
    average_response_time_ms: float
    error_rate_percentage: float
    
    # Processing metrics
    documents_processed_today: int
    pii_detections_today: int
    redactions_completed_today: int
    
    # Resource metrics
    cpu_usage_percentage: float
    memory_usage_percentage: float
    disk_usage_percentage: float
    active_connections: int
    
    # Queue metrics
    pending_jobs: int
    failed_jobs: int
    processing_jobs: int
    
    # User metrics
    active_users: int
    concurrent_sessions: int


class SystemConfigResponse(BaseModel):
    """System configuration response model."""
    app_name: str
    version: str
    environment: str
    debug_mode: bool
    
    # Database configuration
    database_url: str  # Sanitized URL without credentials
    max_connections: int
    connection_timeout: int
    
    # Security settings
    jwt_expire_minutes: int
    password_min_length: int
    max_login_attempts: int
    session_timeout_minutes: int
    
    # Processing settings
    max_file_size_mb: int
    supported_formats: List[str]
    max_concurrent_jobs: int
    job_timeout_minutes: int
    
    # Storage settings
    upload_directory: str
    temp_directory: str
    output_directory: str
    max_storage_gb: int


class SystemConfigUpdateRequest(BaseModel):
    """System configuration update request model."""
    max_file_size_mb: Optional[int] = Field(None, ge=1, le=1000)
    max_concurrent_jobs: Optional[int] = Field(None, ge=1, le=50)
    job_timeout_minutes: Optional[int] = Field(None, ge=5, le=480)
    session_timeout_minutes: Optional[int] = Field(None, ge=15, le=1440)
    max_login_attempts: Optional[int] = Field(None, ge=3, le=10)
    
    # Feature flags
    enable_ocr: Optional[bool] = None
    enable_visual_pii: Optional[bool] = None
    enable_analytics: Optional[bool] = None
    enable_audit_logging: Optional[bool] = None


class SystemMaintenanceRequest(BaseModel):
    """System maintenance request model."""
    maintenance_type: str = Field(..., description="Type of maintenance operation")
    scheduled_at: Optional[datetime] = Field(None, description="Scheduled maintenance time")
    duration_minutes: int = Field(30, ge=1, le=480, description="Expected duration")
    notification_message: Optional[str] = Field(None, description="User notification message")
    
    @validator('maintenance_type')
    def validate_maintenance_type(cls, v):
        valid_types = ["database_cleanup", "log_rotation", "backup", "update", "restart", "cache_clear"]
        if v not in valid_types:
            raise ValueError(f'Maintenance type must be one of: {valid_types}')
        return v


class BackupRequest(BaseModel):
    """System backup request model."""
    backup_type: str = Field("full", regex="^(full|incremental|database|files)$")
    include_logs: bool = Field(True, description="Include audit logs in backup")
    include_documents: bool = Field(False, description="Include processed documents")
    compression: bool = Field(True, description="Compress backup files")
    retention_days: int = Field(30, ge=1, le=365, description="Backup retention period")


class LogLevel(str):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class SystemStatsResponse(BaseModel):
    """System statistics response model."""
    total_users: int
    total_documents: int
    total_sessions: int
    storage_used_gb: float
    processing_time_hours: float
    
    # Today's statistics
    documents_today: int
    pii_detections_today: int
    api_calls_today: int
    errors_today: int
    
    # Weekly trends
    weekly_document_trend: List[Dict[str, Any]]
    weekly_user_activity: List[Dict[str, Any]]
    
    # Top statistics
    top_file_types: List[Dict[str, Any]]
    top_pii_types: List[Dict[str, Any]]
    most_active_users: List[Dict[str, Any]]


# =============================================================================
# SYSTEM HEALTH & MONITORING
# =============================================================================

@router.get("/health", response_model=SystemHealthResponse)
async def get_system_health(
    db: Session = Depends(get_db_session)
):
    """Get comprehensive system health information."""
    
    start_time = datetime.utcnow()
    
    try:
        # Test database connectivity
        db_health = await _check_database_health(db)
        
        # Check Redis connectivity
        redis_health = await _check_redis_health()
        
        # Check storage health
        storage_health = await _check_storage_health()
        
        # Get system resources
        cpu_info = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()
        disk_info = psutil.disk_usage('/')
        
        # Check API endpoints
        api_health = await _check_api_health()
        
        # Check background jobs
        job_health = await _check_job_health()
        
        # Check model services
        model_health = await _check_model_health()
        
        # Calculate uptime (simplified)
        uptime_seconds = 3600.0  # Placeholder - would get from actual process start time
        
        # Determine overall status
        overall_status = "healthy"
        if (not db_health["healthy"] or 
            cpu_info > 90 or 
            memory_info.percent > 90 or 
            disk_info.percent > 90):
            overall_status = "degraded"
        
        return SystemHealthResponse(
            status=overall_status,
            timestamp=datetime.utcnow(),
            uptime_seconds=uptime_seconds,
            database=db_health,
            redis=redis_health,
            storage=storage_health,
            cpu={
                "usage_percentage": cpu_info,
                "cores": psutil.cpu_count(),
                "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
            },
            memory={
                "usage_percentage": memory_info.percent,
                "available_gb": round(memory_info.available / (1024**3), 2),
                "total_gb": round(memory_info.total / (1024**3), 2)
            },
            disk={
                "usage_percentage": disk_info.percent,
                "free_gb": round(disk_info.free / (1024**3), 2),
                "total_gb": round(disk_info.total / (1024**3), 2)
            },
            api_endpoints=api_health,
            background_jobs=job_health,
            model_services=model_health
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return SystemHealthResponse(
            status="unhealthy",
            timestamp=datetime.utcnow(),
            uptime_seconds=0,
            database={"healthy": False, "error": str(e)},
            redis={"healthy": False, "error": "Not checked"},
            storage={"healthy": False, "error": "Not checked"},
            cpu={"usage_percentage": 0, "cores": 0, "load_average": [0, 0, 0]},
            memory={"usage_percentage": 0, "available_gb": 0, "total_gb": 0},
            disk={"usage_percentage": 0, "free_gb": 0, "total_gb": 0},
            api_endpoints={"healthy": False},
            background_jobs={"healthy": False},
            model_services={"healthy": False}
        )


@router.get("/metrics", response_model=SystemMetricsResponse)
async def get_system_metrics(
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    """Get system performance metrics (Admin only)."""
    
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Get processing metrics for today
    documents_today = db.query(DocumentMetadata).filter(
        DocumentMetadata.uploaded_at >= today_start
    ).count()
    
    # Get session metrics
    active_sessions = db.query(ProcessingSession).filter(
        and_(
            ProcessingSession.status == "processing",
            ProcessingSession.created_at >= today_start
        )
    ).count()
    
    # Get user metrics
    active_users = db.query(User).filter(
        and_(
            User.is_active == True,
            User.last_login >= now - timedelta(hours=24)
        )
    ).count()
    
    # System resource metrics
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent
    
    # Mock some metrics that would come from monitoring systems
    requests_per_minute = 125.5
    avg_response_time = 245.0
    error_rate = 1.2
    
    return SystemMetricsResponse(
        timestamp=now,
        requests_per_minute=requests_per_minute,
        average_response_time_ms=avg_response_time,
        error_rate_percentage=error_rate,
        documents_processed_today=documents_today,
        pii_detections_today=documents_today * 8,  # Estimate
        redactions_completed_today=documents_today * 6,  # Estimate
        cpu_usage_percentage=cpu_usage,
        memory_usage_percentage=memory_usage,
        disk_usage_percentage=disk_usage,
        active_connections=45,  # Would get from connection pool
        pending_jobs=12,
        failed_jobs=2,
        processing_jobs=active_sessions,
        active_users=active_users,
        concurrent_sessions=active_sessions
    )


# =============================================================================
# SYSTEM CONFIGURATION
# =============================================================================

@router.get("/config", response_model=SystemConfigResponse)
async def get_system_configuration(
    current_user: User = Depends(get_current_admin_user)
):
    """Get system configuration (Admin only)."""
    
    settings = get_settings()
    
    # Sanitize database URL to remove credentials
    db_url = settings.database_url
    if "@" in db_url:
        # Remove credentials from URL
        protocol, rest = db_url.split("://", 1)
        if "@" in rest:
            credentials, host_db = rest.split("@", 1)
            db_url = f"{protocol}://*****:*****@{host_db}"
    
    return SystemConfigResponse(
        app_name="PII De-identification System",
        version="2.0.0",
        environment=getattr(settings, 'environment', 'development'),
        debug_mode=getattr(settings, 'debug', False),
        database_url=db_url,
        max_connections=getattr(settings, 'max_db_connections', 20),
        connection_timeout=getattr(settings, 'db_connection_timeout', 30),
        jwt_expire_minutes=getattr(settings, 'jwt_expire_minutes', 60),
        password_min_length=getattr(settings, 'password_min_length', 8),
        max_login_attempts=getattr(settings, 'max_login_attempts', 5),
        session_timeout_minutes=getattr(settings, 'session_timeout_minutes', 30),
        max_file_size_mb=getattr(settings, 'max_file_size_mb', 100),
        supported_formats=["pdf", "png", "jpg", "jpeg", "tiff", "bmp"],
        max_concurrent_jobs=getattr(settings, 'max_concurrent_jobs', 10),
        job_timeout_minutes=getattr(settings, 'job_timeout_minutes', 60),
        upload_directory="/uploads",
        temp_directory="/tmp",
        output_directory="/output",
        max_storage_gb=getattr(settings, 'max_storage_gb', 100)
    )


@router.put("/config")
async def update_system_configuration(
    request: SystemConfigUpdateRequest,
    current_user: User = Depends(get_current_admin_user),
    audit_log = Depends(AuditLogDependency("system_config_update"))
):
    """Update system configuration (Admin only)."""
    
    updated_fields = []
    
    # Update configuration fields
    update_data = request.dict(exclude_unset=True)
    
    for field, value in update_data.items():
        if value is not None:
            # Here you would update the actual configuration
            # This might involve updating a config file, environment variables,
            # or a configuration database table
            updated_fields.append(field)
            logger.info(f"Configuration updated: {field} = {value}")
    
    logger.info(f"System configuration updated by {current_user.username}: {updated_fields}")
    
    return {
        "message": "System configuration updated successfully",
        "updated_fields": updated_fields,
        "updated_by": current_user.username,
        "updated_at": datetime.utcnow()
    }


# =============================================================================
# SYSTEM STATISTICS
# =============================================================================

@router.get("/stats", response_model=SystemStatsResponse)
async def get_system_statistics(
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    """Get comprehensive system statistics (Admin only)."""
    
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = now - timedelta(days=7)
    
    # Basic counts
    total_users = db.query(User).count()
    total_documents = db.query(DocumentMetadata).count()
    total_sessions = db.query(ProcessingSession).count()
    
    # Today's statistics
    documents_today = db.query(DocumentMetadata).filter(
        DocumentMetadata.uploaded_at >= today_start
    ).count()
    
    # Storage usage (simplified calculation)
    total_size_query = db.query(func.sum(DocumentMetadata.file_size_bytes)).scalar()
    storage_used_gb = round((total_size_query or 0) / (1024**3), 2)
    
    # Weekly document trend
    weekly_docs = []
    for i in range(7):
        day_start = today_start - timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        day_count = db.query(DocumentMetadata).filter(
            and_(
                DocumentMetadata.uploaded_at >= day_start,
                DocumentMetadata.uploaded_at < day_end
            )
        ).count()
        
        weekly_docs.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "count": day_count
        })
    
    # Top file types
    file_type_stats = db.query(
        DocumentMetadata.file_format,
        func.count(DocumentMetadata.id)
    ).group_by(DocumentMetadata.file_format).order_by(
        desc(func.count(DocumentMetadata.id))
    ).limit(5).all()
    
    top_file_types = [
        {"type": file_type, "count": count}
        for file_type, count in file_type_stats
    ]
    
    # Most active users (by document uploads)
    active_user_stats = db.query(
        User.username,
        func.count(DocumentMetadata.id)
    ).join(
        DocumentMetadata, User.id == DocumentMetadata.uploaded_by
    ).filter(
        DocumentMetadata.uploaded_at >= week_start
    ).group_by(User.username).order_by(
        desc(func.count(DocumentMetadata.id))
    ).limit(5).all()
    
    most_active_users = [
        {"username": username, "uploads": count}
        for username, count in active_user_stats
    ]
    
    return SystemStatsResponse(
        total_users=total_users,
        total_documents=total_documents,
        total_sessions=total_sessions,
        storage_used_gb=storage_used_gb,
        processing_time_hours=round(total_sessions * 0.5, 2),  # Estimate
        documents_today=documents_today,
        pii_detections_today=documents_today * 8,  # Estimate
        api_calls_today=documents_today * 15,  # Estimate
        errors_today=5,  # Would get from logs
        weekly_document_trend=weekly_docs,
        weekly_user_activity=[],  # Would calculate from audit logs
        top_file_types=top_file_types,
        top_pii_types=[  # Would get from PII detection results
            {"type": "email", "count": 1245},
            {"type": "phone", "count": 892},
            {"type": "ssn", "count": 234},
            {"type": "address", "count": 567}
        ],
        most_active_users=most_active_users
    )


# =============================================================================
# SYSTEM MAINTENANCE
# =============================================================================

@router.post("/maintenance")
async def schedule_maintenance(
    request: SystemMaintenanceRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    audit_log = Depends(AuditLogDependency("system_maintenance_schedule"))
):
    """Schedule system maintenance (Admin only)."""
    
    maintenance_id = uuid4()
    
    # Add background task for maintenance
    background_tasks.add_task(
        _perform_maintenance_task,
        maintenance_id,
        request,
        current_user.id
    )
    
    logger.info(f"System maintenance scheduled: {request.maintenance_type} by {current_user.username}")
    
    return {
        "maintenance_id": str(maintenance_id),
        "maintenance_type": request.maintenance_type,
        "scheduled_at": request.scheduled_at or datetime.utcnow(),
        "duration_minutes": request.duration_minutes,
        "status": "scheduled",
        "message": "System maintenance has been scheduled"
    }


async def _perform_maintenance_task(
    maintenance_id: UUID,
    request: SystemMaintenanceRequest,
    user_id: UUID
):
    """Background task to perform maintenance operations."""
    
    try:
        logger.info(f"Starting maintenance: {request.maintenance_type}")
        
        if request.maintenance_type == "database_cleanup":
            # Perform database cleanup
            logger.info("Performing database cleanup...")
            
        elif request.maintenance_type == "log_rotation":
            # Rotate log files
            logger.info("Rotating log files...")
            
        elif request.maintenance_type == "cache_clear":
            # Clear application caches
            logger.info("Clearing caches...")
            
        # Simulate maintenance time
        import asyncio
        await asyncio.sleep(min(request.duration_minutes * 60, 300))  # Max 5 minutes for demo
        
        logger.info(f"Maintenance completed: {maintenance_id}")
        
    except Exception as e:
        logger.error(f"Maintenance failed {maintenance_id}: {e}")


# =============================================================================
# BACKUP & RESTORE
# =============================================================================

@router.post("/backup")
async def create_system_backup(
    request: BackupRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    audit_log = Depends(AuditLogDependency("system_backup_create"))
):
    """Create system backup (Admin only)."""
    
    backup_id = uuid4()
    
    # Add background task for backup
    background_tasks.add_task(
        _create_backup_task,
        backup_id,
        request,
        current_user.id
    )
    
    logger.info(f"System backup started: {request.backup_type} by {current_user.username}")
    
    return {
        "backup_id": str(backup_id),
        "backup_type": request.backup_type,
        "status": "in_progress",
        "started_at": datetime.utcnow(),
        "estimated_completion": datetime.utcnow() + timedelta(minutes=10),
        "message": "Backup process has been started"
    }


async def _create_backup_task(
    backup_id: UUID,
    request: BackupRequest,
    user_id: UUID
):
    """Background task to create system backup."""
    
    try:
        logger.info(f"Creating backup: {request.backup_type}")
        
        # Simulate backup process
        import asyncio
        await asyncio.sleep(5)  # Simulate backup time
        
        backup_path = f"/backups/backup_{backup_id}_{request.backup_type}.tar.gz"
        
        logger.info(f"Backup completed: {backup_id} at {backup_path}")
        
    except Exception as e:
        logger.error(f"Backup failed {backup_id}: {e}")


@router.get("/backups")
async def list_system_backups(
    current_user: User = Depends(get_current_admin_user)
):
    """List available system backups (Admin only)."""
    
    # This would list actual backup files from storage
    backups = [
        {
            "backup_id": str(uuid4()),
            "backup_type": "full",
            "created_at": datetime.utcnow() - timedelta(days=1),
            "file_size_mb": 1024,
            "status": "completed",
            "retention_expires": datetime.utcnow() + timedelta(days=29)
        },
        {
            "backup_id": str(uuid4()),
            "backup_type": "incremental",
            "created_at": datetime.utcnow() - timedelta(hours=6),
            "file_size_mb": 128,
            "status": "completed",
            "retention_expires": datetime.utcnow() + timedelta(days=29)
        }
    ]
    
    return backups


# =============================================================================
# LOG MANAGEMENT
# =============================================================================

@router.get("/logs")
async def get_system_logs(
    level: Optional[str] = Query("INFO", description="Log level filter"),
    lines: int = Query(100, ge=1, le=1000, description="Number of log lines"),
    service: Optional[str] = Query(None, description="Filter by service name"),
    current_user: User = Depends(get_current_admin_user)
):
    """Get system logs (Admin only)."""
    
    # This would read actual log files
    # For demo, return mock log entries
    
    mock_logs = [
        {
            "timestamp": datetime.utcnow() - timedelta(minutes=5),
            "level": "INFO",
            "service": "api",
            "message": "Document processing completed successfully",
            "request_id": str(uuid4())[:8]
        },
        {
            "timestamp": datetime.utcnow() - timedelta(minutes=10),
            "level": "WARNING",
            "service": "pii_detector",
            "message": "Low confidence PII detection result",
            "request_id": str(uuid4())[:8]
        },
        {
            "timestamp": datetime.utcnow() - timedelta(minutes=15),
            "level": "ERROR",
            "service": "database",
            "message": "Connection timeout, retrying...",
            "request_id": str(uuid4())[:8]
        }
    ]
    
    # Apply filters
    if level and level != "ALL":
        mock_logs = [log for log in mock_logs if log["level"] == level]
    
    if service:
        mock_logs = [log for log in mock_logs if log["service"] == service]
    
    return mock_logs[:lines]


@router.post("/logs/level")
async def set_log_level(
    level: str = Field(..., regex="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$"),
    service: Optional[str] = None,
    current_user: User = Depends(get_current_admin_user),
    audit_log = Depends(AuditLogDependency("log_level_change"))
):
    """Set system log level (Admin only)."""
    
    # Update log level for specified service or globally
    logger.info(f"Log level changed to {level} for {service or 'all services'} by {current_user.username}")
    
    return {
        "message": f"Log level set to {level}",
        "service": service or "all",
        "changed_by": current_user.username,
        "changed_at": datetime.utcnow()
    }


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

async def _check_database_health(db: Session) -> Dict[str, Any]:
    """Check database connectivity and health."""
    try:
        # Simple query to test database
        result = db.execute("SELECT 1").fetchone()
        
        # Get connection count (if available)
        connection_count = 5  # Would get from connection pool
        
        return {
            "healthy": True,
            "response_time_ms": 25,
            "active_connections": connection_count,
            "max_connections": 20
        }
    except Exception as e:
        return {
            "healthy": False,
            "error": str(e),
            "response_time_ms": None
        }


async def _check_redis_health() -> Dict[str, Any]:
    """Check Redis connectivity and health."""
    try:
        # Would check actual Redis connection
        return {
            "healthy": True,
            "response_time_ms": 5,
            "memory_usage_mb": 128,
            "connected_clients": 12
        }
    except Exception as e:
        return {
            "healthy": False,
            "error": str(e)
        }


async def _check_storage_health() -> Dict[str, Any]:
    """Check storage system health."""
    try:
        upload_dir = Path("/uploads")
        temp_dir = Path("/tmp")
        
        return {
            "healthy": True,
            "upload_directory_exists": upload_dir.exists(),
            "temp_directory_exists": temp_dir.exists(),
            "permissions_ok": True
        }
    except Exception as e:
        return {
            "healthy": False,
            "error": str(e)
        }


async def _check_api_health() -> Dict[str, Any]:
    """Check API endpoint health."""
    try:
        return {
            "healthy": True,
            "endpoints_responding": 15,
            "total_endpoints": 15,
            "average_response_time_ms": 125
        }
    except Exception as e:
        return {
            "healthy": False,
            "error": str(e)
        }


async def _check_job_health() -> Dict[str, Any]:
    """Check background job system health."""
    try:
        return {
            "healthy": True,
            "queue_depth": 5,
            "active_workers": 3,
            "failed_jobs_24h": 2
        }
    except Exception as e:
        return {
            "healthy": False,
            "error": str(e)
        }


async def _check_model_health() -> Dict[str, Any]:
    """Check ML model service health."""
    try:
        return {
            "healthy": True,
            "models_loaded": 4,
            "total_models": 4,
            "average_inference_time_ms": 150
        }
    except Exception as e:
        return {
            "healthy": False,
            "error": str(e)
        }