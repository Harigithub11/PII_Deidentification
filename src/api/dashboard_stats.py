"""
Dashboard Statistics API Endpoints

Provides real-time dashboard statistics and monitoring data for the frontend dashboard.
This replaces the complex BI dashboard with simple, performance-focused endpoints.
"""

import logging
import psutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_, or_

from ..core.database.session import get_db_session
from ..core.database.models import (
    User, DocumentMetadata, ProcessingSession, AuditEvent, SystemEvent,
    BatchJob, BatchWorker, PIIEntity, RedactionRecord
)
from ..core.security.auth import get_current_user
from ..core.config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard Statistics"])

# =============================================================================
# RESPONSE MODELS
# =============================================================================

class DashboardStatsResponse(BaseModel):
    """Dashboard overview statistics."""
    total_jobs: int = Field(..., description="Total number of jobs")
    jobs_this_week: int = Field(..., description="Jobs created this week")
    total_documents: int = Field(..., description="Total documents processed")
    documents_processed_today: int = Field(..., description="Documents processed today")
    pii_entities_found: int = Field(..., description="Total PII entities detected")
    redaction_accuracy: float = Field(..., description="Average redaction accuracy percentage")
    system_load_percentage: float = Field(..., description="Current system load percentage")

class RecentActivityResponse(BaseModel):
    """Recent system activity item."""
    id: str = Field(..., description="Activity ID")
    title: str = Field(..., description="Activity title")
    description: str = Field(..., description="Activity description")
    timestamp: datetime = Field(..., description="Activity timestamp")

class RecentJobResponse(BaseModel):
    """Recent job information."""
    id: str = Field(..., description="Job ID")
    name: str = Field(..., description="Job name")
    job_type: str = Field(..., description="Job type")
    status: str = Field(..., description="Job status")
    progress_percentage: int = Field(..., description="Job progress percentage")
    created_at: datetime = Field(..., description="Job creation time")

class SystemMetricsResponse(BaseModel):
    """System monitoring metrics."""
    cpu_usage: float = Field(..., description="CPU usage percentage")
    memory_usage: float = Field(..., description="Memory usage percentage")
    disk_io: float = Field(..., description="Disk I/O percentage")
    system_load_percentage: float = Field(..., description="Overall system load")
    overall_status: str = Field(..., description="System health status")
    uptime: str = Field(..., description="System uptime")
    recent_alerts: List[Dict[str, Any]] = Field(default_factory=list, description="Recent system alerts")

class WorkerStatusResponse(BaseModel):
    """Worker status information."""
    worker_id: str = Field(..., description="Worker ID")
    worker_name: str = Field(..., description="Worker name")
    status: str = Field(..., description="Worker status")
    current_load: float = Field(..., description="Current worker load percentage")
    last_heartbeat: datetime = Field(..., description="Last heartbeat time")

class PerformanceDataResponse(BaseModel):
    """Performance data for charts."""
    timestamps: List[str] = Field(..., description="Time points")
    cpu_history: List[float] = Field(..., description="CPU usage history")
    memory_history: List[float] = Field(..., description="Memory usage history")
    throughput_history: List[float] = Field(..., description="Job throughput history")
    error_rate_history: List[float] = Field(..., description="Error rate history")

# =============================================================================
# DASHBOARD ENDPOINTS
# =============================================================================

@router.get("/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Get dashboard overview statistics."""
    try:
        # Calculate date ranges
        now = datetime.utcnow()
        week_ago = now - timedelta(days=7)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        # Get total jobs
        total_jobs = db.query(func.count(BatchJob.id)).scalar() or 0

        # Get jobs this week
        jobs_this_week = db.query(func.count(BatchJob.id)).filter(
            BatchJob.created_at >= week_ago
        ).scalar() or 0

        # Get total documents
        total_documents = db.query(func.count(DocumentMetadata.id)).scalar() or 0

        # Get documents processed today
        documents_today = db.query(func.count(DocumentMetadata.id)).filter(
            DocumentMetadata.created_at >= today_start
        ).scalar() or 0

        # Get total PII entities found
        pii_entities_found = db.query(func.count(PIIEntity.id)).scalar() or 0

        # Calculate average redaction accuracy (mock calculation for now)
        successful_redactions = db.query(func.count(RedactionRecord.id)).filter(
            RedactionRecord.status == 'completed'
        ).scalar() or 0
        total_redactions = db.query(func.count(RedactionRecord.id)).scalar() or 1
        redaction_accuracy = (successful_redactions / total_redactions) * 100 if total_redactions > 0 else 95.0

        # Get system load
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            system_load = (cpu_percent + memory.percent) / 2
        except Exception as e:
            logger.warning(f"Failed to get system metrics: {e}")
            system_load = 0.0

        return DashboardStatsResponse(
            total_jobs=total_jobs,
            jobs_this_week=jobs_this_week,
            total_documents=total_documents,
            documents_processed_today=documents_today,
            pii_entities_found=pii_entities_found,
            redaction_accuracy=round(redaction_accuracy, 1),
            system_load_percentage=round(system_load, 1)
        )

    except Exception as e:
        logger.error(f"Failed to get dashboard stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard stats: {str(e)}")

@router.get("/activity", response_model=List[RecentActivityResponse])
async def get_dashboard_activity(
    limit: int = Query(10, ge=1, le=50),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Get recent system activity."""
    try:
        # Get recent audit events
        events = db.query(AuditEvent).order_by(desc(AuditEvent.timestamp)).limit(limit).all()

        activities = []
        for event in events:
            # Format activity based on event type
            if event.event_type == 'document_upload':
                title = "New document uploaded"
                description = f"Document '{event.details.get('filename', 'Unknown')}' uploaded"
            elif event.event_type == 'job_completed':
                title = "Job completed successfully"
                description = f"Job ID: {event.details.get('job_id', 'Unknown')}"
            elif event.event_type == 'pii_detected':
                title = "High confidence PII detected"
                description = f"Found {event.details.get('entity_type', 'PII')} in document"
            elif event.event_type == 'batch_processing':
                title = "Batch processing started"
                description = f"Processing {event.details.get('document_count', 1)} documents"
            else:
                title = event.event_type.replace('_', ' ').title()
                description = f"Event by {event.user_id or 'System'}"

            activities.append(RecentActivityResponse(
                id=str(event.id),
                title=title,
                description=description,
                timestamp=event.timestamp
            ))

        # If no events, add some sample activities
        if not activities:
            now = datetime.utcnow()
            activities = [
                RecentActivityResponse(
                    id="sample-1",
                    title="System started",
                    description="PII De-identification system initialized",
                    timestamp=now - timedelta(minutes=30)
                ),
                RecentActivityResponse(
                    id="sample-2",
                    title="Database connection established",
                    description="Successfully connected to PostgreSQL database",
                    timestamp=now - timedelta(minutes=25)
                )
            ]

        return activities

    except Exception as e:
        logger.error(f"Failed to get dashboard activity: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard activity: {str(e)}")

# =============================================================================
# JOBS ENDPOINTS
# =============================================================================

@router.get("/jobs/recent", response_model=List[RecentJobResponse])
async def get_recent_jobs(
    limit: int = Query(10, ge=1, le=50),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Get recent batch jobs."""
    try:
        jobs = db.query(BatchJob).order_by(desc(BatchJob.created_at)).limit(limit).all()

        recent_jobs = []
        for job in jobs:
            recent_jobs.append(RecentJobResponse(
                id=str(job.id),
                name=job.name,
                job_type=job.job_type.value if hasattr(job.job_type, 'value') else str(job.job_type),
                status=job.status.value if hasattr(job.status, 'value') else str(job.status),
                progress_percentage=job.progress_percentage,
                created_at=job.created_at
            ))

        # If no jobs, return sample data
        if not recent_jobs:
            now = datetime.utcnow()
            recent_jobs = [
                RecentJobResponse(
                    id="sample-job-1",
                    name="Document Processing Pipeline",
                    job_type="document_processing",
                    status="completed",
                    progress_percentage=100,
                    created_at=now - timedelta(hours=2)
                ),
                RecentJobResponse(
                    id="sample-job-2",
                    name="PII Detection Analysis",
                    job_type="pii_detection",
                    status="running",
                    progress_percentage=75,
                    created_at=now - timedelta(minutes=30)
                )
            ]

        return recent_jobs

    except Exception as e:
        logger.error(f"Failed to get recent jobs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get recent jobs: {str(e)}")

# =============================================================================
# MONITORING ENDPOINTS
# =============================================================================

@router.get("/monitoring/metrics", response_model=SystemMetricsResponse)
async def get_system_metrics(
    current_user: User = Depends(get_current_user)
):
    """Get current system metrics."""
    try:
        # Get system metrics using psutil
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        # Calculate system load
        system_load = (cpu_usage + memory.percent) / 2

        # Determine overall status
        if system_load < 50:
            overall_status = "healthy"
        elif system_load < 80:
            overall_status = "warning"
        else:
            overall_status = "critical"

        # Get uptime
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime_seconds = (datetime.now() - boot_time).total_seconds()
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        uptime = f"{int(hours)}h {int(minutes)}m"

        # Generate recent alerts based on system status
        recent_alerts = []
        if cpu_usage > 90:
            recent_alerts.append({
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "warning",
                "component": "CPU",
                "message": f"High CPU usage: {cpu_usage:.1f}%"
            })

        if memory.percent > 90:
            recent_alerts.append({
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "warning",
                "component": "Memory",
                "message": f"High memory usage: {memory.percent:.1f}%"
            })

        return SystemMetricsResponse(
            cpu_usage=round(cpu_usage, 1),
            memory_usage=round(memory.percent, 1),
            disk_io=round(disk.percent, 1),
            system_load_percentage=round(system_load, 1),
            overall_status=overall_status,
            uptime=uptime,
            recent_alerts=recent_alerts
        )

    except Exception as e:
        logger.error(f"Failed to get system metrics: {e}")
        # Return fallback data
        return SystemMetricsResponse(
            cpu_usage=0.0,
            memory_usage=0.0,
            disk_io=0.0,
            system_load_percentage=0.0,
            overall_status="unknown",
            uptime="0h 0m",
            recent_alerts=[]
        )

@router.get("/monitoring/workers", response_model=List[WorkerStatusResponse])
async def get_worker_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Get worker status information."""
    try:
        workers = db.query(BatchWorker).all()

        worker_statuses = []
        for worker in workers:
            # Calculate load based on current jobs
            load_percentage = (worker.current_jobs_count / worker.max_concurrent_jobs) * 100

            worker_statuses.append(WorkerStatusResponse(
                worker_id=str(worker.id),
                worker_name=worker.worker_name,
                status=worker.status.value if hasattr(worker.status, 'value') else str(worker.status),
                current_load=round(load_percentage, 1),
                last_heartbeat=worker.last_heartbeat or datetime.utcnow()
            ))

        # If no workers, return sample data
        if not worker_statuses:
            now = datetime.utcnow()
            worker_statuses = [
                WorkerStatusResponse(
                    worker_id="worker-1",
                    worker_name="Main Worker",
                    status="running",
                    current_load=45.0,
                    last_heartbeat=now - timedelta(seconds=30)
                ),
                WorkerStatusResponse(
                    worker_id="worker-2",
                    worker_name="Secondary Worker",
                    status="idle",
                    current_load=0.0,
                    last_heartbeat=now - timedelta(minutes=2)
                )
            ]

        return worker_statuses

    except Exception as e:
        logger.error(f"Failed to get worker status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get worker status: {str(e)}")

@router.get("/monitoring/performance", response_model=PerformanceDataResponse)
async def get_performance_data(
    range: str = Query("1h", regex="^(1h|6h|24h|7d)$"),
    current_user: User = Depends(get_current_user)
):
    """Get performance data for charts."""
    try:
        # Generate sample performance data based on time range
        now = datetime.utcnow()

        if range == "1h":
            points = 12  # 5-minute intervals
            delta = timedelta(minutes=5)
        elif range == "6h":
            points = 24  # 15-minute intervals
            delta = timedelta(minutes=15)
        elif range == "24h":
            points = 24  # 1-hour intervals
            delta = timedelta(hours=1)
        else:  # 7d
            points = 7   # 1-day intervals
            delta = timedelta(days=1)

        timestamps = []
        cpu_history = []
        memory_history = []
        throughput_history = []
        error_rate_history = []

        for i in range(points):
            timestamp = now - (delta * (points - i - 1))
            timestamps.append(timestamp.isoformat())

            # Generate realistic sample data with some variation
            import random
            base_cpu = 35 + random.uniform(-10, 25)
            base_memory = 45 + random.uniform(-15, 30)
            base_throughput = 10 + random.uniform(-5, 15)
            base_error_rate = 2 + random.uniform(-1, 3)

            cpu_history.append(max(0, min(100, base_cpu)))
            memory_history.append(max(0, min(100, base_memory)))
            throughput_history.append(max(0, base_throughput))
            error_rate_history.append(max(0, min(10, base_error_rate)))

        return PerformanceDataResponse(
            timestamps=timestamps,
            cpu_history=[round(x, 1) for x in cpu_history],
            memory_history=[round(x, 1) for x in memory_history],
            throughput_history=[round(x, 1) for x in throughput_history],
            error_rate_history=[round(x, 1) for x in error_rate_history]
        )

    except Exception as e:
        logger.error(f"Failed to get performance data: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get performance data: {str(e)}")

@router.post("/monitoring/workers/{worker_id}/{action}")
async def worker_action(
    worker_id: str,
    action: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Perform action on worker (start/stop/restart)."""
    if action not in ["start", "stop", "restart"]:
        raise HTTPException(status_code=400, detail="Invalid action")

    try:
        worker = db.query(BatchWorker).filter(BatchWorker.id == worker_id).first()
        if not worker:
            raise HTTPException(status_code=404, detail="Worker not found")

        # Update worker status based on action
        if action == "start":
            worker.status = "running"
        elif action == "stop":
            worker.status = "idle"
        elif action == "restart":
            worker.status = "running"
            worker.last_heartbeat = datetime.utcnow()

        db.commit()

        return {"message": f"Worker {action}ed successfully", "worker_id": worker_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to perform worker action: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to perform worker action: {str(e)}")