"""
Health check and system status endpoints
"""
import psutil
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_async_db, DatabaseManager
from src.core.config import settings
from src.models.schemas import SystemHealth

router = APIRouter()


@router.get("/health", response_model=SystemHealth)
async def health_check(db: AsyncSession = Depends(get_async_db)):
    """
    Comprehensive system health check
    """
    # Check database connectivity
    database_healthy = await DatabaseManager.health_check()
    
    # Check Redis connectivity (placeholder for now)
    redis_healthy = True  # TODO: Implement Redis health check
    
    # Check OCR service (placeholder for now)
    ocr_healthy = True  # TODO: Implement OCR service health check
    
    # Check PII service (placeholder for now)
    pii_healthy = True  # TODO: Implement PII service health check
    
    # Get system metrics
    disk_usage = psutil.disk_usage('/')
    disk_space_gb = disk_usage.free / (1024**3)
    
    memory = psutil.virtual_memory()
    memory_usage_percent = memory.percent
    
    return SystemHealth(
        database=database_healthy,
        redis=redis_healthy,
        ocr_service=ocr_healthy,
        pii_service=pii_healthy,
        disk_space_gb=round(disk_space_gb, 2),
        memory_usage_percent=memory_usage_percent,
        timestamp=datetime.utcnow()
    )


@router.get("/health/database")
async def database_health():
    """
    Database-specific health check
    """
    is_healthy = await DatabaseManager.health_check()
    return {
        "service": "database",
        "status": "healthy" if is_healthy else "unhealthy",
        "timestamp": datetime.utcnow()
    }


@router.get("/health/storage")
async def storage_health():
    """
    Storage system health check
    """
    paths_to_check = [
        settings.UPLOAD_PATH,
        settings.OUTPUT_PATH,
        settings.TEMP_PATH
    ]
    
    storage_status = {}
    overall_healthy = True
    
    for path_str in paths_to_check:
        path = Path(path_str)
        try:
            path.mkdir(parents=True, exist_ok=True)
            is_accessible = path.exists() and path.is_dir()
            
            # Get disk space for this path
            disk_usage = psutil.disk_usage(str(path))
            free_space_gb = disk_usage.free / (1024**3)
            
            storage_status[path_str] = {
                "accessible": is_accessible,
                "free_space_gb": round(free_space_gb, 2),
                "healthy": is_accessible and free_space_gb > 1.0  # At least 1GB free
            }
            
            if not storage_status[path_str]["healthy"]:
                overall_healthy = False
                
        except Exception as e:
            storage_status[path_str] = {
                "accessible": False,
                "error": str(e),
                "healthy": False
            }
            overall_healthy = False
    
    return {
        "service": "storage",
        "status": "healthy" if overall_healthy else "unhealthy",
        "details": storage_status,
        "timestamp": datetime.utcnow()
    }


@router.get("/health/system")
async def system_health():
    """
    System resource health check
    """
    # CPU usage
    cpu_percent = psutil.cpu_percent(interval=1)
    
    # Memory usage
    memory = psutil.virtual_memory()
    
    # Disk usage
    disk_usage = psutil.disk_usage('/')
    
    return {
        "service": "system",
        "cpu_usage_percent": cpu_percent,
        "memory": {
            "total_gb": round(memory.total / (1024**3), 2),
            "available_gb": round(memory.available / (1024**3), 2),
            "used_percent": memory.percent
        },
        "disk": {
            "total_gb": round(disk_usage.total / (1024**3), 2),
            "free_gb": round(disk_usage.free / (1024**3), 2),
            "used_percent": round((disk_usage.used / disk_usage.total) * 100, 2)
        },
        "healthy": cpu_percent < 90 and memory.percent < 90,
        "timestamp": datetime.utcnow()
    }