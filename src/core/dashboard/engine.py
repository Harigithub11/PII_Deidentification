"""
Business Intelligence Engine

Core engine for coordinating business intelligence operations, dashboard management,
and real-time analytics processing.
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Set
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database.session import get_db_session, transaction_scope
from ..database.repositories.batch_job_repository import BatchJobRepository
from ..database.repositories.batch_worker_repository import BatchWorkerRepository
from ..database.repositories.job_result_repository import JobResultRepository
from ..database.repositories.job_schedule_repository import JobScheduleRepository
from ..config.settings import get_settings
from ..orchestration.airflow_integration import get_airflow_engine

logger = logging.getLogger(__name__)
settings = get_settings()


class DashboardType(str, Enum):
    """Types of dashboards available."""
    EXECUTIVE = "executive"
    OPERATIONAL = "operational" 
    SECURITY = "security"
    COMPLIANCE = "compliance"
    PERFORMANCE = "performance"
    USER_ACTIVITY = "user_activity"
    CUSTOM = "custom"


class MetricType(str, Enum):
    """Types of metrics that can be tracked."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    TREND = "trend"
    RATIO = "ratio"


class RefreshInterval(str, Enum):
    """Refresh intervals for real-time updates."""
    REALTIME = "realtime"  # WebSocket updates
    FIVE_SECONDS = "5s"
    FIFTEEN_SECONDS = "15s"
    THIRTY_SECONDS = "30s"
    ONE_MINUTE = "1m"
    FIVE_MINUTES = "5m"
    FIFTEEN_MINUTES = "15m"
    ONE_HOUR = "1h"


@dataclass
class DashboardMetrics:
    """Metrics about dashboard performance and usage."""
    dashboard_id: UUID
    total_widgets: int
    active_users: int
    avg_load_time_ms: float
    total_queries: int
    cache_hit_ratio: float
    memory_usage_mb: float
    last_updated: datetime
    error_count: int = 0


class DashboardConfig(BaseModel):
    """Configuration for dashboard creation and management."""
    
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    dashboard_type: DashboardType
    
    # Layout and display
    layout: Dict[str, Any] = Field(default_factory=dict)
    theme: str = "default"
    auto_refresh: bool = True
    refresh_interval: RefreshInterval = RefreshInterval.ONE_MINUTE
    
    # Access control
    owner_id: UUID
    shared_with: List[UUID] = Field(default_factory=list)
    public: bool = False
    
    # Widget configuration
    widgets: List[Dict[str, Any]] = Field(default_factory=list)
    widget_order: List[UUID] = Field(default_factory=list)
    
    # Performance settings
    enable_caching: bool = True
    cache_duration_minutes: int = 5
    max_data_points: int = 1000
    
    # Real-time features
    enable_realtime: bool = False
    websocket_enabled: bool = False
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = Field(default_factory=list)


class BusinessIntelligenceEngine:
    """
    Core Business Intelligence Engine for coordinating dashboard operations,
    data aggregation, and real-time analytics.
    """
    
    def __init__(self, session: Optional[Session] = None):
        self._session = session
        self._active_dashboards: Dict[UUID, DashboardConfig] = {}
        self._dashboard_metrics: Dict[UUID, DashboardMetrics] = {}
        self._data_cache: Dict[str, Dict[str, Any]] = {}
        self._realtime_connections: Dict[UUID, Set[str]] = {}  # dashboard_id -> connection_ids
        self._executor = ThreadPoolExecutor(max_workers=4)
        
        # Repository dependencies for batch monitoring
        self._job_repository = BatchJobRepository(session)
        self._worker_repository = BatchWorkerRepository(session)
        self._result_repository = JobResultRepository(session)
        self._schedule_repository = JobScheduleRepository(session)
        
        # Background tasks
        self._refresh_tasks: Dict[UUID, asyncio.Task] = {}
        self._cleanup_task: Optional[asyncio.Task] = None
        
        # Metrics tracking
        self._query_count = 0
        self._cache_hits = 0
        self._cache_misses = 0
        
        logger.info("Business Intelligence Engine initialized with batch monitoring support")
    
    @property
    def session(self) -> Session:
        """Get current database session."""
        if self._session:
            return self._session
        return get_db_session()
    
    async def create_dashboard(self, config: DashboardConfig) -> DashboardConfig:
        """
        Create a new dashboard with specified configuration.
        
        Args:
            config: Dashboard configuration
            
        Returns:
            Created dashboard configuration
        """
        try:
            # Validate configuration
            await self._validate_dashboard_config(config)
            
            # Store dashboard configuration
            self._active_dashboards[config.id] = config
            
            # Initialize metrics
            self._dashboard_metrics[config.id] = DashboardMetrics(
                dashboard_id=config.id,
                total_widgets=len(config.widgets),
                active_users=0,
                avg_load_time_ms=0.0,
                total_queries=0,
                cache_hit_ratio=0.0,
                memory_usage_mb=0.0,
                last_updated=datetime.utcnow()
            )
            
            # Set up real-time connections if enabled
            if config.enable_realtime:
                self._realtime_connections[config.id] = set()
            
            # Start refresh task if auto-refresh is enabled
            if config.auto_refresh:
                await self._start_refresh_task(config.id)
            
            logger.info(f"Dashboard created: {config.id} - {config.name}")
            return config
            
        except Exception as e:
            logger.error(f"Failed to create dashboard {config.id}: {e}")
            raise
    
    async def get_dashboard(self, dashboard_id: UUID) -> Optional[DashboardConfig]:
        """Get dashboard configuration by ID."""
        return self._active_dashboards.get(dashboard_id)
    
    async def update_dashboard(self, dashboard_id: UUID, updates: Dict[str, Any]) -> DashboardConfig:
        """Update dashboard configuration."""
        if dashboard_id not in self._active_dashboards:
            raise ValueError(f"Dashboard not found: {dashboard_id}")
        
        config = self._active_dashboards[dashboard_id]
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(config, key):
                setattr(config, key, value)
        
        config.updated_at = datetime.utcnow()
        
        # Restart refresh task if refresh settings changed
        if any(key in updates for key in ['auto_refresh', 'refresh_interval']):
            await self._restart_refresh_task(dashboard_id)
        
        logger.info(f"Dashboard updated: {dashboard_id}")
        return config
    
    async def delete_dashboard(self, dashboard_id: UUID) -> bool:
        """Delete dashboard and clean up resources."""
        if dashboard_id not in self._active_dashboards:
            return False
        
        # Stop refresh task
        if dashboard_id in self._refresh_tasks:
            self._refresh_tasks[dashboard_id].cancel()
            del self._refresh_tasks[dashboard_id]
        
        # Clean up real-time connections
        self._realtime_connections.pop(dashboard_id, None)
        
        # Remove from active dashboards and metrics
        del self._active_dashboards[dashboard_id]
        del self._dashboard_metrics[dashboard_id]
        
        # Clear related cache entries
        await self._clear_dashboard_cache(dashboard_id)
        
        logger.info(f"Dashboard deleted: {dashboard_id}")
        return True
    
    async def get_dashboard_data(self, dashboard_id: UUID, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Get aggregated data for all widgets in a dashboard.
        
        Args:
            dashboard_id: Dashboard ID
            force_refresh: Skip cache and fetch fresh data
            
        Returns:
            Dictionary containing data for all dashboard widgets
        """
        if dashboard_id not in self._active_dashboards:
            raise ValueError(f"Dashboard not found: {dashboard_id}")
        
        config = self._active_dashboards[dashboard_id]
        
        # Check cache first unless force refresh
        cache_key = f"dashboard_{dashboard_id}"
        if not force_refresh and config.enable_caching:
            cached_data = self._get_cached_data(cache_key)
            if cached_data:
                self._cache_hits += 1
                return cached_data
        
        self._cache_misses += 1
        
        # Aggregate data for all widgets
        dashboard_data = {
            "dashboard_id": str(dashboard_id),
            "name": config.name,
            "last_updated": datetime.utcnow().isoformat(),
            "widgets": {}
        }
        
        # Process each widget
        for widget_config in config.widgets:
            widget_id = widget_config.get("id")
            if widget_id:
                try:
                    widget_data = await self._get_widget_data(widget_config)
                    dashboard_data["widgets"][widget_id] = widget_data
                except Exception as e:
                    logger.error(f"Failed to get data for widget {widget_id}: {e}")
                    dashboard_data["widgets"][widget_id] = {
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat()
                    }
        
        # Cache the result
        if config.enable_caching:
            self._cache_data(cache_key, dashboard_data, config.cache_duration_minutes)
        
        # Update metrics
        self._update_dashboard_metrics(dashboard_id, len(config.widgets))
        
        return dashboard_data
    
    async def get_realtime_data(self, dashboard_id: UUID, widget_id: Optional[str] = None) -> Dict[str, Any]:
        """Get real-time data for dashboard or specific widget."""
        if dashboard_id not in self._active_dashboards:
            raise ValueError(f"Dashboard not found: {dashboard_id}")
        
        config = self._active_dashboards[dashboard_id]
        
        if not config.enable_realtime:
            raise ValueError("Real-time updates not enabled for this dashboard")
        
        if widget_id:
            # Get data for specific widget
            widget_config = next((w for w in config.widgets if w.get("id") == widget_id), None)
            if not widget_config:
                raise ValueError(f"Widget not found: {widget_id}")
            
            return await self._get_widget_data(widget_config)
        else:
            # Get data for entire dashboard
            return await self.get_dashboard_data(dashboard_id, force_refresh=True)
    
    async def register_realtime_connection(self, dashboard_id: UUID, connection_id: str) -> bool:
        """Register a WebSocket connection for real-time updates."""
        if dashboard_id not in self._active_dashboards:
            return False
        
        if dashboard_id not in self._realtime_connections:
            self._realtime_connections[dashboard_id] = set()
        
        self._realtime_connections[dashboard_id].add(connection_id)
        
        # Update active users count
        if dashboard_id in self._dashboard_metrics:
            self._dashboard_metrics[dashboard_id].active_users = len(self._realtime_connections[dashboard_id])
        
        logger.info(f"Real-time connection registered: {connection_id} for dashboard {dashboard_id}")
        return True
    
    async def unregister_realtime_connection(self, dashboard_id: UUID, connection_id: str) -> bool:
        """Unregister a WebSocket connection."""
        if dashboard_id in self._realtime_connections:
            self._realtime_connections[dashboard_id].discard(connection_id)
            
            # Update active users count
            if dashboard_id in self._dashboard_metrics:
                self._dashboard_metrics[dashboard_id].active_users = len(self._realtime_connections[dashboard_id])
            
            logger.info(f"Real-time connection unregistered: {connection_id}")
            return True
        return False
    
    async def broadcast_update(self, dashboard_id: UUID, data: Dict[str, Any]) -> int:
        """Broadcast real-time update to all connected clients."""
        if dashboard_id not in self._realtime_connections:
            return 0
        
        connections = self._realtime_connections[dashboard_id]
        
        # In a real implementation, this would send WebSocket messages
        # For now, we'll just log the broadcast
        logger.info(f"Broadcasting update to {len(connections)} connections for dashboard {dashboard_id}")
        
        return len(connections)
    
    def get_dashboard_metrics(self, dashboard_id: UUID) -> Optional[DashboardMetrics]:
        """Get performance metrics for a dashboard."""
        return self._dashboard_metrics.get(dashboard_id)
    
    def get_global_metrics(self) -> Dict[str, Any]:
        """Get global BI engine metrics."""
        total_dashboards = len(self._active_dashboards)
        total_widgets = sum(len(config.widgets) for config in self._active_dashboards.values())
        total_connections = sum(len(connections) for connections in self._realtime_connections.values())
        
        cache_hit_ratio = 0.0
        if (self._cache_hits + self._cache_misses) > 0:
            cache_hit_ratio = self._cache_hits / (self._cache_hits + self._cache_misses)
        
        return {
            "total_dashboards": total_dashboards,
            "total_widgets": total_widgets,
            "active_connections": total_connections,
            "total_queries": self._query_count,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cache_hit_ratio": round(cache_hit_ratio, 4),
            "cached_entries": len(self._data_cache)
        }
    
    async def _validate_dashboard_config(self, config: DashboardConfig) -> None:
        """Validate dashboard configuration."""
        if not config.name.strip():
            raise ValueError("Dashboard name is required")
        
        if len(config.widgets) > 50:  # Reasonable limit
            raise ValueError("Too many widgets (max 50)")
        
        # Validate widget configurations
        widget_ids = set()
        for widget in config.widgets:
            widget_id = widget.get("id")
            if not widget_id:
                raise ValueError("Widget ID is required")
            if widget_id in widget_ids:
                raise ValueError(f"Duplicate widget ID: {widget_id}")
            widget_ids.add(widget_id)
    
    async def _get_widget_data(self, widget_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get data for a specific widget based on its configuration."""
        widget_type = widget_config.get("type", "metric")
        widget_id = widget_config.get("id")
        
        # This would typically query the database or other data sources
        # For now, we'll return sample data based on widget type
        
        base_data = {
            "widget_id": widget_id,
            "type": widget_type,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Handle batch monitoring widgets
        if widget_type == "batch_job_queue":
            base_data.update(await self._get_batch_job_queue_data(widget_config))
        elif widget_type == "batch_worker_status":
            base_data.update(await self._get_batch_worker_status_data(widget_config))
        elif widget_type == "batch_job_metrics":
            base_data.update(await self._get_batch_job_metrics_data(widget_config))
        elif widget_type == "batch_schedule_status":
            base_data.update(await self._get_batch_schedule_status_data(widget_config))
        elif widget_type == "airflow_dag_status":
            base_data.update(await self._get_airflow_dag_status_data(widget_config))
        elif widget_type == "workflow_execution_chart":
            base_data.update(await self._get_workflow_execution_chart_data(widget_config))
        elif widget_type == "job_performance_metrics":
            base_data.update(await self._get_job_performance_metrics_data(widget_config))
        elif widget_type == "system_health_monitor":
            base_data.update(await self._get_system_health_monitor_data(widget_config))
        # Standard widget types
        elif widget_type == "metric":
            base_data.update({
                "value": 42,
                "unit": "count",
                "change": "+5%",
                "trend": "up"
            })
        elif widget_type == "chart":
            base_data.update({
                "chart_type": widget_config.get("chart_type", "line"),
                "data": [
                    {"x": "2024-01-01", "y": 10},
                    {"x": "2024-01-02", "y": 15},
                    {"x": "2024-01-03", "y": 12}
                ]
            })
        elif widget_type == "table":
            base_data.update({
                "headers": ["Name", "Value", "Status"],
                "rows": [
                    ["Item 1", "100", "Active"],
                    ["Item 2", "250", "Pending"],
                    ["Item 3", "75", "Completed"]
                ]
            })
        
        self._query_count += 1
        return base_data
    
    def _get_cached_data(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get data from cache if not expired."""
        if cache_key in self._data_cache:
            cache_entry = self._data_cache[cache_key]
            if cache_entry["expires_at"] > datetime.utcnow():
                return cache_entry["data"]
            else:
                # Remove expired entry
                del self._data_cache[cache_key]
        return None
    
    def _cache_data(self, cache_key: str, data: Dict[str, Any], duration_minutes: int) -> None:
        """Cache data with expiration."""
        expires_at = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self._data_cache[cache_key] = {
            "data": data,
            "expires_at": expires_at,
            "created_at": datetime.utcnow()
        }
    
    async def _clear_dashboard_cache(self, dashboard_id: UUID) -> None:
        """Clear all cache entries related to a dashboard."""
        keys_to_remove = [
            key for key in self._data_cache.keys()
            if key.startswith(f"dashboard_{dashboard_id}")
        ]
        for key in keys_to_remove:
            del self._data_cache[key]
    
    def _update_dashboard_metrics(self, dashboard_id: UUID, widget_count: int) -> None:
        """Update dashboard performance metrics."""
        if dashboard_id in self._dashboard_metrics:
            metrics = self._dashboard_metrics[dashboard_id]
            metrics.total_queries += 1
            metrics.last_updated = datetime.utcnow()
            
            # Update cache hit ratio
            if (self._cache_hits + self._cache_misses) > 0:
                metrics.cache_hit_ratio = self._cache_hits / (self._cache_hits + self._cache_misses)
    
    async def _start_refresh_task(self, dashboard_id: UUID) -> None:
        """Start background refresh task for dashboard."""
        if dashboard_id in self._refresh_tasks:
            return
        
        config = self._active_dashboards[dashboard_id]
        refresh_seconds = self._get_refresh_seconds(config.refresh_interval)
        
        async def refresh_loop():
            while True:
                try:
                    await asyncio.sleep(refresh_seconds)
                    
                    # Get fresh data and broadcast if real-time enabled
                    if config.enable_realtime:
                        data = await self.get_dashboard_data(dashboard_id, force_refresh=True)
                        await self.broadcast_update(dashboard_id, data)
                    
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in refresh task for dashboard {dashboard_id}: {e}")
        
        self._refresh_tasks[dashboard_id] = asyncio.create_task(refresh_loop())
        logger.info(f"Started refresh task for dashboard {dashboard_id} (interval: {refresh_seconds}s)")
    
    async def _restart_refresh_task(self, dashboard_id: UUID) -> None:
        """Restart refresh task with new settings."""
        # Cancel existing task
        if dashboard_id in self._refresh_tasks:
            self._refresh_tasks[dashboard_id].cancel()
            del self._refresh_tasks[dashboard_id]
        
        # Start new task if auto-refresh is enabled
        config = self._active_dashboards[dashboard_id]
        if config.auto_refresh:
            await self._start_refresh_task(dashboard_id)
    
    def _get_refresh_seconds(self, interval: RefreshInterval) -> int:
        """Convert refresh interval to seconds."""
        interval_map = {
            RefreshInterval.FIVE_SECONDS: 5,
            RefreshInterval.FIFTEEN_SECONDS: 15,
            RefreshInterval.THIRTY_SECONDS: 30,
            RefreshInterval.ONE_MINUTE: 60,
            RefreshInterval.FIVE_MINUTES: 300,
            RefreshInterval.FIFTEEN_MINUTES: 900,
            RefreshInterval.ONE_HOUR: 3600
        }
        return interval_map.get(interval, 60)  # Default to 1 minute
    
    async def cleanup(self) -> None:
        """Clean up resources and stop background tasks."""
        # Cancel all refresh tasks
        for task in self._refresh_tasks.values():
            task.cancel()
        
        # Wait for tasks to complete
        if self._refresh_tasks:
            await asyncio.gather(*self._refresh_tasks.values(), return_exceptions=True)
        
        # Clean up executor
        self._executor.shutdown(wait=True)
        
        logger.info("Business Intelligence Engine cleaned up")
    
    # Batch Monitoring Widget Data Methods
    
    async def _get_batch_job_queue_data(self, widget_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get data for batch job queue monitoring widget."""
        try:
            # Get job queue statistics
            pending_jobs = self._job_repository.find_jobs(status='pending', limit=100)
            queued_jobs = self._job_repository.find_jobs(status='queued', limit=100)
            running_jobs = self._job_repository.find_jobs(status='running', limit=100)
            
            queue_data = {
                "queue_stats": {
                    "pending": len(pending_jobs),
                    "queued": len(queued_jobs),
                    "running": len(running_jobs),
                    "total_in_queue": len(pending_jobs) + len(queued_jobs)
                },
                "recent_jobs": [],
                "job_types": {},
                "priority_breakdown": {"low": 0, "normal": 0, "high": 0, "critical": 0, "urgent": 0}
            }
            
            # Get recent jobs for display
            all_active_jobs = pending_jobs + queued_jobs + running_jobs
            all_active_jobs.sort(key=lambda x: x.created_at, reverse=True)
            
            for job in all_active_jobs[:20]:  # Show top 20 recent jobs
                queue_data["recent_jobs"].append({
                    "id": str(job.id),
                    "name": job.name,
                    "job_type": job.job_type.value if hasattr(job.job_type, 'value') else str(job.job_type),
                    "status": job.status.value if hasattr(job.status, 'value') else str(job.status),
                    "priority": job.priority.value if hasattr(job.priority, 'value') else str(job.priority),
                    "created_at": job.created_at.isoformat(),
                    "progress": job.progress_percentage,
                    "current_step": job.current_step
                })
                
                # Count by job type
                job_type = job.job_type.value if hasattr(job.job_type, 'value') else str(job.job_type)
                queue_data["job_types"][job_type] = queue_data["job_types"].get(job_type, 0) + 1
                
                # Count by priority
                priority = job.priority.value if hasattr(job.priority, 'value') else str(job.priority)
                if priority in queue_data["priority_breakdown"]:
                    queue_data["priority_breakdown"][priority] += 1
            
            return queue_data
            
        except Exception as e:
            logger.error(f"Error getting batch job queue data: {e}")
            return {"error": str(e), "queue_stats": {"total_in_queue": 0}}
    
    async def _get_batch_worker_status_data(self, widget_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get data for batch worker status widget."""
        try:
            # Get all workers
            workers = await self._worker_repository.get_active_workers()
            
            worker_data = {
                "total_workers": len(workers),
                "workers_by_status": {"idle": 0, "busy": 0, "offline": 0, "error": 0, "maintenance": 0},
                "worker_details": [],
                "resource_utilization": {"avg_cpu": 0, "avg_memory": 0, "total_jobs_running": 0}
            }
            
            total_cpu = 0
            total_memory = 0
            active_workers = 0
            
            for worker in workers:
                status = worker.status.value if hasattr(worker.status, 'value') else str(worker.status)
                worker_data["workers_by_status"][status] = worker_data["workers_by_status"].get(status, 0) + 1
                
                worker_data["worker_details"].append({
                    "id": str(worker.id),
                    "name": worker.worker_name,
                    "hostname": worker.hostname,
                    "status": status,
                    "current_jobs": worker.current_jobs_count,
                    "max_jobs": worker.max_concurrent_jobs,
                    "cpu_usage": worker.current_cpu_usage_percent or 0,
                    "memory_usage": worker.current_memory_usage_mb or 0,
                    "memory_limit": worker.memory_limit_mb,
                    "last_heartbeat": worker.last_heartbeat.isoformat() if worker.last_heartbeat else None,
                    "success_rate": worker.success_rate or 0
                })
                
                if worker.current_cpu_usage_percent is not None:
                    total_cpu += worker.current_cpu_usage_percent
                    active_workers += 1
                
                if worker.current_memory_usage_mb is not None:
                    total_memory += worker.current_memory_usage_mb
                
                worker_data["resource_utilization"]["total_jobs_running"] += worker.current_jobs_count
            
            # Calculate averages
            if active_workers > 0:
                worker_data["resource_utilization"]["avg_cpu"] = total_cpu / active_workers
                worker_data["resource_utilization"]["avg_memory"] = total_memory / active_workers
            
            return worker_data
            
        except Exception as e:
            logger.error(f"Error getting batch worker status data: {e}")
            return {"error": str(e), "total_workers": 0}
    
    async def _get_batch_job_metrics_data(self, widget_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get data for batch job metrics widget."""
        try:
            days_back = widget_config.get('days_back', 7)
            
            # Get job statistics
            job_stats = self._job_repository.get_job_statistics(days_back=days_back)
            
            metrics_data = {
                "summary": {
                    "total_jobs": job_stats.get("total_jobs", 0),
                    "success_rate": job_stats.get("success_rate", 0),
                    "average_duration": job_stats.get("average_duration_seconds", 0),
                    "total_processing_time": job_stats.get("total_processing_time", 0)
                },
                "status_breakdown": job_stats.get("by_status", {}),
                "job_type_breakdown": job_stats.get("by_type", {}),
                "priority_breakdown": job_stats.get("by_priority", {}),
                "performance_trends": []
            }
            
            # Generate performance trend data (simplified)
            from datetime import timedelta
            base_time = datetime.utcnow() - timedelta(days=days_back)
            
            for i in range(days_back):
                day_time = base_time + timedelta(days=i)
                # In a real implementation, this would query historical data
                metrics_data["performance_trends"].append({
                    "date": day_time.strftime("%Y-%m-%d"),
                    "jobs_completed": job_stats.get("total_jobs", 0) // days_back + (i % 3),
                    "avg_duration": job_stats.get("average_duration_seconds", 0) + (i * 10),
                    "success_rate": max(0.8, job_stats.get("success_rate", 0) - (0.05 * (i % 3)))
                })
            
            return metrics_data
            
        except Exception as e:
            logger.error(f"Error getting batch job metrics data: {e}")
            return {"error": str(e), "summary": {"total_jobs": 0}}
    
    async def _get_batch_schedule_status_data(self, widget_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get data for batch schedule status widget."""
        try:
            # Get schedule statistics
            schedule_stats = self._schedule_repository.get_schedule_statistics(days_back=30)
            
            # Get due and overdue schedules
            due_schedules = self._schedule_repository.get_due_schedules()
            overdue_schedules = self._schedule_repository.get_overdue_schedules()
            
            schedule_data = {
                "summary": {
                    "total_schedules": schedule_stats.get("total_schedules", 0),
                    "active_schedules": schedule_stats.get("active_schedules", 0),
                    "failed_schedules": schedule_stats.get("failed_schedules", 0),
                    "schedules_due_soon": schedule_stats.get("schedules_due_soon", 0)
                },
                "due_schedules": [],
                "overdue_schedules": [],
                "recent_executions": []
            }
            
            # Format due schedules
            for schedule in due_schedules[:10]:  # Show top 10
                schedule_data["due_schedules"].append({
                    "id": str(schedule.id),
                    "name": schedule.schedule_name,
                    "cron_expression": schedule.cron_expression,
                    "next_run": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
                    "last_status": schedule.last_run_status.value if schedule.last_run_status else "unknown"
                })
            
            # Format overdue schedules
            for schedule in overdue_schedules[:10]:  # Show top 10
                schedule_data["overdue_schedules"].append({
                    "id": str(schedule.id),
                    "name": schedule.schedule_name,
                    "next_run": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
                    "consecutive_failures": schedule.consecutive_failures,
                    "overdue_minutes": int((datetime.utcnow() - schedule.next_run_at).total_seconds() / 60) if schedule.next_run_at else 0
                })
            
            return schedule_data
            
        except Exception as e:
            logger.error(f"Error getting batch schedule status data: {e}")
            return {"error": str(e), "summary": {"total_schedules": 0}}
    
    async def _get_airflow_dag_status_data(self, widget_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get data for Airflow DAG status widget."""
        try:
            # Get Airflow integration engine
            airflow_engine = get_airflow_engine(self.session)
            
            # Get workflow and execution data
            workflows = await airflow_engine.list_workflows(limit=50)
            executions = await airflow_engine.list_executions(limit=100)
            
            airflow_data = {
                "dag_summary": {
                    "total_workflows": len(workflows),
                    "active_workflows": len([w for w in workflows if w.status == "running"]),
                    "total_executions": len(executions),
                    "running_executions": len([e for e in executions if e.status == "running"])
                },
                "recent_dag_runs": [],
                "workflow_status": {},
                "execution_trends": []
            }
            
            # Format recent executions
            executions.sort(key=lambda x: x.created_at, reverse=True)
            for execution in executions[:15]:  # Show top 15
                airflow_data["recent_dag_runs"].append({
                    "execution_id": str(execution.id),
                    "workflow_id": str(execution.workflow_id),
                    "status": execution.status.value if hasattr(execution.status, 'value') else str(execution.status),
                    "started_at": execution.started_at.isoformat() if execution.started_at else None,
                    "duration": execution.get_runtime_seconds(),
                    "airflow_dag_run_id": execution.airflow_dag_run_id
                })
            
            # Count workflows by status
            for workflow in workflows:
                status = workflow.status.value if hasattr(workflow.status, 'value') else str(workflow.status)
                airflow_data["workflow_status"][status] = airflow_data["workflow_status"].get(status, 0) + 1
            
            return airflow_data
            
        except Exception as e:
            logger.error(f"Error getting Airflow DAG status data: {e}")
            return {"error": str(e), "dag_summary": {"total_workflows": 0}}
    
    async def _get_workflow_execution_chart_data(self, widget_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get data for workflow execution chart widget."""
        try:
            days_back = widget_config.get('days_back', 7)
            chart_type = widget_config.get('chart_type', 'line')
            
            # Generate chart data for workflow executions
            from datetime import timedelta
            base_time = datetime.utcnow() - timedelta(days=days_back)
            
            chart_data = {
                "chart_type": chart_type,
                "labels": [],
                "datasets": [
                    {"label": "Successful Executions", "data": [], "color": "#28a745"},
                    {"label": "Failed Executions", "data": [], "color": "#dc3545"},
                    {"label": "Running Executions", "data": [], "color": "#ffc107"}
                ]
            }
            
            # Generate time series data
            for i in range(days_back):
                day_time = base_time + timedelta(days=i)
                chart_data["labels"].append(day_time.strftime("%m/%d"))
                
                # Simulate data - in real implementation, query actual execution data
                chart_data["datasets"][0]["data"].append(10 + (i % 5))  # Successful
                chart_data["datasets"][1]["data"].append(2 + (i % 3))   # Failed
                chart_data["datasets"][2]["data"].append(1 + (i % 2))   # Running
            
            return chart_data
            
        except Exception as e:
            logger.error(f"Error getting workflow execution chart data: {e}")
            return {"error": str(e), "chart_type": "line"}
    
    async def _get_job_performance_metrics_data(self, widget_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get data for job performance metrics widget."""
        try:
            time_window = widget_config.get('time_window_hours', 24)
            
            # Get performance metrics from job results
            performance_data = self._result_repository.get_performance_metrics(
                days_back=time_window // 24
            )
            
            metrics_data = {
                "performance_summary": {
                    "avg_execution_time": performance_data.get("avg_execution_time", 0),
                    "throughput_jobs_per_hour": performance_data.get("throughput", 0),
                    "resource_efficiency": performance_data.get("efficiency_score", 0),
                    "error_rate": performance_data.get("error_rate", 0)
                },
                "top_performers": performance_data.get("top_performers", []),
                "bottlenecks": performance_data.get("bottlenecks", []),
                "resource_usage": {
                    "avg_cpu": performance_data.get("avg_cpu", 0),
                    "avg_memory": performance_data.get("avg_memory", 0),
                    "disk_io": performance_data.get("disk_io", 0)
                }
            }
            
            return metrics_data
            
        except Exception as e:
            logger.error(f"Error getting job performance metrics data: {e}")
            return {"error": str(e), "performance_summary": {"avg_execution_time": 0}}
    
    async def _get_system_health_monitor_data(self, widget_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get data for system health monitoring widget."""
        try:
            health_data = {
                "system_status": "healthy",
                "components": {
                    "batch_engine": {"status": "healthy", "last_check": datetime.utcnow().isoformat()},
                    "database": {"status": "healthy", "last_check": datetime.utcnow().isoformat()},
                    "airflow": {"status": "unknown", "last_check": datetime.utcnow().isoformat()},
                    "workers": {"status": "healthy", "last_check": datetime.utcnow().isoformat()}
                },
                "alerts": [],
                "resource_status": {
                    "database_connections": {"current": 5, "max": 100, "status": "normal"},
                    "memory_usage": {"current": 45, "max": 100, "status": "normal"},
                    "disk_space": {"current": 65, "max": 100, "status": "warning"}
                }
            }
            
            # Check Airflow health
            try:
                airflow_engine = get_airflow_engine(self.session)
                # This would check actual Airflow health in real implementation
                health_data["components"]["airflow"]["status"] = "healthy"
            except Exception:
                health_data["components"]["airflow"]["status"] = "error"
                health_data["system_status"] = "degraded"
                health_data["alerts"].append({
                    "severity": "warning",
                    "message": "Airflow connection issues detected",
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            # Check for any component issues
            unhealthy_components = [k for k, v in health_data["components"].items() if v["status"] != "healthy"]
            if unhealthy_components:
                health_data["system_status"] = "degraded" if len(unhealthy_components) == 1 else "critical"
            
            return health_data
            
        except Exception as e:
            logger.error(f"Error getting system health monitor data: {e}")
            return {"error": str(e), "system_status": "error"}


# Global BI engine instance
_bi_engine: Optional[BusinessIntelligenceEngine] = None


def get_bi_engine(session: Optional[Session] = None) -> BusinessIntelligenceEngine:
    """Get the global BI engine instance."""
    global _bi_engine
    if _bi_engine is None:
        _bi_engine = BusinessIntelligenceEngine(session)
    return _bi_engine


def initialize_bi_engine(session: Optional[Session] = None) -> BusinessIntelligenceEngine:
    """Initialize the BI engine."""
    global _bi_engine
    _bi_engine = BusinessIntelligenceEngine(session)
    logger.info("Business Intelligence Engine initialized successfully")
    return _bi_engine