"""
Dashboard API Endpoints

Provides REST API endpoints for business intelligence dashboards,
real-time visualization, and interactive dashboard management.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.database.session import get_db_session
from ..core.dashboard import (
    BusinessIntelligenceEngine, DashboardConfig, DashboardType,
    RefreshInterval, get_bi_engine, InteractiveDashboard,
    VisualizationEngine, ChartConfiguration, ChartType
)
from ..core.security.auth import get_current_user, User
from ..core.config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/api/v1/dashboard", tags=["Business Intelligence Dashboard"])


# Request/Response Models

class CreateDashboardRequest(BaseModel):
    """Request model for creating a new dashboard."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    dashboard_type: DashboardType
    layout: Dict[str, Any] = Field(default_factory=dict)
    theme: str = "default"
    auto_refresh: bool = True
    refresh_interval: RefreshInterval = RefreshInterval.ONE_MINUTE
    shared_with: List[UUID] = Field(default_factory=list)
    public: bool = False
    enable_realtime: bool = False
    tags: List[str] = Field(default_factory=list)


class UpdateDashboardRequest(BaseModel):
    """Request model for updating dashboard."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    layout: Optional[Dict[str, Any]] = None
    theme: Optional[str] = None
    auto_refresh: Optional[bool] = None
    refresh_interval: Optional[RefreshInterval] = None
    shared_with: Optional[List[UUID]] = None
    public: Optional[bool] = None
    enable_realtime: Optional[bool] = None
    tags: Optional[List[str]] = None


class DashboardResponse(BaseModel):
    """Response model for dashboard operations."""
    id: UUID
    name: str
    description: Optional[str]
    dashboard_type: DashboardType
    owner_id: UUID
    created_at: datetime
    updated_at: datetime
    widget_count: int
    is_public: bool
    enable_realtime: bool
    theme: str
    tags: List[str]


class DashboardDataResponse(BaseModel):
    """Response model for dashboard data."""
    dashboard_id: UUID
    name: str
    last_updated: datetime
    widgets: Dict[str, Any]
    metrics: Dict[str, Any] = Field(default_factory=dict)


class WebSocketMessage(BaseModel):
    """WebSocket message model."""
    type: str  # subscribe, unsubscribe, data_update, error
    dashboard_id: Optional[UUID] = None
    widget_id: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# Dashboard Management Endpoints

@router.post("/", response_model=DashboardResponse)
async def create_dashboard(
    request: CreateDashboardRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Create a new business intelligence dashboard."""
    try:
        # Create dashboard configuration
        config = DashboardConfig(
            name=request.name,
            description=request.description,
            dashboard_type=request.dashboard_type,
            layout=request.layout,
            theme=request.theme,
            auto_refresh=request.auto_refresh,
            refresh_interval=request.refresh_interval,
            owner_id=current_user.id,
            shared_with=request.shared_with,
            public=request.public,
            enable_realtime=request.enable_realtime,
            tags=request.tags
        )
        
        # Create dashboard using BI engine
        bi_engine = get_bi_engine(db)
        created_config = await bi_engine.create_dashboard(config)
        
        return DashboardResponse(
            id=created_config.id,
            name=created_config.name,
            description=created_config.description,
            dashboard_type=created_config.dashboard_type,
            owner_id=created_config.owner_id,
            created_at=created_config.created_at,
            updated_at=created_config.updated_at,
            widget_count=len(created_config.widgets),
            is_public=created_config.public,
            enable_realtime=created_config.enable_realtime,
            theme=created_config.theme,
            tags=created_config.tags
        )
        
    except Exception as e:
        logger.error(f"Failed to create dashboard: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create dashboard: {str(e)}")


@router.get("/", response_model=List[DashboardResponse])
async def list_dashboards(
    dashboard_type: Optional[DashboardType] = None,
    include_public: bool = True,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """List available dashboards for the current user."""
    try:
        # In a real implementation, this would query the database
        # For now, return sample dashboards
        
        sample_dashboards = [
            DashboardResponse(
                id=uuid4(),
                name="Security Overview",
                description="Security monitoring and threat detection dashboard",
                dashboard_type=DashboardType.SECURITY,
                owner_id=current_user.id,
                created_at=datetime.utcnow() - timedelta(days=7),
                updated_at=datetime.utcnow() - timedelta(hours=2),
                widget_count=6,
                is_public=False,
                enable_realtime=True,
                theme="dark",
                tags=["security", "monitoring"]
            ),
            DashboardResponse(
                id=uuid4(),
                name="Executive Summary",
                description="High-level business metrics and KPIs",
                dashboard_type=DashboardType.EXECUTIVE,
                owner_id=current_user.id,
                created_at=datetime.utcnow() - timedelta(days=14),
                updated_at=datetime.utcnow() - timedelta(days=1),
                widget_count=4,
                is_public=include_public,
                enable_realtime=False,
                theme="business",
                tags=["executive", "kpi"]
            )
        ]
        
        # Filter by type if specified
        if dashboard_type:
            sample_dashboards = [d for d in sample_dashboards if d.dashboard_type == dashboard_type]
        
        return sample_dashboards[offset:offset + limit]
        
    except Exception as e:
        logger.error(f"Failed to list dashboards: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list dashboards: {str(e)}")


@router.get("/{dashboard_id}", response_model=DashboardResponse)
async def get_dashboard(
    dashboard_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Get dashboard details by ID."""
    try:
        bi_engine = get_bi_engine(db)
        config = await bi_engine.get_dashboard(dashboard_id)
        
        if not config:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        
        # Check access permissions
        if not config.public and config.owner_id != current_user.id and current_user.id not in config.shared_with:
            raise HTTPException(status_code=403, detail="Access denied")
        
        return DashboardResponse(
            id=config.id,
            name=config.name,
            description=config.description,
            dashboard_type=config.dashboard_type,
            owner_id=config.owner_id,
            created_at=config.created_at,
            updated_at=config.updated_at,
            widget_count=len(config.widgets),
            is_public=config.public,
            enable_realtime=config.enable_realtime,
            theme=config.theme,
            tags=config.tags
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get dashboard {dashboard_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard: {str(e)}")


@router.put("/{dashboard_id}", response_model=DashboardResponse)
async def update_dashboard(
    dashboard_id: UUID,
    request: UpdateDashboardRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Update dashboard configuration."""
    try:
        bi_engine = get_bi_engine(db)
        
        # Check if dashboard exists and user has permission
        config = await bi_engine.get_dashboard(dashboard_id)
        if not config:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        
        if config.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only dashboard owner can update")
        
        # Prepare updates
        updates = {}
        if request.name is not None:
            updates["name"] = request.name
        if request.description is not None:
            updates["description"] = request.description
        if request.layout is not None:
            updates["layout"] = request.layout
        if request.theme is not None:
            updates["theme"] = request.theme
        if request.auto_refresh is not None:
            updates["auto_refresh"] = request.auto_refresh
        if request.refresh_interval is not None:
            updates["refresh_interval"] = request.refresh_interval
        if request.shared_with is not None:
            updates["shared_with"] = request.shared_with
        if request.public is not None:
            updates["public"] = request.public
        if request.enable_realtime is not None:
            updates["enable_realtime"] = request.enable_realtime
        if request.tags is not None:
            updates["tags"] = request.tags
        
        # Update dashboard
        updated_config = await bi_engine.update_dashboard(dashboard_id, updates)
        
        return DashboardResponse(
            id=updated_config.id,
            name=updated_config.name,
            description=updated_config.description,
            dashboard_type=updated_config.dashboard_type,
            owner_id=updated_config.owner_id,
            created_at=updated_config.created_at,
            updated_at=updated_config.updated_at,
            widget_count=len(updated_config.widgets),
            is_public=updated_config.public,
            enable_realtime=updated_config.enable_realtime,
            theme=updated_config.theme,
            tags=updated_config.tags
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update dashboard {dashboard_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update dashboard: {str(e)}")


@router.delete("/{dashboard_id}")
async def delete_dashboard(
    dashboard_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Delete a dashboard."""
    try:
        bi_engine = get_bi_engine(db)
        
        # Check if dashboard exists and user has permission
        config = await bi_engine.get_dashboard(dashboard_id)
        if not config:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        
        if config.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only dashboard owner can delete")
        
        # Delete dashboard
        success = await bi_engine.delete_dashboard(dashboard_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to delete dashboard")
        
        return {"message": "Dashboard deleted successfully", "dashboard_id": str(dashboard_id)}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete dashboard {dashboard_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete dashboard: {str(e)}")


# Dashboard Data Endpoints

@router.get("/{dashboard_id}/data", response_model=DashboardDataResponse)
async def get_dashboard_data(
    dashboard_id: UUID,
    force_refresh: bool = Query(False, description="Force refresh data from sources"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Get aggregated data for all widgets in a dashboard."""
    try:
        bi_engine = get_bi_engine(db)
        
        # Check access permissions
        config = await bi_engine.get_dashboard(dashboard_id)
        if not config:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        
        if not config.public and config.owner_id != current_user.id and current_user.id not in config.shared_with:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Get dashboard data
        data = await bi_engine.get_dashboard_data(dashboard_id, force_refresh=force_refresh)
        
        # Get dashboard metrics
        metrics = bi_engine.get_dashboard_metrics(dashboard_id)
        metrics_dict = {}
        if metrics:
            metrics_dict = {
                "total_widgets": metrics.total_widgets,
                "active_users": metrics.active_users,
                "avg_load_time_ms": metrics.avg_load_time_ms,
                "cache_hit_ratio": metrics.cache_hit_ratio,
                "last_updated": metrics.last_updated.isoformat()
            }
        
        return DashboardDataResponse(
            dashboard_id=dashboard_id,
            name=data.get("name", "Unknown"),
            last_updated=datetime.fromisoformat(data.get("last_updated", datetime.utcnow().isoformat())),
            widgets=data.get("widgets", {}),
            metrics=metrics_dict
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get dashboard data {dashboard_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")


@router.get("/{dashboard_id}/data/{widget_id}")
async def get_widget_data(
    dashboard_id: UUID,
    widget_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Get data for a specific widget."""
    try:
        bi_engine = get_bi_engine(db)
        
        # Check access permissions
        config = await bi_engine.get_dashboard(dashboard_id)
        if not config:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        
        if not config.public and config.owner_id != current_user.id and current_user.id not in config.shared_with:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Get real-time data for specific widget
        data = await bi_engine.get_realtime_data(dashboard_id, widget_id)
        
        return {
            "dashboard_id": str(dashboard_id),
            "widget_id": widget_id,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get widget data {dashboard_id}/{widget_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get widget data: {str(e)}")


# Visualization Endpoints

@router.post("/{dashboard_id}/visualize")
async def create_visualization(
    dashboard_id: UUID,
    chart_config: Dict[str, Any],
    output_format: str = Query("json", regex="^(json|html|svg|png)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Create visualization for dashboard data."""
    try:
        bi_engine = get_bi_engine(db)
        
        # Check access permissions
        config = await bi_engine.get_dashboard(dashboard_id)
        if not config:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        
        if not config.public and config.owner_id != current_user.id and current_user.id not in config.shared_with:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Get dashboard data
        dashboard_data = await bi_engine.get_dashboard_data(dashboard_id)
        
        # Create visualization engine
        viz_engine = VisualizationEngine()
        
        # Create visualization for entire dashboard
        visualization = await viz_engine.create_dashboard_visualization(
            widget_data=list(dashboard_data.get("widgets", {}).values()),
            layout_config=config.layout
        )
        
        return {
            "dashboard_id": str(dashboard_id),
            "visualization": visualization,
            "format": output_format,
            "created_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create visualization for {dashboard_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create visualization: {str(e)}")


# Real-time WebSocket Endpoints

@router.websocket("/{dashboard_id}/ws")
async def dashboard_websocket(
    websocket: WebSocket,
    dashboard_id: UUID,
    db: Session = Depends(get_db_session)
):
    """WebSocket endpoint for real-time dashboard updates."""
    await websocket.accept()
    
    connection_id = str(uuid4())
    logger.info(f"WebSocket connection opened: {connection_id} for dashboard {dashboard_id}")
    
    try:
        bi_engine = get_bi_engine(db)
        
        # Register connection
        registered = await bi_engine.register_realtime_connection(dashboard_id, connection_id)
        if not registered:
            await websocket.close(code=4004, reason="Dashboard not found")
            return
        
        # Send initial data
        try:
            initial_data = await bi_engine.get_dashboard_data(dashboard_id)
            await websocket.send_json({
                "type": "initial_data",
                "dashboard_id": str(dashboard_id),
                "data": initial_data,
                "timestamp": datetime.utcnow().isoformat()
            })
        except Exception as e:
            logger.error(f"Failed to send initial data: {e}")
        
        # Handle incoming messages
        while True:
            try:
                # Wait for message from client
                message = await websocket.receive_json()
                msg = WebSocketMessage(**message)
                
                if msg.type == "subscribe":
                    # Handle subscription to specific widget updates
                    if msg.widget_id:
                        widget_data = await bi_engine.get_realtime_data(dashboard_id, msg.widget_id)
                        await websocket.send_json({
                            "type": "widget_data",
                            "dashboard_id": str(dashboard_id),
                            "widget_id": msg.widget_id,
                            "data": widget_data,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                
                elif msg.type == "unsubscribe":
                    # Handle unsubscription
                    await websocket.send_json({
                        "type": "unsubscribed",
                        "dashboard_id": str(dashboard_id),
                        "widget_id": msg.widget_id,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                
                elif msg.type == "ping":
                    # Handle ping/pong for connection health
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"WebSocket message error: {e}")
                await websocket.send_json({
                    "type": "error",
                    "message": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                })
    
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: {connection_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        try:
            await websocket.close(code=4000, reason=str(e))
        except:
            pass
    finally:
        # Unregister connection
        try:
            await bi_engine.unregister_realtime_connection(dashboard_id, connection_id)
        except:
            pass


# Dashboard Analytics Endpoints

@router.get("/{dashboard_id}/analytics")
async def get_dashboard_analytics(
    dashboard_id: UUID,
    time_range_hours: int = Query(24, ge=1, le=168),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """Get analytics and usage statistics for a dashboard."""
    try:
        bi_engine = get_bi_engine(db)
        
        # Check access permissions
        config = await bi_engine.get_dashboard(dashboard_id)
        if not config:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        
        if config.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Get dashboard metrics
        metrics = bi_engine.get_dashboard_metrics(dashboard_id)
        global_metrics = bi_engine.get_global_metrics()
        
        analytics_data = {
            "dashboard_id": str(dashboard_id),
            "time_range_hours": time_range_hours,
            "dashboard_metrics": {
                "total_widgets": metrics.total_widgets if metrics else 0,
                "active_users": metrics.active_users if metrics else 0,
                "avg_load_time_ms": metrics.avg_load_time_ms if metrics else 0,
                "total_queries": metrics.total_queries if metrics else 0,
                "cache_hit_ratio": metrics.cache_hit_ratio if metrics else 0,
                "memory_usage_mb": metrics.memory_usage_mb if metrics else 0,
                "error_count": metrics.error_count if metrics else 0,
                "last_updated": metrics.last_updated.isoformat() if metrics else None
            },
            "global_metrics": global_metrics,
            "generated_at": datetime.utcnow().isoformat()
        }
        
        return analytics_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get dashboard analytics {dashboard_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard analytics: {str(e)}")


@router.get("/health")
async def dashboard_health():
    """Get dashboard system health status."""
    try:
        bi_engine = get_bi_engine()
        global_metrics = bi_engine.get_global_metrics()
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": global_metrics,
            "version": "1.0.0"
        }
        
    except Exception as e:
        logger.error(f"Dashboard health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }