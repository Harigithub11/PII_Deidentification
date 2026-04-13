"""
Component Monitoring API Endpoints

FastAPI router providing REST endpoints for component monitoring,
health checks, dependency analysis, and system status.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from fastapi import APIRouter, HTTPException, Depends, Query, Path, status
from pydantic import BaseModel, Field

from ..core.monitoring.component_monitor import get_component_monitor, ComponentMonitor
from ..core.monitoring.component_registry import ComponentType, ComponentStatus
from ..core.monitoring.component_health import HealthStatus
from ..core.monitoring.dependency_mapper import ImpactLevel, DependencyType
from ..core.security.auth import get_current_user, require_roles
from .models import APIResponse, PaginatedResponse

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(
    prefix="/api/v1/components",
    tags=["Component Monitoring"],
    responses={404: {"description": "Not found"}}
)


# Request/Response Models

class ComponentSummary(BaseModel):
    """Component summary information."""
    name: str = Field(..., description="Component name")
    component_type: str = Field(..., description="Component type")
    status: str = Field(..., description="Component status")
    health_status: Optional[str] = Field(None, description="Health status")
    description: str = Field(..., description="Component description")
    critical: bool = Field(False, description="Whether component is critical")
    dependencies_count: int = Field(0, description="Number of dependencies")
    dependents_count: int = Field(0, description="Number of dependents")
    last_health_check: Optional[datetime] = Field(None, description="Last health check timestamp")
    response_time_ms: Optional[float] = Field(None, description="Last response time")


class ComponentDetails(BaseModel):
    """Detailed component information."""
    component_name: str = Field(..., description="Component name")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Component metadata")
    health: Optional[Dict[str, Any]] = Field(None, description="Health information")
    dependencies: Optional[Dict[str, Any]] = Field(None, description="Dependency information")


class HealthCheckResult(BaseModel):
    """Health check result."""
    component_name: str = Field(..., description="Component name")
    status: str = Field(..., description="Health status")
    response_time_ms: float = Field(..., description="Response time in milliseconds")
    message: str = Field("", description="Health check message")
    timestamp: datetime = Field(..., description="Check timestamp")
    error_details: Optional[str] = Field(None, description="Error details if unhealthy")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class SystemHealthSummary(BaseModel):
    """System health summary."""
    status: str = Field(..., description="Overall system health status")
    total_components: int = Field(..., description="Total number of components")
    healthy_count: int = Field(..., description="Number of healthy components")
    degraded_count: int = Field(..., description="Number of degraded components") 
    unhealthy_count: int = Field(..., description="Number of unhealthy components")
    last_check: str = Field(..., description="Last check timestamp")
    components: Dict[str, Dict[str, Any]] = Field(..., description="Individual component statuses")


class DependencyImpactAnalysis(BaseModel):
    """Dependency impact analysis result."""
    component: str = Field(..., description="Component being analyzed")
    impacts: List[Dict[str, Any]] = Field(..., description="Impact analysis results")


class SystemStatusResponse(BaseModel):
    """System status response."""
    monitor_running: bool = Field(..., description="Whether monitor is running")
    last_health_check: Optional[str] = Field(None, description="Last health check timestamp")
    last_dependency_analysis: Optional[str] = Field(None, description="Last dependency analysis timestamp")
    last_critical_path_analysis: Optional[str] = Field(None, description="Last critical path analysis timestamp")
    registry: Optional[Dict[str, Any]] = Field(None, description="Registry statistics")
    health: Optional[Dict[str, Any]] = Field(None, description="Health summary")
    dependencies: Optional[Dict[str, Any]] = Field(None, description="Dependency graph statistics")


class ComponentListFilters(BaseModel):
    """Component list filtering parameters."""
    component_type: Optional[ComponentType] = Field(None, description="Filter by component type")
    status: Optional[ComponentStatus] = Field(None, description="Filter by component status")
    health_status: Optional[HealthStatus] = Field(None, description="Filter by health status")
    critical_only: bool = Field(False, description="Show only critical components")
    unhealthy_only: bool = Field(False, description="Show only unhealthy components")


# Dependency functions
async def get_monitor() -> ComponentMonitor:
    """Get component monitor instance."""
    return get_component_monitor()


# API Endpoints

@router.get("/", response_model=APIResponse[List[ComponentSummary]], summary="List all components")
async def list_components(
    component_type: Optional[ComponentType] = Query(None, description="Filter by component type"),
    status: Optional[ComponentStatus] = Query(None, description="Filter by component status"),
    health_status: Optional[HealthStatus] = Query(None, description="Filter by health status"),
    critical_only: bool = Query(False, description="Show only critical components"),
    unhealthy_only: bool = Query(False, description="Show only unhealthy components"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Results offset"),
    monitor: ComponentMonitor = Depends(get_monitor),
    current_user = Depends(get_current_user)
) -> APIResponse[List[ComponentSummary]]:
    """
    List all registered components with optional filtering.
    
    Requires authentication.
    """
    try:
        if not monitor.registry:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Component registry not initialized"
            )
        
        # Get components from registry
        components = monitor.registry.list_components(
            component_type=component_type,
            status=status,
            critical_only=critical_only
        )
        
        # Get health data
        health_results = monitor.health_manager.get_all_health_results() if monitor.health_manager else {}
        
        # Filter by health status
        if health_status or unhealthy_only:
            filtered_components = []
            for comp in components:
                health_result = health_results.get(comp.name)
                if not health_result:
                    continue
                
                if health_status and health_result.status != health_status:
                    continue
                    
                if unhealthy_only and health_result.status == HealthStatus.HEALTHY:
                    continue
                
                filtered_components.append(comp)
            
            components = filtered_components
        
        # Apply pagination
        total = len(components)
        components = components[offset:offset + limit]
        
        # Convert to response format
        component_summaries = []
        for comp in components:
            health_result = health_results.get(comp.name)
            
            # Get dependency counts
            dependencies_count = len(monitor.dependency_graph.get_dependencies(comp.name)) if monitor.dependency_graph else 0
            dependents_count = len(monitor.dependency_graph.get_reverse_dependencies(comp.name)) if monitor.dependency_graph else 0
            
            summary = ComponentSummary(
                name=comp.name,
                component_type=comp.component_type.value,
                status=comp.status.value,
                health_status=health_result.status.value if health_result else None,
                description=comp.description,
                critical=comp.critical,
                dependencies_count=dependencies_count,
                dependents_count=dependents_count,
                last_health_check=health_result.timestamp if health_result else None,
                response_time_ms=health_result.response_time_ms if health_result else None
            )
            component_summaries.append(summary)
        
        return APIResponse(
            success=True,
            data=component_summaries,
            message=f"Found {len(component_summaries)} components (total: {total})"
        )
        
    except Exception as e:
        logger.error(f"Error listing components: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list components: {str(e)}"
        )


@router.get("/{component_name}", response_model=APIResponse[ComponentDetails], summary="Get component details")
async def get_component(
    component_name: str = Path(..., description="Component name"),
    monitor: ComponentMonitor = Depends(get_monitor),
    current_user = Depends(get_current_user)
) -> APIResponse[ComponentDetails]:
    """
    Get detailed information about a specific component.
    
    Requires authentication.
    """
    try:
        details = await monitor.get_component_details(component_name)
        
        if "error" in details:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Component '{component_name}' not found"
            )
        
        return APIResponse(
            success=True,
            data=ComponentDetails(**details),
            message=f"Component details for '{component_name}'"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting component details for {component_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get component details: {str(e)}"
        )


@router.get("/{component_name}/health", response_model=APIResponse[HealthCheckResult], summary="Get component health")
async def get_component_health(
    component_name: str = Path(..., description="Component name"),
    force_check: bool = Query(False, description="Force a new health check"),
    monitor: ComponentMonitor = Depends(get_monitor),
    current_user = Depends(get_current_user)
) -> APIResponse[HealthCheckResult]:
    """
    Get health status of a specific component.
    
    Requires authentication.
    """
    try:
        if force_check:
            # Force a new health check
            check_result = await monitor.force_health_check(component_name)
            if "error" in check_result:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=check_result["error"]
                )
            
            result = check_result["result"]
            if not result:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Component '{component_name}' not found"
                )
        else:
            # Get last health check result
            if not monitor.health_manager:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Health manager not initialized"
                )
            
            result = monitor.health_manager.get_health_result(component_name)
            if not result:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No health data available for component '{component_name}'"
                )
            
            result = result.__dict__
        
        health_result = HealthCheckResult(
            component_name=result["component_name"],
            status=result["status"],
            response_time_ms=result["response_time_ms"],
            message=result["message"],
            timestamp=result["timestamp"] if isinstance(result["timestamp"], datetime) else datetime.fromisoformat(result["timestamp"]),
            error_details=result.get("error_details"),
            metadata=result.get("metadata", {})
        )
        
        return APIResponse(
            success=True,
            data=health_result,
            message=f"Health status for '{component_name}'"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting component health for {component_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get component health: {str(e)}"
        )


@router.post("/{component_name}/health/check", response_model=APIResponse[HealthCheckResult], summary="Force health check")
async def force_component_health_check(
    component_name: str = Path(..., description="Component name"),
    monitor: ComponentMonitor = Depends(get_monitor),
    current_user = Depends(get_current_user)
) -> APIResponse[HealthCheckResult]:
    """
    Force a health check on a specific component.
    
    Requires authentication.
    """
    try:
        check_result = await monitor.force_health_check(component_name)
        
        if "error" in check_result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=check_result["error"]
            )
        
        result = check_result["result"]
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Component '{component_name}' not found"
            )
        
        health_result = HealthCheckResult(
            component_name=result["component_name"],
            status=result["status"],
            response_time_ms=result["response_time_ms"],
            message=result["message"],
            timestamp=result["timestamp"],
            error_details=result.get("error_details"),
            metadata=result.get("metadata", {})
        )
        
        return APIResponse(
            success=True,
            data=health_result,
            message=f"Forced health check completed for '{component_name}'"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error forcing health check for {component_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to force health check: {str(e)}"
        )


@router.get("/health/summary", response_model=APIResponse[SystemHealthSummary], summary="Get system health summary")
async def get_system_health_summary(
    monitor: ComponentMonitor = Depends(get_monitor),
    current_user = Depends(get_current_user)
) -> APIResponse[SystemHealthSummary]:
    """
    Get overall system health summary.
    
    Requires authentication.
    """
    try:
        if not monitor.health_manager:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Health manager not initialized"
            )
        
        health_summary = monitor.health_manager.get_health_summary()
        
        summary = SystemHealthSummary(
            status=health_summary["status"],
            total_components=health_summary["total_components"],
            healthy_count=health_summary["healthy_count"],
            degraded_count=health_summary["degraded_count"],
            unhealthy_count=health_summary["unhealthy_count"],
            last_check=health_summary["last_check"],
            components=health_summary["components"]
        )
        
        return APIResponse(
            success=True,
            data=summary,
            message="System health summary"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting system health summary: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get system health summary: {str(e)}"
        )


@router.post("/health/check-all", response_model=APIResponse[Dict[str, Any]], summary="Force health check on all components")
async def force_all_health_checks(
    monitor: ComponentMonitor = Depends(get_monitor),
    current_user = Depends(require_roles(["admin", "system_monitor"]))
) -> APIResponse[Dict[str, Any]]:
    """
    Force health checks on all components.
    
    Requires admin or system_monitor role.
    """
    try:
        check_results = await monitor.force_health_check()
        
        if "error" in check_results:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=check_results["error"]
            )
        
        # Convert results to response format
        results = {}
        for comp_name, result in check_results["results"].items():
            results[comp_name] = {
                "status": result["status"],
                "response_time_ms": result["response_time_ms"],
                "message": result["message"],
                "timestamp": result["timestamp"].isoformat() if isinstance(result["timestamp"], datetime) else result["timestamp"]
            }
        
        return APIResponse(
            success=True,
            data={"results": results, "total_checked": len(results)},
            message=f"Forced health check completed on {len(results)} components"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error forcing all health checks: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to force health checks: {str(e)}"
        )


@router.get("/{component_name}/dependencies", response_model=APIResponse[Dict[str, Any]], summary="Get component dependencies")
async def get_component_dependencies(
    component_name: str = Path(..., description="Component name"),
    include_transitive: bool = Query(False, description="Include transitive dependencies"),
    monitor: ComponentMonitor = Depends(get_monitor),
    current_user = Depends(get_current_user)
) -> APIResponse[Dict[str, Any]]:
    """
    Get dependencies for a specific component.
    
    Requires authentication.
    """
    try:
        if not monitor.dependency_graph:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Dependency graph not initialized"
            )
        
        dependencies = monitor.dependency_graph.get_dependencies(component_name, include_transitive)
        reverse_dependencies = monitor.dependency_graph.get_reverse_dependencies(component_name, include_transitive)
        criticality_score = monitor.dependency_graph.get_component_criticality_score(component_name)
        
        dependency_chains = []
        if dependencies:
            # Get dependency chains for each dependency
            for dep in list(dependencies)[:5]:  # Limit to first 5 to avoid too much data
                chains = monitor.dependency_graph.find_dependency_chains(component_name, dep)
                if chains:
                    dependency_chains.append({
                        "target": dep,
                        "chains": chains[:3]  # Limit to 3 chains per dependency
                    })
        
        result = {
            "component_name": component_name,
            "dependencies": list(dependencies),
            "reverse_dependencies": list(reverse_dependencies),
            "criticality_score": criticality_score,
            "dependency_chains": dependency_chains,
            "include_transitive": include_transitive,
            "dependencies_count": len(dependencies),
            "reverse_dependencies_count": len(reverse_dependencies)
        }
        
        return APIResponse(
            success=True,
            data=result,
            message=f"Dependencies for component '{component_name}'"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting dependencies for {component_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get component dependencies: {str(e)}"
        )


@router.get("/{component_name}/impact-analysis", response_model=APIResponse[DependencyImpactAnalysis], summary="Analyze component failure impact")
async def analyze_component_impact(
    component_name: str = Path(..., description="Component name"),
    monitor: ComponentMonitor = Depends(get_monitor),
    current_user = Depends(get_current_user)
) -> APIResponse[DependencyImpactAnalysis]:
    """
    Analyze the impact if a component fails.
    
    Requires authentication.
    """
    try:
        impact_analysis = await monitor.analyze_component_impact(component_name)
        
        if "error" in impact_analysis:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=impact_analysis["error"]
            )
        
        analysis = DependencyImpactAnalysis(
            component=impact_analysis["component"],
            impacts=impact_analysis["impacts"]
        )
        
        return APIResponse(
            success=True,
            data=analysis,
            message=f"Impact analysis for component '{component_name}'"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error analyzing impact for {component_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze component impact: {str(e)}"
        )


@router.get("/topology/graph", response_model=APIResponse[Dict[str, Any]], summary="Get dependency topology")
async def get_dependency_topology(
    include_health_status: bool = Query(True, description="Include current health status"),
    format: str = Query("nodes_edges", description="Response format: 'nodes_edges' or 'adjacency'"),
    monitor: ComponentMonitor = Depends(get_monitor),
    current_user = Depends(get_current_user)
) -> APIResponse[Dict[str, Any]]:
    """
    Get dependency topology/graph for visualization.
    
    Requires authentication.
    """
    try:
        if not monitor.dependency_graph:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Dependency graph not initialized"
            )
        
        # Get all components
        components = monitor.registry.list_components() if monitor.registry else []
        health_results = monitor.health_manager.get_all_health_results() if monitor.health_manager else {}
        
        # Build nodes
        nodes = []
        for comp in components:
            node = {
                "id": comp.name,
                "name": comp.name,
                "type": comp.component_type.value,
                "critical": comp.critical,
                "status": comp.status.value,
                "description": comp.description
            }
            
            if include_health_status and comp.name in health_results:
                health = health_results[comp.name]
                node["health_status"] = health.status.value
                node["response_time_ms"] = health.response_time_ms
            
            # Add criticality score
            node["criticality_score"] = monitor.dependency_graph.get_component_criticality_score(comp.name)
            
            nodes.append(node)
        
        # Build edges
        edges = []
        graph = monitor.dependency_graph._graph
        
        for source, target, edge_data in graph.edges(data=True):
            edge = {
                "source": source,
                "target": target,
                "dependency_type": edge_data.get("dependency_type", "hard"),
                "weight": edge_data.get("weight", 1.0),
                "description": edge_data.get("description", "")
            }
            edges.append(edge)
        
        # Get graph statistics
        stats = monitor.dependency_graph.get_graph_statistics()
        
        if format == "adjacency":
            # Convert to adjacency list format
            adjacency = {}
            for node in nodes:
                adjacency[node["id"]] = []
            
            for edge in edges:
                adjacency[edge["source"]].append({
                    "target": edge["target"],
                    "type": edge["dependency_type"],
                    "weight": edge["weight"]
                })
            
            result = {
                "format": "adjacency",
                "adjacency_list": adjacency,
                "nodes_metadata": {node["id"]: {k: v for k, v in node.items() if k != "id"} for node in nodes},
                "statistics": stats
            }
        else:
            # Default nodes and edges format
            result = {
                "format": "nodes_edges",
                "nodes": nodes,
                "edges": edges,
                "statistics": stats
            }
        
        return APIResponse(
            success=True,
            data=result,
            message=f"Dependency topology with {len(nodes)} nodes and {len(edges)} edges"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting dependency topology: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get dependency topology: {str(e)}"
        )


@router.get("/system/status", response_model=APIResponse[SystemStatusResponse], summary="Get system status")
async def get_system_status(
    monitor: ComponentMonitor = Depends(get_monitor),
    current_user = Depends(get_current_user)
) -> APIResponse[SystemStatusResponse]:
    """
    Get overall system monitoring status.
    
    Requires authentication.
    """
    try:
        system_status = await monitor.get_system_status()
        
        status_response = SystemStatusResponse(
            monitor_running=system_status["monitor_running"],
            last_health_check=system_status.get("last_health_check"),
            last_dependency_analysis=system_status.get("last_dependency_analysis"),
            last_critical_path_analysis=system_status.get("last_critical_path_analysis"),
            registry=system_status.get("registry"),
            health=system_status.get("health"),
            dependencies=system_status.get("dependencies")
        )
        
        return APIResponse(
            success=True,
            data=status_response,
            message="System monitoring status"
        )
        
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get system status: {str(e)}"
        )


@router.get("/system/critical-paths", response_model=APIResponse[Dict[str, Any]], summary="Get critical paths analysis")
async def get_critical_paths(
    monitor: ComponentMonitor = Depends(get_monitor),
    current_user = Depends(require_roles(["admin", "system_monitor"]))
) -> APIResponse[Dict[str, Any]]:
    """
    Get critical paths analysis and bottleneck information.
    
    Requires admin or system_monitor role.
    """
    try:
        if not monitor.critical_path_finder:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Critical path finder not initialized"
            )
        
        # Get critical paths
        critical_paths = monitor.critical_path_finder.find_critical_paths(max_paths=20)
        
        # Get bottleneck analysis
        bottleneck_analysis = monitor.critical_path_finder.get_bottleneck_analysis()
        
        # Format critical paths
        paths_data = []
        for path in critical_paths:
            paths_data.append({
                "path": path.path,
                "components_count": path.components_count,
                "total_weight": path.total_weight,
                "risk_score": path.risk_score,
                "description": path.description,
                "bottlenecks": path.bottlenecks
            })
        
        result = {
            "critical_paths": paths_data,
            "bottleneck_analysis": bottleneck_analysis,
            "analysis_summary": {
                "total_paths": len(paths_data),
                "highest_risk_score": max((p.risk_score for p in critical_paths), default=0),
                "total_bottlenecks": len(set().union(*[p.bottlenecks for p in critical_paths]))
            }
        }
        
        return APIResponse(
            success=True,
            data=result,
            message=f"Critical paths analysis: {len(critical_paths)} paths found"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting critical paths: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get critical paths: {str(e)}"
        )