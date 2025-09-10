"""
Component Monitoring Dashboard Integration

Provides dashboard widgets and visualizations for component monitoring,
integrating with the existing Business Intelligence Engine.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field

from .bi_engine import BusinessIntelligenceEngine, get_bi_engine, DashboardWidget, WidgetType, ChartType
from ..monitoring.component_monitor import get_component_monitor
from ..monitoring.component_health import HealthStatus
from ..monitoring.dependency_mapper import ImpactLevel

logger = logging.getLogger(__name__)


@dataclass 
class ComponentDashboardConfig:
    """Configuration for component dashboard."""
    refresh_interval_seconds: int = 30
    max_components_in_overview: int = 50
    max_critical_paths_displayed: int = 10
    health_history_hours: int = 24
    enable_real_time_updates: bool = True


class ComponentDashboard:
    """Component monitoring dashboard manager."""
    
    def __init__(self, bi_engine: Optional[BusinessIntelligenceEngine] = None, config: Optional[ComponentDashboardConfig] = None):
        self.bi_engine = bi_engine or get_bi_engine()
        self.config = config or ComponentDashboardConfig()
        self.component_monitor = get_component_monitor()
        self._dashboard_id: Optional[str] = None
        self._widgets: Dict[str, str] = {}  # widget_name -> widget_id mapping
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the component monitoring dashboard."""
        if self._initialized:
            return
        
        logger.info("Initializing Component Monitoring Dashboard...")
        
        try:
            # Create main dashboard
            dashboard_config = {
                "title": "Component Monitoring Dashboard",
                "description": "Real-time monitoring of system components, health status, and dependencies",
                "category": "System Monitoring",
                "refresh_interval": self.config.refresh_interval_seconds,
                "auto_refresh": True,
                "layout": "grid",
                "columns": 4,
                "theme": "dark"
            }
            
            self._dashboard_id = await self.bi_engine.create_dashboard("component_monitoring", dashboard_config)
            
            # Create dashboard widgets
            await self._create_dashboard_widgets()
            
            self._initialized = True
            logger.info(f"Component Monitoring Dashboard initialized: {self._dashboard_id}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Component Monitoring Dashboard: {e}")
            raise
    
    async def _create_dashboard_widgets(self) -> None:
        """Create all dashboard widgets."""
        widgets_to_create = [
            # Overview widgets
            ("system_health_overview", self._create_system_health_overview_widget),
            ("component_counts", self._create_component_counts_widget),
            ("health_distribution", self._create_health_distribution_widget),
            ("response_times", self._create_response_times_widget),
            
            # Detailed monitoring widgets
            ("unhealthy_components", self._create_unhealthy_components_widget),
            ("component_dependencies", self._create_component_dependencies_widget),
            ("critical_paths", self._create_critical_paths_widget),
            ("bottlenecks", self._create_bottlenecks_widget),
            
            # Performance widgets
            ("health_trends", self._create_health_trends_widget),
            ("performance_metrics", self._create_performance_metrics_widget),
            ("dependency_impact", self._create_dependency_impact_widget),
            ("component_topology", self._create_component_topology_widget),
        ]
        
        for widget_name, create_func in widgets_to_create:
            try:
                widget_id = await create_func()
                self._widgets[widget_name] = widget_id
                
                # Add widget to dashboard
                await self.bi_engine.add_widget_to_dashboard(
                    self._dashboard_id,
                    widget_id,
                    position={"row": len(self._widgets) // 4, "col": len(self._widgets) % 4}
                )
                
                logger.debug(f"Created widget: {widget_name} ({widget_id})")
                
            except Exception as e:
                logger.error(f"Failed to create widget {widget_name}: {e}")
    
    async def _create_system_health_overview_widget(self) -> str:
        """Create system health overview widget."""
        widget_config = {
            "title": "System Health Overview",
            "description": "Overall system health status and key metrics",
            "widget_type": WidgetType.METRIC_CARD,
            "size": {"width": 2, "height": 1},
            "data_source": self._get_system_health_data,
            "refresh_interval": 30,
            "color_scheme": "health_status"
        }
        
        return await self.bi_engine.create_widget("system_health_overview", widget_config)
    
    async def _create_component_counts_widget(self) -> str:
        """Create component counts widget."""
        widget_config = {
            "title": "Component Counts by Type",
            "description": "Number of components by type",
            "widget_type": WidgetType.CHART,
            "chart_type": ChartType.BAR_CHART,
            "size": {"width": 2, "height": 1},
            "data_source": self._get_component_counts_data,
            "refresh_interval": 60
        }
        
        return await self.bi_engine.create_widget("component_counts", widget_config)
    
    async def _create_health_distribution_widget(self) -> str:
        """Create health distribution widget."""
        widget_config = {
            "title": "Health Status Distribution",
            "description": "Distribution of component health statuses",
            "widget_type": WidgetType.CHART,
            "chart_type": ChartType.PIE_CHART,
            "size": {"width": 2, "height": 1},
            "data_source": self._get_health_distribution_data,
            "refresh_interval": 30,
            "color_mapping": {
                "healthy": "#28a745",
                "degraded": "#ffc107", 
                "unhealthy": "#dc3545",
                "unknown": "#6c757d"
            }
        }
        
        return await self.bi_engine.create_widget("health_distribution", widget_config)
    
    async def _create_response_times_widget(self) -> str:
        """Create response times widget."""
        widget_config = {
            "title": "Average Response Times",
            "description": "Average response times by component type",
            "widget_type": WidgetType.CHART,
            "chart_type": ChartType.BAR_CHART,
            "size": {"width": 2, "height": 1},
            "data_source": self._get_response_times_data,
            "refresh_interval": 60,
            "y_axis_label": "Response Time (ms)"
        }
        
        return await self.bi_engine.create_widget("response_times", widget_config)
    
    async def _create_unhealthy_components_widget(self) -> str:
        """Create unhealthy components list widget."""
        widget_config = {
            "title": "Unhealthy Components",
            "description": "Components currently in unhealthy or degraded state",
            "widget_type": WidgetType.TABLE,
            "size": {"width": 4, "height": 2},
            "data_source": self._get_unhealthy_components_data,
            "refresh_interval": 30,
            "columns": [
                {"name": "Component", "field": "name", "sortable": True},
                {"name": "Type", "field": "type", "sortable": True},
                {"name": "Status", "field": "health_status", "sortable": True, "color_by_value": True},
                {"name": "Response Time", "field": "response_time", "sortable": True, "format": "number"},
                {"name": "Last Check", "field": "last_check", "format": "datetime"},
                {"name": "Message", "field": "message"}
            ]
        }
        
        return await self.bi_engine.create_widget("unhealthy_components", widget_config)
    
    async def _create_component_dependencies_widget(self) -> str:
        """Create component dependencies widget."""
        widget_config = {
            "title": "Component Dependencies",
            "description": "Top components by dependency count",
            "widget_type": WidgetType.CHART,
            "chart_type": ChartType.HORIZONTAL_BAR_CHART,
            "size": {"width": 2, "height": 2},
            "data_source": self._get_component_dependencies_data,
            "refresh_interval": 300,  # 5 minutes
            "x_axis_label": "Number of Dependencies"
        }
        
        return await self.bi_engine.create_widget("component_dependencies", widget_config)
    
    async def _create_critical_paths_widget(self) -> str:
        """Create critical paths widget."""
        widget_config = {
            "title": "Critical Paths",
            "description": "Most critical dependency paths in the system",
            "widget_type": WidgetType.TABLE,
            "size": {"width": 4, "height": 2},
            "data_source": self._get_critical_paths_data,
            "refresh_interval": 600,  # 10 minutes
            "columns": [
                {"name": "Path", "field": "path_display", "width": "40%"},
                {"name": "Components", "field": "components_count", "sortable": True, "format": "number"},
                {"name": "Risk Score", "field": "risk_score", "sortable": True, "format": "percentage"},
                {"name": "Total Weight", "field": "total_weight", "sortable": True, "format": "number"},
                {"name": "Bottlenecks", "field": "bottlenecks_display", "width": "30%"}
            ]
        }
        
        return await self.bi_engine.create_widget("critical_paths", widget_config)
    
    async def _create_bottlenecks_widget(self) -> str:
        """Create bottlenecks widget."""
        widget_config = {
            "title": "System Bottlenecks",
            "description": "Components that are bottlenecks in critical paths",
            "widget_type": WidgetType.CHART,
            "chart_type": ChartType.HORIZONTAL_BAR_CHART,
            "size": {"width": 2, "height": 2},
            "data_source": self._get_bottlenecks_data,
            "refresh_interval": 600,  # 10 minutes
            "x_axis_label": "Risk Score"
        }
        
        return await self.bi_engine.create_widget("bottlenecks", widget_config)
    
    async def _create_health_trends_widget(self) -> str:
        """Create health trends over time widget."""
        widget_config = {
            "title": "Health Trends (24h)",
            "description": "Component health trends over the last 24 hours",
            "widget_type": WidgetType.CHART,
            "chart_type": ChartType.LINE_CHART,
            "size": {"width": 4, "height": 2},
            "data_source": self._get_health_trends_data,
            "refresh_interval": 300,  # 5 minutes
            "y_axis_label": "Number of Components",
            "x_axis_label": "Time"
        }
        
        return await self.bi_engine.create_widget("health_trends", widget_config)
    
    async def _create_performance_metrics_widget(self) -> str:
        """Create performance metrics widget."""
        widget_config = {
            "title": "Performance Metrics",
            "description": "Key performance indicators for component monitoring",
            "widget_type": WidgetType.METRIC_GRID,
            "size": {"width": 2, "height": 1},
            "data_source": self._get_performance_metrics_data,
            "refresh_interval": 60,
            "metrics": [
                {"name": "Avg Response Time", "field": "avg_response_time", "format": "number", "unit": "ms"},
                {"name": "Health Check Success Rate", "field": "health_check_success_rate", "format": "percentage"},
                {"name": "Components Online", "field": "components_online_percentage", "format": "percentage"},
                {"name": "Critical Components Healthy", "field": "critical_components_healthy", "format": "percentage"}
            ]
        }
        
        return await self.bi_engine.create_widget("performance_metrics", widget_config)
    
    async def _create_dependency_impact_widget(self) -> str:
        """Create dependency impact analysis widget."""
        widget_config = {
            "title": "Dependency Impact Analysis",
            "description": "Potential impact of component failures",
            "widget_type": WidgetType.HEATMAP,
            "size": {"width": 4, "height": 2},
            "data_source": self._get_dependency_impact_data,
            "refresh_interval": 600,  # 10 minutes
            "color_scale": "risk_level"
        }
        
        return await self.bi_engine.create_widget("dependency_impact", widget_config)
    
    async def _create_component_topology_widget(self) -> str:
        """Create component topology visualization widget."""
        widget_config = {
            "title": "Component Topology",
            "description": "Interactive component dependency graph",
            "widget_type": WidgetType.NETWORK_GRAPH,
            "size": {"width": 4, "height": 3},
            "data_source": self._get_component_topology_data,
            "refresh_interval": 300,  # 5 minutes
            "node_color_by": "health_status",
            "edge_width_by": "dependency_weight",
            "layout": "force_directed",
            "interactive": True
        }
        
        return await self.bi_engine.create_widget("component_topology", widget_config)
    
    # Data source methods
    
    async def _get_system_health_data(self) -> Dict[str, Any]:
        """Get system health overview data."""
        try:
            if not self.component_monitor.health_manager:
                return {"error": "Health manager not available"}
            
            health_summary = self.component_monitor.health_manager.get_health_summary()
            
            return {
                "overall_status": health_summary.get("status", "unknown"),
                "total_components": health_summary.get("total_components", 0),
                "healthy_percentage": (health_summary.get("healthy_count", 0) / max(health_summary.get("total_components", 1), 1)) * 100,
                "last_check": health_summary.get("last_check", datetime.utcnow().isoformat()),
                "status_counts": {
                    "healthy": health_summary.get("healthy_count", 0),
                    "degraded": health_summary.get("degraded_count", 0),
                    "unhealthy": health_summary.get("unhealthy_count", 0)
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting system health data: {e}")
            return {"error": str(e)}
    
    async def _get_component_counts_data(self) -> Dict[str, Any]:
        """Get component counts by type data."""
        try:
            if not self.component_monitor.registry:
                return {"error": "Component registry not available"}
            
            stats = self.component_monitor.registry.get_statistics()
            
            chart_data = []
            for comp_type, count in stats.get("by_type", {}).items():
                chart_data.append({
                    "category": comp_type.replace("_", " ").title(),
                    "value": count
                })
            
            return {
                "chart_data": chart_data,
                "total_components": stats.get("total_components", 0)
            }
            
        except Exception as e:
            logger.error(f"Error getting component counts data: {e}")
            return {"error": str(e)}
    
    async def _get_health_distribution_data(self) -> Dict[str, Any]:
        """Get health status distribution data."""
        try:
            if not self.component_monitor.health_manager:
                return {"error": "Health manager not available"}
            
            health_summary = self.component_monitor.health_manager.get_health_summary()
            
            chart_data = [
                {"label": "Healthy", "value": health_summary.get("healthy_count", 0), "color": "#28a745"},
                {"label": "Degraded", "value": health_summary.get("degraded_count", 0), "color": "#ffc107"},
                {"label": "Unhealthy", "value": health_summary.get("unhealthy_count", 0), "color": "#dc3545"}
            ]
            
            # Remove zero values
            chart_data = [item for item in chart_data if item["value"] > 0]
            
            return {
                "chart_data": chart_data,
                "total": health_summary.get("total_components", 0)
            }
            
        except Exception as e:
            logger.error(f"Error getting health distribution data: {e}")
            return {"error": str(e)}
    
    async def _get_response_times_data(self) -> Dict[str, Any]:
        """Get average response times by component type."""
        try:
            if not self.component_monitor.health_manager or not self.component_monitor.registry:
                return {"error": "Required managers not available"}
            
            health_results = self.component_monitor.health_manager.get_all_health_results()
            components = self.component_monitor.registry.list_components()
            
            # Group response times by component type
            type_response_times = {}
            for comp in components:
                health_result = health_results.get(comp.name)
                if health_result and health_result.response_time_ms > 0:
                    comp_type = comp.component_type.value
                    if comp_type not in type_response_times:
                        type_response_times[comp_type] = []
                    type_response_times[comp_type].append(health_result.response_time_ms)
            
            # Calculate averages
            chart_data = []
            for comp_type, response_times in type_response_times.items():
                avg_response_time = sum(response_times) / len(response_times)
                chart_data.append({
                    "category": comp_type.replace("_", " ").title(),
                    "value": round(avg_response_time, 2)
                })
            
            return {"chart_data": chart_data}
            
        except Exception as e:
            logger.error(f"Error getting response times data: {e}")
            return {"error": str(e)}
    
    async def _get_unhealthy_components_data(self) -> Dict[str, Any]:
        """Get unhealthy components data."""
        try:
            if not self.component_monitor.health_manager or not self.component_monitor.registry:
                return {"error": "Required managers not available"}
            
            health_results = self.component_monitor.health_manager.get_all_health_results()
            components = self.component_monitor.registry.list_components()
            
            unhealthy_data = []
            for comp in components:
                health_result = health_results.get(comp.name)
                if health_result and health_result.status in [HealthStatus.UNHEALTHY, HealthStatus.DEGRADED]:
                    unhealthy_data.append({
                        "name": comp.name,
                        "type": comp.component_type.value.replace("_", " ").title(),
                        "health_status": health_result.status.value,
                        "response_time": f"{health_result.response_time_ms:.1f} ms",
                        "last_check": health_result.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        "message": health_result.message[:100] + "..." if len(health_result.message) > 100 else health_result.message
                    })
            
            return {
                "table_data": unhealthy_data,
                "total_unhealthy": len(unhealthy_data)
            }
            
        except Exception as e:
            logger.error(f"Error getting unhealthy components data: {e}")
            return {"error": str(e)}
    
    async def _get_component_dependencies_data(self) -> Dict[str, Any]:
        """Get component dependencies data."""
        try:
            if not self.component_monitor.dependency_graph or not self.component_monitor.registry:
                return {"error": "Required managers not available"}
            
            components = self.component_monitor.registry.list_components()
            
            dependency_data = []
            for comp in components[:20]:  # Limit to top 20
                dependencies_count = len(self.component_monitor.dependency_graph.get_dependencies(comp.name))
                dependents_count = len(self.component_monitor.dependency_graph.get_reverse_dependencies(comp.name))
                
                if dependencies_count > 0 or dependents_count > 0:
                    dependency_data.append({
                        "component": comp.name.split(".")[-1],  # Show only the class name
                        "dependencies": dependencies_count,
                        "dependents": dependents_count,
                        "total": dependencies_count + dependents_count
                    })
            
            # Sort by total dependencies
            dependency_data.sort(key=lambda x: x["total"], reverse=True)
            dependency_data = dependency_data[:15]  # Top 15
            
            chart_data = [
                {"category": item["component"], "value": item["total"]}
                for item in dependency_data
            ]
            
            return {"chart_data": chart_data}
            
        except Exception as e:
            logger.error(f"Error getting component dependencies data: {e}")
            return {"error": str(e)}
    
    async def _get_critical_paths_data(self) -> Dict[str, Any]:
        """Get critical paths data."""
        try:
            if not self.component_monitor.critical_path_finder:
                return {"error": "Critical path finder not available"}
            
            critical_paths = self.component_monitor.critical_path_finder.find_critical_paths(
                max_paths=self.config.max_critical_paths_displayed
            )
            
            table_data = []
            for path in critical_paths:
                # Simplify path display
                path_display = " → ".join([comp.split(".")[-1] for comp in path.path])
                if len(path_display) > 60:
                    path_display = path_display[:57] + "..."
                
                bottlenecks_display = ", ".join([comp.split(".")[-1] for comp in path.bottlenecks[:3]])
                if len(path.bottlenecks) > 3:
                    bottlenecks_display += f" (+{len(path.bottlenecks) - 3} more)"
                
                table_data.append({
                    "path_display": path_display,
                    "components_count": path.components_count,
                    "risk_score": f"{path.risk_score:.2%}",
                    "total_weight": round(path.total_weight, 2),
                    "bottlenecks_display": bottlenecks_display
                })
            
            return {
                "table_data": table_data,
                "total_paths": len(critical_paths)
            }
            
        except Exception as e:
            logger.error(f"Error getting critical paths data: {e}")
            return {"error": str(e)}
    
    async def _get_bottlenecks_data(self) -> Dict[str, Any]:
        """Get system bottlenecks data."""
        try:
            if not self.component_monitor.critical_path_finder:
                return {"error": "Critical path finder not available"}
            
            bottleneck_analysis = self.component_monitor.critical_path_finder.get_bottleneck_analysis()
            
            chart_data = []
            for bottleneck in bottleneck_analysis.get("top_bottlenecks", [])[:10]:
                chart_data.append({
                    "category": bottleneck["component"].split(".")[-1],
                    "value": round(bottleneck["total_risk"], 3)
                })
            
            return {"chart_data": chart_data}
            
        except Exception as e:
            logger.error(f"Error getting bottlenecks data: {e}")
            return {"error": str(e)}
    
    async def _get_health_trends_data(self) -> Dict[str, Any]:
        """Get health trends over time data."""
        try:
            # This would require historical data collection
            # For now, return placeholder data
            now = datetime.utcnow()
            time_points = []
            
            for i in range(24):
                time_point = now - timedelta(hours=23-i)
                
                # Generate sample trend data (would be replaced with real historical data)
                healthy = 85 + (i % 10) - 5
                degraded = 10 + (i % 5)
                unhealthy = 5 + (i % 3)
                
                time_points.append({
                    "timestamp": time_point.strftime("%H:%M"),
                    "healthy": healthy,
                    "degraded": degraded,
                    "unhealthy": unhealthy
                })
            
            return {
                "time_series": time_points,
                "series_names": ["healthy", "degraded", "unhealthy"]
            }
            
        except Exception as e:
            logger.error(f"Error getting health trends data: {e}")
            return {"error": str(e)}
    
    async def _get_performance_metrics_data(self) -> Dict[str, Any]:
        """Get performance metrics data."""
        try:
            if not self.component_monitor.health_manager:
                return {"error": "Health manager not available"}
            
            health_results = self.component_monitor.health_manager.get_all_health_results()
            health_summary = self.component_monitor.health_manager.get_health_summary()
            
            if not health_results:
                return {"error": "No health data available"}
            
            # Calculate metrics
            response_times = [r.response_time_ms for r in health_results.values() if r.response_time_ms > 0]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0
            
            successful_checks = len([r for r in health_results.values() if r.status == HealthStatus.HEALTHY])
            health_check_success_rate = (successful_checks / len(health_results)) * 100 if health_results else 0
            
            total_components = health_summary.get("total_components", 0)
            online_components = health_summary.get("healthy_count", 0) + health_summary.get("degraded_count", 0)
            components_online_percentage = (online_components / total_components) * 100 if total_components > 0 else 0
            
            # Get critical components
            components = self.component_monitor.registry.list_components(critical_only=True) if self.component_monitor.registry else []
            critical_healthy = 0
            for comp in components:
                health_result = health_results.get(comp.name)
                if health_result and health_result.status == HealthStatus.HEALTHY:
                    critical_healthy += 1
            
            critical_components_healthy = (critical_healthy / len(components)) * 100 if components else 100
            
            return {
                "avg_response_time": round(avg_response_time, 1),
                "health_check_success_rate": round(health_check_success_rate, 1),
                "components_online_percentage": round(components_online_percentage, 1),
                "critical_components_healthy": round(critical_components_healthy, 1)
            }
            
        except Exception as e:
            logger.error(f"Error getting performance metrics data: {e}")
            return {"error": str(e)}
    
    async def _get_dependency_impact_data(self) -> Dict[str, Any]:
        """Get dependency impact heatmap data."""
        try:
            if not self.component_monitor.dependency_analyzer or not self.component_monitor.registry:
                return {"error": "Required analyzers not available"}
            
            components = self.component_monitor.registry.list_components()
            health_results = self.component_monitor.health_manager.get_all_health_results() if self.component_monitor.health_manager else {}
            
            # Create impact matrix (sample - would need full implementation)
            heatmap_data = []
            
            for comp in components[:15]:  # Limit for performance
                comp_name = comp.name.split(".")[-1]
                
                # Get impact analysis
                health_data = {
                    name: {"status": result.status.value}
                    for name, result in health_results.items()
                }
                
                impacts = self.component_monitor.dependency_analyzer.analyze_failure_impact(comp.name, health_data)
                
                # Calculate impact scores
                critical_impacts = len([i for i in impacts if i.impact_level == ImpactLevel.CRITICAL])
                high_impacts = len([i for i in impacts if i.impact_level == ImpactLevel.HIGH])
                
                impact_score = (critical_impacts * 3 + high_impacts * 2) / max(len(impacts), 1) if impacts else 0
                
                heatmap_data.append({
                    "component": comp_name,
                    "impact_score": min(impact_score, 3),  # Normalize to 0-3
                    "affected_components": len(impacts)
                })
            
            return {
                "heatmap_data": heatmap_data,
                "color_scale": {
                    "min": 0,
                    "max": 3,
                    "colors": ["#28a745", "#ffc107", "#fd7e14", "#dc3545"]
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting dependency impact data: {e}")
            return {"error": str(e)}
    
    async def _get_component_topology_data(self) -> Dict[str, Any]:
        """Get component topology network graph data."""
        try:
            if not self.component_monitor.dependency_graph or not self.component_monitor.registry:
                return {"error": "Required managers not available"}
            
            components = self.component_monitor.registry.list_components()
            health_results = self.component_monitor.health_manager.get_all_health_results() if self.component_monitor.health_manager else {}
            
            # Build nodes
            nodes = []
            for comp in components[:30]:  # Limit for performance
                comp_short_name = comp.name.split(".")[-1]
                
                health_result = health_results.get(comp.name)
                health_status = health_result.status.value if health_result else "unknown"
                
                node_color = {
                    "healthy": "#28a745",
                    "degraded": "#ffc107", 
                    "unhealthy": "#dc3545",
                    "unknown": "#6c757d"
                }.get(health_status, "#6c757d")
                
                nodes.append({
                    "id": comp.name,
                    "label": comp_short_name,
                    "type": comp.component_type.value,
                    "health_status": health_status,
                    "color": node_color,
                    "size": 10 + (5 if comp.critical else 0),
                    "critical": comp.critical
                })
            
            # Build edges
            edges = []
            graph = self.component_monitor.dependency_graph._graph
            
            for source, target, edge_data in graph.edges(data=True):
                if source in [n["id"] for n in nodes] and target in [n["id"] for n in nodes]:
                    edges.append({
                        "source": source,
                        "target": target,
                        "weight": edge_data.get("weight", 1.0),
                        "type": edge_data.get("dependency_type", "hard"),
                        "width": 1 + edge_data.get("weight", 1.0) * 2
                    })
            
            return {
                "nodes": nodes,
                "edges": edges,
                "layout_config": {
                    "algorithm": "force_directed",
                    "iterations": 100,
                    "node_repulsion": 100,
                    "edge_length": 50
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting component topology data: {e}")
            return {"error": str(e)}
    
    # Public API methods
    
    async def get_dashboard_id(self) -> Optional[str]:
        """Get the dashboard ID."""
        return self._dashboard_id
    
    async def refresh_dashboard(self) -> None:
        """Refresh all dashboard widgets."""
        try:
            if not self._dashboard_id:
                return
            
            # Refresh all widgets
            for widget_name, widget_id in self._widgets.items():
                await self.bi_engine.refresh_widget(widget_id)
            
            logger.debug("Dashboard refreshed successfully")
            
        except Exception as e:
            logger.error(f"Error refreshing dashboard: {e}")
    
    async def get_dashboard_url(self) -> Optional[str]:
        """Get the dashboard URL."""
        if not self._dashboard_id:
            return None
        
        return f"/dashboard/{self._dashboard_id}"
    
    async def export_dashboard(self, format: str = "json") -> Dict[str, Any]:
        """Export dashboard configuration."""
        try:
            if not self._dashboard_id:
                return {"error": "Dashboard not initialized"}
            
            return await self.bi_engine.export_dashboard(self._dashboard_id, format)
            
        except Exception as e:
            logger.error(f"Error exporting dashboard: {e}")
            return {"error": str(e)}


# Global dashboard instance
_component_dashboard: Optional[ComponentDashboard] = None


def get_component_dashboard() -> ComponentDashboard:
    """Get the global component dashboard instance."""
    global _component_dashboard
    if _component_dashboard is None:
        _component_dashboard = ComponentDashboard()
    return _component_dashboard


async def initialize_component_dashboard(config: Optional[ComponentDashboardConfig] = None) -> ComponentDashboard:
    """Initialize the global component dashboard."""
    dashboard = get_component_dashboard()
    await dashboard.initialize()
    return dashboard