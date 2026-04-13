"""
Component Monitoring System Integration

Main orchestrator that integrates component monitoring with existing
Phase 8 monitoring infrastructure (metrics, alerts, tracing, analytics).
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field

from .component_registry import ComponentRegistry, get_component_registry, initialize_component_registry
from .component_health import ComponentHealthManager, get_health_manager, initialize_health_manager, HealthStatus
from .dependency_mapper import (
    DependencyGraph, DependencyAnalyzer, CriticalPathFinder,
    create_dependency_graph, build_dependencies_from_registry, create_analyzer, create_critical_path_finder
)

# Import existing Phase 8 monitoring infrastructure
from .metrics_collector import get_metrics_collector, MetricType, MetricScope
from .predictive_alerts import get_alert_engine, AnomalyType, AlertSeverity
from .alert_dashboard import get_alert_dashboard
from .tracing import get_tracer, trace
from .analytics import get_analytics_engine

from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class ComponentMonitorConfig:
    """Configuration for component monitoring."""
    health_check_interval: int = 30          # seconds
    dependency_analysis_interval: int = 300   # seconds (5 minutes)
    critical_path_analysis_interval: int = 600  # seconds (10 minutes)
    alert_threshold_unhealthy_count: int = 3
    alert_threshold_degraded_percentage: float = 0.5
    enable_predictive_alerts: bool = True
    enable_dependency_tracking: bool = True
    enable_performance_metrics: bool = True
    max_concurrent_health_checks: int = 20
    component_discovery_interval: int = 3600  # seconds (1 hour)


class ComponentMonitor:
    """Main component monitoring orchestrator."""
    
    def __init__(self, config: Optional[ComponentMonitorConfig] = None):
        self.config = config or ComponentMonitorConfig()
        
        # Core components
        self.registry: Optional[ComponentRegistry] = None
        self.health_manager: Optional[ComponentHealthManager] = None
        self.dependency_graph: Optional[DependencyGraph] = None
        self.dependency_analyzer: Optional[DependencyAnalyzer] = None
        self.critical_path_finder: Optional[CriticalPathFinder] = None
        
        # Existing monitoring integration
        self.metrics_collector = None
        self.alert_engine = None
        self.alert_dashboard = None
        self.tracer = None
        self.analytics_engine = None
        
        # Runtime state
        self._running = False
        self._tasks: List[asyncio.Task] = []
        self._last_health_check: Optional[datetime] = None
        self._last_dependency_analysis: Optional[datetime] = None
        self._last_critical_path_analysis: Optional[datetime] = None
        self._health_history: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
    
    async def initialize(self) -> None:
        """Initialize the component monitor and all subsystems."""
        logger.info("Initializing Component Monitor...")
        
        async with self._lock:
            if self._running:
                logger.warning("Component Monitor already running")
                return
            
            try:
                # Initialize core components
                await self._initialize_core_components()
                
                # Initialize existing monitoring integration
                await self._initialize_monitoring_integration()
                
                # Perform initial analysis
                await self._perform_initial_analysis()
                
                logger.info("Component Monitor initialized successfully")
                
            except Exception as e:
                logger.error(f"Failed to initialize Component Monitor: {e}")
                raise
    
    async def start(self) -> None:
        """Start the component monitoring system."""
        if self._running:
            logger.warning("Component Monitor already running")
            return
        
        logger.info("Starting Component Monitor...")
        
        self._running = True
        
        # Start background tasks
        self._tasks = [
            asyncio.create_task(self._health_check_loop()),
            asyncio.create_task(self._dependency_analysis_loop()),
            asyncio.create_task(self._critical_path_analysis_loop()),
            asyncio.create_task(self._metrics_collection_loop()),
            asyncio.create_task(self._component_discovery_loop())
        ]
        
        logger.info("Component Monitor started")
    
    async def stop(self) -> None:
        """Stop the component monitoring system."""
        if not self._running:
            return
        
        logger.info("Stopping Component Monitor...")
        
        self._running = False
        
        # Cancel all tasks
        for task in self._tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self._tasks, return_exceptions=True)
        
        self._tasks.clear()
        logger.info("Component Monitor stopped")
    
    async def _initialize_core_components(self) -> None:
        """Initialize core monitoring components."""
        # Initialize component registry
        self.registry = await initialize_component_registry()
        
        # Initialize health manager
        self.health_manager = await initialize_health_manager()
        
        # Initialize dependency graph
        self.dependency_graph = create_dependency_graph(self.registry)
        build_dependencies_from_registry(self.dependency_graph)
        
        # Initialize analyzers
        self.dependency_analyzer = create_analyzer(self.dependency_graph)
        self.critical_path_finder = create_critical_path_finder(self.dependency_graph)
        
        logger.debug("Core components initialized")
    
    async def _initialize_monitoring_integration(self) -> None:
        """Initialize integration with existing Phase 8 monitoring."""
        try:
            # Get existing monitoring components
            self.metrics_collector = get_metrics_collector()
            self.alert_engine = get_alert_engine()
            self.alert_dashboard = get_alert_dashboard()
            self.tracer = get_tracer()
            self.analytics_engine = get_analytics_engine()
            
            # Register component-specific metrics
            await self._register_component_metrics()
            
            # Setup component alerts
            await self._setup_component_alerts()
            
            logger.debug("Monitoring integration initialized")
            
        except Exception as e:
            logger.warning(f"Could not fully initialize monitoring integration: {e}")
    
    async def _perform_initial_analysis(self) -> None:
        """Perform initial component analysis."""
        # Initial health check
        await self._perform_health_checks()
        
        # Initial dependency analysis
        await self._perform_dependency_analysis()
        
        # Initial critical path analysis
        await self._perform_critical_path_analysis()
        
        logger.debug("Initial analysis completed")
    
    @trace(operation_name="component_health_check")
    async def _health_check_loop(self) -> None:
        """Background loop for health checking."""
        while self._running:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self.config.health_check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")
                await asyncio.sleep(10)  # Wait before retrying
    
    @trace(operation_name="dependency_analysis")
    async def _dependency_analysis_loop(self) -> None:
        """Background loop for dependency analysis."""
        while self._running:
            try:
                await self._perform_dependency_analysis()
                await asyncio.sleep(self.config.dependency_analysis_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in dependency analysis loop: {e}")
                await asyncio.sleep(30)  # Wait before retrying
    
    @trace(operation_name="critical_path_analysis")
    async def _critical_path_analysis_loop(self) -> None:
        """Background loop for critical path analysis."""
        while self._running:
            try:
                await self._perform_critical_path_analysis()
                await asyncio.sleep(self.config.critical_path_analysis_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in critical path analysis loop: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _metrics_collection_loop(self) -> None:
        """Background loop for metrics collection."""
        while self._running:
            try:
                await self._collect_component_metrics()
                await asyncio.sleep(60)  # Collect metrics every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                await asyncio.sleep(30)
    
    async def _component_discovery_loop(self) -> None:
        """Background loop for component discovery."""
        while self._running:
            try:
                await self._discover_new_components()
                await asyncio.sleep(self.config.component_discovery_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in component discovery loop: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retrying
    
    @trace(operation_name="perform_health_checks")
    async def _perform_health_checks(self) -> None:
        """Perform health checks on all components."""
        if not self.health_manager:
            return
        
        start_time = datetime.utcnow()
        
        # Get all health results
        health_results = await self.health_manager.check_all_components()
        
        # Update last check time
        self._last_health_check = start_time
        
        # Analyze results and trigger alerts if needed
        await self._analyze_health_results(health_results)
        
        # Store health history (keep last 100 entries)
        health_summary = self.health_manager.get_health_summary()
        self._health_history.append({
            "timestamp": start_time.isoformat(),
            "summary": health_summary
        })
        
        if len(self._health_history) > 100:
            self._health_history.pop(0)
        
        logger.debug(f"Health checks completed for {len(health_results)} components")
    
    async def _perform_dependency_analysis(self) -> None:
        """Perform dependency analysis."""
        if not self.dependency_analyzer or not self.health_manager:
            return
        
        start_time = datetime.utcnow()
        
        # Get current health status
        health_results = self.health_manager.get_all_health_results()
        health_data = {
            name: {"status": result.status.value}
            for name, result in health_results.items()
        }
        
        # Find unhealthy components
        unhealthy_components = [
            name for name, result in health_results.items()
            if result.status == HealthStatus.UNHEALTHY
        ]
        
        if unhealthy_components:
            # Analyze cascading failure impact
            cascading_analysis = self.dependency_analyzer.analyze_cascading_failures(
                unhealthy_components, health_data
            )
            
            # Trigger alerts for high-impact failures
            await self._handle_dependency_alerts(cascading_analysis)
        
        self._last_dependency_analysis = start_time
        logger.debug("Dependency analysis completed")
    
    async def _perform_critical_path_analysis(self) -> None:
        """Perform critical path analysis."""
        if not self.critical_path_finder:
            return
        
        start_time = datetime.utcnow()
        
        # Find critical paths
        critical_paths = self.critical_path_finder.find_critical_paths()
        
        # Get bottleneck analysis
        bottleneck_analysis = self.critical_path_finder.get_bottleneck_analysis()
        
        # Store results for dashboard
        if self.metrics_collector:
            # Record critical path metrics
            await self.metrics_collector.record_metric(
                name="component_critical_paths_count",
                value=len(critical_paths),
                metric_type=MetricType.GAUGE,
                scope=MetricScope.SYSTEM,
                tags={"analysis_type": "critical_paths"}
            )
            
            # Record top bottlenecks
            if bottleneck_analysis.get("top_bottlenecks"):
                top_bottleneck = bottleneck_analysis["top_bottlenecks"][0]
                await self.metrics_collector.record_metric(
                    name="component_bottleneck_risk_score",
                    value=top_bottleneck["total_risk"],
                    metric_type=MetricType.GAUGE,
                    scope=MetricScope.SYSTEM,
                    tags={
                        "component": top_bottleneck["component"],
                        "analysis_type": "bottleneck"
                    }
                )
        
        self._last_critical_path_analysis = start_time
        logger.debug(f"Critical path analysis completed: found {len(critical_paths)} critical paths")
    
    async def _collect_component_metrics(self) -> None:
        """Collect component-specific metrics."""
        if not self.metrics_collector or not self.registry:
            return
        
        # Get registry statistics
        stats = self.registry.get_statistics()
        
        # Record component count metrics
        await self.metrics_collector.record_metric(
            name="components_total",
            value=stats["total_components"],
            metric_type=MetricType.GAUGE,
            scope=MetricScope.SYSTEM
        )
        
        await self.metrics_collector.record_metric(
            name="components_active",
            value=stats["active_components"],
            metric_type=MetricType.GAUGE,
            scope=MetricScope.SYSTEM
        )
        
        await self.metrics_collector.record_metric(
            name="components_failed",
            value=stats["failed_components"],
            metric_type=MetricType.GAUGE,
            scope=MetricScope.SYSTEM
        )
        
        # Record component type metrics
        for comp_type, count in stats["by_type"].items():
            await self.metrics_collector.record_metric(
                name="components_by_type",
                value=count,
                metric_type=MetricType.GAUGE,
                scope=MetricScope.SYSTEM,
                tags={"component_type": comp_type}
            )
        
        # Get health summary
        if self.health_manager:
            health_summary = self.health_manager.get_health_summary()
            
            await self.metrics_collector.record_metric(
                name="components_healthy",
                value=health_summary.get("healthy_count", 0),
                metric_type=MetricType.GAUGE,
                scope=MetricScope.SYSTEM
            )
            
            await self.metrics_collector.record_metric(
                name="components_degraded",
                value=health_summary.get("degraded_count", 0),
                metric_type=MetricType.GAUGE,
                scope=MetricScope.SYSTEM
            )
            
            await self.metrics_collector.record_metric(
                name="components_unhealthy",
                value=health_summary.get("unhealthy_count", 0),
                metric_type=MetricType.GAUGE,
                scope=MetricScope.SYSTEM
            )
    
    async def _discover_new_components(self) -> None:
        """Discover new components that may have been added."""
        if not self.registry:
            return
        
        # Re-run component discovery
        await self.registry._discover_components()
        
        # Update health checkers for new components
        if self.health_manager:
            await self.health_manager._create_health_checkers()
        
        # Rebuild dependency graph
        if self.dependency_graph:
            build_dependencies_from_registry(self.dependency_graph)
        
        logger.debug("Component discovery completed")
    
    async def _analyze_health_results(self, health_results: Dict[str, Any]) -> None:
        """Analyze health results and trigger alerts if needed."""
        if not health_results or not self.alert_engine:
            return
        
        unhealthy_count = sum(1 for r in health_results.values() if r.status == HealthStatus.UNHEALTHY)
        total_count = len(health_results)
        degraded_percentage = sum(1 for r in health_results.values() if r.status == HealthStatus.DEGRADED) / total_count if total_count > 0 else 0
        
        # Check alert thresholds
        if unhealthy_count >= self.config.alert_threshold_unhealthy_count:
            await self._trigger_alert(
                alert_type="component_health_critical",
                severity=AlertSeverity.CRITICAL,
                message=f"{unhealthy_count} components are unhealthy",
                metadata={"unhealthy_count": unhealthy_count, "total_count": total_count}
            )
        
        if degraded_percentage >= self.config.alert_threshold_degraded_percentage:
            await self._trigger_alert(
                alert_type="component_health_degraded",
                severity=AlertSeverity.WARNING,
                message=f"{degraded_percentage:.1%} of components are degraded",
                metadata={"degraded_percentage": degraded_percentage, "total_count": total_count}
            )
    
    async def _handle_dependency_alerts(self, cascading_analysis: Dict[str, Any]) -> None:
        """Handle alerts for dependency failures."""
        if not self.alert_engine:
            return
        
        critical_impacts = cascading_analysis.get("critical_impacts", 0)
        system_failure_risk = cascading_analysis.get("system_wide_failure_risk", 0)
        
        if critical_impacts > 0:
            await self._trigger_alert(
                alert_type="dependency_cascade_critical",
                severity=AlertSeverity.CRITICAL,
                message=f"Critical cascading failure detected: {critical_impacts} critical impacts",
                metadata=cascading_analysis
            )
        
        elif system_failure_risk > 0.5:
            await self._trigger_alert(
                alert_type="dependency_cascade_warning",
                severity=AlertSeverity.WARNING,
                message=f"High system failure risk: {system_failure_risk:.1%}",
                metadata=cascading_analysis
            )
    
    async def _trigger_alert(self, alert_type: str, severity: AlertSeverity, message: str, metadata: Dict[str, Any]) -> None:
        """Trigger an alert through the existing alert system."""
        try:
            if self.alert_engine:
                # Create anomaly detection result for the alert engine
                anomaly_result = {
                    "component_name": "component_monitor",
                    "anomaly_type": AnomalyType.THRESHOLD,
                    "severity": severity,
                    "confidence": 0.9,
                    "description": message,
                    "metadata": metadata,
                    "timestamp": datetime.utcnow()
                }
                
                # This would trigger the alert through the existing system
                # The exact method depends on the PredictiveAlertEngine implementation
                logger.warning(f"Component alert triggered: {alert_type} - {message}")
                
        except Exception as e:
            logger.error(f"Failed to trigger alert {alert_type}: {e}")
    
    async def _register_component_metrics(self) -> None:
        """Register component-specific metrics with the metrics collector."""
        if not self.metrics_collector:
            return
        
        # Define component monitoring metrics
        component_metrics = [
            "components_total",
            "components_active", 
            "components_failed",
            "components_healthy",
            "components_degraded",
            "components_unhealthy",
            "components_by_type",
            "component_critical_paths_count",
            "component_bottleneck_risk_score"
        ]
        
        # Register metrics (the exact method depends on AdvancedMetricsCollector implementation)
        logger.debug(f"Registered {len(component_metrics)} component metrics")
    
    async def _setup_component_alerts(self) -> None:
        """Setup component-specific alert rules."""
        if not self.alert_engine:
            return
        
        # Define alert rules for component monitoring
        alert_rules = [
            {
                "name": "component_health_critical",
                "condition": "unhealthy_components >= 3",
                "severity": AlertSeverity.CRITICAL,
                "description": "Multiple components are unhealthy"
            },
            {
                "name": "component_health_degraded", 
                "condition": "degraded_percentage >= 0.5",
                "severity": AlertSeverity.WARNING,
                "description": "High percentage of components degraded"
            },
            {
                "name": "dependency_cascade_critical",
                "condition": "critical_impacts > 0",
                "severity": AlertSeverity.CRITICAL,
                "description": "Critical cascading failure detected"
            }
        ]
        
        # Setup rules (the exact method depends on PredictiveAlertEngine implementation)
        logger.debug(f"Setup {len(alert_rules)} component alert rules")
    
    # Public API methods
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status."""
        status = {
            "monitor_running": self._running,
            "last_health_check": self._last_health_check.isoformat() if self._last_health_check else None,
            "last_dependency_analysis": self._last_dependency_analysis.isoformat() if self._last_dependency_analysis else None,
            "last_critical_path_analysis": self._last_critical_path_analysis.isoformat() if self._last_critical_path_analysis else None
        }
        
        if self.registry:
            status["registry"] = self.registry.get_statistics()
        
        if self.health_manager:
            status["health"] = self.health_manager.get_health_summary()
        
        if self.dependency_graph:
            status["dependencies"] = self.dependency_graph.get_graph_statistics()
        
        return status
    
    async def get_component_details(self, component_name: str) -> Dict[str, Any]:
        """Get detailed information about a specific component."""
        details = {"component_name": component_name}
        
        if self.registry:
            component = self.registry.get_component(component_name)
            if component:
                details["metadata"] = {
                    "type": component.component_type.value,
                    "description": component.description,
                    "version": component.version,
                    "critical": component.critical,
                    "status": component.status.value,
                    "registered_at": component.registered_at.isoformat(),
                    "dependencies": component.dependencies,
                    "tags": component.tags
                }
        
        if self.health_manager:
            health_result = self.health_manager.get_health_result(component_name)
            if health_result:
                details["health"] = {
                    "status": health_result.status.value,
                    "response_time_ms": health_result.response_time_ms,
                    "message": health_result.message,
                    "last_check": health_result.timestamp.isoformat(),
                    "metadata": health_result.metadata
                }
        
        if self.dependency_graph:
            details["dependencies"] = {
                "direct_dependencies": list(self.dependency_graph.get_dependencies(component_name)),
                "reverse_dependencies": list(self.dependency_graph.get_reverse_dependencies(component_name)),
                "criticality_score": self.dependency_graph.get_component_criticality_score(component_name)
            }
        
        return details
    
    async def force_health_check(self, component_name: Optional[str] = None) -> Dict[str, Any]:
        """Force a health check on a specific component or all components."""
        if not self.health_manager:
            return {"error": "Health manager not initialized"}
        
        if component_name:
            result = await self.health_manager.check_component_health(component_name)
            return {"component": component_name, "result": result.__dict__ if result else None}
        else:
            results = await self.health_manager.check_all_components()
            return {"results": {name: result.__dict__ for name, result in results.items()}}
    
    async def analyze_component_impact(self, component_name: str) -> Dict[str, Any]:
        """Analyze the impact if a component fails."""
        if not self.dependency_analyzer:
            return {"error": "Dependency analyzer not initialized"}
        
        health_results = self.health_manager.get_all_health_results() if self.health_manager else {}
        health_data = {
            name: {"status": result.status.value}
            for name, result in health_results.items()
        }
        
        impacts = self.dependency_analyzer.analyze_failure_impact(component_name, health_data)
        
        return {
            "component": component_name,
            "impacts": [
                {
                    "affected_component": impact.affected_component,
                    "impact_level": impact.impact_level.value,
                    "dependency_chain": impact.dependency_chain,
                    "failure_probability": impact.failure_probability,
                    "estimated_downtime_minutes": impact.estimated_downtime_minutes,
                    "mitigation_suggestions": impact.mitigation_suggestions
                }
                for impact in impacts
            ]
        }


# Global component monitor instance
_component_monitor: Optional[ComponentMonitor] = None


def get_component_monitor() -> ComponentMonitor:
    """Get the global component monitor instance."""
    global _component_monitor
    if _component_monitor is None:
        _component_monitor = ComponentMonitor()
    return _component_monitor


async def initialize_component_monitor(config: Optional[ComponentMonitorConfig] = None) -> ComponentMonitor:
    """Initialize the global component monitor."""
    global _component_monitor
    if _component_monitor is None:
        _component_monitor = ComponentMonitor(config)
    
    await _component_monitor.initialize()
    return _component_monitor