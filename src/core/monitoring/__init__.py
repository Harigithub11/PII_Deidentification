"""
Advanced Performance Monitoring System

Comprehensive monitoring solution for the PII De-identification System
that provides real-time performance tracking, intelligent alerting,
predictive analytics, distributed tracing, and infrastructure monitoring.

Complete Phase 8 Implementation:
- Phase 8.1: Enhanced Metrics Collection System ✓
- Phase 8.2: Intelligent Alerting System ✓  
- Phase 8.3: Application Performance Monitoring (APM) ✓
- Phase 8.4: Infrastructure Monitoring ✓
- Phase 8.5: Performance Analytics & Reporting ✓
- Phase 8.6: Load Testing & Benchmarking ✓

🎉 ALL PHASES COMPLETE! 🎉
"""

# Phase 8.1: Enhanced Metrics Collection
from .metrics_collector import (
    AdvancedMetricsCollector,
    MetricType,
    MetricScope,
    MetricPoint,
    MetricSeries,
    get_metrics_collector,
    initialize_metrics_collector
)

# Phase 8.2: Intelligent Alerting System
from .predictive_alerts import (
    PredictiveAlertEngine,
    AnomalyType,
    AlertSeverity,
    AnomalyDetectionResult,
    PredictionResult
)

from .alert_dashboard import (
    AlertDashboardManager,
    AlertStatus,
    AlertSummary,
    AlertGroup,
    AlertCorrelationEngine,
    AlertFilter,
    get_alert_dashboard,
    initialize_alert_dashboard
)

from .alert_escalation import (
    AlertEscalationManager,
    EscalationPolicy,
    NotificationTarget,
    NotificationChannel,
    get_escalation_manager,
    initialize_escalation_manager
)

from .alert_workflow import (
    AlertWorkflowManager,
    WorkflowAction,
    WorkflowTrigger,
    WorkflowRule,
    get_workflow_manager,
    initialize_workflow_manager
)

# Phase 8.3: Application Performance Monitoring (APM)
from .tracing import (
    DistributedTracer,
    Span,
    SpanKind,
    SpanStatus,
    TraceContext,
    Trace,
    trace,
    get_tracer,
    initialize_tracer
)

from .performance_profiler import (
    PerformanceProfiler,
    FunctionProfile,
    DatabaseQueryProfile,
    PerformanceIssue,
    PerformanceIssueType,
    MemoryTracker,
    profile_function,
    get_profiler,
    initialize_profiler
)

# Phase 8.4: Infrastructure Monitoring
from .infrastructure import (
    InfrastructureMonitor,
    SystemResourceMonitor,
    DependencyHealthMonitor,
    ResourceMetrics,
    DependencyHealth,
    ResourceType,
    HealthStatus,
    get_infrastructure_monitor,
    initialize_infrastructure_monitor
)

# Phase 8.5: Performance Analytics & Reporting
from .analytics import (
    PerformanceAnalyticsEngine,
    TimeSeriesAnalyzer,
    RegressionDetector,
    SLAAnalyzer,
    TrendAnalysis,
    CapacityForecast,
    PerformanceBaseline,
    RegressionResult,
    SLACompliance,
    TrendDirection,
    ForecastConfidence,
    get_analytics_engine,
    initialize_analytics_engine
)

# Phase 8.6: Load Testing & Benchmarking
from .load_testing import (
    LoadTestingFramework,
    LoadGenerator,
    PerformanceAnalyzer,
    LoadTestConfig,
    LoadTestResult,
    LoadTestMetrics,
    RequestResult,
    LoadTestType,
    LoadPattern,
    TestStatus,
    get_load_testing_framework,
    initialize_load_testing_framework
)

# Component Monitoring System
from .component_registry import (
    ComponentRegistry,
    ComponentType,
    ComponentStatus,
    ComponentMetadata,
    ComponentDiscovery,
    get_component_registry,
    initialize_component_registry,
    component
)

from .component_health import (
    ComponentHealthManager,
    BaseHealthChecker,
    APIEndpointHealthChecker,
    ServiceHealthChecker,
    DatabaseHealthChecker,
    RedisHealthChecker,
    SystemResourceHealthChecker,
    CompositeHealthChecker,
    HealthStatus,
    HealthCheckResult,
    HealthThresholds,
    get_health_manager,
    initialize_health_manager
)

from .dependency_mapper import (
    DependencyGraph,
    DependencyAnalyzer,
    CriticalPathFinder,
    DependencyType,
    ImpactLevel,
    DependencyEdge,
    ImpactAnalysisResult,
    CriticalPath,
    create_dependency_graph,
    create_analyzer,
    create_critical_path_finder
)

from .component_monitor import (
    ComponentMonitor,
    ComponentMonitorConfig,
    get_component_monitor,
    initialize_component_monitor
)

__all__ = [
    # Phase 8.1: Metrics Collection
    'AdvancedMetricsCollector',
    'MetricType',
    'MetricScope', 
    'MetricPoint',
    'MetricSeries',
    'get_metrics_collector',
    'initialize_metrics_collector',
    
    # Phase 8.2: Intelligent Alerting
    'PredictiveAlertEngine',
    'AnomalyType',
    'AlertSeverity',
    'AnomalyDetectionResult',
    'PredictionResult',
    'AlertDashboardManager',
    'AlertStatus',
    'AlertSummary',
    'AlertGroup',
    'AlertCorrelationEngine',
    'AlertFilter',
    'get_alert_dashboard',
    'initialize_alert_dashboard',
    'AlertEscalationManager',
    'EscalationPolicy',
    'NotificationTarget',
    'NotificationChannel',
    'get_escalation_manager',
    'initialize_escalation_manager',
    'AlertWorkflowManager',
    'WorkflowAction',
    'WorkflowTrigger',
    'WorkflowRule',
    'get_workflow_manager',
    'initialize_workflow_manager',
    
    # Phase 8.3: APM
    'DistributedTracer',
    'Span',
    'SpanKind',
    'SpanStatus',
    'TraceContext',
    'Trace',
    'trace',
    'get_tracer',
    'initialize_tracer',
    'PerformanceProfiler',
    'FunctionProfile',
    'DatabaseQueryProfile',
    'PerformanceIssue',
    'PerformanceIssueType',
    'MemoryTracker',
    'profile_function',
    'get_profiler',
    'initialize_profiler',
    
    # Phase 8.4: Infrastructure Monitoring
    'InfrastructureMonitor',
    'SystemResourceMonitor',
    'DependencyHealthMonitor',
    'ResourceMetrics',
    'DependencyHealth',
    'ResourceType',
    'HealthStatus',
    'get_infrastructure_monitor',
    'initialize_infrastructure_monitor',
    
    # Phase 8.5: Performance Analytics & Reporting
    'PerformanceAnalyticsEngine',
    'TimeSeriesAnalyzer',
    'RegressionDetector',
    'SLAAnalyzer',
    'TrendAnalysis',
    'CapacityForecast',
    'PerformanceBaseline',
    'RegressionResult',
    'SLACompliance',
    'TrendDirection',
    'ForecastConfidence',
    'get_analytics_engine',
    'initialize_analytics_engine',
    
    # Phase 8.6: Load Testing & Benchmarking
    'LoadTestingFramework',
    'LoadGenerator',
    'PerformanceAnalyzer',
    'LoadTestConfig',
    'LoadTestResult',
    'LoadTestMetrics',
    'RequestResult',
    'LoadTestType',
    'LoadPattern',
    'TestStatus',
    'get_load_testing_framework',
    'initialize_load_testing_framework',
    
    # Component Monitoring System
    'ComponentRegistry',
    'ComponentType',
    'ComponentStatus', 
    'ComponentMetadata',
    'ComponentDiscovery',
    'get_component_registry',
    'initialize_component_registry',
    'component',
    'ComponentHealthManager',
    'BaseHealthChecker',
    'APIEndpointHealthChecker',
    'ServiceHealthChecker',
    'DatabaseHealthChecker',
    'RedisHealthChecker',
    'SystemResourceHealthChecker',
    'CompositeHealthChecker',
    'HealthStatus',
    'HealthCheckResult',
    'HealthThresholds',
    'get_health_manager',
    'initialize_health_manager',
    'DependencyGraph',
    'DependencyAnalyzer',
    'CriticalPathFinder',
    'DependencyType',
    'ImpactLevel',
    'DependencyEdge',
    'ImpactAnalysisResult',
    'CriticalPath',
    'create_dependency_graph',
    'create_analyzer',
    'create_critical_path_finder',
    'ComponentMonitor',
    'ComponentMonitorConfig',
    'get_component_monitor',
    'initialize_component_monitor'
]