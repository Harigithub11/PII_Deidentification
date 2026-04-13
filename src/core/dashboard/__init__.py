"""
Business Intelligence Dashboard System

This module provides comprehensive business intelligence and real-time visualization
capabilities for the PII De-identification System, including interactive dashboards,
real-time metrics, and advanced analytics.
"""

from .engine import BusinessIntelligenceEngine, DashboardMetrics, DashboardConfig
from .dashboard import InteractiveDashboard, DashboardWidget, WidgetType
from .aggregation import DataAggregationEngine, MetricAggregator, AggregationRule
from .visualization import VisualizationEngine, ChartType, ChartConfiguration
from .realtime import RealtimeEngine, WebSocketManager, DataStream
from .widgets import (
    MetricWidget, ChartWidget, TableWidget, KPIWidget, 
    AlertWidget, TrendWidget, HeatmapWidget
)

__all__ = [
    # Core Engine
    "BusinessIntelligenceEngine",
    "DashboardMetrics",
    "DashboardConfig",
    
    # Interactive Dashboard
    "InteractiveDashboard",
    "DashboardWidget", 
    "WidgetType",
    
    # Data Aggregation
    "DataAggregationEngine",
    "MetricAggregator",
    "AggregationRule",
    
    # Visualization
    "VisualizationEngine",
    "ChartType",
    "ChartConfiguration",
    
    # Real-time Features
    "RealtimeEngine",
    "WebSocketManager",
    "DataStream",
    
    # Dashboard Widgets
    "MetricWidget",
    "ChartWidget", 
    "TableWidget",
    "KPIWidget",
    "AlertWidget",
    "TrendWidget",
    "HeatmapWidget"
]