"""
Interactive Dashboard Interface

Provides the main dashboard interface with widget management, layout control,
and interactive features for business intelligence visualization.
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field

from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class WidgetType(str, Enum):
    """Types of dashboard widgets."""
    METRIC = "metric"
    CHART = "chart"
    TABLE = "table"
    KPI = "kpi"
    ALERT = "alert"
    TREND = "trend"
    HEATMAP = "heatmap"
    GAUGE = "gauge"
    MAP = "map"
    TEXT = "text"
    IMAGE = "image"
    IFRAME = "iframe"


class ChartType(str, Enum):
    """Types of charts for chart widgets."""
    LINE = "line"
    BAR = "bar"
    PIE = "pie"
    AREA = "area"
    SCATTER = "scatter"
    HISTOGRAM = "histogram"
    DONUT = "donut"
    TIMELINE = "timeline"
    CANDLESTICK = "candlestick"


class WidgetSize(str, Enum):
    """Standard widget sizes."""
    SMALL = "small"      # 1x1
    MEDIUM = "medium"    # 2x1
    LARGE = "large"      # 2x2
    WIDE = "wide"        # 4x1
    TALL = "tall"        # 1x4
    EXTRA_LARGE = "xl"   # 4x2


@dataclass
class WidgetPosition:
    """Widget position and dimensions in grid layout."""
    x: int
    y: int
    width: int
    height: int
    min_width: int = 1
    min_height: int = 1
    max_width: Optional[int] = None
    max_height: Optional[int] = None


class WidgetConfig(BaseModel):
    """Configuration for a dashboard widget."""
    
    id: UUID = Field(default_factory=uuid4)
    type: WidgetType
    title: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    
    # Layout and appearance
    position: WidgetPosition
    size: WidgetSize = WidgetSize.MEDIUM
    theme: str = "default"
    border: bool = True
    
    # Data configuration
    data_source: str  # Query name, endpoint, or data source identifier
    refresh_interval: int = 300  # seconds
    auto_refresh: bool = True
    
    # Widget-specific settings
    chart_type: Optional[ChartType] = None
    chart_config: Dict[str, Any] = Field(default_factory=dict)
    display_options: Dict[str, Any] = Field(default_factory=dict)
    
    # Interactivity
    clickable: bool = False
    drill_down: Optional[str] = None  # URL or action for drill-down
    filters: Dict[str, Any] = Field(default_factory=dict)
    
    # Alerts and notifications
    alert_enabled: bool = False
    alert_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[UUID] = None
    
    @validator('refresh_interval')
    def validate_refresh_interval(cls, v):
        if v < 5:
            raise ValueError('Refresh interval must be at least 5 seconds')
        return v


class DashboardWidget:
    """
    A dashboard widget that handles data fetching, rendering configuration,
    and interactive features.
    """
    
    def __init__(self, config: WidgetConfig):
        self.config = config
        self._data: Optional[Dict[str, Any]] = None
        self._last_updated: Optional[datetime] = None
        self._error: Optional[str] = None
        self._is_loading = False
        
        # Event handlers
        self._on_data_change: Optional[Callable] = None
        self._on_error: Optional[Callable] = None
        self._on_click: Optional[Callable] = None
        
        logger.info(f"Widget created: {config.id} - {config.title}")
    
    @property
    def id(self) -> UUID:
        """Widget ID."""
        return self.config.id
    
    @property
    def type(self) -> WidgetType:
        """Widget type."""
        return self.config.type
    
    @property
    def data(self) -> Optional[Dict[str, Any]]:
        """Current widget data."""
        return self._data
    
    @property
    def is_loading(self) -> bool:
        """Whether widget is currently loading data."""
        return self._is_loading
    
    @property
    def has_error(self) -> bool:
        """Whether widget has an error."""
        return self._error is not None
    
    @property
    def error_message(self) -> Optional[str]:
        """Current error message if any."""
        return self._error
    
    @property
    def last_updated(self) -> Optional[datetime]:
        """When data was last updated."""
        return self._last_updated
    
    def set_data(self, data: Dict[str, Any]) -> None:
        """Set widget data and trigger change event."""
        self._data = data
        self._last_updated = datetime.utcnow()
        self._error = None
        self._is_loading = False
        
        if self._on_data_change:
            self._on_data_change(self, data)
    
    def set_error(self, error: str) -> None:
        """Set widget error and trigger error event."""
        self._error = error
        self._is_loading = False
        
        if self._on_error:
            self._on_error(self, error)
    
    def set_loading(self, loading: bool = True) -> None:
        """Set widget loading state."""
        self._is_loading = loading
        if loading:
            self._error = None
    
    def update_config(self, updates: Dict[str, Any]) -> None:
        """Update widget configuration."""
        for key, value in updates.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        
        self.config.updated_at = datetime.utcnow()
        logger.info(f"Widget config updated: {self.config.id}")
    
    def on_data_change(self, callback: Callable[['DashboardWidget', Dict[str, Any]], None]) -> None:
        """Set callback for data change events."""
        self._on_data_change = callback
    
    def on_error(self, callback: Callable[['DashboardWidget', str], None]) -> None:
        """Set callback for error events."""
        self._on_error = callback
    
    def on_click(self, callback: Callable[['DashboardWidget', Dict[str, Any]], None]) -> None:
        """Set callback for click events."""
        self._on_click = callback
    
    def handle_click(self, event_data: Dict[str, Any] = None) -> None:
        """Handle widget click event."""
        if self._on_click:
            self._on_click(self, event_data or {})
    
    def get_render_data(self) -> Dict[str, Any]:
        """Get data formatted for rendering."""
        return {
            "id": str(self.config.id),
            "type": self.config.type.value,
            "title": self.config.title,
            "description": self.config.description,
            "size": self.config.size.value,
            "position": {
                "x": self.config.position.x,
                "y": self.config.position.y,
                "width": self.config.position.width,
                "height": self.config.position.height
            },
            "theme": self.config.theme,
            "data": self._data,
            "is_loading": self._is_loading,
            "has_error": self.has_error,
            "error_message": self._error,
            "last_updated": self._last_updated.isoformat() if self._last_updated else None,
            "chart_type": self.config.chart_type.value if self.config.chart_type else None,
            "chart_config": self.config.chart_config,
            "display_options": self.config.display_options,
            "clickable": self.config.clickable,
            "auto_refresh": self.config.auto_refresh,
            "refresh_interval": self.config.refresh_interval
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert widget to dictionary representation."""
        render_data = self.get_render_data()
        render_data.update({
            "data_source": self.config.data_source,
            "filters": self.config.filters,
            "alert_enabled": self.config.alert_enabled,
            "alert_conditions": self.config.alert_conditions,
            "created_at": self.config.created_at.isoformat(),
            "updated_at": self.config.updated_at.isoformat(),
            "created_by": str(self.config.created_by) if self.config.created_by else None
        })
        return render_data


class InteractiveDashboard:
    """
    Interactive dashboard that manages multiple widgets, handles layout,
    and coordinates data updates and user interactions.
    """
    
    def __init__(self, dashboard_id: UUID, name: str):
        self.id = dashboard_id
        self.name = name
        self._widgets: Dict[UUID, DashboardWidget] = {}
        self._layout_grid: List[List[Optional[UUID]]] = []
        self._grid_width = 12  # Standard 12-column grid
        self._grid_height = 20  # Initial height, can grow
        
        # Event handlers
        self._on_widget_change: Optional[Callable] = None
        self._on_layout_change: Optional[Callable] = None
        
        # Initialize grid
        self._initialize_grid()
        
        logger.info(f"Interactive dashboard created: {dashboard_id} - {name}")
    
    def _initialize_grid(self) -> None:
        """Initialize empty layout grid."""
        self._layout_grid = [
            [None for _ in range(self._grid_width)]
            for _ in range(self._grid_height)
        ]
    
    def add_widget(self, widget: DashboardWidget) -> bool:
        """Add widget to dashboard and place in layout."""
        try:
            # Check if position is available
            if not self._is_position_available(widget.config.position):
                # Try to find available position
                new_position = self._find_available_position(
                    widget.config.position.width,
                    widget.config.position.height
                )
                if new_position:
                    widget.config.position = new_position
                else:
                    logger.warning(f"No available position for widget: {widget.id}")
                    return False
            
            # Place widget in grid
            self._place_widget_in_grid(widget)
            
            # Add to widgets collection
            self._widgets[widget.id] = widget
            
            # Set up event handlers
            widget.on_data_change(self._handle_widget_data_change)
            widget.on_error(self._handle_widget_error)
            
            logger.info(f"Widget added to dashboard: {widget.id}")
            
            if self._on_layout_change:
                self._on_layout_change(self)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to add widget {widget.id}: {e}")
            return False
    
    def remove_widget(self, widget_id: UUID) -> bool:
        """Remove widget from dashboard."""
        if widget_id not in self._widgets:
            return False
        
        widget = self._widgets[widget_id]
        
        # Remove from grid
        self._remove_widget_from_grid(widget)
        
        # Remove from widgets collection
        del self._widgets[widget_id]
        
        logger.info(f"Widget removed from dashboard: {widget_id}")
        
        if self._on_layout_change:
            self._on_layout_change(self)
        
        return True
    
    def get_widget(self, widget_id: UUID) -> Optional[DashboardWidget]:
        """Get widget by ID."""
        return self._widgets.get(widget_id)
    
    def get_all_widgets(self) -> List[DashboardWidget]:
        """Get all widgets in dashboard."""
        return list(self._widgets.values())
    
    def move_widget(self, widget_id: UUID, new_position: WidgetPosition) -> bool:
        """Move widget to new position."""
        if widget_id not in self._widgets:
            return False
        
        widget = self._widgets[widget_id]
        old_position = widget.config.position
        
        # Check if new position is available
        if not self._is_position_available(new_position, exclude_widget=widget_id):
            return False
        
        # Remove from old position
        self._remove_widget_from_grid(widget)
        
        # Update position
        widget.config.position = new_position
        
        # Place in new position
        self._place_widget_in_grid(widget)
        
        logger.info(f"Widget moved: {widget_id}")
        
        if self._on_layout_change:
            self._on_layout_change(self)
        
        return True
    
    def resize_widget(self, widget_id: UUID, new_width: int, new_height: int) -> bool:
        """Resize widget."""
        if widget_id not in self._widgets:
            return False
        
        widget = self._widgets[widget_id]
        position = widget.config.position
        
        # Create new position with new dimensions
        new_position = WidgetPosition(
            x=position.x,
            y=position.y,
            width=new_width,
            height=new_height,
            min_width=position.min_width,
            min_height=position.min_height,
            max_width=position.max_width,
            max_height=position.max_height
        )
        
        # Check if resize is possible
        if not self._is_position_available(new_position, exclude_widget=widget_id):
            return False
        
        # Remove from old position
        self._remove_widget_from_grid(widget)
        
        # Update position
        widget.config.position = new_position
        
        # Place in new position
        self._place_widget_in_grid(widget)
        
        logger.info(f"Widget resized: {widget_id}")
        
        if self._on_layout_change:
            self._on_layout_change(self)
        
        return True
    
    def get_layout_data(self) -> Dict[str, Any]:
        """Get current layout data."""
        widgets_data = [widget.get_render_data() for widget in self._widgets.values()]
        
        return {
            "dashboard_id": str(self.id),
            "name": self.name,
            "grid_width": self._grid_width,
            "grid_height": self._grid_height,
            "widgets": widgets_data,
            "total_widgets": len(self._widgets)
        }
    
    def update_all_widgets_data(self, widgets_data: Dict[str, Dict[str, Any]]) -> None:
        """Update data for multiple widgets."""
        for widget_id_str, data in widgets_data.items():
            try:
                widget_id = UUID(widget_id_str)
                if widget_id in self._widgets:
                    self._widgets[widget_id].set_data(data)
            except (ValueError, Exception) as e:
                logger.error(f"Failed to update widget data {widget_id_str}: {e}")
    
    def on_widget_change(self, callback: Callable[['InteractiveDashboard', DashboardWidget], None]) -> None:
        """Set callback for widget change events."""
        self._on_widget_change = callback
    
    def on_layout_change(self, callback: Callable[['InteractiveDashboard'], None]) -> None:
        """Set callback for layout change events."""
        self._on_layout_change = callback
    
    def _is_position_available(self, position: WidgetPosition, exclude_widget: Optional[UUID] = None) -> bool:
        """Check if position is available in grid."""
        # Ensure grid is large enough
        required_height = position.y + position.height
        if required_height > self._grid_height:
            self._expand_grid_height(required_height)
        
        # Check each cell in the proposed area
        for y in range(position.y, position.y + position.height):
            for x in range(position.x, position.x + position.width):
                if x >= self._grid_width or y >= self._grid_height:
                    return False
                
                current_widget = self._layout_grid[y][x]
                if current_widget is not None and current_widget != exclude_widget:
                    return False
        
        return True
    
    def _find_available_position(self, width: int, height: int) -> Optional[WidgetPosition]:
        """Find first available position for widget of given size."""
        for y in range(self._grid_height - height + 1):
            for x in range(self._grid_width - width + 1):
                position = WidgetPosition(x=x, y=y, width=width, height=height)
                if self._is_position_available(position):
                    return position
        
        # Try expanding grid height if no position found
        self._expand_grid_height(self._grid_height + height)
        for y in range(self._grid_height - height, self._grid_height - height + 1):
            for x in range(self._grid_width - width + 1):
                position = WidgetPosition(x=x, y=y, width=width, height=height)
                if self._is_position_available(position):
                    return position
        
        return None
    
    def _place_widget_in_grid(self, widget: DashboardWidget) -> None:
        """Place widget in layout grid."""
        position = widget.config.position
        
        for y in range(position.y, position.y + position.height):
            for x in range(position.x, position.x + position.width):
                self._layout_grid[y][x] = widget.id
    
    def _remove_widget_from_grid(self, widget: DashboardWidget) -> None:
        """Remove widget from layout grid."""
        position = widget.config.position
        
        for y in range(position.y, position.y + position.height):
            for x in range(position.x, position.x + position.width):
                if (y < self._grid_height and x < self._grid_width and
                    self._layout_grid[y][x] == widget.id):
                    self._layout_grid[y][x] = None
    
    def _expand_grid_height(self, new_height: int) -> None:
        """Expand grid height if needed."""
        if new_height > self._grid_height:
            for _ in range(new_height - self._grid_height):
                self._layout_grid.append([None for _ in range(self._grid_width)])
            self._grid_height = new_height
    
    def _handle_widget_data_change(self, widget: DashboardWidget, data: Dict[str, Any]) -> None:
        """Handle widget data change events."""
        if self._on_widget_change:
            self._on_widget_change(self, widget)
    
    def _handle_widget_error(self, widget: DashboardWidget, error: str) -> None:
        """Handle widget error events."""
        logger.warning(f"Widget error: {widget.id} - {error}")
        if self._on_widget_change:
            self._on_widget_change(self, widget)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert dashboard to dictionary representation."""
        return {
            "id": str(self.id),
            "name": self.name,
            "layout": self.get_layout_data(),
            "widgets": [widget.to_dict() for widget in self._widgets.values()],
            "created_at": datetime.utcnow().isoformat()  # Would be stored in config
        }