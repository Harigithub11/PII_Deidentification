"""
Visualization Engine

Handles chart generation, data formatting, and visualization configuration
for dashboard widgets and reporting components.
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field
import json
import base64
from io import BytesIO

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ChartType(str, Enum):
    """Types of charts supported by the visualization engine."""
    # Basic charts
    LINE = "line"
    BAR = "bar"
    COLUMN = "column"
    PIE = "pie"
    DONUT = "donut"
    AREA = "area"
    
    # Advanced charts
    SCATTER = "scatter"
    BUBBLE = "bubble"
    HISTOGRAM = "histogram"
    BOX_PLOT = "box_plot"
    VIOLIN_PLOT = "violin_plot"
    
    # Time series
    TIME_SERIES = "time_series"
    CANDLESTICK = "candlestick"
    TIMELINE = "timeline"
    
    # Specialized
    HEATMAP = "heatmap"
    TREEMAP = "treemap"
    SANKEY = "sankey"
    FUNNEL = "funnel"
    GAUGE = "gauge"
    RADAR = "radar"
    
    # Maps and geo
    CHOROPLETH = "choropleth"
    SCATTER_MAP = "scatter_map"
    
    # Tables and text
    TABLE = "table"
    METRIC = "metric"
    TEXT = "text"


class ColorScheme(str, Enum):
    """Color schemes for visualizations."""
    DEFAULT = "default"
    BLUE = "blue"
    GREEN = "green"
    RED = "red"
    PURPLE = "purple"
    ORANGE = "orange"
    TEAL = "teal"
    RAINBOW = "rainbow"
    MONOCHROME = "monochrome"
    BUSINESS = "business"
    DARK = "dark"
    LIGHT = "light"


@dataclass
class ChartAxis:
    """Configuration for chart axis."""
    title: str = ""
    type: str = "linear"  # linear, log, category, datetime
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    tick_format: str = "auto"
    grid_lines: bool = True
    show_axis: bool = True
    reverse: bool = False


@dataclass
class ChartLegend:
    """Configuration for chart legend."""
    show: bool = True
    position: str = "right"  # top, bottom, left, right
    align: str = "center"  # start, center, end
    orientation: str = "vertical"  # vertical, horizontal
    clickable: bool = True


class ChartConfiguration(BaseModel):
    """Complete configuration for chart visualization."""
    
    id: UUID = Field(default_factory=uuid4)
    chart_type: ChartType
    title: str = ""
    subtitle: str = ""
    
    # Visual appearance
    width: int = 600
    height: int = 400
    color_scheme: ColorScheme = ColorScheme.DEFAULT
    custom_colors: List[str] = Field(default_factory=list)
    background_color: str = "transparent"
    
    # Axes configuration
    x_axis: ChartAxis = Field(default_factory=ChartAxis)
    y_axis: ChartAxis = Field(default_factory=ChartAxis)
    
    # Legend and labels
    legend: ChartLegend = Field(default_factory=ChartLegend)
    show_values: bool = False
    value_format: str = "auto"
    
    # Interactivity
    interactive: bool = True
    zoom_enabled: bool = False
    pan_enabled: bool = False
    tooltip_enabled: bool = True
    click_events: bool = False
    
    # Animation
    animate: bool = True
    animation_duration: int = 1000  # milliseconds
    
    # Chart-specific options
    stacked: bool = False  # For bar/area charts
    smooth_lines: bool = True  # For line charts
    fill_area: bool = False  # For line/area charts
    show_dots: bool = True  # For line/scatter charts
    
    # Specialized options
    gauge_min: float = 0  # For gauge charts
    gauge_max: float = 100
    pie_inner_radius: float = 0  # For donut charts (0 = pie, >0 = donut)
    
    # Data formatting
    time_format: str = "%Y-%m-%d"  # For time series
    number_format: str = ",.0f"
    percentage_format: str = ".1%"
    
    # Export options
    export_formats: List[str] = Field(default_factory=lambda: ["png", "svg", "pdf"])
    
    # Responsive settings
    responsive: bool = True
    maintain_aspect_ratio: bool = True
    
    # Custom styling
    custom_css: str = ""
    theme: str = "default"


@dataclass 
class ChartDataSeries:
    """Data series for chart visualization."""
    name: str
    data: List[Dict[str, Any]]
    type: Optional[ChartType] = None  # Override chart type for this series
    color: Optional[str] = None
    visible: bool = True
    y_axis: int = 0  # Which y-axis to use (0 = primary, 1 = secondary)


@dataclass
class VisualizationData:
    """Complete data package for visualization."""
    series: List[ChartDataSeries]
    categories: List[str] = field(default_factory=list)  # X-axis categories
    metadata: Dict[str, Any] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.utcnow)


class ChartRenderer:
    """
    Handles rendering of individual chart types with data formatting
    and visualization generation.
    """
    
    def __init__(self):
        self._color_palettes = {
            ColorScheme.DEFAULT: ["#3498db", "#e74c3c", "#2ecc71", "#f39c12", "#9b59b6", "#1abc9c"],
            ColorScheme.BLUE: ["#1f77b4", "#aec7e8", "#1f77b4", "#c5dbf1", "#08519c", "#6baed6"],
            ColorScheme.GREEN: ["#2ca02c", "#98df8a", "#2ca02c", "#c5e2c5", "#1f8a1f", "#7bcf7b"],
            ColorScheme.BUSINESS: ["#2c3e50", "#34495e", "#7f8c8d", "#bdc3c7", "#ecf0f1", "#d5dbdb"],
        }
    
    async def render_chart(self,
                          config: ChartConfiguration,
                          data: VisualizationData,
                          output_format: str = "json") -> Dict[str, Any]:
        """
        Render chart with given configuration and data.
        
        Args:
            config: Chart configuration
            data: Visualization data
            output_format: Output format (json, html, svg, png)
            
        Returns:
            Rendered chart data/markup
        """
        try:
            # Validate inputs
            self._validate_chart_inputs(config, data)
            
            # Format data for chart type
            formatted_data = self._format_data_for_chart_type(config.chart_type, data)
            
            # Generate chart specification
            chart_spec = await self._generate_chart_specification(config, formatted_data)
            
            # Render based on output format
            if output_format == "json":
                return chart_spec
            elif output_format == "html":
                return await self._render_html_chart(chart_spec, config)
            elif output_format == "svg":
                return await self._render_svg_chart(chart_spec, config)
            elif output_format == "png":
                return await self._render_image_chart(chart_spec, config, "png")
            else:
                raise ValueError(f"Unsupported output format: {output_format}")
                
        except Exception as e:
            logger.error(f"Chart rendering failed: {e}")
            return self._generate_error_chart(str(e))
    
    def _validate_chart_inputs(self, config: ChartConfiguration, data: VisualizationData) -> None:
        """Validate chart configuration and data."""
        if not data.series:
            raise ValueError("At least one data series is required")
        
        # Check data compatibility with chart type
        if config.chart_type in [ChartType.PIE, ChartType.DONUT] and len(data.series) > 1:
            logger.warning("Pie/donut charts work best with single data series")
        
        # Validate data structure
        for series in data.series:
            if not series.data:
                raise ValueError(f"Series '{series.name}' has no data")
    
    def _format_data_for_chart_type(self, chart_type: ChartType, data: VisualizationData) -> Dict[str, Any]:
        """Format data according to chart type requirements."""
        
        if chart_type in [ChartType.LINE, ChartType.AREA, ChartType.BAR, ChartType.COLUMN]:
            return self._format_xy_data(data)
        elif chart_type in [ChartType.PIE, ChartType.DONUT]:
            return self._format_pie_data(data)
        elif chart_type == ChartType.SCATTER:
            return self._format_scatter_data(data)
        elif chart_type == ChartType.HEATMAP:
            return self._format_heatmap_data(data)
        elif chart_type == ChartType.TIME_SERIES:
            return self._format_time_series_data(data)
        elif chart_type == ChartType.TABLE:
            return self._format_table_data(data)
        else:
            # Default to XY format
            return self._format_xy_data(data)
    
    def _format_xy_data(self, data: VisualizationData) -> Dict[str, Any]:
        """Format data for XY-based charts (line, bar, area, etc.)."""
        series_data = []
        
        for series in data.series:
            formatted_series = {
                "name": series.name,
                "data": [],
                "color": series.color,
                "visible": series.visible
            }
            
            # Convert data points
            for point in series.data:
                if "x" in point and "y" in point:
                    formatted_series["data"].append([point["x"], point["y"]])
                elif "value" in point:
                    # Use index as x if no x specified
                    x_val = point.get("category", len(formatted_series["data"]))
                    formatted_series["data"].append([x_val, point["value"]])
            
            series_data.append(formatted_series)
        
        return {
            "series": series_data,
            "categories": data.categories,
            "type": "xy"
        }
    
    def _format_pie_data(self, data: VisualizationData) -> Dict[str, Any]:
        """Format data for pie/donut charts."""
        if not data.series:
            return {"series": [], "type": "pie"}
        
        # Use first series for pie chart
        series = data.series[0]
        pie_data = []
        
        for point in series.data:
            name = point.get("name", point.get("category", "Unknown"))
            value = point.get("value", point.get("y", 0))
            pie_data.append({"name": name, "value": value})
        
        return {
            "series": [{"name": series.name, "data": pie_data}],
            "type": "pie"
        }
    
    def _format_scatter_data(self, data: VisualizationData) -> Dict[str, Any]:
        """Format data for scatter plots."""
        series_data = []
        
        for series in data.series:
            scatter_points = []
            
            for point in series.data:
                x = point.get("x", 0)
                y = point.get("y", 0)
                size = point.get("size", point.get("z", 10))  # For bubble charts
                
                scatter_points.append({
                    "x": x,
                    "y": y, 
                    "size": size,
                    "name": point.get("name", "")
                })
            
            series_data.append({
                "name": series.name,
                "data": scatter_points,
                "color": series.color
            })
        
        return {
            "series": series_data,
            "type": "scatter"
        }
    
    def _format_heatmap_data(self, data: VisualizationData) -> Dict[str, Any]:
        """Format data for heatmap visualization."""
        if not data.series:
            return {"series": [], "type": "heatmap"}
        
        series = data.series[0]
        heatmap_data = []
        
        for point in series.data:
            x = point.get("x", 0)
            y = point.get("y", 0)
            value = point.get("value", point.get("z", 0))
            
            heatmap_data.append([x, y, value])
        
        return {
            "series": [{"name": series.name, "data": heatmap_data}],
            "type": "heatmap"
        }
    
    def _format_time_series_data(self, data: VisualizationData) -> Dict[str, Any]:
        """Format data for time series charts."""
        series_data = []
        
        for series in data.series:
            time_points = []
            
            for point in series.data:
                timestamp = point.get("timestamp", point.get("x"))
                value = point.get("value", point.get("y", 0))
                
                # Convert timestamp to milliseconds if needed
                if isinstance(timestamp, datetime):
                    timestamp = int(timestamp.timestamp() * 1000)
                elif isinstance(timestamp, str):
                    # Try to parse datetime string
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        timestamp = int(dt.timestamp() * 1000)
                    except:
                        timestamp = 0
                
                time_points.append([timestamp, value])
            
            # Sort by timestamp
            time_points.sort(key=lambda x: x[0])
            
            series_data.append({
                "name": series.name,
                "data": time_points,
                "color": series.color
            })
        
        return {
            "series": series_data,
            "type": "time_series"
        }
    
    def _format_table_data(self, data: VisualizationData) -> Dict[str, Any]:
        """Format data for table display."""
        if not data.series:
            return {"headers": [], "rows": [], "type": "table"}
        
        # Extract headers from first data point
        headers = []
        if data.series[0].data:
            headers = list(data.series[0].data[0].keys())
        
        # Extract rows
        rows = []
        for series in data.series:
            for point in series.data:
                row = [point.get(header, "") for header in headers]
                rows.append(row)
        
        return {
            "headers": headers,
            "rows": rows,
            "type": "table"
        }
    
    async def _generate_chart_specification(self,
                                           config: ChartConfiguration,
                                           formatted_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate chart specification for rendering."""
        
        # Get colors for series
        colors = self._get_colors_for_chart(config, len(formatted_data.get("series", [])))
        
        # Base chart specification
        chart_spec = {
            "chart": {
                "type": config.chart_type.value,
                "width": config.width,
                "height": config.height,
                "backgroundColor": config.background_color,
                "animation": {
                    "enabled": config.animate,
                    "duration": config.animation_duration
                },
                "interactive": config.interactive,
                "responsive": config.responsive
            },
            "title": {
                "text": config.title,
                "subtitle": config.subtitle
            },
            "colors": colors,
            "data": formatted_data,
            "plotOptions": self._get_plot_options(config),
            "tooltip": {
                "enabled": config.tooltip_enabled,
                "format": config.value_format
            },
            "legend": {
                "enabled": config.legend.show,
                "position": config.legend.position,
                "align": config.legend.align,
                "orientation": config.legend.orientation
            }
        }
        
        # Add axes configuration for applicable chart types
        if config.chart_type not in [ChartType.PIE, ChartType.DONUT, ChartType.TABLE]:
            chart_spec["xAxis"] = {
                "title": config.x_axis.title,
                "type": config.x_axis.type,
                "gridLines": config.x_axis.grid_lines,
                "visible": config.x_axis.show_axis,
                "tickFormat": config.x_axis.tick_format
            }
            
            chart_spec["yAxis"] = {
                "title": config.y_axis.title,
                "type": config.y_axis.type,
                "gridLines": config.y_axis.grid_lines,
                "visible": config.y_axis.show_axis,
                "min": config.y_axis.min_value,
                "max": config.y_axis.max_value,
                "tickFormat": config.y_axis.tick_format
            }
        
        return chart_spec
    
    def _get_colors_for_chart(self, config: ChartConfiguration, series_count: int) -> List[str]:
        """Get color palette for chart based on configuration."""
        if config.custom_colors:
            return config.custom_colors
        
        palette = self._color_palettes.get(config.color_scheme, self._color_palettes[ColorScheme.DEFAULT])
        
        # Extend palette if needed
        if series_count > len(palette):
            extended_palette = palette * ((series_count // len(palette)) + 1)
            return extended_palette[:series_count]
        
        return palette[:series_count]
    
    def _get_plot_options(self, config: ChartConfiguration) -> Dict[str, Any]:
        """Get plot-specific options based on chart configuration."""
        options = {}
        
        if config.chart_type in [ChartType.BAR, ChartType.COLUMN]:
            options["bar"] = {
                "stacked": config.stacked
            }
        elif config.chart_type == ChartType.LINE:
            options["line"] = {
                "smooth": config.smooth_lines,
                "showDots": config.show_dots,
                "fillArea": config.fill_area
            }
        elif config.chart_type == ChartType.AREA:
            options["area"] = {
                "stacked": config.stacked,
                "smooth": config.smooth_lines
            }
        elif config.chart_type in [ChartType.PIE, ChartType.DONUT]:
            options["pie"] = {
                "innerRadius": config.pie_inner_radius,
                "showValues": config.show_values
            }
        elif config.chart_type == ChartType.GAUGE:
            options["gauge"] = {
                "min": config.gauge_min,
                "max": config.gauge_max
            }
        
        return options
    
    async def _render_html_chart(self, chart_spec: Dict[str, Any], config: ChartConfiguration) -> Dict[str, Any]:
        """Render chart as HTML with embedded JavaScript."""
        
        html_template = f"""
        <div id="chart-{config.id}" style="width: {config.width}px; height: {config.height}px;"></div>
        <script>
            // Chart specification would be used here with a charting library like Chart.js, D3, or Plotly
            const chartSpec = {json.dumps(chart_spec)};
            // renderChart('chart-{config.id}', chartSpec);
        </script>
        """
        
        return {
            "format": "html",
            "content": html_template,
            "chart_spec": chart_spec
        }
    
    async def _render_svg_chart(self, chart_spec: Dict[str, Any], config: ChartConfiguration) -> Dict[str, Any]:
        """Render chart as SVG."""
        # This would generate SVG markup based on chart specification
        # For now, return placeholder SVG
        svg_content = f"""
        <svg width="{config.width}" height="{config.height}" xmlns="http://www.w3.org/2000/svg">
            <rect width="100%" height="100%" fill="{config.background_color or 'white'}"/>
            <text x="50%" y="50%" text-anchor="middle" fill="black">
                Chart: {config.title or 'Untitled'}
            </text>
        </svg>
        """
        
        return {
            "format": "svg",
            "content": svg_content,
            "chart_spec": chart_spec
        }
    
    async def _render_image_chart(self,
                                chart_spec: Dict[str, Any],
                                config: ChartConfiguration,
                                format: str) -> Dict[str, Any]:
        """Render chart as image (PNG, JPEG, etc.)."""
        # This would use a library like Playwright, Selenium, or server-side chart rendering
        # For now, return placeholder image data
        
        placeholder_image = self._generate_placeholder_image(config.width, config.height, config.title or "Chart")
        
        return {
            "format": format,
            "content": placeholder_image,
            "content_type": f"image/{format}",
            "chart_spec": chart_spec
        }
    
    def _generate_placeholder_image(self, width: int, height: int, title: str) -> str:
        """Generate placeholder image as base64 string."""
        # This would generate actual image data
        # For now, return a simple base64 encoded placeholder
        return "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    
    def _generate_error_chart(self, error_message: str) -> Dict[str, Any]:
        """Generate error chart when rendering fails."""
        return {
            "format": "json",
            "error": True,
            "message": error_message,
            "chart_spec": {
                "chart": {"type": "error"},
                "title": {"text": "Chart Error"},
                "error_message": error_message
            }
        }


class VisualizationEngine:
    """
    Main visualization engine that coordinates chart rendering,
    manages renderers, and handles visualization requests.
    """
    
    def __init__(self):
        self._chart_renderer = ChartRenderer()
        self._template_cache: Dict[str, ChartConfiguration] = {}
        self._render_cache: Dict[str, Tuple[Dict[str, Any], datetime]] = {}
        
        # Performance tracking
        self._render_count = 0
        self._cache_hits = 0
        self._cache_misses = 0
        
        logger.info("Visualization Engine initialized")
    
    async def render_visualization(self,
                                 config: ChartConfiguration,
                                 data: VisualizationData,
                                 output_format: str = "json",
                                 use_cache: bool = True) -> Dict[str, Any]:
        """
        Render visualization with given configuration and data.
        
        Args:
            config: Chart configuration
            data: Visualization data
            output_format: Output format
            use_cache: Whether to use render cache
            
        Returns:
            Rendered visualization
        """
        try:
            # Generate cache key
            if use_cache:
                cache_key = self._generate_render_cache_key(config, data, output_format)
                cached_result = self._get_cached_render(cache_key)
                if cached_result:
                    self._cache_hits += 1
                    return cached_result
            
            self._cache_misses += 1
            self._render_count += 1
            
            # Render chart
            result = await self._chart_renderer.render_chart(config, data, output_format)
            
            # Cache result
            if use_cache:
                self._cache_render_result(cache_key, result)
            
            logger.debug(f"Visualization rendered: {config.chart_type} ({output_format})")
            return result
            
        except Exception as e:
            logger.error(f"Visualization rendering failed: {e}")
            return {
                "error": True,
                "message": str(e),
                "format": output_format
            }
    
    def create_chart_config_template(self,
                                   template_name: str,
                                   chart_type: ChartType,
                                   **kwargs) -> ChartConfiguration:
        """Create and save chart configuration template."""
        
        config = ChartConfiguration(
            chart_type=chart_type,
            **kwargs
        )
        
        self._template_cache[template_name] = config
        logger.info(f"Chart template created: {template_name}")
        
        return config
    
    def get_chart_template(self, template_name: str) -> Optional[ChartConfiguration]:
        """Get chart configuration template by name."""
        return self._template_cache.get(template_name)
    
    def list_chart_templates(self) -> List[str]:
        """List available chart templates."""
        return list(self._template_cache.keys())
    
    async def create_dashboard_visualization(self,
                                           widget_data: List[Dict[str, Any]],
                                           layout_config: Dict[str, Any]) -> Dict[str, Any]:
        """Create visualization for entire dashboard layout."""
        
        rendered_widgets = []
        
        for widget in widget_data:
            try:
                # Extract chart configuration
                config = self._extract_chart_config_from_widget(widget)
                
                # Extract visualization data
                vis_data = self._extract_visualization_data_from_widget(widget)
                
                # Render widget visualization
                result = await self.render_visualization(config, vis_data, "json", use_cache=True)
                
                rendered_widgets.append({
                    "widget_id": widget.get("id"),
                    "visualization": result,
                    "position": widget.get("position", {}),
                    "size": widget.get("size", "medium")
                })
                
            except Exception as e:
                logger.error(f"Failed to render widget {widget.get('id')}: {e}")
                rendered_widgets.append({
                    "widget_id": widget.get("id"),
                    "error": str(e)
                })
        
        return {
            "layout": layout_config,
            "widgets": rendered_widgets,
            "rendered_at": datetime.utcnow().isoformat()
        }
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get visualization engine performance metrics."""
        total_requests = self._cache_hits + self._cache_misses
        hit_ratio = self._cache_hits / total_requests if total_requests > 0 else 0
        
        return {
            "total_renders": self._render_count,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cache_hit_ratio": round(hit_ratio, 4),
            "cached_renders": len(self._render_cache),
            "template_count": len(self._template_cache)
        }
    
    def _extract_chart_config_from_widget(self, widget: Dict[str, Any]) -> ChartConfiguration:
        """Extract chart configuration from widget data."""
        
        chart_type_str = widget.get("chart_type", widget.get("type", "line"))
        try:
            chart_type = ChartType(chart_type_str)
        except ValueError:
            chart_type = ChartType.LINE
        
        return ChartConfiguration(
            chart_type=chart_type,
            title=widget.get("title", ""),
            width=widget.get("width", 600),
            height=widget.get("height", 400),
            **widget.get("chart_config", {})
        )
    
    def _extract_visualization_data_from_widget(self, widget: Dict[str, Any]) -> VisualizationData:
        """Extract visualization data from widget data."""
        
        data = widget.get("data", {})
        series = []
        
        if "series" in data:
            # Multiple series format
            for series_data in data["series"]:
                series.append(ChartDataSeries(
                    name=series_data.get("name", "Series"),
                    data=series_data.get("data", []),
                    color=series_data.get("color")
                ))
        elif "data" in data:
            # Single series format
            series.append(ChartDataSeries(
                name=widget.get("title", "Data"),
                data=data["data"]
            ))
        else:
            # Direct data format
            series.append(ChartDataSeries(
                name=widget.get("title", "Data"),
                data=[data] if isinstance(data, dict) else []
            ))
        
        return VisualizationData(
            series=series,
            categories=data.get("categories", []),
            metadata=data.get("metadata", {})
        )
    
    def _generate_render_cache_key(self,
                                 config: ChartConfiguration,
                                 data: VisualizationData,
                                 output_format: str) -> str:
        """Generate cache key for render result."""
        import hashlib
        
        # Create hash from configuration and data
        cache_data = {
            "config": config.dict(),
            "data_hash": self._hash_visualization_data(data),
            "format": output_format
        }
        
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.md5(cache_string.encode()).hexdigest()
    
    def _hash_visualization_data(self, data: VisualizationData) -> str:
        """Generate hash for visualization data."""
        import hashlib
        
        data_str = json.dumps({
            "series_count": len(data.series),
            "categories": data.categories,
            "metadata": data.metadata
        }, sort_keys=True)
        
        return hashlib.md5(data_str.encode()).hexdigest()
    
    def _get_cached_render(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached render result if not expired."""
        if cache_key in self._render_cache:
            result, cached_at = self._render_cache[cache_key]
            # Cache for 10 minutes
            if datetime.utcnow() - cached_at < timedelta(minutes=10):
                return result
            else:
                del self._render_cache[cache_key]
        return None
    
    def _cache_render_result(self, cache_key: str, result: Dict[str, Any]) -> None:
        """Cache render result."""
        self._render_cache[cache_key] = (result, datetime.utcnow())