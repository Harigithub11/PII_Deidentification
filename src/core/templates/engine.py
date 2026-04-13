"""
Template Engine

Core engine for template management, rendering, and configuration processing
with support for multiple template formats and dynamic content generation.
"""

import logging
import asyncio
import json
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable, Type
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
import tempfile
import shutil

from pydantic import BaseModel, Field, validator
from jinja2 import Environment, FileSystemLoader, Template, TemplateError
from sqlalchemy.orm import Session

from ..database.session import get_db_session, transaction_scope
from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class TemplateType(str, Enum):
    """Types of templates supported."""
    REPORT = "report"
    DASHBOARD = "dashboard"
    EMAIL = "email"
    DOCUMENT = "document"
    CHART = "chart"
    TABLE = "table"
    CUSTOM = "custom"


class TemplateFormat(str, Enum):
    """Template format types."""
    HTML = "html"
    JINJA2 = "jinja2"
    MARKDOWN = "markdown"
    JSON = "json"
    XML = "xml"
    YAML = "yaml"
    LATEX = "latex"


class OutputFormat(str, Enum):
    """Output formats for rendered templates."""
    HTML = "html"
    PDF = "pdf"
    DOCX = "docx"
    EXCEL = "excel"
    JSON = "json"
    CSV = "csv"
    TXT = "txt"
    XML = "xml"


class TemplateStatus(str, Enum):
    """Template status."""
    DRAFT = "draft"
    ACTIVE = "active"
    ARCHIVED = "archived"
    DEPRECATED = "deprecated"


@dataclass
class TemplateMetrics:
    """Metrics for template usage and performance."""
    usage_count: int = 0
    render_count: int = 0
    avg_render_time_ms: float = 0.0
    total_render_time_ms: int = 0
    error_count: int = 0
    last_used: Optional[datetime] = None
    last_rendered: Optional[datetime] = None
    success_rate: float = 1.0


class TemplateConfig(BaseModel):
    """Configuration for template creation and management."""
    
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    template_type: TemplateType
    template_format: TemplateFormat = TemplateFormat.JINJA2
    
    # Content
    content: str = Field(..., min_length=1)
    variables: Dict[str, Any] = Field(default_factory=dict)
    default_values: Dict[str, Any] = Field(default_factory=dict)
    
    # Styling and layout
    styles: Dict[str, Any] = Field(default_factory=dict)
    layout: Dict[str, Any] = Field(default_factory=dict)
    theme: str = "default"
    
    # Output configuration
    supported_formats: List[OutputFormat] = Field(default_factory=lambda: [OutputFormat.HTML])
    default_format: OutputFormat = OutputFormat.HTML
    
    # Access control
    owner_id: UUID
    shared_with: List[UUID] = Field(default_factory=list)
    is_public: bool = False
    
    # Metadata
    category: str = "general"
    tags: List[str] = Field(default_factory=list)
    version: str = "1.0.0"
    status: TemplateStatus = TemplateStatus.ACTIVE
    
    # Settings
    cache_enabled: bool = True
    cache_duration_minutes: int = 30
    validation_enabled: bool = True
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    @validator('content')
    def validate_content(cls, v):
        if not v or not v.strip():
            raise ValueError('Template content cannot be empty')
        return v
    
    @validator('name')
    def validate_name(cls, v):
        if not v or not v.strip():
            raise ValueError('Template name is required')
        return v.strip()


@dataclass
class RenderContext:
    """Context for template rendering."""
    template_id: UUID
    variables: Dict[str, Any] = field(default_factory=dict)
    output_format: OutputFormat = OutputFormat.HTML
    user_id: Optional[UUID] = None
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    render_options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RenderResult:
    """Result of template rendering operation."""
    template_id: UUID
    request_id: Optional[str]
    success: bool
    content: Optional[str] = None
    file_path: Optional[str] = None
    file_size_bytes: Optional[int] = None
    output_format: OutputFormat = OutputFormat.HTML
    render_time_ms: int = 0
    error_message: Optional[str] = None
    error_details: Dict[str, Any] = field(default_factory=dict)
    rendered_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


class TemplateEngine:
    """
    Core template engine that manages template lifecycle, rendering,
    and configuration with support for multiple template formats.
    """
    
    def __init__(self, session: Optional[Session] = None):
        self._session = session
        self._templates: Dict[UUID, TemplateConfig] = {}
        self._template_metrics: Dict[UUID, TemplateMetrics] = {}
        self._jinja_env: Optional[Environment] = None
        self._render_cache: Dict[str, Tuple[RenderResult, datetime]] = {}
        
        # Template storage
        self._template_dir = Path(tempfile.gettempdir()) / "pii_templates"
        self._template_dir.mkdir(exist_ok=True)
        
        # Performance tracking
        self._total_renders = 0
        self._cache_hits = 0
        self._cache_misses = 0
        
        # Initialize Jinja2 environment
        self._setup_jinja_environment()
        
        logger.info("Template Engine initialized")
    
    @property
    def session(self) -> Session:
        """Get current database session."""
        if self._session:
            return self._session
        return get_db_session()
    
    def _setup_jinja_environment(self) -> None:
        """Setup Jinja2 environment with custom filters and functions."""
        loader = FileSystemLoader(str(self._template_dir))
        self._jinja_env = Environment(
            loader=loader,
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom filters
        self._jinja_env.filters['datetime_format'] = self._format_datetime
        self._jinja_env.filters['number_format'] = self._format_number
        self._jinja_env.filters['currency_format'] = self._format_currency
        self._jinja_env.filters['truncate_text'] = self._truncate_text
        
        # Add global functions
        self._jinja_env.globals['now'] = datetime.utcnow
        self._jinja_env.globals['today'] = datetime.utcnow().date
        self._jinja_env.globals['uuid'] = uuid4
    
    async def create_template(self, config: TemplateConfig) -> TemplateConfig:
        """
        Create a new template with the given configuration.
        
        Args:
            config: Template configuration
            
        Returns:
            Created template configuration
        """
        try:
            # Validate template content
            await self._validate_template_content(config)
            
            # Store template
            self._templates[config.id] = config
            
            # Initialize metrics
            self._template_metrics[config.id] = TemplateMetrics()
            
            # Save template file for Jinja2
            if config.template_format == TemplateFormat.JINJA2:
                await self._save_template_file(config)
            
            logger.info(f"Template created: {config.id} - {config.name}")
            return config
            
        except Exception as e:
            logger.error(f"Failed to create template {config.id}: {e}")
            raise
    
    async def get_template(self, template_id: UUID) -> Optional[TemplateConfig]:
        """Get template configuration by ID."""
        return self._templates.get(template_id)
    
    async def update_template(self, template_id: UUID, updates: Dict[str, Any]) -> TemplateConfig:
        """Update template configuration."""
        if template_id not in self._templates:
            raise ValueError(f"Template not found: {template_id}")
        
        config = self._templates[template_id]
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(config, key):
                setattr(config, key, value)
        
        config.updated_at = datetime.utcnow()
        
        # Re-validate if content changed
        if 'content' in updates:
            await self._validate_template_content(config)
            
            # Update template file
            if config.template_format == TemplateFormat.JINJA2:
                await self._save_template_file(config)
        
        logger.info(f"Template updated: {template_id}")
        return config
    
    async def delete_template(self, template_id: UUID) -> bool:
        """Delete template and clean up resources."""
        if template_id not in self._templates:
            return False
        
        config = self._templates[template_id]
        
        # Remove template file
        template_file = self._template_dir / f"{template_id}.html"
        if template_file.exists():
            template_file.unlink()
        
        # Clean up cache
        self._clear_template_cache(template_id)
        
        # Remove from collections
        del self._templates[template_id]
        del self._template_metrics[template_id]
        
        logger.info(f"Template deleted: {template_id}")
        return True
    
    async def render_template(self, context: RenderContext) -> RenderResult:
        """
        Render template with given context.
        
        Args:
            context: Rendering context with variables and options
            
        Returns:
            Render result with content or file
        """
        start_time = datetime.utcnow()
        
        try:
            # Get template
            template_config = await self.get_template(context.template_id)
            if not template_config:
                raise ValueError(f"Template not found: {context.template_id}")
            
            # Check cache
            cache_key = self._generate_cache_key(context)
            if template_config.cache_enabled:
                cached_result = self._get_cached_result(cache_key, template_config.cache_duration_minutes)
                if cached_result:
                    self._cache_hits += 1
                    return cached_result
            
            self._cache_misses += 1
            self._total_renders += 1
            
            # Render template
            if template_config.template_format == TemplateFormat.JINJA2:
                result = await self._render_jinja_template(template_config, context)
            elif template_config.template_format == TemplateFormat.HTML:
                result = await self._render_html_template(template_config, context)
            elif template_config.template_format == TemplateFormat.MARKDOWN:
                result = await self._render_markdown_template(template_config, context)
            else:
                result = await self._render_generic_template(template_config, context)
            
            # Calculate render time
            render_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            result.render_time_ms = int(render_time)
            
            # Update metrics
            self._update_template_metrics(context.template_id, render_time, success=True)
            
            # Cache result
            if template_config.cache_enabled:
                self._cache_render_result(cache_key, result)
            
            logger.info(f"Template rendered: {context.template_id} in {render_time}ms")
            return result
            
        except Exception as e:
            render_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            logger.error(f"Template rendering failed: {context.template_id} - {e}")
            
            # Update error metrics
            self._update_template_metrics(context.template_id, render_time, success=False)
            
            return RenderResult(
                template_id=context.template_id,
                request_id=context.request_id,
                success=False,
                output_format=context.output_format,
                render_time_ms=int(render_time),
                error_message=str(e),
                error_details={"exception_type": type(e).__name__}
            )
    
    async def _render_jinja_template(self, config: TemplateConfig, context: RenderContext) -> RenderResult:
        """Render Jinja2 template."""
        try:
            # Load template
            template = self._jinja_env.get_template(f"{config.id}.html")
            
            # Merge variables
            render_vars = {**config.default_values, **context.variables}
            
            # Add template metadata
            render_vars.update({
                'template_id': str(config.id),
                'template_name': config.name,
                'render_time': datetime.utcnow().isoformat(),
                'user_id': str(context.user_id) if context.user_id else None
            })
            
            # Render content
            rendered_content = template.render(**render_vars)
            
            # Convert to different formats if needed
            if context.output_format != OutputFormat.HTML:
                rendered_content = await self._convert_output_format(
                    rendered_content, OutputFormat.HTML, context.output_format
                )
            
            return RenderResult(
                template_id=context.template_id,
                request_id=context.request_id,
                success=True,
                content=rendered_content,
                output_format=context.output_format,
                metadata={"variables_used": list(render_vars.keys())}
            )
            
        except TemplateError as e:
            raise ValueError(f"Template rendering error: {e}")
    
    async def _render_html_template(self, config: TemplateConfig, context: RenderContext) -> RenderResult:
        """Render HTML template with variable substitution."""
        content = config.content
        
        # Simple variable substitution
        render_vars = {**config.default_values, **context.variables}
        
        for key, value in render_vars.items():
            placeholder = f"{{{{{key}}}}}"
            content = content.replace(placeholder, str(value))
        
        return RenderResult(
            template_id=context.template_id,
            request_id=context.request_id,
            success=True,
            content=content,
            output_format=context.output_format,
            metadata={"variables_substituted": len(render_vars)}
        )
    
    async def _render_markdown_template(self, config: TemplateConfig, context: RenderContext) -> RenderResult:
        """Render Markdown template."""
        # This would use a markdown processor like python-markdown
        # For now, return as-is with variable substitution
        content = config.content
        render_vars = {**config.default_values, **context.variables}
        
        for key, value in render_vars.items():
            placeholder = f"{{{{{key}}}}}"
            content = content.replace(placeholder, str(value))
        
        return RenderResult(
            template_id=context.template_id,
            request_id=context.request_id,
            success=True,
            content=content,
            output_format=context.output_format
        )
    
    async def _render_generic_template(self, config: TemplateConfig, context: RenderContext) -> RenderResult:
        """Render generic template format."""
        return RenderResult(
            template_id=context.template_id,
            request_id=context.request_id,
            success=True,
            content=config.content,
            output_format=context.output_format
        )
    
    async def _convert_output_format(self, content: str, from_format: OutputFormat, to_format: OutputFormat) -> str:
        """Convert content from one format to another."""
        if from_format == to_format:
            return content
        
        # This would use libraries like:
        # - weasyprint for HTML to PDF
        # - python-docx for DOCX generation
        # - pandas for Excel/CSV
        
        # For now, return content as-is
        return content
    
    async def _validate_template_content(self, config: TemplateConfig) -> None:
        """Validate template content syntax."""
        if config.template_format == TemplateFormat.JINJA2:
            try:
                # Parse template to check syntax
                template = Template(config.content)
                # Try to render with empty context to check for basic errors
                template.render({})
            except TemplateError as e:
                raise ValueError(f"Invalid Jinja2 template: {e}")
        elif config.template_format == TemplateFormat.JSON:
            try:
                json.loads(config.content)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON template: {e}")
        elif config.template_format == TemplateFormat.YAML:
            try:
                yaml.safe_load(config.content)
            except yaml.YAMLError as e:
                raise ValueError(f"Invalid YAML template: {e}")
    
    async def _save_template_file(self, config: TemplateConfig) -> None:
        """Save template content to file for Jinja2 loader."""
        template_file = self._template_dir / f"{config.id}.html"
        template_file.write_text(config.content, encoding='utf-8')
    
    def get_template_metrics(self, template_id: UUID) -> Optional[TemplateMetrics]:
        """Get metrics for a specific template."""
        return self._template_metrics.get(template_id)
    
    def list_templates(self, 
                      template_type: Optional[TemplateType] = None,
                      status: Optional[TemplateStatus] = None,
                      category: Optional[str] = None,
                      owner_id: Optional[UUID] = None) -> List[TemplateConfig]:
        """List templates with optional filtering."""
        templates = list(self._templates.values())
        
        if template_type:
            templates = [t for t in templates if t.template_type == template_type]
        if status:
            templates = [t for t in templates if t.status == status]
        if category:
            templates = [t for t in templates if t.category == category]
        if owner_id:
            templates = [t for t in templates if t.owner_id == owner_id]
        
        return templates
    
    def get_engine_statistics(self) -> Dict[str, Any]:
        """Get comprehensive engine statistics."""
        total_templates = len(self._templates)
        total_renders = sum(metrics.render_count for metrics in self._template_metrics.values())
        avg_render_time = sum(metrics.avg_render_time_ms for metrics in self._template_metrics.values()) / max(total_templates, 1)
        
        cache_requests = self._cache_hits + self._cache_misses
        cache_hit_ratio = self._cache_hits / max(cache_requests, 1)
        
        return {
            "total_templates": total_templates,
            "templates_by_type": self._count_by_type(),
            "templates_by_status": self._count_by_status(),
            "total_renders": total_renders,
            "avg_render_time_ms": round(avg_render_time, 2),
            "cache_hit_ratio": round(cache_hit_ratio, 4),
            "cache_entries": len(self._render_cache),
            "template_storage_path": str(self._template_dir)
        }
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count templates by type."""
        counts = {}
        for template in self._templates.values():
            counts[template.template_type.value] = counts.get(template.template_type.value, 0) + 1
        return counts
    
    def _count_by_status(self) -> Dict[str, int]:
        """Count templates by status."""
        counts = {}
        for template in self._templates.values():
            counts[template.status.value] = counts.get(template.status.value, 0) + 1
        return counts
    
    def _update_template_metrics(self, template_id: UUID, render_time_ms: float, success: bool) -> None:
        """Update template usage metrics."""
        if template_id in self._template_metrics:
            metrics = self._template_metrics[template_id]
            metrics.usage_count += 1
            metrics.render_count += 1
            metrics.total_render_time_ms += int(render_time_ms)
            metrics.avg_render_time_ms = metrics.total_render_time_ms / metrics.render_count
            metrics.last_used = datetime.utcnow()
            
            if success:
                metrics.last_rendered = datetime.utcnow()
            else:
                metrics.error_count += 1
            
            # Calculate success rate
            metrics.success_rate = (metrics.render_count - metrics.error_count) / metrics.render_count
    
    def _generate_cache_key(self, context: RenderContext) -> str:
        """Generate cache key for render context."""
        import hashlib
        
        key_data = {
            "template_id": str(context.template_id),
            "variables": context.variables,
            "output_format": context.output_format.value,
            "render_options": context.render_options
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _get_cached_result(self, cache_key: str, duration_minutes: int) -> Optional[RenderResult]:
        """Get cached render result if not expired."""
        if cache_key in self._render_cache:
            result, cached_at = self._render_cache[cache_key]
            if datetime.utcnow() - cached_at < timedelta(minutes=duration_minutes):
                return result
            else:
                del self._render_cache[cache_key]
        return None
    
    def _cache_render_result(self, cache_key: str, result: RenderResult) -> None:
        """Cache render result."""
        self._render_cache[cache_key] = (result, datetime.utcnow())
    
    def _clear_template_cache(self, template_id: UUID) -> None:
        """Clear cache entries for specific template."""
        keys_to_remove = []
        for key, (result, _) in self._render_cache.items():
            if result.template_id == template_id:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self._render_cache[key]
    
    # Jinja2 custom filters
    def _format_datetime(self, value: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
        """Format datetime value."""
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except:
                return value
        return value.strftime(format_str)
    
    def _format_number(self, value: Union[int, float], decimals: int = 2) -> str:
        """Format numeric value."""
        if isinstance(value, str):
            try:
                value = float(value)
            except:
                return value
        return f"{value:,.{decimals}f}"
    
    def _format_currency(self, value: Union[int, float], symbol: str = "$") -> str:
        """Format currency value."""
        if isinstance(value, str):
            try:
                value = float(value)
            except:
                return value
        return f"{symbol}{value:,.2f}"
    
    def _truncate_text(self, text: str, length: int = 100, suffix: str = "...") -> str:
        """Truncate text to specified length."""
        if len(text) <= length:
            return text
        return text[:length - len(suffix)] + suffix
    
    async def cleanup(self) -> None:
        """Clean up resources and temporary files."""
        # Clean up template files
        if self._template_dir.exists():
            shutil.rmtree(self._template_dir)
        
        logger.info("Template Engine cleaned up")


# Global template engine instance
_template_engine: Optional[TemplateEngine] = None


def get_template_engine(session: Optional[Session] = None) -> TemplateEngine:
    """Get the global template engine instance."""
    global _template_engine
    if _template_engine is None:
        _template_engine = TemplateEngine(session)
    return _template_engine


def initialize_template_engine(session: Optional[Session] = None) -> TemplateEngine:
    """Initialize the template engine."""
    global _template_engine
    _template_engine = TemplateEngine(session)
    logger.info("Template Engine initialized successfully")
    return _template_engine