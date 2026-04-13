"""
Report Templates and Configuration Management System

This module provides comprehensive template management, visual template builder,
configuration systems, and multi-format report generation capabilities.
"""

from .engine import TemplateEngine, TemplateConfig, TemplateType
from .manager import TemplateManager, TemplateMetadata, TemplateCategory
from .builder import VisualTemplateBuilder, TemplateComponent, ComponentType
from .renderer import TemplateRenderer, RenderContext, OutputFormat
from .variables import VariableManager, VariableDefinition, VariableType
from .styles import StyleManager, StyleSheet, ThemeConfig
from .validation import TemplateValidator, ValidationResult, ValidationRule

__all__ = [
    # Core Engine
    "TemplateEngine",
    "TemplateConfig",
    "TemplateType",
    
    # Template Management
    "TemplateManager", 
    "TemplateMetadata",
    "TemplateCategory",
    
    # Visual Builder
    "VisualTemplateBuilder",
    "TemplateComponent",
    "ComponentType",
    
    # Rendering System
    "TemplateRenderer",
    "RenderContext",
    "OutputFormat",
    
    # Variable Management
    "VariableManager",
    "VariableDefinition", 
    "VariableType",
    
    # Styling System
    "StyleManager",
    "StyleSheet",
    "ThemeConfig",
    
    # Validation System
    "TemplateValidator",
    "ValidationResult",
    "ValidationRule"
]