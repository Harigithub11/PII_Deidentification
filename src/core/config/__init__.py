"""
Configuration package for PII De-identification System

This package handles all configuration management including:
- Environment settings
- Model configurations
- Policy definitions
- Database settings
"""

from .settings import Settings
from .model_config import ModelConfig

__all__ = [
    "Settings",
    "ModelConfig",
]
