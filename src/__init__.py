"""
PII De-identification System

A local AI-powered system for detecting and anonymizing Personally Identifiable Information (PII)
in documents using only free and open-source technologies.

Author: Team 404fixed!
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Team 404fixed!"
__email__ = "team@404fixed.com"

# Core imports
from .core.config.settings import Settings
from .core.models.model_manager import ModelManager
from .core.processors.document_processor import DocumentProcessor

# API imports
from .api.main import create_app

# CLI imports
from .cli.main import main as cli_main

__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "Settings",
    "ModelManager", 
    "DocumentProcessor",
    "create_app",
    "cli_main",
]
