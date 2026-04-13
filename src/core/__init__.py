"""
Core package for PII De-identification System

This package contains the core functionality for:
- Configuration management
- Model management
- Document processing
- Database operations
- Utility functions
"""

from .config.settings import Settings
from .models.model_manager import ModelManager
from .processing.document_factory import DocumentFactory
from .database.models import Base, Job, PIIDetection, RedactionAction, AuditLog

__all__ = [
    "Settings",
    "ModelManager",
    "DocumentFactory", 
    "Base",
    "Job",
    "PIIDetection",
    "RedactionAction",
    "AuditLog",
]
