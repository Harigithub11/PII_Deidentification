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
from .processors.document_processor import DocumentProcessor
from .database.models import Base, Job, PIIDetection, RedactionAction, AuditLog

__all__ = [
    "Settings",
    "ModelManager",
    "DocumentProcessor", 
    "Base",
    "Job",
    "PIIDetection",
    "RedactionAction",
    "AuditLog",
]
