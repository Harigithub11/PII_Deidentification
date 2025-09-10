"""
API Module for PII De-identification System

This module provides FastAPI endpoints for document upload, processing, OCR, PII detection,
visual PII detection, spaCy NLP analysis, unified document-PII processing, policy management,
business intelligence dashboards, reporting, and authentication.
"""

from .document_upload import router as document_router
from .auth import router as auth_router
from .ocr_detection import router as ocr_router
from .pii_detection import router as pii_router
from .visual_pii_detection import router as visual_pii_router
from .spacy_analysis import router as nlp_router
from .document_pii_processing import router as document_pii_router
from .policy_management import router as policy_router
from .redaction import router as redaction_router
from .dashboard import router as dashboard_router
from .reporting import router as reporting_router
from .user_management import router as user_management_router
from .compliance import router as compliance_router
from .system import router as system_router
from .integrations import router as integrations_router
from .component_monitoring import router as component_monitoring_router

__all__ = [
    "document_router", 
    "auth_router", 
    "ocr_router",
    "pii_router",
    "visual_pii_router",
    "nlp_router",
    "document_pii_router",
    "policy_router",
    "redaction_router",
    "dashboard_router",
    "reporting_router",
    "user_management_router",
    "compliance_router",
    "system_router",
    "integrations_router",
    "component_monitoring_router"
]