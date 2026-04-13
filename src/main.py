# -*- coding: utf-8 -*-
"""
Main FastAPI Application for PII De-identification System

This module provides the main FastAPI application with multi-format document support,
business intelligence dashboards, advanced reporting, and comprehensive analytics.
"""

import logging
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse

from .api import (
    document_router, auth_router, dashboard_router, dashboard_stats_router, reporting_router,
    user_management_router, compliance_router, system_router, integrations_router,
    component_monitoring_router
)
from .core.security.middleware import setup_security_middleware
from .core.security.ssl_config import ssl_config_manager
from .core.config.settings import get_settings
from .core.dashboard import initialize_bi_engine
from .core.reporting import initialize_reporting_engine
from .core.templates import initialize_template_engine, initialize_template_manager
from .core.monitoring import initialize_component_monitor

settings = get_settings()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title="PII De-identification System",
    description="Local AI-Powered system for detecting and anonymizing PII in multi-format documents with comprehensive REST APIs, user management, compliance reporting, system monitoring, and external integrations",
    version="2.1.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None
)

# Setup security middleware (includes CORS)
setup_security_middleware(app)

# Include routers
app.include_router(auth_router)
app.include_router(document_router)
app.include_router(dashboard_router)
app.include_router(dashboard_stats_router)
app.include_router(reporting_router)
app.include_router(user_management_router)
app.include_router(compliance_router)
app.include_router(system_router)
app.include_router(integrations_router)
app.include_router(component_monitoring_router)

# Initialize new systems on startup
@app.on_event("startup")
async def startup_event():
    """Initialize all systems on application startup."""
    try:
        logger.info("Initializing PII De-identification System v2.1.0...")
        
        # Initialize Business Intelligence Engine
        initialize_bi_engine()
        logger.info("✅ Business Intelligence Engine initialized")
        
        # Initialize Reporting Engine
        initialize_reporting_engine()
        logger.info("✅ Reporting Engine initialized")
        
        # Initialize Template Engine and Manager
        initialize_template_engine()
        initialize_template_manager()
        logger.info("✅ Template System initialized")
        
        # Initialize Component Monitoring System
        component_monitor = await initialize_component_monitor()
        await component_monitor.start()
        logger.info("✅ Component Monitoring System initialized and started")
        
        logger.info("🚀 All systems initialized successfully!")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize systems: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Clean up resources on application shutdown."""
    try:
        logger.info("Shutting down PII De-identification System...")
        
        # Clean up Business Intelligence Engine
        from .core.dashboard import get_bi_engine
        bi_engine = get_bi_engine()
        await bi_engine.cleanup()
        
        # Clean up Template Engine
        from .core.templates import get_template_engine
        template_engine = get_template_engine()
        await template_engine.cleanup()
        
        # Stop Component Monitor
        from .core.monitoring import get_component_monitor
        component_monitor = get_component_monitor()
        await component_monitor.stop()
        
        logger.info("✅ System shutdown complete")
        
    except Exception as e:
        logger.error(f"❌ Error during shutdown: {e}")

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "message": "PII De-identification System is running",
        "version": "2.1.0"
    }

# Root endpoint with API information
@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint with API information."""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PII De-identification System</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .header { color: #2c3e50; }
            .feature { margin: 10px 0; }
            .endpoint { background-color: #f8f9fa; padding: 10px; margin: 5px 0; border-radius: 5px; }
            .method { font-weight: bold; color: #28a745; }
            .supported-formats { background-color: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <h1 class="header">🛡️ PII De-identification System</h1>
        <p>Local AI-Powered system for detecting and anonymizing PII in multi-format documents</p>
        
        <h2>🚀 Features</h2>
        <ul>
            <li class="feature">✅ Multi-format document support (PDF, Images, Scanned documents)</li>
            <li class="feature">✅ Automatic format detection and optimization</li>
            <li class="feature">✅ Background processing with job tracking</li>
            <li class="feature">✅ Quality enhancement for better OCR results</li>
            <li class="feature">✅ Memory-efficient processing pipeline</li>
            <li class="feature">🆕 Business Intelligence Dashboards with real-time visualization</li>
            <li class="feature">🆕 Advanced Reporting and Analytics Engine</li>
            <li class="feature">🆕 Template Management System with visual builder</li>
            <li class="feature">🆕 Comprehensive Audit Trail and Compliance Reporting</li>
            <li class="feature">🆕 User Management API with role-based access control</li>
            <li class="feature">🆕 System Management and Health Monitoring APIs</li>
            <li class="feature">🆕 External Integration Management with Webhooks</li>
            <li class="feature">🆕 Compliance and Audit APIs for regulatory requirements</li>
        </ul>
        
        <div class="supported-formats">
            <h3>📄 Supported Formats</h3>
            <p><strong>PDFs:</strong> Multi-page documents with text and image extraction</p>
            <p><strong>Images:</strong> PNG, JPG, JPEG, TIFF, TIF, BMP, WebP, GIF</p>
            <p><strong>Scanned Documents:</strong> Automatic detection with specialized optimization</p>
        </div>
        
        <h2>🔐 Authentication Endpoints</h2>
        
        <div class="endpoint">
            <span class="method">POST</span> <strong>/api/v1/auth/token</strong>
            <p>Login and get access token</p>
        </div>
        
        <div class="endpoint">
            <span class="method">POST</span> <strong>/api/v1/auth/refresh</strong>
            <p>Refresh access token</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/auth/me</strong>
            <p>Get current user information</p>
        </div>
        
        <h2>📚 Document Processing Endpoints</h2>
        
        <div class="endpoint">
            <span class="method">POST</span> <strong>/api/v1/documents/upload</strong>
            <p>Upload and optionally process documents (requires authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/documents/status/{document_id}</strong>
            <p>Get document processing status (requires authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/documents/results/{document_id}</strong>
            <p>Get processing results (requires authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/documents/formats</strong>
            <p>Get supported formats and limits</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/documents/job/{job_id}</strong>
            <p>Get background job status (requires authentication)</p>
        </div>
        
        <h2>📊 Business Intelligence Dashboard Endpoints</h2>
        
        <div class="endpoint">
            <span class="method">POST</span> <strong>/api/v1/dashboard/</strong>
            <p>Create new dashboard (requires authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/dashboard/</strong>
            <p>List available dashboards (requires authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/dashboard/{dashboard_id}/data</strong>
            <p>Get dashboard data and widgets (requires authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">WebSocket</span> <strong>/api/v1/dashboard/{dashboard_id}/ws</strong>
            <p>Real-time dashboard updates via WebSocket</p>
        </div>
        
        <h2>📋 Reporting and Analytics Endpoints</h2>
        
        <div class="endpoint">
            <span class="method">POST</span> <strong>/api/v1/reports/</strong>
            <p>Generate new report (requires authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/reports/</strong>
            <p>List available reports (requires authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/reports/{report_id}/download</strong>
            <p>Download report file (requires authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">POST</span> <strong>/api/v1/reports/templates</strong>
            <p>Create report template (requires authentication)</p>
        </div>
        
        <h2>👥 User Management Endpoints</h2>
        
        <div class="endpoint">
            <span class="method">POST</span> <strong>/api/v1/users/</strong>
            <p>Create new user (requires admin authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/users/</strong>
            <p>List all users (requires admin authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">PUT</span> <strong>/api/v1/users/{user_id}</strong>
            <p>Update user information (requires admin authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">DELETE</span> <strong>/api/v1/users/{user_id}</strong>
            <p>Delete user (requires admin authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">POST</span> <strong>/api/v1/users/{user_id}/api-keys</strong>
            <p>Generate API key for user (requires authentication)</p>
        </div>
        
        <h2>📋 Compliance & Audit Endpoints</h2>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/compliance/audit-events</strong>
            <p>Search and filter audit events (requires compliance officer role)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/compliance/statistics</strong>
            <p>Get compliance statistics and metrics (requires compliance officer role)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">POST</span> <strong>/api/v1/compliance/reports</strong>
            <p>Generate compliance report (requires compliance officer role)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/compliance/data-retention</strong>
            <p>Manage data retention policies (requires admin authentication)</p>
        </div>
        
        <h2>⚙️ System Management Endpoints</h2>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/system/health</strong>
            <p>Get comprehensive system health status</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/system/metrics</strong>
            <p>Get system performance metrics (requires admin authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/system/configuration</strong>
            <p>Get system configuration (requires admin authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">PUT</span> <strong>/api/v1/system/configuration</strong>
            <p>Update system configuration (requires admin authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">POST</span> <strong>/api/v1/system/maintenance</strong>
            <p>Schedule system maintenance (requires admin authentication)</p>
        </div>
        
        <h2>🔗 Integration Management Endpoints</h2>
        
        <div class="endpoint">
            <span class="method">POST</span> <strong>/api/v1/integrations/webhooks</strong>
            <p>Create webhook subscription (requires admin authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/integrations/webhooks</strong>
            <p>List webhook subscriptions (requires admin authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">POST</span> <strong>/api/v1/integrations/external-api</strong>
            <p>Make external API call (requires admin authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <strong>/api/v1/integrations/templates</strong>
            <p>Get integration templates for common services</p>
        </div>
        
        <h2>📖 Documentation</h2>
        <p><a href="/docs">📋 Interactive API Documentation (Swagger UI)</a></p>
        <p><a href="/redoc">📚 Alternative API Documentation (ReDoc)</a></p>
        
        <h2>🔧 Quick Test</h2>
        <p>You can test the API using curl:</p>
        <pre>
# Login to get access token (default credentials: admin/admin123 or user/user123)
curl -X POST "http://localhost:8000/api/v1/auth/token" \\
     -H "Content-Type: application/x-www-form-urlencoded" \\
     -d "username=admin&password=admin123"

# Upload a document (replace YOUR_TOKEN with token from login)
curl -X POST "http://localhost:8000/api/v1/documents/upload" \\
     -H "Authorization: Bearer YOUR_TOKEN" \\
     -F "file=@your_document.pdf" \\
     -F "auto_process=true"

# Check supported formats (no authentication required)
curl "http://localhost:8000/api/v1/documents/formats"
        </pre>
    </body>
    </html>
    """
    return html_content

def start_server(enable_https: bool = False, port: int = 8000):
    """Start the server with optional HTTPS support."""
    import uvicorn
    
    if enable_https:
        # Get SSL configuration
        ssl_config = ssl_config_manager.get_uvicorn_ssl_config()
        if ssl_config:
            logger.info("Starting server with HTTPS enabled")
            uvicorn.run(
                app,
                host="0.0.0.0",
                port=port,
                reload=True,
                **ssl_config
            )
        else:
            logger.warning("HTTPS requested but SSL certificates not available, falling back to HTTP")
            uvicorn.run(app, host="0.0.0.0", port=port, reload=True)
    else:
        logger.info("Starting server with HTTP")
        uvicorn.run(app, host="0.0.0.0", port=port, reload=True)

if __name__ == "__main__":
    start_server()