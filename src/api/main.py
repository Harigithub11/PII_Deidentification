"""
Main FastAPI application
AI De-identification System MVP
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.api.routes import documents, health, processing
from src.core.config import settings
from src.core.database import DatabaseManager
from src.models.schemas import APIError


# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(settings.LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan events
    """
    # Startup
    logger.info(f"🚀 Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    
    try:
        # Initialize database
        await DatabaseManager.initialize_database()
        logger.info("✅ Database initialized successfully")
        
        # Check database health
        if await DatabaseManager.health_check():
            logger.info("✅ Database connection verified")
        else:
            logger.error("❌ Database connection failed")
            
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        raise
    
    logger.info("✅ Application startup completed")
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down application")
    logger.info("✅ Application shutdown completed")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="A comprehensive AI-powered solution for detecting and redacting PII from documents",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)


# Custom exception handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content=APIError(
            error="Resource not found",
            detail=f"The requested resource '{request.url.path}' was not found",
            timestamp=datetime.utcnow()
        ).dict()
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content=APIError(
            error="Internal server error",
            detail="An unexpected error occurred. Please try again later.",
            timestamp=datetime.utcnow()
        ).dict()
    )


# Include API routes
app.include_router(
    health.router,
    prefix=settings.API_V1_STR,
    tags=["Health Check"]
)

app.include_router(
    documents.router,
    prefix=settings.API_V1_STR,
    tags=["Documents"]
)

app.include_router(
    processing.router,
    prefix=settings.API_V1_STR,
    tags=["Processing"]
)

# Static files and templates (for web interface)
app.mount("/static", StaticFiles(directory="src/web/static"), name="static")
templates = Jinja2Templates(directory="src/web/templates")


# Root endpoint with web interface
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """
    Main web interface for document upload and processing
    """
    return templates.TemplateResponse("index.html", {
        "request": request,
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION
    })


# API Info endpoint
@app.get(f"{settings.API_V1_STR}/info")
async def api_info():
    """
    Get API information
    """
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "api_version": "v1",
        "docs_url": "/docs",
        "status": "operational",
        "timestamp": datetime.utcnow()
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )