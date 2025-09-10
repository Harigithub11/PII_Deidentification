"""
Debug Server for Multi-Format Document Processing

This version has extensive debugging and error reporting to identify issues.
"""

import logging
import tempfile
import asyncio
import sys
import traceback
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
import uuid
import json
import io
import base64

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.exception_handlers import http_exception_handler
from pydantic import BaseModel, Field

# Configure comprehensive logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

# Create FastAPI application with debug settings
app = FastAPI(
    title="Debug Multi-Format Document Processing",
    description="Debug version with extensive error reporting",
    version="1.0.0-debug",
    debug=True
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler with detailed logging."""
    error_id = str(uuid.uuid4())
    
    logger.error(f"Global exception caught [ID: {error_id}]")
    logger.error(f"Request: {request.method} {request.url}")
    logger.error(f"Exception type: {type(exc).__name__}")
    logger.error(f"Exception message: {str(exc)}")
    logger.error(f"Full traceback:\n{traceback.format_exc()}")
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
            "error_id": error_id,
            "exception_type": type(exc).__name__,
            "timestamp": datetime.now().isoformat()
        }
    )

# Models with minimal dependencies
class SimpleDocumentResponse(BaseModel):
    success: bool
    message: str
    document_id: str
    filename: str
    file_size: int

# Storage
documents: Dict[str, Dict[str, Any]] = {}

@app.get("/")
async def root():
    """Debug root endpoint."""
    logger.info("Root endpoint accessed")
    return {"message": "Debug server is running", "timestamp": datetime.now().isoformat()}

@app.get("/health")
async def health_check():
    """Health check with system info."""
    logger.info("Health check accessed")
    
    try:
        import platform
        
        health_info = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "working_directory": str(Path.cwd()),
            "temp_directory": tempfile.gettempdir()
        }
        
        # Check available libraries
        libraries = {}
        for lib in ["PIL", "PyPDF2", "fitz", "requests"]:
            try:
                __import__(lib)
                libraries[lib] = "available"
            except ImportError as e:
                libraries[lib] = f"missing: {str(e)}"
        
        health_info["libraries"] = libraries
        
        logger.info(f"Health check successful: {health_info}")
        return health_info
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise

@app.get("/debug/test")
async def debug_test():
    """Debug test endpoint."""
    logger.info("Debug test endpoint accessed")
    
    try:
        # Test basic operations
        test_results = {
            "datetime": datetime.now().isoformat(),
            "uuid_generation": str(uuid.uuid4()),
            "path_operations": {
                "cwd": str(Path.cwd()),
                "temp": tempfile.gettempdir(),
                "temp_exists": Path(tempfile.gettempdir()).exists()
            }
        }
        
        # Test file operations
        try:
            temp_file = Path(tempfile.gettempdir()) / "debug_test.txt"
            temp_file.write_text("debug test")
            test_results["file_operations"] = "success"
            temp_file.unlink()  # Clean up
        except Exception as e:
            test_results["file_operations"] = f"failed: {str(e)}"
        
        logger.info(f"Debug test results: {test_results}")
        return test_results
        
    except Exception as e:
        logger.error(f"Debug test failed: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise

@app.post("/debug/upload")
async def debug_upload(file: UploadFile = File(...)):
    """Debug upload endpoint with minimal processing."""
    logger.info(f"Debug upload started for file: {file.filename}")
    
    try:
        # Basic file info
        if not file.filename:
            logger.error("No filename provided")
            raise HTTPException(status_code=400, detail="No filename provided")
        
        logger.info(f"File info - Name: {file.filename}, Content-Type: {file.content_type}")
        
        # Read file content
        logger.info("Reading file content...")
        file_content = await file.read()
        file_size = len(file_content)
        logger.info(f"File content read successfully - Size: {file_size} bytes")
        
        # Generate document ID
        document_id = str(uuid.uuid4())
        logger.info(f"Generated document ID: {document_id}")
        
        # Store minimal info
        documents[document_id] = {
            "document_id": document_id,
            "filename": file.filename,
            "file_size": file_size,
            "upload_time": datetime.now().isoformat(),
            "content_type": file.content_type
        }
        
        logger.info(f"Document stored successfully: {document_id}")
        
        response = SimpleDocumentResponse(
            success=True,
            message="File uploaded successfully",
            document_id=document_id,
            filename=file.filename,
            file_size=file_size
        )
        
        logger.info(f"Returning response: {response}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Debug upload failed: {e}")
        logger.error(f"Exception type: {type(e).__name__}")
        logger.error(f"Full traceback:\n{traceback.format_exc()}")
        raise

@app.get("/debug/documents/{document_id}")
async def get_debug_document(document_id: str):
    """Get debug document info."""
    logger.info(f"Getting document info for ID: {document_id}")
    
    try:
        if document_id not in documents:
            logger.warning(f"Document not found: {document_id}")
            raise HTTPException(status_code=404, detail="Document not found")
        
        doc_info = documents[document_id]
        logger.info(f"Document found: {doc_info}")
        return doc_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get document failed: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise

@app.get("/debug/documents")
async def list_debug_documents():
    """List all uploaded documents."""
    logger.info("Listing all documents")
    
    try:
        doc_list = {
            "total_documents": len(documents),
            "documents": list(documents.values())
        }
        logger.info(f"Document list: {doc_list}")
        return doc_list
        
    except Exception as e:
        logger.error(f"List documents failed: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise

if __name__ == "__main__":
    print("="*60)
    print("STARTING DEBUG SERVER")
    print("="*60)
    print("This server has extensive debugging enabled")
    print("Server: http://localhost:8000")
    print("Health: http://localhost:8000/health")  
    print("Debug Test: http://localhost:8000/debug/test")
    print("Debug Upload: POST http://localhost:8000/debug/upload")
    print("="*60)
    
    try:
        import uvicorn
        uvicorn.run(
            app, 
            host="127.0.0.1", 
            port=8000, 
            log_level="debug",
            access_log=True
        )
    except Exception as e:
        print(f"Failed to start server: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)