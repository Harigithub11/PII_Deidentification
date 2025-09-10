"""
Simple FastAPI Server for Multi-Format Document Processing

This is a minimal server to test the multi-format document API.
"""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title="PII De-identification System",
    description="Multi-format document processing API",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "message": "API is running",
        "version": "1.0.0"
    }

@app.get("/test")
async def test_endpoint():
    """Test endpoint to verify API is working."""
    return {"message": "API is working correctly"}

if __name__ == "__main__":
    import uvicorn
    print("Starting simple server...")
    print("Server will be available at: http://localhost:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)