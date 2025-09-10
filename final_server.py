# -*- coding: utf-8 -*-
"""
Final Working Multi-Format Document Processing Server

Simple, robust server with proper file upload handling.
"""

import logging
import tempfile
import asyncio
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
import uuid
import traceback

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(title="Document Processing API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Response models
class UploadResponse(BaseModel):
    success: bool
    message: str
    document_id: str
    filename: str
    file_size: int
    processing_status: str

# Storage
documents: Dict[str, Dict[str, Any]] = {}

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Exception: {exc}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Server error",
            "detail": str(exc),
            "timestamp": datetime.now().isoformat()
        }
    )

@app.get("/", response_class=HTMLResponse)
async def root():
    """Simple working upload interface."""
    html = """
<!DOCTYPE html>
<html>
<head>
    <title>Document Processing</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #2c3e50; margin-bottom: 30px; }
        .upload-form { background: #f8f9fa; padding: 30px; border-radius: 8px; margin: 20px 0; }
        .file-input { width: 100%; padding: 12px; border: 2px dashed #007bff; border-radius: 5px; background: white; margin: 15px 0; }
        .btn { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        .btn:hover { background: #0056b3; }
        .btn:disabled { background: #6c757d; cursor: not-allowed; }
        .result { margin: 20px 0; padding: 15px; border-radius: 5px; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .loading { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📄 Multi-Format Document Processing</h1>
            <p>Upload PDFs, images, and documents for processing</p>
        </div>
        
        <div class="upload-form">
            <h3>Upload Document</h3>
            <form id="uploadForm" enctype="multipart/form-data">
                <input type="file" id="fileInput" name="file" class="file-input" 
                       accept=".pdf,.png,.jpg,.jpeg,.tiff,.tif,.bmp,.gif" required>
                <br>
                <button type="submit" id="uploadBtn" class="btn">Upload & Process</button>
            </form>
        </div>
        
        <div id="result" class="result hidden"></div>
        
        <div style="margin-top: 30px;">
            <h3>📚 API Endpoints</h3>
            <p><strong>GET /health</strong> - Check server status</p>
            <p><strong>POST /upload</strong> - Upload documents</p>
            <p><strong>GET /documents/{id}</strong> - Get document info</p>
            <p><strong>GET /docs</strong> - API documentation</p>
        </div>
    </div>

    <script>
        const form = document.getElementById('uploadForm');
        const fileInput = document.getElementById('fileInput');
        const uploadBtn = document.getElementById('uploadBtn');
        const result = document.getElementById('result');

        form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const file = fileInput.files[0];
            if (!file) {
                showResult('Please select a file', 'error');
                return;
            }
            
            // Show loading state
            uploadBtn.disabled = true;
            uploadBtn.textContent = 'Uploading...';
            showResult('Uploading file, please wait...', 'loading');
            
            try {
                const formData = new FormData();
                formData.append('file', file);
                
                const response = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (response.ok && data.success) {
                    showResult(`✅ Success! File uploaded: ${data.filename}<br>
                               📄 Document ID: ${data.document_id}<br>
                               💾 Size: ${(data.file_size / 1024 / 1024).toFixed(2)} MB<br>
                               🔄 Status: ${data.processing_status}`, 'success');
                } else {
                    showResult(`❌ Error: ${data.detail || data.error || 'Upload failed'}`, 'error');
                }
                
            } catch (error) {
                console.error('Upload error:', error);
                showResult(`❌ Network error: ${error.message}`, 'error');
            } finally {
                uploadBtn.disabled = false;
                uploadBtn.textContent = 'Upload & Process';
            }
        });
        
        function showResult(message, type) {
            result.innerHTML = message;
            result.className = `result ${type}`;
            result.classList.remove('hidden');
        }
    </script>
</body>
</html>
    """
    return html

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "message": "Server is running",
        "timestamp": datetime.now().isoformat(),
        "documents_uploaded": len(documents)
    }

@app.post("/upload", response_model=UploadResponse)
async def upload_document(file: UploadFile = File(...)):
    """Upload document endpoint."""
    try:
        logger.info(f"Upload started: {file.filename}")
        
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        # Check file extension
        file_extension = Path(file.filename).suffix.lower()
        supported_formats = ['.pdf', '.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp', '.gif']
        
        if file_extension not in supported_formats:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported format: {file_extension}. Supported: {', '.join(supported_formats)}"
            )
        
        # Read file
        file_content = await file.read()
        file_size = len(file_content)
        
        logger.info(f"File read successfully: {file_size} bytes")
        
        # Check file size (100MB limit)
        max_size = 100 * 1024 * 1024
        if file_size > max_size:
            raise HTTPException(
                status_code=400,
                detail=f"File too large: {file_size / (1024*1024):.1f}MB > 100MB"
            )
        
        # Generate document ID
        document_id = str(uuid.uuid4())
        
        # Save file temporarily
        temp_dir = Path(tempfile.gettempdir()) / "doc_processing"
        temp_dir.mkdir(exist_ok=True)
        temp_file = temp_dir / f"{document_id}_{file.filename}"
        
        with open(temp_file, "wb") as f:
            f.write(file_content)
        
        logger.info(f"File saved to: {temp_file}")
        
        # Store document info
        documents[document_id] = {
            "document_id": document_id,
            "filename": file.filename,
            "file_size": file_size,
            "file_path": str(temp_file),
            "upload_time": datetime.now().isoformat(),
            "processing_status": "uploaded"
        }
        
        logger.info(f"Document stored with ID: {document_id}")
        
        # Start basic processing
        asyncio.create_task(process_document(document_id))
        
        return UploadResponse(
            success=True,
            message="File uploaded successfully",
            document_id=document_id,
            filename=file.filename,
            file_size=file_size,
            processing_status="processing"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.get("/documents/{document_id}")
async def get_document(document_id: str):
    """Get document information."""
    if document_id not in documents:
        raise HTTPException(status_code=404, detail="Document not found")
    
    return documents[document_id]

@app.get("/documents")
async def list_documents():
    """List all documents."""
    return {
        "total": len(documents),
        "documents": list(documents.values())
    }

async def process_document(document_id: str):
    """Simple document processing."""
    try:
        logger.info(f"Processing document: {document_id}")
        
        # Update status
        documents[document_id]["processing_status"] = "processing"
        
        # Simulate processing time
        await asyncio.sleep(2)
        
        doc_info = documents[document_id]
        file_path = Path(doc_info["file_path"])
        
        # Basic processing based on file type
        if file_path.suffix.lower() == '.pdf':
            # Try to process PDF
            try:
                # Try PyMuPDF first
                import fitz
                with open(file_path, "rb") as f:
                    doc = fitz.open(stream=f.read(), filetype="pdf")
                    text_content = ""
                    for page in doc:
                        text_content += page.get_text()
                    doc.close()
                
                processing_result = {
                    "text_extracted": len(text_content) > 0,
                    "text_length": len(text_content),
                    "text_preview": text_content[:200] if text_content else "No text found",
                    "processor": "PyMuPDF"
                }
                
            except ImportError:
                # Fallback to PyPDF2
                try:
                    import PyPDF2
                    with open(file_path, "rb") as f:
                        reader = PyPDF2.PdfReader(f)
                        text_content = ""
                        for page in reader.pages:
                            text_content += page.extract_text()
                    
                    processing_result = {
                        "text_extracted": len(text_content) > 0,
                        "text_length": len(text_content),
                        "text_preview": text_content[:200] if text_content else "No text found",
                        "processor": "PyPDF2"
                    }
                    
                except ImportError:
                    processing_result = {
                        "text_extracted": False,
                        "error": "No PDF processing libraries available",
                        "processor": "none"
                    }
        else:
            # Image processing
            try:
                from PIL import Image
                with Image.open(file_path) as img:
                    processing_result = {
                        "image_processed": True,
                        "image_size": img.size,
                        "image_mode": img.mode,
                        "image_format": img.format,
                        "processor": "PIL"
                    }
            except ImportError:
                processing_result = {
                    "image_processed": False,
                    "error": "PIL not available",
                    "processor": "none"
                }
        
        # Update document with results
        documents[document_id]["processing_result"] = processing_result
        documents[document_id]["processing_status"] = "completed"
        
        logger.info(f"Document {document_id} processed successfully")
        
    except Exception as e:
        logger.error(f"Processing failed for {document_id}: {e}")
        documents[document_id]["processing_status"] = "failed"
        documents[document_id]["error"] = str(e)

if __name__ == "__main__":
    print("Starting Final Document Processing Server...")
    print("Server: http://localhost:8000")
    print("Upload your PDF and test the working interface!")
    
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")