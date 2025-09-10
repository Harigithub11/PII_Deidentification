# -*- coding: utf-8 -*-
"""
Clean Multi-Format Document Processing Server on Port 8001

Starting fresh on port 8001 to avoid conflicts.
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

# PII Detection imports
try:
    from src.core.services.pii_detector import PIIDetectionService, get_pii_detection_service
    from src.core.models.ner_models import get_default_ner_model
    PII_DETECTION_AVAILABLE = True
    logger.info("PII Detection modules loaded successfully")
except ImportError as e:
    logger.warning(f"PII Detection modules not available: {e}")
    PII_DETECTION_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(title="Multi-Format Document Processing", version="1.0.0")

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


class PIIEntity(BaseModel):
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float


class DocumentProcessingResult(BaseModel):
    success: bool
    document_id: str
    filename: str
    file_size: int
    processing_status: str
    processor: str = "mock"
    extracted_text: str = ""
    text_length: int = 0
    pages: int = 0
    pii_detection: dict = None
    pii_entities: list = None
    entity_count: int = 0
    risk_level: str = "unknown"
    processing_time: float = 0.0

# Storage
documents: Dict[str, Dict[str, Any]] = {}

# Helper function for PII detection
async def detect_pii_in_text(text: str, document_id: str = None) -> Dict[str, Any]:
    """
    Detect PII entities in extracted text.
    Returns PII analysis results including entities, risk level, and summary.
    """
    if not PII_DETECTION_AVAILABLE or not text or len(text.strip()) < 10:
        return {
            "pii_detection_enabled": PII_DETECTION_AVAILABLE,
            "entities": [],
            "entity_count": 0,
            "risk_level": "unknown",
            "confidence_distribution": {},
            "processing_time": 0.0,
            "error": "Insufficient text for PII analysis" if text else None
        }
    
    try:
        # Get PII detection service
        pii_service = get_pii_detection_service()
        
        # Perform PII detection
        start_time = datetime.now()
        result = await pii_service.detect_pii_async(
            text=text,
            document_id=document_id,
            language="en",
            model_type="presidio",
            confidence_threshold=0.5
        )
        processing_time = (datetime.now() - start_time).total_seconds()
        
        # Convert entities to simple dict format
        entities = []
        for entity in result.entities:
            entities.append({
                "entity_type": entity.entity_type,
                "text": entity.text,
                "start": entity.start,
                "end": entity.end,
                "confidence": entity.confidence
            })
        
        return {
            "pii_detection_enabled": True,
            "detection_id": result.detection_id,
            "entities": entities,
            "entity_count": result.entity_count,
            "risk_level": result.risk_level.value,
            "compliance_flags": result.compliance_flags,
            "confidence_distribution": result.confidence_distribution,
            "processing_time": processing_time,
            "unique_entity_types": result.unique_entity_types
        }
        
    except Exception as e:
        logger.error(f"PII detection failed: {e}")
        return {
            "pii_detection_enabled": True,
            "entities": [],
            "entity_count": 0,
            "risk_level": "unknown",
            "confidence_distribution": {},
            "processing_time": 0.0,
            "error": f"PII detection failed: {str(e)}"
        }

# Global exception handler with detailed error reporting
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_id = str(uuid.uuid4())
    logger.error(f"[ERROR {error_id}] Exception: {exc}")
    logger.error(f"[ERROR {error_id}] Request: {request.method} {request.url}")
    logger.error(f"[ERROR {error_id}] Traceback:\n{traceback.format_exc()}")
    
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Server error",
            "detail": str(exc),
            "error_id": error_id,
            "timestamp": datetime.now().isoformat()
        }
    )

@app.get("/", response_class=HTMLResponse)
async def root():
    """Clean upload interface."""
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Multi-Format Document Processing</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f0f0f0; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
        .header {{ text-align: center; color: #2c3e50; margin-bottom: 30px; }}
        .upload-area {{ background: #f8f9fa; padding: 30px; border-radius: 8px; margin: 20px 0; border: 2px dashed #007bff; }}
        .btn {{ background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }}
        .result {{ margin: 20px 0; padding: 15px; border-radius: 5px; }}
        .success {{ background: #d4edda; color: #155724; }}
        .error {{ background: #f8d7da; color: #721c24; }}
        .hidden {{ display: none; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📄 Multi-Format Document Processing</h1>
            <p><strong>Server running on PORT 8001</strong></p>
            <p>Upload PDFs, Images, and Documents</p>
        </div>
        
        <div class="upload-area">
            <h3>📤 Upload Document</h3>
            <form id="uploadForm">
                <input type="file" id="fileInput" name="file" 
                       accept=".pdf,.png,.jpg,.jpeg,.tiff,.tif,.bmp,.gif" required>
                <br><br>
                <button type="submit" id="uploadBtn" class="btn">Upload & Process</button>
            </form>
        </div>
        
        <div id="result" class="result hidden"></div>
        
        <div style="background: #e9ecef; padding: 15px; border-radius: 5px;">
            <h4>✅ Supported Formats:</h4>
            <p><strong>PDFs:</strong> .pdf files with text extraction</p>
            <p><strong>Images:</strong> .png, .jpg, .jpeg, .tiff, .tif, .bmp, .gif</p>
            <p><strong>Max Size:</strong> 100 MB</p>
        </div>
    </div>

    <script>
        document.getElementById('uploadForm').addEventListener('submit', async function(e) {{
            e.preventDefault();
            
            const fileInput = document.getElementById('fileInput');
            const uploadBtn = document.getElementById('uploadBtn');
            const result = document.getElementById('result');
            const file = fileInput.files[0];
            
            if (!file) {{
                showResult('❌ Please select a file', 'error');
                return;
            }}
            
            // Show loading
            uploadBtn.disabled = true;
            uploadBtn.textContent = 'Uploading...';
            showResult('⏳ Uploading file...', '');
            
            try {{
                const formData = new FormData();
                formData.append('file', file);
                
                const response = await fetch('/upload', {{
                    method: 'POST',
                    body: formData
                }});
                
                const data = await response.json();
                console.log('Response:', data);
                
                if (response.ok && data.success) {{
                    showResult(`✅ SUCCESS!<br>
                               📄 File: ${{data.filename}}<br>
                               🆔 ID: ${{data.document_id}}<br>
                               💾 Size: ${{(data.file_size / 1024 / 1024).toFixed(2)}} MB<br>
                               🔄 Status: ${{data.processing_status}}`, 'success');
                }} else {{
                    showResult(`❌ ERROR: ${{data.detail || data.error || 'Upload failed'}}`, 'error');
                }}
                
            }} catch (error) {{
                console.error('Upload error:', error);
                showResult(`❌ Network Error: ${{error.message}}`, 'error');
            }} finally {{
                uploadBtn.disabled = false;
                uploadBtn.textContent = 'Upload & Process';
            }}
        }});
        
        function showResult(message, type) {{
            const result = document.getElementById('result');
            result.innerHTML = message;
            result.className = `result ${{type}}`;
            result.classList.remove('hidden');
        }}
    </script>
</body>
</html>
    """
    return html

@app.get("/health")
async def health_check():
    """Health check."""
    return {
        "status": "healthy",
        "port": 8001,
        "message": "Clean server running",
        "timestamp": datetime.now().isoformat(),
        "documents": len(documents)
    }

@app.post("/upload", response_model=UploadResponse)
async def upload_document(file: UploadFile = File(...)):
    """Upload and process document."""
    try:
        logger.info(f"=== UPLOAD START: {file.filename} ===")
        
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        # Check extension
        file_extension = Path(file.filename).suffix.lower()
        supported = ['.pdf', '.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp', '.gif']
        
        if file_extension not in supported:
            logger.warning(f"Unsupported format: {file_extension}")
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported format: {file_extension}. Supported: {', '.join(supported)}"
            )
        
        # Read file
        logger.info("Reading file content...")
        file_content = await file.read()
        file_size = len(file_content)
        logger.info(f"File read: {file_size} bytes")
        
        # Size check
        max_size = 100 * 1024 * 1024
        if file_size > max_size:
            raise HTTPException(
                status_code=400,
                detail=f"File too large: {file_size / (1024*1024):.1f}MB > 100MB"
            )
        
        # Generate ID and save
        document_id = str(uuid.uuid4())
        logger.info(f"Generated ID: {document_id}")
        
        temp_dir = Path(tempfile.gettempdir()) / "clean_doc_processing"
        temp_dir.mkdir(exist_ok=True)
        temp_file = temp_dir / f"{document_id}_{file.filename}"
        
        with open(temp_file, "wb") as f:
            f.write(file_content)
        logger.info(f"File saved: {temp_file}")
        
        # Store document
        documents[document_id] = {
            "document_id": document_id,
            "filename": file.filename,
            "file_size": file_size,
            "file_path": str(temp_file),
            "upload_time": datetime.now().isoformat(),
            "processing_status": "processing"
        }
        
        # Start processing
        asyncio.create_task(process_document(document_id))
        
        response = UploadResponse(
            success=True,
            message="Upload successful",
            document_id=document_id,
            filename=file.filename,
            file_size=file_size,
            processing_status="processing"
        )
        
        logger.info(f"=== UPLOAD SUCCESS: {document_id} ===")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"=== UPLOAD FAILED ===")
        logger.error(f"Error: {e}")
        logger.error(f"Traceback:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.get("/documents/{document_id}")
async def get_document(document_id: str):
    """Get document info and results."""
    if document_id not in documents:
        raise HTTPException(status_code=404, detail="Document not found")
    
    return documents[document_id]


@app.get("/documents/{document_id}/pii")
async def get_document_pii_analysis(document_id: str):
    """Get detailed PII analysis for a document."""
    if document_id not in documents:
        raise HTTPException(status_code=404, detail="Document not found")
    
    doc = documents[document_id]
    
    if doc["processing_status"] != "completed":
        raise HTTPException(
            status_code=400, 
            detail=f"Document processing not completed. Status: {doc['processing_status']}"
        )
    
    processing_result = doc.get("processing_result", {})
    pii_detection = processing_result.get("pii_detection", {})
    
    # Format detailed PII response
    pii_response = {
        "document_id": document_id,
        "filename": doc["filename"],
        "processing_status": doc["processing_status"],
        "pii_detection_enabled": pii_detection.get("pii_detection_enabled", False),
        "pii_analysis": {
            "entity_count": pii_detection.get("entity_count", 0),
            "risk_level": pii_detection.get("risk_level", "unknown"),
            "entities": pii_detection.get("entities", []),
            "unique_entity_types": pii_detection.get("unique_entity_types", []),
            "compliance_flags": pii_detection.get("compliance_flags", []),
            "confidence_distribution": pii_detection.get("confidence_distribution", {}),
            "processing_time": pii_detection.get("processing_time", 0.0)
        },
        "document_stats": {
            "text_length": processing_result.get("text_length", 0),
            "pages": processing_result.get("pages", 0),
            "processor": processing_result.get("processor", "unknown")
        },
        "detection_id": pii_detection.get("detection_id"),
        "error": pii_detection.get("error")
    }
    
    return pii_response


@app.post("/documents/{document_id}/reanalyze-pii")
async def reanalyze_document_pii(document_id: str):
    """Re-run PII detection on an already processed document."""
    if document_id not in documents:
        raise HTTPException(status_code=404, detail="Document not found")
    
    doc = documents[document_id]
    processing_result = doc.get("processing_result", {})
    
    # Get the extracted text
    extracted_text = processing_result.get("extracted_text", "")
    
    if not extracted_text:
        raise HTTPException(
            status_code=400, 
            detail="No extracted text available for PII analysis"
        )
    
    # Re-run PII detection
    try:
        logger.info(f"Re-analyzing PII for document {document_id}")
        pii_results = await detect_pii_in_text(extracted_text, document_id)
        
        # Update the document with new PII results
        processing_result["pii_detection"] = pii_results
        processing_result["pii_entities"] = pii_results.get("entities", [])
        processing_result["entity_count"] = pii_results.get("entity_count", 0)
        processing_result["risk_level"] = pii_results.get("risk_level", "unknown")
        processing_result["pii_detection_time"] = pii_results.get("processing_time", 0.0)
        
        # Update document
        documents[document_id]["processing_result"] = processing_result
        
        logger.info(f"PII re-analysis completed: {pii_results.get('entity_count', 0)} entities found")
        
        return {
            "success": True,
            "message": "PII analysis completed",
            "document_id": document_id,
            "entity_count": pii_results.get("entity_count", 0),
            "risk_level": pii_results.get("risk_level", "unknown"),
            "processing_time": pii_results.get("processing_time", 0.0)
        }
        
    except Exception as e:
        logger.error(f"PII re-analysis failed for {document_id}: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"PII analysis failed: {str(e)}"
        )

async def process_document(document_id: str):
    """Process document in background with PII detection integration."""
    try:
        logger.info(f"=== PROCESSING START: {document_id} ===")
        
        doc_info = documents[document_id]
        file_path = Path(doc_info["file_path"])
        
        # Initialize processing result
        processing_result = {
            "processor": "mock", 
            "status": "completed",
            "extracted_text": "",
            "text_length": 0,
            "pages": 0
        }
        
        extracted_text = ""
        
        # Process based on file type
        if file_path.suffix.lower() == '.pdf':
            # Process PDF documents
            try:
                import fitz  # PyMuPDF
                logger.info(f"Processing PDF: {file_path}")
                
                with open(file_path, "rb") as f:
                    doc = fitz.open(stream=f.read(), filetype="pdf")
                    text = ""
                    for page in doc:
                        text += page.get_text() + "\n"
                    doc.close()
                
                extracted_text = text.strip()
                processing_result = {
                    "processor": "PyMuPDF",
                    "pages": len(doc) if 'doc' in locals() else 1,
                    "text_length": len(extracted_text),
                    "text_preview": extracted_text[:300] + "..." if len(extracted_text) > 300 else extracted_text,
                    "extracted_text": extracted_text,
                    "status": "completed"
                }
                logger.info(f"PDF processed successfully: {len(extracted_text)} characters extracted")
                
            except Exception as e:
                logger.warning(f"PDF processing failed: {e}")
                processing_result = {
                    "processor": "failed", 
                    "error": str(e), 
                    "status": "failed",
                    "extracted_text": "",
                    "text_length": 0,
                    "pages": 0
                }
        
        elif file_path.suffix.lower() in ['.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp', '.gif']:
            # Process image documents (OCR would be needed for text extraction)
            try:
                from PIL import Image
                logger.info(f"Processing image: {file_path}")
                
                # For now, just validate the image and set up for future OCR integration
                with Image.open(file_path) as img:
                    width, height = img.size
                    
                processing_result = {
                    "processor": "PIL_Image",
                    "pages": 1,
                    "image_dimensions": f"{width}x{height}",
                    "extracted_text": "",  # OCR would be needed here
                    "text_length": 0,
                    "status": "completed",
                    "note": "Image processed successfully - OCR integration needed for text extraction"
                }
                logger.info(f"Image processed successfully: {width}x{height} pixels")
                
            except Exception as e:
                logger.warning(f"Image processing failed: {e}")
                processing_result = {
                    "processor": "failed", 
                    "error": str(e), 
                    "status": "failed",
                    "extracted_text": "",
                    "text_length": 0,
                    "pages": 0
                }
        
        # Perform PII detection on extracted text
        pii_results = None
        if extracted_text and len(extracted_text.strip()) > 0:
            logger.info(f"Starting PII detection for document {document_id}")
            pii_results = await detect_pii_in_text(extracted_text, document_id)
            logger.info(f"PII detection completed: {pii_results.get('entity_count', 0)} entities found")
        else:
            logger.info("No text extracted - skipping PII detection")
            pii_results = {
                "pii_detection_enabled": PII_DETECTION_AVAILABLE,
                "entities": [],
                "entity_count": 0,
                "risk_level": "unknown",
                "processing_time": 0.0,
                "note": "No text available for PII analysis"
            }
        
        # Combine processing results with PII detection
        combined_result = {
            **processing_result,
            "pii_detection": pii_results,
            "pii_entities": pii_results.get("entities", []),
            "entity_count": pii_results.get("entity_count", 0),
            "risk_level": pii_results.get("risk_level", "unknown"),
            "pii_detection_time": pii_results.get("processing_time", 0.0)
        }
        
        # Update document with comprehensive results
        documents[document_id]["processing_result"] = combined_result
        documents[document_id]["processing_status"] = "completed"
        
        logger.info(f"=== PROCESSING COMPLETED: {document_id} ===")
        logger.info(f"Text extracted: {len(extracted_text)} chars, PII entities: {pii_results.get('entity_count', 0)}")
        
    except Exception as e:
        logger.error(f"Processing failed for {document_id}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        documents[document_id]["processing_status"] = "failed"
        documents[document_id]["error"] = str(e)
        documents[document_id]["processing_result"] = {
            "processor": "failed",
            "error": str(e),
            "status": "failed",
            "pii_detection": {
                "pii_detection_enabled": PII_DETECTION_AVAILABLE,
                "entities": [],
                "entity_count": 0,
                "risk_level": "unknown",
                "error": "Processing failed before PII detection"
            }
        }

if __name__ == "__main__":
    print("="*60)
    print("STARTING CLEAN SERVER ON PORT 8001")
    print("="*60)
    print("Server: http://localhost:8001")
    print("No port conflicts - fresh start!")
    print("="*60)
    
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")