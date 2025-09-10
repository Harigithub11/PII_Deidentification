"""
OCR Detection API for PII De-identification System

This module provides REST API endpoints for OCR text extraction with:
- Multi-format document support (images, PDFs, scanned documents)
- Real-time OCR processing with multiple engines
- PII detection integration
- Batch processing capabilities
- Quality assessment and confidence scoring
"""

import logging
import tempfile
import os
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
import json
import asyncio
from datetime import datetime

from fastapi import APIRouter, File, UploadFile, HTTPException, Depends, Query, Form
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field, validator
import aiofiles

from ..core.services.ocr_service import (
    OCRService, OCRDocumentResult, OCRQuality, create_ocr_service
)
from ..core.processing.ocr_processor import (
    OCRProcessor, OCRProcessingConfig, DocumentType, PreprocessingMode, create_ocr_processor
)
from ..core.models.ocr_models import OCREngine, LanguageCode
from ..core.security.dependencies import verify_token, get_current_user
from ..core.config.settings import get_settings

logger = logging.getLogger(__name__)
security = HTTPBearer()
router = APIRouter(prefix="/api/ocr", tags=["OCR Detection"])


# Pydantic models for API requests/responses
class OCRRequest(BaseModel):
    """Request model for OCR processing."""
    engine: OCREngine = Field(default=OCREngine.TESSERACT, description="OCR engine to use")
    languages: List[str] = Field(default=["eng"], description="Language codes for OCR")
    enable_pii_detection: bool = Field(default=True, description="Enable PII detection")
    preprocessing_mode: PreprocessingMode = Field(default=PreprocessingMode.ENHANCED, description="Preprocessing mode")
    confidence_threshold: float = Field(default=50.0, ge=0.0, le=100.0, description="Minimum confidence threshold")
    max_pages: int = Field(default=50, ge=1, le=200, description="Maximum pages to process")
    
    @validator('languages')
    def validate_languages(cls, v):
        if not v:
            return ["eng"]
        return v


class OCRResponse(BaseModel):
    """Response model for OCR processing."""
    success: bool
    document_type: str
    text_content: str
    confidence_score: float
    total_pages: int
    word_count: int
    character_count: int
    processing_time: float
    engine_used: str
    languages_detected: List[str]
    quality_summary: Dict[str, int]
    pii_summary: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any]
    errors: List[str] = []


class OCRPageResponse(BaseModel):
    """Response model for single page OCR."""
    page_number: int
    text_content: str
    confidence_score: float
    quality_level: str
    bounding_boxes: List[Dict[str, Any]]
    pii_entities: Optional[List[Dict[str, Any]]] = None
    processing_time: float


class BatchOCRRequest(BaseModel):
    """Request model for batch OCR processing."""
    settings: OCRRequest
    file_names: List[str]


class BatchOCRResponse(BaseModel):
    """Response model for batch OCR processing."""
    total_files: int
    successful_files: int
    failed_files: int
    results: List[OCRResponse]
    batch_processing_time: float


class OCREngineInfo(BaseModel):
    """Response model for OCR engine information."""
    available_engines: List[str]
    current_engine: str
    available_languages: List[str]
    supported_formats: List[str]
    features: List[str]


# Global OCR processor instance
_ocr_processor: Optional[OCRProcessor] = None


def get_ocr_processor() -> OCRProcessor:
    """Get or create OCR processor instance."""
    global _ocr_processor
    if _ocr_processor is None:
        _ocr_processor = create_ocr_processor()
    return _ocr_processor


async def save_uploaded_file(upload_file: UploadFile) -> Path:
    """Save uploaded file to temporary location."""
    try:
        # Create temporary file with original extension
        suffix = Path(upload_file.filename).suffix if upload_file.filename else '.tmp'
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        temp_path = Path(temp_file.name)
        temp_file.close()
        
        # Save file content
        async with aiofiles.open(temp_path, 'wb') as f:
            content = await upload_file.read()
            await f.write(content)
        
        logger.info(f"Saved uploaded file to: {temp_path}")
        return temp_path
        
    except Exception as e:
        logger.error(f"Failed to save uploaded file: {e}")
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")


def cleanup_temp_file(file_path: Path):
    """Clean up temporary file."""
    try:
        if file_path.exists():
            os.unlink(file_path)
            logger.debug(f"Cleaned up temporary file: {file_path}")
    except Exception as e:
        logger.warning(f"Failed to cleanup temp file {file_path}: {e}")


def convert_ocr_result_to_response(result: Any, document_path: str) -> OCRResponse:
    """Convert OCR processing result to API response."""
    try:
        if hasattr(result, 'ocr_result') and result.ocr_result:
            ocr_result = result.ocr_result
            return OCRResponse(
                success=result.success,
                document_type=result.document_type.value if hasattr(result, 'document_type') else 'unknown',
                text_content=ocr_result.combined_text or '',
                confidence_score=ocr_result.overall_confidence,
                total_pages=ocr_result.total_pages,
                word_count=ocr_result.word_count,
                character_count=ocr_result.character_count,
                processing_time=result.processing_time,
                engine_used=ocr_result.engine_used or '',
                languages_detected=ocr_result.languages_detected or [],
                quality_summary=ocr_result.quality_summary or {},
                pii_summary=ocr_result.pii_summary,
                metadata={
                    'document_path': document_path,
                    'timestamp': datetime.utcnow().isoformat(),
                    **(result.metadata or {})
                },
                errors=result.processing_errors or []
            )
        else:
            return OCRResponse(
                success=False,
                document_type='unknown',
                text_content='',
                confidence_score=0.0,
                total_pages=0,
                word_count=0,
                character_count=0,
                processing_time=result.processing_time if hasattr(result, 'processing_time') else 0.0,
                engine_used='',
                languages_detected=[],
                quality_summary={},
                metadata={'document_path': document_path},
                errors=result.processing_errors if hasattr(result, 'processing_errors') else ['Unknown error']
            )
    except Exception as e:
        logger.error(f"Failed to convert OCR result: {e}")
        return OCRResponse(
            success=False,
            document_type='unknown',
            text_content='',
            confidence_score=0.0,
            total_pages=0,
            word_count=0,
            character_count=0,
            processing_time=0.0,
            engine_used='',
            languages_detected=[],
            quality_summary={},
            metadata={'document_path': document_path},
            errors=[str(e)]
        )


@router.post("/extract-text", response_model=OCRResponse)
async def extract_text_from_document(
    file: UploadFile = File(..., description="Document file (image, PDF, etc.)"),
    engine: OCREngine = Form(default=OCREngine.TESSERACT),
    languages: str = Form(default="eng", description="Comma-separated language codes"),
    enable_pii_detection: bool = Form(default=True),
    preprocessing_mode: PreprocessingMode = Form(default=PreprocessingMode.ENHANCED),
    confidence_threshold: float = Form(default=50.0, ge=0.0, le=100.0),
    max_pages: int = Form(default=50, ge=1, le=200),
    current_user: Dict = Depends(get_current_user)
):
    """
    Extract text from uploaded document using OCR.
    
    Supports various document formats including:
    - Images: PNG, JPG, TIFF, BMP, etc.
    - PDFs: Both text and scanned PDFs
    - Multi-page documents
    
    Returns extracted text with confidence scores and optional PII detection.
    """
    temp_file_path = None
    
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Save uploaded file
        temp_file_path = await save_uploaded_file(file)
        
        # Parse languages
        language_list = [lang.strip() for lang in languages.split(',') if lang.strip()]
        if not language_list:
            language_list = ['eng']
        
        # Create processing configuration
        config = OCRProcessingConfig(
            engine=engine,
            preprocessing_mode=preprocessing_mode,
            enable_pii_detection=enable_pii_detection,
            language_codes=language_list,
            confidence_threshold=confidence_threshold,
            max_pages=max_pages
        )
        
        # Get OCR processor and process document
        processor = get_ocr_processor()
        result = processor.process_document(temp_file_path, config)
        
        # Convert to API response
        response = convert_ocr_result_to_response(result, file.filename)
        
        logger.info(f"OCR processing completed for {file.filename}: {'Success' if response.success else 'Failed'}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OCR extraction failed: {e}")
        raise HTTPException(status_code=500, detail=f"OCR processing failed: {str(e)}")
    finally:
        if temp_file_path:
            cleanup_temp_file(temp_file_path)


@router.post("/extract-text-image", response_model=OCRResponse)
async def extract_text_from_image(
    file: UploadFile = File(..., description="Image file"),
    engine: OCREngine = Form(default=OCREngine.TESSERACT),
    languages: str = Form(default="eng"),
    enable_pii_detection: bool = Form(default=True),
    apply_preprocessing: bool = Form(default=True),
    current_user: Dict = Depends(get_current_user)
):
    """
    Extract text from uploaded image using OCR.
    
    Optimized for single image processing with fast response times.
    """
    temp_file_path = None
    
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No image file provided")
        
        # Save uploaded file
        temp_file_path = await save_uploaded_file(file)
        
        # Parse languages
        language_list = [lang.strip() for lang in languages.split(',') if lang.strip()]
        
        # Create OCR service
        ocr_service = create_ocr_service(engine, enable_pii_detection)
        
        try:
            # Extract text from image
            result = await ocr_service.extract_text_from_image_async(
                temp_file_path,
                page_number=0,
                detect_pii=enable_pii_detection,
                apply_preprocessing=apply_preprocessing
            )
            
            # Convert to response format
            if result.ocr_result.success:
                response = OCRResponse(
                    success=True,
                    document_type=DocumentType.IMAGE.value,
                    text_content=result.ocr_result.text_content,
                    confidence_score=result.ocr_result.confidence_score,
                    total_pages=1,
                    word_count=result.ocr_result.word_count,
                    character_count=result.ocr_result.character_count,
                    processing_time=result.ocr_result.processing_time,
                    engine_used=result.ocr_result.engine_used,
                    languages_detected=[result.ocr_result.language_detected] if result.ocr_result.language_detected else [],
                    quality_summary={result.quality_assessment.value: 1} if result.quality_assessment else {},
                    pii_summary=result.pii_detection_result.__dict__ if result.pii_detection_result else None,
                    metadata={
                        'image_dimensions': result.ocr_result.image_dimensions,
                        'preprocessing_applied': result.ocr_result.preprocessing_applied,
                        'document_path': file.filename
                    }
                )
            else:
                response = OCRResponse(
                    success=False,
                    document_type=DocumentType.IMAGE.value,
                    text_content='',
                    confidence_score=0.0,
                    total_pages=1,
                    word_count=0,
                    character_count=0,
                    processing_time=result.ocr_result.processing_time,
                    engine_used=result.ocr_result.engine_used,
                    languages_detected=[],
                    quality_summary={},
                    metadata={'document_path': file.filename},
                    errors=result.ocr_result.processing_errors
                )
            
            return response
            
        finally:
            ocr_service.cleanup()
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Image OCR failed: {e}")
        raise HTTPException(status_code=500, detail=f"Image OCR failed: {str(e)}")
    finally:
        if temp_file_path:
            cleanup_temp_file(temp_file_path)


@router.post("/batch-extract", response_model=BatchOCRResponse)
async def batch_extract_text(
    files: List[UploadFile] = File(..., description="Multiple document files"),
    engine: OCREngine = Form(default=OCREngine.TESSERACT),
    languages: str = Form(default="eng"),
    enable_pii_detection: bool = Form(default=True),
    preprocessing_mode: PreprocessingMode = Form(default=PreprocessingMode.ENHANCED),
    max_files: int = Query(default=10, ge=1, le=50, description="Maximum number of files to process"),
    current_user: Dict = Depends(get_current_user)
):
    """
    Extract text from multiple documents using batch processing.
    
    Efficiently processes multiple files concurrently with shared configuration.
    """
    import time
    batch_start_time = time.time()
    temp_files = []
    
    try:
        # Validate batch size
        if len(files) > max_files:
            raise HTTPException(
                status_code=400, 
                detail=f"Too many files. Maximum allowed: {max_files}, received: {len(files)}"
            )
        
        # Save all uploaded files
        for file in files:
            if file.filename:
                temp_path = await save_uploaded_file(file)
                temp_files.append((temp_path, file.filename))
        
        if not temp_files:
            raise HTTPException(status_code=400, detail="No valid files provided")
        
        # Parse languages
        language_list = [lang.strip() for lang in languages.split(',') if lang.strip()]
        if not language_list:
            language_list = ['eng']
        
        # Create processing configuration
        config = OCRProcessingConfig(
            engine=engine,
            preprocessing_mode=preprocessing_mode,
            enable_pii_detection=enable_pii_detection,
            language_codes=language_list,
            enable_parallel_processing=True,
            max_workers=min(4, len(temp_files))
        )
        
        # Process files in batch
        processor = get_ocr_processor()
        file_paths = [temp_path for temp_path, _ in temp_files]
        results = processor.batch_process_documents(file_paths, config)
        
        # Convert results to response format
        api_results = []
        successful_count = 0
        failed_count = 0
        
        for result, (temp_path, original_name) in zip(results, temp_files):
            api_result = convert_ocr_result_to_response(result, original_name)
            api_results.append(api_result)
            
            if api_result.success:
                successful_count += 1
            else:
                failed_count += 1
        
        batch_processing_time = time.time() - batch_start_time
        
        response = BatchOCRResponse(
            total_files=len(temp_files),
            successful_files=successful_count,
            failed_files=failed_count,
            results=api_results,
            batch_processing_time=batch_processing_time
        )
        
        logger.info(f"Batch OCR completed: {successful_count}/{len(temp_files)} successful")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch OCR failed: {e}")
        raise HTTPException(status_code=500, detail=f"Batch processing failed: {str(e)}")
    finally:
        # Cleanup all temp files
        for temp_path, _ in temp_files:
            cleanup_temp_file(temp_path)


@router.get("/engines", response_model=OCREngineInfo)
async def get_available_engines(current_user: Dict = Depends(get_current_user)):
    """
    Get information about available OCR engines and their capabilities.
    """
    try:
        processor = get_ocr_processor()
        stats = processor.get_processing_stats()
        
        # Get current OCR service info
        ocr_service = create_ocr_service()
        try:
            engine_info = ocr_service.get_engine_info()
            
            return OCREngineInfo(
                available_engines=stats.get('available_ocr_engines', []),
                current_engine=stats.get('current_engine', ''),
                available_languages=engine_info.get('available_languages', []),
                supported_formats=engine_info.get('supported_formats', []),
                features=stats.get('features', [])
            )
        finally:
            ocr_service.cleanup()
            
    except Exception as e:
        logger.error(f"Failed to get engine info: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get engine information: {str(e)}")


@router.get("/health")
async def ocr_health_check():
    """
    Check OCR service health and availability.
    """
    try:
        processor = get_ocr_processor()
        stats = processor.get_processing_stats()
        
        # Test OCR functionality with a simple check
        ocr_service = create_ocr_service(enable_pii=False)
        try:
            engine_info = ocr_service.get_engine_info()
            service_status = engine_info.get('status', 'unknown')
        finally:
            ocr_service.cleanup()
        
        return {
            "status": "healthy" if service_status == "ready" else "degraded",
            "ocr_service_status": service_status,
            "available_engines": stats.get('available_ocr_engines', []),
            "supported_formats": stats.get('supported_image_formats', []) + stats.get('supported_pdf_formats', []),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"OCR health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


@router.get("/stats")
async def get_ocr_stats(current_user: Dict = Depends(get_current_user)):
    """
    Get detailed OCR processing statistics and capabilities.
    """
    try:
        processor = get_ocr_processor()
        return processor.get_processing_stats()
        
    except Exception as e:
        logger.error(f"Failed to get OCR stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


# Cleanup handler
@router.on_event("shutdown")
async def cleanup_ocr_resources():
    """Clean up OCR resources on shutdown."""
    global _ocr_processor
    try:
        if _ocr_processor:
            _ocr_processor.cleanup()
            _ocr_processor = None
        logger.info("OCR API resources cleaned up")
    except Exception as e:
        logger.error(f"OCR cleanup failed: {e}")


# Add router to main application
def get_ocr_router() -> APIRouter:
    """Get the OCR detection router."""
    return router