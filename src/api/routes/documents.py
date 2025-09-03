"""
Document management endpoints
"""
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import List

import aiofiles
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.core.config import settings
from src.core.database import get_async_db
from src.models.database import Document, AuditLog, RedactedDocument
from src.models.schemas import (
    DocumentResponse, 
    DocumentStatusUpdate,
    FileUploadResponse,
    AuditLogCreate
)

router = APIRouter()


def validate_file(file: UploadFile) -> None:
    """
    Validate uploaded file
    """
    # Check file size
    if file.size and file.size > settings.MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size is {settings.MAX_FILE_SIZE / (1024*1024):.0f}MB"
        )
    
    # Check file type
    if file.content_type not in settings.ALLOWED_FILE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"File type '{file.content_type}' not supported. "
                   f"Allowed types: {', '.join(settings.ALLOWED_FILE_TYPES)}"
        )


async def save_uploaded_file(file: UploadFile, upload_path: str) -> str:
    """
    Save uploaded file to disk
    """
    file_extension = Path(file.filename).suffix
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = Path(upload_path) / unique_filename
    
    # Ensure upload directory exists
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        async with aiofiles.open(file_path, 'wb') as f:
            content = await file.read()
            await f.write(content)
        
        return str(file_path)
    
    except Exception as e:
        # Clean up partial file if it exists
        if file_path.exists():
            file_path.unlink()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save file: {str(e)}"
        )


async def log_audit_event(
    db: AsyncSession, 
    action: str, 
    document_id: uuid.UUID = None,
    details: dict = None,
    user_id: str = None
):
    """
    Log audit event
    """
    audit_log = AuditLog(
        document_id=document_id,
        action=action,
        user_id=user_id,
        details=details,
        timestamp=datetime.utcnow()
    )
    
    db.add(audit_log)
    await db.commit()


@router.post("/documents/upload", response_model=FileUploadResponse)
async def upload_document(
    file: UploadFile = File(...),
    policy_id: str = Form(None),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Upload a document for processing
    """
    # Validate the uploaded file
    validate_file(file)
    
    try:
        # Save file to upload directory
        file_path = await save_uploaded_file(file, settings.UPLOAD_PATH)
        
        # Get actual file size
        file_size = Path(file_path).stat().st_size
        
        # Create document record
        document = Document(
            original_filename=file.filename,
            file_path=file_path,
            file_size=file_size,
            mime_type=file.content_type,
            status="uploaded"
        )
        
        db.add(document)
        await db.commit()
        await db.refresh(document)
        
        # Log audit event
        await log_audit_event(
            db=db,
            action="upload",
            document_id=document.id,
            details={
                "filename": file.filename,
                "file_size": file_size,
                "mime_type": file.content_type,
                "policy_id": policy_id
            }
        )
        
        return FileUploadResponse(
            message="File uploaded successfully",
            document_id=document.id,
            filename=file.filename,
            file_size=file_size,
            status="uploaded"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Upload failed: {str(e)}"
        )


@router.get("/documents", response_model=List[DocumentResponse])
async def list_documents(
    skip: int = 0,
    limit: int = 100,
    status_filter: str = None,
    db: AsyncSession = Depends(get_async_db)
):
    """
    List uploaded documents
    """
    query = select(Document).offset(skip).limit(limit).order_by(Document.created_at.desc())
    
    if status_filter:
        query = query.where(Document.status == status_filter)
    
    result = await db.execute(query)
    documents = result.scalars().all()
    
    return [DocumentResponse.from_orm(doc) for doc in documents]


@router.get("/documents/{document_id}", response_model=DocumentResponse)
async def get_document(
    document_id: uuid.UUID,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Get document details by ID
    """
    query = select(Document).where(Document.id == document_id)
    result = await db.execute(query)
    document = result.scalar_one_or_none()
    
    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    return DocumentResponse.from_orm(document)


@router.put("/documents/{document_id}/status", response_model=DocumentResponse)
async def update_document_status(
    document_id: uuid.UUID,
    status_update: DocumentStatusUpdate,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Update document status
    """
    query = select(Document).where(Document.id == document_id)
    result = await db.execute(query)
    document = result.scalar_one_or_none()
    
    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    old_status = document.status
    document.status = status_update.status
    
    await db.commit()
    await db.refresh(document)
    
    # Log audit event
    await log_audit_event(
        db=db,
        action="status_update",
        document_id=document.id,
        details={
            "old_status": old_status,
            "new_status": status_update.status
        }
    )
    
    return DocumentResponse.from_orm(document)


@router.delete("/documents/{document_id}")
async def delete_document(
    document_id: uuid.UUID,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Delete a document and its associated file
    """
    query = select(Document).where(Document.id == document_id)
    result = await db.execute(query)
    document = result.scalar_one_or_none()
    
    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    # Delete physical file
    try:
        file_path = Path(document.file_path)
        if file_path.exists():
            file_path.unlink()
    except Exception as e:
        # Log warning but don't fail the deletion
        print(f"Warning: Could not delete file {document.file_path}: {e}")
    
    # Log audit event before deletion
    await log_audit_event(
        db=db,
        action="delete",
        document_id=document.id,
        details={
            "filename": document.original_filename,
            "file_path": document.file_path
        }
    )
    
    # Delete database record (cascades to related records)
    await db.delete(document)
    await db.commit()
    
    return {"message": "Document deleted successfully"}


@router.get("/documents/{document_id}/download")
async def download_document(
    document_id: uuid.UUID,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Download original document
    """
    query = select(Document).where(Document.id == document_id)
    result = await db.execute(query)
    document = result.scalar_one_or_none()
    
    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    file_path = Path(document.file_path)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found on disk"
        )
    
    # Log audit event
    await log_audit_event(
        db=db,
        action="download",
        document_id=document.id,
        details={
            "filename": document.original_filename,
            "download_type": "original"
        }
    )
    
    from fastapi.responses import FileResponse
    return FileResponse(
        path=file_path,
        filename=document.original_filename,
        media_type=document.mime_type
    )


@router.get("/documents/{document_id}/download-redacted")
async def download_redacted_document(
    document_id: uuid.UUID,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Download redacted document
    """
    # Get redacted document
    query = select(RedactedDocument).where(
        RedactedDocument.original_document_id == document_id
    ).order_by(RedactedDocument.created_at.desc())
    
    result = await db.execute(query)
    redacted_doc = result.scalar_one_or_none()
    
    if not redacted_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Redacted document not found. Document may not have been processed yet."
        )
    
    file_path = Path(redacted_doc.redacted_file_path)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Redacted file not found on disk"
        )
    
    # Get original document for filename
    doc_query = select(Document).where(Document.id == document_id)
    doc_result = await db.execute(doc_query)
    original_doc = doc_result.scalar_one_or_none()
    
    original_filename = original_doc.original_filename if original_doc else "redacted_document"
    redacted_filename = f"redacted_{original_filename}"
    
    # Log audit event
    await log_audit_event(
        db=db,
        action="download",
        document_id=document_id,
        details={
            "filename": redacted_filename,
            "download_type": "redacted",
            "redaction_method": redacted_doc.redaction_method,
            "total_redactions": redacted_doc.total_redactions
        }
    )
    
    from fastapi.responses import FileResponse
    return FileResponse(
        path=file_path,
        filename=redacted_filename,
        media_type="text/plain"  # Redacted files are saved as text
    )