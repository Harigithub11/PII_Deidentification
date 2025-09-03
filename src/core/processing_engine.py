"""
Document processing engine - coordinates OCR, PII detection, and redaction
"""
import asyncio
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.models.database import (
    Document, ProcessingJob, PIIDetection, 
    RedactedDocument, PerformanceMetric, AuditLog
)
from src.services.ocr_service import ocr_service
from src.services.pii_service import pii_service

logger = logging.getLogger(__name__)


class DocumentProcessingEngine:
    """
    Main document processing engine that coordinates all processing steps
    """
    
    def __init__(self):
        """Initialize processing engine"""
        self.ocr_service = ocr_service
        self.pii_service = pii_service
    
    async def process_document(
        self, 
        document_id: uuid.UUID,
        db: AsyncSession,
        policy_config: Optional[Dict] = None
    ) -> Dict:
        """
        Process a complete document through the entire pipeline
        
        Args:
            document_id: UUID of document to process
            db: Database session
            policy_config: Processing policy configuration
            
        Returns:
            Processing results summary
        """
        start_time = time.time()
        
        try:
            # Get document from database
            document = await self._get_document(document_id, db)
            if not document:
                raise ValueError(f"Document {document_id} not found")
            
            logger.info(f"Starting processing for document: {document.original_filename}")
            
            # Update document status
            await self._update_document_status(document, "processing", db)
            
            # Step 1: OCR Text Extraction
            ocr_job = await self._create_processing_job(document_id, "ocr", db)
            ocr_result = await self._perform_ocr(document, ocr_job, db)
            
            if not ocr_result["success"]:
                raise Exception(f"OCR failed: {ocr_result.get('error', 'Unknown error')}")
            
            # Step 2: PII Detection
            pii_job = await self._create_processing_job(document_id, "pii_detection", db)
            pii_result = await self._perform_pii_detection(
                document, pii_job, ocr_result, policy_config, db
            )
            
            if not pii_result["success"]:
                raise Exception(f"PII detection failed: {pii_result.get('error', 'Unknown error')}")
            
            # Step 3: Redaction
            redaction_job = await self._create_processing_job(document_id, "redaction", db)
            redaction_result = await self._perform_redaction(
                document, redaction_job, ocr_result, pii_result, db
            )
            
            if not redaction_result["success"]:
                raise Exception(f"Redaction failed: {redaction_result.get('error', 'Unknown error')}")
            
            # Update final document status
            await self._update_document_status(document, "completed", db)
            
            # Record overall performance
            total_time = time.time() - start_time
            await self._record_performance_metric(
                document_id, "complete_pipeline", int(total_time * 1000), True, db
            )
            
            # Log audit event
            await self._log_audit_event(
                document_id, "processing_completed", 
                {"total_time_seconds": total_time}, db
            )
            
            result = {
                "success": True,
                "document_id": str(document_id),
                "processing_time_seconds": total_time,
                "ocr_result": ocr_result,
                "pii_result": pii_result,
                "redaction_result": redaction_result
            }
            
            logger.info(f"Document processing completed successfully in {total_time:.2f} seconds")
            return result
            
        except Exception as e:
            logger.error(f"Document processing failed: {e}")
            
            # Update document status to failed
            try:
                document = await self._get_document(document_id, db)
                if document:
                    await self._update_document_status(document, "failed", db)
            except:
                pass
            
            # Record failure metric
            total_time = time.time() - start_time
            await self._record_performance_metric(
                document_id, "complete_pipeline", int(total_time * 1000), False, db
            )
            
            return {
                "success": False,
                "document_id": str(document_id),
                "error": str(e),
                "processing_time_seconds": total_time
            }
    
    async def _get_document(self, document_id: uuid.UUID, db: AsyncSession) -> Optional[Document]:
        """Get document from database"""
        from sqlalchemy import select
        query = select(Document).where(Document.id == document_id)
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    async def _create_processing_job(
        self, document_id: uuid.UUID, job_type: str, db: AsyncSession
    ) -> ProcessingJob:
        """Create a new processing job"""
        job = ProcessingJob(
            document_id=document_id,
            job_type=job_type,
            status="running",
            started_at=datetime.utcnow()
        )
        
        db.add(job)
        await db.commit()
        await db.refresh(job)
        return job
    
    async def _update_processing_job(
        self, job: ProcessingJob, status: str, result_data: Dict, error_message: str = None, db: AsyncSession = None
    ):
        """Update processing job status"""
        job.status = status
        job.completed_at = datetime.utcnow()
        job.result_data = result_data
        job.error_message = error_message
        
        if db:
            await db.commit()
    
    async def _update_document_status(self, document: Document, status: str, db: AsyncSession):
        """Update document status"""
        document.status = status
        await db.commit()
    
    async def _perform_ocr(self, document: Document, job: ProcessingJob, db: AsyncSession) -> Dict:
        """Perform OCR text extraction"""
        start_time = time.time()
        
        try:
            logger.info(f"Starting OCR for {document.original_filename}")
            
            # Determine file type and extract text
            file_path = document.file_path
            mime_type = document.mime_type
            
            if mime_type == "application/pdf":
                ocr_result = self.ocr_service.extract_text_from_pdf(file_path)
            elif mime_type.startswith("image/"):
                ocr_result = self.ocr_service.extract_text_from_image(file_path)
            else:
                # For text files, read directly
                with open(file_path, 'r', encoding='utf-8') as f:
                    text = f.read()
                ocr_result = {
                    "text": text,
                    "confidence": 100,
                    "word_count": len(text.split()),
                    "success": True
                }
            
            # Record performance metric
            duration_ms = int((time.time() - start_time) * 1000)
            await self._record_performance_metric(
                document.id, "ocr", duration_ms, ocr_result["success"], db
            )
            
            # Update job
            await self._update_processing_job(
                job, "completed" if ocr_result["success"] else "failed", 
                ocr_result, None if ocr_result["success"] else ocr_result.get("error"), db
            )
            
            logger.info(f"OCR completed for {document.original_filename}: "
                       f"{len(ocr_result.get('text', ''))} characters extracted")
            
            return ocr_result
            
        except Exception as e:
            logger.error(f"OCR failed for {document.original_filename}: {e}")
            
            # Record failure metric
            duration_ms = int((time.time() - start_time) * 1000)
            await self._record_performance_metric(
                document.id, "ocr", duration_ms, False, db
            )
            
            # Update job
            await self._update_processing_job(
                job, "failed", {}, str(e), db
            )
            
            return {"success": False, "error": str(e), "text": ""}
    
    async def _perform_pii_detection(
        self, document: Document, job: ProcessingJob, ocr_result: Dict, 
        policy_config: Optional[Dict], db: AsyncSession
    ) -> Dict:
        """Perform PII detection on extracted text"""
        start_time = time.time()
        
        try:
            logger.info(f"Starting PII detection for {document.original_filename}")
            
            text = ocr_result.get("text", "")
            if not text.strip():
                logger.warning(f"No text available for PII detection in {document.original_filename}")
                return {
                    "success": True,
                    "detections": [],
                    "analysis": {"total_entities": 0, "risk_level": "low"}
                }
            
            # Perform comprehensive document analysis
            analysis_result = self.pii_service.analyze_document(text, policy_config)
            
            # Store PII detections in database
            stored_detections = []
            for detection in analysis_result["detections"]:
                pii_detection = PIIDetection(
                    document_id=document.id,
                    detection_type=detection["entity_type"],
                    detected_text=detection["text"],
                    confidence_score=detection["score"],
                    start_position=detection["start"],
                    end_position=detection["end"],
                    redaction_applied=False
                )
                
                db.add(pii_detection)
                stored_detections.append({
                    "entity_type": detection["entity_type"],
                    "text": detection["text"],
                    "confidence": detection["score"],
                    "start": detection["start"],
                    "end": detection["end"]
                })
            
            await db.commit()
            
            # Record performance metric
            duration_ms = int((time.time() - start_time) * 1000)
            await self._record_performance_metric(
                document.id, "pii_detection", duration_ms, True, db
            )
            
            # Update job
            result_data = {
                "detections": stored_detections,
                "statistics": analysis_result["statistics"],
                "risk_level": analysis_result["risk_level"],
                "recommendations": analysis_result["recommendations"]
            }
            
            await self._update_processing_job(job, "completed", result_data, None, db)
            
            logger.info(f"PII detection completed for {document.original_filename}: "
                       f"{len(stored_detections)} entities detected")
            
            return {
                "success": True,
                "detections": stored_detections,
                "analysis": analysis_result
            }
            
        except Exception as e:
            logger.error(f"PII detection failed for {document.original_filename}: {e}")
            
            # Record failure metric
            duration_ms = int((time.time() - start_time) * 1000)
            await self._record_performance_metric(
                document.id, "pii_detection", duration_ms, False, db
            )
            
            # Update job
            await self._update_processing_job(job, "failed", {}, str(e), db)
            
            return {"success": False, "error": str(e), "detections": []}
    
    async def _perform_redaction(
        self, document: Document, job: ProcessingJob, ocr_result: Dict, 
        pii_result: Dict, db: AsyncSession
    ) -> Dict:
        """Perform text redaction based on PII detections"""
        start_time = time.time()
        
        try:
            logger.info(f"Starting redaction for {document.original_filename}")
            
            text = ocr_result.get("text", "")
            detections = pii_result.get("detections", [])
            
            if not detections:
                logger.info(f"No PII to redact in {document.original_filename}")
                # Just copy original file as no redaction needed
                original_path = Path(document.file_path)
                redacted_path = Path(settings.OUTPUT_PATH) / f"redacted_{original_path.name}"
                
                import shutil
                shutil.copy2(document.file_path, redacted_path)
                
                redacted_doc = RedactedDocument(
                    original_document_id=document.id,
                    redacted_file_path=str(redacted_path),
                    redaction_method="none",
                    total_redactions=0,
                    redaction_summary={"message": "No PII detected, file copied unchanged"}
                )
                db.add(redacted_doc)
                await db.commit()
                
                await self._update_processing_job(
                    job, "completed", {"redacted_file": str(redacted_path), "redactions": 0}, None, db
                )
                
                return {
                    "success": True,
                    "redacted_file": str(redacted_path),
                    "total_redactions": 0
                }
            
            # Perform text anonymization
            anonymized_text, anonymization_details = self.pii_service.anonymize_text(
                text=text,
                analyzer_results=detections,
                anonymization_method="mask"
            )
            
            # Save redacted text to file
            original_path = Path(document.file_path)
            redacted_filename = f"redacted_{original_path.stem}.txt"
            redacted_path = Path(settings.OUTPUT_PATH) / redacted_filename
            
            # Ensure output directory exists
            redacted_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(redacted_path, 'w', encoding='utf-8') as f:
                f.write(anonymized_text)
            
            # Create redacted document record
            redaction_summary = {
                "original_entities": len(detections),
                "redacted_entities": len(anonymization_details),
                "redaction_method": "mask",
                "entity_types": list(set(d["entity_type"] for d in detections))
            }
            
            redacted_doc = RedactedDocument(
                original_document_id=document.id,
                redacted_file_path=str(redacted_path),
                redaction_method="mask",
                total_redactions=len(anonymization_details),
                redaction_summary=redaction_summary
            )
            
            db.add(redacted_doc)
            
            # Update PII detections to mark as redacted
            from sqlalchemy import select, update
            update_query = update(PIIDetection).where(
                PIIDetection.document_id == document.id
            ).values(redaction_applied=True)
            await db.execute(update_query)
            
            await db.commit()
            
            # Record performance metric
            duration_ms = int((time.time() - start_time) * 1000)
            await self._record_performance_metric(
                document.id, "redaction", duration_ms, True, db
            )
            
            # Update job
            result_data = {
                "redacted_file": str(redacted_path),
                "total_redactions": len(anonymization_details),
                "redaction_summary": redaction_summary
            }
            
            await self._update_processing_job(job, "completed", result_data, None, db)
            
            logger.info(f"Redaction completed for {document.original_filename}: "
                       f"{len(anonymization_details)} entities redacted")
            
            return {
                "success": True,
                "redacted_file": str(redacted_path),
                "total_redactions": len(anonymization_details),
                "redaction_summary": redaction_summary
            }
            
        except Exception as e:
            logger.error(f"Redaction failed for {document.original_filename}: {e}")
            
            # Record failure metric
            duration_ms = int((time.time() - start_time) * 1000)
            await self._record_performance_metric(
                document.id, "redaction", duration_ms, False, db
            )
            
            # Update job
            await self._update_processing_job(job, "failed", {}, str(e), db)
            
            return {"success": False, "error": str(e)}
    
    async def _record_performance_metric(
        self, document_id: uuid.UUID, stage: str, duration_ms: int, 
        success: bool, db: AsyncSession
    ):
        """Record performance metric"""
        try:
            metric = PerformanceMetric(
                document_id=document_id,
                processing_stage=stage,
                duration_ms=duration_ms,
                success=success,
                timestamp=datetime.utcnow()
            )
            
            db.add(metric)
            await db.commit()
        except Exception as e:
            logger.warning(f"Failed to record performance metric: {e}")
    
    async def _log_audit_event(
        self, document_id: uuid.UUID, action: str, details: Dict, db: AsyncSession
    ):
        """Log audit event"""
        try:
            audit_log = AuditLog(
                document_id=document_id,
                action=action,
                details=details,
                timestamp=datetime.utcnow()
            )
            
            db.add(audit_log)
            await db.commit()
        except Exception as e:
            logger.warning(f"Failed to log audit event: {e}")


# Global processing engine instance
processing_engine = DocumentProcessingEngine()