"""
Document PII Processor for PII De-identification System

This module provides unified document processing with integrated PII detection,
combining document format processing with comprehensive PII analysis for both
text and visual content.
"""

import logging
import time
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import uuid

from PIL import Image

from .document_factory import (
    DocumentFactory, 
    ProcessingOptions, 
    ProcessingMode, 
    UnifiedProcessingResult,
    DocumentType as DocType
)
from ..services.pii_detector import (
    PIIDetectionService, 
    PIIDetectionResult, 
    DetectionStatus, 
    RiskLevel,
    get_pii_detection_service
)
from ..services.visual_pii_detector import (
    VisualPIIDetectionService,
    VisualDetectionResult,
    VisualDetectionStatus,
    get_visual_pii_detection_service
)
from ..services.ocr_service import OCRService, get_ocr_service
from ..services.policy_engine import PolicyEngine, get_policy_engine, evaluate_pii_entities
from ..services.policy_applicator import PolicyApplicator, get_policy_applicator, ApplicationMethod
from ..config.policies.base import PIIType, RedactionMethod
from ..config.policy_models import PolicyContext, PolicyDecision, PolicyDecisionType
from ..config.settings import get_settings
from ..security.compliance_encryption import ComplianceStandard, DataClassification

logger = logging.getLogger(__name__)


class PIIProcessingMode(Enum):
    """PII processing modes for document analysis."""
    TEXT_ONLY = "text_only"              # Only process extracted text
    VISUAL_ONLY = "visual_only"          # Only process images/visual content
    COMPREHENSIVE = "comprehensive"      # Process both text and visual content
    OCR_ENHANCED = "ocr_enhanced"        # Include OCR processing for better text extraction


@dataclass
class PIIProcessingOptions:
    """Options for PII processing within document processing."""
    
    # PII detection modes
    pii_mode: PIIProcessingMode = PIIProcessingMode.COMPREHENSIVE
    enable_text_pii: bool = True
    enable_visual_pii: bool = True
    enable_ocr_pii: bool = True
    
    # Detection parameters
    text_confidence_threshold: float = 0.5
    visual_confidence_threshold: float = 0.6
    language: str = "en"
    model_type: str = "presidio"
    visual_model_type: str = "yolov8"
    
    # Entity filtering
    entity_types: Optional[List[str]] = None
    visual_entity_types: Optional[List[str]] = None
    
    # Compliance and security
    compliance_standards: Optional[List[ComplianceStandard]] = None
    encrypt_results: bool = True
    audit_logging: bool = True
    
    # Policy engine integration
    enable_policy_engine: bool = True
    policy_names: Optional[List[str]] = None
    apply_policies: bool = False
    policy_application_method: ApplicationMethod = ApplicationMethod.PREVIEW
    
    # Processing optimization
    parallel_processing: bool = True
    max_workers: int = 3
    timeout_seconds: int = 300


@dataclass
class PIIDocumentResult:
    """Unified result container for document processing with PII detection."""
    
    # Basic identifiers
    document_id: str
    processing_id: str
    
    # Status and timing
    success: bool
    started_at: datetime
    completed_at: Optional[datetime] = None
    total_processing_time: float = 0.0
    
    # Document processing results
    document_result: Optional[UnifiedProcessingResult] = None
    document_type: Optional[DocType] = None
    page_count: int = 0
    
    # PII Detection results
    text_pii_results: List[PIIDetectionResult] = field(default_factory=list)
    visual_pii_results: List[VisualDetectionResult] = field(default_factory=list)
    ocr_pii_results: List[PIIDetectionResult] = field(default_factory=list)
    
    # Consolidated PII analysis
    total_text_entities: int = 0
    total_visual_entities: int = 0
    unique_pii_types: List[str] = field(default_factory=list)
    overall_risk_level: RiskLevel = RiskLevel.LOW
    compliance_flags: List[str] = field(default_factory=list)
    
    # Policy engine results
    policy_decisions: List[PolicyDecision] = field(default_factory=list)
    policy_violations: List[str] = field(default_factory=list)
    policies_applied: List[str] = field(default_factory=list)
    redacted_content: Optional[Dict[str, Any]] = None
    
    # Processing metadata
    processing_options: Optional[PIIProcessingOptions] = None
    operations_performed: List[str] = field(default_factory=list)
    errors_encountered: List[str] = field(default_factory=list)
    
    # Performance metrics
    document_processing_time: float = 0.0
    text_pii_processing_time: float = 0.0
    visual_pii_processing_time: float = 0.0
    ocr_processing_time: float = 0.0
    
    def __post_init__(self):
        if not self.document_id:
            self.document_id = str(uuid.uuid4())
        if not self.processing_id:
            self.processing_id = str(uuid.uuid4())
        
        # Calculate consolidated metrics
        self._calculate_consolidated_metrics()
    
    def _calculate_consolidated_metrics(self):
        """Calculate consolidated PII detection metrics."""
        
        # Count total entities
        self.total_text_entities = sum(
            len(result.entities) for result in self.text_pii_results + self.ocr_pii_results
        )
        self.total_visual_entities = sum(
            len(result.entities) for result in self.visual_pii_results
        )
        
        # Collect unique PII types
        all_types = set()
        for result in self.text_pii_results + self.ocr_pii_results:
            all_types.update(result.unique_entity_types)
        for result in self.visual_pii_results:
            all_types.update([entity.entity_type.value for entity in result.entities])
        
        self.unique_pii_types = list(all_types)
        
        # Determine overall risk level
        risk_levels = []
        for result in self.text_pii_results + self.ocr_pii_results:
            risk_levels.append(result.risk_level)
        for result in self.visual_pii_results:
            risk_levels.append(result.risk_level)
        
        if RiskLevel.CRITICAL in risk_levels:
            self.overall_risk_level = RiskLevel.CRITICAL
        elif RiskLevel.HIGH in risk_levels:
            self.overall_risk_level = RiskLevel.HIGH
        elif RiskLevel.MEDIUM in risk_levels:
            self.overall_risk_level = RiskLevel.MEDIUM
        else:
            self.overall_risk_level = RiskLevel.LOW
        
        # Collect compliance flags
        all_flags = set()
        for result in self.text_pii_results + self.ocr_pii_results:
            all_flags.update(result.compliance_flags)
        for result in self.visual_pii_results:
            all_flags.update(result.compliance_flags)
        
        self.compliance_flags = list(all_flags)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of the complete processing and PII detection results."""
        return {
            "document_id": self.document_id,
            "processing_id": self.processing_id,
            "success": self.success,
            "document_type": self.document_type.value if self.document_type else None,
            "page_count": self.page_count,
            "total_processing_time": self.total_processing_time,
            "pii_summary": {
                "total_text_entities": self.total_text_entities,
                "total_visual_entities": self.total_visual_entities,
                "unique_pii_types": len(self.unique_pii_types),
                "overall_risk_level": self.overall_risk_level.value,
                "compliance_flags": self.compliance_flags
            },
            "performance": {
                "document_processing_time": self.document_processing_time,
                "text_pii_processing_time": self.text_pii_processing_time,
                "visual_pii_processing_time": self.visual_pii_processing_time,
                "ocr_processing_time": self.ocr_processing_time
            },
            "operations_performed": self.operations_performed,
            "errors_encountered": self.errors_encountered
        }


class DocumentPIIProcessor:
    """Unified processor for document processing with integrated PII detection."""
    
    def __init__(self):
        # Core processing components
        self.document_factory = DocumentFactory()
        self.pii_service = get_pii_detection_service()
        self.visual_pii_service = get_visual_pii_detection_service()
        self.ocr_service = get_ocr_service()
        
        # Policy engine components
        self.policy_engine = get_policy_engine()
        self.policy_applicator = get_policy_applicator()
        
        # Settings
        self.settings = get_settings()
        
        # Processing history
        self.processing_history: Dict[str, PIIDocumentResult] = {}
        
        logger.info("Initialized DocumentPIIProcessor with all services including policy engine")
    
    async def process_document_with_pii(
        self,
        file_path: Union[str, Path],
        document_id: Optional[str] = None,
        processing_options: Optional[ProcessingOptions] = None,
        pii_options: Optional[PIIProcessingOptions] = None
    ) -> PIIDocumentResult:
        """Process document with integrated PII detection."""
        
        start_time = time.time()
        
        # Initialize options
        if processing_options is None:
            processing_options = ProcessingOptions()
        if pii_options is None:
            pii_options = PIIProcessingOptions()
        
        # Create result container
        result = PIIDocumentResult(
            document_id=document_id or str(uuid.uuid4()),
            processing_id=str(uuid.uuid4()),
            success=False,
            started_at=datetime.now(),
            processing_options=pii_options
        )
        
        try:
            # Step 1: Document Processing
            logger.info(f"Starting document processing for {file_path}")
            doc_start_time = time.time()
            
            document_result = self.document_factory.process_document(file_path, processing_options)
            result.document_result = document_result
            result.document_type = document_result.document_type
            result.page_count = document_result.page_count
            result.document_processing_time = time.time() - doc_start_time
            
            if not document_result.success:
                result.errors_encountered.extend(document_result.errors_encountered)
                raise RuntimeError(f"Document processing failed: {document_result.errors_encountered}")
            
            result.operations_performed.append("document_processing")
            
            # Step 2: PII Detection on different content types
            tasks = []
            
            if pii_options.enable_text_pii and document_result.extracted_text:
                tasks.append(self._process_text_pii(document_result.extracted_text, pii_options, result))
            
            if pii_options.enable_visual_pii and document_result.extracted_images:
                tasks.append(self._process_visual_pii(document_result.extracted_images, pii_options, result))
            
            if pii_options.enable_ocr_pii and document_result.extracted_images:
                tasks.append(self._process_ocr_pii(document_result.extracted_images, pii_options, result))
            
            # Execute PII detection tasks
            if tasks:
                if pii_options.parallel_processing:
                    await asyncio.gather(*tasks, return_exceptions=True)
                else:
                    for task in tasks:
                        await task
            
            # Step 3: Policy Engine Integration
            if pii_options.enable_policy_engine:
                await self._apply_policy_engine(result, pii_options, document_result)
            
            # Step 4: Finalize results
            result.completed_at = datetime.now()
            result.total_processing_time = time.time() - start_time
            result.success = len(result.errors_encountered) == 0
            
            result._calculate_consolidated_metrics()
            
            logger.info(f"Completed document PII processing in {result.total_processing_time:.2f}s")
            
        except Exception as e:
            logger.error(f"Error in document PII processing: {e}")
            result.errors_encountered.append(f"Processing failed: {str(e)}")
            result.completed_at = datetime.now()
            result.total_processing_time = time.time() - start_time
        
        # Store in history
        self.processing_history[result.processing_id] = result
        
        return result
    
    async def _process_text_pii(
        self, 
        text: str, 
        options: PIIProcessingOptions, 
        result: PIIDocumentResult
    ):
        """Process text content for PII detection."""
        try:
            text_start_time = time.time()
            
            # Detect PII in extracted text
            pii_result = await self.pii_service.detect_pii_async(
                text=text,
                document_id=result.document_id,
                language=options.language,
                model_type=options.model_type,
                entity_types=options.entity_types,
                confidence_threshold=options.text_confidence_threshold,
                compliance_standards=options.compliance_standards
            )
            
            result.text_pii_results.append(pii_result)
            result.text_pii_processing_time = time.time() - text_start_time
            result.operations_performed.append("text_pii_detection")
            
            logger.debug(f"Text PII detection completed: {len(pii_result.entities)} entities found")
            
        except Exception as e:
            logger.error(f"Text PII processing failed: {e}")
            result.errors_encountered.append(f"Text PII detection failed: {str(e)}")
    
    async def _process_visual_pii(
        self, 
        images: List[Image.Image], 
        options: PIIProcessingOptions, 
        result: PIIDocumentResult
    ):
        """Process visual content for PII detection."""
        try:
            visual_start_time = time.time()
            
            for i, image in enumerate(images):
                visual_result = await self.visual_pii_service.detect_visual_pii_async(
                    image=image,
                    document_id=result.document_id,
                    page_number=i + 1,
                    model_type=options.visual_model_type,
                    entity_types=options.visual_entity_types,
                    confidence_threshold=options.visual_confidence_threshold,
                    compliance_standards=options.compliance_standards
                )
                
                result.visual_pii_results.append(visual_result)
            
            result.visual_pii_processing_time = time.time() - visual_start_time
            result.operations_performed.append("visual_pii_detection")
            
            total_visual_entities = sum(len(r.entities) for r in result.visual_pii_results)
            logger.debug(f"Visual PII detection completed: {total_visual_entities} entities found")
            
        except Exception as e:
            logger.error(f"Visual PII processing failed: {e}")
            result.errors_encountered.append(f"Visual PII detection failed: {str(e)}")
    
    async def _process_ocr_pii(
        self, 
        images: List[Image.Image], 
        options: PIIProcessingOptions, 
        result: PIIDocumentResult
    ):
        """Process OCR-extracted text for PII detection."""
        try:
            ocr_start_time = time.time()
            
            for i, image in enumerate(images):
                # Perform OCR
                ocr_result = await self.ocr_service.process_image_async(
                    image=image,
                    language=options.language
                )
                
                if ocr_result.success and ocr_result.extracted_text:
                    # Detect PII in OCR text
                    pii_result = await self.pii_service.detect_pii_async(
                        text=ocr_result.extracted_text,
                        document_id=result.document_id,
                        language=options.language,
                        model_type=options.model_type,
                        entity_types=options.entity_types,
                        confidence_threshold=options.text_confidence_threshold,
                        compliance_standards=options.compliance_standards
                    )
                    
                    result.ocr_pii_results.append(pii_result)
            
            result.ocr_processing_time = time.time() - ocr_start_time
            result.operations_performed.append("ocr_pii_detection")
            
            total_ocr_entities = sum(len(r.entities) for r in result.ocr_pii_results)
            logger.debug(f"OCR PII detection completed: {total_ocr_entities} entities found")
            
        except Exception as e:
            logger.error(f"OCR PII processing failed: {e}")
            result.errors_encountered.append(f"OCR PII detection failed: {str(e)}")
    
    async def _apply_policy_engine(
        self,
        result: PIIDocumentResult,
        options: PIIProcessingOptions,
        document_result: UnifiedProcessingResult
    ):
        """Apply policy engine to detected PII entities."""
        try:
            policy_start_time = time.time()
            
            # Create policy context
            context = PolicyContext(
                document_id=result.document_id,
                document_type=document_result.document_type.value if document_result.document_type else None,
                processing_mode=options.pii_mode.value,
                compliance_standards=[std.value for std in options.compliance_standards] if options.compliance_standards else [],
                metadata={
                    "page_count": result.page_count,
                    "processing_options": options.__dict__
                }
            )
            
            # Collect all detected entities
            all_entities = []
            
            # Add text entities
            for detection_result in result.text_pii_results + result.ocr_pii_results:
                all_entities.extend(detection_result.entities)
            
            # Add visual entities
            for detection_result in result.visual_pii_results:
                all_entities.extend(detection_result.entities)
            
            if not all_entities:
                logger.debug("No entities found for policy evaluation")
                return
            
            # Evaluate entities against policies
            policy_evaluation = await self.policy_engine.evaluate_entities_async(
                entities=all_entities,
                context=context,
                policy_names=options.policy_names
            )
            
            if policy_evaluation.success:
                result.policy_decisions = policy_evaluation.decisions
                result.policy_violations = [v.description for v in policy_evaluation.violations]
                result.policies_applied = list(set(d.applied_policy for d in policy_evaluation.decisions))
                
                # Apply policies if requested
                if options.apply_policies and policy_evaluation.decisions:
                    application_result = await self.policy_applicator.apply_decisions_async(
                        decisions=policy_evaluation.decisions,
                        text_content=document_result.extracted_text,
                        visual_content=document_result.extracted_images[0] if document_result.extracted_images else None,
                        context=context,
                        method=options.policy_application_method
                    )
                    
                    if application_result.success:
                        result.redacted_content = {
                            "text": application_result.text_result.redacted_text if application_result.text_result else None,
                            "redaction_map": application_result.text_result.redaction_map if application_result.text_result else {},
                            "visual_regions": application_result.visual_result.redaction_regions if application_result.visual_result else []
                        }
                        result.operations_performed.append("policy_application")
                    else:
                        result.errors_encountered.append(f"Policy application failed: {application_result.error_message}")
                
                result.operations_performed.append("policy_evaluation")
                logger.debug(f"Policy evaluation completed: {len(policy_evaluation.decisions)} decisions, {len(policy_evaluation.violations)} violations")
                
            else:
                result.errors_encountered.append(f"Policy evaluation failed: {policy_evaluation.error_message}")
            
            policy_processing_time = time.time() - policy_start_time
            logger.debug(f"Policy engine processing completed in {policy_processing_time:.2f}s")
            
        except Exception as e:
            logger.error(f"Policy engine integration failed: {e}")
            result.errors_encountered.append(f"Policy engine failed: {str(e)}")
    
    def process_document_with_pii_sync(
        self,
        file_path: Union[str, Path],
        document_id: Optional[str] = None,
        processing_options: Optional[ProcessingOptions] = None,
        pii_options: Optional[PIIProcessingOptions] = None
    ) -> PIIDocumentResult:
        """Synchronous version of document processing with PII detection."""
        
        # Create event loop if none exists
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(
            self.process_document_with_pii(file_path, document_id, processing_options, pii_options)
        )
    
    def get_processing_result(self, processing_id: str) -> Optional[PIIDocumentResult]:
        """Get processing result by ID."""
        return self.processing_history.get(processing_id)
    
    def get_processing_statistics(self) -> Dict[str, Any]:
        """Get processing statistics and performance metrics."""
        
        total_processed = len(self.processing_history)
        successful = sum(1 for r in self.processing_history.values() if r.success)
        
        if total_processed == 0:
            return {
                "total_processed": 0,
                "success_rate": 0.0,
                "average_processing_time": 0.0,
                "supported_formats": self.document_factory.get_supported_formats()
            }
        
        avg_time = sum(r.total_processing_time for r in self.processing_history.values()) / total_processed
        
        # Risk level distribution
        risk_distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for result in self.processing_history.values():
            if result.success:
                risk_distribution[result.overall_risk_level.value] += 1
        
        # PII type distribution
        pii_types = {}
        for result in self.processing_history.values():
            for pii_type in result.unique_pii_types:
                pii_types[pii_type] = pii_types.get(pii_type, 0) + 1
        
        return {
            "total_processed": total_processed,
            "successful_processed": successful,
            "success_rate": successful / total_processed,
            "average_processing_time": avg_time,
            "risk_level_distribution": risk_distribution,
            "pii_type_distribution": pii_types,
            "supported_formats": self.document_factory.get_supported_formats(),
            "services_status": {
                "document_factory": "active",
                "pii_service": "active",
                "visual_pii_service": "active",
                "ocr_service": "active"
            }
        }
    
    def cleanup_history(self, max_age_hours: int = 24):
        """Clean up old processing history."""
        cutoff_time = datetime.now().timestamp() - (max_age_hours * 3600)
        
        to_remove = []
        for processing_id, result in self.processing_history.items():
            if result.completed_at and result.completed_at.timestamp() < cutoff_time:
                to_remove.append(processing_id)
        
        for processing_id in to_remove:
            del self.processing_history[processing_id]
        
        logger.info(f"Cleaned up {len(to_remove)} old processing records")


# Global service instance
_default_document_pii_processor = None

def get_document_pii_processor() -> DocumentPIIProcessor:
    """Get or create the default document PII processor instance."""
    global _default_document_pii_processor
    
    if _default_document_pii_processor is None:
        _default_document_pii_processor = DocumentPIIProcessor()
    
    return _default_document_pii_processor


# Convenience functions
async def quick_document_pii_analysis(
    file_path: Union[str, Path],
    pii_mode: PIIProcessingMode = PIIProcessingMode.COMPREHENSIVE,
    confidence_threshold: float = 0.5
) -> PIIDocumentResult:
    """Quick document processing with PII detection using default settings."""
    
    processor = get_document_pii_processor()
    
    pii_options = PIIProcessingOptions(
        pii_mode=pii_mode,
        text_confidence_threshold=confidence_threshold,
        visual_confidence_threshold=confidence_threshold
    )
    
    return await processor.process_document_with_pii(
        file_path=file_path,
        pii_options=pii_options
    )


def quick_document_pii_analysis_sync(
    file_path: Union[str, Path],
    pii_mode: PIIProcessingMode = PIIProcessingMode.COMPREHENSIVE,
    confidence_threshold: float = 0.5
) -> PIIDocumentResult:
    """Synchronous version of quick document PII analysis."""
    
    processor = get_document_pii_processor()
    
    pii_options = PIIProcessingOptions(
        pii_mode=pii_mode,
        text_confidence_threshold=confidence_threshold,
        visual_confidence_threshold=confidence_threshold
    )
    
    return processor.process_document_with_pii_sync(
        file_path=file_path,
        pii_options=pii_options
    )