"""
Enhanced spaCy Service for PII De-identification System

This module provides high-level spaCy NLP services with:
- Advanced linguistic analysis and document processing
- Multi-language support with automatic detection
- Integration with existing PII detection pipeline
- Batch processing and streaming capabilities
- Performance optimization and caching
- Async/sync processing options
"""

import asyncio
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple, AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
import json
import hashlib
from collections import defaultdict

from ..processing.spacy_processor import (
    SpacyProcessor, SpacyProcessingConfig, SpacyAnalysisResult,
    LanguageDetectionResult, TextComplexity, create_spacy_processor
)
from ..models.ner_models import PIIEntity, create_ner_model
from ..services.pii_detector import PIIDetectionService, PIIDetectionResult
from ..config.settings import get_settings
from ..security.compliance_encryption import compliance_encryption

logger = logging.getLogger(__name__)


class ProcessingPriority(Enum):
    """Processing priority levels for task scheduling."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


@dataclass
class NLPProcessingJob:
    """NLP processing job with metadata and status tracking."""
    job_id: str
    text: str
    language: Optional[str] = None
    model_name: Optional[str] = None
    config: Optional[SpacyProcessingConfig] = None
    priority: ProcessingPriority = ProcessingPriority.NORMAL
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "pending"  # pending, processing, completed, failed
    result: Optional[SpacyAnalysisResult] = None
    error_message: Optional[str] = None
    
    @property
    def processing_time(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    @property
    def is_completed(self) -> bool:
        return self.status in ["completed", "failed"]


@dataclass
class BatchProcessingResult:
    """Result of batch NLP processing operation."""
    total_jobs: int
    completed_jobs: int
    failed_jobs: int
    processing_time: float
    results: List[SpacyAnalysisResult]
    job_details: List[NLPProcessingJob]
    summary_statistics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StreamProcessingStats:
    """Statistics for stream processing operations."""
    documents_processed: int = 0
    total_processing_time: float = 0.0
    average_processing_time: float = 0.0
    languages_detected: Dict[str, int] = field(default_factory=dict)
    complexity_distribution: Dict[str, int] = field(default_factory=dict)
    errors_encountered: int = 0


class SpacyService:
    """Enhanced spaCy service with advanced NLP capabilities."""
    
    def __init__(
        self,
        default_config: Optional[SpacyProcessingConfig] = None,
        enable_pii_detection: bool = True,
        enable_caching: bool = True,
        max_cache_size: int = 1000,
        max_workers: int = 4,
        enable_performance_monitoring: bool = True
    ):
        self.default_config = default_config or SpacyProcessingConfig()
        self.enable_pii_detection = enable_pii_detection
        self.enable_caching = enable_caching
        self.max_cache_size = max_cache_size
        self.max_workers = max_workers
        self.enable_performance_monitoring = enable_performance_monitoring
        
        self.settings = get_settings()
        
        # Initialize processors
        self.spacy_processor = create_spacy_processor(self.default_config)
        
        # Initialize PII detection service if enabled
        self.pii_service: Optional[PIIDetectionService] = None
        if enable_pii_detection:
            try:
                self.pii_service = PIIDetectionService()
            except Exception as e:
                logger.warning(f"Failed to initialize PII detection service: {e}")
        
        # Thread pool for concurrent processing
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Processing job queue and tracking
        self.processing_jobs: Dict[str, NLPProcessingJob] = {}
        self.job_queue: List[str] = []
        self.processing_stats: Dict[str, Any] = defaultdict(int)
        
        # Performance monitoring
        self.performance_history: List[Dict[str, Any]] = []
        self.last_cleanup = datetime.utcnow()
        
        logger.info("SpacyService initialized with advanced NLP capabilities")
    
    def analyze_text(
        self,
        text: str,
        language: Optional[str] = None,
        model_name: Optional[str] = None,
        config: Optional[SpacyProcessingConfig] = None,
        include_pii_detection: bool = None,
        job_id: Optional[str] = None
    ) -> SpacyAnalysisResult:
        """Perform comprehensive linguistic analysis of text."""
        start_time = time.time()
        
        if include_pii_detection is None:
            include_pii_detection = self.enable_pii_detection
        
        try:
            # Generate job ID if not provided
            if not job_id:
                job_id = self._generate_job_id(text, language, model_name)
            
            # Create processing job for tracking
            job = NLPProcessingJob(
                job_id=job_id,
                text=text,
                language=language,
                model_name=model_name,
                config=config,
                started_at=datetime.utcnow(),
                status="processing"
            )
            self.processing_jobs[job_id] = job
            
            # Perform spaCy analysis
            analysis_config = config or self.default_config
            analysis_result = self.spacy_processor.analyze_text(
                text, language, model_name, analysis_config
            )
            
            # Enhance with PII detection if enabled
            if include_pii_detection and analysis_result.success and self.pii_service:
                pii_result = self._integrate_pii_detection(text, analysis_result)
                analysis_result = self._merge_pii_with_spacy_analysis(analysis_result, pii_result)
            
            # Update job status
            job.completed_at = datetime.utcnow()
            job.status = "completed" if analysis_result.success else "failed"
            job.result = analysis_result
            if not analysis_result.success:
                job.error_message = "; ".join(analysis_result.processing_errors)
            
            # Update performance statistics
            processing_time = time.time() - start_time
            self._update_performance_stats(analysis_result, processing_time)
            
            return analysis_result
            
        except Exception as e:
            # Update job with error status
            if job_id in self.processing_jobs:
                job = self.processing_jobs[job_id]
                job.completed_at = datetime.utcnow()
                job.status = "failed"
                job.error_message = str(e)
            
            logger.error(f"Text analysis failed: {e}")
            return SpacyAnalysisResult(
                success=False,
                text_length=len(text) if text else 0,
                processing_time=time.time() - start_time,
                processing_errors=[str(e)]
            )
    
    async def analyze_text_async(
        self,
        text: str,
        language: Optional[str] = None,
        model_name: Optional[str] = None,
        config: Optional[SpacyProcessingConfig] = None,
        include_pii_detection: bool = None,
        job_id: Optional[str] = None
    ) -> SpacyAnalysisResult:
        """Asynchronous text analysis."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor,
            self.analyze_text,
            text, language, model_name, config, include_pii_detection, job_id
        )
    
    def batch_analyze_texts(
        self,
        texts: List[str],
        languages: Optional[List[str]] = None,
        model_names: Optional[List[str]] = None,
        configs: Optional[List[SpacyProcessingConfig]] = None,
        include_pii_detection: bool = None,
        priority: ProcessingPriority = ProcessingPriority.NORMAL
    ) -> BatchProcessingResult:
        """Batch analyze multiple texts with job tracking."""
        start_time = time.time()
        
        if include_pii_detection is None:
            include_pii_detection = self.enable_pii_detection
        
        # Prepare job parameters
        job_params = []
        for i, text in enumerate(texts):
            language = languages[i] if languages and i < len(languages) else None
            model_name = model_names[i] if model_names and i < len(model_names) else None
            config = configs[i] if configs and i < len(configs) else None
            
            job_params.append({
                'text': text,
                'language': language,
                'model_name': model_name,
                'config': config,
                'include_pii_detection': include_pii_detection,
                'priority': priority
            })
        
        # Process jobs
        results = []
        job_details = []
        completed_count = 0
        failed_count = 0
        
        for params in job_params:
            try:
                result = self.analyze_text(**params)
                results.append(result)
                
                if result.success:
                    completed_count += 1
                else:
                    failed_count += 1
                
                # Get job details
                job_id = self._generate_job_id(params['text'], params['language'], params['model_name'])
                if job_id in self.processing_jobs:
                    job_details.append(self.processing_jobs[job_id])
                    
            except Exception as e:
                logger.error(f"Batch processing failed for text: {e}")
                failed_count += 1
                results.append(SpacyAnalysisResult(
                    success=False,
                    text_length=len(params['text']) if params['text'] else 0,
                    processing_time=0.0,
                    processing_errors=[str(e)]
                ))
        
        processing_time = time.time() - start_time
        
        # Generate summary statistics
        summary_stats = self._generate_batch_summary_statistics(results)
        
        return BatchProcessingResult(
            total_jobs=len(texts),
            completed_jobs=completed_count,
            failed_jobs=failed_count,
            processing_time=processing_time,
            results=results,
            job_details=job_details,
            summary_statistics=summary_stats
        )
    
    async def batch_analyze_texts_async(
        self,
        texts: List[str],
        languages: Optional[List[str]] = None,
        model_names: Optional[List[str]] = None,
        configs: Optional[List[SpacyProcessingConfig]] = None,
        include_pii_detection: bool = None,
        priority: ProcessingPriority = ProcessingPriority.NORMAL,
        max_concurrent: int = None
    ) -> BatchProcessingResult:
        """Asynchronous batch text analysis with concurrency control."""
        start_time = time.time()
        
        if include_pii_detection is None:
            include_pii_detection = self.enable_pii_detection
        
        max_concurrent = max_concurrent or self.max_workers
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def analyze_with_semaphore(params):
            async with semaphore:
                return await self.analyze_text_async(**params)
        
        # Prepare tasks
        tasks = []
        for i, text in enumerate(texts):
            language = languages[i] if languages and i < len(languages) else None
            model_name = model_names[i] if model_names and i < len(model_names) else None
            config = configs[i] if configs and i < len(configs) else None
            
            params = {
                'text': text,
                'language': language,
                'model_name': model_name,
                'config': config,
                'include_pii_detection': include_pii_detection
            }
            
            task = analyze_with_semaphore(params)
            tasks.append(task)
        
        # Execute tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        processed_results = []
        job_details = []
        completed_count = 0
        failed_count = 0
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Async batch processing failed for text {i}: {result}")
                failed_count += 1
                processed_results.append(SpacyAnalysisResult(
                    success=False,
                    text_length=len(texts[i]) if i < len(texts) else 0,
                    processing_time=0.0,
                    processing_errors=[str(result)]
                ))
            else:
                processed_results.append(result)
                if result.success:
                    completed_count += 1
                else:
                    failed_count += 1
                
                # Get job details
                job_id = self._generate_job_id(texts[i], languages[i] if languages and i < len(languages) else None, None)
                if job_id in self.processing_jobs:
                    job_details.append(self.processing_jobs[job_id])
        
        processing_time = time.time() - start_time
        
        # Generate summary statistics
        summary_stats = self._generate_batch_summary_statistics(processed_results)
        
        return BatchProcessingResult(
            total_jobs=len(texts),
            completed_jobs=completed_count,
            failed_jobs=failed_count,
            processing_time=processing_time,
            results=processed_results,
            job_details=job_details,
            summary_statistics=summary_stats
        )
    
    async def stream_analyze_documents(
        self,
        document_stream: AsyncIterator[str],
        language: Optional[str] = None,
        model_name: Optional[str] = None,
        config: Optional[SpacyProcessingConfig] = None,
        include_pii_detection: bool = None,
        chunk_size: int = 100
    ) -> AsyncIterator[Tuple[SpacyAnalysisResult, StreamProcessingStats]]:
        """Stream processing of documents with real-time analysis."""
        if include_pii_detection is None:
            include_pii_detection = self.enable_pii_detection
        
        stats = StreamProcessingStats()
        chunk_results = []
        
        async for document in document_stream:
            try:
                start_time = time.time()
                
                # Analyze document
                result = await self.analyze_text_async(
                    document, language, model_name, config, include_pii_detection
                )
                
                processing_time = time.time() - start_time
                
                # Update statistics
                stats.documents_processed += 1
                stats.total_processing_time += processing_time
                stats.average_processing_time = stats.total_processing_time / stats.documents_processed
                
                if result.success:
                    # Update language statistics
                    if result.language_detection:
                        lang = result.language_detection.primary_language
                        stats.languages_detected[lang] = stats.languages_detected.get(lang, 0) + 1
                    
                    # Update complexity statistics
                    complexity = result.complexity_level.value
                    stats.complexity_distribution[complexity] = stats.complexity_distribution.get(complexity, 0) + 1
                else:
                    stats.errors_encountered += 1
                
                chunk_results.append(result)
                
                # Yield results in chunks
                if len(chunk_results) >= chunk_size:
                    for chunk_result in chunk_results:
                        yield chunk_result, stats
                    chunk_results = []
                
            except Exception as e:
                logger.error(f"Stream processing failed for document: {e}")
                stats.errors_encountered += 1
                
                error_result = SpacyAnalysisResult(
                    success=False,
                    text_length=len(document) if document else 0,
                    processing_time=0.0,
                    processing_errors=[str(e)]
                )
                chunk_results.append(error_result)
        
        # Yield remaining results
        for chunk_result in chunk_results:
            yield chunk_result, stats
    
    def detect_language_advanced(
        self,
        text: str,
        confidence_threshold: float = 0.7
    ) -> LanguageDetectionResult:
        """Advanced language detection with enhanced confidence scoring."""
        try:
            # Use spaCy processor's language detection
            result = self.spacy_processor.detect_language(text)
            
            # Enhance with additional analysis if confidence is low
            if result.confidence < confidence_threshold:
                # Perform additional analysis using multiple methods
                enhanced_result = self._enhanced_language_detection(text)
                
                # Combine results
                if enhanced_result.confidence > result.confidence:
                    return enhanced_result
            
            return result
            
        except Exception as e:
            logger.error(f"Advanced language detection failed: {e}")
            return LanguageDetectionResult(
                primary_language="en",
                confidence=0.5,
                language_distribution={"en": 0.5}
            )
    
    def analyze_document_similarity(
        self,
        documents: List[str],
        method: str = "embedding",
        language: Optional[str] = None
    ) -> Dict[str, Any]:
        """Analyze similarity between multiple documents."""
        try:
            if method == "embedding":
                return self._analyze_embedding_similarity(documents, language)
            elif method == "linguistic":
                return self._analyze_linguistic_similarity(documents, language)
            else:
                raise ValueError(f"Unsupported similarity method: {method}")
                
        except Exception as e:
            logger.error(f"Document similarity analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "similarity_matrix": [],
                "clusters": []
            }
    
    def extract_key_information(
        self,
        text: str,
        information_types: List[str] = None,
        language: Optional[str] = None
    ) -> Dict[str, Any]:
        """Extract key information from text using NLP analysis."""
        try:
            # Default information types
            if not information_types:
                information_types = [
                    "entities", "key_phrases", "sentiment", "topics", "summary"
                ]
            
            # Perform comprehensive analysis
            result = self.analyze_text(text, language=language, include_pii_detection=True)
            
            if not result.success:
                return {"success": False, "error": result.processing_errors}
            
            # Extract requested information
            extracted_info = {"success": True, "text_length": result.text_length}
            
            if "entities" in information_types:
                extracted_info["entities"] = result.named_entities
            
            if "key_phrases" in information_types:
                extracted_info["key_phrases"] = result.key_phrases
            
            if "sentiment" in information_types:
                extracted_info["sentiment"] = self._analyze_sentiment(result)
            
            if "topics" in information_types:
                extracted_info["topics"] = self._extract_topics(result)
            
            if "summary" in information_types:
                extracted_info["summary"] = self._generate_summary(result)
            
            if "privacy_analysis" in information_types:
                extracted_info["privacy_analysis"] = {
                    "privacy_risk_score": result.privacy_risk_score,
                    "pii_indicators": result.pii_indicators
                }
            
            return extracted_info
            
        except Exception as e:
            logger.error(f"Key information extraction failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _integrate_pii_detection(self, text: str, spacy_result: SpacyAnalysisResult) -> Optional[PIIDetectionResult]:
        """Integrate PII detection with spaCy analysis."""
        try:
            if self.pii_service:
                return self.pii_service.detect_pii(text)
            return None
        except Exception as e:
            logger.warning(f"PII detection integration failed: {e}")
            return None
    
    def _merge_pii_with_spacy_analysis(
        self, 
        spacy_result: SpacyAnalysisResult, 
        pii_result: Optional[PIIDetectionResult]
    ) -> SpacyAnalysisResult:
        """Merge PII detection results with spaCy analysis."""
        try:
            if not pii_result or not pii_result.entities:
                return spacy_result
            
            # Enhance named entities with PII information
            enhanced_entities = list(spacy_result.named_entities)
            
            for pii_entity in pii_result.entities:
                entity_info = {
                    "text": pii_entity.text,
                    "label": f"PII_{pii_entity.entity_type}",
                    "start_char": pii_entity.start,
                    "end_char": pii_entity.end,
                    "confidence": pii_entity.confidence,
                    "description": f"PII: {pii_entity.entity_type}",
                    "pii_metadata": {
                        "recognizer": pii_entity.recognizer_name,
                        "confidence_level": pii_entity.confidence_level.value
                    }
                }
                enhanced_entities.append(entity_info)
            
            # Update spaCy result
            spacy_result.named_entities = enhanced_entities
            spacy_result.entity_types.update(f"PII_{entity.entity_type}" for entity in pii_result.entities)
            
            # Update privacy risk score based on PII findings
            if pii_result.risk_level:
                risk_mapping = {"LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 1.0}
                pii_risk = risk_mapping.get(pii_result.risk_level.value, 0.5)
                spacy_result.privacy_risk_score = max(spacy_result.privacy_risk_score, pii_risk)
            
            return spacy_result
            
        except Exception as e:
            logger.warning(f"Failed to merge PII with spaCy analysis: {e}")
            return spacy_result
    
    def _generate_job_id(self, text: str, language: Optional[str], model_name: Optional[str]) -> str:
        """Generate unique job ID for processing job."""
        content = f"{text[:100]}{language}{model_name}{time.time()}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _update_performance_stats(self, result: SpacyAnalysisResult, processing_time: float):
        """Update performance statistics."""
        if not self.enable_performance_monitoring:
            return
        
        try:
            stats_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "success": result.success,
                "text_length": result.text_length,
                "processing_time": processing_time,
                "language": result.language_detection.primary_language if result.language_detection else "unknown",
                "complexity": result.complexity_level.value if result.success else "unknown",
                "entity_count": len(result.named_entities) if result.success else 0
            }
            
            self.performance_history.append(stats_entry)
            
            # Update aggregate statistics
            self.processing_stats["total_processed"] += 1
            if result.success:
                self.processing_stats["successful_processed"] += 1
            else:
                self.processing_stats["failed_processed"] += 1
            
            self.processing_stats["total_processing_time"] += processing_time
            self.processing_stats["average_processing_time"] = (
                self.processing_stats["total_processing_time"] / self.processing_stats["total_processed"]
            )
            
            # Cleanup old performance history if needed
            if len(self.performance_history) > 10000:
                self.performance_history = self.performance_history[-5000:]  # Keep last 5000 entries
            
        except Exception as e:
            logger.warning(f"Failed to update performance stats: {e}")
    
    def _generate_batch_summary_statistics(self, results: List[SpacyAnalysisResult]) -> Dict[str, Any]:
        """Generate summary statistics for batch processing results."""
        try:
            stats = {
                "total_documents": len(results),
                "successful_analyses": sum(1 for r in results if r.success),
                "failed_analyses": sum(1 for r in results if not r.success),
                "total_text_length": sum(r.text_length for r in results),
                "total_processing_time": sum(r.processing_time for r in results),
                "language_distribution": defaultdict(int),
                "complexity_distribution": defaultdict(int),
                "average_readability": 0.0,
                "total_entities": 0,
                "entity_type_distribution": defaultdict(int)
            }
            
            successful_results = [r for r in results if r.success]
            
            if successful_results:
                # Language distribution
                for result in successful_results:
                    if result.language_detection:
                        lang = result.language_detection.primary_language
                        stats["language_distribution"][lang] += 1
                
                # Complexity distribution
                for result in successful_results:
                    complexity = result.complexity_level.value
                    stats["complexity_distribution"][complexity] += 1
                
                # Average readability
                readability_scores = [r.readability_score for r in successful_results if r.readability_score > 0]
                if readability_scores:
                    stats["average_readability"] = sum(readability_scores) / len(readability_scores)
                
                # Entity statistics
                for result in successful_results:
                    stats["total_entities"] += len(result.named_entities)
                    for entity in result.named_entities:
                        entity_type = entity.get("label", "UNKNOWN")
                        stats["entity_type_distribution"][entity_type] += 1
            
            # Convert defaultdicts to regular dicts for JSON serialization
            stats["language_distribution"] = dict(stats["language_distribution"])
            stats["complexity_distribution"] = dict(stats["complexity_distribution"])
            stats["entity_type_distribution"] = dict(stats["entity_type_distribution"])
            
            return stats
            
        except Exception as e:
            logger.warning(f"Failed to generate batch summary statistics: {e}")
            return {}
    
    def _enhanced_language_detection(self, text: str) -> LanguageDetectionResult:
        """Enhanced language detection using multiple methods."""
        # This is a placeholder for enhanced language detection
        # In practice, you might use multiple libraries or models
        return LanguageDetectionResult(
            primary_language="en",
            confidence=0.6,
            language_distribution={"en": 0.6, "unknown": 0.4}
        )
    
    def _analyze_embedding_similarity(self, documents: List[str], language: Optional[str]) -> Dict[str, Any]:
        """Analyze document similarity using embeddings."""
        # Placeholder for embedding-based similarity analysis
        # Would use document embeddings to calculate similarity
        return {
            "success": True,
            "method": "embedding",
            "similarity_matrix": [],
            "clusters": [],
            "note": "Embedding-based similarity analysis not fully implemented"
        }
    
    def _analyze_linguistic_similarity(self, documents: List[str], language: Optional[str]) -> Dict[str, Any]:
        """Analyze document similarity using linguistic features."""
        # Placeholder for linguistic similarity analysis
        # Would use POS patterns, entity overlap, etc.
        return {
            "success": True,
            "method": "linguistic",
            "similarity_matrix": [],
            "clusters": [],
            "note": "Linguistic similarity analysis not fully implemented"
        }
    
    def _analyze_sentiment(self, result: SpacyAnalysisResult) -> Dict[str, Any]:
        """Analyze sentiment from spaCy analysis result."""
        try:
            # Extract sentiment information from sentences
            sentiments = []
            for sentence in result.sentences:
                if sentence.sentiment is not None:
                    sentiments.append(sentence.sentiment)
            
            if sentiments:
                avg_sentiment = sum(sentiments) / len(sentiments)
                return {
                    "overall_sentiment": avg_sentiment,
                    "sentiment_distribution": {
                        "positive": sum(1 for s in sentiments if s > 0.1),
                        "neutral": sum(1 for s in sentiments if -0.1 <= s <= 0.1),
                        "negative": sum(1 for s in sentiments if s < -0.1)
                    },
                    "sentence_count": len(sentiments)
                }
            
            return {"overall_sentiment": 0.0, "note": "No sentiment data available"}
            
        except Exception:
            return {"overall_sentiment": 0.0, "error": "Sentiment analysis failed"}
    
    def _extract_topics(self, result: SpacyAnalysisResult) -> Dict[str, Any]:
        """Extract topics from spaCy analysis result."""
        try:
            # Simple topic extraction based on key phrases and entities
            topics = []
            
            # Use key phrases as topic indicators
            for phrase in result.key_phrases[:10]:  # Top 10 key phrases
                topics.append({
                    "topic": phrase,
                    "type": "key_phrase",
                    "confidence": 0.7  # Placeholder confidence
                })
            
            # Use named entities as topic indicators
            entity_counts = defaultdict(int)
            for entity in result.named_entities:
                entity_type = entity.get("label", "UNKNOWN")
                entity_counts[entity_type] += 1
            
            for entity_type, count in entity_counts.items():
                topics.append({
                    "topic": entity_type,
                    "type": "entity_type",
                    "confidence": min(1.0, count / 10.0),  # Normalize by frequency
                    "frequency": count
                })
            
            return {
                "topics": topics[:15],  # Top 15 topics
                "extraction_method": "key_phrases_and_entities"
            }
            
        except Exception:
            return {"topics": [], "error": "Topic extraction failed"}
    
    def _generate_summary(self, result: SpacyAnalysisResult) -> Dict[str, Any]:
        """Generate text summary from spaCy analysis result."""
        try:
            # Simple extractive summarization based on sentence importance
            sentences = result.sentences
            
            if not sentences:
                return {"summary": "", "method": "extractive"}
            
            # Score sentences based on various factors
            sentence_scores = []
            for sentence in sentences:
                score = 0.0
                
                # Length factor (prefer medium-length sentences)
                length_score = 1.0 - abs(len(sentence.tokens) - 15) / 30.0
                score += max(0.0, length_score) * 0.3
                
                # Complexity factor (prefer moderate complexity)
                complexity_score = 1.0 - abs(sentence.complexity_score - 0.5) * 2
                score += max(0.0, complexity_score) * 0.2
                
                # Entity presence (prefer sentences with entities)
                entity_score = min(1.0, len(sentence.named_entities) / 3.0)
                score += entity_score * 0.3
                
                # Position factor (prefer sentences from beginning and end)
                position_score = 1.0 if sentence == sentences[0] else 0.5
                score += position_score * 0.2
                
                sentence_scores.append((sentence, score))
            
            # Select top sentences for summary
            sentence_scores.sort(key=lambda x: x[1], reverse=True)
            top_sentences = sentence_scores[:min(3, len(sentence_scores))]  # Top 3 sentences
            
            # Sort by original order
            summary_sentences = sorted(top_sentences, key=lambda x: sentences.index(x[0]))
            summary_text = " ".join(sent[0].text for sent in summary_sentences)
            
            return {
                "summary": summary_text,
                "method": "extractive",
                "sentences_used": len(summary_sentences),
                "compression_ratio": len(summary_text) / result.text_length if result.text_length > 0 else 0.0
            }
            
        except Exception:
            return {"summary": "", "error": "Summary generation failed"}
    
    def get_processing_statistics(self) -> Dict[str, Any]:
        """Get comprehensive processing statistics."""
        try:
            stats = dict(self.processing_stats)
            stats.update({
                "active_jobs": len([job for job in self.processing_jobs.values() if job.status == "processing"]),
                "completed_jobs": len([job for job in self.processing_jobs.values() if job.status == "completed"]),
                "failed_jobs": len([job for job in self.processing_jobs.values() if job.status == "failed"]),
                "total_jobs": len(self.processing_jobs),
                "cache_enabled": self.enable_caching,
                "pii_detection_enabled": self.enable_pii_detection,
                "performance_monitoring_enabled": self.enable_performance_monitoring,
                "performance_history_entries": len(self.performance_history)
            })
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get processing statistics: {e}")
            return {"error": str(e)}
    
    def get_job_status(self, job_id: str) -> Optional[NLPProcessingJob]:
        """Get status of a specific processing job."""
        return self.processing_jobs.get(job_id)
    
    def cleanup_completed_jobs(self, older_than_hours: int = 24):
        """Clean up completed jobs older than specified hours."""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=older_than_hours)
            jobs_to_remove = []
            
            for job_id, job in self.processing_jobs.items():
                if job.is_completed and job.completed_at and job.completed_at < cutoff_time:
                    jobs_to_remove.append(job_id)
            
            for job_id in jobs_to_remove:
                del self.processing_jobs[job_id]
            
            logger.info(f"Cleaned up {len(jobs_to_remove)} completed jobs")
            return len(jobs_to_remove)
            
        except Exception as e:
            logger.error(f"Job cleanup failed: {e}")
            return 0
    
    def cleanup(self):
        """Clean up service resources."""
        try:
            if hasattr(self, 'executor'):
                self.executor.shutdown(wait=True)
            
            if hasattr(self, 'spacy_processor'):
                self.spacy_processor.cleanup()
            
            self.processing_jobs.clear()
            self.performance_history.clear()
            
            logger.info("SpacyService cleanup completed")
            
        except Exception as e:
            logger.error(f"SpacyService cleanup failed: {e}")


# Factory functions
def create_spacy_service(
    config: Optional[SpacyProcessingConfig] = None,
    enable_pii_detection: bool = True,
    enable_caching: bool = True,
    max_workers: int = 4
) -> SpacyService:
    """Create spaCy service with specified configuration."""
    return SpacyService(
        default_config=config,
        enable_pii_detection=enable_pii_detection,
        enable_caching=enable_caching,
        max_workers=max_workers
    )


# Convenience functions
async def quick_nlp_analysis(text: str, language: str = None) -> Dict[str, Any]:
    """Quick NLP analysis returning essential metrics."""
    service = create_spacy_service(enable_pii_detection=False, enable_caching=False)
    try:
        result = await service.analyze_text_async(text, language=language)
        if result.success:
            return {
                "success": True,
                "language": result.language_detection.primary_language if result.language_detection else "unknown",
                "sentences": len(result.sentences),
                "words": len(result.tokens),
                "entities": len(result.named_entities),
                "complexity": result.complexity_level.value,
                "readability": result.readability_score,
                "key_phrases": result.key_phrases[:5],  # Top 5
                "processing_time": result.processing_time
            }
        return {"success": False, "errors": result.processing_errors}
    finally:
        service.cleanup()