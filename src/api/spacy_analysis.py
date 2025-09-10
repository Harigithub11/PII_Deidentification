"""
spaCy NLP Analysis API Endpoints

FastAPI endpoints for advanced spaCy-based natural language processing including
linguistic analysis, language detection, text complexity assessment, and PII integration
with comprehensive validation, error handling, and performance monitoring.
"""

import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from enum import Enum

from ..core.services.spacy_service import (
    SpacyService,
    BatchProcessingResult,
    StreamProcessingStats,
    ProcessingPriority,
    create_spacy_service,
    quick_nlp_analysis
)
from ..core.processing.spacy_processor import (
    SpacyProcessor,
    SpacyAnalysisResult,
    LanguageSupport,
    TextComplexity,
    DocumentStructure,
    LinguisticToken,
    LinguisticSentence,
    LanguageDetectionResult,
    create_spacy_processor,
    quick_language_detection,
    quick_linguistic_analysis
)
from ..core.models.spacy_models import (
    SpacyModelManager,
    EnhancedSpacyModel,
    ModelType,
    get_model_manager
)
from ..core.config.policies.base import PIIType

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/nlp", tags=["spaCy NLP Analysis"])


# Request/Response Models
class LanguageDetectionRequest(BaseModel):
    """Request model for language detection."""
    text: str = Field(..., min_length=1, max_length=100000, description="Text to analyze for language")
    min_confidence: float = Field(0.7, ge=0.0, le=1.0, description="Minimum confidence threshold")
    max_languages: int = Field(3, ge=1, le=10, description="Maximum number of languages to return")


class LanguageDetectionResponse(BaseModel):
    """Response model for language detection."""
    primary_language: str
    confidence: float
    detected_languages: List[Dict[str, Union[str, float]]]
    text_length: int
    processing_time_seconds: float
    supported_by_model: bool


class LinguisticAnalysisRequest(BaseModel):
    """Request model for comprehensive linguistic analysis."""
    text: str = Field(..., min_length=1, max_length=100000, description="Text to analyze")
    language: Optional[str] = Field(None, description="Language code (auto-detect if not provided)")
    model_name: Optional[str] = Field(None, description="Specific spaCy model to use")
    include_entities: bool = Field(True, description="Include named entity recognition")
    include_pos_tags: bool = Field(True, description="Include part-of-speech tags")
    include_dependencies: bool = Field(True, description="Include dependency parsing")
    include_lemmas: bool = Field(True, description="Include lemmatization")
    include_complexity: bool = Field(True, description="Include text complexity analysis")
    include_pii_indicators: bool = Field(True, description="Include PII detection indicators")
    
    @validator('language')
    def validate_language(cls, v):
        if v is not None and len(v) != 2:
            raise ValueError("Language code must be 2 characters (e.g., 'en', 'es')")
        return v


class TokenResponse(BaseModel):
    """Response model for linguistic token."""
    text: str
    lemma: str
    pos: str
    tag: str
    dep: str
    head: int
    is_alpha: bool
    is_digit: bool
    is_punct: bool
    is_stop: bool
    is_oov: bool
    sentiment: Optional[float] = None
    is_pii_indicator: bool = False
    pii_confidence: float = 0.0


class EntityResponse(BaseModel):
    """Response model for named entity."""
    text: str
    label: str
    start: int
    end: int
    confidence: Optional[float] = None
    description: Optional[str] = None


class SentenceResponse(BaseModel):
    """Response model for sentence analysis."""
    text: str
    start: int
    end: int
    token_count: int
    complexity_score: float
    sentiment: Optional[float] = None
    entities: List[EntityResponse]


class TextComplexityResponse(BaseModel):
    """Response model for text complexity analysis."""
    overall_score: float
    level: str
    readability_scores: Dict[str, float]
    vocabulary_diversity: float
    average_sentence_length: float
    sentence_complexity: List[float]
    factors: List[str]


class LinguisticAnalysisResponse(BaseModel):
    """Response model for comprehensive linguistic analysis."""
    analysis_id: str
    text_length: int
    language: str
    model_used: str
    processing_time_seconds: float
    
    # Linguistic components
    tokens: List[TokenResponse]
    sentences: List[SentenceResponse]
    entities: List[EntityResponse]
    
    # Analysis results
    complexity: TextComplexityResponse
    document_structure: Dict[str, Any]
    language_detection: Dict[str, Any]
    
    # PII integration
    pii_indicators: List[Dict[str, Any]]
    privacy_risk_score: float
    
    # Statistics
    statistics: Dict[str, Any]


class BatchAnalysisRequest(BaseModel):
    """Request model for batch linguistic analysis."""
    texts: List[str] = Field(..., min_items=1, max_items=100, description="Texts to analyze")
    language: Optional[str] = Field(None, description="Language code for all texts")
    model_name: Optional[str] = Field(None, description="Specific spaCy model to use")
    priority: str = Field("NORMAL", description="Processing priority")
    batch_size: int = Field(16, ge=1, le=64, description="Batch size for processing")
    
    @validator('priority')
    def validate_priority(cls, v):
        valid_priorities = [p.value for p in ProcessingPriority]
        if v not in valid_priorities:
            raise ValueError(f"Invalid priority. Valid options: {valid_priorities}")
        return v


class BatchAnalysisResponse(BaseModel):
    """Response model for batch analysis results."""
    job_id: str
    total_texts: int
    processed_texts: int
    failed_texts: int
    processing_time_seconds: float
    results: List[LinguisticAnalysisResponse]
    errors: List[Dict[str, str]]
    statistics: Dict[str, Any]


class TextSimilarityRequest(BaseModel):
    """Request model for text similarity analysis."""
    text1: str = Field(..., min_length=1, max_length=50000)
    text2: str = Field(..., min_length=1, max_length=50000)
    language: Optional[str] = Field(None, description="Language code")
    similarity_method: str = Field("semantic", description="Similarity calculation method")
    
    @validator('similarity_method')
    def validate_similarity_method(cls, v):
        valid_methods = ["semantic", "token", "syntactic", "combined"]
        if v not in valid_methods:
            raise ValueError(f"Invalid similarity method. Valid options: {valid_methods}")
        return v


class TextSimilarityResponse(BaseModel):
    """Response model for text similarity analysis."""
    similarity_score: float
    method_used: str
    text1_length: int
    text2_length: int
    processing_time_seconds: float
    details: Dict[str, Any]


class KeyInformationRequest(BaseModel):
    """Request model for key information extraction."""
    text: str = Field(..., min_length=1, max_length=100000)
    information_types: List[str] = Field(..., min_items=1, description="Types of information to extract")
    language: Optional[str] = Field(None, description="Language code")
    
    @validator('information_types')
    def validate_information_types(cls, v):
        valid_types = [
            "entities", "keywords", "topics", "dates", "locations", 
            "organizations", "persons", "events", "concepts", "relations"
        ]
        invalid = [t for t in v if t not in valid_types]
        if invalid:
            raise ValueError(f"Invalid information types: {invalid}")
        return v


class KeyInformationResponse(BaseModel):
    """Response model for key information extraction."""
    extracted_information: Dict[str, List[Dict[str, Any]]]
    information_count: Dict[str, int]
    confidence_scores: Dict[str, float]
    processing_time_seconds: float


class ServiceStatusResponse(BaseModel):
    """Response model for service status."""
    service_name: str
    status: str
    model_manager: Dict[str, Any]
    active_jobs: int
    completed_jobs: int
    processing_queue_size: int
    performance_stats: Dict[str, Any]


# Dependency injection
def get_spacy_service() -> SpacyService:
    """Get spaCy service instance."""
    return create_spacy_service()


def get_spacy_processor() -> SpacyProcessor:
    """Get spaCy processor instance."""
    return create_spacy_processor()


def get_spacy_model_manager() -> SpacyModelManager:
    """Get spaCy model manager instance."""
    return get_model_manager()


# API Endpoints

@router.post("/detect-language", response_model=LanguageDetectionResponse)
async def detect_language(
    request: LanguageDetectionRequest,
    processor: SpacyProcessor = Depends(get_spacy_processor)
):
    """
    Detect the language of input text.
    
    Uses multiple methods for accurate language detection including
    character n-grams, word patterns, and linguistic features.
    """
    try:
        start_time = datetime.now()
        
        # Perform language detection
        result = processor.detect_language(request.text)
        
        processing_time = (datetime.now() - start_time).total_seconds()
        
        # Filter results by confidence
        detected_languages = [
            {"language": lang, "confidence": conf}
            for lang, conf in result.detected_languages.items()
            if conf >= request.min_confidence
        ]
        
        # Sort by confidence and limit results
        detected_languages.sort(key=lambda x: x["confidence"], reverse=True)
        detected_languages = detected_languages[:request.max_languages]
        
        response = LanguageDetectionResponse(
            primary_language=result.primary_language,
            confidence=result.confidence,
            detected_languages=detected_languages,
            text_length=len(request.text),
            processing_time_seconds=processing_time,
            supported_by_model=result.supported_by_model
        )
        
        logger.info(f"Language detection completed: {result.primary_language} ({result.confidence:.2f})")
        return response
        
    except Exception as e:
        logger.error(f"Language detection failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Language detection failed: {str(e)}"
        )


@router.post("/analyze", response_model=LinguisticAnalysisResponse)
async def analyze_text(
    request: LinguisticAnalysisRequest,
    processor: SpacyProcessor = Depends(get_spacy_processor)
):
    """
    Perform comprehensive linguistic analysis of text.
    
    Includes tokenization, POS tagging, dependency parsing, NER,
    sentiment analysis, complexity assessment, and PII indicators.
    """
    try:
        start_time = datetime.now()
        
        # Perform linguistic analysis
        result = processor.analyze_text(
            text=request.text,
            language=request.language,
            model_name=request.model_name,
            include_entities=request.include_entities,
            include_pos_tags=request.include_pos_tags,
            include_dependencies=request.include_dependencies,
            include_lemmas=request.include_lemmas,
            include_complexity=request.include_complexity,
            include_pii_indicators=request.include_pii_indicators
        )
        
        processing_time = (datetime.now() - start_time).total_seconds()
        
        # Convert tokens to response format
        tokens = [
            TokenResponse(
                text=token.text,
                lemma=token.lemma,
                pos=token.pos,
                tag=token.tag,
                dep=token.dependency,
                head=token.head_index,
                is_alpha=token.is_alpha,
                is_digit=token.is_digit,
                is_punct=token.is_punct,
                is_stop=token.is_stop,
                is_oov=token.is_oov,
                sentiment=token.sentiment,
                is_pii_indicator=token.is_pii_indicator,
                pii_confidence=token.pii_confidence
            )
            for token in result.tokens
        ]
        
        # Convert sentences to response format
        sentences = [
            SentenceResponse(
                text=sentence.text,
                start=sentence.start,
                end=sentence.end,
                token_count=sentence.token_count,
                complexity_score=sentence.complexity_score,
                sentiment=sentence.sentiment,
                entities=[
                    EntityResponse(
                        text=entity["text"],
                        label=entity["label"],
                        start=entity["start"],
                        end=entity["end"],
                        confidence=entity.get("confidence"),
                        description=entity.get("description")
                    )
                    for entity in sentence.entities
                ]
            )
            for sentence in result.sentences
        ]
        
        # Convert entities to response format
        entities = [
            EntityResponse(
                text=entity["text"],
                label=entity["label"],
                start=entity["start"],
                end=entity["end"],
                confidence=entity.get("confidence"),
                description=entity.get("description")
            )
            for entity in result.entities
        ]
        
        # Convert complexity analysis
        complexity = TextComplexityResponse(
            overall_score=result.complexity.overall_score,
            level=result.complexity.level.value,
            readability_scores=result.complexity.readability_scores,
            vocabulary_diversity=result.complexity.vocabulary_diversity,
            average_sentence_length=result.complexity.average_sentence_length,
            sentence_complexity=result.complexity.sentence_complexity,
            factors=result.complexity.factors
        )
        
        response = LinguisticAnalysisResponse(
            analysis_id=result.analysis_id,
            text_length=result.text_length,
            language=result.language,
            model_used=result.model_used,
            processing_time_seconds=processing_time,
            tokens=tokens,
            sentences=sentences,
            entities=entities,
            complexity=complexity,
            document_structure=result.document_structure.__dict__,
            language_detection=result.language_detection.__dict__,
            pii_indicators=result.pii_indicators,
            privacy_risk_score=result.privacy_risk_score,
            statistics=result.statistics
        )
        
        logger.info(f"Linguistic analysis completed: {result.analysis_id}")
        return response
        
    except Exception as e:
        logger.error(f"Linguistic analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Linguistic analysis failed: {str(e)}"
        )


@router.post("/analyze/batch", response_model=BatchAnalysisResponse)
async def analyze_batch_texts(
    request: BatchAnalysisRequest,
    service: SpacyService = Depends(get_spacy_service)
):
    """
    Perform batch linguistic analysis on multiple texts.
    
    Efficiently processes multiple texts with configurable batch size
    and priority, returning comprehensive analysis results.
    """
    try:
        start_time = datetime.now()
        
        # Convert priority
        priority = ProcessingPriority(request.priority)
        
        # Perform batch analysis
        result = await service.batch_analyze_texts_async(
            texts=request.texts,
            language=request.language,
            model_name=request.model_name,
            priority=priority,
            batch_size=request.batch_size
        )
        
        processing_time = (datetime.now() - start_time).total_seconds()
        
        # Convert results to response format
        analysis_results = []
        errors = []
        
        for i, analysis in enumerate(result.results):
            if analysis:
                # Convert successful analysis
                tokens = [
                    TokenResponse(
                        text=token.text,
                        lemma=token.lemma,
                        pos=token.pos,
                        tag=token.tag,
                        dep=token.dependency,
                        head=token.head_index,
                        is_alpha=token.is_alpha,
                        is_digit=token.is_digit,
                        is_punct=token.is_punct,
                        is_stop=token.is_stop,
                        is_oov=token.is_oov,
                        sentiment=token.sentiment,
                        is_pii_indicator=token.is_pii_indicator,
                        pii_confidence=token.pii_confidence
                    )
                    for token in analysis.tokens
                ]
                
                sentences = [
                    SentenceResponse(
                        text=sentence.text,
                        start=sentence.start,
                        end=sentence.end,
                        token_count=sentence.token_count,
                        complexity_score=sentence.complexity_score,
                        sentiment=sentence.sentiment,
                        entities=[
                            EntityResponse(
                                text=entity["text"],
                                label=entity["label"],
                                start=entity["start"],
                                end=entity["end"],
                                confidence=entity.get("confidence"),
                                description=entity.get("description")
                            )
                            for entity in sentence.entities
                        ]
                    )
                    for sentence in analysis.sentences
                ]
                
                entities = [
                    EntityResponse(
                        text=entity["text"],
                        label=entity["label"],
                        start=entity["start"],
                        end=entity["end"],
                        confidence=entity.get("confidence"),
                        description=entity.get("description")
                    )
                    for entity in analysis.entities
                ]
                
                complexity = TextComplexityResponse(
                    overall_score=analysis.complexity.overall_score,
                    level=analysis.complexity.level.value,
                    readability_scores=analysis.complexity.readability_scores,
                    vocabulary_diversity=analysis.complexity.vocabulary_diversity,
                    average_sentence_length=analysis.complexity.average_sentence_length,
                    sentence_complexity=analysis.complexity.sentence_complexity,
                    factors=analysis.complexity.factors
                )
                
                analysis_result = LinguisticAnalysisResponse(
                    analysis_id=analysis.analysis_id,
                    text_length=analysis.text_length,
                    language=analysis.language,
                    model_used=analysis.model_used,
                    processing_time_seconds=0.0,  # Individual timing not available in batch
                    tokens=tokens,
                    sentences=sentences,
                    entities=entities,
                    complexity=complexity,
                    document_structure=analysis.document_structure.__dict__,
                    language_detection=analysis.language_detection.__dict__,
                    pii_indicators=analysis.pii_indicators,
                    privacy_risk_score=analysis.privacy_risk_score,
                    statistics=analysis.statistics
                )
                
                analysis_results.append(analysis_result)
            else:
                # Record error
                errors.append({
                    "text_index": i,
                    "error": f"Analysis failed for text {i}"
                })
        
        response = BatchAnalysisResponse(
            job_id=result.job_id,
            total_texts=result.total_texts,
            processed_texts=result.successful_count,
            failed_texts=result.failed_count,
            processing_time_seconds=processing_time,
            results=analysis_results,
            errors=errors,
            statistics=result.performance_stats
        )
        
        logger.info(f"Batch analysis completed: {result.job_id} ({result.successful_count}/{result.total_texts})")
        return response
        
    except Exception as e:
        logger.error(f"Batch analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch analysis failed: {str(e)}"
        )


@router.post("/similarity", response_model=TextSimilarityResponse)
async def analyze_text_similarity(
    request: TextSimilarityRequest,
    service: SpacyService = Depends(get_spacy_service)
):
    """
    Analyze semantic similarity between two texts.
    
    Computes similarity using various methods including semantic vectors,
    token overlap, syntactic similarity, and combined approaches.
    """
    try:
        start_time = datetime.now()
        
        # Perform similarity analysis
        result = service.compute_text_similarity(
            text1=request.text1,
            text2=request.text2,
            language=request.language,
            method=request.similarity_method
        )
        
        processing_time = (datetime.now() - start_time).total_seconds()
        
        response = TextSimilarityResponse(
            similarity_score=result["similarity_score"],
            method_used=result["method_used"],
            text1_length=len(request.text1),
            text2_length=len(request.text2),
            processing_time_seconds=processing_time,
            details=result.get("details", {})
        )
        
        logger.info(f"Text similarity analysis completed: {result['similarity_score']:.3f}")
        return response
        
    except Exception as e:
        logger.error(f"Text similarity analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Similarity analysis failed: {str(e)}"
        )


@router.post("/extract-information", response_model=KeyInformationResponse)
async def extract_key_information(
    request: KeyInformationRequest,
    service: SpacyService = Depends(get_spacy_service)
):
    """
    Extract key information from text based on specified types.
    
    Extracts various types of information including entities, keywords,
    topics, dates, locations, organizations, and conceptual relations.
    """
    try:
        start_time = datetime.now()
        
        # Extract key information
        result = service.extract_key_information(
            text=request.text,
            information_types=request.information_types,
            language=request.language
        )
        
        processing_time = (datetime.now() - start_time).total_seconds()
        
        # Count extracted information
        information_count = {
            info_type: len(items) if isinstance(items, list) else 0
            for info_type, items in result.items()
        }
        
        # Calculate confidence scores (simplified)
        confidence_scores = {}
        for info_type, items in result.items():
            if isinstance(items, list) and items:
                # Average confidence if available
                confidences = [
                    item.get("confidence", 0.8) for item in items
                    if isinstance(item, dict)
                ]
                confidence_scores[info_type] = sum(confidences) / len(confidences) if confidences else 0.8
            else:
                confidence_scores[info_type] = 0.0
        
        response = KeyInformationResponse(
            extracted_information=result,
            information_count=information_count,
            confidence_scores=confidence_scores,
            processing_time_seconds=processing_time
        )
        
        logger.info(f"Key information extraction completed: {sum(information_count.values())} items")
        return response
        
    except Exception as e:
        logger.error(f"Key information extraction failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Information extraction failed: {str(e)}"
        )


@router.get("/status", response_model=ServiceStatusResponse)
def get_service_status(
    service: SpacyService = Depends(get_spacy_service),
    model_manager: SpacyModelManager = Depends(get_spacy_model_manager)
):
    """Get comprehensive service status and statistics."""
    try:
        # Get service statistics
        service_stats = service.get_performance_stats()
        
        # Get model manager information
        model_info = model_manager.get_model_info()
        
        response = ServiceStatusResponse(
            service_name="spaCy NLP Analysis Service",
            status="healthy",
            model_manager=model_info,
            active_jobs=service_stats.get("active_jobs", 0),
            completed_jobs=service_stats.get("completed_jobs", 0),
            processing_queue_size=service_stats.get("queue_size", 0),
            performance_stats=service_stats
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Failed to get service status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve service status: {str(e)}"
        )


@router.get("/models", response_model=Dict[str, Any])
def get_available_models(
    model_manager: SpacyModelManager = Depends(get_spacy_model_manager)
):
    """Get information about available spaCy models."""
    try:
        model_info = model_manager.get_model_info()
        
        # Add supported languages and model types
        response = {
            "model_info": model_info,
            "supported_languages": ["en", "es", "fr", "de"],
            "model_types": [t.value for t in ModelType],
            "default_models": {
                "en": "en_core_web_sm",
                "es": "es_core_news_sm", 
                "fr": "fr_core_news_sm",
                "de": "de_core_news_sm"
            }
        }
        
        return response
        
    except Exception as e:
        logger.error(f"Failed to get model information: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve model information: {str(e)}"
        )


@router.post("/models/{model_name}/load")
def load_model(
    model_name: str,
    language: str = Query("en", description="Language code"),
    model_manager: SpacyModelManager = Depends(get_spacy_model_manager)
):
    """Load a specific spaCy model."""
    try:
        model = model_manager.get_model(
            model_name=model_name,
            language=language
        )
        
        if not model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Failed to load model: {model_name}"
            )
        
        return {
            "message": f"Model {model_name} loaded successfully",
            "model_info": model.get_model_info()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to load model {model_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load model: {str(e)}"
        )


@router.delete("/models/{model_name}")
def unload_model(
    model_name: str,
    model_manager: SpacyModelManager = Depends(get_spacy_model_manager)
):
    """Unload a specific spaCy model to free memory."""
    try:
        if model_name not in model_manager.models:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Model not found: {model_name}"
            )
        
        model = model_manager.models[model_name]
        model.unload()
        
        return {"message": f"Model {model_name} unloaded successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unload model {model_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to unload model: {str(e)}"
        )


@router.get("/health")
def health_check():
    """Health check endpoint for spaCy NLP service."""
    try:
        service = create_spacy_service()
        model_manager = get_model_manager()
        
        service_stats = service.get_performance_stats()
        model_info = model_manager.get_model_info()
        
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "service": "spacy_nlp_analysis",
            "version": "1.0.0",
            "statistics": {
                "loaded_models": model_info.get("loaded_models", 0),
                "total_models": model_info.get("total_models", 0),
                "active_jobs": service_stats.get("active_jobs", 0),
                "completed_jobs": service_stats.get("completed_jobs", 0)
            }
        }
        
        return JSONResponse(content=health_status, status_code=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            content={
                "status": "unhealthy",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            },
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE
        )


# Supported features endpoints
@router.get("/supported/languages")
def get_supported_languages():
    """Get list of supported languages."""
    languages = [
        {"code": "en", "name": "English", "models": ["sm", "md", "lg", "trf"]},
        {"code": "es", "name": "Spanish", "models": ["sm", "md", "lg"]},
        {"code": "fr", "name": "French", "models": ["sm", "md", "lg"]},
        {"code": "de", "name": "German", "models": ["sm", "md", "lg"]},
    ]
    
    return {"supported_languages": languages}


@router.get("/supported/complexity-levels")
def get_supported_complexity_levels():
    """Get list of text complexity levels."""
    levels = [
        {"level": level.value, "description": level.name.replace("_", " ").title()}
        for level in TextComplexity
    ]
    
    return {"complexity_levels": levels}


@router.get("/supported/information-types")
def get_supported_information_types():
    """Get list of supported information extraction types."""
    types = [
        {"type": "entities", "description": "Named entities (persons, organizations, locations)"},
        {"type": "keywords", "description": "Important keywords and key phrases"},
        {"type": "topics", "description": "Main topics and themes"},
        {"type": "dates", "description": "Dates and temporal expressions"},
        {"type": "locations", "description": "Geographic locations and places"},
        {"type": "organizations", "description": "Companies, institutions, and organizations"},
        {"type": "persons", "description": "Person names and references"},
        {"type": "events", "description": "Events and occurrences"},
        {"type": "concepts", "description": "Important concepts and ideas"},
        {"type": "relations", "description": "Relationships between entities"}
    ]
    
    return {"supported_information_types": types}


@router.get("/supported/similarity-methods") 
def get_supported_similarity_methods():
    """Get list of supported text similarity methods."""
    methods = [
        {"method": "semantic", "description": "Semantic vector similarity using word embeddings"},
        {"method": "token", "description": "Token-based similarity using word overlap"},
        {"method": "syntactic", "description": "Syntactic similarity using grammatical structure"},
        {"method": "combined", "description": "Combined approach using multiple methods"}
    ]
    
    return {"supported_similarity_methods": methods}