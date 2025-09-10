"""
Comprehensive test suite for spaCy NLP Processing Module

Tests the spaCy-based natural language processing functionality including
processor, service, models, API endpoints, and integration components.
"""

import pytest
import asyncio
import uuid
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from unittest.mock import Mock, patch, MagicMock

# Test framework imports
import httpx
from fastapi.testclient import TestClient

# Module imports
from src.core.processing.spacy_processor import (
    SpacyProcessor, SpacyAnalysisResult, LanguageSupport, TextComplexity,
    DocumentStructure, LinguisticToken, LinguisticSentence, 
    LanguageDetectionResult, create_spacy_processor,
    quick_language_detection, quick_linguistic_analysis
)
from src.core.services.spacy_service import (
    SpacyService, BatchProcessingResult, StreamProcessingStats,
    ProcessingPriority, NLPProcessingJob, create_spacy_service, quick_nlp_analysis
)
from src.core.models.spacy_models import (
    SpacyModelManager, EnhancedSpacyModel, CustomPIIDetector, PrivacyAnalyzer,
    ModelType, PipelineComponent, CustomEntityPattern, PIIPattern,
    create_enhanced_spacy_model, create_model_manager, get_model_manager
)
from src.core.config.policies.base import PIIType
from src.api.spacy_analysis import router


# Test Data
SAMPLE_TEXT_SIMPLE = "Hello world, this is a simple test message."

SAMPLE_TEXT_COMPLEX = """
Dr. John Smith, a renowned cardiologist at Metropolitan Hospital, published 
a groundbreaking study on cardiovascular health. The research, conducted over 
five years, involved 10,000 participants from diverse backgrounds. 

The study revealed that patients with regular exercise routines showed 
30% lower risk of heart disease. Contact information for the research team 
can be found at research@metro-hospital.org or by calling (555) 123-4567.

The findings were published in the Journal of Cardiology on March 15, 2024.
"""

SAMPLE_TEXT_WITH_PII = """
Patient Information:
Name: Sarah Johnson
SSN: 123-45-6789
Email: sarah.j@email.com
Phone: (555) 987-6543
Address: 456 Oak Street, Boston, MA 02101
Credit Card: 4532-1234-5678-9012
Date of Birth: 05/20/1985
Medical Record: MR123456789
"""

SAMPLE_MULTILINGUAL_TEXT = {
    "en": "The quick brown fox jumps over the lazy dog.",
    "es": "El zorro marrón rápido salta sobre el perro perezoso.",
    "fr": "Le renard brun rapide saute par-dessus le chien paresseux.",
    "de": "Der schnelle braune Fuchs springt über den faulen Hund."
}

SAMPLE_MEDICAL_TEXT = """
Chief Complaint: Patient presents with chest pain and shortness of breath.

History of Present Illness: 
Mr. Robert Williams, a 45-year-old male, reports onset of substernal chest pain 
3 hours prior to admission. Pain is described as crushing, 8/10 severity, 
radiating to left arm. Associated with diaphoresis and nausea.

Past Medical History:
- Hypertension diagnosed 2015
- Type 2 Diabetes Mellitus since 2018
- Family history of coronary artery disease

Current Medications:
- Lisinopril 10mg daily
- Metformin 500mg twice daily

Vital Signs:
- BP: 150/95 mmHg
- HR: 102 bpm
- Temp: 98.6°F
- SpO2: 95% on room air

Assessment and Plan:
Acute coronary syndrome suspected. Recommend cardiac catheterization,
serial troponins, and cardiology consultation.
"""


class TestLinguisticToken:
    """Test LinguisticToken dataclass functionality."""
    
    def test_linguistic_token_creation(self):
        """Test LinguisticToken creation and attributes."""
        token = LinguisticToken(
            text="hospital",
            lemma="hospital",
            pos="NOUN",
            tag="NN",
            dependency="compound",
            head_index=2,
            is_alpha=True,
            is_digit=False,
            is_punct=False,
            is_stop=False,
            is_oov=False,
            sentiment=0.1,
            is_pii_indicator=False,
            pii_confidence=0.0
        )
        
        assert token.text == "hospital"
        assert token.lemma == "hospital"
        assert token.pos == "NOUN"
        assert token.tag == "NN"
        assert token.dependency == "compound"
        assert token.head_index == 2
        assert token.is_alpha
        assert not token.is_digit
        assert not token.is_punct
        assert not token.is_stop
        assert not token.is_oov
        assert token.sentiment == 0.1
        assert not token.is_pii_indicator
        assert token.pii_confidence == 0.0
    
    def test_pii_token_attributes(self):
        """Test PII-related token attributes."""
        pii_token = LinguisticToken(
            text="john@email.com",
            lemma="john@email.com",
            pos="X",
            tag="XX",
            dependency="root",
            head_index=0,
            is_alpha=False,
            is_digit=False,
            is_punct=False,
            is_stop=False,
            is_oov=True,
            sentiment=0.0,
            is_pii_indicator=True,
            pii_confidence=0.95
        )
        
        assert pii_token.is_pii_indicator
        assert pii_token.pii_confidence == 0.95


class TestLanguageDetectionResult:
    """Test LanguageDetectionResult functionality."""
    
    def test_language_detection_result_creation(self):
        """Test LanguageDetectionResult creation."""
        result = LanguageDetectionResult(
            primary_language="en",
            confidence=0.95,
            detected_languages={"en": 0.95, "es": 0.03, "fr": 0.02},
            supported_by_model=True,
            method_used="combined"
        )
        
        assert result.primary_language == "en"
        assert result.confidence == 0.95
        assert result.detected_languages["en"] == 0.95
        assert result.supported_by_model
        assert result.method_used == "combined"


class TestTextComplexityAnalysis:
    """Test TextComplexity analysis functionality."""
    
    def test_text_complexity_levels(self):
        """Test TextComplexity enum values."""
        assert TextComplexity.VERY_SIMPLE.value == "very_simple"
        assert TextComplexity.SIMPLE.value == "simple"
        assert TextComplexity.MODERATE.value == "moderate"
        assert TextComplexity.COMPLEX.value == "complex"
        assert TextComplexity.VERY_COMPLEX.value == "very_complex"


class TestSpacyProcessor:
    """Test SpacyProcessor functionality."""
    
    @pytest.fixture
    def mock_spacy_model(self):
        """Mock spaCy model for testing."""
        # Mock document
        mock_doc = Mock()
        mock_doc.lang_ = "en"
        mock_doc.__len__ = Mock(return_value=10)
        mock_doc.__iter__ = Mock(return_value=iter([]))
        mock_doc.sents = []
        mock_doc.ents = []
        mock_doc.vector = [0.1] * 300  # Mock vector
        mock_doc.has_vector = True
        
        # Mock token
        mock_token = Mock()
        mock_token.text = "test"
        mock_token.lemma_ = "test"
        mock_token.pos_ = "NOUN"
        mock_token.tag_ = "NN"
        mock_token.dep_ = "ROOT"
        mock_token.head.i = 0
        mock_token.is_alpha = True
        mock_token.is_digit = False
        mock_token.is_punct = False
        mock_token.is_stop = False
        mock_token.is_oov = False
        mock_token.sentiment = 0.0
        mock_token.i = 0
        
        mock_doc.__iter__ = Mock(return_value=iter([mock_token]))
        
        # Mock sentence
        mock_sent = Mock()
        mock_sent.text = "This is a test sentence."
        mock_sent.start_char = 0
        mock_sent.end_char = 24
        mock_sent.__len__ = Mock(return_value=5)
        mock_sent.__iter__ = Mock(return_value=iter([mock_token]))
        
        mock_doc.sents = [mock_sent]
        
        # Mock nlp pipeline
        mock_nlp = Mock()
        mock_nlp.return_value = mock_doc
        mock_nlp.pipe_names = ["tok2vec", "tagger", "parser", "ner"]
        mock_nlp.meta = {"lang": "en", "version": "3.6.0"}
        
        return mock_nlp
    
    @pytest.fixture
    def spacy_processor(self, mock_spacy_model):
        """Create SpacyProcessor with mocked dependencies."""
        with patch('src.core.processing.spacy_processor.spacy.load', return_value=mock_spacy_model):
            processor = SpacyProcessor()
            processor.model_manager = Mock()
            processor.model_manager.get_model.return_value = Mock(nlp=mock_spacy_model, is_loaded=True)
            return processor
    
    def test_spacy_processor_creation(self):
        """Test SpacyProcessor creation."""
        processor = SpacyProcessor()
        
        assert processor.supported_languages == ["en", "es", "fr", "de"]
        assert processor.default_model_names["en"] == "en_core_web_sm"
        assert processor.language_detection_methods is not None
        assert processor.complexity_calculators is not None
    
    def test_language_detection(self, spacy_processor):
        """Test language detection functionality."""
        with patch.object(spacy_processor, '_detect_language_ngrams', return_value={"en": 0.9, "es": 0.1}), \
             patch.object(spacy_processor, '_detect_language_patterns', return_value={"en": 0.95, "fr": 0.05}):
            
            result = spacy_processor.detect_language(SAMPLE_TEXT_SIMPLE)
            
            assert result.primary_language is not None
            assert result.confidence >= 0.0
            assert isinstance(result.detected_languages, dict)
            assert isinstance(result.supported_by_model, bool)
    
    def test_analyze_text_basic(self, spacy_processor):
        """Test basic text analysis."""
        with patch.object(spacy_processor, 'detect_language') as mock_lang_detect:
            mock_lang_detect.return_value = LanguageDetectionResult(
                primary_language="en", 
                confidence=0.95,
                detected_languages={"en": 0.95},
                supported_by_model=True,
                method_used="combined"
            )
            
            result = spacy_processor.analyze_text(
                text=SAMPLE_TEXT_SIMPLE,
                include_entities=True,
                include_pos_tags=True,
                include_dependencies=True,
                include_lemmas=True,
                include_complexity=True,
                include_pii_indicators=False
            )
            
            assert isinstance(result, SpacyAnalysisResult)
            assert result.text_length == len(SAMPLE_TEXT_SIMPLE)
            assert result.language == "en"
            assert len(result.analysis_id) > 0
            assert isinstance(result.tokens, list)
            assert isinstance(result.sentences, list)
            assert isinstance(result.entities, list)
            assert isinstance(result.complexity, Mock)  # Mocked complexity
    
    def test_analyze_text_with_pii_indicators(self, spacy_processor):
        """Test text analysis with PII indicators."""
        with patch.object(spacy_processor, 'detect_language') as mock_lang_detect, \
             patch.object(spacy_processor, '_analyze_pii_indicators') as mock_pii:
            
            mock_lang_detect.return_value = LanguageDetectionResult(
                primary_language="en",
                confidence=0.95,
                detected_languages={"en": 0.95},
                supported_by_model=True,
                method_used="combined"
            )
            
            mock_pii.return_value = ([{"type": "EMAIL", "confidence": 0.9}], 0.7)
            
            result = spacy_processor.analyze_text(
                text=SAMPLE_TEXT_WITH_PII,
                include_pii_indicators=True
            )
            
            assert result.pii_indicators is not None
            assert result.privacy_risk_score >= 0.0
    
    def test_complexity_analysis(self, spacy_processor):
        """Test text complexity analysis."""
        with patch.object(spacy_processor, '_calculate_complexity_metrics') as mock_complexity:
            mock_complexity.return_value = {
                "flesch_reading_ease": 65.0,
                "flesch_kincaid_grade": 8.5,
                "automated_readability_index": 7.8,
                "coleman_liau_index": 9.2
            }
            
            complexity = spacy_processor._assess_text_complexity(SAMPLE_TEXT_COMPLEX, Mock(), [Mock()])
            
            assert complexity.overall_score >= 0.0
            assert complexity.level in [level.value for level in TextComplexity]
            assert isinstance(complexity.readability_scores, dict)
    
    def test_batch_processing(self, spacy_processor):
        """Test batch text processing."""
        texts = [SAMPLE_TEXT_SIMPLE, "Another test text.", "Third sample text."]
        
        with patch.object(spacy_processor, 'analyze_text') as mock_analyze:
            mock_result = SpacyAnalysisResult(
                analysis_id=str(uuid.uuid4()),
                text_length=20,
                language="en",
                model_used="en_core_web_sm",
                tokens=[],
                sentences=[],
                entities=[],
                complexity=Mock(),
                document_structure=Mock(),
                language_detection=Mock(),
                pii_indicators=[],
                privacy_risk_score=0.0,
                statistics={}
            )
            mock_analyze.return_value = mock_result
            
            results = spacy_processor.batch_analyze_texts(texts)
            
            assert len(results) == 3
            assert all(isinstance(result, SpacyAnalysisResult) for result in results)


class TestSpacyService:
    """Test SpacyService functionality."""
    
    @pytest.fixture
    def mock_processor(self):
        """Mock SpacyProcessor for testing."""
        processor = Mock()
        
        mock_result = SpacyAnalysisResult(
            analysis_id=str(uuid.uuid4()),
            text_length=100,
            language="en",
            model_used="en_core_web_sm",
            tokens=[],
            sentences=[],
            entities=[],
            complexity=Mock(overall_score=0.5, level=TextComplexity.MODERATE),
            document_structure=Mock(),
            language_detection=Mock(),
            pii_indicators=[],
            privacy_risk_score=0.3,
            statistics={"processing_time": 0.5}
        )
        
        processor.analyze_text.return_value = mock_result
        processor.batch_analyze_texts.return_value = [mock_result, mock_result]
        processor.detect_language.return_value = LanguageDetectionResult(
            primary_language="en",
            confidence=0.95,
            detected_languages={"en": 0.95},
            supported_by_model=True,
            method_used="combined"
        )
        
        return processor
    
    @pytest.fixture
    def spacy_service(self, mock_processor):
        """Create SpacyService with mocked dependencies."""
        with patch('src.core.services.spacy_service.create_spacy_processor', return_value=mock_processor):
            service = SpacyService()
            service.processor = mock_processor
            return service
    
    def test_spacy_service_creation(self):
        """Test SpacyService creation."""
        service = SpacyService()
        
        assert service.max_concurrent_jobs == 10
        assert service.default_timeout_seconds == 300
        assert isinstance(service.active_jobs, dict)
        assert isinstance(service.job_history, dict)
        assert isinstance(service.performance_stats, dict)
    
    @pytest.mark.asyncio
    async def test_async_analysis(self, spacy_service):
        """Test asynchronous text analysis."""
        result = await spacy_service.analyze_text_async(
            text=SAMPLE_TEXT_SIMPLE,
            language="en"
        )
        
        assert isinstance(result, SpacyAnalysisResult)
        assert result.language == "en"
    
    @pytest.mark.asyncio
    async def test_batch_analysis_async(self, spacy_service):
        """Test asynchronous batch analysis."""
        texts = [SAMPLE_TEXT_SIMPLE, "Another text for testing."]
        
        result = await spacy_service.batch_analyze_texts_async(
            texts=texts,
            language="en",
            priority=ProcessingPriority.NORMAL,
            batch_size=2
        )
        
        assert isinstance(result, BatchProcessingResult)
        assert result.total_texts == 2
        assert result.successful_count <= 2
        assert len(result.results) <= 2
    
    def test_text_similarity_calculation(self, spacy_service):
        """Test text similarity calculation."""
        with patch.object(spacy_service, '_calculate_semantic_similarity', return_value=0.85), \
             patch.object(spacy_service, '_calculate_token_similarity', return_value=0.75):
            
            similarity = spacy_service.compute_text_similarity(
                text1="The quick brown fox",
                text2="A fast brown fox",
                method="combined"
            )
            
            assert isinstance(similarity, dict)
            assert "similarity_score" in similarity
            assert 0.0 <= similarity["similarity_score"] <= 1.0
    
    def test_key_information_extraction(self, spacy_service):
        """Test key information extraction."""
        with patch.object(spacy_service, '_extract_entities', return_value={"PERSON": ["John", "Sarah"]}), \
             patch.object(spacy_service, '_extract_keywords', return_value=["hospital", "patient", "treatment"]):
            
            result = spacy_service.extract_key_information(
                text=SAMPLE_MEDICAL_TEXT,
                information_types=["entities", "keywords"]
            )
            
            assert isinstance(result, dict)
            assert "entities" in result or "keywords" in result
    
    def test_performance_monitoring(self, spacy_service):
        """Test performance statistics tracking."""
        # Simulate some processing
        spacy_service._update_performance_stats("analyze_text", 0.5, True)
        spacy_service._update_performance_stats("analyze_text", 0.3, True)
        spacy_service._update_performance_stats("batch_analyze", 2.1, False)
        
        stats = spacy_service.get_performance_stats()
        
        assert isinstance(stats, dict)
        assert "total_operations" in stats
        assert "successful_operations" in stats
        assert "average_processing_time" in stats
    
    def test_job_management(self, spacy_service):
        """Test job creation and management."""
        job = NLPProcessingJob(
            job_id="test-job-123",
            texts=["Test text 1", "Test text 2"],
            priority=ProcessingPriority.HIGH,
            created_at=datetime.now()
        )
        
        spacy_service.active_jobs[job.job_id] = job
        
        assert job.job_id in spacy_service.active_jobs
        assert spacy_service.active_jobs[job.job_id].priority == ProcessingPriority.HIGH
        
        # Test job completion
        spacy_service._complete_job(job.job_id, [], 1.5)
        
        assert job.job_id not in spacy_service.active_jobs
        assert job.job_id in spacy_service.job_history


class TestSpacyModels:
    """Test spaCy model components."""
    
    @pytest.fixture
    def mock_spacy_nlp(self):
        """Mock spaCy NLP pipeline."""
        mock_doc = Mock()
        mock_doc.lang_ = "en"
        mock_doc.__len__ = Mock(return_value=5)
        mock_doc.ents = []
        
        # Mock token with PII extensions
        mock_token = Mock()
        mock_token._.is_pii = False
        mock_token._.pii_type = None
        mock_token._.pii_confidence = 0.0
        mock_token.is_punct = False
        mock_token.is_space = False
        mock_token.text = "test"
        mock_token.like_num = False
        mock_token.pos_ = "NOUN"
        mock_token.is_title = False
        mock_token.i = 0
        
        mock_doc.__iter__ = Mock(return_value=iter([mock_token]))
        mock_doc._.privacy_summary = None
        
        mock_nlp = Mock()
        mock_nlp.return_value = mock_doc
        mock_nlp.has_pipe = Mock(return_value=False)
        mock_nlp.add_pipe = Mock()
        mock_nlp.replace_pipe = Mock()
        mock_nlp.pipe_names = ["tok2vec", "tagger", "parser", "ner"]
        mock_nlp.meta = {"lang": "en", "version": "3.6.0"}
        
        return mock_nlp
    
    def test_custom_pii_detector_creation(self, mock_spacy_nlp):
        """Test CustomPIIDetector creation."""
        with patch('spacy.tokens.Token.set_extension'), \
             patch('spacy.tokens.Span.set_extension'), \
             patch('spacy.tokens.Doc.set_extension'):
            
            detector = CustomPIIDetector(mock_spacy_nlp)
            
            assert detector.name == "custom_pii_detector"
            assert detector.nlp == mock_spacy_nlp
            assert detector.pii_patterns is not None
            assert PIIType.EMAIL in detector.pii_patterns
    
    def test_privacy_analyzer_creation(self, mock_spacy_nlp):
        """Test PrivacyAnalyzer creation."""
        with patch('spacy.tokens.Doc.set_extension'):
            analyzer = PrivacyAnalyzer(mock_spacy_nlp)
            
            assert analyzer.name == "privacy_analyzer"
            assert analyzer.nlp == mock_spacy_nlp
            assert analyzer.risk_weights is not None
            assert PIIType.SSN.value in analyzer.risk_weights
    
    def test_enhanced_spacy_model_creation(self):
        """Test EnhancedSpacyModel creation."""
        model = EnhancedSpacyModel(
            model_name="en_core_web_sm",
            language="en",
            enable_custom_components=True
        )
        
        assert model.model_name == "en_core_web_sm"
        assert model.language == "en"
        assert model.enable_custom_components
        assert not model.is_loaded
        assert model.usage_stats["total_documents"] == 0
    
    @patch('src.core.models.spacy_models.spacy.load')
    def test_enhanced_model_loading(self, mock_spacy_load, mock_spacy_nlp):
        """Test enhanced model loading process."""
        mock_spacy_load.return_value = mock_spacy_nlp
        
        with patch('spacy.tokens.Token.set_extension'), \
             patch('spacy.tokens.Span.set_extension'), \
             patch('spacy.tokens.Doc.set_extension'):
            
            model = EnhancedSpacyModel("en_core_web_sm")
            success = model.load()
            
            assert success
            assert model.is_loaded
            assert model.nlp == mock_spacy_nlp
            assert model.model_info is not None
    
    def test_spacy_model_manager_creation(self):
        """Test SpacyModelManager creation."""
        manager = SpacyModelManager(max_loaded_models=3)
        
        assert manager.max_loaded_models == 3
        assert isinstance(manager.models, dict)
        assert isinstance(manager.model_priority, list)
        assert "en" in manager.default_models
    
    @patch('src.core.models.spacy_models.util.is_package')
    def test_model_manager_get_model(self, mock_is_package, mock_spacy_nlp):
        """Test model manager get_model functionality."""
        mock_is_package.return_value = True
        
        manager = SpacyModelManager()
        
        with patch('src.core.models.spacy_models.spacy.load', return_value=mock_spacy_nlp), \
             patch('spacy.tokens.Token.set_extension'), \
             patch('spacy.tokens.Span.set_extension'), \
             patch('spacy.tokens.Doc.set_extension'):
            
            model = manager.get_model(
                model_name="en_core_web_sm",
                language="en"
            )
            
            assert model is not None
            assert isinstance(model, EnhancedSpacyModel)
            assert model.is_loaded
            assert "en_core_web_sm" in manager.models


class TestAPIEndpoints:
    """Test spaCy Analysis API endpoints."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)
    
    @pytest.fixture
    def mock_spacy_service(self):
        """Mock spaCy service for API testing."""
        service = Mock()
        
        # Mock language detection result
        mock_lang_result = LanguageDetectionResult(
            primary_language="en",
            confidence=0.95,
            detected_languages={"en": 0.95, "es": 0.03},
            supported_by_model=True,
            method_used="combined"
        )
        
        # Mock analysis result
        mock_tokens = [
            LinguisticToken(
                text="test", lemma="test", pos="NOUN", tag="NN",
                dependency="ROOT", head_index=0, is_alpha=True,
                is_digit=False, is_punct=False, is_stop=False,
                is_oov=False, sentiment=0.0, is_pii_indicator=False,
                pii_confidence=0.0
            )
        ]
        
        mock_sentences = [
            LinguisticSentence(
                text="This is a test sentence.",
                start=0, end=24, token_count=5,
                complexity_score=0.5, sentiment=0.0,
                entities=[]
            )
        ]
        
        mock_complexity = Mock()
        mock_complexity.overall_score = 0.5
        mock_complexity.level = TextComplexity.MODERATE
        mock_complexity.readability_scores = {"flesch": 65.0}
        mock_complexity.vocabulary_diversity = 0.8
        mock_complexity.average_sentence_length = 15.0
        mock_complexity.sentence_complexity = [0.5]
        mock_complexity.factors = ["moderate_vocabulary"]
        
        mock_analysis_result = SpacyAnalysisResult(
            analysis_id="test-123",
            text_length=100,
            language="en",
            model_used="en_core_web_sm",
            tokens=mock_tokens,
            sentences=mock_sentences,
            entities=[],
            complexity=mock_complexity,
            document_structure=Mock(),
            language_detection=mock_lang_result,
            pii_indicators=[],
            privacy_risk_score=0.0,
            statistics={}
        )
        
        mock_batch_result = BatchProcessingResult(
            job_id="batch-123",
            total_texts=2,
            successful_count=2,
            failed_count=0,
            results=[mock_analysis_result, mock_analysis_result],
            processing_time_seconds=1.5,
            performance_stats={}
        )
        
        service.processor.detect_language.return_value = mock_lang_result
        service.processor.analyze_text.return_value = mock_analysis_result
        service.batch_analyze_texts_async.return_value = mock_batch_result
        service.compute_text_similarity.return_value = {
            "similarity_score": 0.85,
            "method_used": "semantic",
            "details": {}
        }
        service.extract_key_information.return_value = {
            "entities": [{"text": "John", "type": "PERSON"}],
            "keywords": ["hospital", "patient"]
        }
        service.get_performance_stats.return_value = {
            "total_operations": 100,
            "successful_operations": 95,
            "average_processing_time": 0.5,
            "active_jobs": 2,
            "completed_jobs": 98
        }
        
        return service
    
    @pytest.fixture
    def mock_spacy_processor(self):
        """Mock spaCy processor for API testing."""
        processor = Mock()
        
        processor.detect_language.return_value = LanguageDetectionResult(
            primary_language="en",
            confidence=0.95,
            detected_languages={"en": 0.95, "es": 0.03},
            supported_by_model=True,
            method_used="combined"
        )
        
        return processor
    
    @pytest.fixture
    def mock_model_manager(self):
        """Mock model manager for API testing."""
        manager = Mock()
        
        manager.get_model_info.return_value = {
            "total_models": 2,
            "loaded_models": 1,
            "max_loaded_models": 3,
            "models": {
                "en_core_web_sm": {
                    "model_name": "en_core_web_sm",
                    "is_loaded": True,
                    "language": "en"
                }
            }
        }
        
        mock_model = Mock()
        mock_model.get_model_info.return_value = {
            "model_name": "en_core_web_sm",
            "is_loaded": True,
            "language": "en"
        }
        
        manager.get_model.return_value = mock_model
        manager.models = {"en_core_web_sm": mock_model}
        
        return manager
    
    def test_detect_language_endpoint(self, client, mock_spacy_processor):
        """Test language detection endpoint."""
        with patch('src.api.spacy_analysis.get_spacy_processor', return_value=mock_spacy_processor):
            response = client.post("/api/v1/nlp/detect-language", json={
                "text": SAMPLE_TEXT_SIMPLE,
                "min_confidence": 0.7,
                "max_languages": 3
            })
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["primary_language"] == "en"
        assert data["confidence"] == 0.95
        assert len(data["detected_languages"]) <= 3
        assert data["supported_by_model"]
    
    def test_analyze_text_endpoint(self, client, mock_spacy_processor):
        """Test text analysis endpoint."""
        with patch('src.api.spacy_analysis.get_spacy_processor', return_value=mock_spacy_processor):
            response = client.post("/api/v1/nlp/analyze", json={
                "text": SAMPLE_TEXT_COMPLEX,
                "language": "en",
                "include_entities": True,
                "include_pos_tags": True,
                "include_dependencies": True,
                "include_complexity": True
            })
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["language"] == "en"
        assert "analysis_id" in data
        assert "tokens" in data
        assert "sentences" in data
        assert "entities" in data
        assert "complexity" in data
    
    def test_batch_analysis_endpoint(self, client, mock_spacy_service):
        """Test batch analysis endpoint."""
        with patch('src.api.spacy_analysis.get_spacy_service', return_value=mock_spacy_service):
            response = client.post("/api/v1/nlp/analyze/batch", json={
                "texts": [SAMPLE_TEXT_SIMPLE, "Another test text."],
                "language": "en",
                "priority": "NORMAL",
                "batch_size": 2
            })
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["job_id"] == "batch-123"
        assert data["total_texts"] == 2
        assert data["processed_texts"] == 2
        assert len(data["results"]) == 2
    
    def test_text_similarity_endpoint(self, client, mock_spacy_service):
        """Test text similarity endpoint."""
        with patch('src.api.spacy_analysis.get_spacy_service', return_value=mock_spacy_service):
            response = client.post("/api/v1/nlp/similarity", json={
                "text1": "The quick brown fox",
                "text2": "A fast brown fox",
                "similarity_method": "semantic"
            })
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["similarity_score"] == 0.85
        assert data["method_used"] == "semantic"
        assert "processing_time_seconds" in data
    
    def test_key_information_extraction_endpoint(self, client, mock_spacy_service):
        """Test key information extraction endpoint."""
        with patch('src.api.spacy_analysis.get_spacy_service', return_value=mock_spacy_service):
            response = client.post("/api/v1/nlp/extract-information", json={
                "text": SAMPLE_MEDICAL_TEXT,
                "information_types": ["entities", "keywords"],
                "language": "en"
            })
        
        assert response.status_code == 200
        data = response.json()
        
        assert "extracted_information" in data
        assert "information_count" in data
        assert "confidence_scores" in data
    
    def test_service_status_endpoint(self, client, mock_spacy_service, mock_model_manager):
        """Test service status endpoint."""
        with patch('src.api.spacy_analysis.get_spacy_service', return_value=mock_spacy_service), \
             patch('src.api.spacy_analysis.get_spacy_model_manager', return_value=mock_model_manager):
            
            response = client.get("/api/v1/nlp/status")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["service_name"] == "spaCy NLP Analysis Service"
        assert data["status"] == "healthy"
        assert "model_manager" in data
        assert "performance_stats" in data
    
    def test_available_models_endpoint(self, client, mock_model_manager):
        """Test available models endpoint."""
        with patch('src.api.spacy_analysis.get_spacy_model_manager', return_value=mock_model_manager):
            response = client.get("/api/v1/nlp/models")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "model_info" in data
        assert "supported_languages" in data
        assert "en" in data["supported_languages"]
    
    def test_load_model_endpoint(self, client, mock_model_manager):
        """Test model loading endpoint."""
        with patch('src.api.spacy_analysis.get_spacy_model_manager', return_value=mock_model_manager):
            response = client.post("/api/v1/nlp/models/en_core_web_sm/load?language=en")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "Model en_core_web_sm loaded successfully" in data["message"]
        assert "model_info" in data
    
    def test_unload_model_endpoint(self, client, mock_model_manager):
        """Test model unloading endpoint."""
        with patch('src.api.spacy_analysis.get_spacy_model_manager', return_value=mock_model_manager):
            response = client.delete("/api/v1/nlp/models/en_core_web_sm")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "Model en_core_web_sm unloaded successfully" in data["message"]
    
    def test_health_check_endpoint(self, client):
        """Test health check endpoint."""
        with patch('src.api.spacy_analysis.create_spacy_service') as mock_service, \
             patch('src.api.spacy_analysis.get_model_manager') as mock_manager:
            
            mock_service.return_value.get_performance_stats.return_value = {
                "active_jobs": 0,
                "completed_jobs": 100
            }
            mock_manager.return_value.get_model_info.return_value = {
                "loaded_models": 1,
                "total_models": 2
            }
            
            response = client.get("/api/v1/nlp/health")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["status"] == "healthy"
        assert data["service"] == "spacy_nlp_analysis"
        assert "statistics" in data
    
    def test_supported_languages_endpoint(self, client):
        """Test supported languages endpoint."""
        response = client.get("/api/v1/nlp/supported/languages")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "supported_languages" in data
        languages = data["supported_languages"]
        language_codes = [lang["code"] for lang in languages]
        
        assert "en" in language_codes
        assert "es" in language_codes
        assert "fr" in language_codes
        assert "de" in language_codes
    
    def test_validation_errors(self, client):
        """Test request validation errors."""
        # Test missing required field
        response = client.post("/api/v1/nlp/detect-language", json={})
        assert response.status_code == 422
        
        # Test invalid confidence threshold
        response = client.post("/api/v1/nlp/detect-language", json={
            "text": "test",
            "min_confidence": 1.5  # Invalid, should be <= 1.0
        })
        assert response.status_code == 422
        
        # Test invalid information types
        response = client.post("/api/v1/nlp/extract-information", json={
            "text": "test",
            "information_types": ["invalid_type"]
        })
        assert response.status_code == 422


class TestIntegration:
    """Test integration between components."""
    
    @pytest.mark.asyncio
    async def test_processor_service_integration(self):
        """Test integration between processor and service."""
        with patch('src.core.services.spacy_service.create_spacy_processor') as mock_create_processor:
            mock_processor = Mock()
            mock_processor.analyze_text.return_value = SpacyAnalysisResult(
                analysis_id="test",
                text_length=50,
                language="en",
                model_used="en_core_web_sm",
                tokens=[],
                sentences=[],
                entities=[],
                complexity=Mock(),
                document_structure=Mock(),
                language_detection=Mock(),
                pii_indicators=[],
                privacy_risk_score=0.0,
                statistics={}
            )
            mock_create_processor.return_value = mock_processor
            
            service = SpacyService()
            result = await service.analyze_text_async("Test integration text")
            
            assert result.text_length == 50
            assert result.language == "en"
    
    def test_pii_integration(self):
        """Test PII detection integration with spaCy components."""
        with patch('spacy.tokens.Token.set_extension'), \
             patch('spacy.tokens.Span.set_extension'), \
             patch('spacy.tokens.Doc.set_extension'):
            
            mock_nlp = Mock()
            detector = CustomPIIDetector(mock_nlp)
            
            assert PIIType.EMAIL in detector.pii_patterns
            assert PIIType.SSN in detector.pii_patterns
            assert PIIType.CREDIT_CARD in detector.pii_patterns
    
    def test_model_manager_integration(self):
        """Test model manager integration with enhanced models."""
        manager = SpacyModelManager(max_loaded_models=2)
        
        # Test memory management
        for i in range(3):
            model = EnhancedSpacyModel(f"test_model_{i}")
            manager.models[f"test_model_{i}"] = model
            manager.model_priority.append(f"test_model_{i}")
        
        # Simulate memory management
        manager._manage_memory("new_model")
        
        assert len(manager.models) == 3  # Models still exist, but may be unloaded


class TestPerformanceAndScaling:
    """Test performance and scaling aspects."""
    
    @pytest.mark.asyncio
    async def test_concurrent_analysis(self):
        """Test concurrent text analysis."""
        service = SpacyService()
        
        with patch.object(service, 'processor') as mock_processor:
            mock_result = SpacyAnalysisResult(
                analysis_id=str(uuid.uuid4()),
                text_length=20,
                language="en",
                model_used="en_core_web_sm",
                tokens=[],
                sentences=[],
                entities=[],
                complexity=Mock(),
                document_structure=Mock(),
                language_detection=Mock(),
                pii_indicators=[],
                privacy_risk_score=0.0,
                statistics={}
            )
            mock_processor.analyze_text.return_value = mock_result
            
            tasks = []
            for i in range(5):
                task = service.analyze_text_async(f"Test text {i}")
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            
            assert len(results) == 5
            for result in results:
                assert isinstance(result, SpacyAnalysisResult)
    
    def test_memory_cleanup(self):
        """Test memory cleanup in model manager."""
        manager = SpacyModelManager(max_loaded_models=2)
        
        # Add models
        for i in range(3):
            model = Mock()
            model.is_loaded = True
            model.unload = Mock()
            manager.models[f"model_{i}"] = model
            manager.model_priority.append(f"model_{i}")
        
        # Trigger memory management
        manager._manage_memory("new_model")
        
        # At least one model should have been unloaded
        unload_calls = sum(1 for model in manager.models.values() if model.unload.called)
        assert unload_calls >= 1
    
    def test_batch_processing_efficiency(self):
        """Test batch processing efficiency."""
        processor = SpacyProcessor()
        
        with patch.object(processor, 'analyze_text') as mock_analyze:
            mock_result = SpacyAnalysisResult(
                analysis_id=str(uuid.uuid4()),
                text_length=20,
                language="en",
                model_used="en_core_web_sm",
                tokens=[],
                sentences=[],
                entities=[],
                complexity=Mock(),
                document_structure=Mock(),
                language_detection=Mock(),
                pii_indicators=[],
                privacy_risk_score=0.0,
                statistics={}
            )
            mock_analyze.return_value = mock_result
            
            texts = [f"Sample text {i}" for i in range(10)]
            start_time = time.time()
            
            results = processor.batch_analyze_texts(texts, batch_size=5)
            
            processing_time = time.time() - start_time
            
            assert len(results) == 10
            # Batch processing should be more efficient than individual calls
            assert processing_time < 1.0  # Reasonable threshold for mocked processing


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])