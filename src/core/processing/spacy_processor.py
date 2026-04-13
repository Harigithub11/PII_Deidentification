"""
spaCy NLP Processing Module for PII De-identification System

This module provides comprehensive natural language processing capabilities using spaCy:
- Advanced linguistic analysis (tokenization, POS, parsing, lemmatization)
- Multi-language support with automatic detection
- Document structure analysis and sentence segmentation
- Custom pipeline components for PII-specific analysis
- Entity linking and coreference resolution
- Integration with existing document processing pipeline
"""

import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib

import spacy
from spacy import Language
from spacy.tokens import Doc, Token, Span
# from spacy.lang.detect import detect_language  # Not available in newer spaCy
try:
    from langdetect import detect as detect_language
except ImportError:
    def detect_language(text):
        """Fallback language detection function"""
        return 'en'  # Default to English
from spacy.pipeline import EntityRuler
import numpy as np

from ..config.settings import get_settings
from ..models.model_manager import get_model_manager

logger = logging.getLogger(__name__)


class LanguageSupport(Enum):
    """Supported languages for spaCy processing."""
    ENGLISH = "en"
    SPANISH = "es"
    FRENCH = "fr"
    GERMAN = "de"
    PORTUGUESE = "pt"
    ITALIAN = "it"
    DUTCH = "nl"
    CHINESE = "zh"
    JAPANESE = "ja"
    RUSSIAN = "ru"
    HINDI = "hi"
    ARABIC = "ar"


class TextComplexity(Enum):
    """Text complexity levels based on linguistic analysis."""
    SIMPLE = "simple"
    INTERMEDIATE = "intermediate"
    COMPLEX = "complex"
    VERY_COMPLEX = "very_complex"


class DocumentStructure(Enum):
    """Document structure types identified by linguistic analysis."""
    PARAGRAPH = "paragraph"
    SENTENCE = "sentence"
    PHRASE = "phrase"
    BULLET_POINT = "bullet_point"
    TITLE = "title"
    HEADER = "header"
    TABLE_CELL = "table_cell"
    FORM_FIELD = "form_field"


@dataclass
class LinguisticToken:
    """Enhanced token information with linguistic analysis."""
    text: str
    lemma: str
    pos: str  # Part-of-speech tag
    tag: str  # Detailed POS tag
    dep: str  # Dependency relation
    shape: str  # Token shape (e.g., "Xxxxx" for "Hello")
    is_alpha: bool
    is_ascii: bool
    is_digit: bool
    is_punct: bool
    is_space: bool
    is_stop: bool
    is_oov: bool  # Out of vocabulary
    start_char: int
    end_char: int
    sentiment: Optional[float] = None
    confidence: float = 1.0
    morphology: Dict[str, Any] = field(default_factory=dict)
    

@dataclass
class LinguisticSentence:
    """Sentence-level linguistic analysis."""
    text: str
    tokens: List[LinguisticToken]
    start_char: int
    end_char: int
    sentiment: Optional[float] = None
    complexity_score: float = 0.0
    named_entities: List[Dict[str, Any]] = field(default_factory=list)
    noun_phrases: List[str] = field(default_factory=list)
    verb_phrases: List[str] = field(default_factory=list)
    dependency_structure: Dict[str, Any] = field(default_factory=dict)
    

@dataclass
class DocumentStructureElement:
    """Document structure element with linguistic properties."""
    element_type: DocumentStructure
    text: str
    start_char: int
    end_char: int
    confidence: float
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LanguageDetectionResult:
    """Language detection result with confidence scores."""
    primary_language: str
    confidence: float
    language_distribution: Dict[str, float] = field(default_factory=dict)
    is_multilingual: bool = False
    detected_languages: List[str] = field(default_factory=list)


@dataclass
class SpacyAnalysisResult:
    """Comprehensive spaCy analysis result."""
    success: bool
    text_length: int
    processing_time: float
    
    # Language analysis
    language_detection: Optional[LanguageDetectionResult] = None
    
    # Linguistic analysis
    sentences: List[LinguisticSentence] = field(default_factory=list)
    tokens: List[LinguisticToken] = field(default_factory=list)
    
    # Named entities (enhanced beyond basic NER)
    named_entities: List[Dict[str, Any]] = field(default_factory=list)
    entity_types: Set[str] = field(default_factory=set)
    
    # Document structure
    structure_elements: List[DocumentStructureElement] = field(default_factory=list)
    
    # Complexity and readability
    complexity_level: TextComplexity = TextComplexity.SIMPLE
    readability_score: float = 0.0
    
    # Statistical analysis
    vocabulary_diversity: float = 0.0  # Type-token ratio
    average_sentence_length: float = 0.0
    pos_distribution: Dict[str, int] = field(default_factory=dict)
    
    # Advanced features
    noun_phrases: List[str] = field(default_factory=list)
    verb_phrases: List[str] = field(default_factory=list)
    key_phrases: List[str] = field(default_factory=list)
    
    # Processing metadata
    model_used: str = ""
    pipeline_components: List[str] = field(default_factory=list)
    processing_errors: List[str] = field(default_factory=list)
    
    # PII-specific analysis
    pii_indicators: List[Dict[str, Any]] = field(default_factory=list)
    privacy_risk_score: float = 0.0


class SpacyProcessingConfig:
    """Configuration for spaCy processing operations."""
    
    def __init__(
        self,
        model_name: str = "en_core_web_sm",
        language: Optional[str] = None,
        enable_ner: bool = True,
        enable_parser: bool = True,
        enable_tagger: bool = True,
        enable_lemmatizer: bool = True,
        enable_sentiment: bool = False,
        enable_entity_linking: bool = False,
        custom_patterns: Optional[List[Dict]] = None,
        batch_size: int = 1000,
        max_text_length: int = 1000000,
        confidence_threshold: float = 0.5
    ):
        self.model_name = model_name
        self.language = language
        self.enable_ner = enable_ner
        self.enable_parser = enable_parser
        self.enable_tagger = enable_tagger
        self.enable_lemmatizer = enable_lemmatizer
        self.enable_sentiment = enable_sentiment
        self.enable_entity_linking = enable_entity_linking
        self.custom_patterns = custom_patterns or []
        self.batch_size = batch_size
        self.max_text_length = max_text_length
        self.confidence_threshold = confidence_threshold


class SpacyProcessor:
    """Comprehensive spaCy-based NLP processor."""
    
    def __init__(self, config: Optional[SpacyProcessingConfig] = None):
        self.config = config or SpacyProcessingConfig()
        self.settings = get_settings()
        self.model_manager = get_model_manager()
        
        # Model instances
        self._models: Dict[str, Language] = {}
        self._model_info: Dict[str, Dict[str, Any]] = {}
        
        # Processing cache for efficiency
        self._processing_cache: Dict[str, SpacyAnalysisResult] = {}
        self.cache_enabled = True
        self.cache_max_size = 1000
        
        # Thread pool for concurrent processing
        self._executor = ThreadPoolExecutor(max_workers=4)
        
        # Supported model mappings
        self.model_mappings = {
            "en": ["en_core_web_sm", "en_core_web_md", "en_core_web_lg", "en_core_web_trf"],
            "es": ["es_core_news_sm", "es_core_news_md", "es_core_news_lg"],
            "fr": ["fr_core_news_sm", "fr_core_news_md", "fr_core_news_lg"],
            "de": ["de_core_news_sm", "de_core_news_md", "de_core_news_lg"],
            "pt": ["pt_core_news_sm", "pt_core_news_md", "pt_core_news_lg"],
            "it": ["it_core_news_sm", "it_core_news_md", "it_core_news_lg"],
            "nl": ["nl_core_news_sm", "nl_core_news_md", "nl_core_news_lg"],
            "zh": ["zh_core_web_sm", "zh_core_web_md", "zh_core_web_lg"],
            "ja": ["ja_core_news_sm", "ja_core_news_md", "ja_core_news_lg"],
            "ru": ["ru_core_news_sm", "ru_core_news_md", "ru_core_news_lg"]
        }
        
        logger.info("SpacyProcessor initialized")
    
    def _get_model(self, language: str = None, model_name: str = None) -> Optional[Language]:
        """Get or load spaCy model for specified language."""
        # Determine which model to use
        if model_name:
            target_model = model_name
        elif language and language in self.model_mappings:
            # Use the first available model for the language
            target_model = self.model_mappings[language][0]
        else:
            target_model = self.config.model_name
        
        # Return cached model if available
        if target_model in self._models:
            return self._models[target_model]
        
        # Try to load the model
        try:
            nlp = spacy.load(target_model)
            
            # Configure pipeline based on config
            if not self.config.enable_parser and nlp.has_pipe("parser"):
                nlp.disable_pipe("parser")
            if not self.config.enable_tagger and nlp.has_pipe("tagger"):
                nlp.disable_pipe("tagger")
            if not self.config.enable_ner and nlp.has_pipe("ner"):
                nlp.disable_pipe("ner")
            if not self.config.enable_lemmatizer and nlp.has_pipe("lemmatizer"):
                nlp.disable_pipe("lemmatizer")
            
            # Add custom entity ruler if patterns provided
            if self.config.custom_patterns:
                if not nlp.has_pipe("entity_ruler"):
                    ruler = nlp.add_pipe("entity_ruler", before="ner")
                else:
                    ruler = nlp.get_pipe("entity_ruler")
                ruler.add_patterns(self.config.custom_patterns)
            
            # Store model and info
            self._models[target_model] = nlp
            self._model_info[target_model] = {
                "model_name": target_model,
                "language": nlp.lang,
                "pipeline": nlp.pipe_names,
                "components": list(nlp.components),
                "vocab_size": len(nlp.vocab)
            }
            
            logger.info(f"Loaded spaCy model: {target_model}")
            return nlp
            
        except Exception as e:
            logger.error(f"Failed to load spaCy model {target_model}: {e}")
            
            # Try fallback models
            if language and language in self.model_mappings:
                for fallback_model in self.model_mappings[language][1:]:
                    try:
                        nlp = spacy.load(fallback_model)
                        self._models[fallback_model] = nlp
                        logger.info(f"Loaded fallback spaCy model: {fallback_model}")
                        return nlp
                    except Exception:
                        continue
            
            return None
    
    def detect_language(self, text: str, max_chars: int = 1000) -> LanguageDetectionResult:
        """Detect language of input text with confidence scores."""
        try:
            # Use first part of text for detection to avoid processing very long texts
            sample_text = text[:max_chars] if len(text) > max_chars else text
            
            # Try spaCy's language detection
            try:
                detected_langs = detect_language(sample_text)
                if detected_langs:
                    primary_lang = max(detected_langs, key=detected_langs.get)
                    confidence = detected_langs[primary_lang]
                    
                    return LanguageDetectionResult(
                        primary_language=primary_lang,
                        confidence=confidence,
                        language_distribution=detected_langs,
                        is_multilingual=len(detected_langs) > 1,
                        detected_languages=list(detected_langs.keys())
                    )
            except Exception as e:
                logger.warning(f"spaCy language detection failed: {e}")
            
            # Fallback: simple heuristic-based detection
            return self._fallback_language_detection(sample_text)
            
        except Exception as e:
            logger.error(f"Language detection failed: {e}")
            return LanguageDetectionResult(
                primary_language="en",
                confidence=0.5,
                language_distribution={"en": 0.5}
            )
    
    def _fallback_language_detection(self, text: str) -> LanguageDetectionResult:
        """Fallback language detection using simple heuristics."""
        # Basic character frequency analysis for common languages
        char_patterns = {
            "en": set("abcdefghijklmnopqrstuvwxyz"),
            "es": set("abcdefghijklmnñopqrstuvwxyzáéíóúü"),
            "fr": set("abcdefghijklmnopqrstuvwxyzàâäéèêëïîôùûüÿç"),
            "de": set("abcdefghijklmnopqrstuvwxyzäöüß"),
            "zh": lambda t: any('\u4e00' <= char <= '\u9fff' for char in t),
            "ar": lambda t: any('\u0600' <= char <= '\u06ff' for char in t),
            "hi": lambda t: any('\u0900' <= char <= '\u097f' for char in t)
        }
        
        text_lower = text.lower()
        scores = {}
        
        for lang, pattern in char_patterns.items():
            if callable(pattern):
                scores[lang] = 1.0 if pattern(text) else 0.0
            else:
                char_count = sum(1 for char in text_lower if char in pattern)
                scores[lang] = char_count / len(text) if text else 0.0
        
        # Find best match
        if scores:
            best_lang = max(scores, key=scores.get)
            confidence = scores[best_lang]
        else:
            best_lang, confidence = "en", 0.5
        
        return LanguageDetectionResult(
            primary_language=best_lang,
            confidence=confidence,
            language_distribution=scores
        )
    
    def analyze_text(
        self, 
        text: str, 
        language: Optional[str] = None,
        model_name: Optional[str] = None,
        config_override: Optional[SpacyProcessingConfig] = None
    ) -> SpacyAnalysisResult:
        """Perform comprehensive linguistic analysis of text."""
        start_time = time.time()
        
        # Use config override if provided
        config = config_override or self.config
        
        # Check cache first
        cache_key = self._generate_cache_key(text, language, model_name, config)
        if self.cache_enabled and cache_key in self._processing_cache:
            cached_result = self._processing_cache[cache_key]
            logger.debug(f"Returning cached analysis result for text of length {len(text)}")
            return cached_result
        
        # Validate input
        if not text or not text.strip():
            return SpacyAnalysisResult(
                success=False,
                text_length=0,
                processing_time=0.0,
                processing_errors=["Empty or whitespace-only text provided"]
            )
        
        if len(text) > config.max_text_length:
            text = text[:config.max_text_length]
            logger.warning(f"Text truncated to {config.max_text_length} characters")
        
        try:
            # Detect language if not provided
            if not language:
                lang_result = self.detect_language(text)
                language = lang_result.primary_language
                language_detection = lang_result
            else:
                language_detection = LanguageDetectionResult(
                    primary_language=language,
                    confidence=1.0,
                    language_distribution={language: 1.0}
                )
            
            # Get appropriate model
            nlp = self._get_model(language, model_name)
            if not nlp:
                return SpacyAnalysisResult(
                    success=False,
                    text_length=len(text),
                    processing_time=time.time() - start_time,
                    language_detection=language_detection,
                    processing_errors=[f"No suitable spaCy model found for language: {language}"]
                )
            
            # Process text with spaCy
            doc = nlp(text)
            
            # Extract comprehensive analysis
            result = self._extract_comprehensive_analysis(
                doc, nlp, language_detection, start_time
            )
            
            # Cache result if enabled
            if self.cache_enabled:
                self._cache_result(cache_key, result)
            
            return result
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"spaCy analysis failed: {e}")
            
            return SpacyAnalysisResult(
                success=False,
                text_length=len(text),
                processing_time=processing_time,
                processing_errors=[str(e)]
            )
    
    def _extract_comprehensive_analysis(
        self, 
        doc: Doc, 
        nlp: Language,
        language_detection: LanguageDetectionResult,
        start_time: float
    ) -> SpacyAnalysisResult:
        """Extract comprehensive linguistic analysis from spaCy Doc."""
        
        # Extract tokens
        tokens = []
        for token in doc:
            ling_token = LinguisticToken(
                text=token.text,
                lemma=token.lemma_,
                pos=token.pos_,
                tag=token.tag_,
                dep=token.dep_,
                shape=token.shape_,
                is_alpha=token.is_alpha,
                is_ascii=token.is_ascii,
                is_digit=token.is_digit,
                is_punct=token.is_punct,
                is_space=token.is_space,
                is_stop=token.is_stop,
                is_oov=token.is_oov,
                start_char=token.idx,
                end_char=token.idx + len(token.text),
                morphology=dict(token.morph) if token.morph else {}
            )
            tokens.append(ling_token)
        
        # Extract sentences
        sentences = []
        for sent in doc.sents:
            sent_tokens = [
                token for token in tokens 
                if sent.start_char <= token.start_char < sent.end_char
            ]
            
            # Extract noun phrases for this sentence
            noun_phrases = [chunk.text for chunk in sent.noun_chunks]
            
            # Basic sentiment analysis (if available)
            sentiment = getattr(sent, 'sentiment', None)
            if hasattr(sent, 'sentiment') and hasattr(sent.sentiment, 'polarity'):
                sentiment = sent.sentiment.polarity
            
            ling_sentence = LinguisticSentence(
                text=sent.text,
                tokens=sent_tokens,
                start_char=sent.start_char,
                end_char=sent.end_char,
                sentiment=sentiment,
                complexity_score=self._calculate_sentence_complexity(sent),
                noun_phrases=noun_phrases,
                verb_phrases=self._extract_verb_phrases(sent),
                dependency_structure=self._extract_dependency_structure(sent)
            )
            sentences.append(ling_sentence)
        
        # Extract named entities
        named_entities = []
        entity_types = set()
        for ent in doc.ents:
            entity_info = {
                "text": ent.text,
                "label": ent.label_,
                "start_char": ent.start_char,
                "end_char": ent.end_char,
                "confidence": 1.0,  # spaCy doesn't provide confidence by default
                "description": spacy.explain(ent.label_) or ent.label_
            }
            named_entities.append(entity_info)
            entity_types.add(ent.label_)
        
        # Calculate complexity and readability
        complexity_level = self._assess_text_complexity(doc)
        readability_score = self._calculate_readability_score(doc)
        
        # Calculate vocabulary diversity
        vocabulary_diversity = self._calculate_vocabulary_diversity(doc)
        
        # Calculate average sentence length
        avg_sentence_length = (
            sum(len(sent) for sent in doc.sents) / len(list(doc.sents))
            if list(doc.sents) else 0.0
        )
        
        # POS distribution
        pos_distribution = {}
        for token in doc:
            pos = token.pos_
            pos_distribution[pos] = pos_distribution.get(pos, 0) + 1
        
        # Extract document structure elements
        structure_elements = self._identify_document_structure(doc)
        
        # Extract key phrases
        key_phrases = self._extract_key_phrases(doc)
        
        # Analyze PII indicators
        pii_indicators = self._analyze_pii_indicators(doc)
        privacy_risk_score = self._calculate_privacy_risk_score(pii_indicators)
        
        processing_time = time.time() - start_time
        
        return SpacyAnalysisResult(
            success=True,
            text_length=len(doc.text),
            processing_time=processing_time,
            language_detection=language_detection,
            sentences=sentences,
            tokens=tokens,
            named_entities=named_entities,
            entity_types=entity_types,
            structure_elements=structure_elements,
            complexity_level=complexity_level,
            readability_score=readability_score,
            vocabulary_diversity=vocabulary_diversity,
            average_sentence_length=avg_sentence_length,
            pos_distribution=pos_distribution,
            noun_phrases=list(set(phrase for sent in sentences for phrase in sent.noun_phrases)),
            verb_phrases=list(set(phrase for sent in sentences for phrase in sent.verb_phrases)),
            key_phrases=key_phrases,
            model_used=nlp.meta.get("name", "unknown"),
            pipeline_components=nlp.pipe_names,
            pii_indicators=pii_indicators,
            privacy_risk_score=privacy_risk_score
        )
    
    def _calculate_sentence_complexity(self, sent: Span) -> float:
        """Calculate complexity score for a sentence."""
        try:
            # Factors contributing to complexity
            word_count = len([token for token in sent if not token.is_punct])
            avg_word_length = np.mean([len(token.text) for token in sent if not token.is_punct]) if word_count > 0 else 0
            unique_pos_count = len(set(token.pos_ for token in sent))
            dependency_depth = self._calculate_dependency_depth(sent)
            
            # Normalize and combine scores
            word_complexity = min(word_count / 20.0, 1.0)  # Normalize to 0-1
            length_complexity = min(avg_word_length / 10.0, 1.0)
            pos_complexity = min(unique_pos_count / 15.0, 1.0)
            dep_complexity = min(dependency_depth / 10.0, 1.0)
            
            return (word_complexity + length_complexity + pos_complexity + dep_complexity) / 4.0
            
        except Exception:
            return 0.5  # Default moderate complexity
    
    def _calculate_dependency_depth(self, sent: Span) -> int:
        """Calculate the maximum dependency depth in a sentence."""
        try:
            max_depth = 0
            
            def get_depth(token, current_depth=0):
                nonlocal max_depth
                max_depth = max(max_depth, current_depth)
                for child in token.children:
                    get_depth(child, current_depth + 1)
            
            # Find root tokens and calculate depth
            for token in sent:
                if token.dep_ == "ROOT":
                    get_depth(token)
            
            return max_depth
            
        except Exception:
            return 0
    
    def _extract_verb_phrases(self, sent: Span) -> List[str]:
        """Extract verb phrases from a sentence."""
        verb_phrases = []
        try:
            for token in sent:
                if token.pos_ == "VERB":
                    # Get the verb and its immediate dependents
                    phrase_tokens = [token]
                    for child in token.children:
                        if child.dep_ in ["aux", "auxpass", "neg", "prt"]:
                            phrase_tokens.append(child)
                    
                    # Sort by position and create phrase
                    phrase_tokens.sort(key=lambda t: t.i)
                    phrase = " ".join(t.text for t in phrase_tokens)
                    verb_phrases.append(phrase)
        except Exception:
            pass
        
        return verb_phrases
    
    def _extract_dependency_structure(self, sent: Span) -> Dict[str, Any]:
        """Extract dependency structure information."""
        try:
            structure = {
                "root": None,
                "dependencies": [],
                "depth": self._calculate_dependency_depth(sent)
            }
            
            for token in sent:
                if token.dep_ == "ROOT":
                    structure["root"] = token.text
                
                dependency = {
                    "head": token.head.text,
                    "dependent": token.text,
                    "relation": token.dep_,
                    "head_pos": token.head.pos_,
                    "dependent_pos": token.pos_
                }
                structure["dependencies"].append(dependency)
            
            return structure
            
        except Exception:
            return {"root": None, "dependencies": [], "depth": 0}
    
    def _assess_text_complexity(self, doc: Doc) -> TextComplexity:
        """Assess overall text complexity."""
        try:
            # Calculate various complexity indicators
            avg_sent_length = np.mean([len(sent) for sent in doc.sents]) if list(doc.sents) else 0
            vocab_diversity = len(set(token.lemma_ for token in doc if token.is_alpha)) / len([token for token in doc if token.is_alpha])
            pos_diversity = len(set(token.pos_ for token in doc)) / len(doc) if len(doc) > 0 else 0
            
            # Combine into complexity score
            complexity_score = (
                min(avg_sent_length / 20.0, 1.0) * 0.4 +
                vocab_diversity * 0.3 +
                pos_diversity * 0.3
            )
            
            if complexity_score < 0.3:
                return TextComplexity.SIMPLE
            elif complexity_score < 0.6:
                return TextComplexity.INTERMEDIATE
            elif complexity_score < 0.8:
                return TextComplexity.COMPLEX
            else:
                return TextComplexity.VERY_COMPLEX
                
        except Exception:
            return TextComplexity.INTERMEDIATE
    
    def _calculate_readability_score(self, doc: Doc) -> float:
        """Calculate a simple readability score."""
        try:
            sentences = list(doc.sents)
            if not sentences:
                return 0.0
            
            # Simple readability approximation
            avg_sentence_length = len(doc) / len(sentences)
            syllable_count = sum(self._count_syllables(token.text) for token in doc if token.is_alpha)
            avg_syllables_per_word = syllable_count / len([token for token in doc if token.is_alpha])
            
            # Simplified Flesch formula approximation
            score = 206.835 - (1.015 * avg_sentence_length) - (84.6 * avg_syllables_per_word)
            return max(0.0, min(100.0, score))
            
        except Exception:
            return 50.0
    
    def _count_syllables(self, word: str) -> int:
        """Rough syllable count estimation."""
        word = word.lower()
        count = 0
        vowels = "aeiouy"
        
        if word[0] in vowels:
            count += 1
        
        for i in range(1, len(word)):
            if word[i] in vowels and word[i-1] not in vowels:
                count += 1
        
        if word.endswith("e"):
            count -= 1
        
        return max(1, count)
    
    def _calculate_vocabulary_diversity(self, doc: Doc) -> float:
        """Calculate vocabulary diversity (type-token ratio)."""
        try:
            alpha_tokens = [token.lemma_.lower() for token in doc if token.is_alpha]
            if not alpha_tokens:
                return 0.0
            
            unique_tokens = set(alpha_tokens)
            return len(unique_tokens) / len(alpha_tokens)
            
        except Exception:
            return 0.0
    
    def _identify_document_structure(self, doc: Doc) -> List[DocumentStructureElement]:
        """Identify document structure elements."""
        structure_elements = []
        
        try:
            for sent in doc.sents:
                # Simple heuristics for structure identification
                text = sent.text.strip()
                
                if not text:
                    continue
                
                # Determine element type based on patterns
                element_type = DocumentStructure.SENTENCE  # default
                confidence = 0.8
                
                # Check for titles/headers (short, often capitalized)
                if len(text) < 100 and text.isupper():
                    element_type = DocumentStructure.HEADER
                    confidence = 0.9
                elif len(text) < 50 and any(char.isupper() for char in text[:10]):
                    element_type = DocumentStructure.TITLE
                    confidence = 0.7
                # Check for bullet points
                elif text.startswith(('•', '-', '*', '1.', '2.', 'a)', 'i)')):
                    element_type = DocumentStructure.BULLET_POINT
                    confidence = 0.8
                
                structure_element = DocumentStructureElement(
                    element_type=element_type,
                    text=text,
                    start_char=sent.start_char,
                    end_char=sent.end_char,
                    confidence=confidence
                )
                structure_elements.append(structure_element)
        
        except Exception as e:
            logger.warning(f"Document structure analysis failed: {e}")
        
        return structure_elements
    
    def _extract_key_phrases(self, doc: Doc) -> List[str]:
        """Extract key phrases from the document."""
        key_phrases = []
        
        try:
            # Extract noun phrases as potential key phrases
            for chunk in doc.noun_chunks:
                if len(chunk.text.split()) >= 2:  # Multi-word phrases
                    key_phrases.append(chunk.text)
            
            # Extract frequent adjective-noun combinations
            for token in doc:
                if token.pos_ == "ADJ" and token.head.pos_ == "NOUN":
                    phrase = f"{token.text} {token.head.text}"
                    key_phrases.append(phrase)
            
            # Remove duplicates and sort by length
            key_phrases = list(set(key_phrases))
            key_phrases.sort(key=len, reverse=True)
            
            return key_phrases[:20]  # Return top 20 key phrases
            
        except Exception:
            return []
    
    def _analyze_pii_indicators(self, doc: Doc) -> List[Dict[str, Any]]:
        """Analyze potential PII indicators using linguistic patterns."""
        pii_indicators = []
        
        try:
            # Look for patterns that might indicate PII
            for token in doc:
                indicator = None
                confidence = 0.0
                
                # Email-like patterns
                if "@" in token.text and "." in token.text:
                    indicator = {"type": "email_pattern", "confidence": 0.8}
                
                # Phone number patterns
                elif token.like_num and len(token.text) >= 10:
                    indicator = {"type": "phone_pattern", "confidence": 0.6}
                
                # Name patterns (capitalized words near person indicators)
                elif token.is_title and token.pos_ == "PROPN":
                    # Check if near common person indicators
                    window = doc[max(0, token.i-2):min(len(doc), token.i+3)]
                    person_indicators = ["mr", "mrs", "ms", "dr", "name", "patient", "client"]
                    if any(t.text.lower() in person_indicators for t in window):
                        indicator = {"type": "name_pattern", "confidence": 0.7}
                
                if indicator:
                    pii_indicators.append({
                        "text": token.text,
                        "start_char": token.idx,
                        "end_char": token.idx + len(token.text),
                        **indicator
                    })
        
        except Exception as e:
            logger.warning(f"PII indicator analysis failed: {e}")
        
        return pii_indicators
    
    def _calculate_privacy_risk_score(self, pii_indicators: List[Dict[str, Any]]) -> float:
        """Calculate overall privacy risk score based on PII indicators."""
        if not pii_indicators:
            return 0.0
        
        try:
            # Weight different types of PII indicators
            type_weights = {
                "email_pattern": 0.8,
                "phone_pattern": 0.7,
                "name_pattern": 0.6,
                "address_pattern": 0.9,
                "id_pattern": 0.9
            }
            
            total_risk = 0.0
            for indicator in pii_indicators:
                indicator_type = indicator.get("type", "unknown")
                confidence = indicator.get("confidence", 0.5)
                weight = type_weights.get(indicator_type, 0.5)
                total_risk += confidence * weight
            
            # Normalize to 0-1 range
            return min(1.0, total_risk / 3.0)
            
        except Exception:
            return 0.5
    
    def _generate_cache_key(
        self, 
        text: str, 
        language: Optional[str], 
        model_name: Optional[str],
        config: SpacyProcessingConfig
    ) -> str:
        """Generate cache key for processing results."""
        key_components = [
            text[:100],  # First 100 chars of text
            str(language),
            str(model_name),
            str(config.enable_ner),
            str(config.enable_parser),
            str(config.enable_tagger),
            str(config.confidence_threshold)
        ]
        key_string = "|".join(key_components)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _cache_result(self, cache_key: str, result: SpacyAnalysisResult):
        """Cache analysis result."""
        try:
            if len(self._processing_cache) >= self.cache_max_size:
                # Remove oldest entries (simple FIFO)
                oldest_key = next(iter(self._processing_cache))
                del self._processing_cache[oldest_key]
            
            self._processing_cache[cache_key] = result
            
        except Exception as e:
            logger.warning(f"Failed to cache result: {e}")
    
    async def analyze_text_async(
        self, 
        text: str, 
        language: Optional[str] = None,
        model_name: Optional[str] = None,
        config_override: Optional[SpacyProcessingConfig] = None
    ) -> SpacyAnalysisResult:
        """Asynchronous text analysis."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self.analyze_text,
            text, language, model_name, config_override
        )
    
    def batch_analyze_texts(
        self,
        texts: List[str],
        language: Optional[str] = None,
        model_name: Optional[str] = None,
        config_override: Optional[SpacyProcessingConfig] = None
    ) -> List[SpacyAnalysisResult]:
        """Batch analyze multiple texts."""
        results = []
        
        for text in texts:
            try:
                result = self.analyze_text(text, language, model_name, config_override)
                results.append(result)
            except Exception as e:
                logger.error(f"Batch analysis failed for text: {e}")
                results.append(SpacyAnalysisResult(
                    success=False,
                    text_length=len(text) if text else 0,
                    processing_time=0.0,
                    processing_errors=[str(e)]
                ))
        
        return results
    
    async def batch_analyze_texts_async(
        self,
        texts: List[str],
        language: Optional[str] = None,
        model_name: Optional[str] = None,
        config_override: Optional[SpacyProcessingConfig] = None
    ) -> List[SpacyAnalysisResult]:
        """Asynchronous batch text analysis."""
        tasks = []
        for text in texts:
            task = self.analyze_text_async(text, language, model_name, config_override)
            tasks.append(task)
        
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_available_models(self) -> Dict[str, List[str]]:
        """Get available spaCy models by language."""
        return self.model_mappings.copy()
    
    def get_model_info(self, model_name: str = None) -> Dict[str, Any]:
        """Get information about loaded models."""
        if model_name and model_name in self._model_info:
            return self._model_info[model_name].copy()
        
        return {
            "loaded_models": list(self._model_info.keys()),
            "model_details": self._model_info.copy()
        }
    
    def clear_cache(self):
        """Clear processing cache."""
        self._processing_cache.clear()
        logger.info("Processing cache cleared")
    
    def cleanup(self):
        """Clean up resources."""
        try:
            if hasattr(self, '_executor'):
                self._executor.shutdown(wait=True)
            
            self._models.clear()
            self._model_info.clear()
            self.clear_cache()
            
            logger.info("SpacyProcessor cleanup completed")
            
        except Exception as e:
            logger.error(f"SpacyProcessor cleanup failed: {e}")


# Factory function
def create_spacy_processor(config: Optional[SpacyProcessingConfig] = None) -> SpacyProcessor:
    """Create spaCy processor with specified configuration."""
    return SpacyProcessor(config)


# Convenience functions
def quick_language_detection(text: str) -> str:
    """Quick language detection for text."""
    processor = create_spacy_processor()
    try:
        result = processor.detect_language(text)
        return result.primary_language
    finally:
        processor.cleanup()


def quick_linguistic_analysis(text: str, language: str = None) -> Dict[str, Any]:
    """Quick linguistic analysis returning basic metrics."""
    processor = create_spacy_processor()
    try:
        result = processor.analyze_text(text, language)
        if result.success:
            return {
                "language": result.language_detection.primary_language if result.language_detection else "unknown",
                "sentence_count": len(result.sentences),
                "word_count": len(result.tokens),
                "complexity": result.complexity_level.value,
                "readability": result.readability_score,
                "entity_count": len(result.named_entities),
                "privacy_risk": result.privacy_risk_score
            }
        return {"error": result.processing_errors}
    finally:
        processor.cleanup()