"""
Enhanced spaCy Models for PII De-identification System

This module provides extended spaCy model functionality with:
- Custom entity rulers for domain-specific PII detection
- Multi-language model management with automatic fallbacks
- Transformer-based model integration
- Model versioning and performance optimization
- Custom pipeline components for specialized NLP tasks
"""

import logging
import os
import json
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import time
from collections import defaultdict

import spacy
from spacy import Language, util
from spacy.tokens import Doc, Span, Token
from spacy.pipeline import EntityRuler, Sentencizer
from spacy.lang.en import English
from spacy.lang.es import Spanish
from spacy.lang.fr import French
from spacy.lang.de import German
from spacy.training import Example
import numpy as np

from ..config.settings import get_settings
from ..config.policies.base import PIIType

logger = logging.getLogger(__name__)


class ModelType(Enum):
    """Types of spaCy models available."""
    SMALL = "sm"
    MEDIUM = "md"
    LARGE = "lg"
    TRANSFORMER = "trf"


class PipelineComponent(Enum):
    """Available pipeline components."""
    TOKENIZER = "tokenizer"
    TAGGER = "tagger"
    PARSER = "parser"
    NER = "ner"
    LEMMATIZER = "lemmatizer"
    SENTENCIZER = "sentencizer"
    ENTITY_RULER = "entity_ruler"
    ATTRIBUTE_RULER = "attribute_ruler"
    CUSTOM_PII_DETECTOR = "custom_pii_detector"
    PRIVACY_ANALYZER = "privacy_analyzer"


@dataclass
class ModelInfo:
    """Information about a spaCy model."""
    name: str
    language: str
    model_type: ModelType
    version: str
    size_mb: float
    pipeline: List[str]
    capabilities: Set[str]
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    last_used: Optional[float] = None
    load_time: Optional[float] = None


@dataclass
class CustomEntityPattern:
    """Custom entity pattern for entity ruler."""
    label: str
    pattern: Union[str, List[Dict[str, Any]]]
    confidence: float = 1.0
    description: Optional[str] = None
    category: Optional[str] = None


@dataclass
class PIIPattern:
    """PII-specific entity pattern."""
    pii_type: PIIType
    patterns: List[CustomEntityPattern]
    risk_level: str = "MEDIUM"
    compliance_flags: List[str] = field(default_factory=list)


class CustomPIIDetector:
    """Custom pipeline component for enhanced PII detection."""
    
    def __init__(self, nlp: Language, name: str = "custom_pii_detector"):
        self.name = name
        self.nlp = nlp
        
        # PII detection patterns
        self.pii_patterns = self._initialize_pii_patterns()
        
        # Custom attributes
        if not Token.has_extension("is_pii"):
            Token.set_extension("is_pii", default=False)
        if not Token.has_extension("pii_type"):
            Token.set_extension("pii_type", default=None)
        if not Token.has_extension("pii_confidence"):
            Token.set_extension("pii_confidence", default=0.0)
        
        if not Span.has_extension("privacy_risk"):
            Span.set_extension("privacy_risk", default=0.0)
        if not Doc.has_extension("privacy_summary"):
            Doc.set_extension("privacy_summary", default=None)
    
    def __call__(self, doc: Doc) -> Doc:
        """Process document for PII detection."""
        try:
            pii_entities = []
            privacy_scores = []
            
            # Analyze tokens for PII patterns
            for token in doc:
                pii_info = self._analyze_token_for_pii(token, doc)
                if pii_info:
                    token._.is_pii = True
                    token._.pii_type = pii_info["type"]
                    token._.pii_confidence = pii_info["confidence"]
                    privacy_scores.append(pii_info["risk_score"])
            
            # Analyze spans for multi-token PII
            pii_spans = self._detect_pii_spans(doc)
            for span in pii_spans:
                span._.privacy_risk = span["risk_score"]
                pii_entities.append(span)
            
            # Set document-level privacy summary
            doc._.privacy_summary = {
                "total_pii_tokens": sum(1 for token in doc if token._.is_pii),
                "pii_types": list(set(token._.pii_type for token in doc if token._.is_pii)),
                "overall_privacy_risk": np.mean(privacy_scores) if privacy_scores else 0.0,
                "pii_spans": len(pii_spans)
            }
            
            return doc
            
        except Exception as e:
            logger.error(f"Custom PII detection failed: {e}")
            return doc
    
    def _initialize_pii_patterns(self) -> Dict[PIIType, List[Dict]]:
        """Initialize PII detection patterns."""
        patterns = {
            PIIType.EMAIL: [
                {"pattern": [
                    {"LIKE_EMAIL": True}
                ], "confidence": 0.9},
                {"pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "confidence": 0.8}
            ],
            PIIType.PHONE: [
                {"pattern": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "confidence": 0.8},
                {"pattern": r"\b\(\d{3}\)\s?\d{3}[-.]?\d{4}\b", "confidence": 0.9},
                {"pattern": r"\b\+\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b", "confidence": 0.7}
            ],
            PIIType.SSN: [
                {"pattern": r"\b\d{3}-\d{2}-\d{4}\b", "confidence": 0.95},
                {"pattern": r"\b\d{9}\b", "confidence": 0.6}  # Less confident for 9 digits
            ],
            PIIType.CREDIT_CARD: [
                {"pattern": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", "confidence": 0.8},
                {"pattern": r"\b\d{16}\b", "confidence": 0.7}
            ],
            PIIType.IP_ADDRESS: [
                {"pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "confidence": 0.9}
            ],
            PIIType.DATE_OF_BIRTH: [
                {"pattern": r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", "confidence": 0.7},
                {"pattern": r"\b\d{2,4}[/-]\d{1,2}[/-]\d{1,2}\b", "confidence": 0.7}
            ]
        }
        return patterns
    
    def _analyze_token_for_pii(self, token: Token, doc: Doc) -> Optional[Dict[str, Any]]:
        """Analyze individual token for PII characteristics."""
        try:
            # Skip punctuation and whitespace
            if token.is_punct or token.is_space:
                return None
            
            text = token.text
            
            # Email detection
            if "@" in text and "." in text:
                return {
                    "type": PIIType.EMAIL.value,
                    "confidence": 0.8,
                    "risk_score": 0.7
                }
            
            # Phone number detection (basic)
            if token.like_num and len(text) >= 10:
                return {
                    "type": PIIType.PHONE.value,
                    "confidence": 0.6,
                    "risk_score": 0.6
                }
            
            # IP address detection
            if self._is_ip_address(text):
                return {
                    "type": PIIType.IP_ADDRESS.value,
                    "confidence": 0.9,
                    "risk_score": 0.5
                }
            
            # Potential name detection (enhanced heuristics)
            if self._is_potential_name(token, doc):
                return {
                    "type": PIIType.NAME.value,
                    "confidence": 0.7,
                    "risk_score": 0.8
                }
            
            return None
            
        except Exception:
            return None
    
    def _detect_pii_spans(self, doc: Doc) -> List[Dict[str, Any]]:
        """Detect multi-token PII spans."""
        pii_spans = []
        
        try:
            # Look for patterns that span multiple tokens
            for i in range(len(doc) - 1):
                # SSN pattern: XXX-XX-XXXX
                if (i + 4 < len(doc) and 
                    doc[i].like_num and len(doc[i].text) == 3 and
                    doc[i + 1].text == "-" and
                    doc[i + 2].like_num and len(doc[i + 2].text) == 2 and
                    doc[i + 3].text == "-" and
                    doc[i + 4].like_num and len(doc[i + 4].text) == 4):
                    
                    span_info = {
                        "start": i,
                        "end": i + 5,
                        "type": PIIType.SSN.value,
                        "confidence": 0.95,
                        "risk_score": 0.9,
                        "text": doc[i:i+5].text
                    }
                    pii_spans.append(span_info)
                
                # Credit card pattern: XXXX XXXX XXXX XXXX
                if (i + 6 < len(doc) and
                    all(doc[j].like_num and len(doc[j].text) == 4 for j in [i, i+2, i+4, i+6]) and
                    all(doc[j].is_space or doc[j].text in ["-", " "] for j in [i+1, i+3, i+5])):
                    
                    span_info = {
                        "start": i,
                        "end": i + 7,
                        "type": PIIType.CREDIT_CARD.value,
                        "confidence": 0.8,
                        "risk_score": 0.85,
                        "text": doc[i:i+7].text
                    }
                    pii_spans.append(span_info)
        
        except Exception as e:
            logger.warning(f"PII span detection failed: {e}")
        
        return pii_spans
    
    def _is_ip_address(self, text: str) -> bool:
        """Check if text is an IP address."""
        try:
            parts = text.split(".")
            if len(parts) != 4:
                return False
            
            for part in parts:
                if not part.isdigit() or not (0 <= int(part) <= 255):
                    return False
            
            return True
        except Exception:
            return False
    
    def _is_potential_name(self, token: Token, doc: Doc) -> bool:
        """Enhanced heuristic for potential name detection."""
        try:
            # Check if token is a proper noun
            if token.pos_ != "PROPN":
                return False
            
            # Check if it's titlecased
            if not token.is_title:
                return False
            
            # Look for name indicators in context
            window_start = max(0, token.i - 3)
            window_end = min(len(doc), token.i + 4)
            context = doc[window_start:window_end]
            
            name_indicators = {
                "mr", "mrs", "ms", "dr", "prof", "name", "patient", "client",
                "employee", "person", "individual", "contact", "customer"
            }
            
            context_text = " ".join(t.text.lower() for t in context)
            
            for indicator in name_indicators:
                if indicator in context_text:
                    return True
            
            # Check if followed by another proper noun (could be full name)
            if (token.i + 1 < len(doc) and 
                doc[token.i + 1].pos_ == "PROPN" and
                doc[token.i + 1].is_title):
                return True
            
            return False
            
        except Exception:
            return False


class PrivacyAnalyzer:
    """Pipeline component for privacy risk analysis."""
    
    def __init__(self, nlp: Language, name: str = "privacy_analyzer"):
        self.name = name
        self.nlp = nlp
        
        # Risk scoring weights
        self.risk_weights = {
            PIIType.SSN.value: 1.0,
            PIIType.CREDIT_CARD.value: 0.9,
            PIIType.BANK_ACCOUNT.value: 0.9,
            PIIType.PASSPORT.value: 0.8,
            PIIType.DRIVER_LICENSE.value: 0.8,
            PIIType.EMAIL.value: 0.6,
            PIIType.PHONE.value: 0.6,
            PIIType.NAME.value: 0.7,
            PIIType.ADDRESS.value: 0.7,
            PIIType.DATE_OF_BIRTH.value: 0.5,
            PIIType.IP_ADDRESS.value: 0.4
        }
        
        # Document-level extensions
        if not Doc.has_extension("privacy_analysis"):
            Doc.set_extension("privacy_analysis", default=None)
    
    def __call__(self, doc: Doc) -> Doc:
        """Analyze document for privacy risks."""
        try:
            analysis = {
                "overall_risk_score": 0.0,
                "risk_level": "LOW",
                "pii_density": 0.0,
                "sensitive_entity_count": 0,
                "risk_factors": [],
                "recommendations": []
            }
            
            # Count PII entities by type
            pii_counts = defaultdict(int)
            total_pii = 0
            
            # Count from tokens
            for token in doc:
                if hasattr(token._, 'is_pii') and token._.is_pii:
                    pii_type = token._.pii_type
                    pii_counts[pii_type] += 1
                    total_pii += 1
            
            # Count from named entities
            for ent in doc.ents:
                if ent.label_.startswith("PII_") or ent.label_ in self.risk_weights:
                    entity_type = ent.label_.replace("PII_", "")
                    pii_counts[entity_type] += 1
                    total_pii += 1
            
            # Calculate risk score
            risk_score = 0.0
            for pii_type, count in pii_counts.items():
                weight = self.risk_weights.get(pii_type, 0.5)
                risk_score += count * weight
            
            # Normalize risk score
            if total_pii > 0:
                risk_score = min(1.0, risk_score / (len(doc) * 0.1))  # Normalize by document length
                analysis["pii_density"] = total_pii / len(doc)
            
            analysis["overall_risk_score"] = risk_score
            analysis["sensitive_entity_count"] = total_pii
            
            # Determine risk level
            if risk_score < 0.3:
                analysis["risk_level"] = "LOW"
            elif risk_score < 0.6:
                analysis["risk_level"] = "MEDIUM"
            elif risk_score < 0.8:
                analysis["risk_level"] = "HIGH"
            else:
                analysis["risk_level"] = "CRITICAL"
            
            # Generate risk factors and recommendations
            analysis["risk_factors"] = self._generate_risk_factors(pii_counts, analysis)
            analysis["recommendations"] = self._generate_recommendations(analysis, pii_counts)
            
            doc._.privacy_analysis = analysis
            return doc
            
        except Exception as e:
            logger.error(f"Privacy analysis failed: {e}")
            doc._.privacy_analysis = {"error": str(e)}
            return doc
    
    def _generate_risk_factors(self, pii_counts: Dict[str, int], analysis: Dict) -> List[str]:
        """Generate list of privacy risk factors."""
        factors = []
        
        try:
            # High-risk PII types present
            high_risk_types = [PIIType.SSN.value, PIIType.CREDIT_CARD.value, PIIType.BANK_ACCOUNT.value]
            for pii_type in high_risk_types:
                if pii_counts.get(pii_type, 0) > 0:
                    factors.append(f"Contains {pii_type.replace('_', ' ').title()}")
            
            # Multiple PII types
            if len(pii_counts) > 3:
                factors.append("Multiple PII types present")
            
            # High PII density
            if analysis.get("pii_density", 0) > 0.1:
                factors.append("High concentration of PII")
            
            # Specific combinations
            if (pii_counts.get(PIIType.NAME.value, 0) > 0 and 
                pii_counts.get(PIIType.ADDRESS.value, 0) > 0):
                factors.append("Name and address combination")
            
            if (pii_counts.get(PIIType.EMAIL.value, 0) > 0 and 
                pii_counts.get(PIIType.PHONE.value, 0) > 0):
                factors.append("Contact information cluster")
        
        except Exception as e:
            logger.warning(f"Risk factor generation failed: {e}")
        
        return factors
    
    def _generate_recommendations(self, analysis: Dict, pii_counts: Dict[str, int]) -> List[str]:
        """Generate privacy protection recommendations."""
        recommendations = []
        
        try:
            risk_level = analysis.get("risk_level", "LOW")
            
            if risk_level in ["HIGH", "CRITICAL"]:
                recommendations.append("Implement strong access controls and encryption")
                recommendations.append("Consider data minimization strategies")
                recommendations.append("Regular audit and monitoring required")
            
            if risk_level in ["MEDIUM", "HIGH", "CRITICAL"]:
                recommendations.append("Apply appropriate de-identification techniques")
                recommendations.append("Ensure compliance with privacy regulations")
            
            # Specific recommendations based on PII types
            if pii_counts.get(PIIType.SSN.value, 0) > 0:
                recommendations.append("SSN requires special handling and protection")
            
            if pii_counts.get(PIIType.CREDIT_CARD.value, 0) > 0:
                recommendations.append("PCI DSS compliance required for credit card data")
            
            if len(pii_counts) > 5:
                recommendations.append("Consider data segregation strategies")
            
            if not recommendations:
                recommendations.append("Continue monitoring for privacy risks")
        
        except Exception as e:
            logger.warning(f"Recommendation generation failed: {e}")
        
        return recommendations


class EnhancedSpacyModel:
    """Enhanced spaCy model with custom components and management."""
    
    def __init__(
        self,
        model_name: str,
        language: str = "en",
        enable_custom_components: bool = True,
        custom_patterns: Optional[List[CustomEntityPattern]] = None
    ):
        self.model_name = model_name
        self.language = language
        self.enable_custom_components = enable_custom_components
        self.custom_patterns = custom_patterns or []
        
        self.nlp: Optional[Language] = None
        self.model_info: Optional[ModelInfo] = None
        self.is_loaded = False
        
        # Performance tracking
        self.usage_stats = {
            "total_documents": 0,
            "total_tokens": 0,
            "average_processing_time": 0.0,
            "last_used": None
        }
        
        self.settings = get_settings()
        
    def load(self, disable_components: Optional[List[str]] = None) -> bool:
        """Load the spaCy model with custom components."""
        try:
            start_time = time.time()
            
            # Load base model
            self.nlp = spacy.load(self.model_name)
            
            # Disable components if specified
            if disable_components:
                for component in disable_components:
                    if self.nlp.has_pipe(component):
                        self.nlp.disable_pipe(component)
            
            # Add custom components if enabled
            if self.enable_custom_components:
                self._add_custom_components()
            
            # Add custom entity patterns
            if self.custom_patterns:
                self._add_custom_patterns()
            
            # Gather model information
            self._gather_model_info(time.time() - start_time)
            
            self.is_loaded = True
            logger.info(f"Enhanced spaCy model loaded: {self.model_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load enhanced spaCy model {self.model_name}: {e}")
            self.is_loaded = False
            return False
    
    def _add_custom_components(self):
        """Add custom pipeline components."""
        try:
            # Add custom PII detector
            if not self.nlp.has_pipe("custom_pii_detector"):
                pii_detector = CustomPIIDetector(self.nlp)
                self.nlp.add_pipe("custom_pii_detector", last=False)
                self.nlp.replace_pipe("custom_pii_detector", pii_detector)
            
            # Add privacy analyzer
            if not self.nlp.has_pipe("privacy_analyzer"):
                privacy_analyzer = PrivacyAnalyzer(self.nlp)
                self.nlp.add_pipe("privacy_analyzer", last=True)
                self.nlp.replace_pipe("privacy_analyzer", privacy_analyzer)
            
        except Exception as e:
            logger.error(f"Failed to add custom components: {e}")
    
    def _add_custom_patterns(self):
        """Add custom entity patterns to the model."""
        try:
            # Add entity ruler if not present
            if not self.nlp.has_pipe("entity_ruler"):
                ruler = self.nlp.add_pipe("entity_ruler", before="ner")
            else:
                ruler = self.nlp.get_pipe("entity_ruler")
            
            # Convert custom patterns to spaCy format
            spacy_patterns = []
            for pattern in self.custom_patterns:
                if isinstance(pattern.pattern, str):
                    # Regex pattern
                    spacy_pattern = {
                        "label": pattern.label,
                        "pattern": [{"TEXT": {"REGEX": pattern.pattern}}]
                    }
                else:
                    # Token pattern
                    spacy_pattern = {
                        "label": pattern.label,
                        "pattern": pattern.pattern
                    }
                
                spacy_patterns.append(spacy_pattern)
            
            ruler.add_patterns(spacy_patterns)
            logger.info(f"Added {len(spacy_patterns)} custom patterns to model")
            
        except Exception as e:
            logger.error(f"Failed to add custom patterns: {e}")
    
    def _gather_model_info(self, load_time: float):
        """Gather information about the loaded model."""
        try:
            if not self.nlp:
                return
            
            # Get model metadata
            meta = self.nlp.meta
            
            # Calculate model size (approximation)
            vocab_size = len(self.nlp.vocab)
            estimated_size = vocab_size * 0.001  # Rough estimate in MB
            
            # Determine capabilities
            capabilities = set()
            for pipe_name in self.nlp.pipe_names:
                if pipe_name == "ner":
                    capabilities.add("named_entity_recognition")
                elif pipe_name == "parser":
                    capabilities.add("dependency_parsing")
                elif pipe_name == "tagger":
                    capabilities.add("part_of_speech_tagging")
                elif pipe_name == "lemmatizer":
                    capabilities.add("lemmatization")
                elif pipe_name.startswith("custom_"):
                    capabilities.add(f"custom_{pipe_name}")
            
            self.model_info = ModelInfo(
                name=self.model_name,
                language=meta.get("lang", self.language),
                model_type=self._determine_model_type(),
                version=meta.get("version", "unknown"),
                size_mb=estimated_size,
                pipeline=self.nlp.pipe_names,
                capabilities=capabilities,
                load_time=load_time
            )
            
        except Exception as e:
            logger.warning(f"Failed to gather model info: {e}")
    
    def _determine_model_type(self) -> ModelType:
        """Determine the type of the loaded model."""
        model_name_lower = self.model_name.lower()
        
        if "trf" in model_name_lower:
            return ModelType.TRANSFORMER
        elif "lg" in model_name_lower:
            return ModelType.LARGE
        elif "md" in model_name_lower:
            return ModelType.MEDIUM
        else:
            return ModelType.SMALL
    
    def process(self, text: str) -> Doc:
        """Process text with the enhanced model."""
        if not self.is_loaded:
            raise RuntimeError("Model not loaded. Call load() first.")
        
        try:
            start_time = time.time()
            doc = self.nlp(text)
            processing_time = time.time() - start_time
            
            # Update usage statistics
            self._update_usage_stats(len(doc), processing_time)
            
            return doc
            
        except Exception as e:
            logger.error(f"Text processing failed: {e}")
            raise
    
    def process_batch(self, texts: List[str], batch_size: int = 32) -> List[Doc]:
        """Process multiple texts in batch for efficiency."""
        if not self.is_loaded:
            raise RuntimeError("Model not loaded. Call load() first.")
        
        try:
            start_time = time.time()
            docs = list(self.nlp.pipe(texts, batch_size=batch_size))
            processing_time = time.time() - start_time
            
            # Update usage statistics
            total_tokens = sum(len(doc) for doc in docs)
            self._update_usage_stats(total_tokens, processing_time)
            
            return docs
            
        except Exception as e:
            logger.error(f"Batch processing failed: {e}")
            raise
    
    def _update_usage_stats(self, token_count: int, processing_time: float):
        """Update model usage statistics."""
        try:
            self.usage_stats["total_documents"] += 1
            self.usage_stats["total_tokens"] += token_count
            self.usage_stats["last_used"] = time.time()
            
            # Update average processing time
            total_time = (
                self.usage_stats["average_processing_time"] * 
                (self.usage_stats["total_documents"] - 1) + processing_time
            )
            self.usage_stats["average_processing_time"] = total_time / self.usage_stats["total_documents"]
            
        except Exception as e:
            logger.warning(f"Failed to update usage stats: {e}")
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get comprehensive model information."""
        info = {
            "model_name": self.model_name,
            "language": self.language,
            "is_loaded": self.is_loaded,
            "usage_stats": self.usage_stats.copy()
        }
        
        if self.model_info:
            info.update({
                "model_type": self.model_info.model_type.value,
                "version": self.model_info.version,
                "pipeline": self.model_info.pipeline,
                "capabilities": list(self.model_info.capabilities),
                "load_time": self.model_info.load_time
            })
        
        return info
    
    def unload(self):
        """Unload the model to free memory."""
        if self.nlp:
            self.nlp = None
        
        self.model_info = None
        self.is_loaded = False
        logger.info(f"Enhanced spaCy model unloaded: {self.model_name}")


class SpacyModelManager:
    """Manager for multiple enhanced spaCy models."""
    
    def __init__(self, max_loaded_models: int = 3):
        self.max_loaded_models = max_loaded_models
        self.models: Dict[str, EnhancedSpacyModel] = {}
        self.model_priority: List[str] = []  # LRU ordering
        
        # Default model configurations
        self.default_models = {
            "en": ["en_core_web_sm", "en_core_web_md", "en_core_web_lg"],
            "es": ["es_core_news_sm", "es_core_news_md", "es_core_news_lg"],
            "fr": ["fr_core_news_sm", "fr_core_news_md", "fr_core_news_lg"],
            "de": ["de_core_news_sm", "de_core_news_md", "de_core_news_lg"]
        }
        
    def get_model(
        self,
        model_name: str = None,
        language: str = "en",
        enable_custom_components: bool = True,
        custom_patterns: Optional[List[CustomEntityPattern]] = None
    ) -> Optional[EnhancedSpacyModel]:
        """Get or create an enhanced spaCy model."""
        
        # Determine model name
        if not model_name:
            model_name = self._get_default_model(language)
        
        # Check if model already exists
        if model_name in self.models:
            model = self.models[model_name]
            self._update_priority(model_name)
            
            if not model.is_loaded:
                if not model.load():
                    return None
            
            return model
        
        # Create new model
        try:
            model = EnhancedSpacyModel(
                model_name=model_name,
                language=language,
                enable_custom_components=enable_custom_components,
                custom_patterns=custom_patterns
            )
            
            # Load model
            if not model.load():
                return None
            
            # Manage memory by unloading least used models
            self._manage_memory(model_name)
            
            # Add to manager
            self.models[model_name] = model
            self.model_priority.append(model_name)
            
            return model
            
        except Exception as e:
            logger.error(f"Failed to create enhanced spaCy model: {e}")
            return None
    
    def _get_default_model(self, language: str) -> str:
        """Get default model name for language."""
        if language in self.default_models:
            # Try models in order of preference
            for model_name in self.default_models[language]:
                if self._is_model_available(model_name):
                    return model_name
        
        # Fallback to small English model
        return "en_core_web_sm"
    
    def _is_model_available(self, model_name: str) -> bool:
        """Check if a spaCy model is available."""
        try:
            return util.is_package(model_name)
        except Exception:
            return False
    
    def _manage_memory(self, new_model_name: str):
        """Manage memory by unloading least used models."""
        if len(self.models) >= self.max_loaded_models:
            # Find least recently used model
            for model_name in self.model_priority:
                if model_name != new_model_name:
                    model = self.models[model_name]
                    if model.is_loaded:
                        model.unload()
                        logger.info(f"Unloaded model {model_name} to free memory")
                        break
    
    def _update_priority(self, model_name: str):
        """Update model priority (move to end of list)."""
        if model_name in self.model_priority:
            self.model_priority.remove(model_name)
        self.model_priority.append(model_name)
    
    def get_model_info(self, model_name: str = None) -> Dict[str, Any]:
        """Get information about models."""
        if model_name:
            if model_name in self.models:
                return self.models[model_name].get_model_info()
            else:
                return {"error": f"Model {model_name} not found"}
        
        # Return info for all models
        info = {
            "total_models": len(self.models),
            "loaded_models": sum(1 for m in self.models.values() if m.is_loaded),
            "max_loaded_models": self.max_loaded_models,
            "models": {}
        }
        
        for name, model in self.models.items():
            info["models"][name] = model.get_model_info()
        
        return info
    
    def cleanup(self):
        """Clean up all models."""
        for model in self.models.values():
            if model.is_loaded:
                model.unload()
        
        self.models.clear()
        self.model_priority.clear()
        logger.info("SpacyModelManager cleanup completed")


# Factory functions
def create_enhanced_spacy_model(
    model_name: str,
    language: str = "en",
    enable_custom_components: bool = True,
    custom_patterns: Optional[List[CustomEntityPattern]] = None
) -> EnhancedSpacyModel:
    """Create an enhanced spaCy model."""
    return EnhancedSpacyModel(
        model_name=model_name,
        language=language,
        enable_custom_components=enable_custom_components,
        custom_patterns=custom_patterns
    )


def create_model_manager(max_loaded_models: int = 3) -> SpacyModelManager:
    """Create a spaCy model manager."""
    return SpacyModelManager(max_loaded_models=max_loaded_models)


# Global model manager instance
_global_model_manager: Optional[SpacyModelManager] = None


def get_model_manager() -> SpacyModelManager:
    """Get the global model manager instance."""
    global _global_model_manager
    if _global_model_manager is None:
        _global_model_manager = create_model_manager()
    return _global_model_manager