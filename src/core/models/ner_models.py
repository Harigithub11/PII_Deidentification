"""
Named Entity Recognition (NER) Models for PII De-identification System

This module provides NER models for detecting PII entities using Microsoft Presidio
and spaCy, with support for multiple languages and custom entity recognition.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import spacy
from spacy import Language

# Presidio imports
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, EntityRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import RecognizerResult, OperatorConfig

from ..config.settings import get_settings
from ..config.policies.base import PIIType, RedactionMethod

logger = logging.getLogger(__name__)
settings = get_settings()


class EntityConfidence(str, Enum):
    """Confidence levels for entity detection."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass
class PIIEntity:
    """Detected PII entity with metadata."""
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float
    confidence_level: EntityConfidence
    recognizer_name: str
    language: str = "en"
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        
        # Set confidence level based on score
        if self.confidence >= 0.9:
            self.confidence_level = EntityConfidence.VERY_HIGH
        elif self.confidence >= 0.7:
            self.confidence_level = EntityConfidence.HIGH
        elif self.confidence >= 0.5:
            self.confidence_level = EntityConfidence.MEDIUM
        else:
            self.confidence_level = EntityConfidence.LOW


class NERModel(ABC):
    """Abstract base class for Named Entity Recognition models."""
    
    def __init__(self, model_name: str, language: str = "en"):
        self.model_name = model_name
        self.language = language
        self.is_loaded = False
        
    @abstractmethod
    def load(self) -> bool:
        """Load the NER model."""
        pass
    
    @abstractmethod
    def unload(self):
        """Unload the model to free memory."""
        pass
    
    @abstractmethod
    def detect_entities(
        self, 
        text: str, 
        language: Optional[str] = None,
        entities: Optional[List[str]] = None
    ) -> List[PIIEntity]:
        """Detect PII entities in text."""
        pass
    
    @abstractmethod
    def get_supported_entities(self) -> List[str]:
        """Get list of supported entity types."""
        pass


class PresidioNERModel(NERModel):
    """Microsoft Presidio-based NER model for PII detection."""
    
    def __init__(
        self, 
        language: str = "en",
        model_name: str = "en_core_web_sm",
        custom_recognizers: Optional[List[EntityRecognizer]] = None
    ):
        super().__init__(f"presidio_{model_name}", language)
        
        self.spacy_model_name = model_name
        self.custom_recognizers = custom_recognizers or []
        self.analyzer_engine: Optional[AnalyzerEngine] = None
        self.anonymizer_engine: Optional[AnonymizerEngine] = None
        self.nlp_engine = None
        
        # Entity type mapping from Presidio to our PIIType enum
        self.entity_mapping = {
            "PERSON": PIIType.NAME,
            "EMAIL_ADDRESS": PIIType.EMAIL,
            "PHONE_NUMBER": PIIType.PHONE,
            "SSN": PIIType.SSN,
            "CREDIT_CARD": PIIType.CREDIT_CARD,
            "US_PASSPORT": PIIType.PASSPORT,
            "US_DRIVER_LICENSE": PIIType.DRIVER_LICENSE,
            "DATE_TIME": PIIType.DATE_OF_BIRTH,
            "LOCATION": PIIType.ADDRESS,
            "IBAN_CODE": PIIType.BANK_ACCOUNT,
            "IP_ADDRESS": PIIType.IP_ADDRESS,
            "URL": PIIType.URL,
            "MEDICAL_LICENSE": PIIType.MEDICAL_LICENSE,
            "US_BANK_NUMBER": PIIType.BANK_ACCOUNT,
            "CRYPTO": PIIType.CRYPTO_ADDRESS
        }
        
        logger.info(f"Initialized PresidioNERModel with language: {language}")
    
    def load(self) -> bool:
        """Load Presidio analyzer and anonymizer engines."""
        try:
            # Setup NLP engine with spaCy
            nlp_configuration = {
                "nlp_engine_name": "spacy",
                "models": [
                    {
                        "lang_code": self.language,
                        "model_name": self.spacy_model_name
                    }
                ]
            }
            
            nlp_engine_provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
            self.nlp_engine = nlp_engine_provider.create_engine()
            
            # Create analyzer engine
            self.analyzer_engine = AnalyzerEngine(
                nlp_engine=self.nlp_engine,
                supported_languages=[self.language]
            )
            
            # Add custom recognizers if any
            registry = RecognizerRegistry()
            for recognizer in self.custom_recognizers:
                registry.add_recognizer(recognizer)
                self.analyzer_engine.registry = registry
            
            # Create anonymizer engine
            self.anonymizer_engine = AnonymizerEngine()
            
            self.is_loaded = True
            logger.info(f"Successfully loaded PresidioNERModel for language: {self.language}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load PresidioNERModel: {e}")
            self.is_loaded = False
            return False
    
    def unload(self):
        """Unload the model to free memory."""
        if self.analyzer_engine:
            self.analyzer_engine = None
        if self.anonymizer_engine:
            self.anonymizer_engine = None
        if self.nlp_engine:
            self.nlp_engine = None
        
        self.is_loaded = False
        logger.info("Unloaded PresidioNERModel")
    
    def detect_entities(
        self, 
        text: str, 
        language: Optional[str] = None,
        entities: Optional[List[str]] = None
    ) -> List[PIIEntity]:
        """Detect PII entities using Presidio analyzer."""
        if not self.is_loaded:
            raise RuntimeError("Model not loaded. Call load() first.")
        
        if not text.strip():
            return []
        
        try:
            # Use provided language or default
            detect_language = language or self.language
            
            # Analyze text with Presidio
            results = self.analyzer_engine.analyze(
                text=text,
                language=detect_language,
                entities=entities,
                return_decision_process=False,
                ad_hoc_recognizers=None,
                context=None,
                allow_list=None,
                deny_list=None
            )
            
            # Convert Presidio results to our PIIEntity format
            pii_entities = []
            for result in results:
                entity_type = self._map_entity_type(result.entity_type)
                
                pii_entity = PIIEntity(
                    entity_type=entity_type,
                    text=text[result.start:result.end],
                    start=result.start,
                    end=result.end,
                    confidence=result.score,
                    confidence_level=EntityConfidence.LOW,  # Will be set in __post_init__
                    recognizer_name=result.recognition_metadata.get("recognizer_name", "presidio"),
                    language=detect_language,
                    metadata={
                        "presidio_entity_type": result.entity_type,
                        "recognition_metadata": result.recognition_metadata
                    }
                )
                
                pii_entities.append(pii_entity)
            
            logger.debug(f"Detected {len(pii_entities)} PII entities in text of length {len(text)}")
            return pii_entities
            
        except Exception as e:
            logger.error(f"Error detecting entities: {e}")
            return []
    
    def anonymize_text(
        self,
        text: str,
        entities: List[PIIEntity],
        anonymize_config: Optional[Dict[str, OperatorConfig]] = None
    ) -> str:
        """Anonymize text by replacing detected PII entities."""
        if not self.is_loaded:
            raise RuntimeError("Model not loaded. Call load() first.")
        
        try:
            # Convert our PIIEntity objects to Presidio RecognizerResult format
            presidio_results = []
            for entity in entities:
                presidio_result = RecognizerResult(
                    entity_type=entity.metadata.get("presidio_entity_type", entity.entity_type),
                    start=entity.start,
                    end=entity.end,
                    score=entity.confidence
                )
                presidio_results.append(presidio_result)
            
            # Default anonymization configuration
            default_config = anonymize_config or {
                "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
                "PERSON": OperatorConfig("replace", {"new_value": "[PERSON]"}),
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "[EMAIL]"}),
                "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "[PHONE]"}),
                "SSN": OperatorConfig("replace", {"new_value": "[SSN]"}),
                "CREDIT_CARD": OperatorConfig("replace", {"new_value": "[CREDIT_CARD]"})
            }
            
            # Anonymize text
            anonymized_result = self.anonymizer_engine.anonymize(
                text=text,
                analyzer_results=presidio_results,
                operators=default_config
            )
            
            return anonymized_result.text
            
        except Exception as e:
            logger.error(f"Error anonymizing text: {e}")
            return text
    
    def get_supported_entities(self) -> List[str]:
        """Get list of supported entity types."""
        if not self.is_loaded:
            return list(self.entity_mapping.keys())
        
        try:
            supported = self.analyzer_engine.get_supported_entities(language=self.language)
            return supported
        except Exception as e:
            logger.error(f"Error getting supported entities: {e}")
            return list(self.entity_mapping.keys())
    
    def _map_entity_type(self, presidio_entity_type: str) -> str:
        """Map Presidio entity type to our PIIType enum."""
        return self.entity_mapping.get(presidio_entity_type, presidio_entity_type)
    
    def add_custom_recognizer(self, recognizer: EntityRecognizer):
        """Add a custom entity recognizer."""
        self.custom_recognizers.append(recognizer)
        
        if self.analyzer_engine:
            registry = RecognizerRegistry()
            for rec in self.custom_recognizers:
                registry.add_recognizer(rec)
            self.analyzer_engine.registry = registry
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information and statistics."""
        return {
            "model_name": self.model_name,
            "language": self.language,
            "is_loaded": self.is_loaded,
            "spacy_model": self.spacy_model_name,
            "custom_recognizers": len(self.custom_recognizers),
            "supported_entities": len(self.get_supported_entities())
        }


class SpacyNERModel(NERModel):
    """spaCy-based NER model as fallback option."""
    
    def __init__(self, model_name: str = "en_core_web_sm", language: str = "en"):
        super().__init__(f"spacy_{model_name}", language)
        self.spacy_model_name = model_name
        self.nlp: Optional[Language] = None
        
        # Basic entity type mapping for spaCy
        self.entity_mapping = {
            "PERSON": PIIType.NAME,
            "ORG": PIIType.ORGANIZATION,
            "GPE": PIIType.ADDRESS,  # Geo-political entities
            "DATE": PIIType.DATE_OF_BIRTH,
            "TIME": PIIType.DATE_OF_BIRTH,
            "MONEY": PIIType.FINANCIAL,
            "CARDINAL": PIIType.NUMBER,
            "ORDINAL": PIIType.NUMBER
        }
    
    def load(self) -> bool:
        """Load spaCy model."""
        try:
            self.nlp = spacy.load(self.spacy_model_name)
            self.is_loaded = True
            logger.info(f"Successfully loaded spaCy model: {self.spacy_model_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to load spaCy model {self.spacy_model_name}: {e}")
            self.is_loaded = False
            return False
    
    def unload(self):
        """Unload spaCy model."""
        if self.nlp:
            self.nlp = None
        self.is_loaded = False
        logger.info("Unloaded spaCy model")
    
    def detect_entities(
        self, 
        text: str, 
        language: Optional[str] = None,
        entities: Optional[List[str]] = None
    ) -> List[PIIEntity]:
        """Detect entities using spaCy NER."""
        if not self.is_loaded:
            raise RuntimeError("Model not loaded. Call load() first.")
        
        if not text.strip():
            return []
        
        try:
            doc = self.nlp(text)
            pii_entities = []
            
            for ent in doc.ents:
                entity_type = self._map_entity_type(ent.label_)
                
                # Filter by requested entities if specified
                if entities and entity_type not in entities:
                    continue
                
                pii_entity = PIIEntity(
                    entity_type=entity_type,
                    text=ent.text,
                    start=ent.start_char,
                    end=ent.end_char,
                    confidence=0.8,  # spaCy doesn't provide confidence scores by default
                    confidence_level=EntityConfidence.HIGH,
                    recognizer_name="spacy",
                    language=language or self.language,
                    metadata={
                        "spacy_label": ent.label_,
                        "spacy_label_desc": spacy.explain(ent.label_)
                    }
                )
                
                pii_entities.append(pii_entity)
            
            return pii_entities
            
        except Exception as e:
            logger.error(f"Error detecting entities with spaCy: {e}")
            return []
    
    def get_supported_entities(self) -> List[str]:
        """Get supported entity types."""
        return list(self.entity_mapping.keys())
    
    def _map_entity_type(self, spacy_label: str) -> str:
        """Map spaCy entity label to our PIIType."""
        return self.entity_mapping.get(spacy_label, spacy_label)


# Factory function for creating NER models
def create_ner_model(
    model_type: str = "presidio",
    language: str = "en",
    model_name: Optional[str] = None,
    **kwargs
) -> NERModel:
    """Factory function to create NER model instances."""
    
    if model_type.lower() == "presidio":
        spacy_model = model_name or "en_core_web_sm"
        return PresidioNERModel(
            language=language,
            model_name=spacy_model,
            custom_recognizers=kwargs.get("custom_recognizers")
        )
    elif model_type.lower() == "spacy":
        spacy_model = model_name or "en_core_web_sm"
        return SpacyNERModel(
            model_name=spacy_model,
            language=language
        )
    else:
        raise ValueError(f"Unsupported model type: {model_type}")


# Default model instance
_default_ner_model = None

def get_default_ner_model() -> PresidioNERModel:
    """Get or create the default NER model instance."""
    global _default_ner_model
    
    if _default_ner_model is None:
        _default_ner_model = create_ner_model("presidio")
        if not _default_ner_model.load():
            logger.warning("Failed to load default Presidio model, trying spaCy fallback")
            _default_ner_model = create_ner_model("spacy")
            _default_ner_model.load()
    
    return _default_ner_model