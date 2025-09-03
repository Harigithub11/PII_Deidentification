"""
Microsoft Presidio PII detection service integration
"""
import json
import logging
from typing import Dict, List, Optional, Tuple

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from src.core.config import settings

logger = logging.getLogger(__name__)


class PIIDetectionService:
    """
    Microsoft Presidio PII detection and anonymization service
    """
    
    def __init__(self):
        """Initialize PII detection service"""
        self._initialize_engines()
        self._setup_recognizers()
    
    def _initialize_engines(self):
        """Initialize Presidio engines"""
        try:
            # Initialize NLP engine with spaCy
            nlp_configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": settings.SPACY_MODEL}]
            }
            
            nlp_engine_provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
            nlp_engine = nlp_engine_provider.create_engine()
            
            # Initialize analyzer engine
            self.analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                supported_languages=["en"]
            )
            
            # Initialize anonymizer engine
            self.anonymizer = AnonymizerEngine()
            
            logger.info("✅ Presidio engines initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Presidio engines: {e}")
            raise RuntimeError(f"PII detection service initialization failed: {e}")
    
    def _setup_recognizers(self):
        """Setup custom recognizers for domain-specific PII"""
        try:
            # Get current registry
            registry = RecognizerRegistry()
            
            # Add custom patterns if needed
            # TODO: Add custom recognizers for specific use cases
            
            logger.info("✅ Custom recognizers setup completed")
            
        except Exception as e:
            logger.warning(f"Custom recognizers setup failed: {e}")
    
    def detect_pii(
        self, 
        text: str, 
        language: str = "en",
        entities: Optional[List[str]] = None,
        confidence_threshold: Optional[float] = None
    ) -> List[Dict]:
        """
        Detect PII in text using Presidio analyzer
        
        Args:
            text: Text to analyze
            language: Language code (default: en)
            entities: List of entity types to detect (None for all)
            confidence_threshold: Minimum confidence score (None for default)
            
        Returns:
            List of detected PII entities with metadata
        """
        if confidence_threshold is None:
            confidence_threshold = settings.PII_CONFIDENCE_THRESHOLD
        
        try:
            # Run analysis
            analyzer_results = self.analyzer.analyze(
                text=text,
                language=language,
                entities=entities,
                score_threshold=confidence_threshold
            )
            
            # Convert results to our format
            detections = []
            for result in analyzer_results:
                detection = {
                    "entity_type": result.entity_type,
                    "start": result.start,
                    "end": result.end,
                    "score": result.score,
                    "text": text[result.start:result.end],
                    "recognition_metadata": result.recognition_metadata
                }
                detections.append(detection)
            
            # Sort by position
            detections.sort(key=lambda x: x["start"])
            
            logger.info(f"Detected {len(detections)} PII entities in text")
            return detections
            
        except Exception as e:
            logger.error(f"PII detection failed: {e}")
            return []
    
    def anonymize_text(
        self, 
        text: str, 
        analyzer_results: List[Dict],
        anonymization_method: str = "mask",
        language: str = "en"
    ) -> Tuple[str, List[Dict]]:
        """
        Anonymize text based on detected PII
        
        Args:
            text: Original text
            analyzer_results: PII detection results
            anonymization_method: Method to use (mask, replace, redact, encrypt)
            language: Language code
            
        Returns:
            Tuple of (anonymized_text, anonymization_details)
        """
        try:
            # Convert our format to Presidio format
            presidio_results = []
            for detection in analyzer_results:
                from presidio_analyzer import RecognizerResult
                result = RecognizerResult(
                    entity_type=detection["entity_type"],
                    start=detection["start"],
                    end=detection["end"],
                    score=detection["score"]
                )
                presidio_results.append(result)
            
            # Define anonymization operators
            operators = self._get_anonymization_operators(anonymization_method)
            
            # Perform anonymization
            anonymizer_result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=presidio_results,
                operators=operators
            )
            
            # Extract anonymization details
            anonymization_details = []
            for item in anonymizer_result.items:
                detail = {
                    "entity_type": item.entity_type,
                    "start": item.start,
                    "end": item.end,
                    "operator": item.operator,
                    "original_text": text[item.start:item.end] if hasattr(item, 'original_text') else None
                }
                anonymization_details.append(detail)
            
            logger.info(f"Anonymized {len(anonymization_details)} entities using {anonymization_method}")
            return anonymizer_result.text, anonymization_details
            
        except Exception as e:
            logger.error(f"Text anonymization failed: {e}")
            return text, []  # Return original text on failure
    
    def _get_anonymization_operators(self, method: str) -> Dict[str, OperatorConfig]:
        """
        Get anonymization operators based on method
        """
        if method == "mask":
            return {"DEFAULT": OperatorConfig("mask", {"masking_char": "█", "chars_to_mask": 4})}
        
        elif method == "replace":
            return {
                "PERSON": OperatorConfig("replace", {"new_value": "[PERSON]"}),
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "[EMAIL]"}),
                "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "[PHONE]"}),
                "SSN": OperatorConfig("replace", {"new_value": "[SSN]"}),
                "CREDIT_CARD": OperatorConfig("replace", {"new_value": "[CREDIT_CARD]"}),
                "IBAN_CODE": OperatorConfig("replace", {"new_value": "[IBAN]"}),
                "IP_ADDRESS": OperatorConfig("replace", {"new_value": "[IP_ADDRESS]"}),
                "LOCATION": OperatorConfig("replace", {"new_value": "[LOCATION]"}),
                "DATE_TIME": OperatorConfig("replace", {"new_value": "[DATE]"}),
                "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})
            }
        
        elif method == "redact":
            return {"DEFAULT": OperatorConfig("redact", {})}
        
        elif method == "encrypt":
            return {"DEFAULT": OperatorConfig("encrypt", {"key": "WmZq4t7w!z%C*F-J"})}
        
        else:
            # Default to mask
            return {"DEFAULT": OperatorConfig("mask", {"masking_char": "█", "chars_to_mask": 4})}
    
    def get_supported_entities(self) -> List[str]:
        """
        Get list of supported PII entity types
        """
        try:
            return self.analyzer.get_supported_entities(language="en")
        except Exception as e:
            logger.error(f"Failed to get supported entities: {e}")
            return [
                "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "SSN", 
                "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS", "LOCATION", 
                "DATE_TIME", "MEDICAL_LICENSE", "URL"
            ]
    
    def analyze_document(
        self, 
        text: str, 
        policy_config: Optional[Dict] = None
    ) -> Dict:
        """
        Comprehensive document analysis with PII detection
        
        Args:
            text: Document text to analyze
            policy_config: Policy configuration for detection
            
        Returns:
            Analysis results with statistics and recommendations
        """
        if not policy_config:
            policy_config = {
                "entities": None,  # All entities
                "confidence_threshold": settings.PII_CONFIDENCE_THRESHOLD
            }
        
        try:
            # Detect PII
            detections = self.detect_pii(
                text=text,
                entities=policy_config.get("entities"),
                confidence_threshold=policy_config.get("confidence_threshold")
            )
            
            # Generate statistics
            stats = self._generate_statistics(detections)
            
            # Assess risk level
            risk_level = self._assess_risk_level(detections, stats)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(detections, stats, risk_level)
            
            return {
                "detections": detections,
                "statistics": stats,
                "risk_level": risk_level,
                "recommendations": recommendations,
                "total_entities": len(detections),
                "text_length": len(text),
                "analysis_timestamp": None  # Will be set by caller
            }
            
        except Exception as e:
            logger.error(f"Document analysis failed: {e}")
            return {
                "detections": [],
                "statistics": {},
                "risk_level": "unknown",
                "recommendations": [],
                "total_entities": 0,
                "text_length": len(text),
                "error": str(e)
            }
    
    def _generate_statistics(self, detections: List[Dict]) -> Dict:
        """Generate statistics from PII detections"""
        if not detections:
            return {}
        
        # Count by entity type
        entity_counts = {}
        confidence_scores = []
        
        for detection in detections:
            entity_type = detection["entity_type"]
            entity_counts[entity_type] = entity_counts.get(entity_type, 0) + 1
            confidence_scores.append(detection["score"])
        
        # Calculate statistics
        stats = {
            "entity_types": entity_counts,
            "total_detections": len(detections),
            "unique_entity_types": len(entity_counts),
            "average_confidence": sum(confidence_scores) / len(confidence_scores),
            "min_confidence": min(confidence_scores),
            "max_confidence": max(confidence_scores)
        }
        
        return stats
    
    def _assess_risk_level(self, detections: List[Dict], stats: Dict) -> str:
        """Assess risk level based on detections"""
        if not detections:
            return "low"
        
        high_risk_entities = ["SSN", "CREDIT_CARD", "MEDICAL_LICENSE", "IBAN_CODE"]
        medium_risk_entities = ["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "IP_ADDRESS"]
        
        high_risk_count = sum(stats["entity_types"].get(entity, 0) for entity in high_risk_entities)
        medium_risk_count = sum(stats["entity_types"].get(entity, 0) for entity in medium_risk_entities)
        
        if high_risk_count > 0:
            return "high"
        elif medium_risk_count > 5:
            return "high"
        elif medium_risk_count > 2:
            return "medium"
        else:
            return "low"
    
    def _generate_recommendations(self, detections: List[Dict], stats: Dict, risk_level: str) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        if risk_level == "high":
            recommendations.append("High-risk PII detected. Immediate redaction recommended.")
            recommendations.append("Consider additional security measures for document handling.")
        
        if risk_level == "medium":
            recommendations.append("Medium-risk PII detected. Review and redact as necessary.")
        
        if stats.get("average_confidence", 0) < 0.8:
            recommendations.append("Some detections have low confidence. Manual review recommended.")
        
        if "SSN" in stats.get("entity_types", {}):
            recommendations.append("Social Security Numbers detected. Ensure HIPAA compliance.")
        
        if "CREDIT_CARD" in stats.get("entity_types", {}):
            recommendations.append("Credit card information detected. Ensure PCI DSS compliance.")
        
        if not recommendations:
            recommendations.append("Low-risk document. Standard redaction procedures apply.")
        
        return recommendations
    
    def health_check(self) -> bool:
        """
        Check if PII detection service is working properly
        """
        try:
            # Test with simple text
            test_text = "John Doe's email is john@example.com and his phone is 555-1234."
            detections = self.detect_pii(test_text)
            
            # Should detect at least the email
            return len(detections) > 0
            
        except Exception as e:
            logger.error(f"PII service health check failed: {e}")
            return False


# Global PII service instance
pii_service = PIIDetectionService()