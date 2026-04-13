"""
Unified Redaction Engine

This module provides a comprehensive redaction system that handles text, visual, and document
redaction through a unified interface. It supports multiple redaction methods and integrates
with the policy engine for intelligent redaction decisions.
"""

import logging
import asyncio
import hashlib
import secrets
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import numpy as np
from PIL import Image
import cv2

from ..config.policies.base import RedactionMethod, PIIType
from ..config.policy_models import (
    PolicyContext, PolicyDecision, PolicyDecisionType
)
from ..models.ner_models import PIIEntity
from ..models.visual_models import VisualPIIEntity, BoundingBox
from ..processing.visual_redactor import (
    VisualRedactionEngine, RedactionConfig, 
    VisualRedactionMethod, get_visual_redaction_engine
)
from ..security.encryption import encryption_manager
from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class RedactionType(str, Enum):
    """Types of content that can be redacted."""
    TEXT = "text"
    VISUAL = "visual"
    DOCUMENT = "document"
    HYBRID = "hybrid"


class RedactionIntensity(str, Enum):
    """Intensity levels for redaction methods."""
    LOW = "low"           # Minimal redaction
    MEDIUM = "medium"     # Standard redaction
    HIGH = "high"         # Strong redaction
    MAXIMUM = "maximum"   # Complete redaction


@dataclass
class RedactionParameters:
    """Configuration parameters for redaction methods."""
    method: RedactionMethod
    intensity: RedactionIntensity = RedactionIntensity.MEDIUM
    preserve_format: bool = True
    preserve_length: bool = False
    custom_placeholder: Optional[str] = None
    color: Tuple[int, int, int] = (0, 0, 0)
    pattern: Optional[str] = None
    encryption_key: Optional[str] = None
    pseudonym_seed: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RedactionRequest:
    """Request for redaction operation."""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    redaction_type: RedactionType = RedactionType.TEXT
    content: Any = None  # Text string, image array, or document path
    entities: List[Union[PIIEntity, VisualPIIEntity]] = field(default_factory=list)
    parameters: RedactionParameters = field(default_factory=lambda: RedactionParameters(RedactionMethod.REDACTED_LABEL))
    policy_context: Optional[PolicyContext] = None
    preserve_original: bool = True
    audit_enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class RedactionResult:
    """Result of redaction operation."""
    request_id: str
    success: bool
    redacted_content: Optional[Any] = None
    original_content: Optional[Any] = None
    entities_redacted: List[Union[PIIEntity, VisualPIIEntity]] = field(default_factory=list)
    method_used: Optional[RedactionMethod] = None
    processing_time_seconds: float = 0.0
    quality_score: float = 1.0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    audit_log_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)


class TextRedactor:
    """Text redaction methods implementation."""
    
    def __init__(self):
        self.pseudonym_cache = {}
        logger.debug("Initialized TextRedactor")
    
    def redact_text(
        self, 
        text: str, 
        entities: List[PIIEntity], 
        parameters: RedactionParameters
    ) -> str:
        """Apply text redaction to entities in text."""
        if not text or not entities:
            return text
        
        # Sort entities by start position in reverse order to avoid position shifts
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        
        redacted_text = text
        for entity in sorted_entities:
            try:
                redacted_value = self._apply_text_method(
                    entity.text, entity.entity_type, parameters
                )
                redacted_text = (
                    redacted_text[:entity.start] + 
                    redacted_value + 
                    redacted_text[entity.end:]
                )
            except Exception as e:
                logger.error(f"Error redacting entity {entity}: {e}")
                continue
        
        return redacted_text
    
    def _apply_text_method(
        self, 
        text: str, 
        pii_type: PIIType, 
        parameters: RedactionParameters
    ) -> str:
        """Apply specific redaction method to text."""
        method = parameters.method
        
        if method == RedactionMethod.DELETE:
            return ""
        
        elif method == RedactionMethod.MASK_ASTERISK:
            if parameters.preserve_length:
                return "*" * len(text)
            else:
                return "***"
        
        elif method == RedactionMethod.MASK_X:
            if parameters.preserve_length:
                return "X" * len(text)
            else:
                return "XXX"
        
        elif method == RedactionMethod.MASK_HASH:
            if parameters.preserve_length:
                return "#" * len(text)
            else:
                return "###"
        
        elif method == RedactionMethod.REDACTED_LABEL:
            return "[REDACTED]"
        
        elif method == RedactionMethod.PLACEHOLDER:
            if parameters.custom_placeholder:
                return parameters.custom_placeholder
            return f"[{pii_type.value.upper()}]"
        
        elif method == RedactionMethod.PARTIAL_MASK:
            return self._partial_mask(text, parameters.intensity)
        
        elif method == RedactionMethod.WHITESPACE:
            if parameters.preserve_length:
                return " " * len(text)
            else:
                return "   "
        
        elif method == RedactionMethod.HASH:
            return self._hash_text(text, parameters)
        
        elif method == RedactionMethod.ENCRYPT:
            return self._encrypt_text(text, parameters)
        
        elif method == RedactionMethod.PSEUDONYMIZE:
            return self._pseudonymize_text(text, pii_type, parameters)
        
        elif method == RedactionMethod.GENERALIZE:
            return self._generalize_text(text, pii_type, parameters)
        
        else:
            logger.warning(f"Unsupported text redaction method: {method}")
            return "[REDACTED]"
    
    def _partial_mask(self, text: str, intensity: RedactionIntensity) -> str:
        """Apply partial masking based on intensity."""
        if len(text) <= 2:
            return "*" * len(text)
        
        if intensity == RedactionIntensity.LOW:
            # Show first 2 and last 2 characters
            visible_chars = min(2, len(text) // 2)
            mask_length = max(1, len(text) - (2 * visible_chars))
            return text[:visible_chars] + "*" * mask_length + text[-visible_chars:]
        
        elif intensity == RedactionIntensity.MEDIUM:
            # Show first 1 and last 1 character
            if len(text) <= 3:
                return text[0] + "*" * (len(text) - 1)
            return text[0] + "*" * (len(text) - 2) + text[-1]
        
        else:  # HIGH or MAXIMUM
            return "*" * len(text)
    
    def _hash_text(self, text: str, parameters: RedactionParameters) -> str:
        """Create hash of text."""
        hasher = hashlib.sha256()
        hasher.update(text.encode('utf-8'))
        if parameters.pseudonym_seed:
            hasher.update(parameters.pseudonym_seed.encode('utf-8'))
        
        hash_value = hasher.hexdigest()
        if parameters.intensity == RedactionIntensity.LOW:
            return f"#{hash_value[:8]}"
        elif parameters.intensity == RedactionIntensity.MEDIUM:
            return f"#{hash_value[:16]}"
        else:
            return f"#{hash_value}"
    
    def _encrypt_text(self, text: str, parameters: RedactionParameters) -> str:
        """Encrypt text using encryption manager."""
        try:
            if encryption_manager:
                encrypted = encryption_manager.encrypt(text.encode('utf-8'))
                return f"[ENCRYPTED:{encrypted.hex()[:16]}...]"
            else:
                return "[ENCRYPTED]"
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return "[ENCRYPTED]"
    
    def _pseudonymize_text(self, text: str, pii_type: PIIType, parameters: RedactionParameters) -> str:
        """Generate consistent pseudonym for text."""
        # Create cache key
        seed = parameters.pseudonym_seed or "default"
        cache_key = f"{pii_type.value}_{text}_{seed}"
        
        if cache_key in self.pseudonym_cache:
            return self.pseudonym_cache[cache_key]
        
        # Generate pseudonym based on PII type
        pseudonym = self._generate_pseudonym(text, pii_type, seed)
        self.pseudonym_cache[cache_key] = pseudonym
        
        return pseudonym
    
    def _generate_pseudonym(self, text: str, pii_type: PIIType, seed: str) -> str:
        """Generate type-specific pseudonym."""
        # Use hash for consistent generation
        hasher = hashlib.md5()
        hasher.update(f"{text}_{seed}".encode('utf-8'))
        hash_int = int(hasher.hexdigest(), 16)
        
        if pii_type == PIIType.NAME:
            fake_names = ["Alex Johnson", "Taylor Smith", "Morgan Davis", "Casey Brown", "Jordan Wilson"]
            return fake_names[hash_int % len(fake_names)]
        
        elif pii_type == PIIType.EMAIL:
            domains = ["example.com", "test.org", "sample.net"]
            username = f"user{hash_int % 10000}"
            domain = domains[hash_int % len(domains)]
            return f"{username}@{domain}"
        
        elif pii_type == PIIType.PHONE:
            return f"555-{(hash_int % 900) + 100:03d}-{hash_int % 10000:04d}"
        
        elif pii_type in [PIIType.SSN, PIIType.NATIONAL_ID]:
            return f"{hash_int % 900 + 100:03d}-{hash_int % 100:02d}-{hash_int % 10000:04d}"
        
        else:
            return f"PSEUDO_{hash_int % 100000}"
    
    def _generalize_text(self, text: str, pii_type: PIIType, parameters: RedactionParameters) -> str:
        """Generalize text to broader category."""
        if pii_type == PIIType.AGE:
            try:
                age = int(text)
                if age < 18:
                    return "Minor"
                elif age < 65:
                    return "Adult"
                else:
                    return "Senior"
            except ValueError:
                return "Age Group"
        
        elif pii_type == PIIType.DATE_OF_BIRTH:
            return "Birth Year Range"
        
        elif pii_type == PIIType.ADDRESS:
            if parameters.intensity == RedactionIntensity.LOW:
                return "City Area"
            elif parameters.intensity == RedactionIntensity.MEDIUM:
                return "State/Province"
            else:
                return "Geographic Region"
        
        elif pii_type == PIIType.INCOME:
            return "Income Bracket"
        
        else:
            return f"{pii_type.value.replace('_', ' ').title()} Category"


class UnifiedRedactionEngine:
    """Main redaction engine that orchestrates all redaction types."""
    
    def __init__(self):
        self.text_redactor = TextRedactor()
        self.visual_redactor = get_visual_redaction_engine()
        self.processing_stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "average_processing_time": 0.0
        }
        
        logger.info("Initialized UnifiedRedactionEngine")
    
    async def redact_async(self, request: RedactionRequest) -> RedactionResult:
        """Asynchronously perform redaction based on request."""
        return await asyncio.get_event_loop().run_in_executor(
            None, self.redact, request
        )
    
    def redact(self, request: RedactionRequest) -> RedactionResult:
        """Perform redaction based on request type and parameters."""
        import time
        start_time = time.time()
        
        self.processing_stats["total_requests"] += 1
        
        try:
            if request.redaction_type == RedactionType.TEXT:
                result = self._redact_text(request)
            
            elif request.redaction_type == RedactionType.VISUAL:
                result = self._redact_visual(request)
            
            elif request.redaction_type == RedactionType.HYBRID:
                result = self._redact_hybrid(request)
            
            else:
                raise ValueError(f"Unsupported redaction type: {request.redaction_type}")
            
            result.processing_time_seconds = time.time() - start_time
            result.method_used = request.parameters.method
            
            if result.success:
                self.processing_stats["successful_requests"] += 1
                self._calculate_quality_score(result, request)
            else:
                self.processing_stats["failed_requests"] += 1
            
            self._update_processing_stats(result.processing_time_seconds)
            
            return result
            
        except Exception as e:
            logger.error(f"Redaction failed for request {request.request_id}: {e}")
            self.processing_stats["failed_requests"] += 1
            
            return RedactionResult(
                request_id=request.request_id,
                success=False,
                error_message=str(e),
                processing_time_seconds=time.time() - start_time
            )
    
    def _redact_text(self, request: RedactionRequest) -> RedactionResult:
        """Handle text redaction."""
        if not isinstance(request.content, str):
            raise ValueError("Text redaction requires string content")
        
        text_entities = [e for e in request.entities if isinstance(e, PIIEntity)]
        
        redacted_text = self.text_redactor.redact_text(
            request.content, text_entities, request.parameters
        )
        
        return RedactionResult(
            request_id=request.request_id,
            success=True,
            redacted_content=redacted_text,
            original_content=request.content if request.preserve_original else None,
            entities_redacted=text_entities,
            metadata={
                "original_length": len(request.content),
                "redacted_length": len(redacted_text),
                "entities_count": len(text_entities)
            }
        )
    
    def _redact_visual(self, request: RedactionRequest) -> RedactionResult:
        """Handle visual redaction."""
        if not isinstance(request.content, (np.ndarray, Image.Image, str, Path)):
            raise ValueError("Visual redaction requires image content")
        
        visual_entities = [e for e in request.entities if isinstance(e, VisualPIIEntity)]
        
        # Convert redaction method to visual method
        visual_method = self._convert_to_visual_method(request.parameters.method)
        
        # Create visual redaction config
        visual_config = RedactionConfig(
            method=visual_method,
            intensity=self._convert_intensity(request.parameters.intensity),
            color=request.parameters.color,
            padding=5 if request.parameters.intensity == RedactionIntensity.HIGH else 3,
            placeholder_text=request.parameters.custom_placeholder
        )
        
        # Perform visual redaction
        visual_result = self.visual_redactor.redact_image(
            request.content, visual_entities, visual_config
        )
        
        return RedactionResult(
            request_id=request.request_id,
            success=visual_result.success,
            redacted_content=visual_result.redacted_image,
            original_content=request.content if request.preserve_original else None,
            entities_redacted=visual_result.redacted_entities,
            error_message=visual_result.error_message,
            metadata={
                **visual_result.redaction_metadata,
                "visual_processing_time": visual_result.processing_time_seconds
            }
        )
    
    def _redact_hybrid(self, request: RedactionRequest) -> RedactionResult:
        """Handle hybrid text + visual redaction."""
        # Split entities by type
        text_entities = [e for e in request.entities if isinstance(e, PIIEntity)]
        visual_entities = [e for e in request.entities if isinstance(e, VisualPIIEntity)]
        
        results = []
        
        # Redact text if present
        if text_entities and hasattr(request, 'text_content'):
            text_request = RedactionRequest(
                redaction_type=RedactionType.TEXT,
                content=request.text_content,
                entities=text_entities,
                parameters=request.parameters,
                preserve_original=request.preserve_original
            )
            text_result = self._redact_text(text_request)
            results.append(text_result)
        
        # Redact visual if present
        if visual_entities:
            visual_request = RedactionRequest(
                redaction_type=RedactionType.VISUAL,
                content=request.content,
                entities=visual_entities,
                parameters=request.parameters,
                preserve_original=request.preserve_original
            )
            visual_result = self._redact_visual(visual_request)
            results.append(visual_result)
        
        # Combine results
        if not results:
            return RedactionResult(
                request_id=request.request_id,
                success=False,
                error_message="No valid entities found for hybrid redaction"
            )
        
        success = all(r.success for r in results)
        combined_metadata = {}
        for r in results:
            combined_metadata.update(r.metadata)
        
        return RedactionResult(
            request_id=request.request_id,
            success=success,
            redacted_content={
                "text": results[0].redacted_content if text_entities else None,
                "visual": results[-1].redacted_content if visual_entities else None
            },
            entities_redacted=request.entities,
            metadata=combined_metadata
        )
    
    def _convert_to_visual_method(self, method: RedactionMethod) -> VisualRedactionMethod:
        """Convert general redaction method to visual method."""
        mapping = {
            RedactionMethod.BLACKOUT: VisualRedactionMethod.BLACKOUT,
            RedactionMethod.WHITEOUT: VisualRedactionMethod.WHITEOUT,
            RedactionMethod.BLUR: VisualRedactionMethod.BLUR,
            RedactionMethod.GAUSSIAN_BLUR: VisualRedactionMethod.GAUSSIAN_BLUR,
            RedactionMethod.PIXELATE: VisualRedactionMethod.PIXELATE,
            RedactionMethod.MOSAIC: VisualRedactionMethod.MOSAIC,
            RedactionMethod.SOLID_COLOR: VisualRedactionMethod.SOLID_COLOR,
            RedactionMethod.PATTERN_FILL: VisualRedactionMethod.PATTERN_FILL,
            RedactionMethod.PLACEHOLDER: VisualRedactionMethod.REPLACE_WITH_PLACEHOLDER,
        }
        
        return mapping.get(method, VisualRedactionMethod.BLACKOUT)
    
    def _convert_intensity(self, intensity: RedactionIntensity) -> float:
        """Convert intensity enum to float value."""
        mapping = {
            RedactionIntensity.LOW: 0.3,
            RedactionIntensity.MEDIUM: 0.6,
            RedactionIntensity.HIGH: 0.8,
            RedactionIntensity.MAXIMUM: 1.0
        }
        return mapping.get(intensity, 0.6)
    
    def _calculate_quality_score(self, result: RedactionResult, request: RedactionRequest):
        """Calculate redaction quality score."""
        # Start with base score
        quality_score = 1.0
        
        # Reduce score for failed entities
        total_entities = len(request.entities)
        redacted_entities = len(result.entities_redacted)
        
        if total_entities > 0:
            entity_success_rate = redacted_entities / total_entities
            quality_score *= entity_success_rate
        
        # Consider processing time (faster is better, up to a point)
        if result.processing_time_seconds > 5.0:
            quality_score *= 0.9  # Slight penalty for slow processing
        
        result.quality_score = max(0.0, min(1.0, quality_score))
    
    def _update_processing_stats(self, processing_time: float):
        """Update running processing statistics."""
        current_avg = self.processing_stats["average_processing_time"]
        total_requests = self.processing_stats["total_requests"]
        
        if total_requests > 1:
            self.processing_stats["average_processing_time"] = (
                (current_avg * (total_requests - 1) + processing_time) / total_requests
            )
        else:
            self.processing_stats["average_processing_time"] = processing_time
    
    def get_supported_methods(self, redaction_type: RedactionType) -> List[RedactionMethod]:
        """Get supported redaction methods for a given type."""
        if redaction_type == RedactionType.TEXT:
            return [
                RedactionMethod.DELETE,
                RedactionMethod.MASK_ASTERISK,
                RedactionMethod.MASK_X,
                RedactionMethod.MASK_HASH,
                RedactionMethod.REDACTED_LABEL,
                RedactionMethod.PLACEHOLDER,
                RedactionMethod.PARTIAL_MASK,
                RedactionMethod.WHITESPACE,
                RedactionMethod.HASH,
                RedactionMethod.ENCRYPT,
                RedactionMethod.PSEUDONYMIZE,
                RedactionMethod.GENERALIZE
            ]
        
        elif redaction_type == RedactionType.VISUAL:
            return [
                RedactionMethod.BLACKOUT,
                RedactionMethod.WHITEOUT,
                RedactionMethod.BLUR,
                RedactionMethod.GAUSSIAN_BLUR,
                RedactionMethod.PIXELATE,
                RedactionMethod.MOSAIC,
                RedactionMethod.SOLID_COLOR,
                RedactionMethod.PATTERN_FILL,
                RedactionMethod.PLACEHOLDER,
                RedactionMethod.CROP_OUT
            ]
        
        else:  # HYBRID
            text_methods = self.get_supported_methods(RedactionType.TEXT)
            visual_methods = self.get_supported_methods(RedactionType.VISUAL)
            return list(set(text_methods + visual_methods))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return self.processing_stats.copy()
    
    def validate_request(self, request: RedactionRequest) -> List[str]:
        """Validate redaction request and return list of errors."""
        errors = []
        
        if not request.content:
            errors.append("Content is required")
        
        if not request.entities:
            errors.append("At least one entity is required")
        
        if request.redaction_type == RedactionType.TEXT and not isinstance(request.content, str):
            errors.append("Text redaction requires string content")
        
        if request.redaction_type == RedactionType.VISUAL and not isinstance(
            request.content, (np.ndarray, Image.Image, str, Path)
        ):
            errors.append("Visual redaction requires image content")
        
        supported_methods = self.get_supported_methods(request.redaction_type)
        if request.parameters.method not in supported_methods:
            errors.append(f"Method {request.parameters.method} not supported for {request.redaction_type}")
        
        return errors


# Global redaction engine instance
_default_redaction_engine = None

def get_redaction_engine() -> UnifiedRedactionEngine:
    """Get or create the default redaction engine instance."""
    global _default_redaction_engine
    
    if _default_redaction_engine is None:
        _default_redaction_engine = UnifiedRedactionEngine()
    
    return _default_redaction_engine