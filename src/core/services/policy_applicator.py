"""
Policy Applicator Service for PII De-identification System

This module provides policy enforcement capabilities by applying policy decisions
to detected PII entities, handling both text and visual anonymization/redaction.
"""

import logging
import time
import re
import hashlib
import random
import string
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from PIL import Image
import numpy as np

from ..config.policy_models import (
    PolicyDecision, PolicyContext, PolicyAuditLog, PolicyViolation,
    PolicyDecisionType, PolicyViolationType
)
from ..config.policies.base import RedactionMethod, PIIType
from ..models.ner_models import PIIEntity
from ..models.visual_models import VisualPIIEntity, BoundingBox
from ..processing.visual_redactor import VisualRedactor, RedactionConfig, VisualRedactionMethod
from ..security.encryption import encryption_manager
from ..config.settings import get_settings

logger = logging.getLogger(__name__)


class ApplicationMethod(str, Enum):
    """Methods for applying policy decisions."""
    IN_PLACE = "in_place"
    COPY = "copy"
    PREVIEW = "preview"


@dataclass
class TextRedactionResult:
    """Result of text redaction operation."""
    original_text: str
    redacted_text: str
    redaction_map: Dict[str, str] = field(default_factory=dict)
    entities_processed: int = 0
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class VisualRedactionResult:
    """Result of visual redaction operation."""
    original_image: Image.Image
    redacted_image: Image.Image
    redaction_regions: List[Dict[str, Any]] = field(default_factory=list)
    entities_processed: int = 0
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class PolicyApplicationResult:
    """Result of policy application to entities."""
    
    # Application details
    application_id: str
    context: PolicyContext
    method: ApplicationMethod
    
    # Processing results
    text_result: Optional[TextRedactionResult] = None
    visual_result: Optional[VisualRedactionResult] = None
    
    # Decision tracking
    decisions_applied: List[PolicyDecision] = field(default_factory=list)
    decisions_failed: List[PolicyDecision] = field(default_factory=list)
    violations_created: List[PolicyViolation] = field(default_factory=list)
    
    # Audit information
    audit_logs: List[PolicyAuditLog] = field(default_factory=list)
    
    # Performance metrics
    processing_time_ms: float = 0.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Overall status
    success: bool = True
    error_message: Optional[str] = None
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of application results."""
        return {
            "application_id": self.application_id,
            "success": self.success,
            "decisions_applied": len(self.decisions_applied),
            "decisions_failed": len(self.decisions_failed),
            "violations_created": len(self.violations_created),
            "processing_time_ms": self.processing_time_ms,
            "text_entities_processed": self.text_result.entities_processed if self.text_result else 0,
            "visual_entities_processed": self.visual_result.entities_processed if self.visual_result else 0
        }


class PolicyApplicator:
    """Service for applying policy decisions to PII entities."""
    
    def __init__(self):
        self.settings = get_settings()
        self.visual_redactor = VisualRedactor()
        
        # Pseudonymization mappings
        self.pseudonym_cache: Dict[str, str] = {}
        self.generalization_rules: Dict[PIIType, callable] = {}
        
        # Initialize generalization rules
        self._initialize_generalization_rules()
        
        logger.info("PolicyApplicator initialized")
    
    def _initialize_generalization_rules(self):
        """Initialize rules for generalizing different PII types."""
        
        self.generalization_rules[PIIType.DATE_OF_BIRTH] = self._generalize_date
        self.generalization_rules[PIIType.AGE] = self._generalize_age
        self.generalization_rules[PIIType.ADDRESS] = self._generalize_address
        self.generalization_rules[PIIType.PHONE] = self._generalize_phone
        self.generalization_rules[PIIType.EMAIL] = self._generalize_email
        self.generalization_rules[PIIType.INCOME] = self._generalize_income
    
    async def apply_decisions_async(
        self,
        decisions: List[PolicyDecision],
        text_content: Optional[str] = None,
        visual_content: Optional[Image.Image] = None,
        context: Optional[PolicyContext] = None,
        method: ApplicationMethod = ApplicationMethod.IN_PLACE
    ) -> PolicyApplicationResult:
        """Asynchronously apply policy decisions to content."""
        
        import uuid
        application_id = str(uuid.uuid4())
        start_time = time.time()
        
        result = PolicyApplicationResult(
            application_id=application_id,
            context=context or PolicyContext(),
            method=method,
            started_at=datetime.now()
        )
        
        try:
            # Separate text and visual decisions
            text_decisions = []
            visual_decisions = []
            
            for decision in decisions:
                if self._is_visual_entity(decision):
                    visual_decisions.append(decision)
                else:
                    text_decisions.append(decision)
            
            # Apply text decisions
            if text_content and text_decisions:
                result.text_result = await self._apply_text_decisions_async(
                    text_content, text_decisions, method
                )
                result.decisions_applied.extend([
                    d for d in text_decisions 
                    if result.text_result.success
                ])
            
            # Apply visual decisions
            if visual_content and visual_decisions:
                result.visual_result = await self._apply_visual_decisions_async(
                    visual_content, visual_decisions, method
                )
                result.decisions_applied.extend([
                    d for d in visual_decisions 
                    if result.visual_result.success
                ])
            
            # Create audit logs
            result.audit_logs = self._create_audit_logs(result, context)
            
            # Calculate performance metrics
            result.processing_time_ms = (time.time() - start_time) * 1000
            result.completed_at = datetime.now()
            result.success = (
                (not result.text_result or result.text_result.success) and
                (not result.visual_result or result.visual_result.success)
            )
            
            logger.debug(f"Policy application completed: {result.get_summary()}")
            return result
            
        except Exception as e:
            result.processing_time_ms = (time.time() - start_time) * 1000
            result.completed_at = datetime.now()
            result.success = False
            result.error_message = str(e)
            
            logger.error(f"Policy application failed: {e}")
            return result
    
    def apply_decisions_sync(
        self,
        decisions: List[PolicyDecision],
        text_content: Optional[str] = None,
        visual_content: Optional[Image.Image] = None,
        context: Optional[PolicyContext] = None,
        method: ApplicationMethod = ApplicationMethod.IN_PLACE
    ) -> PolicyApplicationResult:
        """Synchronously apply policy decisions to content."""
        
        import asyncio
        
        # Create event loop if none exists
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(
            self.apply_decisions_async(decisions, text_content, visual_content, context, method)
        )
    
    async def _apply_text_decisions_async(
        self,
        text: str,
        decisions: List[PolicyDecision],
        method: ApplicationMethod
    ) -> TextRedactionResult:
        """Apply text-based policy decisions."""
        
        try:
            redacted_text = text
            redaction_map = {}
            entities_processed = 0
            
            # Sort decisions by position (reverse order to maintain positions)
            text_decisions = [d for d in decisions if hasattr(d, 'entity_position') and d.entity_position]
            text_decisions.sort(
                key=lambda d: d.entity_position.get('start_position', 0), 
                reverse=True
            )
            
            for decision in text_decisions:
                try:
                    entity_text = decision.entity_text
                    decision_type = decision.decision_type
                    
                    # Find entity position in text
                    if decision.entity_position:
                        start_pos = decision.entity_position.get('start_position', 0)
                        end_pos = decision.entity_position.get('end_position', len(entity_text))
                    else:
                        # Search for the entity in text
                        start_pos = text.find(entity_text)
                        if start_pos == -1:
                            continue
                        end_pos = start_pos + len(entity_text)
                    
                    # Apply the decision
                    replacement = await self._generate_replacement_async(decision)
                    
                    if method == ApplicationMethod.PREVIEW:
                        # Just mark what would be changed
                        replacement = f"[{decision_type.value.upper()}:{entity_text}]"
                    
                    # Replace the text
                    redacted_text = (
                        redacted_text[:start_pos] + 
                        replacement + 
                        redacted_text[end_pos:]
                    )
                    
                    redaction_map[entity_text] = replacement
                    entities_processed += 1
                    
                except Exception as e:
                    logger.error(f"Failed to apply decision for '{decision.entity_text}': {e}")
                    continue
            
            return TextRedactionResult(
                original_text=text,
                redacted_text=redacted_text,
                redaction_map=redaction_map,
                entities_processed=entities_processed,
                success=True
            )
            
        except Exception as e:
            logger.error(f"Text redaction failed: {e}")
            return TextRedactionResult(
                original_text=text,
                redacted_text=text,
                success=False,
                error_message=str(e)
            )
    
    async def _apply_visual_decisions_async(
        self,
        image: Image.Image,
        decisions: List[PolicyDecision],
        method: ApplicationMethod
    ) -> VisualRedactionResult:
        """Apply visual-based policy decisions."""
        
        try:
            redacted_image = image.copy() if method != ApplicationMethod.PREVIEW else image
            redaction_regions = []
            entities_processed = 0
            
            for decision in decisions:
                try:
                    # Extract bounding box from decision context
                    bbox = self._extract_bounding_box(decision)
                    if not bbox:
                        continue
                    
                    # Determine visual redaction method
                    visual_method = self._map_to_visual_method(decision.redaction_method)
                    
                    if method == ApplicationMethod.PREVIEW:
                        # Just record what would be redacted
                        redaction_regions.append({
                            "bbox": bbox,
                            "method": visual_method.value,
                            "entity_type": decision.pii_type.value,
                            "preview": True
                        })
                    else:
                        # Apply visual redaction
                        redaction_config = RedactionConfig(
                            method=visual_method,
                            intensity=1.0,
                            color=(0, 0, 0) if visual_method == VisualRedactionMethod.BLACKOUT else (255, 255, 255)
                        )
                        
                        redacted_image = self.visual_redactor.apply_redaction(
                            redacted_image, bbox, redaction_config
                        )
                        
                        redaction_regions.append({
                            "bbox": bbox,
                            "method": visual_method.value,
                            "entity_type": decision.pii_type.value,
                            "applied": True
                        })
                    
                    entities_processed += 1
                    
                except Exception as e:
                    logger.error(f"Failed to apply visual decision: {e}")
                    continue
            
            return VisualRedactionResult(
                original_image=image,
                redacted_image=redacted_image,
                redaction_regions=redaction_regions,
                entities_processed=entities_processed,
                success=True
            )
            
        except Exception as e:
            logger.error(f"Visual redaction failed: {e}")
            return VisualRedactionResult(
                original_image=image,
                redacted_image=image,
                success=False,
                error_message=str(e)
            )
    
    async def _generate_replacement_async(self, decision: PolicyDecision) -> str:
        """Generate replacement text based on policy decision."""
        
        entity_text = decision.entity_text
        decision_type = decision.decision_type
        pii_type = decision.pii_type
        
        if decision_type == PolicyDecisionType.REDACT:
            # Simple redaction
            if decision.redaction_method == RedactionMethod.DELETE:
                return ""
            elif decision.redaction_method == RedactionMethod.BLACKOUT:
                return "█" * len(entity_text)
            else:
                return "[REDACTED]"
        
        elif decision_type == PolicyDecisionType.PSEUDONYMIZE:
            # Generate or retrieve pseudonym
            return self._generate_pseudonym(entity_text, pii_type)
        
        elif decision_type == PolicyDecisionType.ANONYMIZE:
            # Generalize the entity
            return self._generalize_entity(entity_text, pii_type)
        
        elif decision_type == PolicyDecisionType.DENY:
            return "[BLOCKED]"
        
        elif decision_type == PolicyDecisionType.FLAG:
            return f"[FLAGGED:{entity_text}]"
        
        else:
            # Default - return original
            return entity_text
    
    def _generate_pseudonym(self, entity_text: str, pii_type: PIIType) -> str:
        """Generate a consistent pseudonym for an entity."""
        
        # Check cache first
        cache_key = f"{pii_type.value}:{entity_text}"
        if cache_key in self.pseudonym_cache:
            return self.pseudonym_cache[cache_key]
        
        # Generate pseudonym based on type
        if pii_type == PIIType.NAME:
            pseudonym = self._generate_fake_name(entity_text)
        elif pii_type == PIIType.EMAIL:
            pseudonym = self._generate_fake_email(entity_text)
        elif pii_type == PIIType.PHONE:
            pseudonym = self._generate_fake_phone(entity_text)
        elif pii_type == PIIType.ADDRESS:
            pseudonym = self._generate_fake_address(entity_text)
        elif pii_type in [PIIType.SSN, PIIType.NATIONAL_ID]:
            pseudonym = self._generate_fake_id(entity_text)
        else:
            # Generic pseudonym
            hash_value = hashlib.md5(entity_text.encode()).hexdigest()[:8]
            pseudonym = f"PSE_{hash_value.upper()}"
        
        # Cache the pseudonym
        self.pseudonym_cache[cache_key] = pseudonym
        return pseudonym
    
    def _generate_fake_name(self, original_name: str) -> str:
        """Generate a fake name preserving structure."""
        parts = original_name.split()
        fake_parts = []
        
        for part in parts:
            if len(part) <= 2:
                fake_parts.append(part)  # Keep short parts like initials
            else:
                # Generate based on hash for consistency
                hash_value = hashlib.md5(part.lower().encode()).hexdigest()
                fake_part = "Name" + hash_value[:3].upper()
                fake_parts.append(fake_part)
        
        return " ".join(fake_parts)
    
    def _generate_fake_email(self, original_email: str) -> str:
        """Generate a fake email preserving domain structure."""
        if "@" not in original_email:
            return f"user{hashlib.md5(original_email.encode()).hexdigest()[:6]}@example.com"
        
        local, domain = original_email.split("@", 1)
        hash_value = hashlib.md5(local.encode()).hexdigest()[:6]
        
        # Preserve domain structure
        if "." in domain:
            domain_parts = domain.split(".")
            fake_domain = f"example.{domain_parts[-1]}"
        else:
            fake_domain = "example.com"
        
        return f"user{hash_value}@{fake_domain}"
    
    def _generate_fake_phone(self, original_phone: str) -> str:
        """Generate a fake phone number preserving format."""
        # Extract digits only
        digits = re.sub(r'\D', '', original_phone)
        
        if len(digits) >= 10:
            # US format
            fake_digits = "555" + "".join([str(random.randint(0, 9)) for _ in range(7)])
            # Preserve original format
            return re.sub(r'\d', lambda m: fake_digits.pop(0) if fake_digits else '0', original_phone)
        else:
            return "555-0000"
    
    def _generate_fake_address(self, original_address: str) -> str:
        """Generate a fake address preserving structure."""
        return f"123 Privacy Street, Anonymous City, XX 00000"
    
    def _generate_fake_id(self, original_id: str) -> str:
        """Generate a fake ID number preserving format."""
        # Preserve format but change digits
        fake_id = ""
        for char in original_id:
            if char.isdigit():
                fake_id += str(random.randint(0, 9))
            else:
                fake_id += char
        return fake_id
    
    def _generalize_entity(self, entity_text: str, pii_type: PIIType) -> str:
        """Generalize an entity based on its type."""
        
        if pii_type in self.generalization_rules:
            try:
                return self.generalization_rules[pii_type](entity_text)
            except Exception as e:
                logger.warning(f"Generalization failed for {pii_type}: {e}")
        
        # Default generalization
        return f"[{pii_type.value.upper()}]"
    
    def _generalize_date(self, date_text: str) -> str:
        """Generalize date to year only."""
        # Extract year if possible
        year_match = re.search(r'\b(19|20)\d{2}\b', date_text)
        if year_match:
            return year_match.group()
        return "[YEAR]"
    
    def _generalize_age(self, age_text: str) -> str:
        """Generalize age to age range."""
        try:
            age = int(re.search(r'\d+', age_text).group())
            if age < 18:
                return "Under 18"
            elif age < 30:
                return "18-29"
            elif age < 50:
                return "30-49"
            elif age < 65:
                return "50-64"
            else:
                return "65+"
        except:
            return "[AGE RANGE]"
    
    def _generalize_address(self, address_text: str) -> str:
        """Generalize address to city/state level."""
        # Extract state/country if possible
        parts = address_text.split(",")
        if len(parts) >= 2:
            return f"[CITY], {parts[-1].strip()}"
        return "[LOCATION]"
    
    def _generalize_phone(self, phone_text: str) -> str:
        """Generalize phone to area code only."""
        # Extract area code
        digits = re.sub(r'\D', '', phone_text)
        if len(digits) >= 3:
            return f"({digits[:3]}) XXX-XXXX"
        return "[PHONE]"
    
    def _generalize_email(self, email_text: str) -> str:
        """Generalize email to domain only."""
        if "@" in email_text:
            domain = email_text.split("@")[1]
            return f"[USER]@{domain}"
        return "[EMAIL]"
    
    def _generalize_income(self, income_text: str) -> str:
        """Generalize income to range."""
        try:
            # Extract numeric value
            amount = float(re.sub(r'[^\d.]', '', income_text))
            if amount < 25000:
                return "Under $25,000"
            elif amount < 50000:
                return "$25,000-$49,999"
            elif amount < 100000:
                return "$50,000-$99,999"
            else:
                return "$100,000+"
        except:
            return "[INCOME RANGE]"
    
    def _is_visual_entity(self, decision: PolicyDecision) -> bool:
        """Check if decision applies to visual content."""
        visual_types = {PIIType.PHOTO, PIIType.SIGNATURE}
        return (
            decision.pii_type in visual_types or
            "visual" in decision.entity_text.lower() or
            decision.entity_text.startswith("Visual_")
        )
    
    def _extract_bounding_box(self, decision: PolicyDecision) -> Optional[BoundingBox]:
        """Extract bounding box from decision context."""
        if not decision.context or not hasattr(decision.context, 'metadata'):
            return None
        
        metadata = decision.context.metadata
        if 'bounding_box' in metadata:
            bbox_data = metadata['bounding_box']
            return BoundingBox(
                x1=bbox_data.get('x1', 0),
                y1=bbox_data.get('y1', 0),
                x2=bbox_data.get('x2', 100),
                y2=bbox_data.get('y2', 100)
            )
        
        return None
    
    def _map_to_visual_method(self, redaction_method: RedactionMethod) -> VisualRedactionMethod:
        """Map policy redaction method to visual redaction method."""
        mapping = {
            RedactionMethod.BLACKOUT: VisualRedactionMethod.BLACKOUT,
            RedactionMethod.WHITEOUT: VisualRedactionMethod.WHITEOUT,
            RedactionMethod.BLUR: VisualRedactionMethod.GAUSSIAN_BLUR,
            RedactionMethod.PIXELATE: VisualRedactionMethod.PIXELATE,
            RedactionMethod.DELETE: VisualRedactionMethod.CROP_OUT
        }
        return mapping.get(redaction_method, VisualRedactionMethod.BLACKOUT)
    
    def _create_audit_logs(
        self,
        result: PolicyApplicationResult,
        context: Optional[PolicyContext]
    ) -> List[PolicyAuditLog]:
        """Create audit logs for policy application."""
        
        logs = []
        
        # Main application log
        main_log = PolicyAuditLog(
            action="policy_application",
            resource_type="content",
            resource_id=result.application_id,
            system_component="policy_applicator",
            context=context,
            success=result.success,
            error_message=result.error_message,
            duration_ms=result.processing_time_ms,
            rule_details={
                "method": result.method.value,
                "decisions_applied": len(result.decisions_applied),
                "decisions_failed": len(result.decisions_failed),
                "text_entities": result.text_result.entities_processed if result.text_result else 0,
                "visual_entities": result.visual_result.entities_processed if result.visual_result else 0
            }
        )
        logs.append(main_log)
        
        # Individual decision logs
        for decision in result.decisions_applied:
            decision_log = PolicyAuditLog(
                action="decision_applied",
                resource_type="entity",
                resource_id=decision.decision_id,
                system_component="policy_applicator",
                context=context,
                policy_name=decision.applied_policy,
                success=True,
                rule_details={
                    "pii_type": decision.pii_type.value,
                    "decision_type": decision.decision_type.value,
                    "redaction_method": decision.redaction_method.value if decision.redaction_method else None
                }
            )
            logs.append(decision_log)
        
        return logs
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get policy applicator statistics."""
        return {
            "pseudonym_cache_size": len(self.pseudonym_cache),
            "generalization_rules": len(self.generalization_rules),
            "visual_redactor_available": self.visual_redactor is not None,
            "supported_text_operations": [
                "redact", "pseudonymize", "anonymize", "generalize"
            ],
            "supported_visual_operations": [
                "blackout", "whiteout", "blur", "pixelate", "crop"
            ]
        }
    
    def clear_cache(self):
        """Clear the pseudonym cache."""
        self.pseudonym_cache.clear()
        logger.info("Policy applicator cache cleared")


# Global policy applicator instance
_default_policy_applicator = None

def get_policy_applicator() -> PolicyApplicator:
    """Get or create the default policy applicator instance."""
    global _default_policy_applicator
    
    if _default_policy_applicator is None:
        _default_policy_applicator = PolicyApplicator()
    
    return _default_policy_applicator