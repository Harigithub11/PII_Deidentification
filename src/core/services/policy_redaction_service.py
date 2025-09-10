"""
Policy-Driven Redaction Service

This module integrates the unified redaction engine with the policy engine to provide
intelligent, policy-driven redaction decisions and automated redaction enforcement.
"""

import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field

from ..config.policies.base import PIIType, RedactionMethod
from ..config.policy_models import (
    PolicyContext, PolicyDecision, PolicyDecisionType, 
    PolicyEvaluationResult, PolicyViolation
)
from ..models.ner_models import PIIEntity
from ..models.visual_models import VisualPIIEntity
from ..services.policy_engine import get_policy_engine
from ..services.redaction_engine import (
    get_redaction_engine, RedactionRequest, RedactionResult,
    RedactionType, RedactionParameters, RedactionIntensity
)
from ..services.pseudonymization_service import (
    get_pseudonymization_service, PseudonymizationConfig, GeneralizationConfig
)
from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class PolicyRedactionRequest:
    """Request for policy-driven redaction."""
    request_id: str
    content: Any
    entities: List[Union[PIIEntity, VisualPIIEntity]]
    context: PolicyContext
    redaction_type: RedactionType = RedactionType.TEXT
    policy_names: Optional[List[str]] = None
    override_method: Optional[RedactionMethod] = None
    audit_enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PolicyRedactionResult:
    """Result of policy-driven redaction."""
    request_id: str
    success: bool
    redacted_content: Optional[Any] = None
    original_content: Optional[Any] = None
    policy_decisions: List[PolicyDecision] = field(default_factory=list)
    redaction_results: List[RedactionResult] = field(default_factory=list)
    policy_violations: List[PolicyViolation] = field(default_factory=list)
    processing_time_seconds: float = 0.0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


class PolicyRedactionService:
    """Service that combines policy evaluation with redaction execution."""
    
    def __init__(self):
        self.policy_engine = get_policy_engine()
        self.redaction_engine = get_redaction_engine()
        self.pseudonymization_service = get_pseudonymization_service()
        
        # Method mapping for policy decisions to redaction methods
        self.decision_method_mapping = {
            PolicyDecisionType.REDACT: RedactionMethod.REDACTED_LABEL,
            PolicyDecisionType.PSEUDONYMIZE: RedactionMethod.PSEUDONYMIZE,
            PolicyDecisionType.ANONYMIZE: RedactionMethod.GENERALIZE,
            PolicyDecisionType.DENY: RedactionMethod.DELETE,
        }
        
        logger.info("Initialized PolicyRedactionService")
    
    async def redact_with_policy_async(
        self, 
        request: PolicyRedactionRequest
    ) -> PolicyRedactionResult:
        """Asynchronously perform policy-driven redaction."""
        return await asyncio.get_event_loop().run_in_executor(
            None, self.redact_with_policy, request
        )
    
    def redact_with_policy(self, request: PolicyRedactionRequest) -> PolicyRedactionResult:
        """Perform redaction based on policy evaluation."""
        import time
        start_time = time.time()
        
        try:
            # Step 1: Evaluate entities against policies
            policy_result = self.policy_engine.evaluate_entities(
                request.entities,
                request.context,
                request.policy_names
            )
            
            if not policy_result.success:
                return PolicyRedactionResult(
                    request_id=request.request_id,
                    success=False,
                    error_message=f"Policy evaluation failed: {policy_result.error_message}",
                    processing_time_seconds=time.time() - start_time
                )
            
            # Step 2: Group entities by redaction method
            method_groups = self._group_entities_by_method(
                policy_result.decisions, request.override_method
            )
            
            # Step 3: Execute redaction for each method group
            redaction_results = []
            final_content = request.content
            
            for method, entity_decisions in method_groups.items():
                entities = [decision.entity for decision in entity_decisions if hasattr(decision, 'entity')]
                
                if not entities:
                    continue
                
                # Create redaction parameters based on method
                parameters = self._create_redaction_parameters(method, entity_decisions)
                
                # Create redaction request
                redaction_request = RedactionRequest(
                    redaction_type=request.redaction_type,
                    content=final_content,
                    entities=entities,
                    parameters=parameters,
                    policy_context=request.context,
                    preserve_original=False,
                    audit_enabled=request.audit_enabled
                )
                
                # Execute redaction
                redaction_result = self.redaction_engine.redact(redaction_request)
                redaction_results.append(redaction_result)
                
                if redaction_result.success and redaction_result.redacted_content is not None:
                    final_content = redaction_result.redacted_content
                else:
                    logger.warning(f"Redaction failed for method {method}: {redaction_result.error_message}")
            
            # Step 4: Handle special cases (pseudonymization, generalization)
            final_content = await self._handle_advanced_methods(
                final_content, policy_result.decisions, request
            )
            
            processing_time = time.time() - start_time
            
            return PolicyRedactionResult(
                request_id=request.request_id,
                success=True,
                redacted_content=final_content,
                original_content=request.content,
                policy_decisions=policy_result.decisions,
                redaction_results=redaction_results,
                policy_violations=policy_result.violations,
                processing_time_seconds=processing_time,
                metadata={
                    "total_entities": len(request.entities),
                    "redacted_entities": sum(len(r.entities_redacted) for r in redaction_results),
                    "policy_count": len(policy_result.applied_policies),
                    "method_groups": len(method_groups)
                }
            )
        
        except Exception as e:
            logger.error(f"Policy redaction failed for request {request.request_id}: {e}")
            return PolicyRedactionResult(
                request_id=request.request_id,
                success=False,
                error_message=str(e),
                processing_time_seconds=time.time() - start_time
            )
    
    def _group_entities_by_method(
        self,
        decisions: List[PolicyDecision],
        override_method: Optional[RedactionMethod]
    ) -> Dict[RedactionMethod, List[PolicyDecision]]:
        """Group policy decisions by their redaction method."""
        groups = {}
        
        for decision in decisions:
            # Use override method if specified, otherwise use decision method
            if override_method:
                method = override_method
            elif decision.redaction_method:
                method = decision.redaction_method
            else:
                # Map decision type to default method
                method = self.decision_method_mapping.get(
                    decision.decision_type, 
                    RedactionMethod.REDACTED_LABEL
                )
            
            if method not in groups:
                groups[method] = []
            groups[method].append(decision)
        
        return groups
    
    def _create_redaction_parameters(
        self,
        method: RedactionMethod,
        decisions: List[PolicyDecision]
    ) -> RedactionParameters:
        """Create redaction parameters based on method and decisions."""
        
        # Determine intensity based on confidence scores
        avg_confidence = sum(d.confidence for d in decisions) / len(decisions)
        
        if avg_confidence >= 0.9:
            intensity = RedactionIntensity.MAXIMUM
        elif avg_confidence >= 0.7:
            intensity = RedactionIntensity.HIGH
        elif avg_confidence >= 0.5:
            intensity = RedactionIntensity.MEDIUM
        else:
            intensity = RedactionIntensity.LOW
        
        # Create base parameters
        parameters = RedactionParameters(
            method=method,
            intensity=intensity,
            preserve_format=True,
            preserve_length=False
        )
        
        # Method-specific customizations
        if method in [RedactionMethod.BLACKOUT, RedactionMethod.WHITEOUT]:
            parameters.color = (0, 0, 0) if method == RedactionMethod.BLACKOUT else (255, 255, 255)
        
        elif method == RedactionMethod.PLACEHOLDER:
            # Use first decision's PII type for placeholder
            if decisions:
                pii_type = decisions[0].pii_type
                parameters.custom_placeholder = f"[{pii_type.value.upper()}]"
        
        elif method in [RedactionMethod.PSEUDONYMIZE, RedactionMethod.GENERALIZE]:
            # Set consistency key for pseudonymization
            parameters.pseudonym_seed = f"policy_{hash(str(decisions))}"
        
        return parameters
    
    async def _handle_advanced_methods(
        self,
        content: Any,
        decisions: List[PolicyDecision],
        request: PolicyRedactionRequest
    ) -> Any:
        """Handle advanced redaction methods like pseudonymization."""
        
        # Filter decisions that need advanced processing
        advanced_decisions = [
            d for d in decisions 
            if d.redaction_method in [RedactionMethod.PSEUDONYMIZE, RedactionMethod.GENERALIZE]
        ]
        
        if not advanced_decisions or not isinstance(content, str):
            return content
        
        # Apply advanced methods to text content
        processed_content = content
        
        for decision in advanced_decisions:
            if not hasattr(decision, 'entity_text'):
                continue
            
            try:
                if decision.redaction_method == RedactionMethod.PSEUDONYMIZE:
                    config = PseudonymizationConfig(
                        preserve_format=True,
                        consistency_key=f"policy_{request.context.user_id or 'anonymous'}"
                    )
                    result = self.pseudonymization_service.pseudonymize(
                        decision.entity_text, decision.pii_type, config
                    )
                    
                    if result.success:
                        processed_content = processed_content.replace(
                            decision.entity_text, result.anonymized_value
                        )
                
                elif decision.redaction_method == RedactionMethod.GENERALIZE:
                    config = GeneralizationConfig(preserve_utility=True)
                    result = self.pseudonymization_service.generalize(
                        decision.entity_text, decision.pii_type, config
                    )
                    
                    if result.success:
                        processed_content = processed_content.replace(
                            decision.entity_text, result.anonymized_value
                        )
            
            except Exception as e:
                logger.error(f"Advanced method processing failed: {e}")
                continue
        
        return processed_content
    
    def get_redaction_preview(
        self,
        request: PolicyRedactionRequest,
        include_policy_details: bool = True
    ) -> Dict[str, Any]:
        """Generate a preview of what redaction would do without executing it."""
        try:
            # Evaluate policies
            policy_result = self.policy_engine.evaluate_entities(
                request.entities,
                request.context,
                request.policy_names
            )
            
            if not policy_result.success:
                return {
                    "success": False,
                    "error": policy_result.error_message
                }
            
            # Group by method
            method_groups = self._group_entities_by_method(
                policy_result.decisions, request.override_method
            )
            
            # Create preview
            preview = {
                "success": True,
                "total_entities": len(request.entities),
                "policy_decisions": len(policy_result.decisions),
                "violations": len(policy_result.violations),
                "redaction_methods": {}
            }
            
            for method, decisions in method_groups.items():
                preview["redaction_methods"][method.value] = {
                    "entity_count": len(decisions),
                    "entities": [
                        {
                            "text": getattr(d, 'entity_text', 'N/A'),
                            "type": d.pii_type.value,
                            "confidence": d.confidence
                        }
                        for d in decisions
                    ] if include_policy_details else []
                }
            
            if include_policy_details:
                preview["applied_policies"] = policy_result.applied_policies
                preview["violations"] = [
                    {
                        "type": v.violation_type.value,
                        "policy": v.policy_name,
                        "message": v.message
                    }
                    for v in policy_result.violations
                ]
            
            return preview
        
        except Exception as e:
            logger.error(f"Preview generation failed: {e}")
            return {"success": False, "error": str(e)}
    
    def validate_redaction_request(self, request: PolicyRedactionRequest) -> List[str]:
        """Validate policy redaction request."""
        errors = []
        
        if not request.content:
            errors.append("Content is required")
        
        if not request.entities:
            errors.append("At least one entity is required")
        
        if not request.context:
            errors.append("Policy context is required")
        
        # Validate entities match content type
        if request.redaction_type == RedactionType.TEXT:
            if not isinstance(request.content, str):
                errors.append("Text redaction requires string content")
            
            text_entities = [e for e in request.entities if isinstance(e, PIIEntity)]
            if not text_entities:
                errors.append("Text redaction requires PIIEntity objects")
        
        elif request.redaction_type == RedactionType.VISUAL:
            visual_entities = [e for e in request.entities if isinstance(e, VisualPIIEntity)]
            if not visual_entities:
                errors.append("Visual redaction requires VisualPIIEntity objects")
        
        return errors
    
    def get_service_stats(self) -> Dict[str, Any]:
        """Get service statistics."""
        return {
            "policy_engine_stats": self.policy_engine.get_stats(),
            "redaction_engine_stats": self.redaction_engine.get_stats(),
            "pseudonymization_stats": self.pseudonymization_service.get_mapping_stats()
        }


# Global service instance
_default_policy_redaction_service = None

def get_policy_redaction_service() -> PolicyRedactionService:
    """Get or create the default policy redaction service instance."""
    global _default_policy_redaction_service
    
    if _default_policy_redaction_service is None:
        _default_policy_redaction_service = PolicyRedactionService()
    
    return _default_policy_redaction_service