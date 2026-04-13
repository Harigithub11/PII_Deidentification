"""
Policy Engine for PII De-identification System

This module provides the core policy engine that orchestrates policy evaluation,
enforcement, and management across the entire system. It integrates with PII detection
services and provides centralized policy decision-making.
"""

import logging
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import uuid
from collections import defaultdict

from ..config.policy_models import (
    PolicyContext, PolicyDecision, PolicyViolation, PolicyAuditLog,
    PolicyConfiguration, PolicyExecutionStats, PolicyDecisionType,
    PolicyViolationType, PolicyPriority, PolicyScope, PolicyStatus
)
from ..config.policies.base import BasePolicy, PolicyRule, PIIType, RedactionMethod
from ..config.policies.gdpr import GDPRPolicy
from ..config.policies.hipaa import HIPAAPolicy
from ..config.policies.ndhm import NDHMPolicy
from ..models.ner_models import PIIEntity
from ..models.visual_models import VisualPIIEntity
from ..security.compliance_encryption import ComplianceStandard
from ..config.settings import get_settings

logger = logging.getLogger(__name__)


class PolicyEngineError(Exception):
    """Base exception for policy engine errors."""
    pass


class PolicyConflictError(PolicyEngineError):
    """Exception raised when policy conflicts cannot be resolved."""
    pass


class PolicyValidationError(PolicyEngineError):
    """Exception raised when policy validation fails."""
    pass


@dataclass
class PolicyEvaluationRequest:
    """Request for policy evaluation."""
    entities: List[Union[PIIEntity, VisualPIIEntity]]
    context: PolicyContext
    options: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.options is None:
            self.options = {}


@dataclass
class PolicyEvaluationResult:
    """Result of policy evaluation."""
    request_id: str
    decisions: List[PolicyDecision]
    violations: List[PolicyViolation]
    audit_logs: List[PolicyAuditLog]
    execution_time_ms: float
    success: bool
    error_message: Optional[str] = None
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of evaluation results."""
        decision_counts = defaultdict(int)
        for decision in self.decisions:
            decision_counts[decision.decision_type.value] += 1
        
        violation_counts = defaultdict(int)
        for violation in self.violations:
            violation_counts[violation.violation_type.value] += 1
        
        return {
            "request_id": self.request_id,
            "total_entities": len(self.decisions),
            "total_violations": len(self.violations),
            "execution_time_ms": self.execution_time_ms,
            "success": self.success,
            "decision_distribution": dict(decision_counts),
            "violation_distribution": dict(violation_counts)
        }


class PolicyEngine:
    """Central policy engine for orchestrating policy evaluation and enforcement."""
    
    def __init__(self):
        self.settings = get_settings()
        
        # Policy storage
        self.policies: Dict[str, BasePolicy] = {}
        self.policy_configurations: Dict[str, PolicyConfiguration] = {}
        self.policy_stats: Dict[str, PolicyExecutionStats] = {}
        
        # Caching
        self.decision_cache: Dict[str, PolicyDecision] = {}
        self.cache_ttl_seconds = 300  # 5 minutes
        
        # Execution tracking
        self.audit_logs: List[PolicyAuditLog] = []
        self.violations: List[PolicyViolation] = []
        
        # Threading
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
        # Initialize default policies
        self._initialize_default_policies()
        
        logger.info("PolicyEngine initialized successfully")
    
    def _initialize_default_policies(self):
        """Initialize default compliance policies."""
        try:
            # Initialize GDPR policy
            gdpr_policy = GDPRPolicy()
            self.register_policy("gdpr", gdpr_policy)
            
            # Initialize HIPAA policy
            hipaa_policy = HIPAAPolicy()
            self.register_policy("hipaa", hipaa_policy)
            
            # Initialize NDHM policy
            ndhm_policy = NDHMPolicy()
            self.register_policy("ndhm", ndhm_policy)
            
            logger.info("Default policies initialized: GDPR, HIPAA, NDHM")
            
        except Exception as e:
            logger.error(f"Failed to initialize default policies: {e}")
    
    def register_policy(self, policy_name: str, policy: BasePolicy) -> bool:
        """Register a new policy with the engine."""
        try:
            # Validate policy
            validation_errors = policy.validate_policy()
            if validation_errors:
                raise PolicyValidationError(f"Policy validation failed: {validation_errors}")
            
            # Register policy
            self.policies[policy_name] = policy
            
            # Create configuration entry
            config = PolicyConfiguration(
                name=policy_name,
                description=policy.description,
                policy_type=policy.compliance_standard,
                policy_data=policy.to_dict()
            )
            self.policy_configurations[policy_name] = config
            
            # Initialize statistics
            self.policy_stats[policy_name] = PolicyExecutionStats(policy_name=policy_name)
            
            # Audit log
            audit_log = PolicyAuditLog(
                action="policy_registered",
                resource_type="policy",
                resource_id=policy_name,
                system_component="policy_engine",
                policy_name=policy_name,
                changes_made={"policy_registered": True}
            )
            self.audit_logs.append(audit_log)
            
            logger.info(f"Policy registered successfully: {policy_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register policy {policy_name}: {e}")
            return False
    
    def unregister_policy(self, policy_name: str) -> bool:
        """Unregister a policy from the engine."""
        try:
            if policy_name in self.policies:
                del self.policies[policy_name]
            if policy_name in self.policy_configurations:
                del self.policy_configurations[policy_name]
            if policy_name in self.policy_stats:
                del self.policy_stats[policy_name]
            
            # Audit log
            audit_log = PolicyAuditLog(
                action="policy_unregistered",
                resource_type="policy",
                resource_id=policy_name,
                system_component="policy_engine",
                policy_name=policy_name,
                changes_made={"policy_unregistered": True}
            )
            self.audit_logs.append(audit_log)
            
            logger.info(f"Policy unregistered: {policy_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unregister policy {policy_name}: {e}")
            return False
    
    async def evaluate_entities_async(
        self, 
        entities: List[Union[PIIEntity, VisualPIIEntity]], 
        context: PolicyContext,
        policy_names: Optional[List[str]] = None
    ) -> PolicyEvaluationResult:
        """Asynchronously evaluate entities against policies."""
        
        request_id = str(uuid.uuid4())
        start_time = time.time()
        
        try:
            # Determine which policies to apply
            applicable_policies = self._get_applicable_policies(context, policy_names)
            
            if not applicable_policies:
                logger.warning("No applicable policies found for context")
                return PolicyEvaluationResult(
                    request_id=request_id,
                    decisions=[],
                    violations=[],
                    audit_logs=[],
                    execution_time_ms=0,
                    success=False,
                    error_message="No applicable policies found"
                )
            
            # Evaluate entities
            decisions = []
            violations = []
            
            for entity in entities:
                entity_decisions, entity_violations = await self._evaluate_entity_async(
                    entity, context, applicable_policies
                )
                decisions.extend(entity_decisions)
                violations.extend(entity_violations)
            
            # Resolve conflicts
            resolved_decisions = self._resolve_policy_conflicts(decisions, context)
            
            # Update statistics
            execution_time = (time.time() - start_time) * 1000
            for policy_name in applicable_policies:
                if policy_name in self.policy_stats:
                    for decision in resolved_decisions:
                        self.policy_stats[policy_name].add_execution(
                            execution_time / len(resolved_decisions),
                            decision.decision_type,
                            True
                        )
            
            # Create audit logs
            audit_logs = [
                PolicyAuditLog(
                    action="policy_evaluation",
                    resource_type="entity_batch",
                    resource_id=request_id,
                    system_component="policy_engine",
                    context=context,
                    rule_details={
                        "entities_count": len(entities),
                        "policies_applied": applicable_policies,
                        "decisions_count": len(resolved_decisions)
                    },
                    duration_ms=execution_time
                )
            ]
            
            # Store violations and audit logs
            self.violations.extend(violations)
            self.audit_logs.extend(audit_logs)
            
            result = PolicyEvaluationResult(
                request_id=request_id,
                decisions=resolved_decisions,
                violations=violations,
                audit_logs=audit_logs,
                execution_time_ms=execution_time,
                success=True
            )
            
            logger.debug(f"Policy evaluation completed: {result.get_summary()}")
            return result
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            logger.error(f"Policy evaluation failed: {e}")
            
            return PolicyEvaluationResult(
                request_id=request_id,
                decisions=[],
                violations=[],
                audit_logs=[],
                execution_time_ms=execution_time,
                success=False,
                error_message=str(e)
            )
    
    def evaluate_entities_sync(
        self, 
        entities: List[Union[PIIEntity, VisualPIIEntity]], 
        context: PolicyContext,
        policy_names: Optional[List[str]] = None
    ) -> PolicyEvaluationResult:
        """Synchronously evaluate entities against policies."""
        
        # Create event loop if none exists
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(
            self.evaluate_entities_async(entities, context, policy_names)
        )
    
    async def _evaluate_entity_async(
        self,
        entity: Union[PIIEntity, VisualPIIEntity],
        context: PolicyContext,
        policy_names: List[str]
    ) -> Tuple[List[PolicyDecision], List[PolicyViolation]]:
        """Evaluate a single entity against specified policies."""
        
        decisions = []
        violations = []
        
        # Determine entity type
        if hasattr(entity, 'entity_type') and isinstance(entity.entity_type, str):
            # Text PII entity
            pii_type = PIIType(entity.entity_type)
            entity_text = entity.text
        elif hasattr(entity, 'entity_type'):
            # Visual PII entity
            pii_type = PIIType(entity.entity_type.value)
            entity_text = f"Visual_{entity.entity_type.value}"
        else:
            logger.warning(f"Unknown entity type: {type(entity)}")
            return decisions, violations
        
        # Check cache first
        cache_key = self._generate_cache_key(entity_text, pii_type, context)
        if cache_key in self.decision_cache:
            cached_decision = self.decision_cache[cache_key]
            if cached_decision.is_valid():
                return [cached_decision], violations
        
        # Evaluate against each policy
        for policy_name in policy_names:
            policy = self.policies.get(policy_name)
            if not policy:
                continue
            
            try:
                # Get policy rule for this PII type
                rule = policy.get_rule(pii_type)
                if not rule:
                    # No specific rule, use default behavior
                    decision = PolicyDecision(
                        decision_type=PolicyDecisionType.ALLOW,
                        pii_type=pii_type,
                        entity_text=entity_text,
                        applied_policy=policy_name,
                        redaction_method=policy.default_redaction_method,
                        context=context,
                        reasoning="No specific rule found, using default policy"
                    )
                    decisions.append(decision)
                    continue
                
                # Check confidence threshold
                entity_confidence = getattr(entity, 'confidence', 1.0)
                if entity_confidence < rule.confidence_threshold:
                    violation = PolicyViolation(
                        violation_type=PolicyViolationType.DETECTION_THRESHOLD,
                        pii_type=pii_type,
                        violated_policy=policy_name,
                        violated_rule=f"{pii_type.value}_rule",
                        context=context,
                        description=f"Entity confidence {entity_confidence} below threshold {rule.confidence_threshold}",
                        expected_action="Meet confidence threshold",
                        actual_action="Low confidence detection"
                    )
                    violations.append(violation)
                    continue
                
                # Determine action based on rule
                decision_type = self._determine_decision_type(rule.redaction_method)
                
                # Create decision
                decision = PolicyDecision(
                    decision_type=decision_type,
                    pii_type=pii_type,
                    entity_text=entity_text,
                    applied_policy=policy_name,
                    applied_rule=f"{pii_type.value}_rule",
                    policy_priority=PolicyPriority.NORMAL,
                    redaction_method=rule.redaction_method,
                    context=context,
                    reasoning=f"Applied {policy_name} rule for {pii_type.value}",
                    compliance_flags=[policy.compliance_standard]
                )
                
                # Check for policy-specific validations
                if not policy.is_pii_allowed(pii_type, context.metadata):
                    decision.decision_type = PolicyDecisionType.DENY
                    decision.reasoning += " - PII type not allowed in this context"
                
                decisions.append(decision)
                
                # Cache decision
                if cache_key:
                    decision.expires_at = datetime.now() + timedelta(seconds=self.cache_ttl_seconds)
                    self.decision_cache[cache_key] = decision
                
            except Exception as e:
                logger.error(f"Error evaluating entity against policy {policy_name}: {e}")
                violation = PolicyViolation(
                    violation_type=PolicyViolationType.CONFIGURATION_ERROR,
                    pii_type=pii_type,
                    violated_policy=policy_name,
                    context=context,
                    description=f"Policy evaluation error: {str(e)}",
                    expected_action="Successful policy evaluation",
                    actual_action="Evaluation error"
                )
                violations.append(violation)
        
        return decisions, violations
    
    def _get_applicable_policies(
        self, 
        context: PolicyContext, 
        policy_names: Optional[List[str]] = None
    ) -> List[str]:
        """Get list of policies applicable to the given context."""
        
        if policy_names:
            # Use specified policies
            applicable = []
            for name in policy_names:
                if name in self.policies:
                    config = self.policy_configurations.get(name)
                    if config and config.matches_context(context):
                        applicable.append(name)
            return applicable
        
        # Find all applicable policies
        applicable = []
        for name, config in self.policy_configurations.items():
            if config.matches_context(context):
                applicable.append(name)
        
        # Sort by priority
        applicable.sort(key=lambda name: self.policy_configurations[name].priority.value, reverse=True)
        
        return applicable
    
    def _resolve_policy_conflicts(
        self, 
        decisions: List[PolicyDecision], 
        context: PolicyContext
    ) -> List[PolicyDecision]:
        """Resolve conflicts between multiple policy decisions for the same entity."""
        
        # Group decisions by entity
        entity_decisions = defaultdict(list)
        for decision in decisions:
            key = f"{decision.pii_type.value}:{decision.entity_text}"
            entity_decisions[key].append(decision)
        
        resolved_decisions = []
        
        for entity_key, entity_decision_list in entity_decisions.items():
            if len(entity_decision_list) == 1:
                # No conflict
                resolved_decisions.append(entity_decision_list[0])
            else:
                # Resolve conflict
                resolved_decision = self._resolve_single_entity_conflict(entity_decision_list, context)
                resolved_decisions.append(resolved_decision)
        
        return resolved_decisions
    
    def _resolve_single_entity_conflict(
        self, 
        decisions: List[PolicyDecision], 
        context: PolicyContext
    ) -> PolicyDecision:
        """Resolve conflict for a single entity with multiple policy decisions."""
        
        # Sort by priority (highest first)
        decisions.sort(key=lambda d: d.policy_priority.value, reverse=True)
        
        # Choose most restrictive decision among highest priority
        highest_priority = decisions[0].policy_priority
        highest_priority_decisions = [d for d in decisions if d.policy_priority == highest_priority]
        
        # Decision type precedence (most restrictive first)
        precedence = [
            PolicyDecisionType.DENY,
            PolicyDecisionType.REDACT,
            PolicyDecisionType.ANONYMIZE,
            PolicyDecisionType.PSEUDONYMIZE,
            PolicyDecisionType.FLAG,
            PolicyDecisionType.AUDIT_ONLY,
            PolicyDecisionType.ALLOW
        ]
        
        for decision_type in precedence:
            for decision in highest_priority_decisions:
                if decision.decision_type == decision_type:
                    # Mark as conflict resolution
                    decision.reasoning += f" (Resolved from {len(decisions)} conflicting policies)"
                    decision.alternative_actions = [
                        f"{d.applied_policy}:{d.decision_type.value}" 
                        for d in decisions if d != decision
                    ]
                    return decision
        
        # Fallback to first decision
        return highest_priority_decisions[0]
    
    def _determine_decision_type(self, redaction_method: RedactionMethod) -> PolicyDecisionType:
        """Map redaction method to decision type."""
        mapping = {
            RedactionMethod.DELETE: PolicyDecisionType.REDACT,
            RedactionMethod.BLACKOUT: PolicyDecisionType.REDACT,
            RedactionMethod.WHITEOUT: PolicyDecisionType.REDACT,
            RedactionMethod.BLUR: PolicyDecisionType.REDACT,
            RedactionMethod.PIXELATE: PolicyDecisionType.REDACT,
            RedactionMethod.PSEUDONYMIZE: PolicyDecisionType.PSEUDONYMIZE,
            RedactionMethod.GENERALIZE: PolicyDecisionType.ANONYMIZE
        }
        return mapping.get(redaction_method, PolicyDecisionType.REDACT)
    
    def _generate_cache_key(self, entity_text: str, pii_type: PIIType, context: PolicyContext) -> str:
        """Generate cache key for decision caching."""
        key_elements = [
            pii_type.value,
            context.get_context_hash(),
            str(hash(entity_text))  # Hash the entity text for privacy
        ]
        return ":".join(key_elements)
    
    def get_policy_statistics(self) -> Dict[str, Any]:
        """Get comprehensive policy engine statistics."""
        
        total_evaluations = sum(stats.total_evaluations for stats in self.policy_stats.values())
        total_violations = len(self.violations)
        
        policy_stats_dict = {
            name: stats.to_dict() for name, stats in self.policy_stats.items()
        }
        
        return {
            "registered_policies": list(self.policies.keys()),
            "total_evaluations": total_evaluations,
            "total_violations": total_violations,
            "cache_size": len(self.decision_cache),
            "policy_statistics": policy_stats_dict,
            "engine_status": "active"
        }
    
    def clear_cache(self):
        """Clear the decision cache."""
        self.decision_cache.clear()
        logger.info("Policy decision cache cleared")
    
    def cleanup_old_data(self, max_age_hours: int = 24):
        """Clean up old audit logs and violations."""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        # Clean audit logs
        initial_audit_count = len(self.audit_logs)
        self.audit_logs = [log for log in self.audit_logs if log.timestamp > cutoff_time]
        
        # Clean violations
        initial_violation_count = len(self.violations)
        self.violations = [v for v in self.violations if v.timestamp > cutoff_time]
        
        # Clean cache
        expired_keys = []
        for key, decision in self.decision_cache.items():
            if not decision.is_valid():
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.decision_cache[key]
        
        logger.info(
            f"Cleaned up old data: "
            f"{initial_audit_count - len(self.audit_logs)} audit logs, "
            f"{initial_violation_count - len(self.violations)} violations, "
            f"{len(expired_keys)} cache entries"
        )


# Global policy engine instance
_default_policy_engine = None

def get_policy_engine() -> PolicyEngine:
    """Get or create the default policy engine instance."""
    global _default_policy_engine
    
    if _default_policy_engine is None:
        _default_policy_engine = PolicyEngine()
    
    return _default_policy_engine


# Convenience functions
async def evaluate_pii_entities(
    entities: List[Union[PIIEntity, VisualPIIEntity]],
    context: PolicyContext,
    policy_names: Optional[List[str]] = None
) -> PolicyEvaluationResult:
    """Convenience function for evaluating PII entities against policies."""
    engine = get_policy_engine()
    return await engine.evaluate_entities_async(entities, context, policy_names)


def evaluate_pii_entities_sync(
    entities: List[Union[PIIEntity, VisualPIIEntity]],
    context: PolicyContext,
    policy_names: Optional[List[str]] = None
) -> PolicyEvaluationResult:
    """Synchronous convenience function for evaluating PII entities against policies."""
    engine = get_policy_engine()
    return engine.evaluate_entities_sync(entities, context, policy_names)