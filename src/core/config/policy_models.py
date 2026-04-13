"""
Enhanced Policy Models for Configurable Policy Engine

This module provides advanced data models for policy management, execution context,
decision tracking, and audit logging in the PII de-identification system.
"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from pydantic import BaseModel, Field, validator

from .policies.base import BasePolicy, PolicyRule, PIIType, RedactionMethod


class PolicyScope(str, Enum):
    """Scope of policy application."""
    GLOBAL = "global"
    DOCUMENT = "document"
    USER = "user"
    ORGANIZATION = "organization"
    PROJECT = "project"
    TEMPORARY = "temporary"


class PolicyPriority(int, Enum):
    """Policy priority levels for conflict resolution."""
    LOWEST = 1
    LOW = 2
    NORMAL = 3
    HIGH = 4
    HIGHEST = 5
    CRITICAL = 10


class PolicyDecisionType(str, Enum):
    """Types of policy decisions."""
    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    ANONYMIZE = "anonymize"
    PSEUDONYMIZE = "pseudonymize"
    FLAG = "flag"
    AUDIT_ONLY = "audit_only"


class PolicyViolationType(str, Enum):
    """Types of policy violations."""
    DETECTION_THRESHOLD = "detection_threshold"
    RETENTION_PERIOD = "retention_period"
    REDACTION_REQUIRED = "redaction_required"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    COMPLIANCE_BREACH = "compliance_breach"
    CONFIGURATION_ERROR = "configuration_error"


class PolicyStatus(str, Enum):
    """Policy status states."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"
    DEPRECATED = "deprecated"
    SUSPENDED = "suspended"


@dataclass
class PolicyContext:
    """Execution context for policy evaluation."""
    
    # Request context
    document_id: Optional[str] = None
    user_id: Optional[str] = None
    organization_id: Optional[str] = None
    project_id: Optional[str] = None
    session_id: Optional[str] = None
    
    # Document context
    document_type: Optional[str] = None
    document_classification: Optional[str] = None
    document_source: Optional[str] = None
    document_tags: List[str] = field(default_factory=list)
    
    # Processing context
    processing_mode: Optional[str] = None
    confidence_level: float = 0.0
    detected_entities: List[str] = field(default_factory=list)
    
    # Temporal context
    timestamp: datetime = field(default_factory=datetime.now)
    timezone: str = "UTC"
    
    # Compliance context
    compliance_standards: List[str] = field(default_factory=list)
    data_classification: Optional[str] = None
    retention_requirements: Optional[int] = None
    
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def matches_scope(self, scope: PolicyScope, scope_value: Optional[str] = None) -> bool:
        """Check if context matches a policy scope."""
        if scope == PolicyScope.GLOBAL:
            return True
        elif scope == PolicyScope.DOCUMENT and scope_value:
            return self.document_id == scope_value
        elif scope == PolicyScope.USER and scope_value:
            return self.user_id == scope_value
        elif scope == PolicyScope.ORGANIZATION and scope_value:
            return self.organization_id == scope_value
        elif scope == PolicyScope.PROJECT and scope_value:
            return self.project_id == scope_value
        return False
    
    def get_context_hash(self) -> str:
        """Generate a hash for caching policy decisions."""
        key_data = f"{self.document_type}:{self.user_id}:{self.organization_id}:{':'.join(sorted(self.compliance_standards))}"
        return str(hash(key_data))


@dataclass
class PolicyDecision:
    """Result of policy evaluation for a specific PII entity."""
    
    # Entity information (required fields first)
    pii_type: PIIType
    entity_text: str
    applied_policy: str
    
    # Decision details (optional fields with defaults)
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    decision_type: PolicyDecisionType = PolicyDecisionType.ALLOW
    confidence: float = 1.0
    entity_position: Optional[Dict[str, int]] = None
    applied_rule: Optional[str] = None
    policy_priority: PolicyPriority = PolicyPriority.NORMAL
    
    # Action details
    redaction_method: Optional[RedactionMethod] = None
    replacement_value: Optional[str] = None
    anonymization_params: Dict[str, Any] = field(default_factory=dict)
    
    # Context and reasoning
    context: Optional[PolicyContext] = None
    reasoning: str = ""
    alternative_actions: List[str] = field(default_factory=list)
    
    # Compliance and audit
    compliance_flags: List[str] = field(default_factory=list)
    audit_required: bool = False
    approval_required: bool = False
    
    # Timing
    timestamp: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    
    def is_valid(self) -> bool:
        """Check if the decision is still valid."""
        if self.expires_at:
            return datetime.now() < self.expires_at
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert decision to dictionary format."""
        return {
            "decision_id": self.decision_id,
            "decision_type": self.decision_type.value,
            "confidence": self.confidence,
            "pii_type": self.pii_type.value,
            "entity_text": self.entity_text,
            "applied_policy": self.applied_policy,
            "applied_rule": self.applied_rule,
            "redaction_method": self.redaction_method.value if self.redaction_method else None,
            "reasoning": self.reasoning,
            "compliance_flags": self.compliance_flags,
            "timestamp": self.timestamp.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None
        }


@dataclass
class PolicyViolation:
    """Record of a policy violation or compliance issue."""
    
    # Required fields first
    violation_type: PolicyViolationType
    violated_policy: str
    description: str
    expected_action: str
    actual_action: str
    
    # Optional fields with defaults
    violation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: PolicyPriority = PolicyPriority.NORMAL
    pii_type: Optional[PIIType] = None
    violated_rule: Optional[str] = None
    context: Optional[PolicyContext] = None
    entity_details: Dict[str, Any] = field(default_factory=dict)
    
    # Resolution
    resolved: bool = False
    resolution_action: Optional[str] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    
    # Audit and tracking
    timestamp: datetime = field(default_factory=datetime.now)
    reported_by: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    
    def resolve(self, action: str, resolved_by: str):
        """Mark violation as resolved."""
        self.resolved = True
        self.resolution_action = action
        self.resolved_by = resolved_by
        self.resolved_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert violation to dictionary format."""
        return {
            "violation_id": self.violation_id,
            "violation_type": self.violation_type.value,
            "severity": self.severity.value,
            "pii_type": self.pii_type.value if self.pii_type else None,
            "violated_policy": self.violated_policy,
            "description": self.description,
            "expected_action": self.expected_action,
            "actual_action": self.actual_action,
            "resolved": self.resolved,
            "timestamp": self.timestamp.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None
        }


@dataclass
class PolicyAuditLog:
    """Audit log entry for policy-related actions."""

    # Log entry details (required fields first)
    action: str
    resource_type: str
    resource_id: str
    log_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # Actor information
    user_id: Optional[str] = None
    system_component: Optional[str] = None
    
    # Context and details
    context: Optional[PolicyContext] = None
    policy_name: Optional[str] = None
    rule_details: Dict[str, Any] = field(default_factory=dict)
    
    # Outcome
    success: bool = True
    error_message: Optional[str] = None
    changes_made: Dict[str, Any] = field(default_factory=dict)
    
    # Timing and tracking
    timestamp: datetime = field(default_factory=datetime.now)
    duration_ms: Optional[float] = None
    correlation_id: Optional[str] = None
    
    # Compliance
    compliance_relevant: bool = False
    retention_period_days: int = 2555  # 7 years default
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit log to dictionary format."""
        return {
            "log_id": self.log_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "user_id": self.user_id,
            "system_component": self.system_component,
            "policy_name": self.policy_name,
            "success": self.success,
            "error_message": self.error_message,
            "timestamp": self.timestamp.isoformat(),
            "compliance_relevant": self.compliance_relevant
        }


class PolicyConfiguration(BaseModel):
    """Configuration model for policy management."""
    
    # Basic information
    policy_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    version: str = "1.0.0"
    
    # Policy details
    policy_type: str  # GDPR, HIPAA, custom, etc.
    scope: PolicyScope = PolicyScope.GLOBAL
    scope_value: Optional[str] = None
    priority: PolicyPriority = PolicyPriority.NORMAL
    status: PolicyStatus = PolicyStatus.ACTIVE
    
    # Rules and configuration
    policy_data: Dict[str, Any] = Field(default_factory=dict)
    rule_overrides: Dict[str, Any] = Field(default_factory=dict)
    exceptions: List[str] = Field(default_factory=list)
    
    # Metadata
    created_by: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_by: Optional[str] = None
    updated_at: Optional[datetime] = None
    
    # Effective dates
    effective_from: Optional[datetime] = None
    effective_until: Optional[datetime] = None
    
    # Tags and categorization
    tags: List[str] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)
    
    @validator('priority')
    def validate_priority(cls, v):
        if isinstance(v, int):
            return PolicyPriority(v)
        return v
    
    def is_active(self) -> bool:
        """Check if policy is currently active."""
        if self.status != PolicyStatus.ACTIVE:
            return False
        
        now = datetime.now()
        if self.effective_from and now < self.effective_from:
            return False
        if self.effective_until and now > self.effective_until:
            return False
        
        return True
    
    def matches_context(self, context: PolicyContext) -> bool:
        """Check if policy applies to given context."""
        if not self.is_active():
            return False
        
        return context.matches_scope(self.scope, self.scope_value)


@dataclass
class PolicyTemplate:
    """Template for creating new policies."""

    # Required fields first
    name: str
    description: str
    category: str  # compliance, custom, organizational
    base_policy_type: str
    created_by: str

    # Fields with defaults
    template_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    default_rules: List[Dict[str, Any]] = field(default_factory=list)
    configurable_parameters: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    usage_count: int = 0
    
    def create_policy(self, name: str, configuration: Dict[str, Any]) -> PolicyConfiguration:
        """Create a new policy from this template."""
        policy = PolicyConfiguration(
            name=name,
            description=f"Policy created from template: {self.name}",
            policy_type=self.base_policy_type,
            policy_data=configuration
        )
        
        self.usage_count += 1
        return policy


@dataclass
class PolicyExecutionStats:
    """Statistics for policy execution performance."""
    
    policy_name: str
    total_evaluations: int = 0
    successful_evaluations: int = 0
    failed_evaluations: int = 0
    
    # Timing statistics
    total_execution_time_ms: float = 0.0
    average_execution_time_ms: float = 0.0
    min_execution_time_ms: float = float('inf')
    max_execution_time_ms: float = 0.0
    
    # Decision statistics
    decision_counts: Dict[PolicyDecisionType, int] = field(default_factory=dict)
    violation_counts: Dict[PolicyViolationType, int] = field(default_factory=dict)
    
    # Last update
    last_updated: datetime = field(default_factory=datetime.now)
    
    def add_execution(self, execution_time_ms: float, decision_type: PolicyDecisionType, success: bool = True):
        """Add execution statistics."""
        self.total_evaluations += 1
        
        if success:
            self.successful_evaluations += 1
        else:
            self.failed_evaluations += 1
        
        # Update timing stats
        self.total_execution_time_ms += execution_time_ms
        self.average_execution_time_ms = self.total_execution_time_ms / self.total_evaluations
        self.min_execution_time_ms = min(self.min_execution_time_ms, execution_time_ms)
        self.max_execution_time_ms = max(self.max_execution_time_ms, execution_time_ms)
        
        # Update decision counts
        if decision_type not in self.decision_counts:
            self.decision_counts[decision_type] = 0
        self.decision_counts[decision_type] += 1
        
        self.last_updated = datetime.now()
    
    def get_success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_evaluations == 0:
            return 0.0
        return self.successful_evaluations / self.total_evaluations
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary format."""
        return {
            "policy_name": self.policy_name,
            "total_evaluations": self.total_evaluations,
            "success_rate": self.get_success_rate(),
            "average_execution_time_ms": self.average_execution_time_ms,
            "decision_distribution": {k.value: v for k, v in self.decision_counts.items()},
            "last_updated": self.last_updated.isoformat()
        }