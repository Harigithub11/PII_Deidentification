"""
Policy Manager for PII De-identification System

This module provides comprehensive policy configuration management, including
policy storage, versioning, validation, import/export, and template management.
"""

import logging
import json
import yaml
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Union, Tuple
from dataclasses import asdict
import uuid
import os
from collections import defaultdict

from .policy_models import (
    PolicyConfiguration, PolicyTemplate, PolicyContext, PolicyExecutionStats,
    PolicyScope, PolicyPriority, PolicyStatus, PolicyDecisionType
)
from .policies.base import BasePolicy, PolicyRule, PIIType, RedactionMethod
from .policies.gdpr import GDPRPolicy
from .policies.hipaa import HIPAAPolicy
from .policies.ndhm import NDHMPolicy
from ..database.encrypted_fields import EncryptedTextField
from ..security.encryption import encryption_manager
from .settings import get_settings

logger = logging.getLogger(__name__)


class PolicyManagerError(Exception):
    """Base exception for policy manager errors."""
    pass


class PolicyNotFoundError(PolicyManagerError):
    """Exception raised when a policy is not found."""
    pass


class PolicyValidationError(PolicyManagerError):
    """Exception raised when policy validation fails."""
    pass


class PolicyStorageError(PolicyManagerError):
    """Exception raised when policy storage operations fail."""
    pass


class PolicyManager:
    """Manages policy configurations, storage, and lifecycle operations."""
    
    def __init__(self, storage_path: Optional[str] = None):
        self.settings = get_settings()
        
        # Storage configuration
        self.storage_path = Path(storage_path) if storage_path else Path("config/policies")
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # In-memory storage
        self.policies: Dict[str, PolicyConfiguration] = {}
        self.templates: Dict[str, PolicyTemplate] = {}
        self.policy_history: Dict[str, List[PolicyConfiguration]] = defaultdict(list)
        
        # Validation rules
        self.validation_rules: Dict[str, callable] = {}
        
        # Initialize default templates and load existing policies
        self._initialize_default_templates()
        self._load_existing_policies()
        
        logger.info(f"PolicyManager initialized with storage at {self.storage_path}")
    
    def _initialize_default_templates(self):
        """Initialize default policy templates."""
        
        # GDPR Template
        gdpr_template = PolicyTemplate(
            name="GDPR Compliance Template",
            description="Template for creating GDPR-compliant policies",
            category="compliance",
            base_policy_type="gdpr",
            default_rules=[
                {
                    "pii_type": "NAME",
                    "redaction_method": "PSEUDONYMIZE",
                    "confidence_threshold": 0.9,
                    "retention_period_days": 1095
                },
                {
                    "pii_type": "EMAIL",
                    "redaction_method": "PSEUDONYMIZE",
                    "confidence_threshold": 0.8,
                    "retention_period_days": 1095
                }
            ],
            configurable_parameters={
                "retention_period_days": {"type": "int", "min": 30, "max": 3650},
                "confidence_threshold": {"type": "float", "min": 0.0, "max": 1.0},
                "enable_right_to_erasure": {"type": "bool", "default": True}
            },
            created_by="system"
        )
        self.templates["gdpr"] = gdpr_template
        
        # HIPAA Template
        hipaa_template = PolicyTemplate(
            name="HIPAA Compliance Template",
            description="Template for creating HIPAA-compliant policies",
            category="compliance",
            base_policy_type="hipaa",
            default_rules=[
                {
                    "pii_type": "NAME",
                    "redaction_method": "PSEUDONYMIZE",
                    "confidence_threshold": 0.9,
                    "retention_period_days": 2555
                },
                {
                    "pii_type": "MEDICAL_RECORD",
                    "redaction_method": "BLACKOUT",
                    "confidence_threshold": 0.95,
                    "retention_period_days": 2555
                }
            ],
            configurable_parameters={
                "minimum_necessary_standard": {"type": "bool", "default": True},
                "covered_entity_type": {"type": "enum", "values": ["healthcare_provider", "health_plan", "healthcare_clearinghouse"]}
            },
            created_by="system"
        )
        self.templates["hipaa"] = hipaa_template
        
        # Custom Template
        custom_template = PolicyTemplate(
            name="Custom Policy Template",
            description="Template for creating custom organizational policies",
            category="custom",
            base_policy_type="custom",
            default_rules=[],
            configurable_parameters={
                "organization_name": {"type": "string", "required": True},
                "policy_scope": {"type": "enum", "values": ["global", "department", "project"]},
                "approval_required": {"type": "bool", "default": False}
            },
            created_by="system"
        )
        self.templates["custom"] = custom_template
        
        logger.info(f"Initialized {len(self.templates)} default templates")
    
    def _load_existing_policies(self):
        """Load existing policies from storage."""
        try:
            policies_file = self.storage_path / "policies.json"
            if policies_file.exists():
                with open(policies_file, 'r') as f:
                    data = json.load(f)
                
                for policy_data in data.get("policies", []):
                    try:
                        policy = PolicyConfiguration(**policy_data)
                        self.policies[policy.policy_id] = policy
                    except Exception as e:
                        logger.error(f"Failed to load policy {policy_data.get('name', 'unknown')}: {e}")
                
                logger.info(f"Loaded {len(self.policies)} policies from storage")
        
        except Exception as e:
            logger.error(f"Failed to load existing policies: {e}")
    
    def save_policies(self):
        """Save all policies to persistent storage."""
        try:
            policies_file = self.storage_path / "policies.json"
            
            data = {
                "policies": [asdict(policy) for policy in self.policies.values()],
                "last_updated": datetime.now().isoformat()
            }
            
            with open(policies_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Saved {len(self.policies)} policies to storage")
            
        except Exception as e:
            logger.error(f"Failed to save policies: {e}")
            raise PolicyStorageError(f"Failed to save policies: {e}")
    
    def create_policy(
        self,
        name: str,
        policy_type: str,
        description: str = "",
        template_id: Optional[str] = None,
        configuration: Optional[Dict[str, Any]] = None,
        created_by: Optional[str] = None
    ) -> PolicyConfiguration:
        """Create a new policy configuration."""
        
        try:
            policy_id = str(uuid.uuid4())
            
            # Use template if provided
            if template_id and template_id in self.templates:
                template = self.templates[template_id]
                policy = template.create_policy(name, configuration or {})
                policy.policy_id = policy_id
                policy.created_by = created_by
                policy.description = description or policy.description
            else:
                # Create from scratch
                policy = PolicyConfiguration(
                    policy_id=policy_id,
                    name=name,
                    description=description,
                    policy_type=policy_type,
                    policy_data=configuration or {},
                    created_by=created_by
                )
            
            # Validate policy
            validation_errors = self.validate_policy(policy)
            if validation_errors:
                raise PolicyValidationError(f"Policy validation failed: {validation_errors}")
            
            # Store policy
            self.policies[policy_id] = policy
            self.policy_history[policy_id].append(policy)
            
            # Save to persistent storage
            self.save_policies()
            
            logger.info(f"Created policy: {name} (ID: {policy_id})")
            return policy
            
        except Exception as e:
            logger.error(f"Failed to create policy {name}: {e}")
            raise PolicyManagerError(f"Failed to create policy: {e}")
    
    def get_policy(self, policy_id: str) -> Optional[PolicyConfiguration]:
        """Get a policy by ID."""
        return self.policies.get(policy_id)
    
    def get_policy_by_name(self, name: str) -> Optional[PolicyConfiguration]:
        """Get a policy by name."""
        for policy in self.policies.values():
            if policy.name == name:
                return policy
        return None
    
    def update_policy(
        self,
        policy_id: str,
        updates: Dict[str, Any],
        updated_by: Optional[str] = None
    ) -> PolicyConfiguration:
        """Update an existing policy."""
        
        if policy_id not in self.policies:
            raise PolicyNotFoundError(f"Policy {policy_id} not found")
        
        try:
            policy = self.policies[policy_id]
            
            # Create a copy for history
            old_policy = PolicyConfiguration(**asdict(policy))
            self.policy_history[policy_id].append(old_policy)
            
            # Apply updates
            for key, value in updates.items():
                if hasattr(policy, key):
                    setattr(policy, key, value)
            
            policy.updated_by = updated_by
            policy.updated_at = datetime.now()
            
            # Validate updated policy
            validation_errors = self.validate_policy(policy)
            if validation_errors:
                # Rollback
                self.policies[policy_id] = old_policy
                self.policy_history[policy_id].pop()
                raise PolicyValidationError(f"Policy validation failed: {validation_errors}")
            
            # Save to persistent storage
            self.save_policies()
            
            logger.info(f"Updated policy: {policy.name} (ID: {policy_id})")
            return policy
            
        except Exception as e:
            logger.error(f"Failed to update policy {policy_id}: {e}")
            raise PolicyManagerError(f"Failed to update policy: {e}")
    
    def delete_policy(self, policy_id: str, deleted_by: Optional[str] = None) -> bool:
        """Delete a policy (soft delete by marking as inactive)."""
        
        if policy_id not in self.policies:
            raise PolicyNotFoundError(f"Policy {policy_id} not found")
        
        try:
            policy = self.policies[policy_id]
            
            # Soft delete - mark as inactive
            policy.status = PolicyStatus.INACTIVE
            policy.updated_by = deleted_by
            policy.updated_at = datetime.now()
            
            # Save to persistent storage
            self.save_policies()
            
            logger.info(f"Deleted policy: {policy.name} (ID: {policy_id})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete policy {policy_id}: {e}")
            raise PolicyManagerError(f"Failed to delete policy: {e}")
    
    def list_policies(
        self,
        scope: Optional[PolicyScope] = None,
        status: Optional[PolicyStatus] = None,
        policy_type: Optional[str] = None
    ) -> List[PolicyConfiguration]:
        """List policies with optional filtering."""
        
        policies = list(self.policies.values())
        
        # Apply filters
        if scope:
            policies = [p for p in policies if p.scope == scope]
        
        if status:
            policies = [p for p in policies if p.status == status]
        
        if policy_type:
            policies = [p for p in policies if p.policy_type == policy_type]
        
        # Sort by priority and name
        policies.sort(key=lambda p: (p.priority.value, p.name), reverse=True)
        
        return policies
    
    def validate_policy(self, policy: PolicyConfiguration) -> List[str]:
        """Validate a policy configuration."""
        errors = []
        
        # Basic validation
        if not policy.name or not policy.name.strip():
            errors.append("Policy name is required")
        
        if not policy.policy_type or not policy.policy_type.strip():
            errors.append("Policy type is required")
        
        # Check for duplicate names (excluding same policy)
        for other_policy in self.policies.values():
            if (other_policy.policy_id != policy.policy_id and 
                other_policy.name == policy.name and 
                other_policy.status == PolicyStatus.ACTIVE):
                errors.append(f"Policy name '{policy.name}' already exists")
                break
        
        # Validate effective dates
        if policy.effective_from and policy.effective_until:
            if policy.effective_from >= policy.effective_until:
                errors.append("Effective from date must be before effective until date")
        
        # Validate policy data based on type
        if policy.policy_type in self.validation_rules:
            validator = self.validation_rules[policy.policy_type]
            try:
                validator(policy.policy_data)
            except Exception as e:
                errors.append(f"Policy data validation failed: {e}")
        
        return errors
    
    def export_policy(self, policy_id: str, format: str = "json") -> str:
        """Export a policy configuration."""
        
        if policy_id not in self.policies:
            raise PolicyNotFoundError(f"Policy {policy_id} not found")
        
        policy = self.policies[policy_id]
        
        if format.lower() == "json":
            return json.dumps(asdict(policy), indent=2, default=str)
        elif format.lower() == "yaml":
            return yaml.dump(asdict(policy), default_flow_style=False)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def import_policy(
        self,
        data: str,
        format: str = "json",
        imported_by: Optional[str] = None
    ) -> PolicyConfiguration:
        """Import a policy configuration."""
        
        try:
            if format.lower() == "json":
                policy_data = json.loads(data)
            elif format.lower() == "yaml":
                policy_data = yaml.safe_load(data)
            else:
                raise ValueError(f"Unsupported import format: {format}")
            
            # Generate new ID and update metadata
            policy_data["policy_id"] = str(uuid.uuid4())
            policy_data["created_by"] = imported_by
            policy_data["created_at"] = datetime.now()
            policy_data["updated_by"] = None
            policy_data["updated_at"] = None
            
            policy = PolicyConfiguration(**policy_data)
            
            # Validate policy
            validation_errors = self.validate_policy(policy)
            if validation_errors:
                raise PolicyValidationError(f"Imported policy validation failed: {validation_errors}")
            
            # Store policy
            self.policies[policy.policy_id] = policy
            self.policy_history[policy.policy_id].append(policy)
            
            # Save to persistent storage
            self.save_policies()
            
            logger.info(f"Imported policy: {policy.name} (ID: {policy.policy_id})")
            return policy
            
        except Exception as e:
            logger.error(f"Failed to import policy: {e}")
            raise PolicyManagerError(f"Failed to import policy: {e}")
    
    def clone_policy(
        self,
        policy_id: str,
        new_name: str,
        cloned_by: Optional[str] = None
    ) -> PolicyConfiguration:
        """Clone an existing policy."""
        
        if policy_id not in self.policies:
            raise PolicyNotFoundError(f"Policy {policy_id} not found")
        
        source_policy = self.policies[policy_id]
        
        # Create clone data
        clone_data = asdict(source_policy)
        clone_data["policy_id"] = str(uuid.uuid4())
        clone_data["name"] = new_name
        clone_data["description"] = f"Clone of {source_policy.name}"
        clone_data["created_by"] = cloned_by
        clone_data["created_at"] = datetime.now()
        clone_data["updated_by"] = None
        clone_data["updated_at"] = None
        clone_data["status"] = PolicyStatus.DRAFT
        
        cloned_policy = PolicyConfiguration(**clone_data)
        
        # Store policy
        self.policies[cloned_policy.policy_id] = cloned_policy
        self.policy_history[cloned_policy.policy_id].append(cloned_policy)
        
        # Save to persistent storage
        self.save_policies()
        
        logger.info(f"Cloned policy: {new_name} from {source_policy.name}")
        return cloned_policy
    
    def get_policy_history(self, policy_id: str) -> List[PolicyConfiguration]:
        """Get the version history of a policy."""
        return self.policy_history.get(policy_id, [])
    
    def rollback_policy(self, policy_id: str, version_index: int) -> PolicyConfiguration:
        """Rollback a policy to a previous version."""
        
        if policy_id not in self.policies:
            raise PolicyNotFoundError(f"Policy {policy_id} not found")
        
        history = self.policy_history.get(policy_id, [])
        if version_index < 0 or version_index >= len(history):
            raise ValueError(f"Invalid version index: {version_index}")
        
        # Get the version to rollback to
        rollback_version = history[version_index]
        
        # Create new version based on rollback
        current_policy = self.policies[policy_id]
        rollback_data = asdict(rollback_version)
        rollback_data["updated_at"] = datetime.now()
        rollback_data["version"] = f"{rollback_version.version}-rollback"
        
        new_policy = PolicyConfiguration(**rollback_data)
        
        # Update current policy
        self.policies[policy_id] = new_policy
        self.policy_history[policy_id].append(current_policy)  # Save current as history
        
        # Save to persistent storage
        self.save_policies()
        
        logger.info(f"Rolled back policy {policy_id} to version {version_index}")
        return new_policy
    
    def get_templates(self) -> List[PolicyTemplate]:
        """Get all available policy templates."""
        return list(self.templates.values())
    
    def create_template(self, template: PolicyTemplate) -> PolicyTemplate:
        """Create a new policy template."""
        self.templates[template.template_id] = template
        logger.info(f"Created policy template: {template.name}")
        return template
    
    def apply_policy_context(
        self,
        policy_id: str,
        context: PolicyContext
    ) -> Tuple[bool, List[str]]:
        """Check if a policy applies to a given context."""
        
        if policy_id not in self.policies:
            return False, [f"Policy {policy_id} not found"]
        
        policy = self.policies[policy_id]
        
        if not policy.is_active():
            return False, ["Policy is not active"]
        
        if not policy.matches_context(context):
            return False, ["Policy scope does not match context"]
        
        return True, []
    
    def get_applicable_policies(self, context: PolicyContext) -> List[PolicyConfiguration]:
        """Get all policies applicable to a given context."""
        applicable = []
        
        for policy in self.policies.values():
            if policy.is_active() and policy.matches_context(context):
                applicable.append(policy)
        
        # Sort by priority
        applicable.sort(key=lambda p: p.priority.value, reverse=True)
        
        return applicable
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get policy manager statistics."""
        
        total_policies = len(self.policies)
        active_policies = len([p for p in self.policies.values() if p.status == PolicyStatus.ACTIVE])
        
        # Group by type
        policy_types = defaultdict(int)
        for policy in self.policies.values():
            policy_types[policy.policy_type] += 1
        
        # Group by scope
        policy_scopes = defaultdict(int)
        for policy in self.policies.values():
            policy_scopes[policy.scope.value] += 1
        
        return {
            "total_policies": total_policies,
            "active_policies": active_policies,
            "inactive_policies": total_policies - active_policies,
            "policy_types": dict(policy_types),
            "policy_scopes": dict(policy_scopes),
            "available_templates": len(self.templates),
            "storage_path": str(self.storage_path)
        }
    
    def cleanup_old_versions(self, keep_versions: int = 10):
        """Clean up old policy versions."""
        cleaned_count = 0
        
        for policy_id, history in self.policy_history.items():
            if len(history) > keep_versions:
                # Keep only the most recent versions
                self.policy_history[policy_id] = history[-keep_versions:]
                cleaned_count += len(history) - keep_versions
        
        logger.info(f"Cleaned up {cleaned_count} old policy versions")
        return cleaned_count


# Global policy manager instance
_default_policy_manager = None

def get_policy_manager() -> PolicyManager:
    """Get or create the default policy manager instance."""
    global _default_policy_manager
    
    if _default_policy_manager is None:
        _default_policy_manager = PolicyManager()
    
    return _default_policy_manager