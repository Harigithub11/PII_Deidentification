"""
Policy Management API Endpoints

FastAPI endpoints for policy configuration, management, templates, and enforcement
with comprehensive validation, error handling, and security features.
"""

import logging
import tempfile
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query, status, UploadFile, File
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, validator
from enum import Enum
import io
import json

from ..core.config.policy_manager import PolicyManager, get_policy_manager
from ..core.config.policy_models import (
    PolicyConfiguration, PolicyTemplate, PolicyContext, PolicyExecutionStats,
    PolicyScope, PolicyPriority, PolicyStatus, PolicyDecisionType
)
from ..core.services.policy_engine import PolicyEngine, get_policy_engine
from ..core.config.policies.base import BasePolicy, PolicyRule, PIIType, RedactionMethod
from ..core.security.dependencies import (
    get_current_active_user,
    require_write_permission,
    require_read_permission,
    require_admin_permission
)

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/policies", tags=["Policy Management"])

# Global instances
policy_manager = None
policy_engine = None


def get_policy_manager_instance():
    """Get policy manager instance."""
    global policy_manager
    if policy_manager is None:
        policy_manager = get_policy_manager()
    return policy_manager


def get_policy_engine_instance():
    """Get policy engine instance."""
    global policy_engine
    if policy_engine is None:
        policy_engine = get_policy_engine()
    return policy_engine


# Request/Response Models
class PolicyScopeEnum(str, Enum):
    """Policy scope enumeration for API."""
    global_scope = "global"
    document = "document"
    user = "user"
    organization = "organization"
    project = "project"
    temporary = "temporary"


class PolicyPriorityEnum(str, Enum):
    """Policy priority enumeration for API."""
    lowest = "1"
    low = "2"
    normal = "3"
    high = "4"
    highest = "5"
    critical = "10"


class PolicyStatusEnum(str, Enum):
    """Policy status enumeration for API."""
    active = "active"
    inactive = "inactive"
    draft = "draft"
    deprecated = "deprecated"
    suspended = "suspended"


class CreatePolicyRequest(BaseModel):
    """Request model for creating a new policy."""
    name: str = Field(..., min_length=1, max_length=100, description="Policy name")
    description: str = Field("", max_length=500, description="Policy description")
    policy_type: str = Field(..., description="Type of policy (gdpr, hipaa, custom, etc.)")
    
    # Configuration
    scope: PolicyScopeEnum = PolicyScopeEnum.global_scope
    scope_value: Optional[str] = Field(None, description="Scope-specific value")
    priority: PolicyPriorityEnum = PolicyPriorityEnum.normal
    
    # Template and configuration
    template_id: Optional[str] = Field(None, description="Template to base policy on")
    configuration: Dict[str, Any] = Field(default_factory=dict, description="Policy configuration data")
    
    # Rules
    rules: List[Dict[str, Any]] = Field(default_factory=list, description="Policy rules")
    exceptions: List[str] = Field(default_factory=list, description="Policy exceptions")
    
    # Metadata
    tags: List[str] = Field(default_factory=list, description="Policy tags")
    categories: List[str] = Field(default_factory=list, description="Policy categories")
    
    @validator('name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError("Policy name cannot be empty")
        return v.strip()


class UpdatePolicyRequest(BaseModel):
    """Request model for updating an existing policy."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    scope: Optional[PolicyScopeEnum] = None
    scope_value: Optional[str] = None
    priority: Optional[PolicyPriorityEnum] = None
    status: Optional[PolicyStatusEnum] = None
    
    configuration: Optional[Dict[str, Any]] = None
    rules: Optional[List[Dict[str, Any]]] = None
    exceptions: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    categories: Optional[List[str]] = None


class PolicyResponse(BaseModel):
    """Response model for policy operations."""
    policy_id: str
    name: str
    description: str
    policy_type: str
    scope: str
    scope_value: Optional[str]
    priority: int
    status: str
    
    created_by: Optional[str]
    created_at: datetime
    updated_by: Optional[str]
    updated_at: Optional[datetime]
    
    effective_from: Optional[datetime]
    effective_until: Optional[datetime]
    
    tags: List[str]
    categories: List[str]
    
    # Rule summary
    rule_count: int = 0
    exception_count: int = 0


class PolicyListResponse(BaseModel):
    """Response model for policy list operations."""
    policies: List[PolicyResponse]
    total: int
    page: int
    page_size: int
    has_more: bool


class PolicyTemplateResponse(BaseModel):
    """Response model for policy templates."""
    template_id: str
    name: str
    description: str
    category: str
    base_policy_type: str
    usage_count: int
    created_by: str
    created_at: datetime


class PolicyValidationResponse(BaseModel):
    """Response model for policy validation."""
    valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class PolicyEvaluationRequest(BaseModel):
    """Request model for policy evaluation testing."""
    entities: List[Dict[str, Any]] = Field(..., description="PII entities to evaluate")
    context: Dict[str, Any] = Field(default_factory=dict, description="Evaluation context")
    policy_names: Optional[List[str]] = Field(None, description="Specific policies to test")


class PolicyEvaluationResponse(BaseModel):
    """Response model for policy evaluation results."""
    evaluation_id: str
    success: bool
    total_entities: int
    decisions: List[Dict[str, Any]]
    violations: List[Dict[str, Any]]
    execution_time_ms: float
    policies_evaluated: List[str]


# API Endpoints

@router.post(
    "/",
    response_model=PolicyResponse,
    summary="Create a new policy",
    description="Create a new policy configuration with validation"
)
async def create_policy(
    request: CreatePolicyRequest,
    current_user=Depends(get_current_active_user),
    _=Depends(require_write_permission)
):
    """Create a new policy configuration."""
    
    try:
        manager = get_policy_manager_instance()
        
        # Create policy
        policy = manager.create_policy(
            name=request.name,
            policy_type=request.policy_type,
            description=request.description,
            template_id=request.template_id,
            configuration=request.configuration,
            created_by=current_user.get("user_id") if current_user else None
        )
        
        # Update additional fields
        updates = {}
        if request.scope != PolicyScopeEnum.global_scope:
            updates["scope"] = PolicyScope(request.scope.value)
            updates["scope_value"] = request.scope_value
        
        if request.priority != PolicyPriorityEnum.normal:
            updates["priority"] = PolicyPriority(int(request.priority.value))
        
        if request.tags:
            updates["tags"] = request.tags
        
        if request.categories:
            updates["categories"] = request.categories
        
        if updates:
            policy = manager.update_policy(
                policy.policy_id,
                updates,
                current_user.get("user_id") if current_user else None
            )
        
        # Convert to response format
        response = PolicyResponse(
            policy_id=policy.policy_id,
            name=policy.name,
            description=policy.description,
            policy_type=policy.policy_type,
            scope=policy.scope.value,
            scope_value=policy.scope_value,
            priority=policy.priority.value,
            status=policy.status.value,
            created_by=policy.created_by,
            created_at=policy.created_at,
            updated_by=policy.updated_by,
            updated_at=policy.updated_at,
            effective_from=policy.effective_from,
            effective_until=policy.effective_until,
            tags=policy.tags,
            categories=policy.categories,
            rule_count=len(request.rules),
            exception_count=len(request.exceptions)
        )
        
        logger.info(f"Created policy: {policy.name} by {current_user.get('user_id', 'unknown')}")
        return response
        
    except Exception as e:
        logger.error(f"Error creating policy: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get(
    "/",
    response_model=PolicyListResponse,
    summary="List policies",
    description="Get a list of policies with optional filtering"
)
async def list_policies(
    scope: Optional[PolicyScopeEnum] = Query(None, description="Filter by scope"),
    status: Optional[PolicyStatusEnum] = Query(None, description="Filter by status"),
    policy_type: Optional[str] = Query(None, description="Filter by policy type"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user=Depends(get_current_active_user),
    _=Depends(require_read_permission)
):
    """List policies with optional filtering and pagination."""
    
    try:
        manager = get_policy_manager_instance()
        
        # Apply filters
        filters = {}
        if scope:
            filters["scope"] = PolicyScope(scope.value)
        if status:
            filters["status"] = PolicyStatus(status.value)
        if policy_type:
            filters["policy_type"] = policy_type
        
        policies = manager.list_policies(**filters)
        
        # Apply pagination
        total = len(policies)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_policies = policies[start_idx:end_idx]
        
        # Convert to response format
        policy_responses = []
        for policy in page_policies:
            response = PolicyResponse(
                policy_id=policy.policy_id,
                name=policy.name,
                description=policy.description,
                policy_type=policy.policy_type,
                scope=policy.scope.value,
                scope_value=policy.scope_value,
                priority=policy.priority.value,
                status=policy.status.value,
                created_by=policy.created_by,
                created_at=policy.created_at,
                updated_by=policy.updated_by,
                updated_at=policy.updated_at,
                effective_from=policy.effective_from,
                effective_until=policy.effective_until,
                tags=policy.tags,
                categories=policy.categories
            )
            policy_responses.append(response)
        
        return PolicyListResponse(
            policies=policy_responses,
            total=total,
            page=page,
            page_size=page_size,
            has_more=end_idx < total
        )
        
    except Exception as e:
        logger.error(f"Error listing policies: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/{policy_id}",
    response_model=PolicyResponse,
    summary="Get policy by ID",
    description="Retrieve a specific policy configuration"
)
async def get_policy(
    policy_id: str,
    current_user=Depends(get_current_active_user),
    _=Depends(require_read_permission)
):
    """Get a specific policy by ID."""
    
    try:
        manager = get_policy_manager_instance()
        policy = manager.get_policy(policy_id)
        
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        
        response = PolicyResponse(
            policy_id=policy.policy_id,
            name=policy.name,
            description=policy.description,
            policy_type=policy.policy_type,
            scope=policy.scope.value,
            scope_value=policy.scope_value,
            priority=policy.priority.value,
            status=policy.status.value,
            created_by=policy.created_by,
            created_at=policy.created_at,
            updated_by=policy.updated_by,
            updated_at=policy.updated_at,
            effective_from=policy.effective_from,
            effective_until=policy.effective_until,
            tags=policy.tags,
            categories=policy.categories
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting policy {policy_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put(
    "/{policy_id}",
    response_model=PolicyResponse,
    summary="Update policy",
    description="Update an existing policy configuration"
)
async def update_policy(
    policy_id: str,
    request: UpdatePolicyRequest,
    current_user=Depends(get_current_active_user),
    _=Depends(require_write_permission)
):
    """Update an existing policy."""
    
    try:
        manager = get_policy_manager_instance()
        
        # Prepare updates
        updates = {}
        for field, value in request.dict(exclude_unset=True).items():
            if field == "scope" and value:
                updates["scope"] = PolicyScope(value.value)
            elif field == "priority" and value:
                updates["priority"] = PolicyPriority(int(value.value))
            elif field == "status" and value:
                updates["status"] = PolicyStatus(value.value)
            elif value is not None:
                updates[field] = value
        
        # Update policy
        policy = manager.update_policy(
            policy_id,
            updates,
            current_user.get("user_id") if current_user else None
        )
        
        response = PolicyResponse(
            policy_id=policy.policy_id,
            name=policy.name,
            description=policy.description,
            policy_type=policy.policy_type,
            scope=policy.scope.value,
            scope_value=policy.scope_value,
            priority=policy.priority.value,
            status=policy.status.value,
            created_by=policy.created_by,
            created_at=policy.created_at,
            updated_by=policy.updated_by,
            updated_at=policy.updated_at,
            effective_from=policy.effective_from,
            effective_until=policy.effective_until,
            tags=policy.tags,
            categories=policy.categories
        )
        
        logger.info(f"Updated policy: {policy.name} by {current_user.get('user_id', 'unknown')}")
        return response
        
    except Exception as e:
        logger.error(f"Error updating policy {policy_id}: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.delete(
    "/{policy_id}",
    summary="Delete policy",
    description="Delete (deactivate) a policy"
)
async def delete_policy(
    policy_id: str,
    current_user=Depends(get_current_active_user),
    _=Depends(require_write_permission)
):
    """Delete (deactivate) a policy."""
    
    try:
        manager = get_policy_manager_instance()
        success = manager.delete_policy(
            policy_id,
            current_user.get("user_id") if current_user else None
        )
        
        if success:
            logger.info(f"Deleted policy: {policy_id} by {current_user.get('user_id', 'unknown')}")
            return {"message": "Policy deleted successfully"}
        else:
            raise HTTPException(status_code=404, detail="Policy not found")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting policy {policy_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/{policy_id}/validate",
    response_model=PolicyValidationResponse,
    summary="Validate policy",
    description="Validate a policy configuration"
)
async def validate_policy(
    policy_id: str,
    current_user=Depends(get_current_active_user),
    _=Depends(require_read_permission)
):
    """Validate a policy configuration."""
    
    try:
        manager = get_policy_manager_instance()
        policy = manager.get_policy(policy_id)
        
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        
        errors = manager.validate_policy(policy)
        
        return PolicyValidationResponse(
            valid=len(errors) == 0,
            errors=errors,
            warnings=[]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating policy {policy_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/{policy_id}/test",
    response_model=PolicyEvaluationResponse,
    summary="Test policy evaluation",
    description="Test policy evaluation with sample entities"
)
async def test_policy_evaluation(
    policy_id: str,
    request: PolicyEvaluationRequest,
    current_user=Depends(get_current_active_user),
    _=Depends(require_read_permission)
):
    """Test policy evaluation with sample entities."""
    
    try:
        engine = get_policy_engine_instance()
        
        # Create mock entities from request
        # This would need proper entity conversion based on the actual entity types
        mock_entities = []  # Convert request.entities to actual entity objects
        
        # Create context
        context = PolicyContext(**request.context)
        
        # Evaluate
        result = await engine.evaluate_entities_async(
            entities=mock_entities,
            context=context,
            policy_names=[policy_id] if not request.policy_names else request.policy_names
        )
        
        return PolicyEvaluationResponse(
            evaluation_id=result.request_id,
            success=result.success,
            total_entities=len(mock_entities),
            decisions=[d.to_dict() for d in result.decisions],
            violations=[v.to_dict() for v in result.violations],
            execution_time_ms=result.execution_time_ms,
            policies_evaluated=request.policy_names or [policy_id]
        )
        
    except Exception as e:
        logger.error(f"Error testing policy evaluation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/templates/",
    response_model=List[PolicyTemplateResponse],
    summary="List policy templates",
    description="Get available policy templates"
)
async def list_policy_templates(
    current_user=Depends(get_current_active_user),
    _=Depends(require_read_permission)
):
    """List available policy templates."""
    
    try:
        manager = get_policy_manager_instance()
        templates = manager.get_templates()
        
        responses = []
        for template in templates:
            response = PolicyTemplateResponse(
                template_id=template.template_id,
                name=template.name,
                description=template.description,
                category=template.category,
                base_policy_type=template.base_policy_type,
                usage_count=template.usage_count,
                created_by=template.created_by,
                created_at=template.created_at
            )
            responses.append(response)
        
        return responses
        
    except Exception as e:
        logger.error(f"Error listing policy templates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/statistics",
    summary="Get policy statistics",
    description="Get policy management and execution statistics"
)
async def get_policy_statistics(
    current_user=Depends(get_current_active_user),
    _=Depends(require_read_permission)
):
    """Get comprehensive policy statistics."""
    
    try:
        manager = get_policy_manager_instance()
        engine = get_policy_engine_instance()
        
        manager_stats = manager.get_statistics()
        engine_stats = engine.get_policy_statistics()
        
        return {
            "policy_management": manager_stats,
            "policy_engine": engine_stats,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting policy statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/import",
    response_model=PolicyResponse,
    summary="Import policy",
    description="Import a policy from JSON/YAML file"
)
async def import_policy(
    file: UploadFile = File(..., description="Policy file to import"),
    current_user=Depends(get_current_active_user),
    _=Depends(require_write_permission)
):
    """Import a policy from file."""
    
    try:
        # Read file content
        content = await file.read()
        
        # Determine format from file extension
        file_ext = Path(file.filename).suffix.lower()
        if file_ext == '.json':
            format_type = 'json'
        elif file_ext in ['.yaml', '.yml']:
            format_type = 'yaml'
        else:
            raise HTTPException(status_code=400, detail="Unsupported file format. Use JSON or YAML.")
        
        manager = get_policy_manager_instance()
        policy = manager.import_policy(
            content.decode('utf-8'),
            format_type,
            current_user.get("user_id") if current_user else None
        )
        
        response = PolicyResponse(
            policy_id=policy.policy_id,
            name=policy.name,
            description=policy.description,
            policy_type=policy.policy_type,
            scope=policy.scope.value,
            scope_value=policy.scope_value,
            priority=policy.priority.value,
            status=policy.status.value,
            created_by=policy.created_by,
            created_at=policy.created_at,
            updated_by=policy.updated_by,
            updated_at=policy.updated_at,
            effective_from=policy.effective_from,
            effective_until=policy.effective_until,
            tags=policy.tags,
            categories=policy.categories
        )
        
        logger.info(f"Imported policy: {policy.name} by {current_user.get('user_id', 'unknown')}")
        return response
        
    except Exception as e:
        logger.error(f"Error importing policy: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get(
    "/{policy_id}/export",
    summary="Export policy",
    description="Export a policy to JSON/YAML format"
)
async def export_policy(
    policy_id: str,
    format: str = Query("json", regex="^(json|yaml)$", description="Export format"),
    current_user=Depends(get_current_active_user),
    _=Depends(require_read_permission)
):
    """Export a policy to file."""
    
    try:
        manager = get_policy_manager_instance()
        policy_data = manager.export_policy(policy_id, format)
        
        # Create response
        media_type = "application/json" if format == "json" else "application/x-yaml"
        file_ext = "json" if format == "json" else "yaml"
        
        return StreamingResponse(
            io.StringIO(policy_data),
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename=policy_{policy_id}.{file_ext}"}
        )
        
    except Exception as e:
        logger.error(f"Error exporting policy {policy_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))