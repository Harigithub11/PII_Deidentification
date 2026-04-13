"""
Integration API Endpoints

External service integration, webhook management, API gateway functionality,
and third-party service connectors for the De-identification System.
"""

import logging
import json
import hmac
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, status, Query, Path, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, HttpUrl, validator
from sqlalchemy.orm import Session
from sqlalchemy import and_, desc

from ..core.database.session import get_db_session
from ..core.database.models import User
from ..core.security.dependencies import (
    get_current_active_user,
    get_current_admin_user,
    AuditLogDependency
)
from .models import APIResponse, APIError, PaginatedResponse, OperationResult

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/integrations", tags=["Integrations"])


# =============================================================================
# INTEGRATION MODELS
# =============================================================================

class IntegrationType(str, Enum):
    """Types of integrations."""
    WEBHOOK = "webhook"
    API_CLIENT = "api_client"
    CLOUD_STORAGE = "cloud_storage"
    NOTIFICATION_SERVICE = "notification_service"
    MONITORING_SERVICE = "monitoring_service"
    AUTHENTICATION_PROVIDER = "authentication_provider"
    DOCUMENT_STORE = "document_store"
    ANALYTICS_PLATFORM = "analytics_platform"


class IntegrationStatus(str, Enum):
    """Integration status values."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    FAILED = "failed"
    TESTING = "testing"
    PENDING_APPROVAL = "pending_approval"


class WebhookEvent(str, Enum):
    """Webhook event types."""
    DOCUMENT_UPLOADED = "document.uploaded"
    DOCUMENT_PROCESSED = "document.processed"
    PII_DETECTED = "pii.detected"
    PII_REDACTED = "pii.redacted"
    USER_CREATED = "user.created"
    JOB_STARTED = "job.started"
    JOB_COMPLETED = "job.completed"
    JOB_FAILED = "job.failed"
    SYSTEM_ALERT = "system.alert"
    COMPLIANCE_VIOLATION = "compliance.violation"


class HTTPMethod(str, Enum):
    """HTTP methods for API calls."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


# =============================================================================
# WEBHOOK MODELS
# =============================================================================

class WebhookCreateRequest(BaseModel):
    """Request to create a webhook."""
    name: str = Field(..., min_length=1, max_length=100, description="Webhook name")
    description: Optional[str] = Field(None, max_length=500, description="Webhook description")
    url: HttpUrl = Field(..., description="Webhook endpoint URL")
    events: List[WebhookEvent] = Field(..., min_items=1, description="Events to subscribe to")
    secret: Optional[str] = Field(None, min_length=16, max_length=64, description="Secret for HMAC signing")
    headers: Optional[Dict[str, str]] = Field(None, description="Custom headers to send")
    active: bool = Field(True, description="Whether webhook is active")
    retry_attempts: int = Field(3, ge=0, le=10, description="Number of retry attempts on failure")
    timeout_seconds: int = Field(30, ge=5, le=300, description="Request timeout in seconds")


class WebhookUpdateRequest(BaseModel):
    """Request to update a webhook."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    url: Optional[HttpUrl] = None
    events: Optional[List[WebhookEvent]] = Field(None, min_items=1)
    secret: Optional[str] = Field(None, min_length=16, max_length=64)
    headers: Optional[Dict[str, str]] = None
    active: Optional[bool] = None
    retry_attempts: Optional[int] = Field(None, ge=0, le=10)
    timeout_seconds: Optional[int] = Field(None, ge=5, le=300)


class WebhookResponse(BaseModel):
    """Webhook response model."""
    id: UUID = Field(..., description="Webhook ID")
    name: str = Field(..., description="Webhook name")
    description: Optional[str] = Field(None, description="Webhook description")
    url: str = Field(..., description="Webhook endpoint URL")
    events: List[WebhookEvent] = Field(..., description="Subscribed events")
    active: bool = Field(..., description="Whether webhook is active")
    retry_attempts: int = Field(..., description="Retry attempts configuration")
    timeout_seconds: int = Field(..., description="Timeout configuration")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    created_by: UUID = Field(..., description="Creator user ID")
    last_triggered: Optional[datetime] = Field(None, description="Last triggered timestamp")
    success_count: int = Field(..., description="Successful deliveries count")
    failure_count: int = Field(..., description="Failed deliveries count")
    has_secret: bool = Field(..., description="Whether webhook has a secret configured")


class WebhookDelivery(BaseModel):
    """Webhook delivery record."""
    id: UUID = Field(..., description="Delivery ID")
    webhook_id: UUID = Field(..., description="Webhook ID")
    event_type: WebhookEvent = Field(..., description="Event type")
    payload: Dict[str, Any] = Field(..., description="Delivered payload")
    status_code: Optional[int] = Field(None, description="HTTP status code received")
    response_body: Optional[str] = Field(None, description="Response body")
    delivery_time: datetime = Field(..., description="Delivery attempt time")
    success: bool = Field(..., description="Whether delivery was successful")
    attempt_number: int = Field(..., description="Attempt number (1-based)")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    duration_ms: Optional[int] = Field(None, description="Delivery duration in milliseconds")


# =============================================================================
# API CLIENT MODELS
# =============================================================================

class APIClientCreateRequest(BaseModel):
    """Request to create an API client integration."""
    name: str = Field(..., min_length=1, max_length=100, description="Client name")
    description: Optional[str] = Field(None, max_length=500, description="Client description")
    client_type: IntegrationType = Field(..., description="Type of integration")
    base_url: HttpUrl = Field(..., description="Base URL for the API")
    authentication: Dict[str, Any] = Field(..., description="Authentication configuration")
    default_headers: Optional[Dict[str, str]] = Field(None, description="Default headers")
    timeout_seconds: int = Field(30, ge=5, le=300, description="Request timeout")
    retry_attempts: int = Field(3, ge=0, le=10, description="Retry attempts on failure")
    rate_limit_per_minute: Optional[int] = Field(None, ge=1, description="Rate limit per minute")
    active: bool = Field(True, description="Whether client is active")


class APIClientResponse(BaseModel):
    """API client response model."""
    id: UUID = Field(..., description="Client ID")
    name: str = Field(..., description="Client name")
    description: Optional[str] = Field(None, description="Client description")
    client_type: IntegrationType = Field(..., description="Integration type")
    base_url: str = Field(..., description="Base URL")
    timeout_seconds: int = Field(..., description="Timeout configuration")
    retry_attempts: int = Field(..., description="Retry configuration")
    rate_limit_per_minute: Optional[int] = Field(None, description="Rate limit")
    active: bool = Field(..., description="Active status")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    created_by: UUID = Field(..., description="Creator user ID")
    last_used: Optional[datetime] = Field(None, description="Last used timestamp")
    usage_count: int = Field(..., description="Total usage count")
    success_rate: Optional[float] = Field(None, description="Success rate percentage")


# =============================================================================
# EXTERNAL API CALL MODELS
# =============================================================================

class ExternalAPICallRequest(BaseModel):
    """Request to make an external API call."""
    client_id: UUID = Field(..., description="API client ID to use")
    method: HTTPMethod = Field(..., description="HTTP method")
    endpoint: str = Field(..., description="API endpoint path")
    headers: Optional[Dict[str, str]] = Field(None, description="Request headers")
    query_params: Optional[Dict[str, Any]] = Field(None, description="Query parameters")
    body: Optional[Dict[str, Any]] = Field(None, description="Request body")
    timeout_override: Optional[int] = Field(None, ge=5, le=300, description="Override timeout")


class ExternalAPICallResponse(BaseModel):
    """Response from external API call."""
    call_id: UUID = Field(..., description="Call ID for tracking")
    success: bool = Field(..., description="Call success status")
    status_code: Optional[int] = Field(None, description="HTTP status code")
    response_data: Optional[Dict[str, Any]] = Field(None, description="Response data")
    error_message: Optional[str] = Field(None, description="Error message")
    duration_ms: int = Field(..., description="Call duration in milliseconds")
    timestamp: datetime = Field(..., description="Call timestamp")


# =============================================================================
# WEBHOOK MANAGEMENT ENDPOINTS
# =============================================================================

@router.post("/webhooks", response_model=WebhookResponse, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    request: WebhookCreateRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("webhook_create"))
):
    """Create a new webhook subscription."""
    
    # For demonstration, we'll store webhook data in memory
    # In production, this would be stored in the database
    
    webhook_id = uuid4()
    
    webhook = {
        "id": webhook_id,
        "name": request.name,
        "description": request.description,
        "url": str(request.url),
        "events": request.events,
        "active": request.active,
        "retry_attempts": request.retry_attempts,
        "timeout_seconds": request.timeout_seconds,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "created_by": current_user.id,
        "last_triggered": None,
        "success_count": 0,
        "failure_count": 0,
        "has_secret": request.secret is not None
    }
    
    # Store webhook configuration (in production database)
    logger.info(f"Webhook created: {request.name} by {current_user.username}")
    
    return WebhookResponse(**webhook)


@router.get("/webhooks", response_model=List[WebhookResponse])
async def list_webhooks(
    active_only: bool = Query(False, description="Show only active webhooks"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """List all webhooks for the current user."""
    
    # Mock webhook data - in production, query from database
    webhooks = [
        {
            "id": uuid4(),
            "name": "Document Processing Notifications",
            "description": "Notifications for document processing events",
            "url": "https://api.example.com/webhooks/documents",
            "events": [WebhookEvent.DOCUMENT_PROCESSED, WebhookEvent.PII_DETECTED],
            "active": True,
            "retry_attempts": 3,
            "timeout_seconds": 30,
            "created_at": datetime.utcnow() - timedelta(days=5),
            "updated_at": datetime.utcnow() - timedelta(days=1),
            "created_by": current_user.id,
            "last_triggered": datetime.utcnow() - timedelta(hours=2),
            "success_count": 145,
            "failure_count": 3,
            "has_secret": True
        }
    ]
    
    if active_only:
        webhooks = [w for w in webhooks if w["active"]]
    
    return [WebhookResponse(**webhook) for webhook in webhooks]


@router.get("/webhooks/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: UUID = Path(..., description="Webhook ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """Get webhook details by ID."""
    
    # Mock webhook data lookup
    webhook_data = {
        "id": webhook_id,
        "name": "Document Processing Notifications",
        "description": "Notifications for document processing events",
        "url": "https://api.example.com/webhooks/documents",
        "events": [WebhookEvent.DOCUMENT_PROCESSED, WebhookEvent.PII_DETECTED],
        "active": True,
        "retry_attempts": 3,
        "timeout_seconds": 30,
        "created_at": datetime.utcnow() - timedelta(days=5),
        "updated_at": datetime.utcnow() - timedelta(days=1),
        "created_by": current_user.id,
        "last_triggered": datetime.utcnow() - timedelta(hours=2),
        "success_count": 145,
        "failure_count": 3,
        "has_secret": True
    }
    
    return WebhookResponse(**webhook_data)


@router.put("/webhooks/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    request: WebhookUpdateRequest,
    webhook_id: UUID = Path(..., description="Webhook ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("webhook_update"))
):
    """Update webhook configuration."""
    
    # In production, update webhook in database
    logger.info(f"Webhook updated: {webhook_id} by {current_user.username}")
    
    # Return updated webhook data
    updated_data = {
        "id": webhook_id,
        "name": request.name or "Document Processing Notifications",
        "description": request.description,
        "url": str(request.url) if request.url else "https://api.example.com/webhooks/documents",
        "events": request.events or [WebhookEvent.DOCUMENT_PROCESSED],
        "active": request.active if request.active is not None else True,
        "retry_attempts": request.retry_attempts or 3,
        "timeout_seconds": request.timeout_seconds or 30,
        "created_at": datetime.utcnow() - timedelta(days=5),
        "updated_at": datetime.utcnow(),
        "created_by": current_user.id,
        "last_triggered": datetime.utcnow() - timedelta(hours=2),
        "success_count": 145,
        "failure_count": 3,
        "has_secret": True
    }
    
    return WebhookResponse(**updated_data)


@router.delete("/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: UUID = Path(..., description="Webhook ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("webhook_delete"))
):
    """Delete a webhook."""
    
    # In production, delete webhook from database
    logger.info(f"Webhook deleted: {webhook_id} by {current_user.username}")


@router.post("/webhooks/{webhook_id}/test")
async def test_webhook(
    webhook_id: UUID = Path(..., description="Webhook ID"),
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    audit_log = Depends(AuditLogDependency("webhook_test"))
):
    """Test webhook delivery with a sample payload."""
    
    # Add background task to send test webhook
    background_tasks.add_task(_send_test_webhook, webhook_id, current_user.id)
    
    logger.info(f"Webhook test initiated: {webhook_id} by {current_user.username}")
    
    return {
        "message": "Test webhook delivery initiated",
        "webhook_id": str(webhook_id),
        "test_payload": {
            "event": "webhook.test",
            "timestamp": datetime.utcnow().isoformat(),
            "data": {
                "message": "This is a test webhook delivery",
                "triggered_by": current_user.username
            }
        }
    }


async def _send_test_webhook(webhook_id: UUID, user_id: UUID):
    """Background task to send test webhook."""
    
    try:
        import httpx
        
        # In production, get webhook configuration from database
        webhook_url = "https://api.example.com/webhooks/test"
        
        payload = {
            "event": "webhook.test",
            "timestamp": datetime.utcnow().isoformat(),
            "webhook_id": str(webhook_id),
            "data": {
                "message": "This is a test webhook delivery",
                "triggered_by_user_id": str(user_id)
            }
        }
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "De-identification-System/2.0"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook_url,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            logger.info(f"Test webhook sent to {webhook_url}, status: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Failed to send test webhook {webhook_id}: {e}")


# =============================================================================
# WEBHOOK DELIVERY HISTORY
# =============================================================================

@router.get("/webhooks/{webhook_id}/deliveries", response_model=List[WebhookDelivery])
async def get_webhook_deliveries(
    webhook_id: UUID = Path(..., description="Webhook ID"),
    limit: int = Query(50, ge=1, le=200, description="Number of deliveries to return"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """Get webhook delivery history."""
    
    # Mock delivery history data
    deliveries = [
        {
            "id": uuid4(),
            "webhook_id": webhook_id,
            "event_type": WebhookEvent.DOCUMENT_PROCESSED,
            "payload": {"document_id": str(uuid4()), "status": "completed"},
            "status_code": 200,
            "response_body": '{"status": "received"}',
            "delivery_time": datetime.utcnow() - timedelta(hours=1),
            "success": True,
            "attempt_number": 1,
            "error_message": None,
            "duration_ms": 245
        },
        {
            "id": uuid4(),
            "webhook_id": webhook_id,
            "event_type": WebhookEvent.PII_DETECTED,
            "payload": {"document_id": str(uuid4()), "pii_count": 5},
            "status_code": 500,
            "response_body": '{"error": "Internal server error"}',
            "delivery_time": datetime.utcnow() - timedelta(hours=3),
            "success": False,
            "attempt_number": 3,
            "error_message": "HTTP 500 Internal Server Error",
            "duration_ms": 5000
        }
    ]
    
    return [WebhookDelivery(**delivery) for delivery in deliveries[:limit]]


@router.post("/webhooks/{webhook_id}/deliveries/{delivery_id}/retry")
async def retry_webhook_delivery(
    webhook_id: UUID = Path(..., description="Webhook ID"),
    delivery_id: UUID = Path(..., description="Delivery ID"),
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    audit_log = Depends(AuditLogDependency("webhook_retry"))
):
    """Retry a failed webhook delivery."""
    
    # Add background task to retry webhook delivery
    background_tasks.add_task(_retry_webhook_delivery, webhook_id, delivery_id, current_user.id)
    
    logger.info(f"Webhook delivery retry initiated: {delivery_id} by {current_user.username}")
    
    return {
        "message": "Webhook delivery retry initiated",
        "webhook_id": str(webhook_id),
        "delivery_id": str(delivery_id)
    }


async def _retry_webhook_delivery(webhook_id: UUID, delivery_id: UUID, user_id: UUID):
    """Background task to retry webhook delivery."""
    
    try:
        # In production, get original delivery details and retry
        logger.info(f"Retrying webhook delivery: {delivery_id}")
        
        # Simulate retry logic
        import asyncio
        await asyncio.sleep(1)
        
        logger.info(f"Webhook delivery retry completed: {delivery_id}")
        
    except Exception as e:
        logger.error(f"Failed to retry webhook delivery {delivery_id}: {e}")


# =============================================================================
# API CLIENT MANAGEMENT
# =============================================================================

@router.post("/clients", response_model=APIClientResponse, status_code=status.HTTP_201_CREATED)
async def create_api_client(
    request: APIClientCreateRequest,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session),
    audit_log = Depends(AuditLogDependency("api_client_create"))
):
    """Create a new API client integration (Admin only)."""
    
    client_id = uuid4()
    
    client_data = {
        "id": client_id,
        "name": request.name,
        "description": request.description,
        "client_type": request.client_type,
        "base_url": str(request.base_url),
        "timeout_seconds": request.timeout_seconds,
        "retry_attempts": request.retry_attempts,
        "rate_limit_per_minute": request.rate_limit_per_minute,
        "active": request.active,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "created_by": current_user.id,
        "last_used": None,
        "usage_count": 0,
        "success_rate": None
    }
    
    logger.info(f"API client created: {request.name} by {current_user.username}")
    
    return APIClientResponse(**client_data)


@router.get("/clients", response_model=List[APIClientResponse])
async def list_api_clients(
    client_type: Optional[IntegrationType] = Query(None, description="Filter by client type"),
    active_only: bool = Query(False, description="Show only active clients"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    """List API client integrations (Admin only)."""
    
    # Mock client data
    clients = [
        {
            "id": uuid4(),
            "name": "AWS S3 Storage",
            "description": "Amazon S3 integration for document storage",
            "client_type": IntegrationType.CLOUD_STORAGE,
            "base_url": "https://s3.amazonaws.com",
            "timeout_seconds": 60,
            "retry_attempts": 3,
            "rate_limit_per_minute": 100,
            "active": True,
            "created_at": datetime.utcnow() - timedelta(days=30),
            "updated_at": datetime.utcnow() - timedelta(days=5),
            "created_by": current_user.id,
            "last_used": datetime.utcnow() - timedelta(hours=2),
            "usage_count": 1250,
            "success_rate": 99.2
        }
    ]
    
    # Apply filters
    if client_type:
        clients = [c for c in clients if c["client_type"] == client_type]
    
    if active_only:
        clients = [c for c in clients if c["active"]]
    
    return [APIClientResponse(**client) for client in clients]


# =============================================================================
# EXTERNAL API CALLS
# =============================================================================

@router.post("/clients/{client_id}/call", response_model=ExternalAPICallResponse)
async def make_external_api_call(
    request: ExternalAPICallRequest,
    client_id: UUID = Path(..., description="API client ID"),
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    audit_log = Depends(AuditLogDependency("external_api_call"))
):
    """Make an external API call using configured client."""
    
    call_id = uuid4()
    
    # Add background task to make the API call
    background_tasks.add_task(
        _make_external_api_call,
        call_id,
        client_id,
        request,
        current_user.id
    )
    
    logger.info(f"External API call initiated: {call_id} by {current_user.username}")
    
    return ExternalAPICallResponse(
        call_id=call_id,
        success=True,  # Initial status
        status_code=None,
        response_data=None,
        error_message=None,
        duration_ms=0,
        timestamp=datetime.utcnow()
    )


async def _make_external_api_call(
    call_id: UUID,
    client_id: UUID,
    request: ExternalAPICallRequest,
    user_id: UUID
):
    """Background task to make external API call."""
    
    try:
        import httpx
        
        # In production, get client configuration from database
        base_url = "https://api.example.com"
        
        # Construct full URL
        url = f"{base_url.rstrip('/')}/{request.endpoint.lstrip('/')}"
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "De-identification-System/2.0"
        }
        
        if request.headers:
            headers.update(request.headers)
        
        start_time = datetime.utcnow()
        
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=request.method.value,
                url=url,
                headers=headers,
                params=request.query_params,
                json=request.body,
                timeout=request.timeout_override or 30
            )
            
            end_time = datetime.utcnow()
            duration_ms = int((end_time - start_time).total_seconds() * 1000)
            
            logger.info(f"External API call completed: {call_id}, status: {response.status_code}")
            
            # Store call result in database
            
    except Exception as e:
        logger.error(f"External API call failed {call_id}: {e}")


# =============================================================================
# INTEGRATION STATUS AND HEALTH
# =============================================================================

@router.get("/health")
async def get_integrations_health(
    current_user: User = Depends(get_current_active_user)
):
    """Get health status of all integrations."""
    
    # Mock integration health data
    integrations_health = {
        "webhooks": {
            "status": "healthy",
            "active_count": 5,
            "total_deliveries_24h": 1250,
            "success_rate_24h": 98.4,
            "avg_response_time_ms": 245
        },
        "api_clients": {
            "status": "healthy",
            "active_count": 3,
            "total_calls_24h": 450,
            "success_rate_24h": 99.1,
            "avg_response_time_ms": 180
        },
        "cloud_storage": {
            "status": "healthy",
            "connections": 2,
            "data_transferred_gb": 15.7,
            "success_rate_24h": 100.0
        },
        "external_services": {
            "status": "degraded",
            "available_services": 8,
            "unavailable_services": 1,
            "avg_response_time_ms": 520
        }
    }
    
    overall_status = "healthy"
    if any(service["status"] != "healthy" for service in integrations_health.values()):
        overall_status = "degraded"
    
    return {
        "overall_status": overall_status,
        "timestamp": datetime.utcnow(),
        "integrations": integrations_health
    }


@router.get("/stats")
async def get_integration_statistics(
    current_user: User = Depends(get_current_admin_user)
):
    """Get integration usage statistics (Admin only)."""
    
    now = datetime.utcnow()
    
    stats = {
        "total_webhooks": 12,
        "active_webhooks": 8,
        "total_api_clients": 5,
        "active_api_clients": 4,
        
        # Last 24 hours
        "webhook_deliveries_24h": 1250,
        "webhook_success_rate_24h": 98.4,
        "api_calls_24h": 450,
        "api_success_rate_24h": 99.1,
        
        # Last 7 days
        "webhook_deliveries_7d": 8750,
        "api_calls_7d": 3150,
        
        # Top endpoints
        "top_webhook_events": [
            {"event": "document.processed", "count": 450},
            {"event": "pii.detected", "count": 380},
            {"event": "job.completed", "count": 220}
        ],
        
        "top_api_endpoints": [
            {"endpoint": "/documents", "calls": 150},
            {"endpoint": "/storage/upload", "calls": 120},
            {"endpoint": "/notifications/send", "calls": 80}
        ],
        
        "integration_types": {
            "webhook": 12,
            "cloud_storage": 3,
            "notification_service": 2,
            "analytics_platform": 1
        }
    }
    
    return stats


# =============================================================================
# INTEGRATION TEMPLATES
# =============================================================================

@router.get("/templates")
async def get_integration_templates(
    template_type: Optional[IntegrationType] = Query(None, description="Filter by integration type"),
    current_user: User = Depends(get_current_active_user)
):
    """Get predefined integration templates."""
    
    templates = [
        {
            "id": "slack-notifications",
            "name": "Slack Notifications",
            "description": "Send notifications to Slack channels",
            "type": IntegrationType.NOTIFICATION_SERVICE,
            "configuration_schema": {
                "webhook_url": {"type": "string", "required": True},
                "channel": {"type": "string", "required": True},
                "username": {"type": "string", "default": "PII System"}
            },
            "events_supported": [
                WebhookEvent.DOCUMENT_PROCESSED,
                WebhookEvent.JOB_FAILED,
                WebhookEvent.SYSTEM_ALERT
            ]
        },
        {
            "id": "aws-s3-storage",
            "name": "AWS S3 Storage",
            "description": "Store processed documents in Amazon S3",
            "type": IntegrationType.CLOUD_STORAGE,
            "configuration_schema": {
                "access_key_id": {"type": "string", "required": True},
                "secret_access_key": {"type": "string", "required": True, "sensitive": True},
                "bucket_name": {"type": "string", "required": True},
                "region": {"type": "string", "default": "us-east-1"}
            }
        },
        {
            "id": "google-analytics",
            "name": "Google Analytics",
            "description": "Send usage events to Google Analytics",
            "type": IntegrationType.ANALYTICS_PLATFORM,
            "configuration_schema": {
                "tracking_id": {"type": "string", "required": True},
                "measurement_id": {"type": "string", "required": True}
            },
            "events_supported": [
                WebhookEvent.DOCUMENT_UPLOADED,
                WebhookEvent.PII_DETECTED,
                WebhookEvent.USER_CREATED
            ]
        }
    ]
    
    if template_type:
        templates = [t for t in templates if t["type"] == template_type]
    
    return templates


@router.post("/templates/{template_id}/create")
async def create_integration_from_template(
    template_id: str = Path(..., description="Integration template ID"),
    configuration: Dict[str, Any] = Field(..., description="Template configuration"),
    name: str = Field(..., description="Integration name"),
    current_user: User = Depends(get_current_active_user),
    audit_log = Depends(AuditLogDependency("integration_template_create"))
):
    """Create integration from predefined template."""
    
    integration_id = uuid4()
    
    # In production, validate configuration against template schema
    # and create the appropriate integration type
    
    logger.info(f"Integration created from template {template_id}: {name} by {current_user.username}")
    
    return {
        "integration_id": str(integration_id),
        "name": name,
        "template_id": template_id,
        "status": "created",
        "message": f"Integration '{name}' created successfully from template"
    }