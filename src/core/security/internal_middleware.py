"""
Internal Service Authentication Middleware

Provides middleware for authenticating internal service-to-service requests
and ensuring secure communication between system components.
"""

import json
from typing import Callable, Dict, Any, Optional
from fastapi import Request, Response, HTTPException, status
from fastapi.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .internal_encryption import internal_encryption, EncryptedMessage


class InternalServiceMiddleware(BaseHTTPMiddleware):
    """Middleware for internal service authentication."""
    
    INTERNAL_ENDPOINTS = [
        "/internal/",
        "/api/internal/",
        "/service/"
    ]
    
    def __init__(self, app, require_encryption: bool = True):
        super().__init__(app)
        self.require_encryption = require_encryption
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check if this is an internal service endpoint
        if not self._is_internal_endpoint(request.url.path):
            return await call_next(request)
        
        try:
            # Authenticate and decrypt internal service request
            service_info = await self._authenticate_internal_request(request)
            
            if service_info:
                # Add service info to request state for use in endpoints
                request.state.internal_service = service_info
                request.state.is_internal_request = True
            else:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"error": "Invalid internal service credentials"}
                )
            
            response = await call_next(request)
            
            # Encrypt response if needed
            if self.require_encryption and hasattr(request.state, 'encrypt_response'):
                response = await self._encrypt_response(response, service_info)
            
            return response
            
        except Exception as e:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": f"Internal service authentication failed: {str(e)}"}
            )
    
    def _is_internal_endpoint(self, path: str) -> bool:
        """Check if the endpoint is for internal services."""
        return any(path.startswith(endpoint) for endpoint in self.INTERNAL_ENDPOINTS)
    
    async def _authenticate_internal_request(self, request: Request) -> Optional[Dict[str, Any]]:
        """Authenticate internal service request."""
        # Check for service token in headers
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        
        service_token = auth_header[7:]  # Remove "Bearer " prefix
        
        try:
            # Verify the service token
            token_payload = internal_encryption.verify_service_token(service_token)
            
            # Check for encrypted message in request body
            encrypted_data = None
            if request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
                if body:
                    try:
                        request_data = json.loads(body)
                        if "encrypted_message" in request_data:
                            encrypted_msg = EncryptedMessage(**request_data["encrypted_message"])
                            decrypted_data = internal_encryption.decrypt_internal_message(
                                encrypted_msg, 
                                token_payload["service_id"]
                            )
                            encrypted_data = decrypted_data
                    except (json.JSONDecodeError, TypeError, ValueError):
                        # Not an encrypted request, continue normally
                        pass
            
            return {
                "service_id": token_payload["service_id"],
                "permissions": token_payload["permissions"],
                "target_service": token_payload.get("target_service"),
                "decrypted_data": encrypted_data,
                "token_payload": token_payload
            }
            
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid service token: {str(e)}"
            )
    
    async def _encrypt_response(self, response: Response, service_info: Dict[str, Any]) -> Response:
        """Encrypt response for internal service."""
        # This is a simplified implementation
        # In practice, you might want to encrypt based on response content type
        return response


class InternalServiceAuth:
    """Helper class for internal service authentication in endpoints."""
    
    @staticmethod
    def get_service_info(request: Request) -> Optional[Dict[str, Any]]:
        """Get authenticated service information from request."""
        return getattr(request.state, 'internal_service', None)
    
    @staticmethod
    def require_service(required_service: str):
        """Decorator to require specific service authentication."""
        def decorator(func):
            async def wrapper(request: Request, *args, **kwargs):
                service_info = InternalServiceAuth.get_service_info(request)
                if not service_info or service_info["service_id"] != required_service:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Access denied. Required service: {required_service}"
                    )
                return await func(request, *args, **kwargs)
            return wrapper
        return decorator
    
    @staticmethod
    def require_permission(required_permission: str):
        """Decorator to require specific permission."""
        def decorator(func):
            async def wrapper(request: Request, *args, **kwargs):
                service_info = InternalServiceAuth.get_service_info(request)
                if not service_info or required_permission not in service_info["permissions"]:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Access denied. Required permission: {required_permission}"
                    )
                return await func(request, *args, **kwargs)
            return wrapper
        return decorator
    
    @staticmethod
    def create_encrypted_response(
        data: Dict[str, Any], 
        service_id: str,
        target_service: str = None
    ) -> Dict[str, Any]:
        """Create encrypted response for internal service."""
        encrypted_msg = internal_encryption.encrypt_internal_message(
            data, 
            service_id,
            target_service
        )
        
        return {
            "encrypted": True,
            "encrypted_message": {
                "encrypted_data": encrypted_msg.encrypted_data,
                "signature": encrypted_msg.signature,
                "timestamp": encrypted_msg.timestamp,
                "service_id": encrypted_msg.service_id,
                "message_id": encrypted_msg.message_id,
                "ttl": encrypted_msg.ttl
            }
        }


# Helper function to setup internal service middleware
def setup_internal_service_middleware(app, require_encryption: bool = True):
    """Setup internal service middleware."""
    app.add_middleware(InternalServiceMiddleware, require_encryption=require_encryption)


# Example usage functions for internal services
async def make_internal_service_call(
    calling_service: str,
    target_service: str,
    endpoint: str,
    data: Dict[str, Any] = None,
    method: str = "POST"
) -> Dict[str, Any]:
    """Make an authenticated internal service call."""
    import httpx
    
    # Create service token
    token = internal_encryption.create_service_token(calling_service, target_service)
    
    # Encrypt the request data if provided
    encrypted_request = None
    if data:
        encrypted_msg = internal_encryption.encrypt_internal_message(
            data, 
            calling_service,
            target_service
        )
        encrypted_request = {
            "encrypted_message": {
                "encrypted_data": encrypted_msg.encrypted_data,
                "signature": encrypted_msg.signature,
                "timestamp": encrypted_msg.timestamp,
                "service_id": encrypted_msg.service_id,
                "message_id": encrypted_msg.message_id,
                "ttl": encrypted_msg.ttl
            }
        }
    
    # Make the HTTP request
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Internal-Service": calling_service
    }
    
    async with httpx.AsyncClient() as client:
        if method.upper() == "GET":
            response = await client.get(endpoint, headers=headers)
        else:
            response = await client.request(
                method.upper(), 
                endpoint, 
                headers=headers,
                json=encrypted_request
            )
    
    if response.status_code == 200:
        return response.json()
    else:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Internal service call failed: {response.text}"
        )


# Service health check for internal encryption
def get_internal_encryption_status() -> Dict[str, Any]:
    """Get status of internal encryption system."""
    return {
        "status": "healthy",
        "encryption_enabled": True,
        "service_count": len(internal_encryption.registered_services),
        "active_services": internal_encryption.get_service_status()["active_services"],
        "message_cache_size": len(internal_encryption.message_cache),
        "features": {
            "service_authentication": True,
            "message_encryption": True,
            "replay_protection": True,
            "token_expiration": True,
            "permission_based_access": True
        }
    }