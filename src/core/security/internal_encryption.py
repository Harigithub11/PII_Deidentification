"""
Internal Service Encryption

Provides encryption for internal service-to-service communication,
API calls, queue messages, and inter-process communication.
"""

import json
import time
import hmac
import hashlib
import base64
from typing import Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..config.settings import get_settings
from .encryption import encryption_manager

settings = get_settings()


@dataclass
class EncryptedMessage:
    """Encrypted internal message structure."""
    encrypted_data: str
    signature: str
    timestamp: float
    service_id: str
    message_id: str
    ttl: int = 300  # 5 minutes default TTL


@dataclass
class ServiceCredentials:
    """Service authentication credentials."""
    service_id: str
    service_key: str
    permissions: list
    created_at: datetime
    expires_at: Optional[datetime] = None


class InternalServiceEncryption:
    """Handles encryption for internal service communication."""
    
    def __init__(self):
        self.master_key = encryption_manager._fernet_key
        self.service_keys: Dict[str, str] = {}
        self.registered_services: Dict[str, ServiceCredentials] = {}
        self.message_cache: Dict[str, float] = {}  # Prevent replay attacks
        
        # Initialize system services
        self._initialize_system_services()
    
    def _initialize_system_services(self):
        """Initialize built-in system services."""
        system_services = [
            ("pii-detector", ["detect_pii", "classify_content"]),
            ("document-processor", ["process_document", "extract_text"]),
            ("file-manager", ["encrypt_file", "decrypt_file", "store_file"]),
            ("database-service", ["query_data", "store_data", "backup_data"]),
            ("auth-service", ["authenticate", "authorize", "refresh_token"]),
            ("audit-service", ["log_access", "track_changes", "generate_report"])
        ]
        
        for service_id, permissions in system_services:
            self.register_service(service_id, permissions)
    
    def derive_service_key(self, service_id: str, salt: bytes = None) -> bytes:
        """Derive a unique key for a service."""
        if salt is None:
            salt = f"service-{service_id}".encode()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(self.master_key)
    
    def register_service(
        self, 
        service_id: str, 
        permissions: list, 
        expires_in_hours: Optional[int] = None
    ) -> ServiceCredentials:
        """Register a new internal service."""
        service_key = base64.urlsafe_b64encode(self.derive_service_key(service_id)).decode()
        
        expires_at = None
        if expires_in_hours:
            expires_at = datetime.now() + timedelta(hours=expires_in_hours)
        
        credentials = ServiceCredentials(
            service_id=service_id,
            service_key=service_key,
            permissions=permissions,
            created_at=datetime.now(),
            expires_at=expires_at
        )
        
        self.registered_services[service_id] = credentials
        self.service_keys[service_id] = service_key
        
        return credentials
    
    def create_service_token(
        self, 
        service_id: str, 
        target_service: str = None,
        expires_in: int = 3600
    ) -> str:
        """Create JWT token for service authentication."""
        if service_id not in self.registered_services:
            raise ValueError(f"Service {service_id} not registered")
        
        service_creds = self.registered_services[service_id]
        
        payload = {
            "service_id": service_id,
            "target_service": target_service,
            "permissions": service_creds.permissions,
            "iat": time.time(),
            "exp": time.time() + expires_in,
            "jti": f"{service_id}_{int(time.time())}"  # JWT ID for tracking
        }
        
        return jwt.encode(
            payload, 
            service_creds.service_key, 
            algorithm="HS256"
        )
    
    def verify_service_token(self, token: str, expected_service: str = None) -> Dict[str, Any]:
        """Verify and decode service JWT token."""
        try:
            # First decode without verification to get service_id
            unverified = jwt.decode(token, options={"verify_signature": False})
            service_id = unverified.get("service_id")
            
            if not service_id or service_id not in self.service_keys:
                raise ValueError("Invalid service token")
            
            # Verify with service key
            payload = jwt.decode(
                token,
                self.service_keys[service_id],
                algorithms=["HS256"]
            )
            
            # Check if token is for expected service
            if expected_service and payload.get("target_service") != expected_service:
                raise ValueError("Token not valid for target service")
            
            # Check service expiration
            service_creds = self.registered_services[service_id]
            if service_creds.expires_at and datetime.now() > service_creds.expires_at:
                raise ValueError("Service credentials expired")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise ValueError("Token expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")
    
    def encrypt_internal_message(
        self, 
        data: Union[Dict, str, bytes], 
        service_id: str,
        target_service: str = None,
        ttl: int = 300
    ) -> EncryptedMessage:
        """Encrypt a message for internal service communication."""
        if service_id not in self.registered_services:
            raise ValueError(f"Service {service_id} not registered")
        
        # Serialize data
        if isinstance(data, dict):
            message_data = json.dumps(data).encode()
        elif isinstance(data, str):
            message_data = data.encode()
        else:
            message_data = data
        
        # Create service-specific Fernet instance
        service_key = self.derive_service_key(service_id)
        fernet = Fernet(base64.urlsafe_b64encode(service_key))
        
        # Encrypt the message
        encrypted_data = fernet.encrypt(message_data)
        
        # Create message metadata
        message_id = f"{service_id}_{int(time.time() * 1000000)}"
        timestamp = time.time()
        
        # Create signature for integrity
        signature_data = f"{encrypted_data.decode()}{timestamp}{service_id}{message_id}"
        signature = hmac.new(
            service_key,
            signature_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return EncryptedMessage(
            encrypted_data=encrypted_data.decode(),
            signature=signature,
            timestamp=timestamp,
            service_id=service_id,
            message_id=message_id,
            ttl=ttl
        )
    
    def decrypt_internal_message(
        self, 
        encrypted_msg: EncryptedMessage,
        expected_service: str = None
    ) -> Union[Dict, str, bytes]:
        """Decrypt and verify an internal service message."""
        # Check message TTL
        if time.time() - encrypted_msg.timestamp > encrypted_msg.ttl:
            raise ValueError("Message expired")
        
        # Check for replay attacks
        if encrypted_msg.message_id in self.message_cache:
            raise ValueError("Message replay detected")
        
        # Verify service
        if expected_service and encrypted_msg.service_id != expected_service:
            raise ValueError("Message not from expected service")
        
        if encrypted_msg.service_id not in self.registered_services:
            raise ValueError(f"Unknown service: {encrypted_msg.service_id}")
        
        # Verify signature
        service_key = self.derive_service_key(encrypted_msg.service_id)
        signature_data = f"{encrypted_msg.encrypted_data}{encrypted_msg.timestamp}{encrypted_msg.service_id}{encrypted_msg.message_id}"
        expected_signature = hmac.new(
            service_key,
            signature_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(encrypted_msg.signature, expected_signature):
            raise ValueError("Message signature verification failed")
        
        # Decrypt the message
        fernet = Fernet(base64.urlsafe_b64encode(service_key))
        decrypted_data = fernet.decrypt(encrypted_msg.encrypted_data.encode())
        
        # Cache message ID to prevent replay
        self.message_cache[encrypted_msg.message_id] = time.time()
        self._cleanup_message_cache()
        
        # Try to parse as JSON
        try:
            return json.loads(decrypted_data.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return decrypted_data
    
    def _cleanup_message_cache(self):
        """Clean up old message IDs from cache."""
        current_time = time.time()
        expired_ids = [
            msg_id for msg_id, timestamp in self.message_cache.items()
            if current_time - timestamp > 3600  # Clean up after 1 hour
        ]
        for msg_id in expired_ids:
            del self.message_cache[msg_id]
    
    def create_secure_channel(self, service_a: str, service_b: str) -> Dict[str, str]:
        """Create a secure communication channel between two services."""
        if service_a not in self.registered_services or service_b not in self.registered_services:
            raise ValueError("Both services must be registered")
        
        # Create bidirectional tokens
        token_a_to_b = self.create_service_token(service_a, service_b, expires_in=3600)
        token_b_to_a = self.create_service_token(service_b, service_a, expires_in=3600)
        
        return {
            f"{service_a}_to_{service_b}": token_a_to_b,
            f"{service_b}_to_{service_a}": token_b_to_a,
            "channel_id": f"{service_a}_{service_b}_{int(time.time())}",
            "expires_at": datetime.fromtimestamp(time.time() + 3600).isoformat()
        }
    
    def encrypt_database_query(
        self, 
        query: str, 
        params: Dict = None,
        service_id: str = "database-service"
    ) -> EncryptedMessage:
        """Encrypt a database query for secure internal communication."""
        query_data = {
            "query": query,
            "params": params or {},
            "timestamp": time.time(),
            "service_type": "database"
        }
        
        return self.encrypt_internal_message(query_data, service_id)
    
    def encrypt_api_request(
        self,
        endpoint: str,
        method: str = "GET",
        headers: Dict = None,
        body: Any = None,
        service_id: str = "api-gateway"
    ) -> EncryptedMessage:
        """Encrypt internal API request data."""
        request_data = {
            "endpoint": endpoint,
            "method": method,
            "headers": headers or {},
            "body": body,
            "timestamp": time.time(),
            "service_type": "api"
        }
        
        return self.encrypt_internal_message(request_data, service_id)
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get status of all registered services."""
        current_time = datetime.now()
        
        status = {
            "total_services": len(self.registered_services),
            "active_services": 0,
            "expired_services": 0,
            "services": {}
        }
        
        for service_id, creds in self.registered_services.items():
            is_active = creds.expires_at is None or current_time < creds.expires_at
            
            if is_active:
                status["active_services"] += 1
            else:
                status["expired_services"] += 1
            
            status["services"][service_id] = {
                "active": is_active,
                "permissions": creds.permissions,
                "created_at": creds.created_at.isoformat(),
                "expires_at": creds.expires_at.isoformat() if creds.expires_at else None
            }
        
        return status
    
    def revoke_service(self, service_id: str) -> bool:
        """Revoke a service's access."""
        if service_id in self.registered_services:
            del self.registered_services[service_id]
            del self.service_keys[service_id]
            return True
        return False


# Global internal service encryption manager
internal_encryption = InternalServiceEncryption()


# Helper functions for common operations
def create_encrypted_service_request(
    service_id: str,
    target_service: str,
    data: Dict[str, Any]
) -> Tuple[str, EncryptedMessage]:
    """Create an encrypted service request with authentication token."""
    token = internal_encryption.create_service_token(service_id, target_service)
    encrypted_msg = internal_encryption.encrypt_internal_message(data, service_id)
    return token, encrypted_msg


def process_encrypted_service_request(
    token: str,
    encrypted_msg: EncryptedMessage,
    expected_service: str = None
) -> Tuple[Dict[str, Any], Any]:
    """Process and decrypt an encrypted service request."""
    # Verify the service token
    token_payload = internal_encryption.verify_service_token(token, expected_service)
    
    # Decrypt the message
    decrypted_data = internal_encryption.decrypt_internal_message(
        encrypted_msg, 
        token_payload["service_id"]
    )
    
    return token_payload, decrypted_data


def secure_service_call(
    calling_service: str,
    target_service: str,
    operation: str,
    data: Dict[str, Any] = None
) -> EncryptedMessage:
    """Make a secure call between services."""
    request_data = {
        "operation": operation,
        "data": data or {},
        "calling_service": calling_service,
        "target_service": target_service,
        "timestamp": time.time()
    }
    
    return internal_encryption.encrypt_internal_message(
        request_data, 
        calling_service,
        target_service
    )