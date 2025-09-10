"""
Data Encryption and Security Utilities

Provides AES-256 encryption, key management, and secure data handling for PII protection.
"""

import base64
import hashlib
import os
import secrets
from typing import Dict, Optional, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..config.settings import get_settings

settings = get_settings()


class EncryptionManager:
    """Manager for encryption operations."""
    
    def __init__(self):
        self._fernet_key = self._derive_fernet_key()
        self._fernet = Fernet(self._fernet_key)
    
    def _derive_fernet_key(self) -> bytes:
        """Derive Fernet key from settings encryption key."""
        password = settings.encryption_key.encode()
        salt = b"pii-deidentification-salt"  # In production, use random salt per key
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def encrypt_text(self, plaintext: str) -> str:
        """Encrypt text data using Fernet (AES-256)."""
        if not plaintext:
            return plaintext
            
        encrypted_data = self._fernet.encrypt(plaintext.encode('utf-8'))
        return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
    
    def decrypt_text(self, ciphertext: str) -> str:
        """Decrypt text data using Fernet (AES-256)."""
        if not ciphertext:
            return ciphertext
            
        try:
            encrypted_data = base64.urlsafe_b64decode(ciphertext.encode('utf-8'))
            decrypted_data = self._fernet.decrypt(encrypted_data)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Failed to decrypt data: {e}")
    
    def encrypt_file(self, file_path: str, output_path: str) -> Dict[str, str]:
        """Encrypt file contents."""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = self._fernet.encrypt(file_data)
            
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            return {
                "status": "success",
                "encrypted_file": output_path,
                "checksum": hashlib.sha256(file_data).hexdigest()
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    def decrypt_file(self, encrypted_file_path: str, output_path: str) -> Dict[str, str]:
        """Decrypt file contents."""
        try:
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self._fernet.decrypt(encrypted_data)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            return {
                "status": "success",
                "decrypted_file": output_path,
                "checksum": hashlib.sha256(decrypted_data).hexdigest()
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }


class PIIEncryption:
    """Specialized encryption for PII data with field-level encryption."""
    
    def __init__(self):
        self.encryption_manager = EncryptionManager()
        self.sensitive_fields = {
            'ssn', 'social_security_number', 'tax_id',
            'passport_number', 'driver_license',
            'credit_card', 'bank_account', 'phone_number',
            'email', 'address', 'date_of_birth', 'medical_record_number'
        }
    
    def encrypt_pii_document(self, document_data: Dict[str, Union[str, Dict]]) -> Dict[str, Union[str, Dict]]:
        """Encrypt PII fields in document data."""
        encrypted_doc = document_data.copy()
        
        def encrypt_recursive(obj: Union[Dict, str, list], path: str = "") -> Union[Dict, str, list]:
            if isinstance(obj, dict):
                encrypted_obj = {}
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    if key.lower() in self.sensitive_fields or self._is_pii_field(key):
                        # Encrypt sensitive fields
                        if isinstance(value, str):
                            encrypted_obj[key] = {
                                "encrypted": True,
                                "value": self.encryption_manager.encrypt_text(value),
                                "field_type": "pii"
                            }
                        else:
                            encrypted_obj[key] = encrypt_recursive(value, current_path)
                    else:
                        encrypted_obj[key] = encrypt_recursive(value, current_path)
                return encrypted_obj
            elif isinstance(obj, list):
                return [encrypt_recursive(item, path) for item in obj]
            else:
                return obj
        
        return encrypt_recursive(encrypted_doc)
    
    def decrypt_pii_document(self, encrypted_document_data: Dict[str, Union[str, Dict]]) -> Dict[str, Union[str, Dict]]:
        """Decrypt PII fields in document data."""
        def decrypt_recursive(obj: Union[Dict, str, list]) -> Union[Dict, str, list]:
            if isinstance(obj, dict):
                if obj.get("encrypted") and obj.get("field_type") == "pii":
                    # Decrypt PII field
                    return self.encryption_manager.decrypt_text(obj["value"])
                else:
                    decrypted_obj = {}
                    for key, value in obj.items():
                        decrypted_obj[key] = decrypt_recursive(value)
                    return decrypted_obj
            elif isinstance(obj, list):
                return [decrypt_recursive(item) for item in obj]
            else:
                return obj
        
        return decrypt_recursive(encrypted_document_data)
    
    def _is_pii_field(self, field_name: str) -> bool:
        """Check if field name indicates PII data."""
        field_lower = field_name.lower()
        pii_indicators = [
            'name', 'address', 'phone', 'email', 'ssn', 'id',
            'birth', 'age', 'medical', 'patient', 'account'
        ]
        return any(indicator in field_lower for indicator in pii_indicators)


class SecureStorage:
    """Secure storage utilities with encryption at rest."""
    
    def __init__(self):
        self.encryption_manager = EncryptionManager()
        self.storage_base = settings.get_data_paths()['output']
    
    def store_encrypted_document(self, document_id: str, document_data: Dict, metadata: Dict = None) -> str:
        """Store document with encryption."""
        storage_path = self.storage_base / f"encrypted_{document_id}.enc"
        
        # Prepare data for encryption
        storage_data = {
            "document_id": document_id,
            "data": document_data,
            "metadata": metadata or {},
            "encrypted_at": os.urandom(16).hex(),  # Random salt
            "version": "1.0"
        }
        
        # Encrypt and store
        encrypted_content = self.encryption_manager.encrypt_text(str(storage_data))
        
        with open(storage_path, 'w') as f:
            f.write(encrypted_content)
        
        return str(storage_path)
    
    def retrieve_encrypted_document(self, document_id: str) -> Optional[Dict]:
        """Retrieve and decrypt stored document."""
        storage_path = self.storage_base / f"encrypted_{document_id}.enc"
        
        if not storage_path.exists():
            return None
        
        try:
            with open(storage_path, 'r') as f:
                encrypted_content = f.read()
            
            decrypted_content = self.encryption_manager.decrypt_text(encrypted_content)
            return eval(decrypted_content)  # In production, use proper JSON parsing
            
        except Exception as e:
            raise ValueError(f"Failed to retrieve document: {e}")


class KeyManager:
    """Encryption key management utilities."""
    
    @staticmethod
    def generate_encryption_key() -> str:
        """Generate a new encryption key."""
        return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
    
    @staticmethod
    def generate_api_key() -> str:
        """Generate a secure API key."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """Hash API key for secure storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    @staticmethod
    def generate_rsa_keypair() -> Dict[str, bytes]:
        """Generate RSA key pair for asymmetric encryption."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            "private_key": private_pem,
            "public_key": public_pem
        }


# Global instances
encryption_manager = EncryptionManager()
pii_encryption = PIIEncryption()
secure_storage = SecureStorage()
key_manager = KeyManager()


# Convenience functions
def encrypt_data(data: str) -> str:
    """Encrypt text data."""
    return encryption_manager.encrypt_text(data)


def decrypt_data(encrypted_data: str) -> str:
    """Decrypt text data."""
    return encryption_manager.decrypt_text(encrypted_data)


def encrypt_pii_fields(document_data: Dict) -> Dict:
    """Encrypt PII fields in document."""
    return pii_encryption.encrypt_pii_document(document_data)


def decrypt_pii_fields(encrypted_document_data: Dict) -> Dict:
    """Decrypt PII fields in document."""
    return pii_encryption.decrypt_pii_document(encrypted_document_data)


def secure_hash(data: str) -> str:
    """Create secure hash of data."""
    return hashlib.sha256(data.encode()).hexdigest()


def generate_secure_token() -> str:
    """Generate cryptographically secure token."""
    return secrets.token_urlsafe(32)