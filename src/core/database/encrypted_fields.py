"""
Encrypted Database Fields

Provides SQLAlchemy custom field types that automatically encrypt/decrypt data.
"""

import json
from typing import Any, Optional, Union, Dict

from sqlalchemy import String, Text, TypeDecorator
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Dialect

from ..security.encryption import encryption_manager


class EncryptedType(TypeDecorator):
    """Base class for encrypted field types."""
    
    impl = String
    cache_ok = True
    
    def __init__(self, secret_key: Optional[str] = None, **kwargs):
        """
        Initialize encrypted field type.
        
        Args:
            secret_key: Optional encryption key (uses default if None)
            **kwargs: Additional arguments for base type
        """
        self.secret_key = secret_key
        super().__init__(**kwargs)
    
    def process_bind_param(self, value: Any, dialect: Dialect) -> Optional[str]:
        """Encrypt value before storing in database."""
        if value is not None:
            if isinstance(value, str):
                return encryption_manager.encrypt_text(value)
            else:
                # Convert to string representation for non-string types
                return encryption_manager.encrypt_text(str(value))
        return value
    
    def process_result_value(self, value: Any, dialect: Dialect) -> Any:
        """Decrypt value after retrieving from database."""
        if value is not None:
            try:
                return encryption_manager.decrypt_text(value)
            except Exception:
                # Return original value if decryption fails (for backward compatibility)
                return value
        return value


class EncryptedString(EncryptedType):
    """Encrypted string field for SQLAlchemy models."""
    
    impl = String
    
    def __init__(self, length: int = 255, **kwargs):
        """
        Initialize encrypted string field.
        
        Args:
            length: Maximum length for the encrypted string storage
            **kwargs: Additional arguments
        """
        # Encrypted data is longer than original, so increase storage size
        encrypted_length = max(length * 2, 500)  # At least double the original length
        super().__init__(length=encrypted_length, **kwargs)
    
    def process_result_value(self, value: Any, dialect: Dialect) -> Optional[str]:
        """Decrypt and return as string."""
        decrypted = super().process_result_value(value, dialect)
        return decrypted if decrypted is None else str(decrypted)


class EncryptedText(EncryptedType):
    """Encrypted text field for large text data."""
    
    impl = Text
    
    def process_result_value(self, value: Any, dialect: Dialect) -> Optional[str]:
        """Decrypt and return as string."""
        decrypted = super().process_result_value(value, dialect)
        return decrypted if decrypted is None else str(decrypted)


class EncryptedJSON(EncryptedType):
    """Encrypted JSON field that stores JSON data encrypted."""
    
    impl = Text
    
    def process_bind_param(self, value: Any, dialect: Dialect) -> Optional[str]:
        """Serialize to JSON and encrypt before storing."""
        if value is not None:
            try:
                json_str = json.dumps(value, ensure_ascii=False)
                return encryption_manager.encrypt_text(json_str)
            except (TypeError, ValueError):
                # If serialization fails, treat as regular encrypted text
                return encryption_manager.encrypt_text(str(value))
        return value
    
    def process_result_value(self, value: Any, dialect: Dialect) -> Any:
        """Decrypt and deserialize from JSON."""
        if value is not None:
            try:
                decrypted_str = encryption_manager.decrypt_text(value)
                if decrypted_str:
                    return json.loads(decrypted_str)
            except (json.JSONDecodeError, ValueError, Exception):
                # If decryption or JSON parsing fails, return None
                return None
        return value


class EncryptedEmailType(EncryptedType):
    """Encrypted email field with additional validation."""
    
    impl = String
    
    def __init__(self, **kwargs):
        # Email addresses can be up to 320 characters, encrypted needs more space
        super().__init__(length=800, **kwargs)
    
    def process_bind_param(self, value: Any, dialect: Dialect) -> Optional[str]:
        """Validate email format and encrypt."""
        if value is not None:
            email_str = str(value).lower().strip()  # Normalize email
            if '@' not in email_str:
                raise ValueError(f"Invalid email format: {email_str}")
            return encryption_manager.encrypt_text(email_str)
        return value
    
    def process_result_value(self, value: Any, dialect: Dialect) -> Optional[str]:
        """Decrypt and return email."""
        decrypted = super().process_result_value(value, dialect)
        return decrypted.lower().strip() if decrypted else None


class EncryptedPhoneType(EncryptedType):
    """Encrypted phone number field."""
    
    impl = String
    
    def __init__(self, **kwargs):
        super().__init__(length=400, **kwargs)
    
    def process_bind_param(self, value: Any, dialect: Dialect) -> Optional[str]:
        """Normalize and encrypt phone number."""
        if value is not None:
            # Remove common phone number formatting
            phone_str = str(value).strip()
            # Keep only digits, +, and basic formatting
            normalized_phone = ''.join(c for c in phone_str if c.isdigit() or c in '+()-. ')
            return encryption_manager.encrypt_text(normalized_phone)
        return value


class EncryptedSSNType(EncryptedType):
    """Encrypted Social Security Number field with extra security."""
    
    impl = String
    
    def __init__(self, **kwargs):
        super().__init__(length=400, **kwargs)
    
    def process_bind_param(self, value: Any, dialect: Dialect) -> Optional[str]:
        """Validate and encrypt SSN."""
        if value is not None:
            ssn_str = str(value).strip().replace('-', '').replace(' ', '')
            if len(ssn_str) != 9 or not ssn_str.isdigit():
                raise ValueError("Invalid SSN format")
            return encryption_manager.encrypt_text(ssn_str)
        return value
    
    def process_result_value(self, value: Any, dialect: Dialect) -> Optional[str]:
        """Decrypt and format SSN."""
        decrypted = super().process_result_value(value, dialect)
        if decrypted and len(decrypted) == 9:
            # Format as XXX-XX-XXXX
            return f"{decrypted[:3]}-{decrypted[3:5]}-{decrypted[5:]}"
        return decrypted


class EncryptedCreditCardType(EncryptedType):
    """Encrypted credit card number field."""
    
    impl = String
    
    def __init__(self, **kwargs):
        super().__init__(length=400, **kwargs)
    
    def process_bind_param(self, value: Any, dialect: Dialect) -> Optional[str]:
        """Validate and encrypt credit card number."""
        if value is not None:
            cc_str = str(value).strip().replace('-', '').replace(' ', '')
            if not cc_str.isdigit() or len(cc_str) < 13 or len(cc_str) > 19:
                raise ValueError("Invalid credit card number format")
            return encryption_manager.encrypt_text(cc_str)
        return value
    
    def process_result_value(self, value: Any, dialect: Dialect) -> Optional[str]:
        """Decrypt and mask credit card number."""
        decrypted = super().process_result_value(value, dialect)
        if decrypted and len(decrypted) >= 13:
            # Return masked version (show only last 4 digits)
            return f"****-****-****-{decrypted[-4:]}"
        return decrypted
    
    def get_full_number(self, encrypted_value: str) -> Optional[str]:
        """Get full credit card number (for authorized operations only)."""
        try:
            return encryption_manager.decrypt_text(encrypted_value)
        except Exception:
            return None


class SearchableEncryptedType(EncryptedType):
    """
    Encrypted field that supports search operations.
    Uses deterministic encryption for exact matches.
    """
    
    impl = String
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    
    def create_search_hash(self, value: str) -> str:
        """Create searchable hash for the value."""
        import hashlib
        # Create deterministic hash for searching
        search_value = f"{value}_{encryption_manager._fernet_key[:16].decode('utf-8', errors='ignore')}"
        return hashlib.sha256(search_value.encode()).hexdigest()[:32]
    
    def process_bind_param(self, value: Any, dialect: Dialect) -> Optional[str]:
        """Encrypt value and store with search hash."""
        if value is not None:
            encrypted = encryption_manager.encrypt_text(str(value))
            search_hash = self.create_search_hash(str(value))
            # Store as: searchhash:encrypteddata
            return f"{search_hash}:{encrypted}"
        return value
    
    def process_result_value(self, value: Any, dialect: Dialect) -> Any:
        """Extract and decrypt the actual value."""
        if value is not None and ':' in str(value):
            try:
                _, encrypted_data = str(value).split(':', 1)
                return encryption_manager.decrypt_text(encrypted_data)
            except Exception:
                return None
        return value
    
    def create_search_value(self, search_term: str) -> str:
        """Create search value for queries."""
        search_hash = self.create_search_hash(search_term)
        return f"{search_hash}:%"  # Use LIKE with wildcard for the encrypted part


# Convenience functions for creating encrypted fields
def create_encrypted_string(length: int = 255, **kwargs) -> EncryptedString:
    """Create an encrypted string field."""
    return EncryptedString(length=length, **kwargs)


def create_encrypted_text(**kwargs) -> EncryptedText:
    """Create an encrypted text field."""
    return EncryptedText(**kwargs)


def create_encrypted_json(**kwargs) -> EncryptedJSON:
    """Create an encrypted JSON field."""
    return EncryptedJSON(**kwargs)


def create_encrypted_email(**kwargs) -> EncryptedEmailType:
    """Create an encrypted email field."""
    return EncryptedEmailType(**kwargs)


def create_encrypted_phone(**kwargs) -> EncryptedPhoneType:
    """Create an encrypted phone field."""
    return EncryptedPhoneType(**kwargs)


def create_encrypted_ssn(**kwargs) -> EncryptedSSNType:
    """Create an encrypted SSN field."""
    return EncryptedSSNType(**kwargs)


def create_searchable_encrypted_field(length: int = 255, **kwargs) -> SearchableEncryptedType:
    """Create a searchable encrypted field."""
    return SearchableEncryptedType(length=length*3, **kwargs)  # Extra space for hash prefix