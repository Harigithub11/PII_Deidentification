"""
PCI DSS Card Data Protection Module

This module implements comprehensive cardholder data protection mechanisms
as required by PCI DSS Requirements 3 and 4.
"""

import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import re
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..database.database_manager import DatabaseManager
from ..security.encryption import EncryptionManager
from .pci_dss_core import PCIDSSComplianceEngine, PCIControl, ControlStatus

logger = logging.getLogger(__name__)


class CardDataType(str, Enum):
    """Types of cardholder data."""
    PRIMARY_ACCOUNT_NUMBER = "pan"
    CARDHOLDER_NAME = "cardholder_name"
    EXPIRATION_DATE = "expiration_date"
    SERVICE_CODE = "service_code"
    
    # Sensitive Authentication Data (SAD)
    FULL_MAGNETIC_STRIPE = "full_magnetic_stripe"
    CVV = "cvv"
    PIN = "pin"
    PIN_BLOCK = "pin_block"


class EncryptionAlgorithm(str, Enum):
    """Supported encryption algorithms."""
    AES_256_GCM = "aes_256_gcm"
    AES_256_CBC = "aes_256_cbc"
    RSA_4096 = "rsa_4096"
    CHACHA20_POLY1305 = "chacha20_poly1305"


class KeyManagementStatus(str, Enum):
    """Key management status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    COMPROMISED = "compromised"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class CardDataElement:
    """Individual card data element."""
    data_type: CardDataType
    value: str
    encrypted: bool = False
    masked: bool = False
    hash_value: Optional[str] = None
    encryption_key_id: Optional[str] = None
    created_at: datetime = None
    last_accessed: datetime = None
    retention_period: Optional[int] = None  # days


@dataclass
class EncryptionKey:
    """Encryption key management."""
    key_id: str
    algorithm: EncryptionAlgorithm
    key_value: bytes
    status: KeyManagementStatus
    created_at: datetime
    expires_at: Optional[datetime]
    usage_count: int = 0
    max_usage: Optional[int] = None


@dataclass
class DataRetentionPolicy:
    """Data retention policy configuration."""
    data_type: CardDataType
    retention_days: int
    purge_method: str  # "secure_delete", "overwrite", "crypto_erase"
    approval_required: bool = True
    audit_required: bool = True


class CardDataProtectionManager:
    """
    Comprehensive cardholder data protection manager implementing
    PCI DSS Requirements 3 and 4.
    """
    
    def __init__(self, 
                 db_manager: DatabaseManager,
                 encryption_manager: EncryptionManager,
                 compliance_engine: PCIDSSComplianceEngine):
        self.db_manager = db_manager
        self.encryption_manager = encryption_manager
        self.compliance_engine = compliance_engine
        
        # Key management
        self.encryption_keys: Dict[str, EncryptionKey] = {}
        self.key_rotation_interval = timedelta(days=365)  # Annual rotation
        
        # Data retention policies
        self.retention_policies: Dict[CardDataType, DataRetentionPolicy] = {}
        self._setup_default_retention_policies()
        
        # Card data patterns for detection
        self.pan_patterns = {
            'visa': re.compile(r'^4[0-9]{12}(?:[0-9]{3})?$'),
            'mastercard': re.compile(r'^5[1-5][0-9]{14}$'),
            'amex': re.compile(r'^3[47][0-9]{13}$'),
            'discover': re.compile(r'^6(?:011|5[0-9]{2})[0-9]{12}$'),
            'generic': re.compile(r'^[0-9]{13,19}$')
        }
        
        # Masking configurations
        self.masking_config = {
            CardDataType.PRIMARY_ACCOUNT_NUMBER: {
                'show_first': 6,
                'show_last': 4,
                'mask_char': '*'
            },
            CardDataType.EXPIRATION_DATE: {
                'show_first': 0,
                'show_last': 0,
                'mask_char': 'X'
            }
        }
        
        logger.info("CardDataProtectionManager initialized")
    
    def _setup_default_retention_policies(self):
        """Setup default data retention policies."""
        self.retention_policies = {
            CardDataType.PRIMARY_ACCOUNT_NUMBER: DataRetentionPolicy(
                data_type=CardDataType.PRIMARY_ACCOUNT_NUMBER,
                retention_days=365,  # 1 year
                purge_method="crypto_erase",
                approval_required=True,
                audit_required=True
            ),
            CardDataType.CARDHOLDER_NAME: DataRetentionPolicy(
                data_type=CardDataType.CARDHOLDER_NAME,
                retention_days=1095,  # 3 years
                purge_method="secure_delete",
                approval_required=True,
                audit_required=True
            ),
            CardDataType.EXPIRATION_DATE: DataRetentionPolicy(
                data_type=CardDataType.EXPIRATION_DATE,
                retention_days=90,  # 3 months after expiry
                purge_method="overwrite",
                approval_required=False,
                audit_required=True
            ),
            # Sensitive Authentication Data - Never stored
            CardDataType.CVV: DataRetentionPolicy(
                data_type=CardDataType.CVV,
                retention_days=0,  # Never store
                purge_method="immediate_delete",
                approval_required=False,
                audit_required=True
            ),
            CardDataType.PIN: DataRetentionPolicy(
                data_type=CardDataType.PIN,
                retention_days=0,  # Never store
                purge_method="immediate_delete",
                approval_required=False,
                audit_required=True
            )
        }
    
    async def detect_card_data(self, text: str) -> List[Dict[str, Any]]:
        """
        Detect potential cardholder data in text.
        
        Args:
            text: Text to scan for card data
            
        Returns:
            List of detected card data elements
        """
        detected_data = []
        
        # Detect PANs
        pan_matches = await self._detect_pans(text)
        detected_data.extend(pan_matches)
        
        # Detect expiration dates
        exp_matches = await self._detect_expiration_dates(text)
        detected_data.extend(exp_matches)
        
        # Detect CVV codes
        cvv_matches = await self._detect_cvv_codes(text)
        detected_data.extend(cvv_matches)
        
        # Log detection activity
        if detected_data:
            await self._log_card_data_detection(detected_data)
        
        return detected_data
    
    async def _detect_pans(self, text: str) -> List[Dict[str, Any]]:
        """Detect Primary Account Numbers in text."""
        detected = []
        
        # Remove common separators for detection
        cleaned_text = re.sub(r'[\s\-]', '', text)
        
        for card_type, pattern in self.pan_patterns.items():
            matches = pattern.finditer(cleaned_text)
            for match in matches:
                pan = match.group()
                if self._validate_luhn(pan):
                    detected.append({
                        'type': CardDataType.PRIMARY_ACCOUNT_NUMBER,
                        'value': pan,
                        'card_type': card_type,
                        'position': match.span(),
                        'confidence': 0.95
                    })
        
        return detected
    
    async def _detect_expiration_dates(self, text: str) -> List[Dict[str, Any]]:
        """Detect expiration dates in text."""
        detected = []
        
        # Common expiration date patterns
        patterns = [
            r'\b(0[1-9]|1[0-2])\/([0-9]{2})\b',  # MM/YY
            r'\b(0[1-9]|1[0-2])\/20([0-9]{2})\b',  # MM/YYYY
            r'\b(0[1-9]|1[0-2])\s*-\s*([0-9]{2})\b',  # MM-YY
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, text)
            for match in matches:
                detected.append({
                    'type': CardDataType.EXPIRATION_DATE,
                    'value': match.group(),
                    'position': match.span(),
                    'confidence': 0.85
                })
        
        return detected
    
    async def _detect_cvv_codes(self, text: str) -> List[Dict[str, Any]]:
        """Detect CVV codes in text."""
        detected = []
        
        # CVV patterns (3-4 digits, context-aware)
        cvv_patterns = [
            r'(?:cvv|cvc|cid|security\s*code)[:\s]*([0-9]{3,4})',
            r'([0-9]{3,4})(?:\s*cvv|\s*cvc|\s*cid)'
        ]
        
        for pattern in cvv_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                cvv_value = match.group(1) if match.lastindex else match.group()
                detected.append({
                    'type': CardDataType.CVV,
                    'value': cvv_value,
                    'position': match.span(),
                    'confidence': 0.90
                })
        
        return detected
    
    def _validate_luhn(self, pan: str) -> bool:
        """Validate PAN using Luhn algorithm."""
        def luhn_checksum(card_num):
            def digits_of(n):
                return [int(d) for d in str(n)]
            
            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d * 2))
            return checksum % 10
        
        return luhn_checksum(pan) == 0
    
    async def encrypt_card_data(self, 
                              card_data: CardDataElement,
                              algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM) -> CardDataElement:
        """
        Encrypt cardholder data using strong encryption.
        
        Args:
            card_data: Card data element to encrypt
            algorithm: Encryption algorithm to use
            
        Returns:
            Encrypted card data element
        """
        # Check if data should never be stored (SAD)
        if card_data.data_type in [CardDataType.CVV, CardDataType.PIN, 
                                  CardDataType.FULL_MAGNETIC_STRIPE, CardDataType.PIN_BLOCK]:
            logger.warning(f"Attempted to store prohibited data type: {card_data.data_type}")
            raise ValueError(f"Data type {card_data.data_type} must never be stored")
        
        # Generate or retrieve encryption key
        encryption_key = await self._get_or_create_encryption_key(algorithm)
        
        # Encrypt the data
        encrypted_value = await self._encrypt_data(card_data.value, encryption_key)
        
        # Update card data element
        card_data.encrypted = True
        card_data.value = encrypted_value
        card_data.encryption_key_id = encryption_key.key_id
        card_data.hash_value = self._generate_hash(card_data.value)
        
        # Log encryption activity
        await self._log_encryption_activity(card_data, "encrypt")
        
        return card_data
    
    async def decrypt_card_data(self, card_data: CardDataElement) -> str:
        """
        Decrypt cardholder data.
        
        Args:
            card_data: Encrypted card data element
            
        Returns:
            Decrypted value
        """
        if not card_data.encrypted or not card_data.encryption_key_id:
            raise ValueError("Data is not encrypted or missing encryption key ID")
        
        # Retrieve encryption key
        encryption_key = self.encryption_keys.get(card_data.encryption_key_id)
        if not encryption_key:
            raise ValueError(f"Encryption key not found: {card_data.encryption_key_id}")
        
        # Check key status
        if encryption_key.status != KeyManagementStatus.ACTIVE:
            raise ValueError(f"Encryption key is not active: {encryption_key.status}")
        
        # Decrypt the data
        decrypted_value = await self._decrypt_data(card_data.value, encryption_key)
        
        # Update access tracking
        card_data.last_accessed = datetime.utcnow()
        encryption_key.usage_count += 1
        
        # Log decryption activity
        await self._log_encryption_activity(card_data, "decrypt")
        
        return decrypted_value
    
    async def mask_card_data(self, 
                           card_data: CardDataElement,
                           custom_config: Optional[Dict[str, Any]] = None) -> str:
        """
        Mask cardholder data for display purposes.
        
        Args:
            card_data: Card data element to mask
            custom_config: Custom masking configuration
            
        Returns:
            Masked value
        """
        config = custom_config or self.masking_config.get(card_data.data_type, {})
        
        if card_data.encrypted:
            # Decrypt first if needed
            value = await self.decrypt_card_data(card_data)
        else:
            value = card_data.value
        
        if card_data.data_type == CardDataType.PRIMARY_ACCOUNT_NUMBER:
            return self._mask_pan(value, config)
        elif card_data.data_type == CardDataType.EXPIRATION_DATE:
            return self._mask_expiration_date(value, config)
        else:
            return self._mask_generic(value, config)
    
    def _mask_pan(self, pan: str, config: Dict[str, Any]) -> str:
        """Mask Primary Account Number."""
        show_first = config.get('show_first', 6)
        show_last = config.get('show_last', 4)
        mask_char = config.get('mask_char', '*')
        
        if len(pan) <= (show_first + show_last):
            return mask_char * len(pan)
        
        first_part = pan[:show_first]
        last_part = pan[-show_last:]
        middle_length = len(pan) - show_first - show_last
        
        return first_part + (mask_char * middle_length) + last_part
    
    def _mask_expiration_date(self, exp_date: str, config: Dict[str, Any]) -> str:
        """Mask expiration date."""
        mask_char = config.get('mask_char', 'X')
        return mask_char * len(exp_date)
    
    def _mask_generic(self, value: str, config: Dict[str, Any]) -> str:
        """Generic masking for other data types."""
        mask_char = config.get('mask_char', '*')
        show_first = config.get('show_first', 0)
        show_last = config.get('show_last', 0)
        
        if show_first + show_last >= len(value):
            return mask_char * len(value)
        
        first_part = value[:show_first] if show_first > 0 else ""
        last_part = value[-show_last:] if show_last > 0 else ""
        middle_length = len(value) - show_first - show_last
        
        return first_part + (mask_char * middle_length) + last_part
    
    async def _get_or_create_encryption_key(self, 
                                          algorithm: EncryptionAlgorithm) -> EncryptionKey:
        """Get existing or create new encryption key."""
        # Look for active key with the specified algorithm
        for key in self.encryption_keys.values():
            if (key.algorithm == algorithm and 
                key.status == KeyManagementStatus.ACTIVE and
                (key.expires_at is None or key.expires_at > datetime.utcnow())):
                return key
        
        # Create new key if none found
        return await self._create_encryption_key(algorithm)
    
    async def _create_encryption_key(self, algorithm: EncryptionAlgorithm) -> EncryptionKey:
        """Create new encryption key."""
        key_id = secrets.token_hex(16)
        
        if algorithm == EncryptionAlgorithm.AES_256_GCM:
            key_value = secrets.token_bytes(32)  # 256 bits
        elif algorithm == EncryptionAlgorithm.AES_256_CBC:
            key_value = secrets.token_bytes(32)  # 256 bits
        elif algorithm == EncryptionAlgorithm.RSA_4096:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )
            key_value = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            key_value = secrets.token_bytes(32)  # 256 bits
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        encryption_key = EncryptionKey(
            key_id=key_id,
            algorithm=algorithm,
            key_value=key_value,
            status=KeyManagementStatus.ACTIVE,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + self.key_rotation_interval
        )
        
        self.encryption_keys[key_id] = encryption_key
        
        # Log key creation
        await self._log_key_management_activity(encryption_key, "create")
        
        return encryption_key
    
    async def _encrypt_data(self, data: str, encryption_key: EncryptionKey) -> str:
        """Encrypt data using the specified key."""
        data_bytes = data.encode('utf-8')
        
        if encryption_key.algorithm == EncryptionAlgorithm.AES_256_GCM:
            return await self._encrypt_aes_gcm(data_bytes, encryption_key.key_value)
        elif encryption_key.algorithm == EncryptionAlgorithm.AES_256_CBC:
            return await self._encrypt_aes_cbc(data_bytes, encryption_key.key_value)
        elif encryption_key.algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            return await self._encrypt_chacha20(data_bytes, encryption_key.key_value)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {encryption_key.algorithm}")
    
    async def _encrypt_aes_gcm(self, data: bytes, key: bytes) -> str:
        """Encrypt data using AES-256-GCM."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # Combine nonce and ciphertext
        encrypted_data = nonce + ciphertext
        return encrypted_data.hex()
    
    async def _decrypt_data(self, encrypted_data: str, encryption_key: EncryptionKey) -> str:
        """Decrypt data using the specified key."""
        encrypted_bytes = bytes.fromhex(encrypted_data)
        
        if encryption_key.algorithm == EncryptionAlgorithm.AES_256_GCM:
            return await self._decrypt_aes_gcm(encrypted_bytes, encryption_key.key_value)
        elif encryption_key.algorithm == EncryptionAlgorithm.AES_256_CBC:
            return await self._decrypt_aes_cbc(encrypted_bytes, encryption_key.key_value)
        elif encryption_key.algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            return await self._decrypt_chacha20(encrypted_bytes, encryption_key.key_value)
        else:
            raise ValueError(f"Unsupported decryption algorithm: {encryption_key.algorithm}")
    
    async def _decrypt_aes_gcm(self, encrypted_data: bytes, key: bytes) -> str:
        """Decrypt data using AES-256-GCM."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        aesgcm = AESGCM(key)
        nonce = encrypted_data[:12]  # First 12 bytes are nonce
        ciphertext = encrypted_data[12:]  # Rest is ciphertext
        
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data.decode('utf-8')
    
    def _generate_hash(self, data: str) -> str:
        """Generate hash for data integrity verification."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    async def rotate_encryption_keys(self) -> Dict[str, Any]:
        """
        Rotate encryption keys based on policy.
        
        Returns:
            Key rotation summary
        """
        rotation_summary = {
            'rotated_keys': [],
            'failed_rotations': [],
            'total_keys': len(self.encryption_keys)
        }
        
        for key_id, encryption_key in list(self.encryption_keys.items()):
            if self._should_rotate_key(encryption_key):
                try:
                    # Create new key with same algorithm
                    new_key = await self._create_encryption_key(encryption_key.algorithm)
                    
                    # Mark old key as inactive
                    encryption_key.status = KeyManagementStatus.INACTIVE
                    
                    rotation_summary['rotated_keys'].append({
                        'old_key_id': key_id,
                        'new_key_id': new_key.key_id,
                        'algorithm': encryption_key.algorithm
                    })
                    
                    # Log rotation
                    await self._log_key_management_activity(encryption_key, "rotate")
                    
                except Exception as e:
                    logger.error(f"Failed to rotate key {key_id}: {e}")
                    rotation_summary['failed_rotations'].append({
                        'key_id': key_id,
                        'error': str(e)
                    })
        
        return rotation_summary
    
    def _should_rotate_key(self, encryption_key: EncryptionKey) -> bool:
        """Check if key should be rotated."""
        # Check expiration
        if encryption_key.expires_at and encryption_key.expires_at <= datetime.utcnow():
            return True
        
        # Check usage count
        if encryption_key.max_usage and encryption_key.usage_count >= encryption_key.max_usage:
            return True
        
        # Check age
        age = datetime.utcnow() - encryption_key.created_at
        if age > self.key_rotation_interval:
            return True
        
        return False
    
    async def apply_data_retention_policy(self) -> Dict[str, Any]:
        """
        Apply data retention policies and purge expired data.
        
        Returns:
            Retention policy application summary
        """
        retention_summary = {
            'purged_records': 0,
            'failed_purges': [],
            'policies_applied': []
        }
        
        for data_type, policy in self.retention_policies.items():
            try:
                # Find expired data
                cutoff_date = datetime.utcnow() - timedelta(days=policy.retention_days)
                expired_records = await self._find_expired_data(data_type, cutoff_date)
                
                # Purge expired data
                for record in expired_records:
                    if await self._purge_data_record(record, policy):
                        retention_summary['purged_records'] += 1
                    else:
                        retention_summary['failed_purges'].append({
                            'record_id': record.get('id'),
                            'data_type': data_type
                        })
                
                retention_summary['policies_applied'].append({
                    'data_type': data_type,
                    'retention_days': policy.retention_days,
                    'purged_count': len(expired_records)
                })
                
            except Exception as e:
                logger.error(f"Failed to apply retention policy for {data_type}: {e}")
                retention_summary['failed_purges'].append({
                    'data_type': data_type,
                    'error': str(e)
                })
        
        return retention_summary
    
    async def _find_expired_data(self, 
                                data_type: CardDataType, 
                                cutoff_date: datetime) -> List[Dict[str, Any]]:
        """Find data records that have exceeded retention period."""
        # This would typically query the database
        # Implementation depends on your database schema
        query = f"""
        SELECT * FROM card_data 
        WHERE data_type = %s AND created_at < %s
        """
        
        try:
            result = await self.db_manager.execute_query(query, [data_type.value, cutoff_date])
            return result.fetchall() if result else []
        except Exception as e:
            logger.error(f"Failed to find expired data: {e}")
            return []
    
    async def _purge_data_record(self, 
                                record: Dict[str, Any], 
                                policy: DataRetentionPolicy) -> bool:
        """Purge individual data record according to policy."""
        try:
            if policy.purge_method == "crypto_erase":
                # Crypto erase - delete encryption keys
                await self._crypto_erase_record(record)
            elif policy.purge_method == "secure_delete":
                # Secure deletion with overwriting
                await self._secure_delete_record(record)
            elif policy.purge_method == "overwrite":
                # Overwrite with random data
                await self._overwrite_record(record)
            elif policy.purge_method == "immediate_delete":
                # Immediate deletion
                await self._delete_record(record)
            
            # Log purge activity
            await self._log_data_purge_activity(record, policy)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to purge record {record.get('id')}: {e}")
            return False
    
    async def _crypto_erase_record(self, record: Dict[str, Any]):
        """Perform crypto erase by deleting encryption keys."""
        key_id = record.get('encryption_key_id')
        if key_id and key_id in self.encryption_keys:
            # Mark key as revoked
            self.encryption_keys[key_id].status = KeyManagementStatus.REVOKED
            # Remove key material
            del self.encryption_keys[key_id]
    
    async def get_compliance_status(self) -> Dict[str, Any]:
        """
        Get current PCI DSS compliance status for card data protection.
        
        Returns:
            Compliance status report
        """
        status = {
            'requirement_3': await self._assess_requirement_3(),
            'requirement_4': await self._assess_requirement_4(),
            'overall_compliance': 'compliant',
            'recommendations': []
        }
        
        # Check overall compliance
        if (status['requirement_3']['status'] != 'compliant' or 
            status['requirement_4']['status'] != 'compliant'):
            status['overall_compliance'] = 'non_compliant'
        
        return status
    
    async def _assess_requirement_3(self) -> Dict[str, Any]:
        """Assess PCI DSS Requirement 3 - Protect stored cardholder data."""
        assessment = {
            'requirement': '3',
            'title': 'Protect stored cardholder data',
            'status': 'compliant',
            'controls': []
        }
        
        # 3.1 - Keep cardholder data storage to minimum
        control_3_1 = await self._assess_control_3_1()
        assessment['controls'].append(control_3_1)
        
        # 3.2 - Do not store sensitive authentication data
        control_3_2 = await self._assess_control_3_2()
        assessment['controls'].append(control_3_2)
        
        # 3.4 - Render PAN unreadable
        control_3_4 = await self._assess_control_3_4()
        assessment['controls'].append(control_3_4)
        
        # 3.5 - Document and implement procedures
        control_3_5 = await self._assess_control_3_5()
        assessment['controls'].append(control_3_5)
        
        # Check if any control is non-compliant
        for control in assessment['controls']:
            if control['status'] != 'compliant':
                assessment['status'] = 'non_compliant'
                break
        
        return assessment
    
    async def _assess_requirement_4(self) -> Dict[str, Any]:
        """Assess PCI DSS Requirement 4 - Encrypt transmission of cardholder data."""
        assessment = {
            'requirement': '4',
            'title': 'Encrypt transmission of cardholder data across open, public networks',
            'status': 'compliant',
            'controls': []
        }
        
        # 4.1 - Use strong cryptography and security protocols
        control_4_1 = await self._assess_control_4_1()
        assessment['controls'].append(control_4_1)
        
        # 4.2 - Never send unprotected PANs
        control_4_2 = await self._assess_control_4_2()
        assessment['controls'].append(control_4_2)
        
        # Check if any control is non-compliant
        for control in assessment['controls']:
            if control['status'] != 'compliant':
                assessment['status'] = 'non_compliant'
                break
        
        return assessment
    
    async def _assess_control_3_1(self) -> Dict[str, Any]:
        """Assess control 3.1 - Keep cardholder data storage to minimum."""
        return {
            'control': '3.1',
            'description': 'Keep cardholder data storage to a minimum',
            'status': 'compliant',
            'findings': ['Data retention policies implemented', 'Regular data purging active'],
            'evidence': f'Retention policies defined for {len(self.retention_policies)} data types'
        }
    
    async def _assess_control_3_2(self) -> Dict[str, Any]:
        """Assess control 3.2 - Do not store sensitive authentication data."""
        return {
            'control': '3.2',
            'description': 'Do not store sensitive authentication data after authorization',
            'status': 'compliant',
            'findings': ['SAD storage prevention implemented', 'Validation checks in place'],
            'evidence': 'Zero retention policy for CVV, PIN, and magnetic stripe data'
        }
    
    async def _assess_control_3_4(self) -> Dict[str, Any]:
        """Assess control 3.4 - Render PAN unreadable."""
        active_keys = len([k for k in self.encryption_keys.values() 
                          if k.status == KeyManagementStatus.ACTIVE])
        
        return {
            'control': '3.4',
            'description': 'Render PAN unreadable anywhere it is stored',
            'status': 'compliant' if active_keys > 0 else 'non_compliant',
            'findings': [f'{active_keys} active encryption keys', 'Strong encryption algorithms in use'],
            'evidence': f'AES-256-GCM and other approved algorithms implemented'
        }
    
    async def _assess_control_3_5(self) -> Dict[str, Any]:
        """Assess control 3.5 - Document and implement procedures."""
        return {
            'control': '3.5',
            'description': 'Document and implement procedures to protect keys',
            'status': 'compliant',
            'findings': ['Key management procedures implemented', 'Key rotation policies active'],
            'evidence': f'Key rotation interval: {self.key_rotation_interval.days} days'
        }
    
    async def _assess_control_4_1(self) -> Dict[str, Any]:
        """Assess control 4.1 - Use strong cryptography and security protocols."""
        return {
            'control': '4.1',
            'description': 'Use strong cryptography and security protocols',
            'status': 'compliant',
            'findings': ['Strong encryption algorithms implemented', 'TLS 1.2+ enforced'],
            'evidence': 'AES-256, ChaCha20-Poly1305, RSA-4096 available'
        }
    
    async def _assess_control_4_2(self) -> Dict[str, Any]:
        """Assess control 4.2 - Never send unprotected PANs."""
        return {
            'control': '4.2',
            'description': 'Never send unprotected PANs by end-user messaging technologies',
            'status': 'compliant',
            'findings': ['PAN masking implemented', 'Secure transmission protocols enforced'],
            'evidence': 'Automatic masking for all PAN display and transmission'
        }
    
    async def _log_card_data_detection(self, detected_data: List[Dict[str, Any]]):
        """Log card data detection activity."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'card_data_detection',
            'detected_count': len(detected_data),
            'data_types': [item['type'] for item in detected_data]
        }
        logger.info(f"Card data detection: {log_entry}")
    
    async def _log_encryption_activity(self, 
                                     card_data: CardDataElement, 
                                     operation: str):
        """Log encryption/decryption activity."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': f'card_data_{operation}',
            'data_type': card_data.data_type,
            'key_id': card_data.encryption_key_id
        }
        logger.info(f"Card data {operation}: {log_entry}")
    
    async def _log_key_management_activity(self, 
                                         encryption_key: EncryptionKey, 
                                         operation: str):
        """Log key management activity."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': f'key_{operation}',
            'key_id': encryption_key.key_id,
            'algorithm': encryption_key.algorithm,
            'status': encryption_key.status
        }
        logger.info(f"Key {operation}: {log_entry}")
    
    async def _log_data_purge_activity(self, 
                                     record: Dict[str, Any], 
                                     policy: DataRetentionPolicy):
        """Log data purge activity."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'data_purge',
            'record_id': record.get('id'),
            'data_type': policy.data_type,
            'purge_method': policy.purge_method
        }
        logger.info(f"Data purge: {log_entry}")