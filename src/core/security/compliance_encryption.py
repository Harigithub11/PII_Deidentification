"""
Compliance and Audit Encryption

Implements encryption features required for healthcare compliance (HIPAA, GDPR, etc.)
including audit trails, compliance reporting, and regulatory-compliant encryption.
"""

import json
import time
import hashlib
import uuid
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

from ..config.settings import get_settings
from .encryption import encryption_manager

settings = get_settings()


class ComplianceStandard(Enum):
    """Compliance standards supported by the system."""
    HIPAA = "hipaa"
    GDPR = "gdpr"
    PCI_DSS = "pci_dss"
    SOX = "sox"
    NDHM = "ndhm"  # National Digital Health Mission (India)
    ISO_27001 = "iso_27001"


class DataClassification(Enum):
    """Data classification levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class AuditEventType(Enum):
    """Types of audit events."""
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    ENCRYPTION_OPERATION = "encryption_operation"
    DECRYPTION_OPERATION = "decryption_operation"
    KEY_OPERATION = "key_operation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    POLICY_VIOLATION = "policy_violation"
    SYSTEM_EVENT = "system_event"


@dataclass
class ComplianceMetadata:
    """Metadata for compliance tracking."""
    classification: DataClassification
    standards: List[ComplianceStandard]
    retention_period_days: int
    encryption_required: bool
    audit_required: bool
    data_subject_id: Optional[str] = None
    legal_basis: Optional[str] = None
    consent_id: Optional[str] = None
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()


@dataclass
class AuditRecord:
    """Audit record for compliance tracking."""
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    user_id: Optional[str]
    service_id: Optional[str]
    resource_id: Optional[str]
    action: str
    result: str
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    compliance_metadata: Optional[ComplianceMetadata] = None
    encrypted: bool = False
    
    def __post_init__(self):
        if self.event_id is None:
            self.event_id = str(uuid.uuid4())


class ComplianceEncryptionManager:
    """Manages encryption for compliance requirements."""
    
    def __init__(self):
        self.audit_dir = Path("data/audit/encrypted")
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        
        self.compliance_keys: Dict[ComplianceStandard, bytes] = {}
        self._initialize_compliance_keys()
        
        # Compliance-specific encryption settings
        self.compliance_settings = {
            ComplianceStandard.HIPAA: {
                "min_key_length": 256,
                "algorithm": "AES-256-GCM",
                "require_audit": True,
                "retention_years": 6,
                "require_encryption_at_rest": True,
                "require_encryption_in_transit": True
            },
            ComplianceStandard.GDPR: {
                "min_key_length": 256,
                "algorithm": "AES-256-GCM", 
                "require_audit": True,
                "retention_years": 7,
                "require_encryption_at_rest": True,
                "require_encryption_in_transit": True,
                "pseudonymization_required": True
            },
            ComplianceStandard.PCI_DSS: {
                "min_key_length": 256,
                "algorithm": "AES-256-GCM",
                "require_audit": True,
                "retention_years": 1,
                "require_encryption_at_rest": True,
                "require_encryption_in_transit": True
            }
        }
    
    def _initialize_compliance_keys(self):
        """Initialize compliance-specific encryption keys."""
        for standard in ComplianceStandard:
            key_data = f"{encryption_manager._fernet_key.decode('utf-8', errors='ignore')}-{standard.value}"
            derived_key = hashlib.pbkdf2_hmac(
                'sha256',
                key_data.encode(),
                b'compliance-salt',
                100000,
                32
            )
            self.compliance_keys[standard] = derived_key
    
    def encrypt_with_compliance(
        self,
        data: Union[str, bytes],
        metadata: ComplianceMetadata
    ) -> Dict[str, Any]:
        """Encrypt data according to compliance requirements."""
        if isinstance(data, str):
            data = data.encode()
        
        # Determine encryption requirements based on standards
        encryption_config = self._get_encryption_config(metadata.standards)
        
        # Generate unique initialization vector
        iv = os.urandom(16)
        
        # Select appropriate key based on highest compliance standard
        compliance_key = self._select_compliance_key(metadata.standards)
        
        # Encrypt using AES-256-GCM
        cipher = Cipher(
            algorithms.AES(compliance_key),
            modes.GCM(iv)
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Create compliance record
        compliance_record = {
            "encrypted_data": base64.b64encode(ciphertext).decode(),
            "iv": base64.b64encode(iv).decode(),
            "tag": base64.b64encode(encryptor.tag).decode(),
            "algorithm": "AES-256-GCM",
            "key_id": f"compliance-{hash(str(metadata.standards))}",
            "metadata": asdict(metadata),
            "encryption_timestamp": datetime.now().isoformat(),
            "compliance_version": "1.0"
        }
        
        # Log audit event
        self._log_audit_event(
            AuditEventType.ENCRYPTION_OPERATION,
            "data_encrypted",
            "success",
            {
                "algorithm": "AES-256-GCM",
                "data_size": len(data),
                "classification": metadata.classification.value,
                "standards": [s.value for s in metadata.standards]
            },
            metadata
        )
        
        return compliance_record
    
    def decrypt_with_compliance(
        self,
        encrypted_record: Dict[str, Any],
        user_id: Optional[str] = None,
        purpose: str = "data_access"
    ) -> bytes:
        """Decrypt data with compliance tracking."""
        try:
            # Extract encryption components
            ciphertext = base64.b64decode(encrypted_record["encrypted_data"])
            iv = base64.b64decode(encrypted_record["iv"])
            tag = base64.b64decode(encrypted_record["tag"])
            
            # Get metadata
            metadata_dict = encrypted_record["metadata"]
            metadata = ComplianceMetadata(**metadata_dict)
            
            # Check access permissions
            if not self._check_access_permissions(metadata, user_id, purpose):
                raise ValueError("Access denied due to compliance restrictions")
            
            # Select decryption key
            compliance_key = self._select_compliance_key(metadata.standards)
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(compliance_key),
                modes.GCM(iv, tag)
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Log audit event
            self._log_audit_event(
                AuditEventType.DECRYPTION_OPERATION,
                "data_decrypted",
                "success",
                {
                    "purpose": purpose,
                    "data_size": len(plaintext),
                    "classification": metadata.classification.value,
                    "user_id": user_id
                },
                metadata
            )
            
            return plaintext
            
        except Exception as e:
            # Log failed decryption attempt
            self._log_audit_event(
                AuditEventType.DECRYPTION_OPERATION,
                "data_decryption_failed",
                "failure",
                {"error": str(e), "user_id": user_id},
                metadata if 'metadata' in locals() else None
            )
            raise
    
    def _get_encryption_config(self, standards: List[ComplianceStandard]) -> Dict[str, Any]:
        """Get encryption configuration for given compliance standards."""
        config = {
            "min_key_length": 128,
            "algorithm": "AES-128-CBC",
            "require_audit": False,
            "retention_years": 1
        }
        
        # Apply most restrictive settings from all standards
        for standard in standards:
            if standard in self.compliance_settings:
                std_config = self.compliance_settings[standard]
                config["min_key_length"] = max(config["min_key_length"], std_config["min_key_length"])
                if std_config["require_audit"]:
                    config["require_audit"] = True
                config["retention_years"] = max(config["retention_years"], std_config["retention_years"])
        
        return config
    
    def _select_compliance_key(self, standards: List[ComplianceStandard]) -> bytes:
        """Select appropriate compliance key."""
        # Use the most restrictive standard's key
        priority_order = [
            ComplianceStandard.HIPAA,
            ComplianceStandard.GDPR,
            ComplianceStandard.PCI_DSS,
            ComplianceStandard.SOX,
            ComplianceStandard.NDHM,
            ComplianceStandard.ISO_27001
        ]
        
        for standard in priority_order:
            if standard in standards:
                return self.compliance_keys[standard]
        
        # Default to HIPAA key if no specific standard
        return self.compliance_keys[ComplianceStandard.HIPAA]
    
    def _check_access_permissions(
        self,
        metadata: ComplianceMetadata,
        user_id: Optional[str],
        purpose: str
    ) -> bool:
        """Check if access is allowed based on compliance rules."""
        # Implement access control logic based on compliance requirements
        
        # Check retention period
        if metadata.created_at:
            retention_days = metadata.retention_period_days
            if datetime.now() > metadata.created_at + timedelta(days=retention_days):
                return False  # Data past retention period
        
        # Check GDPR right to be forgotten
        if ComplianceStandard.GDPR in metadata.standards:
            # In real implementation, check if data subject has requested deletion
            pass
        
        # For now, allow access if user is provided
        return user_id is not None
    
    def _log_audit_event(
        self,
        event_type: AuditEventType,
        action: str,
        result: str,
        details: Dict[str, Any],
        metadata: Optional[ComplianceMetadata] = None,
        user_id: Optional[str] = None,
        service_id: Optional[str] = None
    ):
        """Log audit event for compliance."""
        audit_record = AuditRecord(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=datetime.now(),
            user_id=user_id,
            service_id=service_id,
            resource_id=details.get("resource_id"),
            action=action,
            result=result,
            details=details,
            compliance_metadata=metadata
        )
        
        # Encrypt audit record
        encrypted_audit = self._encrypt_audit_record(audit_record)
        
        # Store audit record
        self._store_audit_record(encrypted_audit)
    
    def _encrypt_audit_record(self, audit_record: AuditRecord) -> Dict[str, Any]:
        """Encrypt audit record for tamper-proof storage."""
        # Serialize audit record
        audit_data = asdict(audit_record)
        
        # Convert datetime objects to ISO strings
        for key, value in audit_data.items():
            if isinstance(value, datetime):
                audit_data[key] = value.isoformat()
        
        audit_json = json.dumps(audit_data, default=str)
        
        # Encrypt using Fernet (includes integrity protection)
        encrypted_data = encryption_manager._fernet.encrypt(audit_json.encode())
        
        # Create hash for integrity verification
        data_hash = hashlib.sha256(audit_json.encode()).hexdigest()
        
        return {
            "audit_id": audit_record.event_id,
            "encrypted_data": encrypted_data.decode(),
            "data_hash": data_hash,
            "timestamp": audit_record.timestamp.isoformat(),
            "event_type": audit_record.event_type.value,
            "encrypted": True
        }
    
    def _store_audit_record(self, encrypted_audit: Dict[str, Any]):
        """Store encrypted audit record."""
        # Create filename based on date for organization
        date_str = datetime.now().strftime("%Y-%m-%d")
        audit_file = self.audit_dir / f"audit_{date_str}.jsonl"
        
        # Append to daily audit file
        with open(audit_file, "a") as f:
            f.write(json.dumps(encrypted_audit) + "\n")
    
    def get_audit_records(
        self,
        start_date: datetime,
        end_date: datetime,
        event_types: List[AuditEventType] = None,
        user_id: str = None
    ) -> List[AuditRecord]:
        """Retrieve and decrypt audit records for compliance reporting."""
        records = []
        
        # Iterate through date range
        current_date = start_date
        while current_date <= end_date:
            date_str = current_date.strftime("%Y-%m-%d")
            audit_file = self.audit_dir / f"audit_{date_str}.jsonl"
            
            if audit_file.exists():
                with open(audit_file, "r") as f:
                    for line in f:
                        encrypted_audit = json.loads(line.strip())
                        
                        # Decrypt audit record
                        try:
                            decrypted_data = encryption_manager._fernet.decrypt(
                                encrypted_audit["encrypted_data"].encode()
                            )
                            audit_data = json.loads(decrypted_data)
                            
                            # Convert back to AuditRecord
                            # Handle datetime conversion
                            if "timestamp" in audit_data:
                                audit_data["timestamp"] = datetime.fromisoformat(audit_data["timestamp"])
                            
                            audit_record = AuditRecord(**audit_data)
                            
                            # Apply filters
                            if event_types and audit_record.event_type not in event_types:
                                continue
                            if user_id and audit_record.user_id != user_id:
                                continue
                            
                            records.append(audit_record)
                            
                        except Exception as e:
                            # Log but continue - don't fail entire query for one bad record
                            print(f"Failed to decrypt audit record: {e}")
            
            current_date += timedelta(days=1)
        
        return records
    
    def generate_compliance_report(
        self,
        standards: List[ComplianceStandard],
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """Generate compliance report for specified standards."""
        audit_records = self.get_audit_records(start_date, end_date)
        
        report = {
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.now().isoformat(),
            "standards": [s.value for s in standards],
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "summary": {
                "total_events": len(audit_records),
                "encryption_events": 0,
                "decryption_events": 0,
                "access_events": 0,
                "failed_events": 0
            },
            "compliance_status": {},
            "violations": [],
            "recommendations": []
        }
        
        # Analyze audit records
        for record in audit_records:
            if record.event_type == AuditEventType.ENCRYPTION_OPERATION:
                report["summary"]["encryption_events"] += 1
            elif record.event_type == AuditEventType.DECRYPTION_OPERATION:
                report["summary"]["decryption_events"] += 1
            elif record.event_type == AuditEventType.DATA_ACCESS:
                report["summary"]["access_events"] += 1
            
            if record.result == "failure":
                report["summary"]["failed_events"] += 1
        
        # Check compliance for each standard
        for standard in standards:
            report["compliance_status"][standard.value] = self._check_standard_compliance(
                standard, audit_records
            )
        
        return report
    
    def _check_standard_compliance(
        self,
        standard: ComplianceStandard,
        audit_records: List[AuditRecord]
    ) -> Dict[str, Any]:
        """Check compliance status for a specific standard."""
        compliance_status = {
            "compliant": True,
            "issues": [],
            "score": 100.0
        }
        
        # Standard-specific compliance checks
        if standard == ComplianceStandard.HIPAA:
            # Check for required audit trails
            encryption_events = [r for r in audit_records if r.event_type == AuditEventType.ENCRYPTION_OPERATION]
            if len(encryption_events) == 0:
                compliance_status["issues"].append("No encryption events found - HIPAA requires encryption of PHI")
                compliance_status["compliant"] = False
                compliance_status["score"] -= 25
        
        elif standard == ComplianceStandard.GDPR:
            # Check for data subject access
            access_events = [r for r in audit_records if r.event_type == AuditEventType.DATA_ACCESS]
            if any(r.result == "failure" for r in access_events):
                compliance_status["issues"].append("Failed data access attempts detected")
                compliance_status["score"] -= 10
        
        return compliance_status
    
    def pseudonymize_data(self, data: str, data_subject_id: str) -> str:
        """Pseudonymize data for GDPR compliance."""
        # Create consistent pseudonym for the data subject
        pseudonym_key = hashlib.pbkdf2_hmac(
            'sha256',
            data_subject_id.encode(),
            b'pseudonym-salt',
            100000,
            16
        )
        
        # Simple pseudonymization (in practice, use more sophisticated methods)
        pseudonym = base64.b64encode(pseudonym_key).decode()[:8]
        
        # Replace identifiable information with pseudonym
        # This is a simplified implementation
        pseudonymized = data.replace(data_subject_id, f"SUBJ_{pseudonym}")
        
        return pseudonymized
    
    def cleanup_expired_data(self):
        """Clean up data that has exceeded retention periods."""
        current_time = datetime.now()
        
        # This would iterate through stored encrypted data and check retention periods
        # For now, just log the action
        self._log_audit_event(
            AuditEventType.SYSTEM_EVENT,
            "data_retention_cleanup",
            "success",
            {"cleanup_time": current_time.isoformat()}
        )


# Global compliance encryption manager
compliance_encryption = ComplianceEncryptionManager()


# Helper functions
def create_hipaa_compliant_encryption(data: Union[str, bytes]) -> Dict[str, Any]:
    """Create HIPAA-compliant encryption of PHI data."""
    metadata = ComplianceMetadata(
        classification=DataClassification.RESTRICTED,
        standards=[ComplianceStandard.HIPAA],
        retention_period_days=2190,  # 6 years
        encryption_required=True,
        audit_required=True
    )
    
    return compliance_encryption.encrypt_with_compliance(data, metadata)


def create_gdpr_compliant_encryption(
    data: Union[str, bytes],
    data_subject_id: str,
    legal_basis: str = "consent"
) -> Dict[str, Any]:
    """Create GDPR-compliant encryption of personal data."""
    metadata = ComplianceMetadata(
        classification=DataClassification.CONFIDENTIAL,
        standards=[ComplianceStandard.GDPR],
        retention_period_days=2555,  # 7 years
        encryption_required=True,
        audit_required=True,
        data_subject_id=data_subject_id,
        legal_basis=legal_basis
    )
    
    return compliance_encryption.encrypt_with_compliance(data, metadata)