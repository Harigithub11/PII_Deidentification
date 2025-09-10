"""
Enhanced Encrypted Storage System

Provides comprehensive file and document encryption with versioning, integrity checks,
and secure storage management.
"""

import os
import hashlib
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, BinaryIO
import zipfile
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

from ..config.settings import get_settings
from .encryption import encryption_manager

settings = get_settings()


class SecureFileStorage:
    """Enhanced secure file storage with encryption and integrity verification."""
    
    def __init__(self, base_path: Optional[str] = None):
        self.base_path = Path(base_path or settings.output_dir)
        self.encrypted_dir = self.base_path / "encrypted"
        self.temp_dir = self.base_path / "temp_secure"
        self.metadata_dir = self.base_path / "metadata"
        
        # Create directories
        self.encrypted_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_file_key(self, file_id: str, user_salt: Optional[str] = None) -> bytes:
        """
        Generate unique encryption key for a specific file.
        
        Args:
            file_id: Unique file identifier
            user_salt: Optional user-specific salt
            
        Returns:
            Derived encryption key
        """
        # Combine master key with file-specific data
        master_key = settings.encryption_key.encode()
        salt_data = f"{file_id}:{user_salt or 'default'}".encode()
        
        # Use PBKDF2 to derive file-specific key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_data,
            iterations=100000
        )
        
        file_key = base64.urlsafe_b64encode(kdf.derive(master_key))
        return file_key
    
    def calculate_file_hash(self, file_path: Union[str, Path]) -> str:
        """Calculate SHA-256 hash of file for integrity verification."""
        hash_sha256 = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        
        return hash_sha256.hexdigest()
    
    def encrypt_file_with_metadata(
        self,
        source_file: Union[str, Path, BinaryIO],
        file_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Encrypt file with comprehensive metadata.
        
        Args:
            source_file: Source file path or file-like object
            file_id: Unique file identifier (generated if None)
            metadata: Additional metadata to store
            user_id: User ID for access control
            
        Returns:
            Dictionary with encryption results and metadata
        """
        try:
            # Generate file ID if not provided
            if file_id is None:
                file_id = str(uuid.uuid4())
            
            # Handle different input types
            if hasattr(source_file, 'read'):
                # File-like object
                file_data = source_file.read()
                original_filename = getattr(source_file, 'name', 'unknown')
                file_size = len(file_data)
                file_hash = hashlib.sha256(file_data).hexdigest()
            else:
                # File path
                source_path = Path(source_file)
                if not source_path.exists():
                    raise FileNotFoundError(f"Source file not found: {source_path}")
                
                with open(source_path, 'rb') as f:
                    file_data = f.read()
                
                original_filename = source_path.name
                file_size = len(file_data)
                file_hash = self.calculate_file_hash(source_path)
            
            # Generate file-specific encryption key
            file_key = self.generate_file_key(file_id, user_id)
            fernet = Fernet(file_key)
            
            # Encrypt file data
            encrypted_data = fernet.encrypt(file_data)
            
            # Create encrypted file path
            encrypted_filename = f"{file_id}.enc"
            encrypted_path = self.encrypted_dir / encrypted_filename
            
            # Write encrypted file
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Create comprehensive metadata
            file_metadata = {
                "file_id": file_id,
                "original_filename": original_filename,
                "file_size": file_size,
                "encrypted_size": len(encrypted_data),
                "file_hash": file_hash,
                "encryption_algorithm": "Fernet-AES256",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "user_id": user_id,
                "version": 1,
                "access_count": 0,
                "last_accessed": None,
                "encrypted_path": str(encrypted_path),
                "metadata": metadata or {}
            }
            
            # Save metadata
            metadata_path = self.metadata_dir / f"{file_id}.json"
            with open(metadata_path, 'w') as f:
                json.dump(file_metadata, f, indent=2)
            
            return {
                "success": True,
                "file_id": file_id,
                "encrypted_path": str(encrypted_path),
                "metadata_path": str(metadata_path),
                "file_metadata": file_metadata
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "file_id": file_id
            }
    
    def decrypt_file_with_verification(
        self,
        file_id: str,
        output_path: Optional[Union[str, Path]] = None,
        verify_integrity: bool = True,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Decrypt file with integrity verification.
        
        Args:
            file_id: File identifier
            output_path: Output file path (temp file if None)
            verify_integrity: Whether to verify file integrity
            user_id: User ID for access control
            
        Returns:
            Decryption results
        """
        try:
            # Load metadata
            metadata_path = self.metadata_dir / f"{file_id}.json"
            if not metadata_path.exists():
                return {"success": False, "error": "File metadata not found"}
            
            with open(metadata_path, 'r') as f:
                file_metadata = json.load(f)
            
            # Access control check
            if file_metadata.get("user_id") and user_id != file_metadata["user_id"]:
                return {"success": False, "error": "Access denied"}
            
            # Check encrypted file exists
            encrypted_path = Path(file_metadata["encrypted_path"])
            if not encrypted_path.exists():
                return {"success": False, "error": "Encrypted file not found"}
            
            # Generate file-specific decryption key
            file_key = self.generate_file_key(file_id, file_metadata.get("user_id"))
            fernet = Fernet(file_key)
            
            # Read and decrypt file
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Verify integrity if requested
            if verify_integrity:
                calculated_hash = hashlib.sha256(decrypted_data).hexdigest()
                if calculated_hash != file_metadata["file_hash"]:
                    return {"success": False, "error": "File integrity verification failed"}
            
            # Determine output path
            if output_path is None:
                # Create temporary file
                temp_fd, output_path = tempfile.mkstemp(
                    suffix=Path(file_metadata["original_filename"]).suffix,
                    dir=self.temp_dir
                )
                os.close(temp_fd)
            
            output_path = Path(output_path)
            
            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Update access metadata
            file_metadata["access_count"] += 1
            file_metadata["last_accessed"] = datetime.now(timezone.utc).isoformat()
            
            with open(metadata_path, 'w') as f:
                json.dump(file_metadata, f, indent=2)
            
            return {
                "success": True,
                "file_id": file_id,
                "decrypted_path": str(output_path),
                "original_filename": file_metadata["original_filename"],
                "file_size": file_metadata["file_size"],
                "integrity_verified": verify_integrity
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "file_id": file_id
            }
    
    def create_secure_archive(
        self,
        file_ids: List[str],
        archive_name: str,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create encrypted archive of multiple files.
        
        Args:
            file_ids: List of file IDs to include
            archive_name: Name for the archive
            user_id: User ID for access control
            
        Returns:
            Archive creation results
        """
        try:
            # Create temporary directory for archive creation
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                archive_temp_path = temp_path / f"{archive_name}.zip"
                
                # Create zip archive
                with zipfile.ZipFile(archive_temp_path, 'w', zipfile.ZIP_DEFLATED) as archive:
                    for file_id in file_ids:
                        # Decrypt file to temporary location
                        decrypt_result = self.decrypt_file_with_verification(
                            file_id, 
                            user_id=user_id
                        )
                        
                        if not decrypt_result["success"]:
                            return {
                                "success": False,
                                "error": f"Failed to decrypt file {file_id}: {decrypt_result['error']}"
                            }
                        
                        # Add to archive with original filename
                        archive.write(
                            decrypt_result["decrypted_path"],
                            decrypt_result["original_filename"]
                        )
                        
                        # Clean up temporary decrypted file
                        os.unlink(decrypt_result["decrypted_path"])
                
                # Encrypt the entire archive
                archive_id = str(uuid.uuid4())
                encrypt_result = self.encrypt_file_with_metadata(
                    archive_temp_path,
                    file_id=archive_id,
                    metadata={
                        "archive_type": "multi_file",
                        "contained_files": file_ids,
                        "archive_name": archive_name
                    },
                    user_id=user_id
                )
                
                return encrypt_result
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_file_info(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Get file information without decrypting."""
        try:
            metadata_path = self.metadata_dir / f"{file_id}.json"
            if not metadata_path.exists():
                return None
            
            with open(metadata_path, 'r') as f:
                return json.load(f)
                
        except Exception:
            return None
    
    def list_encrypted_files(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all encrypted files, optionally filtered by user."""
        files = []
        
        for metadata_file in self.metadata_dir.glob("*.json"):
            try:
                with open(metadata_file, 'r') as f:
                    file_info = json.load(f)
                
                # Filter by user if specified
                if user_id and file_info.get("user_id") != user_id:
                    continue
                
                # Remove sensitive information
                safe_info = {
                    "file_id": file_info["file_id"],
                    "original_filename": file_info["original_filename"],
                    "file_size": file_info["file_size"],
                    "created_at": file_info["created_at"],
                    "access_count": file_info["access_count"],
                    "last_accessed": file_info.get("last_accessed")
                }
                
                files.append(safe_info)
                
            except Exception:
                continue
        
        return sorted(files, key=lambda x: x["created_at"], reverse=True)
    
    def delete_encrypted_file(self, file_id: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Securely delete encrypted file and metadata."""
        try:
            # Load metadata for access control
            metadata_path = self.metadata_dir / f"{file_id}.json"
            if not metadata_path.exists():
                return {"success": False, "error": "File not found"}
            
            with open(metadata_path, 'r') as f:
                file_metadata = json.load(f)
            
            # Access control check
            if file_metadata.get("user_id") and user_id != file_metadata["user_id"]:
                return {"success": False, "error": "Access denied"}
            
            # Delete encrypted file
            encrypted_path = Path(file_metadata["encrypted_path"])
            if encrypted_path.exists():
                # Secure deletion (overwrite with random data)
                file_size = encrypted_path.stat().st_size
                with open(encrypted_path, 'r+b') as f:
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
                
                encrypted_path.unlink()
            
            # Delete metadata
            metadata_path.unlink()
            
            return {
                "success": True,
                "message": f"File {file_id} securely deleted"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def cleanup_temp_files(self, max_age_hours: int = 24) -> Dict[str, Any]:
        """Clean up temporary files older than specified age."""
        try:
            from datetime import timedelta
            
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            deleted_count = 0
            
            for temp_file in self.temp_dir.glob("*"):
                if temp_file.is_file():
                    file_time = datetime.fromtimestamp(temp_file.stat().st_mtime)
                    if file_time < cutoff_time:
                        temp_file.unlink()
                        deleted_count += 1
            
            return {
                "success": True,
                "deleted_files": deleted_count
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }


class DocumentEncryptionManager:
    """Specialized encryption for PII documents with compliance features."""
    
    def __init__(self):
        self.storage = SecureFileStorage()
        self.classification_levels = {
            "public": 1,
            "internal": 2,
            "confidential": 3,
            "restricted": 4,
            "top_secret": 5
        }
    
    def encrypt_pii_document(
        self,
        document_path: Union[str, Path],
        pii_data: Dict[str, Any],
        classification: str = "confidential",
        retention_days: Optional[int] = None,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Encrypt PII document with compliance metadata.
        
        Args:
            document_path: Path to document file
            pii_data: Detected PII information
            classification: Data classification level
            retention_days: Data retention period
            user_id: User ID for access control
            
        Returns:
            Encryption results with compliance metadata
        """
        # Create comprehensive metadata
        compliance_metadata = {
            "data_classification": classification,
            "classification_level": self.classification_levels.get(classification, 3),
            "pii_detected": pii_data,
            "retention_days": retention_days,
            "compliance_flags": {
                "hipaa_applicable": self._check_hipaa_applicable(pii_data),
                "gdpr_applicable": self._check_gdpr_applicable(pii_data),
                "pci_applicable": self._check_pci_applicable(pii_data)
            },
            "processing_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return self.storage.encrypt_file_with_metadata(
            document_path,
            metadata=compliance_metadata,
            user_id=user_id
        )
    
    def _check_hipaa_applicable(self, pii_data: Dict[str, Any]) -> bool:
        """Check if document contains HIPAA-regulated data."""
        hipaa_indicators = [
            "medical_record_number", "ssn", "date_of_birth", 
            "health_plan_number", "patient_id"
        ]
        return any(indicator in str(pii_data).lower() for indicator in hipaa_indicators)
    
    def _check_gdpr_applicable(self, pii_data: Dict[str, Any]) -> bool:
        """Check if document contains GDPR-regulated data."""
        gdpr_indicators = [
            "email", "phone", "address", "name", "identification_number"
        ]
        return any(indicator in str(pii_data).lower() for indicator in gdpr_indicators)
    
    def _check_pci_applicable(self, pii_data: Dict[str, Any]) -> bool:
        """Check if document contains PCI-regulated data."""
        pci_indicators = ["credit_card", "card_number", "cvv", "payment"]
        return any(indicator in str(pii_data).lower() for indicator in pci_indicators)
    
    def create_compliance_report(self, file_ids: List[str]) -> Dict[str, Any]:
        """Generate compliance report for encrypted documents."""
        report = {
            "total_documents": len(file_ids),
            "classification_summary": {},
            "compliance_summary": {
                "hipaa_documents": 0,
                "gdpr_documents": 0,
                "pci_documents": 0
            },
            "retention_analysis": {},
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
        
        for file_id in file_ids:
            file_info = self.storage.get_file_info(file_id)
            if not file_info:
                continue
            
            metadata = file_info.get("metadata", {})
            
            # Classification summary
            classification = metadata.get("data_classification", "unknown")
            report["classification_summary"][classification] = \
                report["classification_summary"].get(classification, 0) + 1
            
            # Compliance flags
            compliance_flags = metadata.get("compliance_flags", {})
            if compliance_flags.get("hipaa_applicable"):
                report["compliance_summary"]["hipaa_documents"] += 1
            if compliance_flags.get("gdpr_applicable"):
                report["compliance_summary"]["gdpr_documents"] += 1
            if compliance_flags.get("pci_applicable"):
                report["compliance_summary"]["pci_documents"] += 1
            
            # Retention analysis
            retention_days = metadata.get("retention_days")
            if retention_days:
                retention_key = f"{retention_days}_days"
                report["retention_analysis"][retention_key] = \
                    report["retention_analysis"].get(retention_key, 0) + 1
        
        return report


# Global instances
secure_file_storage = SecureFileStorage()
document_encryption_manager = DocumentEncryptionManager()


def encrypt_document_secure(
    file_path: Union[str, Path],
    metadata: Optional[Dict[str, Any]] = None,
    user_id: Optional[str] = None
) -> Dict[str, Any]:
    """Encrypt document with secure storage."""
    return secure_file_storage.encrypt_file_with_metadata(file_path, metadata=metadata, user_id=user_id)


def decrypt_document_secure(
    file_id: str,
    output_path: Optional[str] = None,
    user_id: Optional[str] = None
) -> Dict[str, Any]:
    """Decrypt document from secure storage."""
    return secure_file_storage.decrypt_file_with_verification(file_id, output_path, user_id=user_id)