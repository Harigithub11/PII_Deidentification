"""
Key Rotation and Management System

Handles automatic key rotation, key versioning, and secure key lifecycle management.
"""

import os
import json
import secrets
import schedule
import time
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
import base64
import hashlib

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..config.settings import get_settings

settings = get_settings()


class KeyVersionInfo:
    """Information about a key version."""
    
    def __init__(
        self,
        version: int,
        key_id: str,
        created_at: datetime,
        expires_at: Optional[datetime] = None,
        status: str = "active",
        algorithm: str = "Fernet-AES256"
    ):
        self.version = version
        self.key_id = key_id
        self.created_at = created_at
        self.expires_at = expires_at
        self.status = status  # active, deprecated, revoked
        self.algorithm = algorithm
        self.usage_count = 0
        self.last_used = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "version": self.version,
            "key_id": self.key_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status,
            "algorithm": self.algorithm,
            "usage_count": self.usage_count,
            "last_used": self.last_used.isoformat() if self.last_used else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyVersionInfo':
        """Create from dictionary representation."""
        instance = cls(
            version=data["version"],
            key_id=data["key_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            status=data.get("status", "active"),
            algorithm=data.get("algorithm", "Fernet-AES256")
        )
        instance.usage_count = data.get("usage_count", 0)
        instance.last_used = datetime.fromisoformat(data["last_used"]) if data.get("last_used") else None
        return instance


class EncryptionKeyManager:
    """Manages encryption keys with rotation and versioning."""
    
    def __init__(self):
        self.keys_dir = Path("secrets/keys")
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        
        self.metadata_file = self.keys_dir / "key_metadata.json"
        self.current_version = 1
        self.key_versions: Dict[int, KeyVersionInfo] = {}
        self.encryption_keys: Dict[int, bytes] = {}
        
        # Load existing keys
        self._load_key_metadata()
        self._load_encryption_keys()
        
        # Ensure we have at least one key
        if not self.key_versions:
            self._generate_initial_key()
    
    def _generate_key_id(self) -> str:
        """Generate unique key identifier."""
        return f"key_{secrets.token_hex(8)}_{int(datetime.now().timestamp())}"
    
    def _derive_key_from_master(self, key_id: str, version: int) -> bytes:
        """Derive encryption key from master key and key ID."""
        master_key = settings.encryption_key.encode()
        salt = f"{key_id}_v{version}".encode()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        
        derived_key = base64.urlsafe_b64encode(kdf.derive(master_key))
        return derived_key
    
    def _save_key_metadata(self) -> None:
        """Save key metadata to file."""
        metadata = {
            "current_version": self.current_version,
            "key_versions": {
                str(version): info.to_dict() 
                for version, info in self.key_versions.items()
            },
            "last_rotation": datetime.now(timezone.utc).isoformat()
        }
        
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def _load_key_metadata(self) -> None:
        """Load key metadata from file."""
        if not self.metadata_file.exists():
            return
        
        try:
            with open(self.metadata_file, 'r') as f:
                metadata = json.load(f)
            
            self.current_version = metadata.get("current_version", 1)
            
            for version_str, info_dict in metadata.get("key_versions", {}).items():
                version = int(version_str)
                self.key_versions[version] = KeyVersionInfo.from_dict(info_dict)
                
        except Exception as e:
            print(f"Warning: Failed to load key metadata: {e}")
    
    def _save_encryption_key(self, version: int, key_data: bytes) -> None:
        """Save encryption key to secure file."""
        key_file = self.keys_dir / f"key_v{version}.key"
        
        # Encrypt key with system key for storage
        system_fernet = Fernet(base64.urlsafe_b64encode(
            settings.secret_key.encode().ljust(32)[:32]
        ))
        encrypted_key = system_fernet.encrypt(key_data)
        
        with open(key_file, 'wb') as f:
            f.write(encrypted_key)
        
        # Set restrictive permissions
        try:
            os.chmod(key_file, 0o600)
        except (OSError, AttributeError):
            pass
    
    def _load_encryption_keys(self) -> None:
        """Load all encryption keys from files."""
        for version_info in self.key_versions.values():
            key_file = self.keys_dir / f"key_v{version_info.version}.key"
            
            if key_file.exists():
                try:
                    # Decrypt key with system key
                    system_fernet = Fernet(base64.urlsafe_b64encode(
                        settings.secret_key.encode().ljust(32)[:32]
                    ))
                    
                    with open(key_file, 'rb') as f:
                        encrypted_key = f.read()
                    
                    key_data = system_fernet.decrypt(encrypted_key)
                    self.encryption_keys[version_info.version] = key_data
                    
                except Exception as e:
                    print(f"Warning: Failed to load key v{version_info.version}: {e}")
    
    def _generate_initial_key(self) -> None:
        """Generate the initial encryption key."""
        self.rotate_key("Initial key generation")
    
    def rotate_key(self, reason: str = "Scheduled rotation") -> Dict[str, Any]:
        """
        Rotate to a new encryption key.
        
        Args:
            reason: Reason for key rotation
            
        Returns:
            Information about the new key
        """
        try:
            # Create new key version
            new_version = self.current_version + 1
            new_key_id = self._generate_key_id()
            
            # Generate new encryption key
            new_key = self._derive_key_from_master(new_key_id, new_version)
            
            # Create key version info
            key_info = KeyVersionInfo(
                version=new_version,
                key_id=new_key_id,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(days=365),  # 1 year default
                status="active"
            )
            
            # Mark previous key as deprecated
            if self.current_version in self.key_versions:
                self.key_versions[self.current_version].status = "deprecated"
            
            # Store new key
            self.key_versions[new_version] = key_info
            self.encryption_keys[new_version] = new_key
            self.current_version = new_version
            
            # Save to files
            self._save_encryption_key(new_version, new_key)
            self._save_key_metadata()
            
            return {
                "success": True,
                "new_version": new_version,
                "key_id": new_key_id,
                "reason": reason,
                "rotated_at": key_info.created_at.isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_current_key(self) -> Optional[bytes]:
        """Get the current active encryption key."""
        return self.encryption_keys.get(self.current_version)
    
    def get_key_by_version(self, version: int) -> Optional[bytes]:
        """Get encryption key by version number."""
        return self.encryption_keys.get(version)
    
    def get_fernet_cipher(self, version: Optional[int] = None) -> Optional[Fernet]:
        """Get Fernet cipher for encryption/decryption."""
        version = version or self.current_version
        key = self.get_key_by_version(version)
        
        if key:
            # Update usage statistics
            if version in self.key_versions:
                self.key_versions[version].usage_count += 1
                self.key_versions[version].last_used = datetime.now(timezone.utc)
            
            return Fernet(key)
        
        return None
    
    def revoke_key(self, version: int, reason: str = "Security incident") -> Dict[str, Any]:
        """
        Revoke a specific key version.
        
        Args:
            version: Key version to revoke
            reason: Reason for revocation
            
        Returns:
            Revocation result
        """
        try:
            if version not in self.key_versions:
                return {"success": False, "error": "Key version not found"}
            
            if version == self.current_version:
                return {"success": False, "error": "Cannot revoke current active key"}
            
            # Mark key as revoked
            self.key_versions[version].status = "revoked"
            
            # Remove key from memory (but keep file for audit)
            if version in self.encryption_keys:
                del self.encryption_keys[version]
            
            self._save_key_metadata()
            
            return {
                "success": True,
                "revoked_version": version,
                "reason": reason,
                "revoked_at": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def cleanup_old_keys(self, keep_versions: int = 3) -> Dict[str, Any]:
        """
        Clean up old key versions (keep specified number of recent versions).
        
        Args:
            keep_versions: Number of recent versions to keep
            
        Returns:
            Cleanup result
        """
        try:
            # Sort versions by creation date (newest first)
            sorted_versions = sorted(
                self.key_versions.items(),
                key=lambda x: x[1].created_at,
                reverse=True
            )
            
            cleaned_count = 0
            
            # Keep current key plus specified number of recent versions
            versions_to_keep = [self.current_version]
            for version, info in sorted_versions[:keep_versions]:
                if version not in versions_to_keep:
                    versions_to_keep.append(version)
            
            # Remove old versions
            for version in list(self.key_versions.keys()):
                if version not in versions_to_keep:
                    key_info = self.key_versions[version]
                    
                    # Only clean up deprecated keys (not revoked for audit)
                    if key_info.status == "deprecated":
                        # Remove key file
                        key_file = self.keys_dir / f"key_v{version}.key"
                        if key_file.exists():
                            # Secure deletion
                            with open(key_file, 'r+b') as f:
                                f.write(os.urandom(f.seek(0, 2)))
                                f.flush()
                                os.fsync(f.fileno())
                            key_file.unlink()
                        
                        # Remove from memory
                        if version in self.encryption_keys:
                            del self.encryption_keys[version]
                        del self.key_versions[version]
                        
                        cleaned_count += 1
            
            self._save_key_metadata()
            
            return {
                "success": True,
                "cleaned_versions": cleaned_count,
                "kept_versions": len(versions_to_keep)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_key_status(self) -> Dict[str, Any]:
        """Get comprehensive key status information."""
        active_keys = sum(1 for info in self.key_versions.values() if info.status == "active")
        deprecated_keys = sum(1 for info in self.key_versions.values() if info.status == "deprecated")
        revoked_keys = sum(1 for info in self.key_versions.values() if info.status == "revoked")
        
        current_key_info = self.key_versions.get(self.current_version)
        
        return {
            "current_version": self.current_version,
            "total_versions": len(self.key_versions),
            "active_keys": active_keys,
            "deprecated_keys": deprecated_keys,
            "revoked_keys": revoked_keys,
            "current_key_age_days": (
                (datetime.now(timezone.utc) - current_key_info.created_at).days
                if current_key_info else None
            ),
            "current_key_expires": (
                current_key_info.expires_at.isoformat()
                if current_key_info and current_key_info.expires_at else None
            ),
            "versions": {
                version: info.to_dict()
                for version, info in self.key_versions.items()
            }
        }


class AutomaticKeyRotation:
    """Handles automatic key rotation scheduling."""
    
    def __init__(self, key_manager: EncryptionKeyManager):
        self.key_manager = key_manager
        self.rotation_thread = None
        self.running = False
        
        # Rotation policies
        self.rotation_interval_days = 90  # Rotate every 90 days
        self.usage_threshold = 1000000   # Rotate after 1M operations
        
        # Callbacks for rotation events
        self.rotation_callbacks: List[Callable[[Dict[str, Any]], None]] = []
    
    def add_rotation_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Add callback to be called when key rotation occurs."""
        self.rotation_callbacks.append(callback)
    
    def should_rotate_key(self) -> bool:
        """Check if key should be rotated based on policy."""
        current_key_info = self.key_manager.key_versions.get(self.key_manager.current_version)
        
        if not current_key_info:
            return True
        
        # Check age-based rotation
        age_days = (datetime.now(timezone.utc) - current_key_info.created_at).days
        if age_days >= self.rotation_interval_days:
            return True
        
        # Check usage-based rotation
        if current_key_info.usage_count >= self.usage_threshold:
            return True
        
        # Check if key is near expiration
        if current_key_info.expires_at:
            days_to_expiry = (current_key_info.expires_at - datetime.now(timezone.utc)).days
            if days_to_expiry <= 7:  # Rotate 7 days before expiry
                return True
        
        return False
    
    def perform_rotation_check(self) -> None:
        """Perform rotation check and rotate if needed."""
        try:
            if self.should_rotate_key():
                current_info = self.key_manager.key_versions.get(self.key_manager.current_version)
                age_days = (datetime.now(timezone.utc) - current_info.created_at).days if current_info else 0
                
                reason = f"Automatic rotation (age: {age_days} days, usage: {current_info.usage_count if current_info else 0})"
                result = self.key_manager.rotate_key(reason)
                
                if result["success"]:
                    print(f"Key rotated automatically: {result}")
                    
                    # Notify callbacks
                    for callback in self.rotation_callbacks:
                        try:
                            callback(result)
                        except Exception as e:
                            print(f"Rotation callback error: {e}")
                    
                    # Clean up old keys
                    cleanup_result = self.key_manager.cleanup_old_keys()
                    if cleanup_result["success"]:
                        print(f"Cleaned up {cleanup_result['cleaned_versions']} old key versions")
                
                else:
                    print(f"Key rotation failed: {result['error']}")
                    
        except Exception as e:
            print(f"Rotation check failed: {e}")
    
    def start_automatic_rotation(self) -> None:
        """Start automatic key rotation scheduler."""
        if self.running:
            return
        
        self.running = True
        
        # Schedule daily rotation checks
        schedule.every().day.at("02:00").do(self.perform_rotation_check)
        
        def rotation_worker():
            while self.running:
                schedule.run_pending()
                time.sleep(3600)  # Check every hour
        
        self.rotation_thread = threading.Thread(target=rotation_worker, daemon=True)
        self.rotation_thread.start()
        
        print("Automatic key rotation scheduler started")
    
    def stop_automatic_rotation(self) -> None:
        """Stop automatic key rotation scheduler."""
        self.running = False
        schedule.clear()
        
        if self.rotation_thread:
            self.rotation_thread.join(timeout=5)
        
        print("Automatic key rotation scheduler stopped")


# Global key manager and rotation instances
key_manager = EncryptionKeyManager()
auto_rotation = AutomaticKeyRotation(key_manager)


def get_current_encryption_key() -> Optional[bytes]:
    """Get current encryption key."""
    return key_manager.get_current_key()


def get_encryption_cipher(version: Optional[int] = None) -> Optional[Fernet]:
    """Get Fernet cipher for encryption/decryption."""
    return key_manager.get_fernet_cipher(version)


def rotate_encryption_key(reason: str = "Manual rotation") -> Dict[str, Any]:
    """Manually rotate encryption key."""
    return key_manager.rotate_key(reason)


def start_key_rotation_scheduler() -> None:
    """Start automatic key rotation."""
    auto_rotation.start_automatic_rotation()


def get_key_management_status() -> Dict[str, Any]:
    """Get key management status."""
    return key_manager.get_key_status()