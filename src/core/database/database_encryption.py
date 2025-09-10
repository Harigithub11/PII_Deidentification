"""
Database Encryption Manager

Handles database-level encryption, connection security, and encrypted backups.
"""

import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool

from ..config.settings import get_settings
from ..security.encryption import encryption_manager

settings = get_settings()


class DatabaseEncryptionManager:
    """Manages database encryption and secure connections."""
    
    def __init__(self):
        self.backup_dir = Path("data/backups/encrypted")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def create_encrypted_database_url(self, base_url: str, ssl_mode: str = "require") -> str:
        """
        Create encrypted database connection URL with SSL.
        
        Args:
            base_url: Base database URL
            ssl_mode: SSL mode for PostgreSQL connections
            
        Returns:
            Enhanced database URL with encryption settings
        """
        parsed = urlparse(base_url)
        
        if parsed.scheme.startswith('postgresql'):
            # PostgreSQL with SSL
            if '?' in base_url:
                return f"{base_url}&sslmode={ssl_mode}&sslcert=client-cert.pem&sslkey=client-key.pem&sslrootcert=ca-cert.pem"
            else:
                return f"{base_url}?sslmode={ssl_mode}&sslcert=client-cert.pem&sslkey=client-key.pem&sslrootcert=ca-cert.pem"
        
        elif parsed.scheme.startswith('mysql'):
            # MySQL with SSL
            if '?' in base_url:
                return f"{base_url}&ssl_disabled=false&ssl_verify_cert=true&ssl_verify_identity=true"
            else:
                return f"{base_url}?ssl_disabled=false&ssl_verify_cert=true&ssl_verify_identity=true"
        
        # SQLite - add encryption parameters if using SQLCipher
        elif parsed.scheme.startswith('sqlite'):
            # For SQLCipher support (would need pysqlcipher3)
            return base_url  # Standard SQLite doesn't support encryption
        
        return base_url
    
    def create_secure_engine(
        self,
        database_url: str,
        enable_ssl: bool = True,
        pool_pre_ping: bool = True,
        **kwargs
    ) -> Engine:
        """
        Create SQLAlchemy engine with security enhancements.
        
        Args:
            database_url: Database connection URL
            enable_ssl: Enable SSL connections
            pool_pre_ping: Enable connection health checks
            **kwargs: Additional engine parameters
            
        Returns:
            Configured SQLAlchemy engine
        """
        if enable_ssl and not database_url.startswith('sqlite'):
            database_url = self.create_encrypted_database_url(database_url)
        
        # Default secure engine parameters
        engine_params = {
            'pool_pre_ping': pool_pre_ping,
            'pool_recycle': 3600,  # Recycle connections every hour
            'echo': settings.database_echo,
            'future': True,  # Use SQLAlchemy 2.0 style
            **kwargs
        }
        
        # SQLite-specific parameters
        if database_url.startswith('sqlite'):
            engine_params.update({
                'poolclass': StaticPool,
                'connect_args': {
                    'check_same_thread': False,
                    'timeout': 30
                }
            })
        
        return create_engine(database_url, **engine_params)
    
    def encrypt_database_backup(self, backup_file: str) -> Dict[str, Any]:
        """
        Encrypt a database backup file.
        
        Args:
            backup_file: Path to backup file
            
        Returns:
            Result dictionary with encryption status
        """
        try:
            backup_path = Path(backup_file)
            if not backup_path.exists():
                return {"success": False, "error": "Backup file not found"}
            
            # Read backup file
            with open(backup_path, 'rb') as f:
                backup_data = f.read()
            
            # Encrypt backup data
            encrypted_data = encryption_manager._fernet.encrypt(backup_data)
            
            # Save encrypted backup
            encrypted_path = self.backup_dir / f"{backup_path.stem}_encrypted{backup_path.suffix}.enc"
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Create metadata file
            metadata = {
                "original_file": str(backup_path),
                "encrypted_file": str(encrypted_path),
                "encryption_time": datetime.now().isoformat(),
                "original_size": len(backup_data),
                "encrypted_size": len(encrypted_data)
            }
            
            metadata_path = encrypted_path.with_suffix('.json')
            with open(metadata_path, 'w') as f:
                import json
                json.dump(metadata, f, indent=2)
            
            return {
                "success": True,
                "encrypted_file": str(encrypted_path),
                "metadata_file": str(metadata_path),
                "original_size": len(backup_data),
                "encrypted_size": len(encrypted_data)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def decrypt_database_backup(self, encrypted_file: str, output_file: str) -> Dict[str, Any]:
        """
        Decrypt a database backup file.
        
        Args:
            encrypted_file: Path to encrypted backup
            output_file: Path for decrypted output
            
        Returns:
            Result dictionary with decryption status
        """
        try:
            encrypted_path = Path(encrypted_file)
            if not encrypted_path.exists():
                return {"success": False, "error": "Encrypted backup file not found"}
            
            # Read encrypted backup
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt backup data
            backup_data = encryption_manager._fernet.decrypt(encrypted_data)
            
            # Save decrypted backup
            output_path = Path(output_file)
            with open(output_path, 'wb') as f:
                f.write(backup_data)
            
            return {
                "success": True,
                "decrypted_file": str(output_path),
                "size": len(backup_data)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def create_encrypted_sqlite_backup(self, db_path: str) -> Dict[str, Any]:
        """
        Create encrypted backup of SQLite database.
        
        Args:
            db_path: Path to SQLite database
            
        Returns:
            Backup creation result
        """
        try:
            db_file = Path(db_path)
            if not db_file.exists():
                return {"success": False, "error": "Database file not found"}
            
            # Create backup filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{db_file.stem}_backup_{timestamp}.db"
            backup_path = self.backup_dir / backup_name
            
            # Copy database file
            import shutil
            shutil.copy2(db_file, backup_path)
            
            # Encrypt the backup
            encryption_result = self.encrypt_database_backup(str(backup_path))
            
            # Remove unencrypted backup
            if encryption_result.get("success") and backup_path.exists():
                backup_path.unlink()
            
            return encryption_result
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def create_postgresql_encrypted_backup(
        self,
        connection_params: Dict[str, str],
        backup_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create encrypted backup of PostgreSQL database.
        
        Args:
            connection_params: Database connection parameters
            backup_name: Optional backup name
            
        Returns:
            Backup creation result
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = backup_name or f"postgres_backup_{timestamp}.sql"
            backup_path = self.backup_dir / backup_name
            
            # Build pg_dump command
            cmd = [
                'pg_dump',
                '--host', connection_params.get('host', 'localhost'),
                '--port', str(connection_params.get('port', 5432)),
                '--username', connection_params.get('username', 'postgres'),
                '--dbname', connection_params.get('database'),
                '--file', str(backup_path),
                '--verbose',
                '--clean',
                '--no-owner',
                '--no-privileges'
            ]
            
            # Set password via environment variable
            env = os.environ.copy()
            if 'password' in connection_params:
                env['PGPASSWORD'] = connection_params['password']
            
            # Execute pg_dump
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"pg_dump failed: {result.stderr}"
                }
            
            # Encrypt the backup
            encryption_result = self.encrypt_database_backup(str(backup_path))
            
            # Remove unencrypted backup
            if encryption_result.get("success") and backup_path.exists():
                backup_path.unlink()
            
            return encryption_result
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def setup_database_encryption_at_rest(self, engine: Engine) -> Dict[str, Any]:
        """
        Setup database encryption at rest (database-specific).
        
        Args:
            engine: SQLAlchemy engine
            
        Returns:
            Setup result
        """
        try:
            db_url = str(engine.url)
            
            if 'postgresql' in db_url:
                # PostgreSQL: Enable pgcrypto extension
                with engine.connect() as conn:
                    conn.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto;"))
                    conn.commit()
                
                return {
                    "success": True,
                    "message": "PostgreSQL pgcrypto extension enabled",
                    "features": ["pgp_encrypt", "pgp_decrypt", "crypt", "gen_salt"]
                }
                
            elif 'mysql' in db_url:
                # MySQL: Check AES encryption functions
                with engine.connect() as conn:
                    result = conn.execute(text("SELECT AES_ENCRYPT('test', 'key') IS NOT NULL as supported;"))
                    supported = result.scalar()
                
                return {
                    "success": True,
                    "message": "MySQL AES encryption functions available",
                    "supported": bool(supported)
                }
                
            elif 'sqlite' in db_url:
                # SQLite: Limited encryption support
                return {
                    "success": True,
                    "message": "SQLite using application-level encryption",
                    "note": "Consider SQLCipher for database-level encryption"
                }
            
            return {
                "success": False,
                "message": "Database type not supported for encryption at rest"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def validate_database_security(self, engine: Engine) -> Dict[str, Any]:
        """
        Validate database security configuration.
        
        Args:
            engine: SQLAlchemy engine to validate
            
        Returns:
            Validation results
        """
        results = {
            "connection_secure": False,
            "encryption_available": False,
            "ssl_enabled": False,
            "recommendations": []
        }
        
        try:
            db_url = str(engine.url)
            
            # Check SSL configuration
            if 'sslmode' in db_url or 'ssl' in db_url:
                results["ssl_enabled"] = True
                results["connection_secure"] = True
            
            # Test connection
            with engine.connect() as conn:
                # Check database version and security features
                if 'postgresql' in db_url:
                    # Check PostgreSQL version and SSL
                    version_result = conn.execute(text("SELECT version();"))
                    version = version_result.scalar()
                    
                    ssl_result = conn.execute(text("SHOW ssl;"))
                    ssl_status = ssl_result.scalar()
                    
                    results["database_version"] = version
                    results["ssl_database_setting"] = ssl_status
                    
                    # Check pgcrypto
                    try:
                        conn.execute(text("SELECT pgp_encrypt('test', 'key');"))
                        results["encryption_available"] = True
                    except:
                        results["recommendations"].append("Install pgcrypto extension for encryption functions")
                
                elif 'mysql' in db_url:
                    # Check MySQL SSL variables
                    ssl_result = conn.execute(text("SHOW STATUS LIKE 'Ssl%';"))
                    ssl_vars = {row[0]: row[1] for row in ssl_result}
                    results["ssl_status"] = ssl_vars
                    
                    if ssl_vars.get('Ssl_cipher'):
                        results["connection_secure"] = True
                    
                elif 'sqlite' in db_url:
                    # SQLite security is primarily application-level
                    results["encryption_available"] = True  # Via our encrypted fields
                    results["recommendations"].append("Consider SQLCipher for database file encryption")
            
            # General recommendations
            if not results["ssl_enabled"]:
                results["recommendations"].append("Enable SSL/TLS for database connections")
            
            if not results["encryption_available"]:
                results["recommendations"].append("Enable database encryption extensions")
            
            results["overall_security"] = (
                results["connection_secure"] and 
                results["encryption_available"]
            )
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def list_encrypted_backups(self) -> List[Dict[str, Any]]:
        """List all encrypted database backups."""
        backups = []
        
        for backup_file in self.backup_dir.glob("*.enc"):
            metadata_file = backup_file.with_suffix('.json')
            
            backup_info = {
                "encrypted_file": str(backup_file),
                "size": backup_file.stat().st_size,
                "created": datetime.fromtimestamp(backup_file.stat().st_ctime).isoformat()
            }
            
            # Load metadata if available
            if metadata_file.exists():
                try:
                    import json
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                    backup_info.update(metadata)
                except Exception:
                    pass
            
            backups.append(backup_info)
        
        return sorted(backups, key=lambda x: x["created"], reverse=True)


# Global database encryption manager
db_encryption_manager = DatabaseEncryptionManager()


def create_secure_database_engine(database_url: str, **kwargs) -> Engine:
    """Create secure database engine with encryption support."""
    return db_encryption_manager.create_secure_engine(database_url, **kwargs)


def backup_database_encrypted(db_path_or_params: str) -> Dict[str, Any]:
    """Create encrypted database backup."""
    if isinstance(db_path_or_params, str) and db_path_or_params.endswith('.db'):
        return db_encryption_manager.create_encrypted_sqlite_backup(db_path_or_params)
    else:
        return db_encryption_manager.create_postgresql_encrypted_backup(db_path_or_params)