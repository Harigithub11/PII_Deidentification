"""
SSL Certificate Management System

Handles SSL certificate generation, validation, and management for HTTPS encryption.
"""

import os
import socket
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from ..config.settings import get_settings

settings = get_settings()


class CertificateManager:
    """Manages SSL certificates for the de-identification system."""
    
    def __init__(self):
        self.cert_dir = Path("secrets/certificates")
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_private_key(self, key_size: int = 2048) -> rsa.RSAPrivateKey:
        """Generate RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
    
    def create_self_signed_certificate(
        self,
        hostname: str = "localhost",
        validity_days: int = 365,
        key_size: int = 2048
    ) -> Tuple[bytes, bytes]:
        """
        Create a self-signed SSL certificate for development/testing.
        
        Returns:
            Tuple of (certificate_pem, private_key_pem)
        """
        # Generate private key
        private_key = self.generate_private_key(key_size)
        
        # Create certificate subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PII De-identification System"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        
        # Define certificate validity period
        now = datetime.utcnow()
        valid_from = now
        valid_to = now + timedelta(days=validity_days)
        
        # Create certificate
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            valid_from
        ).not_valid_after(
            valid_to
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
                x509.DNSName("localhost"),
                x509.IPAddress("127.0.0.1"),
                x509.IPAddress("::1"),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        ).sign(private_key, hashes.SHA256())
        
        # Serialize certificate and private key
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return cert_pem, key_pem
    
    def save_certificate_files(
        self,
        cert_pem: bytes,
        key_pem: bytes,
        cert_name: str = "server"
    ) -> Dict[str, str]:
        """
        Save certificate and private key to files.
        
        Returns:
            Dictionary with cert_file and key_file paths
        """
        cert_file = self.cert_dir / f"{cert_name}.crt"
        key_file = self.cert_dir / f"{cert_name}.key"
        
        # Save certificate
        with open(cert_file, "wb") as f:
            f.write(cert_pem)
        
        # Save private key with restricted permissions
        with open(key_file, "wb") as f:
            f.write(key_pem)
        
        # Set secure file permissions (Unix systems)
        try:
            os.chmod(cert_file, 0o644)  # Read-write for owner, read for others
            os.chmod(key_file, 0o600)   # Read-write for owner only
        except (OSError, AttributeError):
            # Windows doesn't support chmod the same way
            pass
        
        return {
            "cert_file": str(cert_file),
            "key_file": str(key_file)
        }
    
    def generate_development_certificates(self) -> Dict[str, str]:
        """Generate self-signed certificates for development."""
        hostname = socket.gethostname()
        
        print(f"Generating self-signed SSL certificate for {hostname}...")
        cert_pem, key_pem = self.create_self_signed_certificate(hostname)
        
        files = self.save_certificate_files(cert_pem, key_pem, "dev")
        
        print(f"Certificate saved to: {files['cert_file']}")
        print(f"Private key saved to: {files['key_file']}")
        
        return files
    
    def validate_certificate(self, cert_file: str) -> Dict[str, any]:
        """
        Validate an existing SSL certificate.
        
        Returns:
            Dictionary with certificate information and validity status
        """
        try:
            with open(cert_file, "rb") as f:
                cert_data = f.read()
            
            certificate = x509.load_pem_x509_certificate(cert_data)
            
            now = datetime.utcnow()
            is_valid = now >= certificate.not_valid_before and now <= certificate.not_valid_after
            days_until_expiry = (certificate.not_valid_after - now).days
            
            # Extract subject information
            subject_info = {}
            for attribute in certificate.subject:
                subject_info[attribute.oid._name] = attribute.value
            
            # Extract SAN (Subject Alternative Names)
            san_list = []
            try:
                san_ext = certificate.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_list = [name.value for name in san_ext.value]
            except x509.ExtensionNotFound:
                pass
            
            return {
                "valid": is_valid,
                "not_valid_before": certificate.not_valid_before,
                "not_valid_after": certificate.not_valid_after,
                "days_until_expiry": days_until_expiry,
                "subject": subject_info,
                "san": san_list,
                "serial_number": str(certificate.serial_number),
                "signature_algorithm": certificate.signature_algorithm_oid._name
            }
            
        except Exception as e:
            return {
                "valid": False,
                "error": str(e)
            }
    
    def create_certificate_signing_request(
        self,
        hostname: str,
        private_key: Optional[rsa.RSAPrivateKey] = None
    ) -> Tuple[bytes, rsa.RSAPrivateKey]:
        """
        Create a Certificate Signing Request (CSR) for production certificates.
        
        Returns:
            Tuple of (csr_pem, private_key)
        """
        if private_key is None:
            private_key = self.generate_private_key()
        
        # Create CSR subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PII De-identification System"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        
        # Create CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        
        return csr_pem, private_key
    
    def setup_lets_encrypt_certificate(self, domain: str, email: str) -> Dict[str, str]:
        """
        Setup Let's Encrypt certificate using certbot (requires certbot installation).
        
        Note: This is a placeholder implementation. In production, you would:
        1. Install certbot
        2. Configure web server
        3. Run certbot commands
        """
        cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
        
        # Check if certbot is available
        try:
            result = subprocess.run(["certbot", "--version"], capture_output=True, text=True)
            if result.returncode != 0:
                raise FileNotFoundError("certbot not found")
        except FileNotFoundError:
            return {
                "error": "certbot not installed",
                "message": "Please install certbot for Let's Encrypt certificates",
                "install_command": "pip install certbot certbot-nginx"
            }
        
        # For production, implement actual certbot integration
        return {
            "status": "not_implemented",
            "message": "Let's Encrypt integration requires production setup",
            "cert_path": cert_path,
            "key_path": key_path,
            "command": f"certbot certonly --standalone -d {domain} --email {email} --agree-tos"
        }
    
    def get_certificate_info(self, cert_name: str = "dev") -> Optional[Dict]:
        """Get information about an existing certificate."""
        cert_file = self.cert_dir / f"{cert_name}.crt"
        
        if not cert_file.exists():
            return None
        
        return self.validate_certificate(str(cert_file))
    
    def list_certificates(self) -> List[Dict[str, str]]:
        """List all available certificates."""
        certificates = []
        
        for cert_file in self.cert_dir.glob("*.crt"):
            cert_name = cert_file.stem
            key_file = self.cert_dir / f"{cert_name}.key"
            
            cert_info = self.validate_certificate(str(cert_file))
            
            certificates.append({
                "name": cert_name,
                "cert_file": str(cert_file),
                "key_file": str(key_file) if key_file.exists() else None,
                "valid": cert_info.get("valid", False),
                "expires": cert_info.get("not_valid_after"),
                "days_until_expiry": cert_info.get("days_until_expiry", 0)
            })
        
        return certificates
    
    def ensure_development_certificate(self) -> Dict[str, str]:
        """Ensure development certificate exists, create if missing."""
        cert_info = self.get_certificate_info("dev")
        
        if cert_info is None or not cert_info.get("valid", False):
            print("Development certificate not found or invalid, generating new one...")
            return self.generate_development_certificates()
        
        if cert_info.get("days_until_expiry", 0) < 30:
            print("Development certificate expires soon, generating new one...")
            return self.generate_development_certificates()
        
        cert_file = self.cert_dir / "dev.crt"
        key_file = self.cert_dir / "dev.key"
        
        return {
            "cert_file": str(cert_file),
            "key_file": str(key_file)
        }


class TLSConfig:
    """TLS configuration management."""
    
    def __init__(self):
        self.certificate_manager = CertificateManager()
    
    def get_uvicorn_ssl_config(self, cert_name: str = "dev") -> Dict[str, str]:
        """Get SSL configuration for uvicorn server."""
        cert_info = self.certificate_manager.get_certificate_info(cert_name)
        
        if cert_info is None or not cert_info.get("valid", False):
            # Generate development certificate
            files = self.certificate_manager.ensure_development_certificate()
            cert_name = "dev"
        
        cert_file = self.certificate_manager.cert_dir / f"{cert_name}.crt"
        key_file = self.certificate_manager.cert_dir / f"{cert_name}.key"
        
        return {
            "ssl_keyfile": str(key_file),
            "ssl_certfile": str(cert_file),
            "ssl_version": "TLSv1_2",
            "ssl_cert_reqs": "none"
        }
    
    def validate_tls_config(self) -> Dict[str, any]:
        """Validate current TLS configuration."""
        certificates = self.certificate_manager.list_certificates()
        
        valid_certs = [cert for cert in certificates if cert["valid"]]
        expiring_certs = [cert for cert in certificates if cert.get("days_until_expiry", 0) < 30]
        
        return {
            "total_certificates": len(certificates),
            "valid_certificates": len(valid_certs),
            "expiring_certificates": len(expiring_certs),
            "certificates": certificates,
            "tls_ready": len(valid_certs) > 0
        }


# Global instances
certificate_manager = CertificateManager()
tls_config = TLSConfig()


def setup_ssl_certificates() -> Dict[str, str]:
    """Setup SSL certificates for the application."""
    return certificate_manager.ensure_development_certificate()


def get_ssl_config() -> Dict[str, str]:
    """Get SSL configuration for server startup."""
    return tls_config.get_uvicorn_ssl_config()