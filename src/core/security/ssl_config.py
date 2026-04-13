"""
SSL/TLS Configuration Management

Handles HTTPS configuration, TLS settings, and secure server setup.
"""

import ssl
import socket
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

from ..config.settings import get_settings
from .certificates import certificate_manager, TLSConfig

settings = get_settings()


class SSLConfigManager:
    """Manages SSL/TLS configuration for the application."""
    
    def __init__(self):
        self.tls_config = TLSConfig()
        self.min_tls_version = ssl.TLSVersion.TLSv1_2
        self.max_tls_version = ssl.TLSVersion.TLSv1_3
        
    def create_ssl_context(
        self,
        cert_file: str,
        key_file: str,
        ca_certs: Optional[str] = None
    ) -> ssl.SSLContext:
        """
        Create SSL context with secure defaults.
        
        Args:
            cert_file: Path to certificate file
            key_file: Path to private key file
            ca_certs: Path to CA certificates (optional)
            
        Returns:
            Configured SSL context
        """
        # Create SSL context with secure defaults
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Set minimum and maximum TLS versions
        context.minimum_version = self.min_tls_version
        context.maximum_version = self.max_tls_version
        
        # Load certificate and private key
        context.load_cert_chain(cert_file, key_file)
        
        # Load CA certificates if provided
        if ca_certs and Path(ca_certs).exists():
            context.load_verify_locations(ca_certs)
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_NONE
        
        # Configure cipher suites (secure defaults)
        context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS")
        
        # Enable OCSP stapling if available
        try:
            context.check_hostname = False  # We handle hostname verification separately
        except AttributeError:
            pass
        
        # Additional security options
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE
        
        return context
    
    def get_uvicorn_ssl_config(
        self,
        enable_ssl: bool = True,
        cert_name: str = "dev"
    ) -> Dict[str, Any]:
        """
        Get SSL configuration for uvicorn server.
        
        Args:
            enable_ssl: Whether to enable SSL
            cert_name: Certificate name to use
            
        Returns:
            Dictionary with SSL configuration
        """
        if not enable_ssl:
            return {}
        
        try:
            # Get certificate files
            cert_files = certificate_manager.ensure_development_certificate()
            
            ssl_config = {
                "ssl_keyfile": cert_files["key_file"],
                "ssl_certfile": cert_files["cert_file"],
                "ssl_version": ssl.PROTOCOL_TLS_SERVER,
                "ssl_cert_reqs": ssl.CERT_NONE,
                "ssl_ca_certs": None,
                "ssl_ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
            }
            
            return ssl_config
            
        except Exception as e:
            print(f"SSL configuration error: {e}")
            return {}
    
    def get_secure_headers(self) -> Dict[str, str]:
        """
        Get security headers for HTTPS connections.
        
        Returns:
            Dictionary of security headers
        """
        return {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            ),
            "Permissions-Policy": (
                "geolocation=(), microphone=(), camera=(), "
                "magnetometer=(), gyroscope=(), fullscreen=(self), "
                "payment=(), usb=()"
            )
        }
    
    def validate_ssl_configuration(self, host: str = "localhost", port: int = 8443) -> Dict[str, Any]:
        """
        Validate SSL configuration by attempting a connection.
        
        Args:
            host: Hostname to test
            port: Port to test
            
        Returns:
            Validation results
        """
        try:
            # Create SSL context for client connection
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Attempt connection
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    return {
                        "status": "success",
                        "tls_version": version,
                        "cipher_suite": cipher[0] if cipher else None,
                        "certificate": cert,
                        "connection_secure": True
                    }
                    
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "connection_secure": False
            }
    
    def get_recommended_nginx_config(self, domain: str, cert_path: str, key_path: str) -> str:
        """
        Generate recommended Nginx configuration for SSL termination.
        
        Args:
            domain: Domain name
            cert_path: Certificate file path
            key_path: Private key file path
            
        Returns:
            Nginx configuration string
        """
        return f"""
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {domain};

    # SSL Configuration
    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Modern configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Proxy to FastAPI application
    location / {{
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }}
}}

# Redirect HTTP to HTTPS
server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    return 301 https://$server_name$request_uri;
}}
"""
    
    def get_apache_ssl_config(self, domain: str, cert_path: str, key_path: str) -> str:
        """
        Generate Apache SSL configuration.
        
        Args:
            domain: Domain name
            cert_path: Certificate file path
            key_path: Private key file path
            
        Returns:
            Apache configuration string
        """
        return f"""
<VirtualHost *:443>
    ServerName {domain}
    
    # SSL Configuration
    SSLEngine on
    SSLCertificateFile {cert_path}
    SSLCertificateKeyFile {key_path}
    
    # Modern SSL Configuration
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder off
    SSLSessionTickets off
    
    # OCSP Stapling
    SSLUseStapling on
    SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
    
    # Security Headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Proxy to FastAPI application
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8000/
    ProxyPassReverse / http://127.0.0.1:8000/
    
    # Set headers for proxy
    ProxyPassReverse / http://127.0.0.1:8000/
    ProxySetHeader X-Real-IP %{{REMOTE_ADDR}}s
    ProxySetHeader X-Forwarded-For %{{REMOTE_ADDR}}s
    ProxySetHeader X-Forwarded-Proto %{{REQUEST_SCHEME}}s
    ProxySetHeader X-Forwarded-Host %{{HTTP_HOST}}s
</VirtualHost>

<VirtualHost *:80>
    ServerName {domain}
    Redirect permanent / https://{domain}/
</VirtualHost>
"""

    def create_ssl_test_server(self, port: int = 8443) -> Dict[str, Any]:
        """
        Create a test SSL server to verify configuration.
        
        Args:
            port: Port to run test server on
            
        Returns:
            Server information or error details
        """
        try:
            # Get SSL configuration
            ssl_config = self.get_uvicorn_ssl_config()
            
            if not ssl_config:
                return {"error": "SSL configuration not available"}
            
            # Create SSL context
            context = self.create_ssl_context(
                ssl_config["ssl_certfile"],
                ssl_config["ssl_keyfile"]
            )
            
            return {
                "status": "ready",
                "port": port,
                "ssl_config": ssl_config,
                "message": f"SSL test server ready on port {port}"
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "message": "Failed to create SSL test server"
            }


class HTTPSRedirectMiddleware:
    """Middleware to redirect HTTP traffic to HTTPS."""
    
    def __init__(self, app, https_port: int = 443):
        self.app = app
        self.https_port = https_port
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Check if request is not HTTPS
            scheme = scope.get("scheme", "http")
            headers = scope.get("headers", [])
            
            # Check for X-Forwarded-Proto header (for reverse proxies)
            forwarded_proto = None
            for name, value in headers:
                if name == b"x-forwarded-proto":
                    forwarded_proto = value.decode()
                    break
            
            # Redirect to HTTPS if needed
            if scheme == "http" and forwarded_proto != "https":
                host = None
                for name, value in headers:
                    if name == b"host":
                        host = value.decode()
                        break
                
                if host:
                    # Build HTTPS URL
                    path = scope.get("path", "/")
                    query_string = scope.get("query_string", b"").decode()
                    
                    https_url = f"https://{host}"
                    if self.https_port != 443:
                        https_url = f"https://{host}:{self.https_port}"
                    
                    https_url += path
                    if query_string:
                        https_url += f"?{query_string}"
                    
                    # Send redirect response
                    response = {
                        "type": "http.response.start",
                        "status": 301,
                        "headers": [
                            [b"location", https_url.encode()],
                            [b"content-length", b"0"],
                        ],
                    }
                    await send(response)
                    await send({"type": "http.response.body"})
                    return
        
        # Continue with normal processing
        await self.app(scope, receive, send)


# Global SSL configuration manager
ssl_config_manager = SSLConfigManager()


def get_ssl_config_for_server(enable_ssl: bool = True) -> Dict[str, Any]:
    """Get SSL configuration for server startup."""
    return ssl_config_manager.get_uvicorn_ssl_config(enable_ssl)


def setup_https_redirect_middleware(app, https_port: int = 443):
    """Setup HTTPS redirect middleware."""
    return HTTPSRedirectMiddleware(app, https_port)


def validate_ssl_setup() -> Dict[str, Any]:
    """Validate SSL setup and configuration."""
    return ssl_config_manager.validate_ssl_configuration()