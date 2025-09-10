#!/usr/bin/env python3
"""
Production server startup script for PII De-identification System

This script starts the FastAPI server with production-grade security configurations.
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Add src directory to Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

def setup_production_logging():
    """Setup structured logging for production."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/production.log'),
            logging.StreamHandler()
        ]
    )

def main():
    """Main function to start the production server."""
    parser = argparse.ArgumentParser(description="Start PII De-identification System in production mode")
    parser.add_argument("--port", type=int, default=443, help="Port to run the server on (default: 443 for HTTPS)")
    parser.add_argument("--workers", type=int, default=4, help="Number of worker processes")
    parser.add_argument("--cert-file", type=str, help="Path to SSL certificate file")
    parser.add_argument("--key-file", type=str, help="Path to SSL private key file")
    parser.add_argument("--generate-certs", action="store_true", help="Generate self-signed certificates")
    
    args = parser.parse_args()
    
    # Create logs directory
    os.makedirs("logs", exist_ok=True)
    setup_production_logging()
    
    logger = logging.getLogger(__name__)
    
    try:
        import uvicorn
        from src.main import app
        from src.core.security.ssl_config import ssl_config_manager
        from src.core.security.certificates import ssl_cert_manager
        
        logger.info("Starting PII De-identification System in production mode...")
        
        # Ensure SSL certificates are available
        ssl_config = None
        if args.cert_file and args.key_file:
            # Use provided certificates
            ssl_config = {
                "ssl_keyfile": args.key_file,
                "ssl_certfile": args.cert_file,
                "ssl_ca_certs": None,
                "ssl_ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS",
                "ssl_version": 3  # TLS 1.2+
            }
            logger.info(f"Using provided SSL certificates: {args.cert_file}")
        elif args.generate_certs:
            # Generate self-signed certificates
            logger.info("Generating self-signed SSL certificates...")
            result = ssl_cert_manager.create_self_signed_certificate()
            if result.get("success"):
                logger.info(f"✅ SSL certificates generated: {result['cert_file']}")
                ssl_config = ssl_config_manager.get_uvicorn_ssl_config()
            else:
                logger.error(f"❌ Failed to generate certificates: {result.get('error', 'Unknown error')}")
                sys.exit(1)
        else:
            # Try to use existing certificates
            ssl_config = ssl_config_manager.get_uvicorn_ssl_config()
            if not ssl_config:
                logger.warning("No SSL certificates found. Use --generate-certs or provide --cert-file and --key-file")
                logger.warning("Starting in HTTP mode (NOT RECOMMENDED FOR PRODUCTION)")
        
        # Configure server settings
        server_config = {
            "app": app,
            "host": "0.0.0.0",
            "port": args.port,
            "workers": args.workers,
            "log_level": "info",
            "access_log": True,
            "use_colors": False,  # Better for log files
            "server_header": False,  # Hide server version for security
            "date_header": True,
            "proxy_headers": True,  # For reverse proxy setups
            "forwarded_allow_ips": "*"  # Configure based on your proxy setup
        }
        
        # Add SSL configuration if available
        if ssl_config:
            server_config.update(ssl_config)
            logger.info(f"🔒 HTTPS server starting on port {args.port}")
            logger.info("🛡️  SSL/TLS encryption enabled for data in transit")
        else:
            logger.warning(f"⚠️  HTTP server starting on port {args.port} - NOT SECURE FOR PRODUCTION")
        
        logger.info(f"👥 Worker processes: {args.workers}")
        logger.info("📊 Production logging enabled")
        logger.info("="*60)
        
        # Start the production server
        uvicorn.run(**server_config)
        
    except ImportError as e:
        logger.error(f"Import error: {e}")
        logger.error("Make sure all dependencies are installed:")
        logger.error("   pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()