#!/usr/bin/env python3
"""
Startup script for PII De-identification System

This script starts the FastAPI server with proper configuration.
"""

import sys
import os
import argparse
from pathlib import Path

# Add src directory to Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

def main():
    """Main function to start the server."""
    parser = argparse.ArgumentParser(description="Start PII De-identification System")
    parser.add_argument("--https", action="store_true", help="Enable HTTPS with SSL certificates")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server on")
    parser.add_argument("--generate-certs", action="store_true", help="Generate self-signed certificates before starting")
    
    args = parser.parse_args()
    
    try:
        from src.main import start_server
        
        print("Starting PII De-identification System...")
        
        if args.generate_certs:
            print("Generating SSL certificates...")
            from src.core.security.certificates import ssl_cert_manager
            result = ssl_cert_manager.create_self_signed_certificate()
            if result.get("success"):
                print(f"✅ SSL certificates generated: {result['cert_file']}")
            else:
                print(f"❌ Failed to generate certificates: {result.get('error', 'Unknown error')}")
                if not args.https:
                    print("Continuing with HTTP...")
                else:
                    print("Cannot start HTTPS server without certificates.")
                    sys.exit(1)
        
        protocol = "https" if args.https else "http"
        print(f"Server will be available at: {protocol}://localhost:{args.port}")
        print(f"API Documentation: {protocol}://localhost:{args.port}/docs")
        
        if args.https:
            print("🔒 HTTPS encryption enabled for data in transit")
        else:
            print("⚠️  HTTP mode - consider using --https for production")
        
        print("Auto-reload enabled for development")
        print("\n" + "="*50)
        
        # Start the server with HTTPS support
        start_server(enable_https=args.https, port=args.port)
        
    except ImportError as e:
        print(f"Import error: {e}")
        print("Make sure all dependencies are installed:")
        print("   pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()