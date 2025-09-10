# -*- coding: utf-8 -*-
"""
Unicode-safe startup wrapper for Windows environments.

This script sets up proper UTF-8 encoding for console output to prevent
unicode errors when running on Windows systems with cp1252 encoding.
"""

import os
import sys
import locale

def setup_unicode_environment():
    """Configure environment for proper unicode handling."""
    
    # Set environment variables for UTF-8 support
    os.environ['PYTHONUTF8'] = '1'
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    
    # For Windows systems, try to set console encoding
    if sys.platform == 'win32':
        try:
            # Try to set console to UTF-8
            os.system('chcp 65001 >nul 2>&1')
        except:
            pass
    
    # Set locale for better unicode support
    try:
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
    except:
        try:
            locale.setlocale(locale.LC_ALL, 'C.UTF-8')
        except:
            pass
    
    # Configure stdout and stderr for UTF-8
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except:
            pass

def run_server(server_module):
    """Run a server module with proper unicode configuration."""
    setup_unicode_environment()
    
    print("[INFO] Unicode environment configured")
    print("[INFO] Starting server...")
    
    try:
        # Import and run the specified server
        if server_module == 'clean':
            from clean_server import *
            # The server will run from its __main__ block
        elif server_module == 'final':
            from final_server import *
        elif server_module == 'test':
            from test_api import APITester
            tester = APITester()
            tester.run_comprehensive_test()
        else:
            print(f"[ERROR] Unknown server module: {server_module}")
            sys.exit(1)
            
    except Exception as e:
        print(f"[ERROR] Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python start_unicode_safe.py <server_type>")
        print("Available servers: clean, final, test")
        sys.exit(1)
    
    server_type = sys.argv[1]
    run_server(server_type)