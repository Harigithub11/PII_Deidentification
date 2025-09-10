#!/usr/bin/env python3
"""Quick test of the API server."""

import requests
import time

def test_api():
    """Test the API endpoints."""
    base_url = "http://localhost:8000"
    
    try:
        print("Testing API server...")
        
        # Test health endpoint
        response = requests.get(f"{base_url}/health", timeout=10)
        print(f"Health check: {response.status_code}")
        print(f"Response: {response.json()}")
        
        # Test another endpoint
        response = requests.get(f"{base_url}/test", timeout=10)
        print(f"Test endpoint: {response.status_code}")
        print(f"Response: {response.json()}")
        
        print("API is working!")
        
    except Exception as e:
        print(f"Error testing API: {e}")

if __name__ == "__main__":
    test_api()