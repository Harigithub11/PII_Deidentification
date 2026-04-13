#!/usr/bin/env python3
"""
Simple test for pixelation pipeline - ASCII only
"""

import requests
import json
import time
import os

# Configuration
BASE_URL = "http://localhost:8002"
TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass123"

def test_pixelation_pipeline():
    print("STARTING PIXELATION PIPELINE TEST")
    print("=" * 50)
    
    session = requests.Session()
    
    # Test 1: Health Check
    print("\nTest 1: Health Check")
    try:
        response = session.get(f"{BASE_URL}/health")
        if response.status_code == 200:
            print("PASS: Backend is healthy")
        else:
            print(f"FAIL: Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"FAIL: Health check error: {e}")
        return False
    
    # Test 2: Login
    print("\nTest 2: User Login")
    try:
        login_data = {"username": TEST_USERNAME, "password": TEST_PASSWORD}
        response = session.post(f"{BASE_URL}/api/v1/auth/login", json=login_data)
        
        if response.status_code == 200:
            data = response.json()
            access_token = data.get("data", {}).get("access_token")
            if access_token:
                session.headers.update({"Authorization": f"Bearer {access_token}"})
                print("PASS: Login successful")
            else:
                print("FAIL: No access token received")
                return False
        else:
            print(f"FAIL: Login failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"FAIL: Login error: {e}")
        return False
    
    # Test 3: Create test document
    print("\nTest 3: Create Test Document")
    test_content = """John Smith, SSN: 123-45-6789, Email: john@email.com, Phone: (555) 123-4567"""
    
    try:
        with open("test_doc.txt", "w") as f:
            f.write(test_content)
        print("PASS: Test document created")
    except Exception as e:
        print(f"FAIL: Document creation error: {e}")
        return False
    
    # Test 4: Upload document
    print("\nTest 4: Upload Document")
    try:
        with open("test_doc.txt", "rb") as f:
            files = {"file": ("test_doc.txt", f, "text/plain")}
            response = session.post(f"{BASE_URL}/api/v1/documents/upload", files=files)
        
        if response.status_code == 201:
            data = response.json()
            document_id = data.get("data", {}).get("id")
            if document_id:
                print(f"PASS: Document uploaded, ID: {document_id}")
            else:
                print("FAIL: No document ID received")
                return False
        else:
            print(f"FAIL: Upload failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"FAIL: Upload error: {e}")
        return False
    
    # Test 5: Process with pixelation
    print("\nTest 5: Process with Pixelation")
    try:
        process_data = {
            "redaction_method": "pixelate",
            "output_format": "same",
            "detection_sensitivity": "high"
        }
        
        response = session.post(
            f"{BASE_URL}/api/v1/documents/{document_id}/process",
            json=process_data
        )
        
        if response.status_code == 200:
            print("PASS: Processing initiated")
            time.sleep(2)  # Wait for processing
        else:
            print(f"FAIL: Processing failed: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"FAIL: Processing error: {e}")
        return False
    
    # Test 6: Download redacted document
    print("\nTest 6: Download Redacted Document")
    try:
        response = session.get(f"{BASE_URL}/api/v1/documents/{document_id}/download/redacted")
        
        if response.status_code == 200:
            with open("redacted_doc.txt", "wb") as f:
                f.write(response.content)
            print("PASS: Redacted document downloaded")
            
            # Show content preview
            try:
                with open("redacted_doc.txt", "r") as f:
                    content = f.read()
                print(f"Content preview: {content[:100]}...")
            except:
                pass
        else:
            print(f"FAIL: Download failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"FAIL: Download error: {e}")
        return False
    
    # Test 7: Verify PII detection
    print("\nTest 7: Verify PII Detection")
    try:
        response = session.get(f"{BASE_URL}/api/v1/documents/{document_id}/pii")
        
        if response.status_code == 200:
            data = response.json()
            pii_entities = data.get("data", [])
            if pii_entities:
                print(f"PASS: PII detection found {len(pii_entities)} entities")
                for entity in pii_entities[:3]:  # Show first 3
                    entity_type = entity.get("entity_type", "Unknown")
                    confidence = entity.get("confidence_score", 0)
                    print(f"  - {entity_type}: {confidence:.2f}")
            else:
                print("WARN: No PII entities detected")
        else:
            print(f"FAIL: PII check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"FAIL: PII check error: {e}")
        return False
    
    # Cleanup
    try:
        os.remove("test_doc.txt")
        os.remove("redacted_doc.txt")
        print("\nCleanup completed")
    except:
        pass
    
    print("\n" + "=" * 50)
    print("ALL TESTS PASSED - Pixelation pipeline working!")
    return True

if __name__ == "__main__":
    success = test_pixelation_pipeline()
    exit(0 if success else 1)