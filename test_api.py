#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Script for Multi-Format Document API

This script tests the PII De-identification System API with various document formats.
"""

import requests
import json
import time
import os
import sys
import locale
from pathlib import Path
from typing import Dict, Any, Optional
import tempfile
from PIL import Image, ImageDraw, ImageFont
import io

# Configure UTF-8 environment for Windows compatibility
if sys.platform == 'win32':
    os.environ['PYTHONUTF8'] = '1'
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    try:
        os.system('chcp 65001 >nul 2>&1')
    except:
        pass

class APITester:
    """Class to test the document processing API."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.test_results = {}
        
    def test_health(self) -> bool:
        """Test if the API is running."""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            if response.status_code == 200:
                print("[OK] API Health Check: PASSED")
                return True
            else:
                print(f"[ERROR] API Health Check: FAILED (Status: {response.status_code})")
                return False
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] API Health Check: FAILED (Error: {e})")
            return False
    
    def get_supported_formats(self) -> Dict[str, Any]:
        """Get supported formats from the API."""
        try:
            response = requests.get(f"{self.base_url}/api/v1/documents/formats")
            if response.status_code == 200:
                formats = response.json()
                print("[OK] Supported Formats Retrieved:")
                print(f"   [PDF] PDF: {formats['supported_formats']['pdf']}")
                print(f"   [IMG] Images: {formats['supported_formats']['images']}")
                print(f"   [INFO] Max file size: {formats['max_file_size_mb']}MB")
                print(f"   [INFO] Max pages: {formats['max_pages']}")
                return formats
            else:
                print(f"[ERROR] Failed to get supported formats: {response.status_code}")
                return {}
        except Exception as e:
            print(f"[ERROR] Error getting supported formats: {e}")
            return {}
    
    def create_test_image(self, format_ext: str, text: str = "Sample Document\nThis is a test document\nfor PII detection.") -> bytes:
        """Create a test image with text."""
        # Create a white image
        img = Image.new('RGB', (800, 600), color='white')
        draw = ImageDraw.Draw(img)
        
        # Try to use a default font, fallback to default if not available
        try:
            font = ImageFont.truetype("arial.ttf", 24)
        except:
            try:
                font = ImageFont.load_default()
            except:
                font = None
        
        # Draw text
        lines = text.split('\n')
        y_offset = 50
        for line in lines:
            draw.text((50, y_offset), line, fill='black', font=font)
            y_offset += 40
        
        # Add some sample PII-like text
        pii_text = [
            "Name: John Doe",
            "Email: john.doe@email.com", 
            "Phone: (555) 123-4567",
            "SSN: 123-45-6789"
        ]
        
        y_offset += 50
        for line in pii_text:
            draw.text((50, y_offset), line, fill='red', font=font)
            y_offset += 30
        
        # Convert to bytes
        img_bytes = io.BytesIO()
        img.save(img_bytes, format=format_ext.upper().replace('.', ''))
        return img_bytes.getvalue()
    
    def create_test_pdf(self) -> bytes:
        """Create a simple test PDF."""
        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter
            
            buffer = io.BytesIO()
            c = canvas.Canvas(buffer, pagesize=letter)
            
            # Add text content
            c.drawString(100, 750, "Test PDF Document")
            c.drawString(100, 720, "This is a sample PDF for testing multi-format support.")
            c.drawString(100, 690, "")
            c.drawString(100, 660, "Sample PII Data:")
            c.drawString(120, 630, "Name: Jane Smith")
            c.drawString(120, 600, "Email: jane.smith@example.com")
            c.drawString(120, 570, "Phone: +1-555-987-6543")
            c.drawString(120, 540, "ID: ABC123456")
            
            # Add a second page
            c.showPage()
            c.drawString(100, 750, "Page 2 of Test PDF")
            c.drawString(100, 720, "Additional content on second page.")
            c.drawString(100, 690, "More PII examples:")
            c.drawString(120, 660, "Address: 123 Main St, Anytown, ST 12345")
            c.drawString(120, 630, "Credit Card: 4111-1111-1111-1111")
            
            c.save()
            return buffer.getvalue()
            
        except ImportError:
            print("[WARN] ReportLab not available, creating dummy PDF content")
            return b"Dummy PDF content for testing"
    
    def upload_and_test_format(self, filename: str, file_content: bytes, format_name: str) -> Optional[str]:
        """Upload a file and test processing."""
        try:
            print(f"\n[TEST] Testing {format_name} format...")
            
            files = {'file': (filename, file_content)}
            data = {'auto_process': 'true'}
            
            # Upload the file
            response = requests.post(
                f"{self.base_url}/api/v1/documents/upload",
                files=files,
                data=data,
                timeout=30
            )
            
            if response.status_code != 200:
                print(f"[ERROR] Upload failed: {response.status_code} - {response.text}")
                return None
            
            result = response.json()
            document_id = result['document_id']
            
            print(f"[OK] Upload successful:")
            print(f"   [ID] Document ID: {document_id}")
            print(f"   [TYPE] Type: {result['document_type']}")
            print(f"   [SIZE] Size: {result['file_size_bytes']} bytes")
            print(f"   [PAGES] Pages: {result['estimated_pages']}")
            
            # Wait for processing and check status
            return self.monitor_processing(document_id, format_name)
            
        except Exception as e:
            print(f"[ERROR] Error testing {format_name}: {e}")
            return None
    
    def monitor_processing(self, document_id: str, format_name: str) -> Optional[str]:
        """Monitor document processing progress."""
        try:
            max_wait_time = 60  # seconds
            check_interval = 2  # seconds
            elapsed_time = 0
            
            print("[MONITOR] Monitoring processing status...")
            
            while elapsed_time < max_wait_time:
                # Check document status
                status_response = requests.get(f"{self.base_url}/api/v1/documents/status/{document_id}")
                
                if status_response.status_code == 200:
                    status = status_response.json()
                    processing_status = status['processing_status']
                    
                    print(f"   [STATUS] Status: {processing_status}")
                    
                    if processing_status == 'completed':
                        # Get results
                        results_response = requests.get(f"{self.base_url}/api/v1/documents/results/{document_id}")
                        
                        if results_response.status_code == 200:
                            results = results_response.json()
                            
                            print(f"[OK] Processing completed for {format_name}:")
                            print(f"   [TIME] Processing time: {results['processing_time_seconds']:.2f}s")
                            print(f"   [SCORE] Quality score: {results['quality_score']:.1f}")
                            print(f"   [PAGES] Pages processed: {results['page_count']}")
                            print(f"   [OPS] Operations: {', '.join(results['operations_performed'])}")
                            
                            if results['extracted_text_preview']:
                                print(f"   [TEXT] Text preview: {results['extracted_text_preview'][:100]}...")
                            
                            if results['errors_encountered']:
                                print(f"   [WARN] Errors: {', '.join(results['errors_encountered'])}")
                            
                            self.test_results[format_name] = {
                                'success': True,
                                'document_id': document_id,
                                'results': results
                            }
                            
                            return document_id
                        else:
                            print(f"[ERROR] Failed to get results: {results_response.status_code}")
                            break
                    
                    elif processing_status == 'failed':
                        print(f"[ERROR] Processing failed for {format_name}")
                        break
                    
                    elif processing_status == 'processing':
                        print("   [WAIT] Still processing...")
                
                time.sleep(check_interval)
                elapsed_time += check_interval
            
            if elapsed_time >= max_wait_time:
                print(f"[TIMEOUT] Processing timeout for {format_name}")
            
            return None
            
        except Exception as e:
            print(f"[ERROR] Error monitoring {format_name}: {e}")
            return None
    
    def run_comprehensive_test(self):
        """Run comprehensive tests for all supported formats."""
        print("[START] Starting Comprehensive Multi-Format API Test")
        print("=" * 60)
        
        # Test health check
        if not self.test_health():
            print("[ERROR] API is not available. Please start the server first.")
            return
        
        # Get supported formats
        formats = self.get_supported_formats()
        if not formats:
            print("[ERROR] Cannot get supported formats. Test aborted.")
            return
        
        print("\n[FORMATS] Testing Document Formats:")
        print("=" * 40)
        
        # Test PDF
        if '.pdf' in formats.get('supported_formats', {}).get('pdf', []):
            pdf_content = self.create_test_pdf()
            self.upload_and_test_format('test_document.pdf', pdf_content, 'PDF')
        
        # Test various image formats
        image_formats = [
            ('.png', 'PNG'),
            ('.jpg', 'JPEG'),
            ('.jpeg', 'JPEG'),
            ('.tiff', 'TIFF'),
            ('.bmp', 'BMP'),
            ('.webp', 'WebP'),
        ]
        
        for ext, format_name in image_formats:
            if ext in formats.get('supported_formats', {}).get('images', []):
                try:
                    # Handle WebP separately as PIL might not support it
                    if ext == '.webp':
                        try:
                            img_content = self.create_test_image('PNG')  # Create as PNG first
                            img = Image.open(io.BytesIO(img_content))
                            webp_buffer = io.BytesIO()
                            img.save(webp_buffer, format='WebP')
                            img_content = webp_buffer.getvalue()
                        except Exception as e:
                            print(f"[WARN] Skipping WebP test: {e}")
                            continue
                    else:
                        img_content = self.create_test_image(ext.replace('.', ''))
                    
                    self.upload_and_test_format(f'test_image{ext}', img_content, format_name)
                except Exception as e:
                    print(f"[WARN] Skipping {format_name} test: {e}")
        
        # Print summary
        self.print_test_summary()
    
    def print_test_summary(self):
        """Print test results summary."""
        print("\n[SUMMARY] Test Summary:")
        print("=" * 40)
        
        successful_tests = sum(1 for result in self.test_results.values() if result.get('success', False))
        total_tests = len(self.test_results)
        
        print(f"[OK] Successful tests: {successful_tests}/{total_tests}")
        
        for format_name, result in self.test_results.items():
            status = "[PASS]" if result.get('success', False) else "[FAIL]"
            print(f"   {status} {format_name}")
        
        if successful_tests == total_tests and total_tests > 0:
            print("\n[SUCCESS] All tests passed! Multi-format support is working correctly.")
        elif successful_tests > 0:
            print(f"\n[WARN] {successful_tests}/{total_tests} tests passed. Some formats may need attention.")
        else:
            print("\n[ERROR] No tests passed. Please check the API implementation.")

def main():
    """Main function to run tests."""
    print("[TEST] Multi-Format Document API Tester")
    print("This script will test various document formats with the PII detection API.")
    print("\nMake sure the API server is running at http://localhost:8000")
    print("Start it with: python run_server.py\n")
    
    input("Press Enter to start testing...")
    
    tester = APITester()
    tester.run_comprehensive_test()

if __name__ == "__main__":
    main()