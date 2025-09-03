#!/usr/bin/env python3
"""
MVP End-to-end Testing Script for AI De-identification System
"""
import asyncio
import json
import sys
import time
from pathlib import Path

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from src.core.config import settings
from src.core.database import DatabaseManager, get_async_db
from src.services.ocr_service import ocr_service
from src.services.pii_service import pii_service
from src.core.processing_engine import processing_engine


class MVPTester:
    """MVP testing class"""
    
    def __init__(self):
        self.test_results = []
        self.test_data_dir = project_root / "test_data"
    
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Log test result"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"   {details}")
        
        self.test_results.append({
            "test": test_name,
            "success": success,
            "details": details
        })
    
    async def test_database_connectivity(self):
        """Test database connection and table creation"""
        print("\n🔍 Testing Database Connectivity")
        
        try:
            # Test sync connection
            sync_health = DatabaseManager.health_check_sync()
            self.log_test("Database sync connection", sync_health)
            
            # Test async connection
            async_health = await DatabaseManager.health_check()
            self.log_test("Database async connection", async_health)
            
            # Test table creation
            await DatabaseManager.initialize_database()
            self.log_test("Database table creation", True, "All tables created successfully")
            
            return sync_health and async_health
            
        except Exception as e:
            self.log_test("Database connectivity", False, str(e))
            return False
    
    def test_ocr_service(self):
        """Test OCR service functionality"""
        print("\n🔍 Testing OCR Service")
        
        try:
            # Test health check
            health = ocr_service.health_check()
            self.log_test("OCR service health check", health)
            
            # Test with sample documents
            test_files = list(self.test_data_dir.glob("*.txt"))
            if not test_files:
                self.log_test("OCR text file test", False, "No test files found")
                return False
            
            for test_file in test_files[:1]:  # Test with first file
                result = ocr_service.extract_text_from_image(str(test_file))  # Will handle text files
                success = len(result.get("text", "")) > 0
                self.log_test(f"OCR text extraction - {test_file.name}", success, 
                            f"Extracted {len(result.get('text', ''))} characters")
            
            return health
            
        except Exception as e:
            self.log_test("OCR service", False, str(e))
            return False
    
    def test_pii_service(self):
        """Test PII detection service"""
        print("\n🔍 Testing PII Detection Service")
        
        try:
            # Test health check
            health = pii_service.health_check()
            self.log_test("PII service health check", health)
            
            # Test with sample text containing PII
            test_text = """
            Patient: John Smith
            SSN: 123-45-6789
            Email: john.smith@email.com
            Phone: (555) 123-4567
            Address: 123 Main St, Anytown, NY 12345
            """
            
            detections = pii_service.detect_pii(test_text)
            pii_found = len(detections) > 0
            self.log_test("PII detection functionality", pii_found, 
                         f"Detected {len(detections)} PII entities")
            
            if pii_found:
                # Test anonymization
                anonymized_text, details = pii_service.anonymize_text(test_text, detections)
                anonymization_success = len(anonymized_text) > 0 and anonymized_text != test_text
                self.log_test("PII anonymization", anonymization_success,
                             f"Applied {len(details)} redactions")
            
            # Test document analysis
            analysis = pii_service.analyze_document(test_text)
            analysis_success = "detections" in analysis and "risk_level" in analysis
            self.log_test("Document analysis", analysis_success,
                         f"Risk level: {analysis.get('risk_level', 'unknown')}")
            
            return health and pii_found
            
        except Exception as e:
            self.log_test("PII service", False, str(e))
            return False
    
    async def test_processing_engine(self):
        """Test the complete processing engine"""
        print("\n🔍 Testing Processing Engine")
        
        try:
            # Create a test document in database
            from src.models.database import Document
            
            async with DatabaseManager.AsyncSessionLocal() as db:
                # Find a test file
                test_files = list(self.test_data_dir.glob("*.txt"))
                if not test_files:
                    self.log_test("Processing engine", False, "No test files found")
                    return False
                
                test_file = test_files[0]
                
                # Create document record
                document = Document(
                    original_filename=test_file.name,
                    file_path=str(test_file),
                    file_size=test_file.stat().st_size,
                    mime_type="text/plain",
                    status="uploaded"
                )
                
                db.add(document)
                await db.commit()
                await db.refresh(document)
                
                # Test processing
                result = await processing_engine.process_document(
                    document_id=document.id,
                    db=db
                )
                
                success = result.get("success", False)
                self.log_test("End-to-end document processing", success,
                             f"Processing time: {result.get('processing_time_seconds', 0):.2f}s")
                
                if success:
                    ocr_success = result.get("ocr_result", {}).get("success", False)
                    pii_success = result.get("pii_result", {}).get("success", False)
                    redaction_success = result.get("redaction_result", {}).get("success", False)
                    
                    self.log_test("OCR processing step", ocr_success)
                    self.log_test("PII detection step", pii_success)
                    self.log_test("Redaction step", redaction_success)
                    
                    # Check if files were created
                    if redaction_success:
                        redacted_file = result.get("redaction_result", {}).get("redacted_file")
                        if redacted_file and Path(redacted_file).exists():
                            self.log_test("Redacted file creation", True, f"File: {redacted_file}")
                        else:
                            self.log_test("Redacted file creation", False, "File not found")
                
                return success
                
        except Exception as e:
            self.log_test("Processing engine", False, str(e))
            return False
    
    def test_configuration(self):
        """Test configuration and settings"""
        print("\n🔍 Testing Configuration")
        
        try:
            # Test directory creation
            dirs_exist = all(
                Path(directory).exists() 
                for directory in [
                    settings.UPLOAD_PATH,
                    settings.OUTPUT_PATH, 
                    settings.TEMP_PATH
                ]
            )
            self.log_test("Required directories exist", dirs_exist)
            
            # Test configuration values
            config_valid = (
                settings.MAX_FILE_SIZE > 0 and
                settings.PII_CONFIDENCE_THRESHOLD > 0 and
                settings.OCR_CONFIDENCE_THRESHOLD > 0
            )
            self.log_test("Configuration validity", config_valid)
            
            return dirs_exist and config_valid
            
        except Exception as e:
            self.log_test("Configuration", False, str(e))
            return False
    
    def test_file_operations(self):
        """Test file operations"""
        print("\n🔍 Testing File Operations")
        
        try:
            # Test file reading
            test_files = list(self.test_data_dir.glob("*.txt"))
            if test_files:
                test_file = test_files[0]
                with open(test_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                read_success = len(content) > 0
                self.log_test("File reading", read_success, f"Read {len(content)} characters")
            else:
                self.log_test("File reading", False, "No test files found")
                return False
            
            # Test file writing
            test_output = Path(settings.OUTPUT_PATH) / "test_output.txt"
            try:
                with open(test_output, 'w', encoding='utf-8') as f:
                    f.write("Test output content")
                write_success = test_output.exists()
                self.log_test("File writing", write_success)
                
                # Clean up
                if test_output.exists():
                    test_output.unlink()
                    
            except Exception as e:
                self.log_test("File writing", False, str(e))
                return False
            
            return read_success and write_success
            
        except Exception as e:
            self.log_test("File operations", False, str(e))
            return False
    
    async def run_all_tests(self):
        """Run all tests"""
        print("🧪 AI De-identification System - MVP Testing Suite")
        print("=" * 60)
        
        # Run tests in order
        test_functions = [
            ("Configuration", self.test_configuration),
            ("File Operations", self.test_file_operations),
            ("Database Connectivity", self.test_database_connectivity),
            ("OCR Service", self.test_ocr_service),
            ("PII Detection Service", self.test_pii_service),
            ("Processing Engine", self.test_processing_engine),
        ]
        
        overall_success = True
        
        for test_name, test_func in test_functions:
            print(f"\n{'='*20} {test_name} {'='*20}")
            
            try:
                if asyncio.iscoroutinefunction(test_func):
                    result = await test_func()
                else:
                    result = test_func()
                
                if result is False:
                    overall_success = False
                    
            except Exception as e:
                print(f"❌ FAIL {test_name} - Exception: {e}")
                overall_success = False
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        
        passed = sum(1 for result in self.test_results if result["success"])
        total = len(self.test_results)
        
        print(f"Tests Run: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Success Rate: {(passed/total)*100:.1f}%" if total > 0 else "N/A")
        
        if overall_success:
            print("\n🎉 ALL TESTS PASSED! MVP is ready for deployment.")
        else:
            print("\n⚠️  Some tests failed. Please review and fix issues before deployment.")
            print("\nFailed tests:")
            for result in self.test_results:
                if not result["success"]:
                    print(f"  - {result['test']}: {result['details']}")
        
        return overall_success


async def main():
    """Main testing function"""
    tester = MVPTester()
    success = await tester.run_all_tests()
    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)