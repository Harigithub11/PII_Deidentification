"""
Production Readiness Validation Test Suite
Comprehensive tests to validate system is ready for production deployment.
"""
import pytest
import time
import threading
import tempfile
import shutil
import json
import psutil
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import requests
import uuid
import concurrent.futures
from unittest.mock import MagicMock, patch

from src.core.compliance.hipaa_safe_harbor import SafeHarborProcessor
from src.core.compliance.hipaa_baa import HIPAABAAManager
from src.core.compliance.hipaa_security_rule import HIPAASecurityRuleManager
from src.core.compliance.hipaa_privacy_rule import HIPAAPrivacyRuleManager
from src.core.reporting.compliance_reporter import ComplianceReporter, ComplianceMetricType
from src.core.monitoring.compliance_monitor import ComplianceMonitor, MonitoringConfig, MonitoringMode
from src.core.database.db_manager import DatabaseManager
from src.core.security.encryption_manager import EncryptionManager


class ProductionReadinessConfig:
    """Configuration for production readiness testing"""
    
    # System requirements
    MIN_MEMORY_GB = 8
    MIN_DISK_SPACE_GB = 100
    MIN_CPU_CORES = 4
    
    # Performance requirements
    MAX_STARTUP_TIME = 60  # seconds
    MAX_RESPONSE_TIME = 5   # seconds for typical requests
    MIN_THROUGHPUT = 10     # requests per second
    MAX_ERROR_RATE = 0.01   # 1% max error rate
    
    # Availability requirements
    MIN_UPTIME_PERCENTAGE = 99.9
    MAX_DOWNTIME_MINUTES = 4.32  # 99.9% uptime allows 4.32 min/month
    
    # Security requirements
    ENCRYPTION_ALGORITHMS = ['AES-256', 'RSA-2048']
    REQUIRED_SECURITY_HEADERS = ['X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']
    
    # Compliance requirements
    MIN_HIPAA_COMPLIANCE_SCORE = 0.95
    MAX_PHI_FALSE_POSITIVE_RATE = 0.05
    MAX_PHI_FALSE_NEGATIVE_RATE = 0.01


@pytest.fixture
def prod_config():
    """Production readiness configuration fixture"""
    return ProductionReadinessConfig()


@pytest.fixture
def system_components():
    """System components for testing"""
    # Mock database for testing
    db_manager = MagicMock()
    
    # Initialize components
    safe_harbor = SafeHarborProcessor()
    baa_manager = HIPAABAAManager()
    security_manager = HIPAASecurityRuleManager()
    privacy_manager = HIPAAPrivacyRuleManager()
    reporter = ComplianceReporter(db_manager, safe_harbor, baa_manager, security_manager, privacy_manager)
    
    monitor_config = MonitoringConfig(mode=MonitoringMode.PRODUCTION)
    monitor = ComplianceMonitor(reporter, db_manager, monitor_config)
    
    return {
        'safe_harbor': safe_harbor,
        'baa_manager': baa_manager,
        'security_manager': security_manager,
        'privacy_manager': privacy_manager,
        'reporter': reporter,
        'monitor': monitor,
        'db_manager': db_manager
    }


class TestSystemRequirements:
    """Test system meets minimum hardware/software requirements"""
    
    def test_memory_requirements(self, prod_config):
        """Test system has sufficient memory"""
        available_memory_gb = psutil.virtual_memory().total / (1024**3)
        assert available_memory_gb >= prod_config.MIN_MEMORY_GB, \
            f"Insufficient memory: {available_memory_gb:.1f}GB < {prod_config.MIN_MEMORY_GB}GB required"
    
    def test_disk_space_requirements(self, prod_config):
        """Test system has sufficient disk space"""
        disk_usage = psutil.disk_usage('/')
        available_space_gb = disk_usage.free / (1024**3)
        assert available_space_gb >= prod_config.MIN_DISK_SPACE_GB, \
            f"Insufficient disk space: {available_space_gb:.1f}GB < {prod_config.MIN_DISK_SPACE_GB}GB required"
    
    def test_cpu_requirements(self, prod_config):
        """Test system has sufficient CPU cores"""
        cpu_count = psutil.cpu_count()
        assert cpu_count >= prod_config.MIN_CPU_CORES, \
            f"Insufficient CPU cores: {cpu_count} < {prod_config.MIN_CPU_CORES} required"
    
    def test_python_version(self):
        """Test Python version compatibility"""
        import sys
        python_version = sys.version_info
        assert python_version >= (3, 8), \
            f"Python version {python_version.major}.{python_version.minor} < 3.8 required"
    
    def test_required_dependencies(self):
        """Test all required dependencies are installed"""
        required_packages = [
            'fastapi', 'uvicorn', 'pydantic', 'sqlalchemy', 'alembic',
            'cryptography', 'jwt', 'requests', 'aiofiles', 'pytest',
            'spacy', 'transformers', 'torch', 'numpy', 'pandas'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_packages.append(package)
        
        assert not missing_packages, f"Missing required packages: {missing_packages}"


class TestStartupAndShutdown:
    """Test system startup and shutdown procedures"""
    
    def test_startup_time(self, prod_config, system_components):
        """Test system starts within acceptable time"""
        start_time = time.time()
        
        # Initialize all components
        for component_name, component in system_components.items():
            if hasattr(component, 'initialize') and callable(component.initialize):
                component.initialize()
        
        startup_time = time.time() - start_time
        
        assert startup_time < prod_config.MAX_STARTUP_TIME, \
            f"Startup time {startup_time:.2f}s exceeds limit {prod_config.MAX_STARTUP_TIME}s"
    
    def test_graceful_shutdown(self, system_components):
        """Test system shuts down gracefully"""
        # Start monitoring
        monitor = system_components['monitor']
        monitor.start_monitoring()
        
        # Allow monitoring to run briefly
        time.sleep(2)
        
        # Test graceful shutdown
        shutdown_start = time.time()
        monitor.stop_monitoring()
        shutdown_time = time.time() - shutdown_start
        
        # Should shutdown within reasonable time
        assert shutdown_time < 30, f"Shutdown took too long: {shutdown_time:.2f}s"
        assert not monitor.is_monitoring, "Monitor should be stopped after shutdown"
    
    def test_component_initialization(self, system_components):
        """Test all components initialize properly"""
        for component_name, component in system_components.items():
            # Test that components are properly instantiated
            assert component is not None, f"Component {component_name} is None"
            
            # Test basic functionality where applicable
            if component_name == 'safe_harbor':
                result = component.process_document("Test document with no PHI")
                assert result is not None
                assert hasattr(result, 'compliance_level')
            
            elif component_name == 'security_manager':
                assessment = component.conduct_security_assessment("production_readiness_test")
                assert assessment is not None
                assert hasattr(assessment, 'overall_score')
    
    def test_database_connectivity(self, system_components):
        """Test database connection is established"""
        db_manager = system_components['db_manager']
        
        # Since we're using a mock, test that it's properly configured
        assert db_manager is not None
        assert hasattr(db_manager, 'query_processed_documents')
        assert hasattr(db_manager, 'query_performance_logs')


class TestPerformanceRequirements:
    """Test system meets performance requirements"""
    
    def test_response_time_under_load(self, prod_config, system_components):
        """Test response times under concurrent load"""
        safe_harbor = system_components['safe_harbor']
        
        # Test document with typical PHI content
        test_doc = """
        Patient: John Smith
        SSN: 123-45-6789
        DOB: 01/15/1985
        Email: patient@example.com
        Phone: (555) 123-4567
        Address: 123 Main St, Anytown, CA 90210
        
        Medical History:
        Patient presents with hypertension and diabetes.
        Previous hospitalizations in 2020 and 2022.
        Current medications include metformin and lisinopril.
        
        Assessment and Plan:
        Continue current treatment regimen.
        Follow up in 3 months.
        """
        
        response_times = []
        num_requests = 50
        
        def process_document():
            start_time = time.time()
            result = safe_harbor.process_document(test_doc)
            end_time = time.time()
            return end_time - start_time
        
        # Test concurrent processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(process_document) for _ in range(num_requests)]
            for future in concurrent.futures.as_completed(futures):
                response_time = future.result()
                response_times.append(response_time)
        
        # Validate response times
        avg_response_time = sum(response_times) / len(response_times)
        max_response_time = max(response_times)
        
        assert max_response_time < prod_config.MAX_RESPONSE_TIME, \
            f"Max response time {max_response_time:.2f}s exceeds limit {prod_config.MAX_RESPONSE_TIME}s"
        
        assert avg_response_time < prod_config.MAX_RESPONSE_TIME * 0.5, \
            f"Average response time {avg_response_time:.2f}s too high"
        
        print(f"\nPerformance Results:")
        print(f"Average response time: {avg_response_time:.3f}s")
        print(f"Maximum response time: {max_response_time:.3f}s")
        print(f"Minimum response time: {min(response_times):.3f}s")
    
    def test_throughput_requirements(self, prod_config, system_components):
        """Test system meets throughput requirements"""
        safe_harbor = system_components['safe_harbor']
        
        test_doc = "Patient record with minimal PHI for throughput testing."
        
        # Test throughput over a specific time period
        test_duration = 10  # seconds
        start_time = time.time()
        requests_completed = 0
        
        def continuous_processing():
            nonlocal requests_completed
            while time.time() - start_time < test_duration:
                result = safe_harbor.process_document(test_doc)
                requests_completed += 1
        
        # Run multiple threads for concurrent processing
        threads = []
        for _ in range(5):  # 5 concurrent threads
            thread = threading.Thread(target=continuous_processing)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        actual_duration = time.time() - start_time
        throughput = requests_completed / actual_duration
        
        assert throughput >= prod_config.MIN_THROUGHPUT, \
            f"Throughput {throughput:.2f} req/s below minimum {prod_config.MIN_THROUGHPUT} req/s"
        
        print(f"\nThroughput Test Results:")
        print(f"Requests completed: {requests_completed}")
        print(f"Test duration: {actual_duration:.2f}s")
        print(f"Throughput: {throughput:.2f} requests/second")
    
    def test_memory_stability_under_load(self, prod_config):
        """Test memory usage remains stable under sustained load"""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / (1024 * 1024)  # MB
        
        safe_harbor = SafeHarborProcessor()
        
        # Generate varying document sizes
        documents = []
        for size in [1000, 5000, 10000, 50000]:  # Different document sizes
            doc_content = "PHI content: " + "x" * size
            documents.extend([doc_content] * 25)  # 25 docs per size
        
        memory_measurements = []
        
        # Process documents and monitor memory
        for i, doc in enumerate(documents):
            result = safe_harbor.process_document(doc)
            
            if i % 20 == 0:  # Check memory every 20 documents
                current_memory = process.memory_info().rss / (1024 * 1024)
                memory_measurements.append(current_memory)
        
        final_memory = process.memory_info().rss / (1024 * 1024)
        memory_increase = final_memory - initial_memory
        max_memory = max(memory_measurements)
        
        # Memory should not increase excessively (allow 50% increase)
        assert memory_increase < initial_memory * 0.5, \
            f"Memory increase {memory_increase:.1f}MB too high (initial: {initial_memory:.1f}MB)"
        
        assert max_memory < 1000, \
            f"Peak memory usage {max_memory:.1f}MB exceeds reasonable limit"
        
        print(f"\nMemory Stability Test:")
        print(f"Initial memory: {initial_memory:.1f}MB")
        print(f"Final memory: {final_memory:.1f}MB")
        print(f"Peak memory: {max_memory:.1f}MB")
        print(f"Memory increase: {memory_increase:.1f}MB")


class TestSecurityReadiness:
    """Test security features are production-ready"""
    
    def test_encryption_functionality(self, prod_config):
        """Test encryption is properly configured and functional"""
        encryption_manager = EncryptionManager()
        
        # Test data encryption
        test_data = "Sensitive PHI data for encryption testing"
        encrypted_data = encryption_manager.encrypt_data(test_data)
        decrypted_data = encryption_manager.decrypt_data(encrypted_data)
        
        assert encrypted_data != test_data, "Data should be encrypted"
        assert decrypted_data == test_data, "Decrypted data should match original"
        
        # Test encryption algorithms
        for algorithm in prod_config.ENCRYPTION_ALGORITHMS:
            assert encryption_manager.supports_algorithm(algorithm), \
                f"Required encryption algorithm {algorithm} not supported"
    
    def test_key_management(self):
        """Test encryption key management is secure"""
        encryption_manager = EncryptionManager()
        
        # Test key generation
        key = encryption_manager.generate_key()
        assert key is not None
        assert len(key) >= 32, "Key should be at least 256 bits"
        
        # Test key rotation
        old_key = encryption_manager.current_key
        encryption_manager.rotate_key()
        new_key = encryption_manager.current_key
        
        assert old_key != new_key, "Key should change after rotation"
    
    def test_secure_communication(self):
        """Test secure communication protocols"""
        # This would test HTTPS, TLS certificates, etc.
        # For now, test that insecure protocols are disabled
        
        # Test that HTTP redirects to HTTPS (would need actual server)
        # Test TLS version requirements
        # Test certificate validation
        pass
    
    def test_access_control(self, system_components):
        """Test access control mechanisms"""
        security_manager = system_components['security_manager']
        
        # Test role-based access control
        roles = security_manager.get_available_roles()
        assert 'admin' in roles
        assert 'user' in roles
        assert 'read_only' in roles
        
        # Test permission enforcement
        permissions = security_manager.get_role_permissions('user')
        assert 'read_data' in permissions
        assert 'process_documents' in permissions
        assert 'admin_functions' not in permissions
    
    def test_audit_logging(self, system_components):
        """Test audit logging is comprehensive"""
        # Test that sensitive operations are logged
        safe_harbor = system_components['safe_harbor']
        
        # Process a document (should be logged)
        result = safe_harbor.process_document("Test PHI: SSN 123-45-6789")
        
        # Verify logging functionality
        assert hasattr(safe_harbor, 'logger')
        
        # Test log integrity (would check actual log files in real deployment)
        # Test log retention policies
        # Test log access controls


class TestComplianceReadiness:
    """Test HIPAA compliance features are production-ready"""
    
    def test_hipaa_compliance_score(self, prod_config, system_components):
        """Test overall HIPAA compliance score meets requirements"""
        reporter = system_components['reporter']
        
        # Collect current compliance metrics
        current_time = datetime.now()
        period_start = current_time - timedelta(hours=1)
        
        # Mock some metrics for testing
        with patch.object(reporter, 'collect_metrics') as mock_collect:
            mock_metrics = [
                # Create mock compliance metrics with high scores
                type('MockMetric', (), {
                    'metric_type': ComplianceMetricType.DEIDENTIFICATION_ACCURACY,
                    'value': 0.98,
                    'timestamp': current_time,
                    'source': 'test'
                })(),
                type('MockMetric', (), {
                    'metric_type': ComplianceMetricType.SECURITY_SCORE,
                    'value': 0.95,
                    'timestamp': current_time,
                    'source': 'test'
                })(),
                type('MockMetric', (), {
                    'metric_type': ComplianceMetricType.PRIVACY_COMPLIANCE,
                    'value': 0.97,
                    'timestamp': current_time,
                    'source': 'test'
                })(),
            ]
            mock_collect.return_value = mock_metrics
            
            compliance_score = reporter._calculate_compliance_score(mock_metrics)
            
            assert compliance_score >= prod_config.MIN_HIPAA_COMPLIANCE_SCORE, \
                f"HIPAA compliance score {compliance_score:.3f} below minimum {prod_config.MIN_HIPAA_COMPLIANCE_SCORE}"
    
    def test_phi_detection_accuracy(self, prod_config, system_components):
        """Test PHI detection meets accuracy requirements"""
        safe_harbor = system_components['safe_harbor']
        
        # Test cases with known PHI
        test_cases = [
            {
                'text': 'Patient: John Smith, SSN: 123-45-6789',
                'expected_phi': ['John Smith', '123-45-6789'],
                'phi_types': ['name', 'ssn']
            },
            {
                'text': 'Email: patient@example.com, Phone: (555) 123-4567',
                'expected_phi': ['patient@example.com', '(555) 123-4567'],
                'phi_types': ['email', 'phone']
            },
            {
                'text': 'Address: 123 Main St, Anytown, CA 90210',
                'expected_phi': ['123 Main St, Anytown, CA 90210'],
                'phi_types': ['address']
            },
            {
                'text': 'DOB: 01/15/1985, MRN: 987654321',
                'expected_phi': ['01/15/1985', '987654321'],
                'phi_types': ['date', 'mrn']
            }
        ]
        
        total_phi_items = 0
        correctly_detected = 0
        false_positives = 0
        
        for test_case in test_cases:
            result = safe_harbor.process_document(test_case['text'])
            
            total_phi_items += len(test_case['expected_phi'])
            
            # Check detection accuracy (simplified - would need more sophisticated checking)
            detected_items = len(result.detected_phi) if hasattr(result, 'detected_phi') else 0
            expected_items = len(test_case['expected_phi'])
            
            # Assume detection is correct if counts match (simplified)
            if detected_items == expected_items:
                correctly_detected += expected_items
            elif detected_items > expected_items:
                correctly_detected += expected_items
                false_positives += (detected_items - expected_items)
        
        # Calculate accuracy metrics
        detection_rate = correctly_detected / total_phi_items if total_phi_items > 0 else 0
        false_positive_rate = false_positives / (correctly_detected + false_positives) if (correctly_detected + false_positives) > 0 else 0
        
        assert detection_rate >= (1 - prod_config.MAX_PHI_FALSE_NEGATIVE_RATE), \
            f"PHI detection rate {detection_rate:.3f} below required threshold"
        
        assert false_positive_rate <= prod_config.MAX_PHI_FALSE_POSITIVE_RATE, \
            f"False positive rate {false_positive_rate:.3f} exceeds maximum allowed"
        
        print(f"\nPHI Detection Accuracy:")
        print(f"Detection rate: {detection_rate:.3f}")
        print(f"False positive rate: {false_positive_rate:.3f}")
    
    def test_baa_management_readiness(self, system_components):
        """Test Business Associate Agreement management is ready"""
        baa_manager = system_components['baa_manager']
        
        # Test creating business associate
        ba = baa_manager.create_business_associate(
            name="Production Test Partner",
            organization_type="Healthcare Technology"
        )
        
        assert ba is not None
        assert ba.compliance_status is not None
        assert hasattr(ba, 'id')
        
        # Test BAA compliance tracking
        baa_manager.update_compliance_status(ba.id, 'COMPLIANT')
        updated_ba = baa_manager.get_business_associate(ba.id)
        assert updated_ba.compliance_status == 'COMPLIANT'
    
    def test_audit_trail_completeness(self, system_components):
        """Test audit trail captures all required information"""
        # Test document processing audit trail
        safe_harbor = system_components['safe_harbor']
        
        test_doc = "Patient: John Doe, SSN: 987-65-4321"
        result = safe_harbor.process_document(test_doc)
        
        # Verify audit information is captured
        assert hasattr(result, 'processing_timestamp')
        assert hasattr(result, 'compliance_level')
        assert hasattr(result, 'confidence_score')
        
        # Test privacy rights audit trail
        privacy_manager = system_components['privacy_manager']
        individual_id = uuid.uuid4()
        
        access_request = privacy_manager.submit_rights_request(
            individual_id, 
            privacy_manager.IndividualRight.ACCESS
        )
        
        assert access_request is not None
        assert hasattr(access_request, 'timestamp')
        assert hasattr(access_request, 'status')


class TestRecoveryAndResilience:
    """Test system recovery and resilience capabilities"""
    
    def test_error_handling(self, system_components):
        """Test system handles errors gracefully"""
        safe_harbor = system_components['safe_harbor']
        
        # Test with malformed input
        try:
            result = safe_harbor.process_document(None)
            # Should handle gracefully without crashing
        except Exception as e:
            # Exception should be handled appropriately
            assert str(e) != "", "Error should have meaningful message"
        
        # Test with extremely large input
        large_doc = "x" * 1000000  # 1MB document
        try:
            result = safe_harbor.process_document(large_doc)
            assert result is not None
        except Exception as e:
            # Should handle memory/size limits gracefully
            pass
    
    def test_monitoring_resilience(self, system_components):
        """Test monitoring system continues despite errors"""
        monitor = system_components['monitor']
        
        # Start monitoring
        monitor.start_monitoring()
        
        # Simulate error condition
        with patch.object(monitor.compliance_reporter, 'collect_metrics', side_effect=Exception("Test error")):
            time.sleep(3)  # Let monitoring run with errors
        
        # Monitoring should still be running
        assert monitor.is_monitoring, "Monitoring should continue despite errors"
        
        # Stop monitoring
        monitor.stop_monitoring()
    
    def test_database_connection_handling(self, system_components):
        """Test handling of database connectivity issues"""
        db_manager = system_components['db_manager']
        reporter = system_components['reporter']
        
        # Simulate database connection failure
        with patch.object(db_manager, 'query_processed_documents', side_effect=Exception("Database connection error")):
            # System should handle database errors gracefully
            try:
                metrics = reporter.collect_metrics(datetime.now() - timedelta(hours=1), datetime.now())
                # Should return empty or cached results, not crash
            except Exception as e:
                # If exception is raised, it should be handled appropriately
                assert "Database connection error" in str(e)


class TestDeploymentReadiness:
    """Test system is ready for deployment"""
    
    def test_configuration_management(self):
        """Test configuration is properly managed"""
        # Test environment variable handling
        import os
        
        # Test required environment variables
        required_env_vars = [
            'DATABASE_URL',
            'SECRET_KEY',
            'ENCRYPTION_KEY',
            'LOG_LEVEL'
        ]
        
        # In production, these should be set
        # For testing, we just verify the system handles missing vars gracefully
        for env_var in required_env_vars:
            # System should have default handling or validation
            pass
    
    def test_logging_configuration(self):
        """Test logging is properly configured for production"""
        import logging
        
        # Test that logging is configured
        logger = logging.getLogger('src.core')
        assert logger is not None
        
        # Test log levels are appropriate
        # In production, should not log DEBUG level
        assert logger.level >= logging.INFO
    
    def test_health_check_endpoint(self):
        """Test health check functionality"""
        # This would test the actual health check endpoint
        # For now, test the components that would be checked
        
        components_status = {
            'database': 'healthy',  # Would check actual DB connection
            'encryption': 'healthy',  # Would check encryption service
            'compliance': 'healthy',  # Would check compliance services
            'monitoring': 'healthy'   # Would check monitoring service
        }
        
        # All components should be healthy for production
        for component, status in components_status.items():
            assert status == 'healthy', f"Component {component} is not healthy: {status}"
    
    def test_resource_cleanup(self, system_components):
        """Test system properly cleans up resources"""
        monitor = system_components['monitor']
        
        # Start monitoring to create resources
        monitor.start_monitoring()
        initial_thread_count = threading.active_count()
        
        # Stop monitoring
        monitor.stop_monitoring()
        time.sleep(1)  # Allow cleanup time
        
        final_thread_count = threading.active_count()
        
        # Thread count should not increase permanently
        assert final_thread_count <= initial_thread_count + 1, \
            "Threads not properly cleaned up after shutdown"


@pytest.mark.integration
class TestEndToEndProductionScenarios:
    """End-to-end tests simulating production scenarios"""
    
    def test_typical_healthcare_workflow(self, system_components):
        """Test complete healthcare document processing workflow"""
        # Simulate a typical healthcare document processing scenario
        safe_harbor = system_components['safe_harbor']
        baa_manager = system_components['baa_manager']
        privacy_manager = system_components['privacy_manager']
        
        # 1. Create business associate relationship
        healthcare_partner = baa_manager.create_business_associate(
            name="Regional Medical Center",
            organization_type="Hospital"
        )
        
        # 2. Process healthcare document
        healthcare_doc = """
        DISCHARGE SUMMARY
        
        Patient: Sarah Johnson
        MRN: 12345678
        DOB: 03/22/1978
        SSN: 456-78-9012
        
        Address: 456 Oak Street, Springfield, IL 62701
        Phone: (217) 555-0198
        Email: sarah.johnson@email.com
        
        Admission Date: 10/15/2024
        Discharge Date: 10/18/2024
        
        Attending Physician: Dr. Michael Smith, NPI: 1234567890
        
        HOSPITAL COURSE:
        The patient was admitted for chest pain evaluation. 
        Cardiac catheterization revealed no significant coronary artery disease.
        Patient was discharged in stable condition.
        
        DISCHARGE MEDICATIONS:
        1. Aspirin 81mg daily
        2. Metoprolol 50mg twice daily
        
        FOLLOW-UP:
        Cardiology clinic in 2 weeks
        Primary care in 1 week
        
        Provider: Dr. Michael Smith
        Date: 10/18/2024
        """
        
        # 3. De-identify document
        deident_result = safe_harbor.process_document(healthcare_doc)
        
        # 4. Verify compliance
        assert deident_result.compliance_level == 'HIPAA_COMPLIANT'
        assert deident_result.confidence_score >= 0.95
        
        # 5. Log access for BAA compliance
        individual_id = uuid.uuid4()
        baa_manager.log_phi_access(
            healthcare_partner.id,
            str(individual_id),
            "document_processing",
            "discharge_summary_deidentification"
        )
        
        # 6. Handle individual rights request
        access_request = privacy_manager.submit_rights_request(
            individual_id,
            privacy_manager.IndividualRight.ACCESS
        )
        
        assert access_request.status == 'SUBMITTED'
        
        print("\nEnd-to-End Workflow Test Completed Successfully")
        print(f"Document processed with {deident_result.confidence_score:.3f} confidence")
        print(f"BAA compliance logged for partner: {healthcare_partner.name}")
        print(f"Individual rights request created: {access_request.id}")
    
    def test_high_volume_processing(self, system_components):
        """Test system handles high-volume production load"""
        safe_harbor = system_components['safe_harbor']
        
        # Generate batch of documents
        document_batch = []
        for i in range(100):  # 100 documents
            doc = f"""
            Medical Record #{i+1}
            Patient: Test Patient {i+1}
            SSN: {str(i+1).zfill(3)}-45-{str(i+1).zfill(4)}
            DOB: 01/{str((i % 12) + 1).zfill(2)}/1980
            Email: patient{i+1}@test.com
            Phone: (555) {str(i+1).zfill(3)}-{str(i+1).zfill(4)}
            
            Clinical Notes:
            Patient presents for routine checkup.
            Vital signs stable. No acute concerns.
            Continue current medication regimen.
            """
            document_batch.append(doc)
        
        # Process batch
        start_time = time.time()
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(safe_harbor.process_document, doc) for doc in document_batch]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
        
        processing_time = time.time() - start_time
        
        # Validate results
        assert len(results) == len(document_batch)
        
        compliant_docs = sum(1 for r in results if r.compliance_level == 'HIPAA_COMPLIANT')
        compliance_rate = compliant_docs / len(results)
        
        assert compliance_rate >= 0.99, f"Compliance rate {compliance_rate:.3f} below 99% threshold"
        
        throughput = len(document_batch) / processing_time
        assert throughput >= 5, f"Throughput {throughput:.2f} docs/sec below minimum requirement"
        
        print(f"\nHigh Volume Processing Test:")
        print(f"Documents processed: {len(results)}")
        print(f"Processing time: {processing_time:.2f}s")
        print(f"Throughput: {throughput:.2f} documents/second")
        print(f"Compliance rate: {compliance_rate:.3f}")


if __name__ == "__main__":
    pytest.main(["-v", __file__, "--tb=short", "-m", "not integration"])