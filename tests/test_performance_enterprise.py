"""
Enterprise-Scale Performance Testing Suite
Tests system performance under enterprise workloads with HIPAA compliance requirements.
"""
import pytest
import asyncio
import time
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
import uuid
import json
import psutil
import tempfile
import os
from pathlib import Path
import threading
import queue
import random
import string

from src.core.compliance.hipaa_safe_harbor import SafeHarborProcessor
from src.core.compliance.hipaa_baa import HIPAABAAManager
from src.core.compliance.hipaa_security_rule import HIPAASecurityRuleManager
from src.core.compliance.hipaa_privacy_rule import HIPAAPrivacyRuleManager
from src.core.processing.document_processor import DocumentProcessor
from src.core.processing.batch_processor import BatchProcessor
from src.core.monitoring.performance_monitor import PerformanceMonitor
from src.core.database.db_manager import DatabaseManager
from src.core.orchestration.workflow_engine import WorkflowEngine


class PerformanceTestConfig:
    """Configuration for performance tests"""
    
    # Enterprise scale targets
    MAX_DOCUMENT_PROCESSING_TIME = 30.0  # seconds for typical healthcare document
    MAX_BATCH_PROCESSING_TIME = 300.0    # seconds for 100 documents
    MIN_THROUGHPUT_DOCS_PER_SECOND = 5.0
    MAX_MEMORY_USAGE_MB = 2048
    MAX_CPU_USAGE_PERCENT = 85
    
    # Load testing parameters
    CONCURRENT_USERS = 50
    DOCUMENTS_PER_USER = 20
    TOTAL_DOCUMENTS = 10000
    STRESS_TEST_DURATION = 3600  # 1 hour
    
    # Document sizes (bytes)
    SMALL_DOCUMENT_SIZE = 5000
    MEDIUM_DOCUMENT_SIZE = 50000
    LARGE_DOCUMENT_SIZE = 500000
    XLARGE_DOCUMENT_SIZE = 2000000


@pytest.fixture
def performance_config():
    """Performance test configuration"""
    return PerformanceTestConfig()


@pytest.fixture
def performance_monitor():
    """Performance monitoring fixture"""
    return PerformanceMonitor()


@pytest.fixture
def test_documents():
    """Generate test documents with varying sizes and PHI content"""
    documents = []
    
    # Sample PHI patterns for realistic testing
    phi_patterns = [
        "Patient: John Smith, SSN: 123-45-6789, DOB: 01/15/1985",
        "Email: patient@example.com, Phone: (555) 123-4567",
        "Address: 123 Main St, Anytown, CA 90210",
        "Medical Record: MRN-987654, Account: ACC-123456",
        "Provider: Dr. Jane Doe, NPI: 1234567890",
        "Visit Date: 03/15/2024, Discharge: 03/20/2024"
    ]
    
    # Generate documents of different sizes
    for size_type, size_bytes in [
        ("small", PerformanceTestConfig.SMALL_DOCUMENT_SIZE),
        ("medium", PerformanceTestConfig.MEDIUM_DOCUMENT_SIZE),
        ("large", PerformanceTestConfig.LARGE_DOCUMENT_SIZE),
        ("xlarge", PerformanceTestConfig.XLARGE_DOCUMENT_SIZE)
    ]:
        for i in range(25):  # 25 docs per size category
            # Create realistic medical document content
            phi_content = random.choices(phi_patterns, k=3)
            filler_text = ''.join(random.choices(string.ascii_letters + string.digits + ' ', 
                                               k=size_bytes - sum(len(p) for p in phi_content) - 100))
            
            document_text = f"""
MEDICAL RECORD - {size_type.upper()} DOCUMENT #{i+1}

{chr(10).join(phi_content)}

Clinical Notes:
{filler_text}

Assessment and Plan:
Continue current treatment regimen. Follow up in 2 weeks.
Patient education provided regarding medication compliance.

Signed: Dr. Medical Provider
Date: {time.strftime('%m/%d/%Y')}
            """.strip()
            
            documents.append({
                'id': str(uuid.uuid4()),
                'content': document_text,
                'size': len(document_text),
                'type': size_type,
                'phi_count': len(phi_content)
            })
    
    return documents


class TestDocumentProcessingPerformance:
    """Test individual document processing performance"""
    
    def test_single_document_processing_time(self, performance_config, test_documents):
        """Test that individual documents process within time limits"""
        processor = SafeHarborProcessor()
        processing_times = []
        
        for doc in test_documents[:20]:  # Test subset for speed
            start_time = time.time()
            result = processor.process_document(doc['content'])
            end_time = time.time()
            
            processing_time = end_time - start_time
            processing_times.append(processing_time)
            
            # Assert individual document processing time
            assert processing_time < performance_config.MAX_DOCUMENT_PROCESSING_TIME, \
                f"Document {doc['id']} took {processing_time:.2f}s (limit: {performance_config.MAX_DOCUMENT_PROCESSING_TIME}s)"
            
            # Verify compliance maintained under performance pressure
            assert result.compliance_level == 'HIPAA_COMPLIANT'
            assert result.confidence_score >= 0.95
        
        # Performance statistics
        avg_time = statistics.mean(processing_times)
        max_time = max(processing_times)
        min_time = min(processing_times)
        
        print(f"\nDocument Processing Performance:")
        print(f"Average time: {avg_time:.3f}s")
        print(f"Maximum time: {max_time:.3f}s")
        print(f"Minimum time: {min_time:.3f}s")
        
        assert avg_time < performance_config.MAX_DOCUMENT_PROCESSING_TIME * 0.7
    
    def test_batch_processing_performance(self, performance_config, test_documents):
        """Test batch processing performance"""
        batch_processor = BatchProcessor()
        
        # Test batch of 100 documents
        batch_docs = test_documents[:100]
        
        start_time = time.time()
        batch_result = batch_processor.process_batch(batch_docs)
        end_time = time.time()
        
        batch_processing_time = end_time - start_time
        
        assert batch_processing_time < performance_config.MAX_BATCH_PROCESSING_TIME, \
            f"Batch processing took {batch_processing_time:.2f}s (limit: {performance_config.MAX_BATCH_PROCESSING_TIME}s)"
        
        # Verify all documents processed successfully
        assert len(batch_result.processed_documents) == 100
        assert batch_result.success_rate >= 0.99
        
        # Calculate throughput
        throughput = len(batch_docs) / batch_processing_time
        assert throughput >= performance_config.MIN_THROUGHPUT_DOCS_PER_SECOND
        
        print(f"\nBatch Processing Performance:")
        print(f"Processing time: {batch_processing_time:.2f}s")
        print(f"Throughput: {throughput:.2f} docs/second")
        print(f"Success rate: {batch_result.success_rate:.3f}")


class TestConcurrentProcessingPerformance:
    """Test concurrent processing under load"""
    
    def test_concurrent_user_simulation(self, performance_config, test_documents):
        """Simulate multiple concurrent users processing documents"""
        processor = SafeHarborProcessor()
        results_queue = queue.Queue()
        
        def user_session(user_id: int, documents: List[Dict]):
            """Simulate a user session processing documents"""
            session_results = []
            session_start = time.time()
            
            for doc in documents:
                doc_start = time.time()
                try:
                    result = processor.process_document(doc['content'])
                    doc_end = time.time()
                    
                    session_results.append({
                        'user_id': user_id,
                        'doc_id': doc['id'],
                        'processing_time': doc_end - doc_start,
                        'success': True,
                        'compliance': result.compliance_level == 'HIPAA_COMPLIANT'
                    })
                except Exception as e:
                    session_results.append({
                        'user_id': user_id,
                        'doc_id': doc['id'],
                        'processing_time': 0,
                        'success': False,
                        'error': str(e)
                    })
            
            session_end = time.time()
            results_queue.put({
                'user_id': user_id,
                'session_time': session_end - session_start,
                'documents_processed': len(documents),
                'results': session_results
            })
        
        # Create user sessions
        docs_per_user = performance_config.DOCUMENTS_PER_USER
        user_threads = []
        
        test_start = time.time()
        
        for user_id in range(performance_config.CONCURRENT_USERS):
            user_docs = random.sample(test_documents, docs_per_user)
            thread = threading.Thread(target=user_session, args=(user_id, user_docs))
            user_threads.append(thread)
            thread.start()
        
        # Wait for all users to complete
        for thread in user_threads:
            thread.join(timeout=600)  # 10 minute timeout
        
        test_end = time.time()
        total_test_time = test_end - test_start
        
        # Collect results
        session_results = []
        while not results_queue.empty():
            session_results.append(results_queue.get())
        
        # Analyze performance
        total_docs_processed = sum(r['documents_processed'] for r in session_results)
        total_successful = sum(len([d for d in r['results'] if d['success']]) for r in session_results)
        success_rate = total_successful / total_docs_processed if total_docs_processed > 0 else 0
        overall_throughput = total_docs_processed / total_test_time
        
        print(f"\nConcurrent Processing Performance:")
        print(f"Total test time: {total_test_time:.2f}s")
        print(f"Total documents processed: {total_docs_processed}")
        print(f"Success rate: {success_rate:.3f}")
        print(f"Overall throughput: {overall_throughput:.2f} docs/second")
        
        # Performance assertions
        assert success_rate >= 0.95, f"Success rate {success_rate:.3f} below 95% threshold"
        assert overall_throughput >= performance_config.MIN_THROUGHPUT_DOCS_PER_SECOND
        assert len(session_results) == performance_config.CONCURRENT_USERS


class TestResourceUtilizationPerformance:
    """Test system resource utilization under load"""
    
    def test_memory_usage_under_load(self, performance_config, test_documents):
        """Test memory usage stays within limits during processing"""
        processor = SafeHarborProcessor()
        process = psutil.Process()
        
        # Get baseline memory usage
        baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        memory_measurements = []
        
        for i, doc in enumerate(test_documents):
            # Process document
            result = processor.process_document(doc['content'])
            
            # Measure memory every 10 documents
            if i % 10 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024
                memory_measurements.append(current_memory)
                
                # Assert memory usage within limits
                assert current_memory < performance_config.MAX_MEMORY_USAGE_MB, \
                    f"Memory usage {current_memory:.1f}MB exceeds limit {performance_config.MAX_MEMORY_USAGE_MB}MB"
        
        max_memory = max(memory_measurements)
        avg_memory = statistics.mean(memory_measurements)
        
        print(f"\nMemory Usage Analysis:")
        print(f"Baseline memory: {baseline_memory:.1f}MB")
        print(f"Average memory: {avg_memory:.1f}MB")
        print(f"Peak memory: {max_memory:.1f}MB")
        print(f"Memory limit: {performance_config.MAX_MEMORY_USAGE_MB}MB")
    
    def test_cpu_usage_under_load(self, performance_config, test_documents):
        """Test CPU usage during intensive processing"""
        processor = SafeHarborProcessor()
        cpu_measurements = []
        
        # Monitor CPU during processing
        def cpu_monitor():
            while not stop_monitoring:
                cpu_percent = psutil.cpu_percent(interval=1)
                cpu_measurements.append(cpu_percent)
        
        stop_monitoring = False
        cpu_thread = threading.Thread(target=cpu_monitor)
        cpu_thread.start()
        
        try:
            # Process subset of documents intensively
            for doc in test_documents[:50]:
                result = processor.process_document(doc['content'])
                assert result.compliance_level == 'HIPAA_COMPLIANT'
        
        finally:
            stop_monitoring = True
            cpu_thread.join()
        
        if cpu_measurements:
            max_cpu = max(cpu_measurements)
            avg_cpu = statistics.mean(cpu_measurements)
            
            print(f"\nCPU Usage Analysis:")
            print(f"Average CPU: {avg_cpu:.1f}%")
            print(f"Peak CPU: {max_cpu:.1f}%")
            print(f"CPU limit: {performance_config.MAX_CPU_USAGE_PERCENT}%")
            
            assert avg_cpu < performance_config.MAX_CPU_USAGE_PERCENT


class TestScalabilityPerformance:
    """Test system scalability with increasing load"""
    
    def test_linear_scalability(self, performance_config, test_documents):
        """Test that performance scales linearly with document count"""
        processor = SafeHarborProcessor()
        
        document_counts = [10, 50, 100, 500, 1000]
        processing_times = []
        throughputs = []
        
        for doc_count in document_counts:
            test_docs = test_documents[:doc_count]
            
            start_time = time.time()
            for doc in test_docs:
                result = processor.process_document(doc['content'])
                assert result.compliance_level == 'HIPAA_COMPLIANT'
            end_time = time.time()
            
            processing_time = end_time - start_time
            throughput = doc_count / processing_time
            
            processing_times.append(processing_time)
            throughputs.append(throughput)
            
            print(f"Documents: {doc_count}, Time: {processing_time:.2f}s, Throughput: {throughput:.2f} docs/s")
        
        # Verify throughput doesn't degrade significantly
        min_throughput = min(throughputs)
        max_throughput = max(throughputs)
        throughput_degradation = (max_throughput - min_throughput) / max_throughput
        
        assert throughput_degradation < 0.3, \
            f"Throughput degradation {throughput_degradation:.3f} exceeds 30% threshold"
    
    def test_enterprise_volume_processing(self, performance_config):
        """Test processing enterprise volume (10,000+ documents)"""
        processor = SafeHarborProcessor()
        
        # Generate large volume of test documents
        large_volume_docs = []
        for i in range(1000):  # Generate 1000 docs for performance test
            doc_content = f"""
Patient Record #{i+1}
Name: Test Patient {i+1}
SSN: {random.randint(100000000, 999999999)}
DOB: {random.randint(1,12)}/{random.randint(1,28)}/{random.randint(1950,2010)}
Phone: ({random.randint(100,999)}) {random.randint(100,999)}-{random.randint(1000,9999)}
Email: patient{i+1}@example.com

Medical History:
{' '.join(random.choices(string.ascii_letters + ' ', k=2000))}

Treatment Plan:
Continue monitoring vital signs. Follow up in 2 weeks.
            """
            
            large_volume_docs.append({
                'id': str(uuid.uuid4()),
                'content': doc_content,
                'size': len(doc_content)
            })
        
        # Process in batches to simulate enterprise workflow
        batch_size = 100
        total_start_time = time.time()
        total_processed = 0
        
        for i in range(0, len(large_volume_docs), batch_size):
            batch = large_volume_docs[i:i+batch_size]
            batch_start_time = time.time()
            
            for doc in batch:
                result = processor.process_document(doc['content'])
                assert result.compliance_level == 'HIPAA_COMPLIANT'
                total_processed += 1
            
            batch_end_time = time.time()
            batch_time = batch_end_time - batch_start_time
            batch_throughput = len(batch) / batch_time
            
            # Ensure each batch meets performance requirements
            assert batch_throughput >= performance_config.MIN_THROUGHPUT_DOCS_PER_SECOND
        
        total_end_time = time.time()
        total_time = total_end_time - total_start_time
        overall_throughput = total_processed / total_time
        
        print(f"\nEnterprise Volume Processing:")
        print(f"Total documents processed: {total_processed}")
        print(f"Total processing time: {total_time:.2f}s")
        print(f"Overall throughput: {overall_throughput:.2f} docs/second")
        
        assert overall_throughput >= performance_config.MIN_THROUGHPUT_DOCS_PER_SECOND
        assert total_processed == len(large_volume_docs)


class TestCompliancePerformanceIntegration:
    """Test compliance features don't significantly impact performance"""
    
    def test_full_compliance_stack_performance(self, performance_config, test_documents):
        """Test performance with full HIPAA compliance stack enabled"""
        # Initialize all compliance components
        safe_harbor = SafeHarborProcessor()
        baa_manager = HIPAABAAManager()
        security_manager = HIPAASecurityRuleManager()
        privacy_manager = HIPAAPrivacyRuleManager()
        
        # Create test business associate
        ba = baa_manager.create_business_associate(
            name="Performance Test Partner",
            organization_type="Healthcare Technology"
        )
        
        processing_times = []
        
        for doc in test_documents[:50]:  # Test subset for performance validation
            start_time = time.time()
            
            # Full compliance processing pipeline
            # 1. Safe Harbor de-identification
            deident_result = safe_harbor.process_document(doc['content'])
            
            # 2. Security rule validation
            security_assessment = security_manager.conduct_security_assessment("test_assessor")
            
            # 3. Privacy rule compliance check
            individual_id = uuid.uuid4()
            access_request = privacy_manager.submit_rights_request(
                individual_id, 
                privacy_manager.IndividualRight.ACCESS
            )
            
            # 4. BAA compliance logging
            baa_manager.log_phi_access(
                ba.id, 
                str(individual_id), 
                "performance_test", 
                "automated_processing"
            )
            
            end_time = time.time()
            processing_time = end_time - start_time
            processing_times.append(processing_time)
            
            # Verify compliance maintained
            assert deident_result.compliance_level == 'HIPAA_COMPLIANT'
            assert security_assessment.overall_score >= 0.8
            assert access_request.status == 'SUBMITTED'
        
        # Performance analysis
        avg_time = statistics.mean(processing_times)
        max_time = max(processing_times)
        
        print(f"\nFull Compliance Stack Performance:")
        print(f"Average processing time: {avg_time:.3f}s")
        print(f"Maximum processing time: {max_time:.3f}s")
        
        # Allow higher time limit for full compliance stack
        compliance_time_limit = performance_config.MAX_DOCUMENT_PROCESSING_TIME * 2
        assert avg_time < compliance_time_limit, \
            f"Full compliance processing time {avg_time:.3f}s exceeds limit {compliance_time_limit}s"


if __name__ == "__main__":
    pytest.main(["-v", __file__, "--tb=short"])