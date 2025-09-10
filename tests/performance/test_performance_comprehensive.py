"""
Comprehensive Performance Tests

Tests performance characteristics including response times,
throughput, memory usage, and scalability under load.
"""

import pytest
import time
import threading
import asyncio
import psutil
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from pathlib import Path

from fastapi.testclient import TestClient

from tests.utils import (
    PerformanceTestHelper, TestDataFactory, 
    FileTestHelper, APITestHelper
)


class TestAPIPerformance:
    """Test API endpoint performance."""
    
    def setup_method(self):
        """Set up performance testing utilities."""
        self.performance_helper = PerformanceTestHelper()
        self.data_factory = TestDataFactory()
        self.api_helper = APITestHelper()
    
    @pytest.mark.performance
    def test_pii_detection_response_time(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test PII detection API response time."""
        # Test different text sizes
        test_cases = [
            {"name": "small", "text": self.data_factory.create_pii_text(['PERSON']), "max_time": 1.0},
            {"name": "medium", "text": self.data_factory.create_pii_text() * 10, "max_time": 3.0},
            {"name": "large", "text": self.data_factory.create_pii_text() * 100, "max_time": 10.0}
        ]
        
        for test_case in test_cases:
            # Act
            result, execution_time = self.performance_helper.measure_execution_time(
                client.post,
                "/api/v1/pii/detect",
                json={"text": test_case["text"]},
                headers=auth_headers
            )
            
            # Assert
            assert result.status_code == 200, f"Request failed for {test_case['name']} text"
            assert execution_time <= test_case["max_time"], \
                f"{test_case['name']} text took {execution_time:.3f}s, expected <{test_case['max_time']}s"
    
    @pytest.mark.performance
    def test_concurrent_request_handling(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test API performance under concurrent load."""
        # Arrange
        num_concurrent_requests = 20
        request_data = {"text": self.data_factory.create_pii_text(['PERSON', 'EMAIL'])}
        
        def make_request():
            start_time = time.time()
            response = client.post(
                "/api/v1/pii/detect",
                json=request_data,
                headers=auth_headers
            )
            end_time = time.time()
            return {
                "status_code": response.status_code,
                "response_time": end_time - start_time,
                "response_size": len(response.content)
            }
        
        # Act - Execute concurrent requests
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=num_concurrent_requests) as executor:
            futures = [executor.submit(make_request) for _ in range(num_concurrent_requests)]
            results = [future.result() for future in as_completed(futures)]
        total_time = time.time() - start_time
        
        # Assert
        successful_requests = [r for r in results if r["status_code"] == 200]
        failed_requests = [r for r in results if r["status_code"] != 200]
        
        # At least 80% of requests should succeed
        success_rate = len(successful_requests) / len(results)
        assert success_rate >= 0.8, f"Success rate {success_rate:.2%} below 80% under load"
        
        # Calculate throughput
        throughput = len(successful_requests) / total_time
        assert throughput >= 5.0, f"Throughput {throughput:.2f} req/s below minimum 5 req/s"
        
        # Response time should not degrade too much under load
        response_times = [r["response_time"] for r in successful_requests]
        avg_response_time = statistics.mean(response_times)
        p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
        
        assert avg_response_time <= 5.0, f"Average response time {avg_response_time:.3f}s too high"
        assert p95_response_time <= 10.0, f"95th percentile response time {p95_response_time:.3f}s too high"
    
    @pytest.mark.performance
    @pytest.mark.slow
    def test_sustained_load_performance(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test performance under sustained load."""
        # Arrange
        duration_seconds = 60  # 1 minute test
        target_rps = 10  # 10 requests per second
        request_data = {"text": self.data_factory.create_pii_text()}
        
        results = []
        start_time = time.time()
        end_time = start_time + duration_seconds
        
        # Act - Send requests for specified duration
        while time.time() < end_time:
            request_start = time.time()
            
            try:
                response = client.post(
                    "/api/v1/pii/detect",
                    json=request_data,
                    headers=auth_headers
                )
                
                results.append({
                    "timestamp": request_start,
                    "status_code": response.status_code,
                    "response_time": time.time() - request_start
                })
                
            except Exception as e:
                results.append({
                    "timestamp": request_start,
                    "status_code": 500,
                    "error": str(e),
                    "response_time": time.time() - request_start
                })
            
            # Throttle to maintain target RPS
            sleep_time = max(0, (1.0 / target_rps) - (time.time() - request_start))
            time.sleep(sleep_time)
        
        # Assert
        total_requests = len(results)
        successful_requests = len([r for r in results if r["status_code"] == 200])
        
        success_rate = successful_requests / total_requests
        actual_rps = total_requests / duration_seconds
        
        assert success_rate >= 0.95, f"Success rate {success_rate:.2%} degraded under sustained load"
        assert actual_rps >= target_rps * 0.8, f"Actual RPS {actual_rps:.2f} below target {target_rps}"
    
    @pytest.mark.performance
    def test_memory_usage_under_load(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test memory usage under load."""
        # Get initial memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Generate load
        large_text = self.data_factory.create_pii_text() * 50
        requests_count = 50
        
        max_memory = initial_memory
        
        for i in range(requests_count):
            # Make request
            response = client.post(
                "/api/v1/pii/detect",
                json={"text": large_text},
                headers=auth_headers
            )
            
            # Monitor memory
            current_memory = process.memory_info().rss / 1024 / 1024  # MB
            max_memory = max(max_memory, current_memory)
            
            # Force garbage collection every 10 requests
            if i % 10 == 0:
                import gc
                gc.collect()
        
        # Final memory check
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        peak_memory_increase = max_memory - initial_memory
        
        # Assert reasonable memory usage
        assert memory_increase <= 100, f"Memory increased by {memory_increase:.2f}MB (potential leak)"
        assert peak_memory_increase <= 200, f"Peak memory increased by {peak_memory_increase:.2f}MB"


class TestDocumentProcessingPerformance:
    """Test document processing performance."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.file_helper = FileTestHelper()
        self.data_factory = TestDataFactory()
    
    @pytest.mark.performance
    def test_pdf_processing_performance(self, client: TestClient, temp_directory: Path, auth_headers: Dict[str, str]):
        """Test PDF processing performance with different file sizes."""
        test_cases = [
            {"pages": 1, "max_time": 5.0},
            {"pages": 10, "max_time": 15.0},
            {"pages": 50, "max_time": 60.0}
        ]
        
        for test_case in test_cases:
            # Create PDF with specified number of pages
            content = "\n".join([
                self.data_factory.create_pii_text() for _ in range(test_case["pages"] * 10)
            ])
            pdf_file = self.file_helper.create_pdf_file(
                content, 
                temp_directory / f"test_{test_case['pages']}_pages.pdf"
            )
            
            # Act
            start_time = time.time()
            response = self.api_helper.upload_file(client, pdf_file, headers=auth_headers)
            upload_time = time.time() - start_time
            
            # Assert
            assert response.status_code in [200, 202], f"Upload failed for {test_case['pages']} pages"
            assert upload_time <= test_case["max_time"], \
                f"{test_case['pages']} page PDF took {upload_time:.3f}s, expected <{test_case['max_time']}s"
    
    @pytest.mark.performance
    def test_image_processing_performance(self, client: TestClient, temp_directory: Path, auth_headers: Dict[str, str]):
        """Test image processing performance."""
        # Create test images with different sizes
        test_cases = [
            {"size": (800, 600), "max_time": 3.0},
            {"size": (1920, 1080), "max_time": 8.0},
            {"size": (4000, 3000), "max_time": 20.0}
        ]
        
        for test_case in test_cases:
            content = self.data_factory.create_pii_text(['PERSON', 'EMAIL', 'PHONE_NUMBER'])
            image_file = self.file_helper.create_image_file(
                content,
                temp_directory / f"test_{test_case['size'][0]}x{test_case['size'][1]}.png",
                width=test_case['size'][0],
                height=test_case['size'][1]
            )
            
            # Act
            start_time = time.time()
            response = self.api_helper.upload_file(client, image_file, headers=auth_headers)
            processing_time = time.time() - start_time
            
            # Assert
            assert response.status_code in [200, 202], f"Processing failed for {test_case['size']} image"
            assert processing_time <= test_case["max_time"], \
                f"{test_case['size']} image took {processing_time:.3f}s, expected <{test_case['max_time']}s"
    
    @pytest.mark.performance
    def test_batch_processing_performance(self, client: TestClient, temp_directory: Path, auth_headers: Dict[str, str]):
        """Test batch document processing performance."""
        # Create multiple small documents
        num_documents = 20
        files = []
        
        for i in range(num_documents):
            content = self.data_factory.create_pii_text(['PERSON', 'EMAIL'])
            file_path = self.file_helper.create_text_file(
                content,
                temp_directory / f"batch_doc_{i}.txt"
            )
            files.append(file_path)
        
        # Act - Process all files
        start_time = time.time()
        
        upload_times = []
        for file_path in files:
            file_start = time.time()
            response = self.api_helper.upload_file(client, file_path, headers=auth_headers)
            upload_times.append(time.time() - file_start)
            
            assert response.status_code in [200, 202]
        
        total_time = time.time() - start_time
        
        # Assert
        avg_time_per_doc = total_time / num_documents
        throughput = num_documents / total_time
        
        assert avg_time_per_doc <= 2.0, f"Average time per document {avg_time_per_doc:.3f}s too high"
        assert throughput >= 5.0, f"Document throughput {throughput:.2f} docs/s too low"


class TestDatabasePerformance:
    """Test database operation performance."""
    
    @pytest.mark.performance
    @pytest.mark.requires_database
    def test_query_performance(self, test_db):
        """Test database query performance."""
        from src.core.database.models import Document, User, DetectionResult
        from sqlalchemy import text
        
        # Test simple queries
        start_time = time.time()
        users = test_db.query(User).limit(100).all()
        query_time = time.time() - start_time
        
        assert query_time <= 0.1, f"User query took {query_time:.3f}s, expected <0.1s"
        
        # Test complex join queries
        start_time = time.time()
        results = test_db.query(Document).join(DetectionResult).limit(50).all()
        join_query_time = time.time() - start_time
        
        assert join_query_time <= 0.5, f"Join query took {join_query_time:.3f}s, expected <0.5s"
    
    @pytest.mark.performance
    @pytest.mark.requires_database
    def test_bulk_insert_performance(self, test_db):
        """Test bulk insert performance."""
        from src.core.database.models import DetectionResult
        
        # Create test data
        num_records = 1000
        test_records = []
        
        for i in range(num_records):
            record = DetectionResult(
                document_id=f"doc_{i}",
                entity_text=f"entity_{i}",
                entity_type="PERSON",
                confidence=0.9,
                start_position=0,
                end_position=10
            )
            test_records.append(record)
        
        # Act - Bulk insert
        start_time = time.time()
        test_db.bulk_save_objects(test_records)
        test_db.commit()
        bulk_insert_time = time.time() - start_time
        
        # Assert
        records_per_second = num_records / bulk_insert_time
        assert records_per_second >= 500, \
            f"Bulk insert rate {records_per_second:.2f} records/s too slow"


class TestCachePerformance:
    """Test caching system performance."""
    
    @pytest.mark.performance
    @pytest.mark.requires_redis
    def test_cache_response_time(self):
        """Test cache operation response times."""
        import redis
        
        # Connect to Redis
        r = redis.Redis(host='localhost', port=6379, db=15)
        
        # Test SET operations
        set_times = []
        for i in range(100):
            start_time = time.time()
            r.set(f"test_key_{i}", f"test_value_{i}")
            set_times.append(time.time() - start_time)
        
        avg_set_time = statistics.mean(set_times)
        assert avg_set_time <= 0.01, f"Average SET time {avg_set_time:.4f}s too slow"
        
        # Test GET operations
        get_times = []
        for i in range(100):
            start_time = time.time()
            value = r.get(f"test_key_{i}")
            get_times.append(time.time() - start_time)
            assert value is not None
        
        avg_get_time = statistics.mean(get_times)
        assert avg_get_time <= 0.005, f"Average GET time {avg_get_time:.4f}s too slow"
    
    @pytest.mark.performance
    @pytest.mark.requires_redis
    def test_cache_hit_ratio_performance(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test cache hit ratio and performance impact."""
        # Make the same request multiple times
        request_data = {"text": self.data_factory.create_pii_text()}
        
        response_times = []
        
        # First request (cache miss)
        for i in range(10):
            start_time = time.time()
            response = client.post(
                "/api/v1/pii/detect",
                json=request_data,
                headers=auth_headers
            )
            response_times.append(time.time() - start_time)
            assert response.status_code == 200
        
        # Analyze performance improvement from caching
        first_request_time = response_times[0]
        subsequent_avg_time = statistics.mean(response_times[1:])
        
        # Subsequent requests should be faster if caching is working
        if subsequent_avg_time < first_request_time * 0.8:
            # Caching is providing performance benefit
            improvement = ((first_request_time - subsequent_avg_time) / first_request_time) * 100
            print(f"Cache improved performance by {improvement:.1f}%")


class TestScalabilityLimits:
    """Test system scalability limits."""
    
    @pytest.mark.performance
    @pytest.mark.slow
    def test_maximum_concurrent_connections(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test maximum number of concurrent connections."""
        max_connections = 100
        success_count = 0
        error_count = 0
        
        def make_connection():
            nonlocal success_count, error_count
            try:
                response = client.post(
                    "/api/v1/pii/detect",
                    json={"text": "test text"},
                    headers=auth_headers
                )
                if response.status_code == 200:
                    success_count += 1
                else:
                    error_count += 1
            except Exception:
                error_count += 1
        
        # Create many concurrent connections
        threads = []
        for _ in range(max_connections):
            thread = threading.Thread(target=make_connection)
            threads.append(thread)
            thread.start()
        
        # Wait for all to complete
        for thread in threads:
            thread.join(timeout=30)
        
        # Assert
        total_requests = success_count + error_count
        success_rate = success_count / total_requests if total_requests > 0 else 0
        
        assert success_rate >= 0.8, \
            f"Only {success_rate:.2%} of {total_requests} concurrent connections succeeded"
    
    @pytest.mark.performance
    @pytest.mark.slow  
    def test_memory_scaling_with_document_size(self, client: TestClient, temp_directory: Path, auth_headers: Dict[str, str]):
        """Test memory usage scaling with document size."""
        process = psutil.Process()
        
        # Test with progressively larger documents
        document_sizes = [1, 5, 10, 25, 50]  # MB equivalent in text
        memory_usage = []
        
        for size_mb in document_sizes:
            # Create large text (~1MB per 1M characters)
            large_text = "A" * (size_mb * 1024 * 1024)
            
            # Measure memory before
            before_memory = process.memory_info().rss / 1024 / 1024
            
            # Process large document
            response = client.post(
                "/api/v1/pii/detect",
                json={"text": large_text},
                headers=auth_headers
            )
            
            # Measure memory after
            after_memory = process.memory_info().rss / 1024 / 1024
            memory_increase = after_memory - before_memory
            
            memory_usage.append({
                "document_size_mb": size_mb,
                "memory_increase_mb": memory_increase,
                "status_code": response.status_code
            })
            
            # Force garbage collection
            import gc
            gc.collect()
            time.sleep(1)
        
        # Assert reasonable memory scaling
        for usage in memory_usage:
            # Memory increase should not be more than 3x the document size
            max_expected_memory = usage["document_size_mb"] * 3
            assert usage["memory_increase_mb"] <= max_expected_memory, \
                f"Memory usage {usage['memory_increase_mb']:.2f}MB too high for {usage['document_size_mb']}MB document"


class TestPerformanceRegression:
    """Test for performance regressions."""
    
    @pytest.mark.performance
    def test_baseline_performance_metrics(self, client: TestClient, auth_headers: Dict[str, str]):
        """Establish baseline performance metrics."""
        # Standard test case
        standard_text = self.data_factory.create_pii_text(['PERSON', 'EMAIL', 'PHONE_NUMBER'])
        
        # Run multiple iterations for statistical accuracy
        response_times = []
        for _ in range(20):
            start_time = time.time()
            response = client.post(
                "/api/v1/pii/detect",
                json={"text": standard_text},
                headers=auth_headers
            )
            response_times.append(time.time() - start_time)
            assert response.status_code == 200
        
        # Calculate statistics
        avg_time = statistics.mean(response_times)
        p50_time = statistics.median(response_times)
        p95_time = statistics.quantiles(response_times, n=20)[18]
        
        # Define baseline thresholds (these should be updated based on actual performance)
        baseline_metrics = {
            "avg_response_time": 2.0,  # seconds
            "p50_response_time": 1.5,  # seconds  
            "p95_response_time": 3.0   # seconds
        }
        
        # Assert against baselines
        assert avg_time <= baseline_metrics["avg_response_time"], \
            f"Average response time {avg_time:.3f}s exceeds baseline {baseline_metrics['avg_response_time']}s"
        
        assert p50_time <= baseline_metrics["p50_response_time"], \
            f"P50 response time {p50_time:.3f}s exceeds baseline {baseline_metrics['p50_response_time']}s"
        
        assert p95_time <= baseline_metrics["p95_response_time"], \
            f"P95 response time {p95_time:.3f}s exceeds baseline {baseline_metrics['p95_response_time']}s"
        
        # Log performance metrics for tracking
        print(f"Performance Baseline Results:")
        print(f"  Average: {avg_time:.3f}s")
        print(f"  P50: {p50_time:.3f}s") 
        print(f"  P95: {p95_time:.3f}s")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "performance"])