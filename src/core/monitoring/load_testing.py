"""
Automated Load Testing Framework

Comprehensive performance testing system with continuous performance testing,
performance regression testing, and scalability analysis. This implements
Phase 8.6: Load Testing & Benchmarking.
"""

import asyncio
import logging
import time
import aiohttp
import json
import statistics
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Callable, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import aiosqlite
import numpy as np
import concurrent.futures
import threading
import queue
import multiprocessing
from pathlib import Path
import yaml
import random

from .tracing import get_tracer, SpanKind
from .performance_profiler import get_profiler

logger = logging.getLogger(__name__)


class LoadTestType(Enum):
    """Types of load tests."""
    STRESS = "stress"          # Find breaking point
    LOAD = "load"              # Normal expected load
    VOLUME = "volume"          # Large amounts of data
    SPIKE = "spike"            # Sudden load increases
    ENDURANCE = "endurance"    # Extended periods
    SCALABILITY = "scalability" # Performance vs resources
    BASELINE = "baseline"      # Performance baseline establishment


class TestStatus(Enum):
    """Load test status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class LoadPattern(Enum):
    """Load generation patterns."""
    CONSTANT = "constant"      # Steady load
    RAMP_UP = "ramp_up"       # Gradual increase
    RAMP_DOWN = "ramp_down"   # Gradual decrease
    STEP = "step"             # Step increases
    SPIKE = "spike"           # Sudden spikes
    WAVE = "wave"             # Sinusoidal pattern
    RANDOM = "random"         # Random variations


@dataclass
class LoadTestConfig:
    """Load test configuration."""
    test_name: str
    test_type: LoadTestType
    target_url: str
    duration_seconds: int
    
    # Load parameters
    concurrent_users: int = 10
    requests_per_second: float = 10.0
    load_pattern: LoadPattern = LoadPattern.CONSTANT
    ramp_up_time: int = 60
    ramp_down_time: int = 60
    
    # Request configuration
    http_method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    payload: Optional[Dict[str, Any]] = None
    timeout_seconds: int = 30
    
    # Test data
    test_data_file: Optional[str] = None
    test_data: List[Dict[str, Any]] = field(default_factory=list)
    
    # Thresholds
    max_response_time_ms: float = 1000.0
    max_error_rate_percent: float = 5.0
    min_throughput_rps: float = 1.0
    
    # Advanced options
    think_time_ms: int = 0
    connection_pool_size: int = 100
    keep_alive: bool = True
    verify_ssl: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'test_name': self.test_name,
            'test_type': self.test_type.value,
            'target_url': self.target_url,
            'duration_seconds': self.duration_seconds,
            'concurrent_users': self.concurrent_users,
            'requests_per_second': self.requests_per_second,
            'load_pattern': self.load_pattern.value,
            'ramp_up_time': self.ramp_up_time,
            'ramp_down_time': self.ramp_down_time,
            'http_method': self.http_method,
            'headers': self.headers,
            'payload': self.payload,
            'timeout_seconds': self.timeout_seconds,
            'max_response_time_ms': self.max_response_time_ms,
            'max_error_rate_percent': self.max_error_rate_percent,
            'min_throughput_rps': self.min_throughput_rps,
            'think_time_ms': self.think_time_ms,
            'connection_pool_size': self.connection_pool_size,
            'keep_alive': self.keep_alive,
            'verify_ssl': self.verify_ssl
        }


@dataclass
class RequestResult:
    """Individual request result."""
    timestamp: datetime
    response_time_ms: float
    status_code: int
    success: bool
    error_message: Optional[str] = None
    response_size_bytes: int = 0
    request_size_bytes: int = 0


@dataclass
class LoadTestMetrics:
    """Load test performance metrics."""
    timestamp: datetime
    concurrent_users: int
    requests_per_second: float
    response_time_avg_ms: float
    response_time_min_ms: float
    response_time_max_ms: float
    response_time_p50_ms: float
    response_time_p95_ms: float
    response_time_p99_ms: float
    throughput_rps: float
    error_rate_percent: float
    errors_count: int
    total_requests: int
    bytes_received: int = 0
    bytes_sent: int = 0
    active_connections: int = 0


@dataclass
class LoadTestResult:
    """Complete load test results."""
    test_id: str
    config: LoadTestConfig
    status: TestStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_actual_seconds: Optional[float] = None
    
    # Summary metrics
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    average_response_time_ms: float = 0.0
    p95_response_time_ms: float = 0.0
    p99_response_time_ms: float = 0.0
    max_response_time_ms: float = 0.0
    min_response_time_ms: float = float('inf')
    throughput_rps: float = 0.0
    error_rate_percent: float = 0.0
    
    # Detailed results
    metrics_timeline: List[LoadTestMetrics] = field(default_factory=list)
    error_distribution: Dict[str, int] = field(default_factory=dict)
    response_time_distribution: List[float] = field(default_factory=list)
    
    # Analysis results
    performance_score: float = 0.0
    bottlenecks_detected: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Comparison data
    baseline_comparison: Optional[Dict[str, Any]] = None
    regression_detected: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'test_id': self.test_id,
            'config': self.config.to_dict(),
            'status': self.status.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_actual_seconds': self.duration_actual_seconds,
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'average_response_time_ms': self.average_response_time_ms,
            'p95_response_time_ms': self.p95_response_time_ms,
            'p99_response_time_ms': self.p99_response_time_ms,
            'max_response_time_ms': self.max_response_time_ms,
            'min_response_time_ms': self.min_response_time_ms,
            'throughput_rps': self.throughput_rps,
            'error_rate_percent': self.error_rate_percent,
            'performance_score': self.performance_score,
            'bottlenecks_detected': self.bottlenecks_detected,
            'recommendations': self.recommendations,
            'regression_detected': self.regression_detected,
            'baseline_comparison': self.baseline_comparison
        }


class LoadGenerator:
    """Generates load according to specified patterns."""
    
    def __init__(self, config: LoadTestConfig):
        self.config = config
        self.running = False
        self.start_time: Optional[datetime] = None
        self.results_queue = queue.Queue()
        self.metrics_queue = queue.Queue()
        self.active_sessions = 0
        self.session_lock = threading.Lock()
    
    async def generate_load(self, result_callback: Callable[[RequestResult], None],
                          metrics_callback: Callable[[LoadTestMetrics], None]):
        """Generate load according to the configuration."""
        self.running = True
        self.start_time = datetime.now(timezone.utc)
        
        try:
            # Create HTTP session with connection pooling
            connector = aiohttp.TCPConnector(
                limit=self.config.connection_pool_size,
                keepalive_timeout=30,
                enable_cleanup_closed=True
            )
            
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=self.config.headers
            )
            
            # Start metrics collection task
            metrics_task = asyncio.create_task(self._collect_metrics(metrics_callback))
            
            # Generate load based on pattern
            if self.config.load_pattern == LoadPattern.CONSTANT:
                await self._generate_constant_load(session, result_callback)
            elif self.config.load_pattern == LoadPattern.RAMP_UP:
                await self._generate_ramp_up_load(session, result_callback)
            elif self.config.load_pattern == LoadPattern.STEP:
                await self._generate_step_load(session, result_callback)
            elif self.config.load_pattern == LoadPattern.SPIKE:
                await self._generate_spike_load(session, result_callback)
            elif self.config.load_pattern == LoadPattern.WAVE:
                await self._generate_wave_load(session, result_callback)
            else:
                await self._generate_constant_load(session, result_callback)
            
            # Stop metrics collection
            metrics_task.cancel()
            try:
                await metrics_task
            except asyncio.CancelledError:
                pass
            
            await session.close()
            
        except Exception as e:
            logger.error(f"Error generating load: {e}")
        finally:
            self.running = False
    
    async def _generate_constant_load(self, session: aiohttp.ClientSession,
                                    result_callback: Callable[[RequestResult], None]):
        """Generate constant load."""
        end_time = self.start_time + timedelta(seconds=self.config.duration_seconds)
        
        # Calculate delay between requests for target RPS
        delay_between_requests = 1.0 / self.config.requests_per_second if self.config.requests_per_second > 0 else 0.1
        
        tasks = []
        last_request_time = time.time()
        
        while datetime.now(timezone.utc) < end_time and self.running:
            current_time = time.time()
            
            # Maintain target RPS
            if current_time - last_request_time >= delay_between_requests:
                # Limit concurrent requests
                if len(tasks) < self.config.concurrent_users:
                    task = asyncio.create_task(self._make_request(session, result_callback))
                    tasks.append(task)
                    last_request_time = current_time
            
            # Clean up completed tasks
            tasks = [task for task in tasks if not task.done()]
            
            # Small delay to prevent tight loop
            await asyncio.sleep(0.01)
        
        # Wait for all tasks to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _generate_ramp_up_load(self, session: aiohttp.ClientSession,
                                   result_callback: Callable[[RequestResult], None]):
        """Generate ramping up load."""
        ramp_up_end = self.start_time + timedelta(seconds=self.config.ramp_up_time)
        steady_end = ramp_up_end + timedelta(seconds=self.config.duration_seconds - self.config.ramp_up_time - self.config.ramp_down_time)
        final_end = steady_end + timedelta(seconds=self.config.ramp_down_time)
        
        tasks = []
        
        while datetime.now(timezone.utc) < final_end and self.running:
            current_time = datetime.now(timezone.utc)
            
            # Calculate current target load
            if current_time < ramp_up_end:
                # Ramp up phase
                progress = (current_time - self.start_time).total_seconds() / self.config.ramp_up_time
                current_rps = self.config.requests_per_second * progress
                current_users = int(self.config.concurrent_users * progress)
            elif current_time < steady_end:
                # Steady state
                current_rps = self.config.requests_per_second
                current_users = self.config.concurrent_users
            else:
                # Ramp down phase
                remaining_time = (final_end - current_time).total_seconds()
                progress = remaining_time / self.config.ramp_down_time
                current_rps = self.config.requests_per_second * progress
                current_users = int(self.config.concurrent_users * progress)
            
            # Generate load at current rate
            delay_between_requests = 1.0 / max(current_rps, 0.1)
            
            if len(tasks) < current_users and time.time() % delay_between_requests < 0.1:
                task = asyncio.create_task(self._make_request(session, result_callback))
                tasks.append(task)
            
            # Clean up completed tasks
            tasks = [task for task in tasks if not task.done()]
            
            await asyncio.sleep(0.01)
        
        # Wait for all tasks to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _generate_step_load(self, session: aiohttp.ClientSession,
                                result_callback: Callable[[RequestResult], None]):
        """Generate step load increases."""
        steps = 5
        step_duration = self.config.duration_seconds // steps
        
        for step in range(steps):
            step_start = self.start_time + timedelta(seconds=step * step_duration)
            step_end = step_start + timedelta(seconds=step_duration)
            
            # Increase load at each step
            current_rps = self.config.requests_per_second * (step + 1) / steps
            current_users = int(self.config.concurrent_users * (step + 1) / steps)
            
            tasks = []
            delay_between_requests = 1.0 / max(current_rps, 0.1)
            last_request_time = time.time()
            
            while datetime.now(timezone.utc) < step_end and self.running:
                current_time = time.time()
                
                if current_time - last_request_time >= delay_between_requests:
                    if len(tasks) < current_users:
                        task = asyncio.create_task(self._make_request(session, result_callback))
                        tasks.append(task)
                        last_request_time = current_time
                
                tasks = [task for task in tasks if not task.done()]
                await asyncio.sleep(0.01)
            
            # Wait for step tasks to complete
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _generate_spike_load(self, session: aiohttp.ClientSession,
                                 result_callback: Callable[[RequestResult], None]):
        """Generate spike load pattern."""
        normal_duration = self.config.duration_seconds * 0.8
        spike_duration = self.config.duration_seconds * 0.2
        
        # Normal load phase
        normal_end = self.start_time + timedelta(seconds=normal_duration)
        tasks = []
        delay_between_requests = 1.0 / self.config.requests_per_second
        last_request_time = time.time()
        
        while datetime.now(timezone.utc) < normal_end and self.running:
            current_time = time.time()
            
            if current_time - last_request_time >= delay_between_requests:
                if len(tasks) < self.config.concurrent_users:
                    task = asyncio.create_task(self._make_request(session, result_callback))
                    tasks.append(task)
                    last_request_time = current_time
            
            tasks = [task for task in tasks if not task.done()]
            await asyncio.sleep(0.01)
        
        # Spike phase - 5x normal load
        spike_end = normal_end + timedelta(seconds=spike_duration)
        spike_rps = self.config.requests_per_second * 5
        spike_users = self.config.concurrent_users * 3
        spike_delay = 1.0 / spike_rps
        
        while datetime.now(timezone.utc) < spike_end and self.running:
            current_time = time.time()
            
            if current_time - last_request_time >= spike_delay:
                if len(tasks) < spike_users:
                    task = asyncio.create_task(self._make_request(session, result_callback))
                    tasks.append(task)
                    last_request_time = current_time
            
            tasks = [task for task in tasks if not task.done()]
            await asyncio.sleep(0.001)  # Faster loop for spikes
        
        # Wait for all tasks to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _generate_wave_load(self, session: aiohttp.ClientSession,
                                result_callback: Callable[[RequestResult], None]):
        """Generate sinusoidal wave load pattern."""
        end_time = self.start_time + timedelta(seconds=self.config.duration_seconds)
        tasks = []
        
        while datetime.now(timezone.utc) < end_time and self.running:
            current_time = datetime.now(timezone.utc)
            elapsed_seconds = (current_time - self.start_time).total_seconds()
            
            # Sinusoidal variation (2 cycles over duration)
            wave_factor = 0.5 + 0.5 * np.sin(2 * np.pi * elapsed_seconds / (self.config.duration_seconds / 2))
            current_rps = self.config.requests_per_second * wave_factor
            current_users = int(self.config.concurrent_users * wave_factor)
            
            delay_between_requests = 1.0 / max(current_rps, 0.1)
            
            if len(tasks) < current_users and time.time() % delay_between_requests < 0.1:
                task = asyncio.create_task(self._make_request(session, result_callback))
                tasks.append(task)
            
            tasks = [task for task in tasks if not task.done()]
            await asyncio.sleep(0.01)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _make_request(self, session: aiohttp.ClientSession,
                          result_callback: Callable[[RequestResult], None]):
        """Make a single HTTP request."""
        start_time = time.time()
        timestamp = datetime.now(timezone.utc)
        
        # Increment active sessions
        with self.session_lock:
            self.active_sessions += 1
        
        try:
            # Get test data if available
            test_data = {}
            if self.config.test_data:
                test_data = random.choice(self.config.test_data)
            
            # Prepare request
            url = self.config.target_url
            method = self.config.http_method.upper()
            
            # Add test data to URL or payload
            if method == 'GET' and test_data:
                url += '?' + '&'.join(f"{k}={v}" for k, v in test_data.items())
                payload = None
                request_size = len(url.encode())
            else:
                payload = self.config.payload or test_data
                request_size = len(json.dumps(payload).encode()) if payload else 0
            
            # Add think time
            if self.config.think_time_ms > 0:
                await asyncio.sleep(self.config.think_time_ms / 1000.0)
            
            # Make request
            async with session.request(
                method=method,
                url=url,
                json=payload if method != 'GET' else None,
                ssl=self.config.verify_ssl
            ) as response:
                response_content = await response.read()
                response_size = len(response_content)
                
                end_time = time.time()
                response_time_ms = (end_time - start_time) * 1000
                
                success = 200 <= response.status < 400
                error_message = None if success else f"HTTP {response.status}"
                
                result = RequestResult(
                    timestamp=timestamp,
                    response_time_ms=response_time_ms,
                    status_code=response.status,
                    success=success,
                    error_message=error_message,
                    response_size_bytes=response_size,
                    request_size_bytes=request_size
                )
                
                result_callback(result)
        
        except Exception as e:
            end_time = time.time()
            response_time_ms = (end_time - start_time) * 1000
            
            result = RequestResult(
                timestamp=timestamp,
                response_time_ms=response_time_ms,
                status_code=0,
                success=False,
                error_message=str(e)
            )
            
            result_callback(result)
        
        finally:
            # Decrement active sessions
            with self.session_lock:
                self.active_sessions -= 1
    
    async def _collect_metrics(self, metrics_callback: Callable[[LoadTestMetrics], None]):
        """Collect and report metrics during load test."""
        metrics_buffer = deque(maxlen=1000)
        
        while self.running:
            try:
                # Collect metrics every second
                await asyncio.sleep(1.0)
                
                current_time = datetime.now(timezone.utc)
                
                # Collect recent results
                recent_results = []
                while not self.results_queue.empty():
                    try:
                        result = self.results_queue.get_nowait()
                        recent_results.append(result)
                        metrics_buffer.append(result)
                    except queue.Empty:
                        break
                
                if not metrics_buffer:
                    continue
                
                # Calculate metrics for the last minute
                one_minute_ago = current_time - timedelta(minutes=1)
                recent_buffer = [r for r in metrics_buffer if r.timestamp > one_minute_ago]
                
                if not recent_buffer:
                    continue
                
                # Calculate metrics
                response_times = [r.response_time_ms for r in recent_buffer]
                successful_requests = sum(1 for r in recent_buffer if r.success)
                total_requests = len(recent_buffer)
                error_count = total_requests - successful_requests
                
                metrics = LoadTestMetrics(
                    timestamp=current_time,
                    concurrent_users=self.active_sessions,
                    requests_per_second=total_requests,  # Requests in last minute
                    response_time_avg_ms=statistics.mean(response_times),
                    response_time_min_ms=min(response_times),
                    response_time_max_ms=max(response_times),
                    response_time_p50_ms=sorted(response_times)[int(0.5 * len(response_times))],
                    response_time_p95_ms=sorted(response_times)[int(0.95 * len(response_times))],
                    response_time_p99_ms=sorted(response_times)[int(0.99 * len(response_times))],
                    throughput_rps=successful_requests,
                    error_rate_percent=(error_count / total_requests * 100) if total_requests > 0 else 0,
                    errors_count=error_count,
                    total_requests=total_requests,
                    bytes_received=sum(r.response_size_bytes for r in recent_buffer),
                    bytes_sent=sum(r.request_size_bytes for r in recent_buffer),
                    active_connections=self.active_sessions
                )
                
                metrics_callback(metrics)
                
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")


class PerformanceAnalyzer:
    """Analyzes load test results and detects performance issues."""
    
    def __init__(self):
        self.baseline_results: Dict[str, LoadTestResult] = {}
    
    def analyze_results(self, result: LoadTestResult) -> LoadTestResult:
        """Analyze load test results and generate insights."""
        try:
            # Calculate performance score
            result.performance_score = self._calculate_performance_score(result)
            
            # Detect bottlenecks
            result.bottlenecks_detected = self._detect_bottlenecks(result)
            
            # Generate recommendations
            result.recommendations = self._generate_recommendations(result)
            
            # Compare with baseline if available
            baseline_key = f"{result.config.test_type.value}_{result.config.target_url}"
            if baseline_key in self.baseline_results:
                result.baseline_comparison = self._compare_with_baseline(result, self.baseline_results[baseline_key])
                result.regression_detected = self._detect_regression(result, self.baseline_results[baseline_key])
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing results: {e}")
            return result
    
    def _calculate_performance_score(self, result: LoadTestResult) -> float:
        """Calculate overall performance score (0-100)."""
        score = 100.0
        
        # Deduct points for high response times
        if result.average_response_time_ms > result.config.max_response_time_ms:
            excess = result.average_response_time_ms - result.config.max_response_time_ms
            score -= min(30, excess / result.config.max_response_time_ms * 100)
        
        # Deduct points for high error rate
        if result.error_rate_percent > result.config.max_error_rate_percent:
            excess = result.error_rate_percent - result.config.max_error_rate_percent
            score -= min(40, excess * 2)
        
        # Deduct points for low throughput
        if result.throughput_rps < result.config.min_throughput_rps:
            deficit = result.config.min_throughput_rps - result.throughput_rps
            score -= min(20, deficit / result.config.min_throughput_rps * 100)
        
        # Deduct points for high P95/P99 response times
        if result.p95_response_time_ms > result.config.max_response_time_ms * 2:
            score -= 10
        
        if result.p99_response_time_ms > result.config.max_response_time_ms * 3:
            score -= 10
        
        return max(0, score)
    
    def _detect_bottlenecks(self, result: LoadTestResult) -> List[str]:
        """Detect performance bottlenecks."""
        bottlenecks = []
        
        # High response time bottleneck
        if result.average_response_time_ms > result.config.max_response_time_ms:
            bottlenecks.append("High average response time")
        
        # High error rate bottleneck
        if result.error_rate_percent > result.config.max_error_rate_percent:
            bottlenecks.append("High error rate")
        
        # Low throughput bottleneck
        if result.throughput_rps < result.config.min_throughput_rps:
            bottlenecks.append("Low throughput")
        
        # Response time variance bottleneck
        if result.response_time_distribution:
            std_dev = statistics.stdev(result.response_time_distribution)
            if std_dev > result.average_response_time_ms * 0.5:
                bottlenecks.append("High response time variance")
        
        # P95/P99 bottleneck
        if result.p95_response_time_ms > result.average_response_time_ms * 2:
            bottlenecks.append("High P95 response time")
        
        if result.p99_response_time_ms > result.p95_response_time_ms * 2:
            bottlenecks.append("High P99 response time")
        
        return bottlenecks
    
    def _generate_recommendations(self, result: LoadTestResult) -> List[str]:
        """Generate performance improvement recommendations."""
        recommendations = []
        
        if "High average response time" in result.bottlenecks_detected:
            recommendations.extend([
                "Optimize database queries and add appropriate indexes",
                "Implement caching for frequently accessed data",
                "Review application code for performance bottlenecks",
                "Consider scaling up server resources"
            ])
        
        if "High error rate" in result.bottlenecks_detected:
            recommendations.extend([
                "Review application logs for error patterns",
                "Implement proper error handling and retries",
                "Check external service dependencies",
                "Verify input validation and data quality"
            ])
        
        if "Low throughput" in result.bottlenecks_detected:
            recommendations.extend([
                "Optimize connection pooling and keep-alive settings",
                "Review thread pool and async processing configuration",
                "Consider horizontal scaling with load balancing",
                "Optimize serialization and data processing"
            ])
        
        if "High response time variance" in result.bottlenecks_detected:
            recommendations.extend([
                "Investigate garbage collection and memory management",
                "Review resource contention and locking mechanisms",
                "Optimize async processing and eliminate blocking operations"
            ])
        
        if "High P95 response time" in result.bottlenecks_detected or "High P99 response time" in result.bottlenecks_detected:
            recommendations.extend([
                "Implement request timeout and circuit breaker patterns",
                "Optimize worst-case scenarios and edge cases",
                "Consider request queuing and rate limiting"
            ])
        
        return recommendations
    
    def _compare_with_baseline(self, current: LoadTestResult, baseline: LoadTestResult) -> Dict[str, Any]:
        """Compare current results with baseline."""
        comparison = {
            'baseline_date': baseline.start_time.isoformat(),
            'response_time_change_percent': self._calculate_change_percent(
                baseline.average_response_time_ms, current.average_response_time_ms
            ),
            'throughput_change_percent': self._calculate_change_percent(
                baseline.throughput_rps, current.throughput_rps
            ),
            'error_rate_change_percent': self._calculate_change_percent(
                baseline.error_rate_percent, current.error_rate_percent
            ),
            'p95_change_percent': self._calculate_change_percent(
                baseline.p95_response_time_ms, current.p95_response_time_ms
            ),
            'performance_score_change_percent': self._calculate_change_percent(
                baseline.performance_score, current.performance_score
            )
        }
        
        return comparison
    
    def _detect_regression(self, current: LoadTestResult, baseline: LoadTestResult) -> bool:
        """Detect performance regression."""
        # Response time regression (>20% increase)
        response_time_regression = (current.average_response_time_ms - baseline.average_response_time_ms) / baseline.average_response_time_ms > 0.2
        
        # Throughput regression (>15% decrease)
        throughput_regression = (baseline.throughput_rps - current.throughput_rps) / baseline.throughput_rps > 0.15
        
        # Error rate regression (>50% increase)
        error_rate_regression = current.error_rate_percent > baseline.error_rate_percent * 1.5
        
        # Performance score regression (>10 point decrease)
        score_regression = baseline.performance_score - current.performance_score > 10
        
        return any([response_time_regression, throughput_regression, error_rate_regression, score_regression])
    
    def _calculate_change_percent(self, baseline: float, current: float) -> float:
        """Calculate percentage change."""
        if baseline == 0:
            return 0.0 if current == 0 else float('inf')
        
        return ((current - baseline) / baseline) * 100
    
    def set_baseline(self, result: LoadTestResult):
        """Set a result as baseline for future comparisons."""
        baseline_key = f"{result.config.test_type.value}_{result.config.target_url}"
        self.baseline_results[baseline_key] = result


class LoadTestingFramework:
    """
    Main load testing framework that orchestrates test execution,
    result analysis, and reporting.
    """
    
    def __init__(self, db_path: str = "performance_metrics.db"):
        self.db_path = db_path
        self.analyzer = PerformanceAnalyzer()
        
        # Test management
        self.active_tests: Dict[str, LoadTestResult] = {}
        self.test_history: List[LoadTestResult] = []
        
        # Configuration
        self.enabled = True
        self.max_concurrent_tests = 3
        
        # Scheduled tests
        self.scheduled_tests: List[Tuple[datetime, LoadTestConfig]] = []
        self.scheduler_task: Optional[asyncio.Task] = None
        self.running = False
    
    async def initialize(self):
        """Initialize the load testing framework."""
        await self._create_load_testing_tables()
        logger.info("Load Testing Framework initialized")
    
    async def _create_load_testing_tables(self):
        """Create load testing database tables."""
        async with aiosqlite.connect(self.db_path) as db:
            # Load test configurations
            await db.execute("""
                CREATE TABLE IF NOT EXISTS load_test_configs (
                    id TEXT PRIMARY KEY,
                    test_name TEXT NOT NULL,
                    config_data TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE
                )
            """)
            
            # Load test results
            await db.execute("""
                CREATE TABLE IF NOT EXISTS load_test_results (
                    test_id TEXT PRIMARY KEY,
                    test_name TEXT NOT NULL,
                    test_type TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    status TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    duration_actual_seconds REAL,
                    total_requests INTEGER DEFAULT 0,
                    successful_requests INTEGER DEFAULT 0,
                    failed_requests INTEGER DEFAULT 0,
                    average_response_time_ms REAL DEFAULT 0.0,
                    p95_response_time_ms REAL DEFAULT 0.0,
                    p99_response_time_ms REAL DEFAULT 0.0,
                    throughput_rps REAL DEFAULT 0.0,
                    error_rate_percent REAL DEFAULT 0.0,
                    performance_score REAL DEFAULT 0.0,
                    regression_detected BOOLEAN DEFAULT FALSE,
                    config_data TEXT,
                    results_data TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Load test metrics timeline
            await db.execute("""
                CREATE TABLE IF NOT EXISTS load_test_metrics (
                    id TEXT PRIMARY KEY,
                    test_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    concurrent_users INTEGER,
                    requests_per_second REAL,
                    response_time_avg_ms REAL,
                    response_time_p95_ms REAL,
                    response_time_p99_ms REAL,
                    throughput_rps REAL,
                    error_rate_percent REAL,
                    active_connections INTEGER,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    FOREIGN KEY (test_id) REFERENCES load_test_results(test_id)
                )
            """)
            
            # Scheduled tests
            await db.execute("""
                CREATE TABLE IF NOT EXISTS scheduled_load_tests (
                    id TEXT PRIMARY KEY,
                    test_name TEXT NOT NULL,
                    config_id TEXT NOT NULL,
                    schedule_cron TEXT,
                    next_run_time TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (config_id) REFERENCES load_test_configs(id)
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_load_test_results_name ON load_test_results(test_name, start_time)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_load_test_metrics_test_id ON load_test_metrics(test_id, timestamp)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_scheduled_tests_next_run ON scheduled_load_tests(next_run_time)")
            
            await db.commit()
    
    async def create_test_config(self, config: LoadTestConfig) -> str:
        """Create and store a test configuration."""
        try:
            config_id = str(uuid.uuid4())
            
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO load_test_configs (id, test_name, config_data)
                    VALUES (?, ?, ?)
                """, (config_id, config.test_name, json.dumps(config.to_dict())))
                
                await db.commit()
            
            logger.info(f"Created test configuration: {config.test_name}")
            return config_id
            
        except Exception as e:
            logger.error(f"Error creating test configuration: {e}")
            raise
    
    async def run_test(self, config: LoadTestConfig) -> LoadTestResult:
        """Run a load test."""
        if len(self.active_tests) >= self.max_concurrent_tests:
            raise RuntimeError("Maximum concurrent tests reached")
        
        test_id = str(uuid.uuid4())
        result = LoadTestResult(
            test_id=test_id,
            config=config,
            status=TestStatus.PENDING,
            start_time=datetime.now(timezone.utc)
        )
        
        self.active_tests[test_id] = result
        
        try:
            # Update status to running
            result.status = TestStatus.RUNNING
            await self._update_test_result(result)
            
            logger.info(f"Starting load test: {config.test_name}")
            
            # Create load generator
            generator = LoadGenerator(config)
            
            # Collect results and metrics
            request_results = []
            metrics_timeline = []
            
            def result_callback(req_result: RequestResult):
                request_results.append(req_result)
            
            def metrics_callback(metrics: LoadTestMetrics):
                metrics_timeline.append(metrics)
                asyncio.create_task(self._store_test_metrics(test_id, metrics))
            
            # Start tracing if available
            tracer = get_tracer()
            if tracer:
                trace_context = tracer.start_trace(f"load_test_{config.test_name}")
                span = tracer.start_span(
                    "load_test_execution",
                    kind=SpanKind.CLIENT,
                    tags={
                        'test.name': config.test_name,
                        'test.type': config.test_type.value,
                        'test.target_url': config.target_url,
                        'test.duration': config.duration_seconds,
                        'test.concurrent_users': config.concurrent_users
                    }
                )
            
            # Run load test
            await generator.generate_load(result_callback, metrics_callback)
            
            # Finish tracing
            if tracer and 'span' in locals():
                tracer.finish_span(span)
            
            # Process results
            result.end_time = datetime.now(timezone.utc)
            result.duration_actual_seconds = (result.end_time - result.start_time).total_seconds()
            result.status = TestStatus.COMPLETED
            
            # Calculate summary metrics
            if request_results:
                result.total_requests = len(request_results)
                result.successful_requests = sum(1 for r in request_results if r.success)
                result.failed_requests = result.total_requests - result.successful_requests
                
                response_times = [r.response_time_ms for r in request_results]
                result.response_time_distribution = response_times
                
                result.average_response_time_ms = statistics.mean(response_times)
                result.min_response_time_ms = min(response_times)
                result.max_response_time_ms = max(response_times)
                
                sorted_times = sorted(response_times)
                result.p95_response_time_ms = sorted_times[int(0.95 * len(sorted_times))]
                result.p99_response_time_ms = sorted_times[int(0.99 * len(sorted_times))]
                
                result.throughput_rps = result.successful_requests / result.duration_actual_seconds
                result.error_rate_percent = (result.failed_requests / result.total_requests) * 100
                
                # Error distribution
                error_types = defaultdict(int)
                for req_result in request_results:
                    if not req_result.success and req_result.error_message:
                        error_types[req_result.error_message] += 1
                result.error_distribution = dict(error_types)
            
            result.metrics_timeline = metrics_timeline
            
            # Analyze results
            result = self.analyzer.analyze_results(result)
            
            # Store final results
            await self._update_test_result(result)
            
            logger.info(f"Load test completed: {config.test_name} - Score: {result.performance_score:.1f}")
            
        except Exception as e:
            result.status = TestStatus.FAILED
            result.end_time = datetime.now(timezone.utc)
            await self._update_test_result(result)
            logger.error(f"Load test failed: {config.test_name} - {e}")
            raise
        
        finally:
            # Clean up
            if test_id in self.active_tests:
                del self.active_tests[test_id]
            self.test_history.append(result)
        
        return result
    
    async def _update_test_result(self, result: LoadTestResult):
        """Update test result in database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO load_test_results 
                    (test_id, test_name, test_type, target_url, status, start_time,
                     end_time, duration_actual_seconds, total_requests, successful_requests,
                     failed_requests, average_response_time_ms, p95_response_time_ms,
                     p99_response_time_ms, throughput_rps, error_rate_percent,
                     performance_score, regression_detected, config_data, results_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.test_id,
                    result.config.test_name,
                    result.config.test_type.value,
                    result.config.target_url,
                    result.status.value,
                    result.start_time.isoformat(),
                    result.end_time.isoformat() if result.end_time else None,
                    result.duration_actual_seconds,
                    result.total_requests,
                    result.successful_requests,
                    result.failed_requests,
                    result.average_response_time_ms,
                    result.p95_response_time_ms,
                    result.p99_response_time_ms,
                    result.throughput_rps,
                    result.error_rate_percent,
                    result.performance_score,
                    result.regression_detected,
                    json.dumps(result.config.to_dict()),
                    json.dumps({
                        'bottlenecks_detected': result.bottlenecks_detected,
                        'recommendations': result.recommendations,
                        'baseline_comparison': result.baseline_comparison,
                        'error_distribution': result.error_distribution
                    })
                ))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error updating test result: {e}")
    
    async def _store_test_metrics(self, test_id: str, metrics: LoadTestMetrics):
        """Store test metrics in database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO load_test_metrics 
                    (id, test_id, timestamp, concurrent_users, requests_per_second,
                     response_time_avg_ms, response_time_p95_ms, response_time_p99_ms,
                     throughput_rps, error_rate_percent, active_connections,
                     bytes_sent, bytes_received)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    test_id,
                    metrics.timestamp.isoformat(),
                    metrics.concurrent_users,
                    metrics.requests_per_second,
                    metrics.response_time_avg_ms,
                    metrics.response_time_p95_ms,
                    metrics.response_time_p99_ms,
                    metrics.throughput_rps,
                    metrics.error_rate_percent,
                    metrics.active_connections,
                    metrics.bytes_sent,
                    metrics.bytes_received
                ))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error storing test metrics: {e}")
    
    async def get_test_results(self, test_name: Optional[str] = None, 
                             limit: int = 50) -> List[Dict[str, Any]]:
        """Get test results."""
        try:
            query = """
                SELECT test_id, test_name, test_type, status, start_time, end_time,
                       total_requests, successful_requests, average_response_time_ms,
                       throughput_rps, error_rate_percent, performance_score,
                       regression_detected
                FROM load_test_results
            """
            
            params = []
            if test_name:
                query += " WHERE test_name = ?"
                params.append(test_name)
            
            query += " ORDER BY start_time DESC LIMIT ?"
            params.append(limit)
            
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(query, params)
                rows = await cursor.fetchall()
                
                results = []
                for row in rows:
                    results.append({
                        'test_id': row[0],
                        'test_name': row[1],
                        'test_type': row[2],
                        'status': row[3],
                        'start_time': row[4],
                        'end_time': row[5],
                        'total_requests': row[6],
                        'successful_requests': row[7],
                        'average_response_time_ms': row[8],
                        'throughput_rps': row[9],
                        'error_rate_percent': row[10],
                        'performance_score': row[11],
                        'regression_detected': bool(row[12])
                    })
                
                return results
                
        except Exception as e:
            logger.error(f"Error getting test results: {e}")
            return []
    
    async def get_performance_trends(self, test_name: str, days: int = 30) -> Dict[str, Any]:
        """Get performance trends for a test."""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(days=days)
            
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT start_time, average_response_time_ms, throughput_rps, 
                           error_rate_percent, performance_score
                    FROM load_test_results
                    WHERE test_name = ? AND start_time >= ? AND status = 'completed'
                    ORDER BY start_time
                """, (test_name, cutoff_time.isoformat()))
                
                rows = await cursor.fetchall()
                
                if not rows:
                    return {}
                
                timestamps = [row[0] for row in rows]
                response_times = [row[1] for row in rows]
                throughputs = [row[2] for row in rows]
                error_rates = [row[3] for row in rows]
                performance_scores = [row[4] for row in rows]
                
                return {
                    'test_name': test_name,
                    'time_range_days': days,
                    'data_points': len(rows),
                    'trends': {
                        'timestamps': timestamps,
                        'response_times': response_times,
                        'throughputs': throughputs,
                        'error_rates': error_rates,
                        'performance_scores': performance_scores
                    },
                    'summary': {
                        'avg_response_time': statistics.mean(response_times),
                        'avg_throughput': statistics.mean(throughputs),
                        'avg_error_rate': statistics.mean(error_rates),
                        'avg_performance_score': statistics.mean(performance_scores),
                        'response_time_trend': self._calculate_trend(response_times),
                        'throughput_trend': self._calculate_trend(throughputs),
                        'performance_trend': self._calculate_trend(performance_scores)
                    }
                }
                
        except Exception as e:
            logger.error(f"Error getting performance trends: {e}")
            return {}
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction from values."""
        if len(values) < 2:
            return 'insufficient_data'
        
        # Simple linear regression slope
        x = list(range(len(values)))
        n = len(values)
        
        sum_x = sum(x)
        sum_y = sum(values)
        sum_xy = sum(x[i] * values[i] for i in range(n))
        sum_x2 = sum(x[i] ** 2 for i in range(n))
        
        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x ** 2)
        
        if abs(slope) < 0.01:
            return 'stable'
        elif slope > 0:
            return 'increasing'
        else:
            return 'decreasing'
    
    def set_baseline(self, test_name: str):
        """Set most recent successful test as baseline."""
        # Find most recent successful test
        for result in reversed(self.test_history):
            if (result.config.test_name == test_name and 
                result.status == TestStatus.COMPLETED and
                result.performance_score > 50):  # Reasonable performance score
                
                self.analyzer.set_baseline(result)
                logger.info(f"Set baseline for test '{test_name}' from {result.start_time}")
                break


# Global load testing framework instance
global_load_testing_framework: Optional[LoadTestingFramework] = None


def get_load_testing_framework() -> Optional[LoadTestingFramework]:
    """Get the global load testing framework instance."""
    return global_load_testing_framework


async def initialize_load_testing_framework(db_path: str = "performance_metrics.db") -> LoadTestingFramework:
    """Initialize the global load testing framework."""
    global global_load_testing_framework
    
    framework = LoadTestingFramework(db_path)
    await framework.initialize()
    global_load_testing_framework = framework
    
    return framework