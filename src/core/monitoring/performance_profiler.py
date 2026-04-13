"""
Code-Level Performance Monitoring

Comprehensive code-level performance profiling system that provides
function-level profiling, database query optimization insights,
memory leak detection, and resource contention analysis.
This completes Phase 8.3: APM.
"""

import asyncio
import logging
import time
import threading
import sys
import os
import traceback
import gc
import psutil
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Callable, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from collections import defaultdict, deque
import json
import aiosqlite
import uuid
import cProfile
import pstats
import io
import linecache
import weakref
from contextlib import contextmanager

from .tracing import get_tracer, trace, SpanKind

logger = logging.getLogger(__name__)


class ProfilerType(Enum):
    """Types of profiling available."""
    CPU = "cpu"
    MEMORY = "memory"
    DATABASE = "database"
    IO = "io"
    ASYNC = "async"
    CUSTOM = "custom"


class PerformanceIssueType(Enum):
    """Types of performance issues."""
    SLOW_FUNCTION = "slow_function"
    MEMORY_LEAK = "memory_leak"
    INEFFICIENT_QUERY = "inefficient_query"
    BLOCKING_IO = "blocking_io"
    DEADLOCK = "deadlock"
    HIGH_CPU = "high_cpu"
    EXCESSIVE_ALLOCATIONS = "excessive_allocations"
    RESOURCE_CONTENTION = "resource_contention"


@dataclass
class FunctionProfile:
    """Profile data for a function."""
    function_name: str
    module_name: str
    file_path: str
    line_number: int
    call_count: int = 0
    total_time: float = 0.0
    average_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    memory_usage_bytes: int = 0
    cpu_time: float = 0.0
    last_called: Optional[datetime] = None
    error_count: int = 0
    
    def update(self, execution_time: float, memory_usage: int = 0, cpu_time: float = 0):
        """Update profile with new execution data."""
        self.call_count += 1
        self.total_time += execution_time
        self.average_time = self.total_time / self.call_count
        self.min_time = min(self.min_time, execution_time)
        self.max_time = max(self.max_time, execution_time)
        self.memory_usage_bytes += memory_usage
        self.cpu_time += cpu_time
        self.last_called = datetime.now(timezone.utc)
    
    def record_error(self):
        """Record an error in this function."""
        self.error_count += 1


@dataclass
class DatabaseQueryProfile:
    """Profile data for database queries."""
    query_hash: str
    query_template: str
    query_type: str  # SELECT, INSERT, UPDATE, DELETE
    call_count: int = 0
    total_time: float = 0.0
    average_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    rows_examined: int = 0
    rows_returned: int = 0
    table_names: List[str] = field(default_factory=list)
    index_usage: Dict[str, int] = field(default_factory=dict)
    lock_time: float = 0.0
    last_executed: Optional[datetime] = None
    slow_query_count: int = 0
    
    def update(self, execution_time: float, rows_examined: int = 0, rows_returned: int = 0):
        """Update query profile with execution data."""
        self.call_count += 1
        self.total_time += execution_time
        self.average_time = self.total_time / self.call_count
        self.min_time = min(self.min_time, execution_time)
        self.max_time = max(self.max_time, execution_time)
        self.rows_examined += rows_examined
        self.rows_returned += rows_returned
        self.last_executed = datetime.now(timezone.utc)
        
        # Mark as slow if over threshold
        if execution_time > 0.5:  # 500ms threshold
            self.slow_query_count += 1


@dataclass
class MemoryAllocation:
    """Memory allocation tracking."""
    object_type: str
    size_bytes: int
    timestamp: datetime
    stack_trace: str
    thread_id: int
    is_freed: bool = False
    freed_at: Optional[datetime] = None


@dataclass
class PerformanceIssue:
    """Detected performance issue."""
    id: str
    issue_type: PerformanceIssueType
    severity: str  # low, medium, high, critical
    title: str
    description: str
    location: str  # file:line or function name
    detected_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    impact_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'issue_type': self.issue_type.value,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'location': self.location,
            'detected_at': self.detected_at.isoformat(),
            'metadata': self.metadata,
            'recommendations': self.recommendations,
            'impact_score': self.impact_score
        }


class MemoryTracker:
    """Memory usage and leak detection tracker."""
    
    def __init__(self, track_allocations: bool = False):
        self.track_allocations = track_allocations
        self.allocations: Dict[int, MemoryAllocation] = {}
        self.allocation_stats = defaultdict(int)
        self.leak_threshold_mb = 100
        self.baseline_memory = self._get_memory_usage()
        self.memory_samples = deque(maxlen=1000)
        self.sample_interval = 60  # seconds
        self.last_sample_time = time.time()
        
        if track_allocations:
            self._enable_allocation_tracking()
    
    def _get_memory_usage(self) -> Dict[str, int]:
        """Get current memory usage."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            return {
                'rss': memory_info.rss,
                'vms': memory_info.vms,
                'percent': process.memory_percent(),
                'available': psutil.virtual_memory().available,
                'gc_objects': len(gc.get_objects())
            }
        except Exception as e:
            logger.debug(f"Could not get memory usage: {e}")
            return {}
    
    def _enable_allocation_tracking(self):
        """Enable detailed allocation tracking."""
        # This would integrate with memory profiling tools like tracemalloc
        try:
            import tracemalloc
            if not tracemalloc.is_tracing():
                tracemalloc.start()
                logger.info("Memory allocation tracking enabled")
        except ImportError:
            logger.warning("tracemalloc not available, allocation tracking disabled")
    
    def sample_memory(self):
        """Sample current memory usage."""
        current_time = time.time()
        if current_time - self.last_sample_time >= self.sample_interval:
            memory_usage = self._get_memory_usage()
            memory_usage['timestamp'] = current_time
            self.memory_samples.append(memory_usage)
            self.last_sample_time = current_time
    
    def detect_memory_leaks(self) -> List[PerformanceIssue]:
        """Detect potential memory leaks."""
        issues = []
        
        if len(self.memory_samples) < 10:
            return issues
        
        # Analyze memory growth trend
        recent_samples = list(self.memory_samples)[-10:]
        memory_growth = []
        
        for i in range(1, len(recent_samples)):
            growth = recent_samples[i].get('rss', 0) - recent_samples[i-1].get('rss', 0)
            memory_growth.append(growth)
        
        # Check for consistent growth
        if all(growth > 0 for growth in memory_growth[-5:]):  # Last 5 samples showing growth
            avg_growth = sum(memory_growth) / len(memory_growth)
            current_memory = recent_samples[-1].get('rss', 0)
            baseline_memory = self.baseline_memory.get('rss', current_memory)
            
            growth_mb = (current_memory - baseline_memory) / (1024 * 1024)
            
            if growth_mb > self.leak_threshold_mb:
                severity = "critical" if growth_mb > 500 else "high" if growth_mb > 200 else "medium"
                
                issue = PerformanceIssue(
                    id=str(uuid.uuid4()),
                    issue_type=PerformanceIssueType.MEMORY_LEAK,
                    severity=severity,
                    title="Potential Memory Leak Detected",
                    description=f"Memory usage has grown by {growth_mb:.1f} MB from baseline. "
                               f"Average growth rate: {avg_growth / (1024 * 1024):.2f} MB per sample.",
                    location="system_wide",
                    detected_at=datetime.now(timezone.utc),
                    metadata={
                        'growth_mb': growth_mb,
                        'avg_growth_rate_mb': avg_growth / (1024 * 1024),
                        'current_memory_mb': current_memory / (1024 * 1024),
                        'baseline_memory_mb': baseline_memory / (1024 * 1024)
                    },
                    recommendations=[
                        "Review recent code changes for resource leaks",
                        "Check for circular references preventing garbage collection",
                        "Monitor memory usage patterns over longer periods",
                        "Use memory profiling tools to identify leak sources"
                    ],
                    impact_score=min(100, growth_mb / 10)
                )
                issues.append(issue)
        
        return issues
    
    def get_top_memory_consumers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top memory consuming object types."""
        try:
            import tracemalloc
            if tracemalloc.is_tracing():
                snapshot = tracemalloc.take_snapshot()
                top_stats = snapshot.statistics('traceback')
                
                consumers = []
                for stat in top_stats[:limit]:
                    consumers.append({
                        'size_mb': stat.size / (1024 * 1024),
                        'count': stat.count,
                        'traceback': str(stat.traceback)
                    })
                
                return consumers
        except Exception as e:
            logger.debug(f"Could not get memory consumers: {e}")
        
        return []


class DatabaseProfiler:
    """Database query performance profiler."""
    
    def __init__(self):
        self.query_profiles: Dict[str, DatabaseQueryProfile] = {}
        self.slow_query_threshold = 0.5  # 500ms
        self.n_plus_one_detection = True
        self.active_queries: Dict[str, float] = {}  # query_id -> start_time
        self.query_patterns = {}
    
    def start_query(self, query: str, params: Optional[Tuple] = None) -> str:
        """Start tracking a database query."""
        query_id = str(uuid.uuid4())
        self.active_queries[query_id] = time.time()
        
        # Create or get query profile
        query_hash = self._hash_query(query)
        
        if query_hash not in self.query_profiles:
            self.query_profiles[query_hash] = DatabaseQueryProfile(
                query_hash=query_hash,
                query_template=self._normalize_query(query),
                query_type=self._get_query_type(query),
                table_names=self._extract_table_names(query)
            )
        
        return query_id
    
    def finish_query(self, query_id: str, rows_examined: int = 0, rows_returned: int = 0):
        """Finish tracking a database query."""
        if query_id not in self.active_queries:
            return
        
        execution_time = time.time() - self.active_queries[query_id]
        del self.active_queries[query_id]
        
        # Update profile (would need to associate query_id with query_hash)
        # This is simplified - in practice you'd track the query_hash with query_id
        
        # Record query execution with tracing if available
        tracer = get_tracer()
        if tracer:
            span = tracer.start_span(
                "database_query",
                kind=SpanKind.CLIENT,
                tags={
                    'db.duration_ms': execution_time * 1000,
                    'db.rows_examined': rows_examined,
                    'db.rows_returned': rows_returned
                }
            )
            tracer.finish_span(span)
    
    def _hash_query(self, query: str) -> str:
        """Create hash for query template."""
        normalized = self._normalize_query(query)
        return str(hash(normalized))
    
    def _normalize_query(self, query: str) -> str:
        """Normalize query by removing parameters."""
        # Simple normalization - replace numbers and strings with placeholders
        import re
        normalized = re.sub(r'\b\d+\b', '?', query)
        normalized = re.sub(r"'[^']*'", '?', normalized)
        normalized = re.sub(r'"[^"]*"', '?', normalized)
        return normalized.strip()
    
    def _get_query_type(self, query: str) -> str:
        """Extract query type (SELECT, INSERT, etc.)."""
        query_upper = query.strip().upper()
        for query_type in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER']:
            if query_upper.startswith(query_type):
                return query_type
        return 'UNKNOWN'
    
    def _extract_table_names(self, query: str) -> List[str]:
        """Extract table names from query."""
        # Simple table extraction - would need more sophisticated parsing
        import re
        tables = []
        
        # Look for FROM and JOIN clauses
        patterns = [
            r'\bFROM\s+(\w+)',
            r'\bJOIN\s+(\w+)',
            r'\bINTO\s+(\w+)',
            r'\bUPDATE\s+(\w+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, query, re.IGNORECASE)
            tables.extend(matches)
        
        return list(set(tables))
    
    def detect_query_issues(self) -> List[PerformanceIssue]:
        """Detect database query performance issues."""
        issues = []
        
        for query_hash, profile in self.query_profiles.items():
            if profile.call_count == 0:
                continue
            
            # Detect slow queries
            if profile.average_time > self.slow_query_threshold:
                severity = "critical" if profile.average_time > 2.0 else "high"
                
                issue = PerformanceIssue(
                    id=str(uuid.uuid4()),
                    issue_type=PerformanceIssueType.INEFFICIENT_QUERY,
                    severity=severity,
                    title="Slow Database Query",
                    description=f"Query averaging {profile.average_time:.2f}s execution time. "
                               f"Called {profile.call_count} times.",
                    location=f"query:{query_hash[:8]}",
                    detected_at=datetime.now(timezone.utc),
                    metadata={
                        'query_template': profile.query_template,
                        'average_time': profile.average_time,
                        'max_time': profile.max_time,
                        'call_count': profile.call_count,
                        'query_type': profile.query_type,
                        'tables': profile.table_names
                    },
                    recommendations=[
                        "Add appropriate database indexes",
                        "Optimize WHERE clauses",
                        "Consider query rewriting or caching",
                        "Review table design and normalization"
                    ],
                    impact_score=profile.average_time * profile.call_count
                )
                issues.append(issue)
            
            # Detect potential N+1 queries
            if profile.call_count > 50 and profile.query_type == 'SELECT':
                issue = PerformanceIssue(
                    id=str(uuid.uuid4()),
                    issue_type=PerformanceIssueType.INEFFICIENT_QUERY,
                    severity="medium",
                    title="Potential N+1 Query Pattern",
                    description=f"SELECT query executed {profile.call_count} times. "
                               "This may indicate an N+1 query problem.",
                    location=f"query:{query_hash[:8]}",
                    detected_at=datetime.now(timezone.utc),
                    metadata={
                        'query_template': profile.query_template,
                        'call_count': profile.call_count,
                        'tables': profile.table_names
                    },
                    recommendations=[
                        "Use JOIN instead of separate queries",
                        "Implement query batching",
                        "Add eager loading for related data",
                        "Consider using ORM optimization features"
                    ],
                    impact_score=profile.call_count * 0.1
                )
                issues.append(issue)
        
        return issues


class ResourceContentionMonitor:
    """Monitor resource contention and blocking operations."""
    
    def __init__(self):
        self.lock_waits: Dict[str, List[float]] = defaultdict(list)
        self.thread_blocks: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        self.io_operations: deque = deque(maxlen=1000)
        self.deadlock_detection_enabled = True
    
    def record_lock_wait(self, lock_name: str, wait_time: float):
        """Record a lock wait time."""
        self.lock_waits[lock_name].append(wait_time)
        
        # Keep only recent waits (last 100)
        if len(self.lock_waits[lock_name]) > 100:
            self.lock_waits[lock_name] = self.lock_waits[lock_name][-100:]
    
    def record_thread_block(self, thread_id: int, block_type: str, duration: float, 
                           location: str):
        """Record thread blocking operation."""
        block_info = {
            'type': block_type,
            'duration': duration,
            'location': location,
            'timestamp': time.time()
        }
        
        self.thread_blocks[thread_id].append(block_info)
        
        # Keep only recent blocks
        if len(self.thread_blocks[thread_id]) > 50:
            self.thread_blocks[thread_id] = self.thread_blocks[thread_id][-50:]
    
    def detect_contention_issues(self) -> List[PerformanceIssue]:
        """Detect resource contention issues."""
        issues = []
        
        # Check for excessive lock waits
        for lock_name, wait_times in self.lock_waits.items():
            if len(wait_times) < 5:
                continue
            
            avg_wait = sum(wait_times) / len(wait_times)
            max_wait = max(wait_times)
            
            if avg_wait > 0.1 or max_wait > 1.0:  # 100ms average or 1s max
                severity = "high" if max_wait > 5.0 else "medium"
                
                issue = PerformanceIssue(
                    id=str(uuid.uuid4()),
                    issue_type=PerformanceIssueType.RESOURCE_CONTENTION,
                    severity=severity,
                    title="Lock Contention Detected",
                    description=f"Lock '{lock_name}' showing high contention. "
                               f"Average wait: {avg_wait:.3f}s, Max wait: {max_wait:.3f}s",
                    location=f"lock:{lock_name}",
                    detected_at=datetime.now(timezone.utc),
                    metadata={
                        'lock_name': lock_name,
                        'average_wait_time': avg_wait,
                        'max_wait_time': max_wait,
                        'recent_waits': len(wait_times)
                    },
                    recommendations=[
                        "Reduce critical section size",
                        "Consider using read-write locks",
                        "Implement lock-free algorithms where possible",
                        "Review locking order to prevent deadlocks"
                    ],
                    impact_score=avg_wait * len(wait_times)
                )
                issues.append(issue)
        
        return issues


class PerformanceProfiler:
    """
    Main performance profiler that orchestrates function-level profiling,
    database query optimization, memory leak detection, and resource
    contention analysis.
    """
    
    def __init__(self, db_path: str = "performance_metrics.db"):
        self.db_path = db_path
        self.enabled = True
        
        # Profiler components
        self.function_profiles: Dict[str, FunctionProfile] = {}
        self.memory_tracker = MemoryTracker(track_allocations=True)
        self.database_profiler = DatabaseProfiler()
        self.contention_monitor = ResourceContentionMonitor()
        
        # Performance issue tracking
        self.detected_issues: List[PerformanceIssue] = []
        self.issue_detection_interval = 300  # 5 minutes
        self.last_issue_detection = time.time()
        
        # Profiling overhead control
        self.profiling_overhead_threshold = 0.05  # 5%
        self.current_overhead = 0.0
        
        # Background tasks
        self.monitoring_task: Optional[asyncio.Task] = None
        self.running = False
    
    async def initialize(self):
        """Initialize the performance profiler."""
        await self._create_profiler_tables()
        
        # Start background monitoring
        self.running = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        logger.info("Performance Profiler initialized")
    
    async def _create_profiler_tables(self):
        """Create profiler database tables."""
        async with aiosqlite.connect(self.db_path) as db:
            # Function profiles table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS function_profiles (
                    id TEXT PRIMARY KEY,
                    function_name TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    file_path TEXT,
                    line_number INTEGER,
                    call_count INTEGER DEFAULT 0,
                    total_time REAL DEFAULT 0.0,
                    average_time REAL DEFAULT 0.0,
                    min_time REAL DEFAULT 0.0,
                    max_time REAL DEFAULT 0.0,
                    memory_usage_bytes INTEGER DEFAULT 0,
                    cpu_time REAL DEFAULT 0.0,
                    error_count INTEGER DEFAULT 0,
                    last_called TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Performance issues table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS performance_issues (
                    id TEXT PRIMARY KEY,
                    issue_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    location TEXT,
                    detected_at TEXT NOT NULL,
                    resolved_at TEXT,
                    is_resolved BOOLEAN DEFAULT FALSE,
                    metadata TEXT,
                    recommendations TEXT,
                    impact_score REAL DEFAULT 0.0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Query profiles table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS query_profiles (
                    query_hash TEXT PRIMARY KEY,
                    query_template TEXT NOT NULL,
                    query_type TEXT NOT NULL,
                    call_count INTEGER DEFAULT 0,
                    total_time REAL DEFAULT 0.0,
                    average_time REAL DEFAULT 0.0,
                    min_time REAL DEFAULT 0.0,
                    max_time REAL DEFAULT 0.0,
                    rows_examined INTEGER DEFAULT 0,
                    rows_returned INTEGER DEFAULT 0,
                    table_names TEXT,
                    slow_query_count INTEGER DEFAULT 0,
                    last_executed TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Memory samples table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS memory_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    rss_bytes INTEGER,
                    vms_bytes INTEGER,
                    memory_percent REAL,
                    available_bytes INTEGER,
                    gc_objects INTEGER,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_function_profiles_time ON function_profiles(average_time DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_performance_issues_severity ON performance_issues(severity, detected_at)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_query_profiles_time ON query_profiles(average_time DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_memory_samples_timestamp ON memory_samples(timestamp)")
            
            await db.commit()
    
    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while self.running:
            try:
                # Sample memory usage
                self.memory_tracker.sample_memory()
                
                # Periodic issue detection
                current_time = time.time()
                if current_time - self.last_issue_detection >= self.issue_detection_interval:
                    await self._detect_performance_issues()
                    self.last_issue_detection = current_time
                
                # Persist data periodically
                await self._persist_profiles()
                
                await asyncio.sleep(60)  # Check every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in performance monitoring loop: {e}")
                await asyncio.sleep(60)
    
    async def _detect_performance_issues(self):
        """Detect various performance issues."""
        new_issues = []
        
        # Memory leak detection
        memory_issues = self.memory_tracker.detect_memory_leaks()
        new_issues.extend(memory_issues)
        
        # Database query issues
        query_issues = self.database_profiler.detect_query_issues()
        new_issues.extend(query_issues)
        
        # Resource contention issues
        contention_issues = self.contention_monitor.detect_contention_issues()
        new_issues.extend(contention_issues)
        
        # Function performance issues
        function_issues = self._detect_function_issues()
        new_issues.extend(function_issues)
        
        # Store new issues
        if new_issues:
            await self._store_performance_issues(new_issues)
            self.detected_issues.extend(new_issues)
            
            logger.info(f"Detected {len(new_issues)} new performance issues")
    
    def _detect_function_issues(self) -> List[PerformanceIssue]:
        """Detect function-level performance issues."""
        issues = []
        
        for func_key, profile in self.function_profiles.items():
            if profile.call_count < 5:  # Need minimum calls for analysis
                continue
            
            # Detect slow functions
            if profile.average_time > 1.0:  # > 1 second average
                severity = "critical" if profile.average_time > 5.0 else "high"
                
                issue = PerformanceIssue(
                    id=str(uuid.uuid4()),
                    issue_type=PerformanceIssueType.SLOW_FUNCTION,
                    severity=severity,
                    title="Slow Function Detected",
                    description=f"Function '{profile.function_name}' averaging {profile.average_time:.2f}s. "
                               f"Called {profile.call_count} times.",
                    location=f"{profile.file_path}:{profile.line_number}",
                    detected_at=datetime.now(timezone.utc),
                    metadata={
                        'function_name': profile.function_name,
                        'module_name': profile.module_name,
                        'average_time': profile.average_time,
                        'max_time': profile.max_time,
                        'call_count': profile.call_count,
                        'total_time': profile.total_time
                    },
                    recommendations=[
                        "Profile function with detailed profiler",
                        "Check for inefficient algorithms or data structures",
                        "Consider caching frequently computed results",
                        "Review database queries within function",
                        "Optimize I/O operations"
                    ],
                    impact_score=profile.average_time * profile.call_count
                )
                issues.append(issue)
            
            # Detect high error rates
            if profile.error_count > 0 and profile.error_count / profile.call_count > 0.1:  # > 10% error rate
                issue = PerformanceIssue(
                    id=str(uuid.uuid4()),
                    issue_type=PerformanceIssueType.HIGH_CPU,  # Using as generic performance issue
                    severity="medium",
                    title="High Function Error Rate",
                    description=f"Function '{profile.function_name}' has {profile.error_count} errors "
                               f"out of {profile.call_count} calls ({profile.error_count/profile.call_count*100:.1f}%).",
                    location=f"{profile.file_path}:{profile.line_number}",
                    detected_at=datetime.now(timezone.utc),
                    metadata={
                        'function_name': profile.function_name,
                        'error_count': profile.error_count,
                        'call_count': profile.call_count,
                        'error_rate': profile.error_count / profile.call_count
                    },
                    recommendations=[
                        "Review error handling in function",
                        "Check input validation",
                        "Add better error logging",
                        "Consider function refactoring"
                    ],
                    impact_score=profile.error_count * 10
                )
                issues.append(issue)
        
        return issues
    
    async def _store_performance_issues(self, issues: List[PerformanceIssue]):
        """Store performance issues in database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                for issue in issues:
                    await db.execute("""
                        INSERT OR REPLACE INTO performance_issues 
                        (id, issue_type, severity, title, description, location,
                         detected_at, metadata, recommendations, impact_score)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        issue.id,
                        issue.issue_type.value,
                        issue.severity,
                        issue.title,
                        issue.description,
                        issue.location,
                        issue.detected_at.isoformat(),
                        json.dumps(issue.metadata),
                        json.dumps(issue.recommendations),
                        issue.impact_score
                    ))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error storing performance issues: {e}")
    
    async def _persist_profiles(self):
        """Persist current profiles to database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Update function profiles
                for func_key, profile in self.function_profiles.items():
                    await db.execute("""
                        INSERT OR REPLACE INTO function_profiles 
                        (id, function_name, module_name, file_path, line_number,
                         call_count, total_time, average_time, min_time, max_time,
                         memory_usage_bytes, cpu_time, error_count, last_called, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        func_key,
                        profile.function_name,
                        profile.module_name,
                        profile.file_path,
                        profile.line_number,
                        profile.call_count,
                        profile.total_time,
                        profile.average_time,
                        profile.min_time,
                        profile.max_time,
                        profile.memory_usage_bytes,
                        profile.cpu_time,
                        profile.error_count,
                        profile.last_called.isoformat() if profile.last_called else None,
                        datetime.now(timezone.utc).isoformat()
                    ))
                
                # Update query profiles
                for query_hash, profile in self.database_profiler.query_profiles.items():
                    await db.execute("""
                        INSERT OR REPLACE INTO query_profiles 
                        (query_hash, query_template, query_type, call_count,
                         total_time, average_time, min_time, max_time,
                         rows_examined, rows_returned, table_names, slow_query_count,
                         last_executed, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        query_hash,
                        profile.query_template,
                        profile.query_type,
                        profile.call_count,
                        profile.total_time,
                        profile.average_time,
                        profile.min_time,
                        profile.max_time,
                        profile.rows_examined,
                        profile.rows_returned,
                        json.dumps(profile.table_names),
                        profile.slow_query_count,
                        profile.last_executed.isoformat() if profile.last_executed else None,
                        datetime.now(timezone.utc).isoformat()
                    ))
                
                # Store memory samples
                if self.memory_tracker.memory_samples:
                    latest_sample = self.memory_tracker.memory_samples[-1]
                    await db.execute("""
                        INSERT INTO memory_samples 
                        (timestamp, rss_bytes, vms_bytes, memory_percent, 
                         available_bytes, gc_objects)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        datetime.fromtimestamp(latest_sample['timestamp'], timezone.utc).isoformat(),
                        latest_sample.get('rss', 0),
                        latest_sample.get('vms', 0),
                        latest_sample.get('percent', 0.0),
                        latest_sample.get('available', 0),
                        latest_sample.get('gc_objects', 0)
                    ))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error persisting profiles: {e}")
    
    def profile_function(self, func_name: str, module_name: str, file_path: str, 
                        line_number: int, execution_time: float, 
                        memory_usage: int = 0, error: bool = False):
        """Profile a function execution."""
        if not self.enabled:
            return
        
        func_key = f"{module_name}.{func_name}"
        
        if func_key not in self.function_profiles:
            self.function_profiles[func_key] = FunctionProfile(
                function_name=func_name,
                module_name=module_name,
                file_path=file_path,
                line_number=line_number
            )
        
        profile = self.function_profiles[func_key]
        profile.update(execution_time, memory_usage)
        
        if error:
            profile.record_error()
    
    async def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        try:
            # Top slow functions
            slow_functions = sorted(
                self.function_profiles.values(),
                key=lambda p: p.average_time,
                reverse=True
            )[:10]
            
            # Recent issues
            recent_issues = [
                issue for issue in self.detected_issues
                if (datetime.now(timezone.utc) - issue.detected_at).days < 1
            ]
            
            # Memory usage trend
            memory_samples = list(self.memory_tracker.memory_samples)[-10:]
            
            return {
                'summary': {
                    'total_functions_profiled': len(self.function_profiles),
                    'total_issues_detected': len(self.detected_issues),
                    'recent_issues': len(recent_issues),
                    'profiler_enabled': self.enabled,
                    'current_overhead': self.current_overhead
                },
                'slow_functions': [
                    {
                        'name': f.function_name,
                        'module': f.module_name,
                        'average_time': f.average_time,
                        'call_count': f.call_count,
                        'total_time': f.total_time
                    }
                    for f in slow_functions if f.call_count > 0
                ],
                'recent_issues': [issue.to_dict() for issue in recent_issues[-5:]],
                'memory_trend': [
                    {
                        'timestamp': sample.get('timestamp'),
                        'rss_mb': sample.get('rss', 0) / (1024 * 1024),
                        'memory_percent': sample.get('percent', 0)
                    }
                    for sample in memory_samples
                ],
                'database_stats': {
                    'total_queries_profiled': len(self.database_profiler.query_profiles),
                    'slow_queries': sum(1 for p in self.database_profiler.query_profiles.values() 
                                      if p.average_time > self.database_profiler.slow_query_threshold)
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting performance summary: {e}")
            return {}
    
    async def get_function_profile(self, function_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed profile for a specific function."""
        for func_key, profile in self.function_profiles.items():
            if func_key.endswith(function_name):
                return {
                    'function_name': profile.function_name,
                    'module_name': profile.module_name,
                    'file_path': profile.file_path,
                    'line_number': profile.line_number,
                    'call_count': profile.call_count,
                    'total_time': profile.total_time,
                    'average_time': profile.average_time,
                    'min_time': profile.min_time,
                    'max_time': profile.max_time,
                    'memory_usage_bytes': profile.memory_usage_bytes,
                    'error_count': profile.error_count,
                    'last_called': profile.last_called.isoformat() if profile.last_called else None
                }
        return None
    
    async def shutdown(self):
        """Shutdown the profiler."""
        self.running = False
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        # Final data persistence
        await self._persist_profiles()
        
        logger.info("Performance Profiler shutdown complete")


# Profiling decorators
def profile_function(profiler: Optional[PerformanceProfiler] = None):
    """Decorator for profiling function performance."""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            if not profiler or not profiler.enabled:
                return await func(*args, **kwargs)
            
            start_time = time.time()
            memory_before = psutil.Process().memory_info().rss
            error_occurred = False
            
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                error_occurred = True
                raise
            finally:
                execution_time = time.time() - start_time
                memory_after = psutil.Process().memory_info().rss
                memory_delta = memory_after - memory_before
                
                profiler.profile_function(
                    func.__name__,
                    func.__module__,
                    func.__code__.co_filename,
                    func.__code__.co_firstlineno,
                    execution_time,
                    memory_delta,
                    error_occurred
                )
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            if not profiler or not profiler.enabled:
                return func(*args, **kwargs)
            
            start_time = time.time()
            memory_before = psutil.Process().memory_info().rss
            error_occurred = False
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                error_occurred = True
                raise
            finally:
                execution_time = time.time() - start_time
                memory_after = psutil.Process().memory_info().rss
                memory_delta = memory_after - memory_before
                
                profiler.profile_function(
                    func.__name__,
                    func.__module__,
                    func.__code__.co_filename,
                    func.__code__.co_firstlineno,
                    execution_time,
                    memory_delta,
                    error_occurred
                )
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    return decorator


# Global profiler instance
global_profiler: Optional[PerformanceProfiler] = None


def get_profiler() -> Optional[PerformanceProfiler]:
    """Get the global profiler instance."""
    return global_profiler


async def initialize_profiler(db_path: str = "performance_metrics.db") -> PerformanceProfiler:
    """Initialize the global performance profiler."""
    global global_profiler
    
    profiler = PerformanceProfiler(db_path)
    await profiler.initialize()
    global_profiler = profiler
    
    return profiler