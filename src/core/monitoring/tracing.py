"""
Distributed Tracing System

OpenTelemetry-compatible distributed tracing implementation for end-to-end
request flow visualization, performance bottleneck identification, and
dependency mapping. This is the core component of Phase 8.3: APM.
"""

import asyncio
import logging
import time
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Union, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from contextvars import ContextVar
from functools import wraps
import aiosqlite
import threading
from collections import defaultdict, deque
import statistics

logger = logging.getLogger(__name__)

# Context variable for current trace
current_trace: ContextVar[Optional['TraceContext']] = ContextVar('current_trace', default=None)
current_span: ContextVar[Optional['Span']] = ContextVar('current_span', default=None)


class SpanKind(Enum):
    """Span kind enumeration."""
    INTERNAL = "internal"
    SERVER = "server"
    CLIENT = "client"
    PRODUCER = "producer"
    CONSUMER = "consumer"


class SpanStatus(Enum):
    """Span status enumeration."""
    UNSET = "unset"
    OK = "ok"
    ERROR = "error"


@dataclass
class SpanEvent:
    """Event within a span."""
    name: str
    timestamp: datetime
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SpanLink:
    """Link to another span."""
    trace_id: str
    span_id: str
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Span:
    """Distributed tracing span."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    operation_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    status: SpanStatus = SpanStatus.UNSET
    kind: SpanKind = SpanKind.INTERNAL
    service_name: str = "unknown"
    resource_name: str = ""
    
    # Span data
    tags: Dict[str, Any] = field(default_factory=dict)
    logs: List[SpanEvent] = field(default_factory=list)
    links: List[SpanLink] = field(default_factory=list)
    
    # Performance data
    cpu_time_ms: Optional[float] = None
    memory_usage_bytes: Optional[int] = None
    
    # Error information
    error: bool = False
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    stack_trace: Optional[str] = None
    
    def finish(self, end_time: Optional[datetime] = None):
        """Finish the span."""
        self.end_time = end_time or datetime.now(timezone.utc)
        if self.start_time:
            self.duration_ms = (self.end_time - self.start_time).total_seconds() * 1000
    
    def set_tag(self, key: str, value: Any):
        """Set a tag on the span."""
        self.tags[key] = value
    
    def set_error(self, error: Exception):
        """Mark span as having an error."""
        self.error = True
        self.status = SpanStatus.ERROR
        self.error_message = str(error)
        self.error_type = type(error).__name__
        
        # Get stack trace if available
        import traceback
        self.stack_trace = traceback.format_exc()
    
    def log_event(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        """Log an event in the span."""
        event = SpanEvent(
            name=name,
            timestamp=datetime.now(timezone.utc),
            attributes=attributes or {}
        )
        self.logs.append(event)
    
    def add_link(self, trace_id: str, span_id: str, attributes: Optional[Dict[str, Any]] = None):
        """Add a link to another span."""
        link = SpanLink(
            trace_id=trace_id,
            span_id=span_id,
            attributes=attributes or {}
        )
        self.links.append(link)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert span to dictionary."""
        return {
            'trace_id': self.trace_id,
            'span_id': self.span_id,
            'parent_span_id': self.parent_span_id,
            'operation_name': self.operation_name,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_ms': self.duration_ms,
            'status': self.status.value,
            'kind': self.kind.value,
            'service_name': self.service_name,
            'resource_name': self.resource_name,
            'tags': self.tags,
            'logs': [
                {
                    'name': log.name,
                    'timestamp': log.timestamp.isoformat(),
                    'attributes': log.attributes
                }
                for log in self.logs
            ],
            'links': [
                {
                    'trace_id': link.trace_id,
                    'span_id': link.span_id,
                    'attributes': link.attributes
                }
                for link in self.links
            ],
            'cpu_time_ms': self.cpu_time_ms,
            'memory_usage_bytes': self.memory_usage_bytes,
            'error': self.error,
            'error_message': self.error_message,
            'error_type': self.error_type,
            'stack_trace': self.stack_trace
        }


@dataclass
class TraceContext:
    """Distributed tracing context."""
    trace_id: str
    baggage: Dict[str, str] = field(default_factory=dict)
    sampling_decision: bool = True
    
    def set_baggage_item(self, key: str, value: str):
        """Set baggage item."""
        self.baggage[key] = value
    
    def get_baggage_item(self, key: str) -> Optional[str]:
        """Get baggage item."""
        return self.baggage.get(key)


@dataclass
class Trace:
    """Complete distributed trace."""
    trace_id: str
    spans: List[Span] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    service_names: List[str] = field(default_factory=list)
    
    def add_span(self, span: Span):
        """Add span to trace."""
        self.spans.append(span)
        
        # Update trace metadata
        if span.service_name and span.service_name not in self.service_names:
            self.service_names.append(span.service_name)
        
        if not self.start_time or span.start_time < self.start_time:
            self.start_time = span.start_time
        
        if span.end_time and (not self.end_time or span.end_time > self.end_time):
            self.end_time = span.end_time
        
        # Recalculate duration
        if self.start_time and self.end_time:
            self.duration_ms = (self.end_time - self.start_time).total_seconds() * 1000
    
    def get_root_span(self) -> Optional[Span]:
        """Get root span of the trace."""
        for span in self.spans:
            if not span.parent_span_id:
                return span
        return None
    
    def get_span_by_id(self, span_id: str) -> Optional[Span]:
        """Get span by ID."""
        for span in self.spans:
            if span.span_id == span_id:
                return span
        return None
    
    def get_child_spans(self, parent_span_id: str) -> List[Span]:
        """Get child spans of a parent."""
        return [span for span in self.spans if span.parent_span_id == parent_span_id]
    
    def has_errors(self) -> bool:
        """Check if trace has any errors."""
        return any(span.error for span in self.spans)
    
    def get_critical_path(self) -> List[Span]:
        """Get critical path (longest duration path) through the trace."""
        if not self.spans:
            return []
        
        # Build span tree
        root_span = self.get_root_span()
        if not root_span:
            return []
        
        def find_critical_path(span: Span) -> Tuple[List[Span], float]:
            """Recursively find critical path from a span."""
            children = self.get_child_spans(span.span_id)
            
            if not children:
                return [span], span.duration_ms or 0
            
            # Find child with longest critical path
            best_path = [span]
            best_duration = span.duration_ms or 0
            
            for child in children:
                child_path, child_duration = find_critical_path(child)
                total_duration = (span.duration_ms or 0) + child_duration
                
                if total_duration > best_duration:
                    best_path = [span] + child_path
                    best_duration = total_duration
            
            return best_path, best_duration
        
        critical_path, _ = find_critical_path(root_span)
        return critical_path


class SpanProcessor:
    """Base class for span processors."""
    
    def on_start(self, span: Span):
        """Called when span starts."""
        pass
    
    def on_end(self, span: Span):
        """Called when span ends."""
        pass
    
    def shutdown(self):
        """Shutdown the processor."""
        pass


class BatchSpanProcessor(SpanProcessor):
    """Batching span processor for efficient storage."""
    
    def __init__(self, exporter: 'SpanExporter', max_batch_size: int = 100, 
                 batch_timeout_ms: int = 5000):
        self.exporter = exporter
        self.max_batch_size = max_batch_size
        self.batch_timeout_ms = batch_timeout_ms
        
        self.span_queue = deque()
        self.batch_lock = threading.Lock()
        self.shutdown_event = threading.Event()
        
        # Start background batch processing
        self.batch_thread = threading.Thread(target=self._batch_worker, daemon=True)
        self.batch_thread.start()
    
    def on_end(self, span: Span):
        """Add span to batch queue."""
        with self.batch_lock:
            self.span_queue.append(span)
            
            if len(self.span_queue) >= self.max_batch_size:
                self._export_batch()
    
    def _batch_worker(self):
        """Background worker for batch processing."""
        while not self.shutdown_event.is_set():
            try:
                # Wait for batch timeout
                self.shutdown_event.wait(self.batch_timeout_ms / 1000)
                
                with self.batch_lock:
                    if self.span_queue:
                        self._export_batch()
                        
            except Exception as e:
                logger.error(f"Error in batch worker: {e}")
    
    def _export_batch(self):
        """Export current batch."""
        if not self.span_queue:
            return
        
        batch = list(self.span_queue)
        self.span_queue.clear()
        
        try:
            self.exporter.export_spans(batch)
        except Exception as e:
            logger.error(f"Error exporting span batch: {e}")
    
    def shutdown(self):
        """Shutdown the processor."""
        self.shutdown_event.set()
        
        # Export remaining spans
        with self.batch_lock:
            if self.span_queue:
                self._export_batch()
        
        if self.batch_thread.is_alive():
            self.batch_thread.join(timeout=5)


class SpanExporter:
    """Base class for span exporters."""
    
    def export_spans(self, spans: List[Span]):
        """Export spans."""
        raise NotImplementedError


class DatabaseSpanExporter(SpanExporter):
    """Database span exporter."""
    
    def __init__(self, db_path: str = "performance_metrics.db"):
        self.db_path = db_path
    
    def export_spans(self, spans: List[Span]):
        """Export spans to database."""
        asyncio.create_task(self._async_export_spans(spans))
    
    async def _async_export_spans(self, spans: List[Span]):
        """Async export spans to database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                for span in spans:
                    await db.execute("""
                        INSERT OR REPLACE INTO distributed_traces 
                        (trace_id, span_id, parent_span_id, operation_name, service_name,
                         start_time, end_time, duration_ms, status, kind, tags, 
                         logs, error, error_message, cpu_time_ms, memory_usage_bytes)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        span.trace_id,
                        span.span_id,
                        span.parent_span_id,
                        span.operation_name,
                        span.service_name,
                        span.start_time.isoformat(),
                        span.end_time.isoformat() if span.end_time else None,
                        span.duration_ms,
                        span.status.value,
                        span.kind.value,
                        json.dumps(span.tags),
                        json.dumps([log.to_dict() if hasattr(log, 'to_dict') else log for log in span.logs]),
                        span.error,
                        span.error_message,
                        span.cpu_time_ms,
                        span.memory_usage_bytes
                    ))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error exporting spans to database: {e}")


class Sampler:
    """Base class for trace sampling."""
    
    def should_sample(self, trace_id: str, operation_name: str, 
                     parent_span_context: Optional[TraceContext] = None) -> bool:
        """Determine if trace should be sampled."""
        raise NotImplementedError


class ProbabilitySampler(Sampler):
    """Probability-based sampler."""
    
    def __init__(self, probability: float = 1.0):
        self.probability = max(0.0, min(1.0, probability))
    
    def should_sample(self, trace_id: str, operation_name: str, 
                     parent_span_context: Optional[TraceContext] = None) -> bool:
        """Sample based on probability."""
        if parent_span_context:
            return parent_span_context.sampling_decision
        
        # Use trace_id for deterministic sampling
        trace_hash = hash(trace_id) % 1000000
        return (trace_hash / 1000000) < self.probability


class RateLimitingSampler(Sampler):
    """Rate limiting sampler."""
    
    def __init__(self, max_traces_per_second: float = 100):
        self.max_traces_per_second = max_traces_per_second
        self.last_reset_time = time.time()
        self.current_count = 0
        self.lock = threading.Lock()
    
    def should_sample(self, trace_id: str, operation_name: str, 
                     parent_span_context: Optional[TraceContext] = None) -> bool:
        """Sample based on rate limit."""
        if parent_span_context:
            return parent_span_context.sampling_decision
        
        with self.lock:
            current_time = time.time()
            
            # Reset count if a second has passed
            if current_time - self.last_reset_time >= 1.0:
                self.current_count = 0
                self.last_reset_time = current_time
            
            if self.current_count < self.max_traces_per_second:
                self.current_count += 1
                return True
            
            return False


class DistributedTracer:
    """
    Main distributed tracing implementation with OpenTelemetry-compatible API.
    Provides end-to-end request flow tracking with minimal performance overhead.
    """
    
    def __init__(self, service_name: str, db_path: str = "performance_metrics.db"):
        self.service_name = service_name
        self.db_path = db_path
        
        # Configuration
        self.enabled = True
        self.sampler = ProbabilitySampler(probability=1.0)  # Sample all by default
        
        # Span processors and exporters
        self.span_processors: List[SpanProcessor] = []
        
        # Initialize default exporter
        exporter = DatabaseSpanExporter(db_path)
        processor = BatchSpanProcessor(exporter)
        self.span_processors.append(processor)
        
        # Active traces
        self.active_traces: Dict[str, Trace] = {}
        self.trace_lock = threading.Lock()
        
        # Performance tracking
        self.trace_stats = {
            'traces_started': 0,
            'traces_finished': 0,
            'spans_created': 0,
            'spans_finished': 0,
            'errors_recorded': 0
        }
    
    async def initialize(self):
        """Initialize the tracer."""
        await self._create_tracing_tables()
        logger.info(f"Distributed Tracer initialized for service: {self.service_name}")
    
    async def _create_tracing_tables(self):
        """Create tracing database tables."""
        async with aiosqlite.connect(self.db_path) as db:
            # Distributed traces table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS distributed_traces (
                    trace_id TEXT NOT NULL,
                    span_id TEXT PRIMARY KEY,
                    parent_span_id TEXT,
                    operation_name TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    duration_ms REAL,
                    status TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    tags TEXT,
                    logs TEXT,
                    error BOOLEAN DEFAULT FALSE,
                    error_message TEXT,
                    cpu_time_ms REAL,
                    memory_usage_bytes INTEGER,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Trace summary table for quick lookups
            await db.execute("""
                CREATE TABLE IF NOT EXISTS trace_summaries (
                    trace_id TEXT PRIMARY KEY,
                    root_span_id TEXT,
                    operation_name TEXT,
                    service_names TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    duration_ms REAL,
                    span_count INTEGER,
                    error_count INTEGER,
                    has_errors BOOLEAN,
                    critical_path_duration_ms REAL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Performance bottlenecks table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS performance_bottlenecks (
                    id TEXT PRIMARY KEY,
                    trace_id TEXT NOT NULL,
                    span_id TEXT NOT NULL,
                    operation_name TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    duration_ms REAL NOT NULL,
                    bottleneck_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    metadata TEXT,
                    FOREIGN KEY (trace_id, span_id) REFERENCES distributed_traces(trace_id, span_id)
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_traces_trace_id ON distributed_traces(trace_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_traces_service_time ON distributed_traces(service_name, start_time)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_traces_operation_time ON distributed_traces(operation_name, start_time)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_trace_summaries_time ON trace_summaries(start_time)")
            
            await db.commit()
    
    def start_trace(self, operation_name: str, trace_id: Optional[str] = None, 
                   parent_span_context: Optional[TraceContext] = None) -> TraceContext:
        """Start a new distributed trace."""
        if not self.enabled:
            return TraceContext(trace_id="disabled")
        
        # Generate or use provided trace ID
        if not trace_id:
            trace_id = self._generate_trace_id()
        
        # Check sampling decision
        should_sample = self.sampler.should_sample(trace_id, operation_name, parent_span_context)
        
        trace_context = TraceContext(
            trace_id=trace_id,
            sampling_decision=should_sample
        )
        
        # Copy baggage from parent context
        if parent_span_context:
            trace_context.baggage = parent_span_context.baggage.copy()
        
        # Create trace object if sampling
        if should_sample:
            with self.trace_lock:
                self.active_traces[trace_id] = Trace(trace_id=trace_id)
                self.trace_stats['traces_started'] += 1
        
        # Set context
        current_trace.set(trace_context)
        
        return trace_context
    
    def start_span(self, operation_name: str, parent: Optional[Span] = None,
                  kind: SpanKind = SpanKind.INTERNAL, tags: Optional[Dict[str, Any]] = None) -> Span:
        """Start a new span."""
        trace_context = current_trace.get()
        
        if not trace_context or not trace_context.sampling_decision:
            # Return no-op span
            return Span(
                trace_id="disabled",
                span_id="disabled",
                parent_span_id=None,
                operation_name=operation_name,
                start_time=datetime.now(timezone.utc)
            )
        
        # Get parent span info
        parent_span_id = None
        if parent:
            parent_span_id = parent.span_id
        else:
            current_span_context = current_span.get()
            if current_span_context:
                parent_span_id = current_span_context.span_id
        
        # Create span
        span = Span(
            trace_id=trace_context.trace_id,
            span_id=self._generate_span_id(),
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            start_time=datetime.now(timezone.utc),
            kind=kind,
            service_name=self.service_name,
            tags=tags or {}
        )
        
        # Add to active trace
        with self.trace_lock:
            if span.trace_id in self.active_traces:
                self.active_traces[span.trace_id].add_span(span)
        
        # Notify processors
        for processor in self.span_processors:
            try:
                processor.on_start(span)
            except Exception as e:
                logger.error(f"Error in span processor on_start: {e}")
        
        # Set as current span
        current_span.set(span)
        
        self.trace_stats['spans_created'] += 1
        return span
    
    def finish_span(self, span: Span):
        """Finish a span."""
        if span.span_id == "disabled":
            return
        
        span.finish()
        
        # Collect performance metrics
        self._collect_span_performance_metrics(span)
        
        # Notify processors
        for processor in self.span_processors:
            try:
                processor.on_end(span)
            except Exception as e:
                logger.error(f"Error in span processor on_end: {e}")
        
        # Check if trace is complete
        self._check_trace_completion(span.trace_id)
        
        self.trace_stats['spans_finished'] += 1
    
    def _collect_span_performance_metrics(self, span: Span):
        """Collect performance metrics for the span."""
        try:
            import psutil
            import os
            
            process = psutil.Process(os.getpid())
            
            # Get CPU time (approximate)
            cpu_times = process.cpu_times()
            span.cpu_time_ms = (cpu_times.user + cpu_times.system) * 1000
            
            # Get memory usage
            memory_info = process.memory_info()
            span.memory_usage_bytes = memory_info.rss
            
        except Exception as e:
            logger.debug(f"Could not collect performance metrics for span: {e}")
    
    def _check_trace_completion(self, trace_id: str):
        """Check if trace is complete and finalize if so."""
        with self.trace_lock:
            if trace_id not in self.active_traces:
                return
            
            trace = self.active_traces[trace_id]
            
            # Simple completion check: all spans have end times
            incomplete_spans = [span for span in trace.spans if not span.end_time]
            
            if not incomplete_spans:
                # Trace is complete, finalize it
                asyncio.create_task(self._finalize_trace(trace))
                del self.active_traces[trace_id]
                self.trace_stats['traces_finished'] += 1
    
    async def _finalize_trace(self, trace: Trace):
        """Finalize a complete trace."""
        try:
            # Create trace summary
            await self._create_trace_summary(trace)
            
            # Detect performance bottlenecks
            await self._detect_bottlenecks(trace)
            
            logger.debug(f"Finalized trace {trace.trace_id} with {len(trace.spans)} spans")
            
        except Exception as e:
            logger.error(f"Error finalizing trace {trace.trace_id}: {e}")
    
    async def _create_trace_summary(self, trace: Trace):
        """Create trace summary for quick lookups."""
        try:
            root_span = trace.get_root_span()
            service_names_json = json.dumps(trace.service_names)
            error_count = sum(1 for span in trace.spans if span.error)
            
            # Calculate critical path duration
            critical_path = trace.get_critical_path()
            critical_path_duration = sum(span.duration_ms or 0 for span in critical_path)
            
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO trace_summaries 
                    (trace_id, root_span_id, operation_name, service_names, start_time,
                     end_time, duration_ms, span_count, error_count, has_errors, critical_path_duration_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    trace.trace_id,
                    root_span.span_id if root_span else None,
                    root_span.operation_name if root_span else None,
                    service_names_json,
                    trace.start_time.isoformat() if trace.start_time else None,
                    trace.end_time.isoformat() if trace.end_time else None,
                    trace.duration_ms,
                    len(trace.spans),
                    error_count,
                    error_count > 0,
                    critical_path_duration
                ))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error creating trace summary: {e}")
    
    async def _detect_bottlenecks(self, trace: Trace):
        """Detect performance bottlenecks in the trace."""
        try:
            bottlenecks = []
            
            # Calculate percentiles for span durations
            durations = [span.duration_ms or 0 for span in trace.spans if span.duration_ms]
            if not durations:
                return
            
            p95_duration = sorted(durations)[int(0.95 * len(durations))] if len(durations) > 1 else durations[0]
            p99_duration = sorted(durations)[int(0.99 * len(durations))] if len(durations) > 1 else durations[0]
            
            for span in trace.spans:
                if not span.duration_ms:
                    continue
                
                bottleneck_type = None
                severity = None
                
                # Detect slow operations
                if span.duration_ms > p99_duration and span.duration_ms > 1000:  # > 1 second
                    bottleneck_type = "slow_operation"
                    severity = "critical"
                elif span.duration_ms > p95_duration and span.duration_ms > 500:  # > 500ms
                    bottleneck_type = "slow_operation"
                    severity = "warning"
                
                # Detect database bottlenecks
                if any(tag in span.operation_name.lower() for tag in ['query', 'db', 'database', 'sql']):
                    if span.duration_ms > 200:  # > 200ms for DB operations
                        bottleneck_type = "database_bottleneck"
                        severity = "critical" if span.duration_ms > 1000 else "warning"
                
                # Detect external service bottlenecks
                if span.kind == SpanKind.CLIENT and span.duration_ms > 1000:  # > 1 second for external calls
                    bottleneck_type = "external_service_bottleneck"
                    severity = "critical"
                
                if bottleneck_type and severity:
                    bottleneck_id = f"{trace.trace_id}_{span.span_id}_{bottleneck_type}"
                    bottlenecks.append({
                        'id': bottleneck_id,
                        'trace_id': trace.trace_id,
                        'span_id': span.span_id,
                        'operation_name': span.operation_name,
                        'service_name': span.service_name,
                        'duration_ms': span.duration_ms,
                        'bottleneck_type': bottleneck_type,
                        'severity': severity,
                        'metadata': {
                            'tags': span.tags,
                            'p95_duration': p95_duration,
                            'p99_duration': p99_duration
                        }
                    })
            
            # Store bottlenecks
            if bottlenecks:
                async with aiosqlite.connect(self.db_path) as db:
                    for bottleneck in bottlenecks:
                        await db.execute("""
                            INSERT OR REPLACE INTO performance_bottlenecks 
                            (id, trace_id, span_id, operation_name, service_name, duration_ms,
                             bottleneck_type, severity, detected_at, metadata)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            bottleneck['id'],
                            bottleneck['trace_id'],
                            bottleneck['span_id'],
                            bottleneck['operation_name'],
                            bottleneck['service_name'],
                            bottleneck['duration_ms'],
                            bottleneck['bottleneck_type'],
                            bottleneck['severity'],
                            datetime.now(timezone.utc).isoformat(),
                            json.dumps(bottleneck['metadata'])
                        ))
                    
                    await db.commit()
                
                logger.info(f"Detected {len(bottlenecks)} performance bottlenecks in trace {trace.trace_id}")
                
        except Exception as e:
            logger.error(f"Error detecting bottlenecks: {e}")
    
    def _generate_trace_id(self) -> str:
        """Generate a unique trace ID."""
        return str(uuid.uuid4())
    
    def _generate_span_id(self) -> str:
        """Generate a unique span ID."""
        return str(uuid.uuid4())
    
    def record_exception(self, exception: Exception, span: Optional[Span] = None):
        """Record an exception in the current span."""
        target_span = span or current_span.get()
        
        if target_span and target_span.span_id != "disabled":
            target_span.set_error(exception)
            self.trace_stats['errors_recorded'] += 1
    
    def get_current_span(self) -> Optional[Span]:
        """Get the current active span."""
        return current_span.get()
    
    def get_current_trace(self) -> Optional[TraceContext]:
        """Get the current trace context."""
        return current_trace.get()
    
    async def get_trace_by_id(self, trace_id: str) -> Optional[Trace]:
        """Get a trace by ID."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Get all spans for the trace
                cursor = await db.execute("""
                    SELECT trace_id, span_id, parent_span_id, operation_name, service_name,
                           start_time, end_time, duration_ms, status, kind, tags, logs,
                           error, error_message, cpu_time_ms, memory_usage_bytes
                    FROM distributed_traces
                    WHERE trace_id = ?
                    ORDER BY start_time
                """, (trace_id,))
                
                rows = await cursor.fetchall()
                if not rows:
                    return None
                
                trace = Trace(trace_id=trace_id)
                
                for row in rows:
                    span = Span(
                        trace_id=row[0],
                        span_id=row[1],
                        parent_span_id=row[2],
                        operation_name=row[3],
                        service_name=row[4],
                        start_time=datetime.fromisoformat(row[5]),
                        end_time=datetime.fromisoformat(row[6]) if row[6] else None,
                        duration_ms=row[7],
                        status=SpanStatus(row[8]),
                        kind=SpanKind(row[9]),
                        tags=json.loads(row[10]) if row[10] else {},
                        logs=json.loads(row[11]) if row[11] else [],
                        error=bool(row[12]),
                        error_message=row[13],
                        cpu_time_ms=row[14],
                        memory_usage_bytes=row[15]
                    )
                    
                    trace.add_span(span)
                
                return trace
                
        except Exception as e:
            logger.error(f"Error getting trace by ID: {e}")
            return None
    
    async def get_traces(self, limit: int = 100, start_time: Optional[datetime] = None,
                        end_time: Optional[datetime] = None, service_name: Optional[str] = None,
                        has_errors: Optional[bool] = None) -> List[Dict[str, Any]]:
        """Get traces with filters."""
        try:
            query_parts = ["SELECT * FROM trace_summaries WHERE 1=1"]
            params = []
            
            if start_time:
                query_parts.append("AND start_time >= ?")
                params.append(start_time.isoformat())
            
            if end_time:
                query_parts.append("AND end_time <= ?")
                params.append(end_time.isoformat())
            
            if service_name:
                query_parts.append("AND service_names LIKE ?")
                params.append(f'%"{service_name}"%')
            
            if has_errors is not None:
                query_parts.append("AND has_errors = ?")
                params.append(has_errors)
            
            query_parts.append("ORDER BY start_time DESC LIMIT ?")
            params.append(limit)
            
            query = " ".join(query_parts)
            
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(query, params)
                rows = await cursor.fetchall()
                
                column_names = [description[0] for description in cursor.description]
                traces = [dict(zip(column_names, row)) for row in rows]
                
                return traces
                
        except Exception as e:
            logger.error(f"Error getting traces: {e}")
            return []
    
    async def get_bottlenecks(self, limit: int = 50, severity: Optional[str] = None,
                            bottleneck_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get performance bottlenecks."""
        try:
            query_parts = ["SELECT * FROM performance_bottlenecks WHERE 1=1"]
            params = []
            
            if severity:
                query_parts.append("AND severity = ?")
                params.append(severity)
            
            if bottleneck_type:
                query_parts.append("AND bottleneck_type = ?")
                params.append(bottleneck_type)
            
            query_parts.append("ORDER BY detected_at DESC LIMIT ?")
            params.append(limit)
            
            query = " ".join(query_parts)
            
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(query, params)
                rows = await cursor.fetchall()
                
                column_names = [description[0] for description in cursor.description]
                bottlenecks = [dict(zip(column_names, row)) for row in rows]
                
                return bottlenecks
                
        except Exception as e:
            logger.error(f"Error getting bottlenecks: {e}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get tracer statistics."""
        return {
            'enabled': self.enabled,
            'service_name': self.service_name,
            'active_traces': len(self.active_traces),
            'span_processors': len(self.span_processors),
            'stats': self.trace_stats.copy()
        }
    
    def shutdown(self):
        """Shutdown the tracer."""
        # Shutdown processors
        for processor in self.span_processors:
            try:
                processor.shutdown()
            except Exception as e:
                logger.error(f"Error shutting down span processor: {e}")
        
        logger.info("Distributed Tracer shutdown complete")


# Decorators for easy tracing
def trace(operation_name: Optional[str] = None, kind: SpanKind = SpanKind.INTERNAL,
          tags: Optional[Dict[str, Any]] = None):
    """Decorator for tracing functions."""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            tracer = get_tracer()
            if not tracer:
                return await func(*args, **kwargs)
            
            span_name = operation_name or f"{func.__module__}.{func.__name__}"
            span = tracer.start_span(span_name, kind=kind, tags=tags)
            
            try:
                result = await func(*args, **kwargs)
                span.status = SpanStatus.OK
                return result
            except Exception as e:
                tracer.record_exception(e, span)
                raise
            finally:
                tracer.finish_span(span)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            tracer = get_tracer()
            if not tracer:
                return func(*args, **kwargs)
            
            span_name = operation_name or f"{func.__module__}.{func.__name__}"
            span = tracer.start_span(span_name, kind=kind, tags=tags)
            
            try:
                result = func(*args, **kwargs)
                span.status = SpanStatus.OK
                return result
            except Exception as e:
                tracer.record_exception(e, span)
                raise
            finally:
                tracer.finish_span(span)
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    return decorator


# Global tracer instance
global_tracer: Optional[DistributedTracer] = None


def get_tracer() -> Optional[DistributedTracer]:
    """Get the global tracer instance."""
    return global_tracer


async def initialize_tracer(service_name: str, db_path: str = "performance_metrics.db",
                          sampling_probability: float = 1.0) -> DistributedTracer:
    """Initialize the global tracer."""
    global global_tracer
    
    tracer = DistributedTracer(service_name, db_path)
    tracer.sampler = ProbabilitySampler(sampling_probability)
    
    await tracer.initialize()
    global_tracer = tracer
    
    return tracer