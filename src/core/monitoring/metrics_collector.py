"""
Advanced Metrics Collector

Comprehensive performance data collection system that aggregates metrics from
multiple sources including system resources, application performance, and
business metrics for real-time monitoring and historical analysis.
"""

import asyncio
import logging
import time
import psutil
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
import threading
from pathlib import Path
import aiosqlite
import statistics

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of metrics that can be collected."""
    COUNTER = "counter"  # Monotonically increasing value
    GAUGE = "gauge"      # Point-in-time value
    HISTOGRAM = "histogram"  # Distribution of values
    TIMER = "timer"      # Duration measurements
    RATE = "rate"        # Events per time unit


class MetricScope(Enum):
    """Scope of metrics collection."""
    SYSTEM = "system"           # OS-level metrics
    APPLICATION = "application" # App-level metrics
    DATABASE = "database"       # DB performance metrics
    API = "api"                # API endpoint metrics
    SECURITY = "security"       # Security-related metrics
    BUSINESS = "business"       # Business logic metrics
    USER = "user"              # User behavior metrics


@dataclass
class MetricPoint:
    """Individual metric data point."""
    name: str
    value: Union[int, float]
    timestamp: datetime
    metric_type: MetricType
    scope: MetricScope
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'value': self.value,
            'timestamp': self.timestamp.isoformat(),
            'type': self.metric_type.value,
            'scope': self.scope.value,
            'tags': self.tags,
            'metadata': self.metadata
        }


@dataclass
class MetricSeries:
    """Time series of metric points."""
    name: str
    metric_type: MetricType
    scope: MetricScope
    points: List[MetricPoint] = field(default_factory=list)
    retention_hours: int = 24
    
    def add_point(self, value: Union[int, float], timestamp: Optional[datetime] = None,
                  tags: Optional[Dict[str, str]] = None, metadata: Optional[Dict[str, Any]] = None):
        """Add a new metric point."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
            
        point = MetricPoint(
            name=self.name,
            value=value,
            timestamp=timestamp,
            metric_type=self.metric_type,
            scope=self.scope,
            tags=tags or {},
            metadata=metadata or {}
        )
        
        self.points.append(point)
        self._cleanup_old_points()
    
    def _cleanup_old_points(self):
        """Remove points older than retention period."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.retention_hours)
        self.points = [p for p in self.points if p.timestamp > cutoff_time]
    
    def get_latest(self) -> Optional[MetricPoint]:
        """Get the latest metric point."""
        return self.points[-1] if self.points else None
    
    def get_range(self, start_time: datetime, end_time: datetime) -> List[MetricPoint]:
        """Get points within time range."""
        return [p for p in self.points if start_time <= p.timestamp <= end_time]
    
    def get_stats(self, minutes: int = 60) -> Dict[str, float]:
        """Get statistical summary for recent points."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        recent_points = [p for p in self.points if p.timestamp > cutoff_time]
        
        if not recent_points:
            return {}
        
        values = [p.value for p in recent_points]
        
        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'std_dev': statistics.stdev(values) if len(values) > 1 else 0.0,
            'p95': sorted(values)[int(0.95 * len(values))] if len(values) > 1 else values[0],
            'p99': sorted(values)[int(0.99 * len(values))] if len(values) > 1 else values[0]
        }


class SystemResourceCollector:
    """Collects system-level resource metrics."""
    
    def __init__(self):
        self.process = psutil.Process()
        self._disk_io_counters = psutil.disk_io_counters()
        self._network_io_counters = psutil.net_io_counters()
        self._last_cpu_times = psutil.cpu_times()
        self._collection_interval = 5  # seconds
    
    async def collect_metrics(self) -> List[MetricPoint]:
        """Collect current system resource metrics."""
        metrics = []
        timestamp = datetime.now(timezone.utc)
        
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)
            
            metrics.extend([
                MetricPoint("cpu_usage_percent", cpu_percent, timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
                MetricPoint("cpu_count", cpu_count, timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
                MetricPoint("load_average_1m", load_avg[0], timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
                MetricPoint("load_average_5m", load_avg[1], timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
                MetricPoint("load_average_15m", load_avg[2], timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
            ])
            
            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            metrics.extend([
                MetricPoint("memory_usage_percent", memory.percent, timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
                MetricPoint("memory_available_bytes", memory.available, timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
                MetricPoint("memory_total_bytes", memory.total, timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
                MetricPoint("memory_used_bytes", memory.used, timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
                MetricPoint("swap_usage_percent", swap.percent, timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
                MetricPoint("swap_used_bytes", swap.used, timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
            ])
            
            # Disk metrics
            disk_usage = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            metrics.extend([
                MetricPoint("disk_usage_percent", disk_usage.percent, timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
                MetricPoint("disk_free_bytes", disk_usage.free, timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
                MetricPoint("disk_total_bytes", disk_usage.total, timestamp, MetricType.GAUGE, MetricScope.SYSTEM),
            ])
            
            if disk_io and self._disk_io_counters:
                read_bytes_delta = disk_io.read_bytes - self._disk_io_counters.read_bytes
                write_bytes_delta = disk_io.write_bytes - self._disk_io_counters.write_bytes
                
                metrics.extend([
                    MetricPoint("disk_read_bytes_per_sec", read_bytes_delta / self._collection_interval, 
                              timestamp, MetricType.RATE, MetricScope.SYSTEM),
                    MetricPoint("disk_write_bytes_per_sec", write_bytes_delta / self._collection_interval,
                              timestamp, MetricType.RATE, MetricScope.SYSTEM),
                ])
                
                self._disk_io_counters = disk_io
            
            # Network metrics
            network_io = psutil.net_io_counters()
            
            if network_io and self._network_io_counters:
                bytes_sent_delta = network_io.bytes_sent - self._network_io_counters.bytes_sent
                bytes_recv_delta = network_io.bytes_recv - self._network_io_counters.bytes_recv
                
                metrics.extend([
                    MetricPoint("network_bytes_sent_per_sec", bytes_sent_delta / self._collection_interval,
                              timestamp, MetricType.RATE, MetricScope.SYSTEM),
                    MetricPoint("network_bytes_recv_per_sec", bytes_recv_delta / self._collection_interval,
                              timestamp, MetricType.RATE, MetricScope.SYSTEM),
                ])
                
                self._network_io_counters = network_io
            
            # Process-specific metrics
            process_memory = self.process.memory_info()
            process_cpu = self.process.cpu_percent()
            
            metrics.extend([
                MetricPoint("process_memory_rss_bytes", process_memory.rss, timestamp, MetricType.GAUGE, MetricScope.APPLICATION),
                MetricPoint("process_memory_vms_bytes", process_memory.vms, timestamp, MetricType.GAUGE, MetricScope.APPLICATION),
                MetricPoint("process_cpu_percent", process_cpu, timestamp, MetricType.GAUGE, MetricScope.APPLICATION),
                MetricPoint("process_threads", self.process.num_threads(), timestamp, MetricType.GAUGE, MetricScope.APPLICATION),
                MetricPoint("process_fds", self.process.num_fds() if hasattr(self.process, 'num_fds') else 0, 
                          timestamp, MetricType.GAUGE, MetricScope.APPLICATION),
            ])
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
        
        return metrics


class ApplicationMetricsCollector:
    """Collects application-level performance metrics."""
    
    def __init__(self):
        self.request_times = deque(maxlen=1000)
        self.request_counts = defaultdict(int)
        self.error_counts = defaultdict(int)
        self.active_requests = 0
        self.database_query_times = deque(maxlen=1000)
        self.cache_hit_rates = deque(maxlen=100)
        self._lock = threading.Lock()
    
    def record_request(self, endpoint: str, method: str, duration: float, 
                      status_code: int, user_id: Optional[str] = None):
        """Record API request metrics."""
        with self._lock:
            self.request_times.append(duration)
            self.request_counts[f"{method}:{endpoint}"] += 1
            
            if status_code >= 400:
                self.error_counts[f"{status_code}"] += 1
    
    def record_database_query(self, duration: float, query_type: str):
        """Record database query metrics."""
        with self._lock:
            self.database_query_times.append(duration)
    
    def record_cache_operation(self, hit: bool):
        """Record cache hit/miss."""
        with self._lock:
            self.cache_hit_rates.append(1 if hit else 0)
    
    def start_request(self):
        """Mark start of request processing."""
        with self._lock:
            self.active_requests += 1
    
    def end_request(self):
        """Mark end of request processing."""
        with self._lock:
            self.active_requests = max(0, self.active_requests - 1)
    
    async def collect_metrics(self) -> List[MetricPoint]:
        """Collect current application metrics."""
        metrics = []
        timestamp = datetime.now(timezone.utc)
        
        with self._lock:
            # Request metrics
            if self.request_times:
                metrics.extend([
                    MetricPoint("request_duration_avg_ms", statistics.mean(self.request_times), 
                              timestamp, MetricType.GAUGE, MetricScope.API),
                    MetricPoint("request_duration_p95_ms", 
                              sorted(self.request_times)[int(0.95 * len(self.request_times))],
                              timestamp, MetricType.GAUGE, MetricScope.API),
                    MetricPoint("request_duration_p99_ms",
                              sorted(self.request_times)[int(0.99 * len(self.request_times))],
                              timestamp, MetricType.GAUGE, MetricScope.API),
                ])
            
            # Request rate (requests per minute)
            total_requests = sum(self.request_counts.values())
            metrics.append(
                MetricPoint("requests_per_minute", total_requests, timestamp, MetricType.RATE, MetricScope.API)
            )
            
            # Error rate
            total_errors = sum(self.error_counts.values())
            error_rate = (total_errors / total_requests * 100) if total_requests > 0 else 0
            metrics.append(
                MetricPoint("error_rate_percent", error_rate, timestamp, MetricType.GAUGE, MetricScope.API)
            )
            
            # Active requests
            metrics.append(
                MetricPoint("active_requests", self.active_requests, timestamp, MetricType.GAUGE, MetricScope.API)
            )
            
            # Database metrics
            if self.database_query_times:
                metrics.extend([
                    MetricPoint("db_query_duration_avg_ms", statistics.mean(self.database_query_times),
                              timestamp, MetricType.GAUGE, MetricScope.DATABASE),
                    MetricPoint("db_query_duration_p95_ms",
                              sorted(self.database_query_times)[int(0.95 * len(self.database_query_times))],
                              timestamp, MetricType.GAUGE, MetricScope.DATABASE),
                ])
            
            # Cache metrics
            if self.cache_hit_rates:
                cache_hit_rate = statistics.mean(self.cache_hit_rates) * 100
                metrics.append(
                    MetricPoint("cache_hit_rate_percent", cache_hit_rate, timestamp, MetricType.GAUGE, MetricScope.APPLICATION)
                )
        
        return metrics


class BusinessMetricsCollector:
    """Collects business logic and PII processing metrics."""
    
    def __init__(self):
        self.documents_processed = 0
        self.pii_entities_detected = defaultdict(int)
        self.redaction_operations = 0
        self.processing_accuracy_scores = deque(maxlen=100)
        self.user_activity = defaultdict(int)
        self._lock = threading.Lock()
    
    def record_document_processed(self, file_type: str, size_bytes: int, 
                                 processing_time: float, accuracy_score: float):
        """Record document processing metrics."""
        with self._lock:
            self.documents_processed += 1
            self.processing_accuracy_scores.append(accuracy_score)
    
    def record_pii_detection(self, pii_type: str, confidence: float):
        """Record PII detection metrics."""
        with self._lock:
            self.pii_entities_detected[pii_type] += 1
    
    def record_redaction(self):
        """Record redaction operation."""
        with self._lock:
            self.redaction_operations += 1
    
    def record_user_activity(self, user_id: str, action: str):
        """Record user activity metrics."""
        with self._lock:
            self.user_activity[f"{user_id}:{action}"] += 1
    
    async def collect_metrics(self) -> List[MetricPoint]:
        """Collect current business metrics."""
        metrics = []
        timestamp = datetime.now(timezone.utc)
        
        with self._lock:
            # Document processing metrics
            metrics.extend([
                MetricPoint("documents_processed_total", self.documents_processed,
                          timestamp, MetricType.COUNTER, MetricScope.BUSINESS),
                MetricPoint("redaction_operations_total", self.redaction_operations,
                          timestamp, MetricType.COUNTER, MetricScope.BUSINESS),
            ])
            
            # PII detection metrics
            total_pii_detected = sum(self.pii_entities_detected.values())
            metrics.append(
                MetricPoint("pii_entities_detected_total", total_pii_detected,
                          timestamp, MetricType.COUNTER, MetricScope.BUSINESS)
            )
            
            # Processing accuracy
            if self.processing_accuracy_scores:
                avg_accuracy = statistics.mean(self.processing_accuracy_scores)
                metrics.append(
                    MetricPoint("processing_accuracy_percent", avg_accuracy * 100,
                              timestamp, MetricType.GAUGE, MetricScope.BUSINESS)
                )
            
            # User activity
            active_users = len(set(key.split(':')[0] for key in self.user_activity.keys()))
            metrics.append(
                MetricPoint("active_users", active_users, timestamp, MetricType.GAUGE, MetricScope.USER)
            )
        
        return metrics


class AdvancedMetricsCollector:
    """
    Main metrics collection orchestrator that coordinates multiple collectors
    and provides a unified interface for metrics aggregation and storage.
    """
    
    def __init__(self, db_path: str = "performance_metrics.db", collection_interval: int = 30):
        self.db_path = db_path
        self.collection_interval = collection_interval
        self.running = False
        
        # Initialize collectors
        self.system_collector = SystemResourceCollector()
        self.app_collector = ApplicationMetricsCollector()
        self.business_collector = BusinessMetricsCollector()
        
        # Metric storage
        self.metric_series: Dict[str, MetricSeries] = {}
        self._collection_task: Optional[asyncio.Task] = None
        
        # Callbacks for real-time metric updates
        self.metric_callbacks: List[Callable[[List[MetricPoint]], None]] = []
    
    async def initialize(self):
        """Initialize the metrics collector."""
        try:
            await self._create_database()
            logger.info("Advanced Metrics Collector initialized")
        except Exception as e:
            logger.error(f"Failed to initialize metrics collector: {e}")
            raise
    
    async def _create_database(self):
        """Create metrics database schema."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS metric_points (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    value REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    metric_type TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    tags TEXT,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS metric_aggregates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    period TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    count INTEGER,
                    min_value REAL,
                    max_value REAL,
                    avg_value REAL,
                    sum_value REAL,
                    p95_value REAL,
                    p99_value REAL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for better query performance
            await db.execute("CREATE INDEX IF NOT EXISTS idx_metric_name_time ON metric_points(name, timestamp)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_metric_scope_time ON metric_points(scope, timestamp)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_aggregate_name_period ON metric_aggregates(name, period, start_time)")
            
            await db.commit()
    
    async def start_collection(self):
        """Start the metrics collection process."""
        if self.running:
            return
        
        self.running = True
        self._collection_task = asyncio.create_task(self._collection_loop())
        logger.info("Metrics collection started")
    
    async def stop_collection(self):
        """Stop the metrics collection process."""
        if not self.running:
            return
        
        self.running = False
        if self._collection_task:
            self._collection_task.cancel()
            try:
                await self._collection_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Metrics collection stopped")
    
    async def _collection_loop(self):
        """Main collection loop."""
        while self.running:
            try:
                await self._collect_all_metrics()
                await asyncio.sleep(self.collection_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                await asyncio.sleep(self.collection_interval)
    
    async def _collect_all_metrics(self):
        """Collect metrics from all collectors."""
        all_metrics = []
        
        try:
            # Collect from all collectors in parallel
            collectors_results = await asyncio.gather(
                self.system_collector.collect_metrics(),
                self.app_collector.collect_metrics(),
                self.business_collector.collect_metrics(),
                return_exceptions=True
            )
            
            for result in collectors_results:
                if isinstance(result, list):
                    all_metrics.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"Collector error: {result}")
            
            # Store metrics
            await self._store_metrics(all_metrics)
            
            # Update in-memory series
            self._update_metric_series(all_metrics)
            
            # Trigger callbacks
            for callback in self.metric_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(all_metrics)
                    else:
                        callback(all_metrics)
                except Exception as e:
                    logger.error(f"Error in metric callback: {e}")
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
    
    async def _store_metrics(self, metrics: List[MetricPoint]):
        """Store metrics in database."""
        if not metrics:
            return
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                for metric in metrics:
                    await db.execute("""
                        INSERT INTO metric_points (name, value, timestamp, metric_type, scope, tags, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        metric.name,
                        metric.value,
                        metric.timestamp.isoformat(),
                        metric.metric_type.value,
                        metric.scope.value,
                        json.dumps(metric.tags),
                        json.dumps(metric.metadata)
                    ))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error storing metrics: {e}")
    
    def _update_metric_series(self, metrics: List[MetricPoint]):
        """Update in-memory metric series."""
        for metric in metrics:
            series_key = f"{metric.scope.value}:{metric.name}"
            
            if series_key not in self.metric_series:
                self.metric_series[series_key] = MetricSeries(
                    name=metric.name,
                    metric_type=metric.metric_type,
                    scope=metric.scope
                )
            
            self.metric_series[series_key].add_point(
                value=metric.value,
                timestamp=metric.timestamp,
                tags=metric.tags,
                metadata=metric.metadata
            )
    
    def add_metric_callback(self, callback: Callable[[List[MetricPoint]], None]):
        """Add callback for real-time metric updates."""
        self.metric_callbacks.append(callback)
    
    def remove_metric_callback(self, callback: Callable[[List[MetricPoint]], None]):
        """Remove metric callback."""
        if callback in self.metric_callbacks:
            self.metric_callbacks.remove(callback)
    
    async def get_metrics_summary(self) -> Dict[str, Any]:
        """Get current metrics summary."""
        summary = {}
        
        for series_key, series in self.metric_series.items():
            latest_point = series.get_latest()
            if latest_point:
                stats = series.get_stats(minutes=60)  # Last hour stats
                
                summary[series_key] = {
                    'current_value': latest_point.value,
                    'timestamp': latest_point.timestamp.isoformat(),
                    'stats': stats,
                    'type': series.metric_type.value,
                    'scope': series.scope.value
                }
        
        return summary
    
    async def get_metric_history(self, metric_name: str, scope: MetricScope,
                               start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Get historical metric data."""
        series_key = f"{scope.value}:{metric_name}"
        
        if series_key in self.metric_series:
            points = self.metric_series[series_key].get_range(start_time, end_time)
            return [point.to_dict() for point in points]
        
        # Fallback to database query
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT name, value, timestamp, metric_type, scope, tags, metadata
                    FROM metric_points
                    WHERE name = ? AND scope = ? AND timestamp BETWEEN ? AND ?
                    ORDER BY timestamp
                """, (metric_name, scope.value, start_time.isoformat(), end_time.isoformat()))
                
                rows = await cursor.fetchall()
                
                return [
                    {
                        'name': row[0],
                        'value': row[1],
                        'timestamp': row[2],
                        'type': row[3],
                        'scope': row[4],
                        'tags': json.loads(row[5]) if row[5] else {},
                        'metadata': json.loads(row[6]) if row[6] else {}
                    }
                    for row in rows
                ]
                
        except Exception as e:
            logger.error(f"Error querying metric history: {e}")
            return []
    
    # Convenience methods for collectors
    def record_request(self, endpoint: str, method: str, duration: float, status_code: int, user_id: Optional[str] = None):
        """Record API request metrics."""
        self.app_collector.record_request(endpoint, method, duration, status_code, user_id)
    
    def record_database_query(self, duration: float, query_type: str):
        """Record database query metrics."""
        self.app_collector.record_database_query(duration, query_type)
    
    def record_document_processed(self, file_type: str, size_bytes: int, processing_time: float, accuracy_score: float):
        """Record document processing metrics."""
        self.business_collector.record_document_processed(file_type, size_bytes, processing_time, accuracy_score)
    
    def record_pii_detection(self, pii_type: str, confidence: float):
        """Record PII detection metrics."""
        self.business_collector.record_pii_detection(pii_type, confidence)
    
    async def shutdown(self):
        """Shutdown the metrics collector."""
        await self.stop_collection()
        logger.info("Advanced Metrics Collector shutdown complete")


# Global metrics collector instance
metrics_collector: Optional[AdvancedMetricsCollector] = None


def get_metrics_collector() -> AdvancedMetricsCollector:
    """Get the global metrics collector instance."""
    global metrics_collector
    if metrics_collector is None:
        metrics_collector = AdvancedMetricsCollector()
    return metrics_collector


async def initialize_metrics_collector():
    """Initialize the global metrics collector."""
    collector = get_metrics_collector()
    await collector.initialize()
    await collector.start_collection()
    return collector