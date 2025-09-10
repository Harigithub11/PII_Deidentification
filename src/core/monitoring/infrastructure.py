"""
Infrastructure Monitoring System

Deep system monitoring with container/process-level resource tracking,
network performance monitoring, storage performance analysis, and
dependency health monitoring. This implements Phase 8.4.
"""

import asyncio
import logging
import time
import psutil
import socket
import json
import aiohttp
import aiofiles
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import aiosqlite
import uuid
import subprocess
import platform
import shutil
import pathlib

logger = logging.getLogger(__name__)


class ResourceType(Enum):
    """Types of infrastructure resources."""
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    PROCESS = "process"
    CONTAINER = "container"
    SERVICE = "service"
    DATABASE = "database"
    EXTERNAL_API = "external_api"


class HealthStatus(Enum):
    """Health status enumeration."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    MAINTENANCE = "maintenance"


@dataclass
class ResourceMetrics:
    """Infrastructure resource metrics."""
    resource_id: str
    resource_type: ResourceType
    timestamp: datetime
    status: HealthStatus
    metrics: Dict[str, float]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'resource_id': self.resource_id,
            'resource_type': self.resource_type.value,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status.value,
            'metrics': self.metrics,
            'metadata': self.metadata
        }


@dataclass
class DependencyHealth:
    """External dependency health status."""
    dependency_id: str
    name: str
    url: str
    status: HealthStatus
    response_time_ms: float
    last_check: datetime
    error_message: Optional[str] = None
    uptime_percentage: float = 100.0
    check_count: int = 0
    failure_count: int = 0
    
    def update_status(self, is_healthy: bool, response_time: float, error: Optional[str] = None):
        """Update dependency health status."""
        self.check_count += 1
        self.response_time_ms = response_time
        self.last_check = datetime.now(timezone.utc)
        self.error_message = error
        
        if not is_healthy:
            self.failure_count += 1
            self.status = HealthStatus.UNHEALTHY
        else:
            self.status = HealthStatus.HEALTHY
        
        # Update uptime percentage
        self.uptime_percentage = ((self.check_count - self.failure_count) / self.check_count) * 100


@dataclass
class NetworkInterface:
    """Network interface information."""
    name: str
    ip_address: str
    is_up: bool
    speed_mbps: int
    mtu: int
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    errors_in: int
    errors_out: int
    drops_in: int
    drops_out: int


@dataclass
class StorageDevice:
    """Storage device information."""
    device: str
    mountpoint: str
    filesystem: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    usage_percent: float
    read_count: int
    write_count: int
    read_bytes: int
    write_bytes: int
    read_time_ms: int
    write_time_ms: int


class SystemResourceMonitor:
    """Deep system resource monitoring."""
    
    def __init__(self, collection_interval: int = 60):
        self.collection_interval = collection_interval
        self.process = psutil.Process()
        self.system_info = self._get_system_info()
        
        # Resource history
        self.cpu_history = deque(maxlen=1440)  # 24 hours at 1-minute intervals
        self.memory_history = deque(maxlen=1440)
        self.disk_history = deque(maxlen=1440)
        self.network_history = deque(maxlen=1440)
        
        # Baseline measurements
        self.baseline_metrics = {}
        self.performance_thresholds = {
            'cpu_usage_critical': 90.0,
            'cpu_usage_warning': 80.0,
            'memory_usage_critical': 95.0,
            'memory_usage_warning': 85.0,
            'disk_usage_critical': 95.0,
            'disk_usage_warning': 85.0,
            'network_error_rate_critical': 0.1,
            'network_error_rate_warning': 0.05
        }
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get static system information."""
        try:
            return {
                'platform': platform.platform(),
                'processor': platform.processor(),
                'architecture': platform.architecture()[0],
                'hostname': socket.gethostname(),
                'cpu_count': psutil.cpu_count(),
                'cpu_count_logical': psutil.cpu_count(logical=True),
                'memory_total': psutil.virtual_memory().total,
                'boot_time': datetime.fromtimestamp(psutil.boot_time(), timezone.utc),
                'python_version': platform.python_version()
            }
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {}
    
    async def collect_cpu_metrics(self) -> ResourceMetrics:
        """Collect CPU metrics."""
        try:
            # CPU usage and load
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_times = psutil.cpu_times()
            load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)
            
            # Per-CPU usage
            cpu_per_core = psutil.cpu_percent(percpu=True)
            
            # CPU frequency
            cpu_freq = psutil.cpu_freq()
            
            metrics = {
                'usage_percent': cpu_percent,
                'user_time': cpu_times.user,
                'system_time': cpu_times.system,
                'idle_time': cpu_times.idle,
                'load_1m': load_avg[0],
                'load_5m': load_avg[1],
                'load_15m': load_avg[2],
                'cores_count': len(cpu_per_core),
                'frequency_current_mhz': cpu_freq.current if cpu_freq else 0,
                'frequency_max_mhz': cpu_freq.max if cpu_freq else 0
            }
            
            # Add per-core usage
            for i, core_usage in enumerate(cpu_per_core):
                metrics[f'core_{i}_usage_percent'] = core_usage
            
            # Determine status
            status = HealthStatus.HEALTHY
            if cpu_percent >= self.performance_thresholds['cpu_usage_critical']:
                status = HealthStatus.UNHEALTHY
            elif cpu_percent >= self.performance_thresholds['cpu_usage_warning']:
                status = HealthStatus.DEGRADED
            
            resource_metrics = ResourceMetrics(
                resource_id="system_cpu",
                resource_type=ResourceType.CPU,
                timestamp=datetime.now(timezone.utc),
                status=status,
                metrics=metrics,
                metadata={'system_info': self.system_info}
            )
            
            self.cpu_history.append(resource_metrics)
            return resource_metrics
            
        except Exception as e:
            logger.error(f"Error collecting CPU metrics: {e}")
            return ResourceMetrics(
                "system_cpu", ResourceType.CPU, datetime.now(timezone.utc),
                HealthStatus.UNKNOWN, {}, {'error': str(e)}
            )
    
    async def collect_memory_metrics(self) -> ResourceMetrics:
        """Collect memory metrics."""
        try:
            # Virtual memory
            virtual_memory = psutil.virtual_memory()
            
            # Swap memory
            swap_memory = psutil.swap_memory()
            
            # Process memory
            process_memory = self.process.memory_info()
            
            metrics = {
                'total_bytes': virtual_memory.total,
                'available_bytes': virtual_memory.available,
                'used_bytes': virtual_memory.used,
                'usage_percent': virtual_memory.percent,
                'free_bytes': virtual_memory.free,
                'active_bytes': getattr(virtual_memory, 'active', 0),
                'inactive_bytes': getattr(virtual_memory, 'inactive', 0),
                'buffers_bytes': getattr(virtual_memory, 'buffers', 0),
                'cached_bytes': getattr(virtual_memory, 'cached', 0),
                'swap_total_bytes': swap_memory.total,
                'swap_used_bytes': swap_memory.used,
                'swap_usage_percent': swap_memory.percent,
                'process_rss_bytes': process_memory.rss,
                'process_vms_bytes': process_memory.vms
            }
            
            # Memory growth rate (if we have history)
            if self.memory_history:
                prev_metrics = self.memory_history[-1]
                time_diff = (datetime.now(timezone.utc) - prev_metrics.timestamp).total_seconds()
                if time_diff > 0:
                    usage_diff = metrics['used_bytes'] - prev_metrics.metrics.get('used_bytes', 0)
                    metrics['growth_rate_bytes_per_second'] = usage_diff / time_diff
            
            # Determine status
            status = HealthStatus.HEALTHY
            if virtual_memory.percent >= self.performance_thresholds['memory_usage_critical']:
                status = HealthStatus.UNHEALTHY
            elif virtual_memory.percent >= self.performance_thresholds['memory_usage_warning']:
                status = HealthStatus.DEGRADED
            
            resource_metrics = ResourceMetrics(
                resource_id="system_memory",
                resource_type=ResourceType.MEMORY,
                timestamp=datetime.now(timezone.utc),
                status=status,
                metrics=metrics
            )
            
            self.memory_history.append(resource_metrics)
            return resource_metrics
            
        except Exception as e:
            logger.error(f"Error collecting memory metrics: {e}")
            return ResourceMetrics(
                "system_memory", ResourceType.MEMORY, datetime.now(timezone.utc),
                HealthStatus.UNKNOWN, {}, {'error': str(e)}
            )
    
    async def collect_disk_metrics(self) -> List[ResourceMetrics]:
        """Collect disk metrics for all mounted filesystems."""
        disk_metrics = []
        
        try:
            # Get all disk partitions
            partitions = psutil.disk_partitions()
            
            # Get disk I/O counters
            disk_io = psutil.disk_io_counters(perdisk=True)
            
            for partition in partitions:
                try:
                    # Skip special filesystems
                    if partition.fstype in ['', 'tmpfs', 'devtmpfs', 'squashfs']:
                        continue
                    
                    # Get disk usage
                    disk_usage = psutil.disk_usage(partition.mountpoint)
                    
                    # Get I/O stats for this disk
                    device_name = partition.device.split('/')[-1]
                    io_stats = disk_io.get(device_name, None)
                    
                    metrics = {
                        'total_bytes': disk_usage.total,
                        'used_bytes': disk_usage.used,
                        'free_bytes': disk_usage.free,
                        'usage_percent': (disk_usage.used / disk_usage.total) * 100,
                        'filesystem': partition.fstype,
                        'mount_options': ','.join(partition.opts) if partition.opts else ''
                    }
                    
                    if io_stats:
                        metrics.update({
                            'read_count': io_stats.read_count,
                            'write_count': io_stats.write_count,
                            'read_bytes': io_stats.read_bytes,
                            'write_bytes': io_stats.write_bytes,
                            'read_time_ms': io_stats.read_time,
                            'write_time_ms': io_stats.write_time
                        })
                        
                        # Calculate rates if we have history
                        prev_disk_metrics = None
                        for prev_resource in self.disk_history:
                            if prev_resource.resource_id == f"disk_{device_name}":
                                prev_disk_metrics = prev_resource
                                break
                        
                        if prev_disk_metrics:
                            time_diff = (datetime.now(timezone.utc) - prev_disk_metrics.timestamp).total_seconds()
                            if time_diff > 0:
                                read_bytes_diff = io_stats.read_bytes - prev_disk_metrics.metrics.get('read_bytes', 0)
                                write_bytes_diff = io_stats.write_bytes - prev_disk_metrics.metrics.get('write_bytes', 0)
                                
                                metrics['read_rate_bytes_per_second'] = read_bytes_diff / time_diff
                                metrics['write_rate_bytes_per_second'] = write_bytes_diff / time_diff
                    
                    # Determine status
                    status = HealthStatus.HEALTHY
                    usage_percent = metrics['usage_percent']
                    if usage_percent >= self.performance_thresholds['disk_usage_critical']:
                        status = HealthStatus.UNHEALTHY
                    elif usage_percent >= self.performance_thresholds['disk_usage_warning']:
                        status = HealthStatus.DEGRADED
                    
                    resource_metrics = ResourceMetrics(
                        resource_id=f"disk_{device_name}",
                        resource_type=ResourceType.DISK,
                        timestamp=datetime.now(timezone.utc),
                        status=status,
                        metrics=metrics,
                        metadata={
                            'device': partition.device,
                            'mountpoint': partition.mountpoint,
                            'filesystem': partition.fstype
                        }
                    )
                    
                    disk_metrics.append(resource_metrics)
                    
                except Exception as e:
                    logger.debug(f"Error collecting metrics for partition {partition.device}: {e}")
                    continue
            
            # Update disk history
            self.disk_history.extend(disk_metrics)
            
        except Exception as e:
            logger.error(f"Error collecting disk metrics: {e}")
        
        return disk_metrics
    
    async def collect_network_metrics(self) -> List[ResourceMetrics]:
        """Collect network interface metrics."""
        network_metrics = []
        
        try:
            # Get network I/O statistics
            net_io = psutil.net_io_counters(pernic=True)
            
            # Get network interface addresses
            net_if_addrs = psutil.net_if_addrs()
            
            # Get network interface stats
            net_if_stats = psutil.net_if_stats()
            
            for interface_name, io_stats in net_io.items():
                try:
                    # Skip loopback and inactive interfaces
                    if interface_name.startswith('lo'):
                        continue
                    
                    # Get interface details
                    if_addrs = net_if_addrs.get(interface_name, [])
                    if_stats = net_if_stats.get(interface_name)
                    
                    # Get IP addresses
                    ip_addresses = []
                    for addr in if_addrs:
                        if addr.family == socket.AF_INET:
                            ip_addresses.append(addr.address)
                    
                    metrics = {
                        'bytes_sent': io_stats.bytes_sent,
                        'bytes_received': io_stats.bytes_recv,
                        'packets_sent': io_stats.packets_sent,
                        'packets_received': io_stats.packets_recv,
                        'errors_in': io_stats.errin,
                        'errors_out': io_stats.errout,
                        'drops_in': io_stats.dropin,
                        'drops_out': io_stats.dropout
                    }
                    
                    if if_stats:
                        metrics.update({
                            'is_up': if_stats.isup,
                            'duplex': if_stats.duplex.name if if_stats.duplex else 'unknown',
                            'speed_mbps': if_stats.speed,
                            'mtu': if_stats.mtu
                        })
                    
                    # Calculate rates and error rates if we have history
                    prev_net_metrics = None
                    for prev_resource in self.network_history:
                        if prev_resource.resource_id == f"network_{interface_name}":
                            prev_net_metrics = prev_resource
                            break
                    
                    if prev_net_metrics:
                        time_diff = (datetime.now(timezone.utc) - prev_net_metrics.timestamp).total_seconds()
                        if time_diff > 0:
                            bytes_sent_diff = io_stats.bytes_sent - prev_net_metrics.metrics.get('bytes_sent', 0)
                            bytes_recv_diff = io_stats.bytes_recv - prev_net_metrics.metrics.get('bytes_received', 0)
                            
                            metrics['send_rate_bytes_per_second'] = bytes_sent_diff / time_diff
                            metrics['receive_rate_bytes_per_second'] = bytes_recv_diff / time_diff
                            
                            # Error rates
                            total_packets = io_stats.packets_sent + io_stats.packets_recv
                            total_errors = io_stats.errin + io_stats.errout
                            if total_packets > 0:
                                metrics['error_rate'] = total_errors / total_packets
                    
                    # Determine status
                    status = HealthStatus.HEALTHY
                    if not if_stats or not if_stats.isup:
                        status = HealthStatus.UNHEALTHY
                    else:
                        error_rate = metrics.get('error_rate', 0)
                        if error_rate >= self.performance_thresholds['network_error_rate_critical']:
                            status = HealthStatus.UNHEALTHY
                        elif error_rate >= self.performance_thresholds['network_error_rate_warning']:
                            status = HealthStatus.DEGRADED
                    
                    resource_metrics = ResourceMetrics(
                        resource_id=f"network_{interface_name}",
                        resource_type=ResourceType.NETWORK,
                        timestamp=datetime.now(timezone.utc),
                        status=status,
                        metrics=metrics,
                        metadata={
                            'interface_name': interface_name,
                            'ip_addresses': ip_addresses
                        }
                    )
                    
                    network_metrics.append(resource_metrics)
                    
                except Exception as e:
                    logger.debug(f"Error collecting metrics for interface {interface_name}: {e}")
                    continue
            
            # Update network history
            self.network_history.extend(network_metrics)
            
        except Exception as e:
            logger.error(f"Error collecting network metrics: {e}")
        
        return network_metrics
    
    async def collect_process_metrics(self) -> List[ResourceMetrics]:
        """Collect metrics for running processes."""
        process_metrics = []
        
        try:
            # Get all running processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status']):
                try:
                    proc_info = proc.info
                    if proc_info['status'] != psutil.STATUS_ZOMBIE:
                        processes.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU usage and take top 10
            processes.sort(key=lambda p: p.info.get('cpu_percent', 0), reverse=True)
            top_processes = processes[:10]
            
            for proc in top_processes:
                try:
                    proc_info = proc.info
                    memory_info = proc_info.get('memory_info')
                    
                    metrics = {
                        'cpu_percent': proc_info.get('cpu_percent', 0),
                        'memory_rss_bytes': memory_info.rss if memory_info else 0,
                        'memory_vms_bytes': memory_info.vms if memory_info else 0,
                        'memory_percent': proc.memory_percent() if hasattr(proc, 'memory_percent') else 0,
                        'num_threads': proc.num_threads() if hasattr(proc, 'num_threads') else 0,
                        'status': proc_info.get('status', 'unknown')
                    }
                    
                    # Try to get additional process info
                    try:
                        metrics['num_fds'] = proc.num_fds() if hasattr(proc, 'num_fds') else 0
                        metrics['create_time'] = proc.create_time() if hasattr(proc, 'create_time') else 0
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # Determine status based on resource usage
                    status = HealthStatus.HEALTHY
                    if metrics['cpu_percent'] > 80 or metrics['memory_percent'] > 80:
                        status = HealthStatus.DEGRADED
                    
                    resource_metrics = ResourceMetrics(
                        resource_id=f"process_{proc_info['pid']}",
                        resource_type=ResourceType.PROCESS,
                        timestamp=datetime.now(timezone.utc),
                        status=status,
                        metrics=metrics,
                        metadata={
                            'pid': proc_info['pid'],
                            'name': proc_info['name']
                        }
                    )
                    
                    process_metrics.append(resource_metrics)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
        except Exception as e:
            logger.error(f"Error collecting process metrics: {e}")
        
        return process_metrics


class DependencyHealthMonitor:
    """Monitor external dependency health."""
    
    def __init__(self):
        self.dependencies: Dict[str, DependencyHealth] = {}
        self.check_interval = 300  # 5 minutes
        self.timeout_seconds = 30
        self.user_agent = "Infrastructure-Monitor/1.0"
    
    def add_dependency(self, dependency_id: str, name: str, url: str, 
                      check_type: str = 'http'):
        """Add a dependency to monitor."""
        self.dependencies[dependency_id] = DependencyHealth(
            dependency_id=dependency_id,
            name=name,
            url=url,
            status=HealthStatus.UNKNOWN,
            response_time_ms=0,
            last_check=datetime.now(timezone.utc)
        )
    
    async def check_http_dependency(self, dependency: DependencyHealth) -> Tuple[bool, float, Optional[str]]:
        """Check HTTP/HTTPS dependency health."""
        start_time = time.time()
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
            headers = {'User-Agent': self.user_agent}
            
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(dependency.url) as response:
                    response_time = (time.time() - start_time) * 1000
                    
                    # Consider 2xx and 3xx as healthy
                    is_healthy = 200 <= response.status < 400
                    error_message = None if is_healthy else f"HTTP {response.status}"
                    
                    return is_healthy, response_time, error_message
                    
        except asyncio.TimeoutError:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, "Timeout"
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, str(e)
    
    async def check_database_dependency(self, dependency: DependencyHealth) -> Tuple[bool, float, Optional[str]]:
        """Check database dependency health."""
        start_time = time.time()
        
        try:
            # This is a simplified check - in practice you'd use actual DB connections
            # For now, we'll do a basic network connectivity check
            
            # Parse URL to get host and port
            from urllib.parse import urlparse
            parsed = urlparse(dependency.url)
            host = parsed.hostname or 'localhost'
            port = parsed.port or 5432
            
            # Test TCP connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout_seconds
            )
            
            writer.close()
            await writer.wait_closed()
            
            response_time = (time.time() - start_time) * 1000
            return True, response_time, None
            
        except asyncio.TimeoutError:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, "Connection timeout"
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, str(e)
    
    async def check_all_dependencies(self) -> List[DependencyHealth]:
        """Check health of all dependencies."""
        results = []
        
        for dependency in self.dependencies.values():
            try:
                # Determine check type based on URL
                if dependency.url.startswith(('http://', 'https://')):
                    is_healthy, response_time, error = await self.check_http_dependency(dependency)
                elif dependency.url.startswith(('postgresql://', 'mysql://', 'mongodb://')):
                    is_healthy, response_time, error = await self.check_database_dependency(dependency)
                else:
                    # Default to HTTP check
                    is_healthy, response_time, error = await self.check_http_dependency(dependency)
                
                dependency.update_status(is_healthy, response_time, error)
                results.append(dependency)
                
            except Exception as e:
                logger.error(f"Error checking dependency {dependency.dependency_id}: {e}")
                dependency.update_status(False, 0, str(e))
                results.append(dependency)
        
        return results
    
    def get_dependency_summary(self) -> Dict[str, Any]:
        """Get summary of dependency health."""
        if not self.dependencies:
            return {'total': 0, 'healthy': 0, 'unhealthy': 0, 'unknown': 0}
        
        status_counts = defaultdict(int)
        total_response_time = 0
        
        for dep in self.dependencies.values():
            status_counts[dep.status.value] += 1
            total_response_time += dep.response_time_ms
        
        avg_response_time = total_response_time / len(self.dependencies) if self.dependencies else 0
        
        return {
            'total': len(self.dependencies),
            'healthy': status_counts['healthy'],
            'unhealthy': status_counts['unhealthy'],
            'degraded': status_counts['degraded'],
            'unknown': status_counts['unknown'],
            'average_response_time_ms': avg_response_time,
            'dependencies': [
                {
                    'id': dep.dependency_id,
                    'name': dep.name,
                    'status': dep.status.value,
                    'response_time_ms': dep.response_time_ms,
                    'uptime_percentage': dep.uptime_percentage,
                    'last_check': dep.last_check.isoformat(),
                    'error_message': dep.error_message
                }
                for dep in self.dependencies.values()
            ]
        }


class InfrastructureMonitor:
    """
    Comprehensive infrastructure monitoring system that coordinates
    system resource monitoring and dependency health checking.
    """
    
    def __init__(self, db_path: str = "performance_metrics.db"):
        self.db_path = db_path
        self.system_monitor = SystemResourceMonitor()
        self.dependency_monitor = DependencyHealthMonitor()
        
        # Configuration
        self.enabled = True
        self.collection_interval = 60  # seconds
        self.dependency_check_interval = 300  # 5 minutes
        
        # Monitoring state
        self.running = False
        self.monitoring_task: Optional[asyncio.Task] = None
        self.dependency_task: Optional[asyncio.Task] = None
        
        # Performance data
        self.resource_cache: Dict[str, ResourceMetrics] = {}
        self.cache_ttl = 120  # seconds
        
        # Alerts integration
        self.alert_callbacks: List[Callable] = []
    
    async def initialize(self):
        """Initialize the infrastructure monitor."""
        await self._create_infrastructure_tables()
        await self._setup_default_dependencies()
        
        logger.info("Infrastructure Monitor initialized")
    
    async def _create_infrastructure_tables(self):
        """Create infrastructure monitoring tables."""
        async with aiosqlite.connect(self.db_path) as db:
            # Infrastructure metrics table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS infrastructure_metrics (
                    id TEXT PRIMARY KEY,
                    resource_id TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    metrics TEXT NOT NULL,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Dependency health table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS dependency_health (
                    dependency_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    status TEXT NOT NULL,
                    response_time_ms REAL NOT NULL,
                    last_check TEXT NOT NULL,
                    error_message TEXT,
                    uptime_percentage REAL DEFAULT 100.0,
                    check_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Infrastructure alerts table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS infrastructure_alerts (
                    id TEXT PRIMARY KEY,
                    resource_id TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    triggered_at TEXT NOT NULL,
                    resolved_at TEXT,
                    is_resolved BOOLEAN DEFAULT FALSE,
                    threshold_value REAL,
                    current_value REAL,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_infrastructure_metrics_resource ON infrastructure_metrics(resource_id, timestamp)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_infrastructure_metrics_type ON infrastructure_metrics(resource_type, timestamp)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_dependency_health_status ON dependency_health(status, last_check)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_infrastructure_alerts_resource ON infrastructure_alerts(resource_id, triggered_at)")
            
            await db.commit()
    
    async def _setup_default_dependencies(self):
        """Setup default dependencies to monitor."""
        # Example dependencies - would be configurable
        default_deps = [
            {
                'id': 'database_primary',
                'name': 'Primary Database',
                'url': 'postgresql://localhost:5432/app_db'
            },
            {
                'id': 'cache_redis',
                'name': 'Redis Cache',
                'url': 'redis://localhost:6379'
            }
        ]
        
        for dep in default_deps:
            self.dependency_monitor.add_dependency(
                dep['id'], dep['name'], dep['url']
            )
    
    async def start_monitoring(self):
        """Start infrastructure monitoring."""
        if self.running:
            return
        
        self.running = True
        
        # Start monitoring tasks
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        self.dependency_task = asyncio.create_task(self._dependency_monitoring_loop())
        
        logger.info("Infrastructure monitoring started")
    
    async def stop_monitoring(self):
        """Stop infrastructure monitoring."""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel monitoring tasks
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        if self.dependency_task:
            self.dependency_task.cancel()
            try:
                await self.dependency_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Infrastructure monitoring stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop for system resources."""
        while self.running:
            try:
                # Collect all resource metrics
                all_metrics = []
                
                # CPU metrics
                cpu_metrics = await self.system_monitor.collect_cpu_metrics()
                all_metrics.append(cpu_metrics)
                
                # Memory metrics
                memory_metrics = await self.system_monitor.collect_memory_metrics()
                all_metrics.append(memory_metrics)
                
                # Disk metrics
                disk_metrics = await self.system_monitor.collect_disk_metrics()
                all_metrics.extend(disk_metrics)
                
                # Network metrics
                network_metrics = await self.system_monitor.collect_network_metrics()
                all_metrics.extend(network_metrics)
                
                # Process metrics
                process_metrics = await self.system_monitor.collect_process_metrics()
                all_metrics.extend(process_metrics)
                
                # Store metrics
                await self._store_metrics(all_metrics)
                
                # Update cache
                for metrics in all_metrics:
                    self.resource_cache[metrics.resource_id] = metrics
                
                # Check for alerts
                await self._check_resource_alerts(all_metrics)
                
                await asyncio.sleep(self.collection_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(self.collection_interval)
    
    async def _dependency_monitoring_loop(self):
        """Dependency health monitoring loop."""
        while self.running:
            try:
                # Check all dependencies
                dependency_results = await self.dependency_monitor.check_all_dependencies()
                
                # Store dependency health
                await self._store_dependency_health(dependency_results)
                
                # Check for dependency alerts
                await self._check_dependency_alerts(dependency_results)
                
                await asyncio.sleep(self.dependency_check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in dependency monitoring loop: {e}")
                await asyncio.sleep(self.dependency_check_interval)
    
    async def _store_metrics(self, metrics_list: List[ResourceMetrics]):
        """Store infrastructure metrics."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                for metrics in metrics_list:
                    await db.execute("""
                        INSERT INTO infrastructure_metrics 
                        (id, resource_id, resource_type, timestamp, status, metrics, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        str(uuid.uuid4()),
                        metrics.resource_id,
                        metrics.resource_type.value,
                        metrics.timestamp.isoformat(),
                        metrics.status.value,
                        json.dumps(metrics.metrics),
                        json.dumps(metrics.metadata)
                    ))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error storing infrastructure metrics: {e}")
    
    async def _store_dependency_health(self, dependencies: List[DependencyHealth]):
        """Store dependency health status."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                for dep in dependencies:
                    await db.execute("""
                        INSERT OR REPLACE INTO dependency_health 
                        (dependency_id, name, url, status, response_time_ms, last_check,
                         error_message, uptime_percentage, check_count, failure_count, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        dep.dependency_id,
                        dep.name,
                        dep.url,
                        dep.status.value,
                        dep.response_time_ms,
                        dep.last_check.isoformat(),
                        dep.error_message,
                        dep.uptime_percentage,
                        dep.check_count,
                        dep.failure_count,
                        datetime.now(timezone.utc).isoformat()
                    ))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error storing dependency health: {e}")
    
    async def _check_resource_alerts(self, metrics_list: List[ResourceMetrics]):
        """Check for resource-based alerts."""
        alerts = []
        
        for metrics in metrics_list:
            if metrics.status == HealthStatus.UNHEALTHY:
                alert_id = str(uuid.uuid4())
                
                # Determine alert details based on resource type
                if metrics.resource_type == ResourceType.CPU:
                    cpu_usage = metrics.metrics.get('usage_percent', 0)
                    if cpu_usage >= self.system_monitor.performance_thresholds['cpu_usage_critical']:
                        alerts.append({
                            'id': alert_id,
                            'resource_id': metrics.resource_id,
                            'alert_type': 'high_cpu_usage',
                            'severity': 'critical',
                            'message': f'CPU usage at {cpu_usage:.1f}% (threshold: {self.system_monitor.performance_thresholds["cpu_usage_critical"]}%)',
                            'current_value': cpu_usage,
                            'threshold_value': self.system_monitor.performance_thresholds['cpu_usage_critical']
                        })
                
                elif metrics.resource_type == ResourceType.MEMORY:
                    memory_usage = metrics.metrics.get('usage_percent', 0)
                    if memory_usage >= self.system_monitor.performance_thresholds['memory_usage_critical']:
                        alerts.append({
                            'id': alert_id,
                            'resource_id': metrics.resource_id,
                            'alert_type': 'high_memory_usage',
                            'severity': 'critical',
                            'message': f'Memory usage at {memory_usage:.1f}% (threshold: {self.system_monitor.performance_thresholds["memory_usage_critical"]}%)',
                            'current_value': memory_usage,
                            'threshold_value': self.system_monitor.performance_thresholds['memory_usage_critical']
                        })
                
                elif metrics.resource_type == ResourceType.DISK:
                    disk_usage = metrics.metrics.get('usage_percent', 0)
                    if disk_usage >= self.system_monitor.performance_thresholds['disk_usage_critical']:
                        alerts.append({
                            'id': alert_id,
                            'resource_id': metrics.resource_id,
                            'alert_type': 'high_disk_usage',
                            'severity': 'critical',
                            'message': f'Disk usage at {disk_usage:.1f}% (threshold: {self.system_monitor.performance_thresholds["disk_usage_critical"]}%)',
                            'current_value': disk_usage,
                            'threshold_value': self.system_monitor.performance_thresholds['disk_usage_critical']
                        })
        
        if alerts:
            await self._store_infrastructure_alerts(alerts)
    
    async def _check_dependency_alerts(self, dependencies: List[DependencyHealth]):
        """Check for dependency-based alerts."""
        alerts = []
        
        for dep in dependencies:
            if dep.status == HealthStatus.UNHEALTHY:
                alert_id = str(uuid.uuid4())
                alerts.append({
                    'id': alert_id,
                    'resource_id': dep.dependency_id,
                    'alert_type': 'dependency_unhealthy',
                    'severity': 'high',
                    'message': f'Dependency {dep.name} is unhealthy: {dep.error_message or "Unknown error"}',
                    'current_value': dep.response_time_ms,
                    'threshold_value': self.dependency_monitor.timeout_seconds * 1000
                })
        
        if alerts:
            await self._store_infrastructure_alerts(alerts)
    
    async def _store_infrastructure_alerts(self, alerts: List[Dict[str, Any]]):
        """Store infrastructure alerts."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                for alert in alerts:
                    await db.execute("""
                        INSERT INTO infrastructure_alerts 
                        (id, resource_id, alert_type, severity, message, triggered_at,
                         threshold_value, current_value, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        alert['id'],
                        alert['resource_id'],
                        alert['alert_type'],
                        alert['severity'],
                        alert['message'],
                        datetime.now(timezone.utc).isoformat(),
                        alert.get('threshold_value'),
                        alert.get('current_value'),
                        json.dumps({})
                    ))
                
                await db.commit()
                
                # Trigger alert callbacks
                for callback in self.alert_callbacks:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            await callback(alerts)
                        else:
                            callback(alerts)
                    except Exception as e:
                        logger.error(f"Error in alert callback: {e}")
                
        except Exception as e:
            logger.error(f"Error storing infrastructure alerts: {e}")
    
    async def get_infrastructure_summary(self) -> Dict[str, Any]:
        """Get comprehensive infrastructure summary."""
        try:
            # Get latest metrics for each resource type
            resource_summary = {}
            
            for resource_id, metrics in self.resource_cache.items():
                resource_type = metrics.resource_type.value
                if resource_type not in resource_summary:
                    resource_summary[resource_type] = []
                
                resource_summary[resource_type].append({
                    'resource_id': resource_id,
                    'status': metrics.status.value,
                    'key_metrics': self._extract_key_metrics(metrics),
                    'last_updated': metrics.timestamp.isoformat()
                })
            
            # Get dependency summary
            dependency_summary = self.dependency_monitor.get_dependency_summary()
            
            # Get recent alerts
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT alert_type, severity, COUNT(*) as count
                    FROM infrastructure_alerts 
                    WHERE triggered_at >= ? AND is_resolved = FALSE
                    GROUP BY alert_type, severity
                """, ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),))
                
                alert_summary = {}
                async for row in cursor:
                    alert_type = row[0]
                    severity = row[1]
                    count = row[2]
                    
                    if alert_type not in alert_summary:
                        alert_summary[alert_type] = {}
                    alert_summary[alert_type][severity] = count
            
            return {
                'system_health': self._calculate_overall_health(resource_summary),
                'resources': resource_summary,
                'dependencies': dependency_summary,
                'alerts': alert_summary,
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting infrastructure summary: {e}")
            return {}
    
    def _extract_key_metrics(self, metrics: ResourceMetrics) -> Dict[str, Any]:
        """Extract key metrics for summary."""
        key_metrics = {}
        
        if metrics.resource_type == ResourceType.CPU:
            key_metrics = {
                'usage_percent': metrics.metrics.get('usage_percent'),
                'load_1m': metrics.metrics.get('load_1m')
            }
        elif metrics.resource_type == ResourceType.MEMORY:
            key_metrics = {
                'usage_percent': metrics.metrics.get('usage_percent'),
                'available_gb': (metrics.metrics.get('available_bytes', 0) / (1024**3))
            }
        elif metrics.resource_type == ResourceType.DISK:
            key_metrics = {
                'usage_percent': metrics.metrics.get('usage_percent'),
                'free_gb': (metrics.metrics.get('free_bytes', 0) / (1024**3))
            }
        elif metrics.resource_type == ResourceType.NETWORK:
            key_metrics = {
                'is_up': metrics.metrics.get('is_up'),
                'error_rate': metrics.metrics.get('error_rate', 0)
            }
        
        return key_metrics
    
    def _calculate_overall_health(self, resource_summary: Dict[str, Any]) -> str:
        """Calculate overall system health."""
        total_resources = 0
        unhealthy_resources = 0
        
        for resource_type, resources in resource_summary.items():
            for resource in resources:
                total_resources += 1
                if resource['status'] in ['unhealthy', 'degraded']:
                    unhealthy_resources += 1
        
        if total_resources == 0:
            return 'unknown'
        
        health_percentage = ((total_resources - unhealthy_resources) / total_resources) * 100
        
        if health_percentage >= 95:
            return 'healthy'
        elif health_percentage >= 80:
            return 'degraded'
        else:
            return 'unhealthy'
    
    def add_dependency(self, dependency_id: str, name: str, url: str):
        """Add a new dependency to monitor."""
        self.dependency_monitor.add_dependency(dependency_id, name, url)
    
    def add_alert_callback(self, callback: Callable):
        """Add callback for infrastructure alerts."""
        self.alert_callbacks.append(callback)


# Global infrastructure monitor instance
global_infrastructure_monitor: Optional[InfrastructureMonitor] = None


def get_infrastructure_monitor() -> Optional[InfrastructureMonitor]:
    """Get the global infrastructure monitor instance."""
    return global_infrastructure_monitor


async def initialize_infrastructure_monitor(db_path: str = "performance_metrics.db") -> InfrastructureMonitor:
    """Initialize the global infrastructure monitor."""
    global global_infrastructure_monitor
    
    monitor = InfrastructureMonitor(db_path)
    await monitor.initialize()
    global_infrastructure_monitor = monitor
    
    return monitor