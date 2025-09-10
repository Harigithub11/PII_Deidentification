"""
Component Health Checking System

Provides comprehensive health checking capabilities for all system components
including APIs, services, databases, and external dependencies.
"""

import asyncio
import logging
import time
import traceback
import psutil
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import aiohttp
import aioredis
import sqlalchemy
from sqlalchemy import text

from .component_registry import ComponentRegistry, get_component_registry, ComponentStatus
from ..config.settings import get_settings
from ..database.session import get_db_session

logger = logging.getLogger(__name__)
settings = get_settings()


class HealthStatus(str, Enum):
    """Health check status values."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Health check result data."""
    component_name: str
    status: HealthStatus
    response_time_ms: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    message: str = ""
    error_details: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthThresholds:
    """Health check thresholds configuration."""
    response_time_warning_ms: float = 1000.0
    response_time_critical_ms: float = 5000.0
    memory_warning_percent: float = 80.0
    memory_critical_percent: float = 95.0
    disk_warning_percent: float = 85.0
    disk_critical_percent: float = 95.0
    cpu_warning_percent: float = 80.0
    cpu_critical_percent: float = 95.0


class BaseHealthChecker(ABC):
    """Base class for all health checkers."""
    
    def __init__(self, component_name: str, thresholds: Optional[HealthThresholds] = None):
        self.component_name = component_name
        self.thresholds = thresholds or HealthThresholds()
        self._last_result: Optional[HealthCheckResult] = None
        self._consecutive_failures = 0
        
    @abstractmethod
    async def check_health(self) -> HealthCheckResult:
        """Perform the health check."""
        pass
    
    async def perform_check(self) -> HealthCheckResult:
        """Perform health check with error handling and timing."""
        start_time = time.time()
        
        try:
            result = await self.check_health()
            
            # Calculate response time if not set
            if result.response_time_ms == 0:
                result.response_time_ms = (time.time() - start_time) * 1000
            
            # Update consecutive failure count
            if result.status == HealthStatus.HEALTHY:
                self._consecutive_failures = 0
            else:
                self._consecutive_failures += 1
            
            # Add consecutive failure info to metadata
            result.metadata["consecutive_failures"] = self._consecutive_failures
            
            self._last_result = result
            return result
            
        except Exception as e:
            self._consecutive_failures += 1
            response_time = (time.time() - start_time) * 1000
            
            error_result = HealthCheckResult(
                component_name=self.component_name,
                status=HealthStatus.UNHEALTHY,
                response_time_ms=response_time,
                message=f"Health check failed: {str(e)}",
                error_details=traceback.format_exc(),
                metadata={
                    "consecutive_failures": self._consecutive_failures,
                    "exception_type": type(e).__name__
                }
            )
            
            self._last_result = error_result
            return error_result
    
    def get_last_result(self) -> Optional[HealthCheckResult]:
        """Get the last health check result."""
        return self._last_result
    
    def _determine_status_by_response_time(self, response_time_ms: float) -> HealthStatus:
        """Determine health status based on response time."""
        if response_time_ms > self.thresholds.response_time_critical_ms:
            return HealthStatus.UNHEALTHY
        elif response_time_ms > self.thresholds.response_time_warning_ms:
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY


class APIEndpointHealthChecker(BaseHealthChecker):
    """Health checker for API endpoints."""
    
    def __init__(
        self, 
        component_name: str, 
        endpoint_url: str,
        method: str = "GET",
        timeout: float = 30.0,
        expected_status_codes: List[int] = None,
        headers: Optional[Dict[str, str]] = None,
        thresholds: Optional[HealthThresholds] = None
    ):
        super().__init__(component_name, thresholds)
        self.endpoint_url = endpoint_url
        self.method = method.upper()
        self.timeout = timeout
        self.expected_status_codes = expected_status_codes or [200, 201, 204]
        self.headers = headers or {}
    
    async def check_health(self) -> HealthCheckResult:
        """Check API endpoint health."""
        start_time = time.time()
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            try:
                async with session.request(
                    self.method, 
                    self.endpoint_url, 
                    headers=self.headers
                ) as response:
                    response_time = (time.time() - start_time) * 1000
                    
                    # Determine status
                    if response.status in self.expected_status_codes:
                        status = self._determine_status_by_response_time(response_time)
                        message = f"API endpoint responding normally (HTTP {response.status})"
                    else:
                        status = HealthStatus.UNHEALTHY
                        message = f"Unexpected HTTP status: {response.status}"
                    
                    return HealthCheckResult(
                        component_name=self.component_name,
                        status=status,
                        response_time_ms=response_time,
                        message=message,
                        metadata={
                            "http_status": response.status,
                            "endpoint": self.endpoint_url,
                            "method": self.method,
                            "content_type": response.headers.get('content-type', ''),
                            "content_length": response.headers.get('content-length', 0)
                        }
                    )
                    
            except asyncio.TimeoutError:
                response_time = (time.time() - start_time) * 1000
                return HealthCheckResult(
                    component_name=self.component_name,
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=response_time,
                    message=f"API endpoint timeout after {self.timeout}s",
                    metadata={"endpoint": self.endpoint_url, "timeout": self.timeout}
                )
            
            except Exception as e:
                response_time = (time.time() - start_time) * 1000
                return HealthCheckResult(
                    component_name=self.component_name,
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=response_time,
                    message=f"API endpoint error: {str(e)}",
                    error_details=str(e),
                    metadata={"endpoint": self.endpoint_url, "error_type": type(e).__name__}
                )


class ServiceHealthChecker(BaseHealthChecker):
    """Health checker for service instances."""
    
    def __init__(
        self,
        component_name: str,
        service_instance: Any,
        health_method_name: str = "health_check",
        thresholds: Optional[HealthThresholds] = None
    ):
        super().__init__(component_name, thresholds)
        self.service_instance = service_instance
        self.health_method_name = health_method_name
    
    async def check_health(self) -> HealthCheckResult:
        """Check service instance health."""
        start_time = time.time()
        
        try:
            # Check if service instance exists
            if self.service_instance is None:
                return HealthCheckResult(
                    component_name=self.component_name,
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=0,
                    message="Service instance is None",
                    metadata={"service_available": False}
                )
            
            # Check if health method exists
            if hasattr(self.service_instance, self.health_method_name):
                health_method = getattr(self.service_instance, self.health_method_name)
                
                # Call health method (async or sync)
                if asyncio.iscoroutinefunction(health_method):
                    health_result = await health_method()
                else:
                    health_result = health_method()
                
                response_time = (time.time() - start_time) * 1000
                
                # Parse health result
                if isinstance(health_result, dict):
                    status_str = health_result.get('status', 'unknown')
                    status = HealthStatus(status_str.lower()) if status_str in HealthStatus.__members__.values() else HealthStatus.UNKNOWN
                    message = health_result.get('message', 'Service health check completed')
                    metadata = health_result.get('metadata', {})
                elif isinstance(health_result, bool):
                    status = HealthStatus.HEALTHY if health_result else HealthStatus.UNHEALTHY
                    message = f"Service health check: {'passed' if health_result else 'failed'}"
                    metadata = {}
                else:
                    status = HealthStatus.HEALTHY if health_result else HealthStatus.UNHEALTHY
                    message = f"Service health check result: {health_result}"
                    metadata = {"raw_result": str(health_result)}
                
                return HealthCheckResult(
                    component_name=self.component_name,
                    status=status,
                    response_time_ms=response_time,
                    message=message,
                    metadata={
                        **metadata,
                        "service_class": self.service_instance.__class__.__name__,
                        "health_method": self.health_method_name
                    }
                )
            
            else:
                # No health method available, check basic service availability
                response_time = (time.time() - start_time) * 1000
                
                return HealthCheckResult(
                    component_name=self.component_name,
                    status=HealthStatus.HEALTHY,
                    response_time_ms=response_time,
                    message="Service instance available (no health method)",
                    metadata={
                        "service_class": self.service_instance.__class__.__name__,
                        "health_method_available": False,
                        "service_available": True
                    }
                )
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheckResult(
                component_name=self.component_name,
                status=HealthStatus.UNHEALTHY,
                response_time_ms=response_time,
                message=f"Service health check failed: {str(e)}",
                error_details=str(e),
                metadata={
                    "service_class": getattr(self.service_instance, '__class__', {}).get('__name__', 'Unknown'),
                    "error_type": type(e).__name__
                }
            )


class DatabaseHealthChecker(BaseHealthChecker):
    """Health checker for database connections."""
    
    def __init__(
        self,
        component_name: str,
        connection_string: Optional[str] = None,
        thresholds: Optional[HealthThresholds] = None
    ):
        super().__init__(component_name, thresholds)
        self.connection_string = connection_string
    
    async def check_health(self) -> HealthCheckResult:
        """Check database connection health."""
        start_time = time.time()
        
        try:
            # Use existing database session
            with get_db_session() as session:
                # Execute a simple query
                result = session.execute(text("SELECT 1"))
                result.fetchone()
                
                response_time = (time.time() - start_time) * 1000
                status = self._determine_status_by_response_time(response_time)
                
                return HealthCheckResult(
                    component_name=self.component_name,
                    status=status,
                    response_time_ms=response_time,
                    message="Database connection healthy",
                    metadata={
                        "database_type": "sqlite/postgresql",  # This would be determined dynamically
                        "query_executed": "SELECT 1",
                        "connection_pool_info": self._get_connection_pool_info(session)
                    }
                )
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheckResult(
                component_name=self.component_name,
                status=HealthStatus.UNHEALTHY,
                response_time_ms=response_time,
                message=f"Database connection failed: {str(e)}",
                error_details=str(e),
                metadata={"error_type": type(e).__name__}
            )
    
    def _get_connection_pool_info(self, session) -> Dict[str, Any]:
        """Get connection pool information."""
        try:
            engine = session.get_bind()
            pool = engine.pool
            
            return {
                "pool_size": getattr(pool, 'size', 'unknown'),
                "checked_in": getattr(pool, 'checkedin', 'unknown'),
                "checked_out": getattr(pool, 'checkedout', 'unknown'),
                "overflow": getattr(pool, 'overflow', 'unknown')
            }
        except:
            return {"pool_info": "unavailable"}


class RedisHealthChecker(BaseHealthChecker):
    """Health checker for Redis connections."""
    
    def __init__(
        self,
        component_name: str,
        redis_url: Optional[str] = None,
        thresholds: Optional[HealthThresholds] = None
    ):
        super().__init__(component_name, thresholds)
        self.redis_url = redis_url or f"redis://{getattr(settings, 'redis_host', 'localhost')}:{getattr(settings, 'redis_port', 6379)}"
    
    async def check_health(self) -> HealthCheckResult:
        """Check Redis connection health."""
        start_time = time.time()
        
        try:
            redis = aioredis.from_url(self.redis_url)
            
            # Execute ping command
            ping_result = await redis.ping()
            
            # Get Redis info
            info = await redis.info()
            
            await redis.close()
            
            response_time = (time.time() - start_time) * 1000
            status = self._determine_status_by_response_time(response_time)
            
            return HealthCheckResult(
                component_name=self.component_name,
                status=status,
                response_time_ms=response_time,
                message="Redis connection healthy",
                metadata={
                    "ping_result": ping_result,
                    "redis_version": info.get('redis_version', 'unknown'),
                    "connected_clients": info.get('connected_clients', 0),
                    "used_memory": info.get('used_memory_human', 'unknown'),
                    "uptime_seconds": info.get('uptime_in_seconds', 0)
                }
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheckResult(
                component_name=self.component_name,
                status=HealthStatus.UNHEALTHY,
                response_time_ms=response_time,
                message=f"Redis connection failed: {str(e)}",
                error_details=str(e),
                metadata={"redis_url": self.redis_url, "error_type": type(e).__name__}
            )


class SystemResourceHealthChecker(BaseHealthChecker):
    """Health checker for system resources."""
    
    def __init__(
        self,
        component_name: str,
        thresholds: Optional[HealthThresholds] = None
    ):
        super().__init__(component_name, thresholds)
    
    async def check_health(self) -> HealthCheckResult:
        """Check system resource health."""
        start_time = time.time()
        
        try:
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Get memory usage
            memory = psutil.virtual_memory()
            
            # Get disk usage
            disk = psutil.disk_usage('/')
            
            response_time = (time.time() - start_time) * 1000
            
            # Determine overall status
            status = HealthStatus.HEALTHY
            warnings = []
            
            if cpu_percent > self.thresholds.cpu_critical_percent:
                status = HealthStatus.UNHEALTHY
                warnings.append(f"CPU usage critical: {cpu_percent}%")
            elif cpu_percent > self.thresholds.cpu_warning_percent:
                status = HealthStatus.DEGRADED if status == HealthStatus.HEALTHY else status
                warnings.append(f"CPU usage high: {cpu_percent}%")
            
            if memory.percent > self.thresholds.memory_critical_percent:
                status = HealthStatus.UNHEALTHY
                warnings.append(f"Memory usage critical: {memory.percent}%")
            elif memory.percent > self.thresholds.memory_warning_percent:
                status = HealthStatus.DEGRADED if status == HealthStatus.HEALTHY else status
                warnings.append(f"Memory usage high: {memory.percent}%")
            
            disk_percent = (disk.used / disk.total) * 100
            if disk_percent > self.thresholds.disk_critical_percent:
                status = HealthStatus.UNHEALTHY
                warnings.append(f"Disk usage critical: {disk_percent:.1f}%")
            elif disk_percent > self.thresholds.disk_warning_percent:
                status = HealthStatus.DEGRADED if status == HealthStatus.HEALTHY else status
                warnings.append(f"Disk usage high: {disk_percent:.1f}%")
            
            message = "System resources healthy" if not warnings else "; ".join(warnings)
            
            return HealthCheckResult(
                component_name=self.component_name,
                status=status,
                response_time_ms=response_time,
                message=message,
                metadata={
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory.percent,
                    "memory_used_gb": memory.used / (1024**3),
                    "memory_total_gb": memory.total / (1024**3),
                    "disk_percent": disk_percent,
                    "disk_used_gb": disk.used / (1024**3),
                    "disk_total_gb": disk.total / (1024**3),
                    "warnings": warnings
                }
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheckResult(
                component_name=self.component_name,
                status=HealthStatus.UNHEALTHY,
                response_time_ms=response_time,
                message=f"System resource check failed: {str(e)}",
                error_details=str(e),
                metadata={"error_type": type(e).__name__}
            )


class CompositeHealthChecker(BaseHealthChecker):
    """Health checker that aggregates multiple health checkers."""
    
    def __init__(
        self,
        component_name: str,
        health_checkers: List[BaseHealthChecker],
        require_all_healthy: bool = False,
        thresholds: Optional[HealthThresholds] = None
    ):
        super().__init__(component_name, thresholds)
        self.health_checkers = health_checkers
        self.require_all_healthy = require_all_healthy
    
    async def check_health(self) -> HealthCheckResult:
        """Check health of all sub-checkers."""
        start_time = time.time()
        
        try:
            # Run all health checks concurrently
            results = await asyncio.gather(
                *[checker.perform_check() for checker in self.health_checkers],
                return_exceptions=True
            )
            
            response_time = (time.time() - start_time) * 1000
            
            # Analyze results
            healthy_count = 0
            degraded_count = 0
            unhealthy_count = 0
            errors = []
            sub_results = []
            
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    unhealthy_count += 1
                    errors.append(f"Checker {i}: {str(result)}")
                    continue
                
                sub_results.append({
                    "checker": self.health_checkers[i].component_name,
                    "status": result.status.value,
                    "response_time_ms": result.response_time_ms,
                    "message": result.message
                })
                
                if result.status == HealthStatus.HEALTHY:
                    healthy_count += 1
                elif result.status == HealthStatus.DEGRADED:
                    degraded_count += 1
                else:
                    unhealthy_count += 1
                    if result.error_details:
                        errors.append(f"{result.component_name}: {result.message}")
            
            # Determine overall status
            total_checkers = len(self.health_checkers)
            
            if self.require_all_healthy:
                if unhealthy_count > 0:
                    status = HealthStatus.UNHEALTHY
                elif degraded_count > 0:
                    status = HealthStatus.DEGRADED
                else:
                    status = HealthStatus.HEALTHY
            else:
                if unhealthy_count >= total_checkers:
                    status = HealthStatus.UNHEALTHY
                elif unhealthy_count > 0 or degraded_count > total_checkers // 2:
                    status = HealthStatus.DEGRADED
                else:
                    status = HealthStatus.HEALTHY
            
            message_parts = [
                f"{healthy_count} healthy",
                f"{degraded_count} degraded",
                f"{unhealthy_count} unhealthy"
            ]
            message = f"Composite health: {', '.join(message_parts)}"
            
            return HealthCheckResult(
                component_name=self.component_name,
                status=status,
                response_time_ms=response_time,
                message=message,
                error_details="\n".join(errors) if errors else None,
                metadata={
                    "total_checkers": total_checkers,
                    "healthy_count": healthy_count,
                    "degraded_count": degraded_count,
                    "unhealthy_count": unhealthy_count,
                    "require_all_healthy": self.require_all_healthy,
                    "sub_results": sub_results,
                    "errors": errors
                }
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheckResult(
                component_name=self.component_name,
                status=HealthStatus.UNHEALTHY,
                response_time_ms=response_time,
                message=f"Composite health check failed: {str(e)}",
                error_details=str(e),
                metadata={"error_type": type(e).__name__}
            )


class ComponentHealthManager:
    """Manager for component health checking."""
    
    def __init__(self, registry: Optional[ComponentRegistry] = None):
        self.registry = registry or get_component_registry()
        self._health_checkers: Dict[str, BaseHealthChecker] = {}
        self._health_results: Dict[str, HealthCheckResult] = {}
        self._running = False
        self._check_tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()
    
    async def initialize(self) -> None:
        """Initialize the health manager."""
        logger.info("Initializing Component Health Manager...")
        
        # Create health checkers for registered components
        await self._create_health_checkers()
        
        logger.info(f"Initialized {len(self._health_checkers)} health checkers")
    
    async def _create_health_checkers(self) -> None:
        """Create health checkers for registered components."""
        components = self.registry.list_components()
        
        for component in components:
            await self._create_health_checker_for_component(component)
    
    async def _create_health_checker_for_component(self, component) -> None:
        """Create appropriate health checker for a component."""
        try:
            component_name = component.name
            
            # Choose appropriate health checker based on component type
            if component.component_type.value == "api_endpoint":
                # Create API endpoint health checker
                # This would need endpoint URL configuration
                base_url = getattr(settings, 'base_url', 'http://localhost:8000')
                if hasattr(component, 'metadata') and 'path' in component.metadata:
                    endpoint_url = f"{base_url}{component.metadata['path']}"
                    checker = APIEndpointHealthChecker(component_name, endpoint_url)
                    self._health_checkers[component_name] = checker
                    
            elif component.component_type.value in ["service", "engine", "processor", "manager"]:
                # Create service health checker
                if component.instance:
                    health_method = component.health_check_method or "health_check"
                    checker = ServiceHealthChecker(component_name, component.instance, health_method)
                    self._health_checkers[component_name] = checker
                    
            elif component.component_type.value == "database":
                # Create database health checker
                checker = DatabaseHealthChecker(component_name)
                self._health_checkers[component_name] = checker
                
            elif component.component_type.value == "cache":
                # Create Redis health checker  
                checker = RedisHealthChecker(component_name)
                self._health_checkers[component_name] = checker
                
            else:
                # Create basic service health checker as fallback
                if component.instance:
                    checker = ServiceHealthChecker(component_name, component.instance)
                    self._health_checkers[component_name] = checker
                    
        except Exception as e:
            logger.error(f"Failed to create health checker for {component.name}: {e}")
    
    async def check_component_health(self, component_name: str) -> Optional[HealthCheckResult]:
        """Check health of a specific component."""
        checker = self._health_checkers.get(component_name)
        if not checker:
            return None
        
        result = await checker.perform_check()
        self._health_results[component_name] = result
        
        # Update component status in registry
        if result.status == HealthStatus.HEALTHY:
            self.registry.update_component_status(component_name, ComponentStatus.ACTIVE)
        elif result.status == HealthStatus.UNHEALTHY:
            self.registry.update_component_status(component_name, ComponentStatus.FAILED)
        else:
            self.registry.update_component_status(component_name, ComponentStatus.INACTIVE)
        
        return result
    
    async def check_all_components(self) -> Dict[str, HealthCheckResult]:
        """Check health of all registered components."""
        logger.debug("Checking health of all components...")
        
        # Run all health checks concurrently
        tasks = []
        component_names = []
        
        for component_name, checker in self._health_checkers.items():
            tasks.append(checker.perform_check())
            component_names.append(component_name)
        
        if not tasks:
            return {}
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            component_name = component_names[i]
            
            if isinstance(result, Exception):
                logger.error(f"Health check failed for {component_name}: {result}")
                result = HealthCheckResult(
                    component_name=component_name,
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=0,
                    message=f"Health check exception: {str(result)}",
                    error_details=str(result)
                )
            
            self._health_results[component_name] = result
            
            # Update registry status
            if result.status == HealthStatus.HEALTHY:
                self.registry.update_component_status(component_name, ComponentStatus.ACTIVE)
            elif result.status == HealthStatus.UNHEALTHY:
                self.registry.update_component_status(component_name, ComponentStatus.FAILED)
        
        return self._health_results.copy()
    
    def get_health_result(self, component_name: str) -> Optional[HealthCheckResult]:
        """Get the last health check result for a component."""
        return self._health_results.get(component_name)
    
    def get_all_health_results(self) -> Dict[str, HealthCheckResult]:
        """Get all health check results."""
        return self._health_results.copy()
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get a summary of all component health."""
        if not self._health_results:
            return {"status": "unknown", "components": {}}
        
        healthy_count = sum(1 for r in self._health_results.values() if r.status == HealthStatus.HEALTHY)
        degraded_count = sum(1 for r in self._health_results.values() if r.status == HealthStatus.DEGRADED)
        unhealthy_count = sum(1 for r in self._health_results.values() if r.status == HealthStatus.UNHEALTHY)
        
        total_components = len(self._health_results)
        
        # Determine overall system health
        if unhealthy_count == 0 and degraded_count == 0:
            overall_status = HealthStatus.HEALTHY
        elif unhealthy_count > total_components // 2:
            overall_status = HealthStatus.UNHEALTHY
        else:
            overall_status = HealthStatus.DEGRADED
        
        return {
            "status": overall_status.value,
            "total_components": total_components,
            "healthy_count": healthy_count,
            "degraded_count": degraded_count,
            "unhealthy_count": unhealthy_count,
            "last_check": datetime.utcnow().isoformat(),
            "components": {
                name: {
                    "status": result.status.value,
                    "response_time_ms": result.response_time_ms,
                    "message": result.message,
                    "last_check": result.timestamp.isoformat()
                }
                for name, result in self._health_results.items()
            }
        }


# Global health manager instance
_health_manager: Optional[ComponentHealthManager] = None


def get_health_manager() -> ComponentHealthManager:
    """Get the global health manager instance."""
    global _health_manager
    if _health_manager is None:
        _health_manager = ComponentHealthManager()
    return _health_manager


async def initialize_health_manager() -> ComponentHealthManager:
    """Initialize the global health manager."""
    manager = get_health_manager()
    await manager.initialize()
    return manager