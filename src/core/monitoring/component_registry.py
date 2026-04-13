"""
Component Registry and Discovery System

Provides centralized registration and discovery of all system components
for comprehensive monitoring and health tracking.
"""

import asyncio
import inspect
import logging
import pkgutil
import importlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Callable, Type
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class ComponentType(str, Enum):
    """Component type classifications."""
    API_ENDPOINT = "api_endpoint"
    SERVICE = "service"
    ENGINE = "engine"
    PROCESSOR = "processor"
    MANAGER = "manager"
    REPOSITORY = "repository"
    DATABASE = "database"
    EXTERNAL_DEPENDENCY = "external_dependency"
    MIDDLEWARE = "middleware"
    SCHEDULER = "scheduler"
    CACHE = "cache"
    QUEUE = "queue"
    MODEL = "model"


class ComponentStatus(str, Enum):
    """Component status values."""
    REGISTERED = "registered"
    ACTIVE = "active"
    INACTIVE = "inactive"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass
class ComponentMetadata:
    """Component metadata information."""
    name: str
    component_type: ComponentType
    description: str
    version: str = "1.0.0"
    module_path: str = ""
    class_name: str = ""
    instance: Optional[Any] = None
    dependencies: List[str] = field(default_factory=list)
    health_check_method: Optional[str] = None
    health_check_interval: int = 30  # seconds
    critical: bool = False
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    registered_at: datetime = field(default_factory=datetime.utcnow)
    last_health_check: Optional[datetime] = None
    status: ComponentStatus = ComponentStatus.REGISTERED


class ComponentRegistry:
    """Central registry for system components."""
    
    def __init__(self):
        self._components: Dict[str, ComponentMetadata] = {}
        self._component_instances: Dict[str, Any] = {}
        self._dependency_graph: Dict[str, Set[str]] = {}
        self._reverse_dependencies: Dict[str, Set[str]] = {}
        self._lock = asyncio.Lock()
        self._initialized = False
        
    async def initialize(self) -> None:
        """Initialize the component registry."""
        async with self._lock:
            if self._initialized:
                return
                
            logger.info("Initializing Component Registry...")
            
            # Discover and register components
            await self._discover_components()
            
            # Build dependency graph
            self._build_dependency_graph()
            
            self._initialized = True
            logger.info(f"Component Registry initialized with {len(self._components)} components")
    
    async def register_component(
        self,
        name: str,
        component_type: ComponentType,
        description: str,
        instance: Optional[Any] = None,
        **kwargs
    ) -> bool:
        """Register a component in the registry."""
        try:
            async with self._lock:
                if name in self._components:
                    logger.warning(f"Component '{name}' already registered, updating...")
                
                metadata = ComponentMetadata(
                    name=name,
                    component_type=component_type,
                    description=description,
                    instance=instance,
                    **kwargs
                )
                
                # Extract module and class information if instance provided
                if instance:
                    metadata.module_path = instance.__class__.__module__
                    metadata.class_name = instance.__class__.__name__
                    self._component_instances[name] = instance
                    metadata.status = ComponentStatus.ACTIVE
                
                self._components[name] = metadata
                
                logger.debug(f"Registered component: {name} ({component_type})")
                return True
                
        except Exception as e:
            logger.error(f"Failed to register component '{name}': {e}")
            return False
    
    async def unregister_component(self, name: str) -> bool:
        """Unregister a component from the registry."""
        try:
            async with self._lock:
                if name in self._components:
                    del self._components[name]
                    if name in self._component_instances:
                        del self._component_instances[name]
                    
                    # Clean up dependencies
                    if name in self._dependency_graph:
                        del self._dependency_graph[name]
                    if name in self._reverse_dependencies:
                        del self._reverse_dependencies[name]
                    
                    # Remove from other components' dependencies
                    for comp_name in self._dependency_graph:
                        self._dependency_graph[comp_name].discard(name)
                    for comp_name in self._reverse_dependencies:
                        self._reverse_dependencies[comp_name].discard(name)
                    
                    logger.debug(f"Unregistered component: {name}")
                    return True
                    
                logger.warning(f"Component '{name}' not found for unregistration")
                return False
                
        except Exception as e:
            logger.error(f"Failed to unregister component '{name}': {e}")
            return False
    
    def get_component(self, name: str) -> Optional[ComponentMetadata]:
        """Get component metadata by name."""
        return self._components.get(name)
    
    def get_component_instance(self, name: str) -> Optional[Any]:
        """Get component instance by name."""
        return self._component_instances.get(name)
    
    def list_components(
        self,
        component_type: Optional[ComponentType] = None,
        status: Optional[ComponentStatus] = None,
        critical_only: bool = False
    ) -> List[ComponentMetadata]:
        """List components with optional filtering."""
        components = list(self._components.values())
        
        if component_type:
            components = [c for c in components if c.component_type == component_type]
        
        if status:
            components = [c for c in components if c.status == status]
        
        if critical_only:
            components = [c for c in components if c.critical]
        
        return components
    
    def get_dependencies(self, name: str) -> Set[str]:
        """Get direct dependencies for a component."""
        return self._dependency_graph.get(name, set())
    
    def get_reverse_dependencies(self, name: str) -> Set[str]:
        """Get components that depend on this component."""
        return self._reverse_dependencies.get(name, set())
    
    def get_dependency_chain(self, name: str, max_depth: int = 10) -> List[List[str]]:
        """Get all dependency chains for a component."""
        chains = []
        visited = set()
        
        def _build_chain(comp_name: str, current_chain: List[str], depth: int):
            if depth > max_depth or comp_name in visited:
                return
            
            visited.add(comp_name)
            current_chain.append(comp_name)
            
            dependencies = self._dependency_graph.get(comp_name, set())
            if not dependencies:
                chains.append(current_chain.copy())
            else:
                for dep in dependencies:
                    _build_chain(dep, current_chain.copy(), depth + 1)
        
        _build_chain(name, [], 0)
        return chains
    
    def update_component_status(self, name: str, status: ComponentStatus) -> bool:
        """Update component status."""
        if name in self._components:
            self._components[name].status = status
            self._components[name].last_health_check = datetime.utcnow()
            return True
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get registry statistics."""
        components = list(self._components.values())
        
        stats = {
            "total_components": len(components),
            "by_type": {},
            "by_status": {},
            "critical_components": len([c for c in components if c.critical]),
            "active_components": len([c for c in components if c.status == ComponentStatus.ACTIVE]),
            "failed_components": len([c for c in components if c.status == ComponentStatus.FAILED]),
            "last_updated": datetime.utcnow().isoformat()
        }
        
        # Count by type
        for comp in components:
            comp_type = comp.component_type.value
            stats["by_type"][comp_type] = stats["by_type"].get(comp_type, 0) + 1
        
        # Count by status
        for comp in components:
            status = comp.status.value
            stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
        
        return stats
    
    async def _discover_components(self) -> None:
        """Discover components automatically from the codebase."""
        logger.info("Starting component discovery...")
        
        # Define discovery patterns
        discovery_patterns = [
            # API endpoints
            {
                "pattern": "router",
                "type": ComponentType.API_ENDPOINT,
                "modules": ["src.api"]
            },
            # Services, Managers, Engines, Processors
            {
                "pattern": r"(Service|Manager|Engine|Processor)$",
                "type": ComponentType.SERVICE,
                "modules": ["src.core"]
            },
            # Repositories
            {
                "pattern": "Repository",
                "type": ComponentType.REPOSITORY,
                "modules": ["src.core.database.repositories"]
            }
        ]
        
        # Discover from patterns
        for pattern_config in discovery_patterns:
            await self._discover_from_pattern(pattern_config)
        
        # Register known critical infrastructure components
        await self._register_infrastructure_components()
    
    async def _discover_from_pattern(self, pattern_config: Dict[str, Any]) -> None:
        """Discover components matching a specific pattern."""
        try:
            modules = pattern_config["modules"]
            pattern = pattern_config["pattern"]
            comp_type = pattern_config["type"]
            
            for module_name in modules:
                try:
                    await self._scan_module_for_components(module_name, pattern, comp_type)
                except Exception as e:
                    logger.debug(f"Could not scan module {module_name}: {e}")
                    
        except Exception as e:
            logger.error(f"Error in pattern discovery: {e}")
    
    async def _scan_module_for_components(
        self, 
        module_name: str, 
        pattern: str, 
        comp_type: ComponentType
    ) -> None:
        """Scan a module for components matching pattern."""
        try:
            # Import the module
            module = importlib.import_module(module_name)
            
            # Get all classes and functions in the module
            for name, obj in inspect.getmembers(module):
                if self._matches_pattern(name, obj, pattern):
                    component_name = f"{module_name}.{name}"
                    
                    # Try to get description from docstring
                    description = getattr(obj, "__doc__", f"{name} component").split("\n")[0]
                    if not description:
                        description = f"{name} component"
                    
                    await self.register_component(
                        name=component_name,
                        component_type=comp_type,
                        description=description,
                        module_path=module_name,
                        class_name=name,
                        instance=obj if not inspect.isclass(obj) else None,
                        version="1.0.0"
                    )
                    
        except Exception as e:
            logger.debug(f"Could not scan module {module_name} for pattern {pattern}: {e}")
    
    def _matches_pattern(self, name: str, obj: Any, pattern: str) -> bool:
        """Check if an object matches the discovery pattern."""
        import re
        
        # Skip private members
        if name.startswith("_"):
            return False
        
        # Check for router pattern (API endpoints)
        if pattern == "router":
            return hasattr(obj, 'tags') and hasattr(obj, 'routes')
        
        # Check for class patterns
        if inspect.isclass(obj) and re.search(pattern, name):
            return True
        
        # Check for instance patterns
        if hasattr(obj, '__class__') and re.search(pattern, obj.__class__.__name__):
            return True
        
        return False
    
    async def _register_infrastructure_components(self) -> None:
        """Register known infrastructure components."""
        infrastructure_components = [
            {
                "name": "redis_cache",
                "type": ComponentType.CACHE,
                "description": "Redis cache server",
                "critical": True,
                "health_check_method": "ping"
            },
            {
                "name": "database_primary",
                "type": ComponentType.DATABASE,
                "description": "Primary database connection",
                "critical": True,
                "health_check_method": "ping"
            },
            {
                "name": "celery_broker",
                "type": ComponentType.QUEUE,
                "description": "Celery message broker",
                "critical": True,
                "health_check_method": "ping"
            },
            {
                "name": "file_storage",
                "type": ComponentType.EXTERNAL_DEPENDENCY,
                "description": "File storage system",
                "critical": True,
                "health_check_method": "check_disk_space"
            }
        ]
        
        for comp_config in infrastructure_components:
            await self.register_component(**comp_config)
    
    def _build_dependency_graph(self) -> None:
        """Build the component dependency graph."""
        logger.debug("Building component dependency graph...")
        
        for name, component in self._components.items():
            # Initialize dependency sets
            self._dependency_graph[name] = set(component.dependencies)
            self._reverse_dependencies[name] = set()
        
        # Build reverse dependencies
        for name, dependencies in self._dependency_graph.items():
            for dep in dependencies:
                if dep in self._reverse_dependencies:
                    self._reverse_dependencies[dep].add(name)
        
        logger.debug(f"Dependency graph built with {len(self._dependency_graph)} nodes")


class ComponentDiscovery:
    """Component discovery utilities."""
    
    @staticmethod
    def discover_api_endpoints() -> List[Dict[str, Any]]:
        """Discover API endpoints from router definitions."""
        endpoints = []
        
        try:
            # Import all API modules and extract endpoints
            api_modules = [
                "src.api.auth", "src.api.document_upload", "src.api.dashboard",
                "src.api.reporting", "src.api.user_management", "src.api.compliance",
                "src.api.system", "src.api.integrations"
            ]
            
            for module_name in api_modules:
                try:
                    module = importlib.import_module(module_name)
                    if hasattr(module, 'router'):
                        router = module.router
                        for route in router.routes:
                            endpoints.append({
                                "name": f"{module_name}.{route.name or route.path}",
                                "path": route.path,
                                "methods": getattr(route, 'methods', ['GET']),
                                "module": module_name,
                                "description": f"API endpoint {route.path}"
                            })
                except Exception as e:
                    logger.debug(f"Could not discover endpoints from {module_name}: {e}")
                    
        except Exception as e:
            logger.error(f"Error discovering API endpoints: {e}")
        
        return endpoints
    
    @staticmethod
    def discover_service_classes() -> List[Dict[str, Any]]:
        """Discover service classes from core modules."""
        services = []
        
        try:
            # Scan core modules for service classes
            core_path = Path("src/core")
            if core_path.exists():
                for py_file in core_path.rglob("*.py"):
                    if py_file.name.startswith("__"):
                        continue
                    
                    try:
                        # Convert path to module name
                        module_name = str(py_file.with_suffix("")).replace("/", ".").replace("\\", ".")
                        
                        module = importlib.import_module(module_name)
                        
                        for name, obj in inspect.getmembers(module, inspect.isclass):
                            if name.endswith(('Service', 'Manager', 'Engine', 'Processor')):
                                services.append({
                                    "name": f"{module_name}.{name}",
                                    "class_name": name,
                                    "module": module_name,
                                    "description": getattr(obj, "__doc__", f"{name} service class")
                                })
                    except Exception as e:
                        logger.debug(f"Could not scan {py_file}: {e}")
                        
        except Exception as e:
            logger.error(f"Error discovering service classes: {e}")
        
        return services


# Global registry instance
_component_registry: Optional[ComponentRegistry] = None


def get_component_registry() -> ComponentRegistry:
    """Get the global component registry instance."""
    global _component_registry
    if _component_registry is None:
        _component_registry = ComponentRegistry()
    return _component_registry


async def initialize_component_registry() -> ComponentRegistry:
    """Initialize the global component registry."""
    registry = get_component_registry()
    await registry.initialize()
    return registry


def component(
    name: Optional[str] = None,
    component_type: ComponentType = ComponentType.SERVICE,
    description: Optional[str] = None,
    dependencies: Optional[List[str]] = None,
    critical: bool = False,
    health_check_method: Optional[str] = None,
    **kwargs
) -> Callable:
    """Decorator to automatically register components."""
    def decorator(cls_or_func):
        # Register the component
        component_name = name or f"{cls_or_func.__module__}.{cls_or_func.__name__}"
        comp_description = description or getattr(cls_or_func, "__doc__", f"{cls_or_func.__name__} component")
        
        # Store registration info for later
        cls_or_func._component_registration = {
            "name": component_name,
            "component_type": component_type,
            "description": comp_description,
            "dependencies": dependencies or [],
            "critical": critical,
            "health_check_method": health_check_method,
            "module_path": cls_or_func.__module__,
            "class_name": cls_or_func.__name__,
            **kwargs
        }
        
        return cls_or_func
    
    return decorator


async def register_decorated_components():
    """Register all components that were decorated with @component."""
    registry = get_component_registry()
    
    # This would need to be called during application startup
    # to find and register all decorated components
    logger.info("Registering decorated components...")
    
    # Implementation would scan for decorated classes/functions
    # For now, this is a placeholder for the registration process
    pass