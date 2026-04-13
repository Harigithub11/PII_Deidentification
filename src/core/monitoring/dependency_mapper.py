"""
Component Dependency Mapping System

Provides dependency analysis, impact assessment, and critical path
identification for system components.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import networkx as nx
from collections import defaultdict, deque

from .component_registry import ComponentRegistry, get_component_registry, ComponentType
from .component_health import HealthStatus

logger = logging.getLogger(__name__)


class DependencyType(str, Enum):
    """Types of dependencies between components."""
    HARD = "hard"          # Component cannot function without dependency
    SOFT = "soft"          # Component can function with degraded capability
    OPTIONAL = "optional"   # Dependency improves functionality but not required
    CIRCULAR = "circular"   # Circular dependency (should be avoided)


class ImpactLevel(str, Enum):
    """Impact levels for dependency analysis."""
    CRITICAL = "critical"   # System-wide failure
    HIGH = "high"          # Major functionality affected
    MEDIUM = "medium"      # Some functionality affected  
    LOW = "low"           # Minor functionality affected
    NONE = "none"         # No impact


@dataclass
class DependencyEdge:
    """Represents a dependency relationship between components."""
    source: str                    # Component that depends on target
    target: str                    # Component being depended upon
    dependency_type: DependencyType = DependencyType.HARD
    description: str = ""
    weight: float = 1.0           # Dependency strength (0.0 to 1.0)
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ImpactAnalysisResult:
    """Result of dependency impact analysis."""
    affected_component: str
    impact_level: ImpactLevel
    dependency_chain: List[str]
    failure_probability: float    # 0.0 to 1.0
    estimated_downtime_minutes: int
    mitigation_suggestions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CriticalPath:
    """Represents a critical path through the system."""
    path: List[str]
    total_weight: float
    risk_score: float            # 0.0 to 1.0
    components_count: int
    description: str = ""
    bottlenecks: List[str] = field(default_factory=list)


class DependencyGraph:
    """Manages the component dependency graph."""
    
    def __init__(self, registry: Optional[ComponentRegistry] = None):
        self.registry = registry or get_component_registry()
        self._graph = nx.DiGraph()
        self._dependency_cache: Dict[str, Set[str]] = {}
        self._reverse_dependency_cache: Dict[str, Set[str]] = {}
        self._critical_paths: List[CriticalPath] = []
        self._last_analysis: Optional[datetime] = None
    
    def add_dependency(self, dependency: DependencyEdge) -> bool:
        """Add a dependency to the graph."""
        try:
            self._graph.add_edge(
                dependency.source,
                dependency.target,
                dependency_type=dependency.dependency_type.value,
                description=dependency.description,
                weight=dependency.weight,
                created_at=dependency.created_at,
                metadata=dependency.metadata
            )
            
            # Clear caches
            self._clear_caches()
            
            logger.debug(f"Added dependency: {dependency.source} -> {dependency.target}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add dependency {dependency.source} -> {dependency.target}: {e}")
            return False
    
    def remove_dependency(self, source: str, target: str) -> bool:
        """Remove a dependency from the graph."""
        try:
            if self._graph.has_edge(source, target):
                self._graph.remove_edge(source, target)
                self._clear_caches()
                logger.debug(f"Removed dependency: {source} -> {target}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove dependency {source} -> {target}: {e}")
            return False
    
    def get_dependencies(self, component: str, include_transitive: bool = False) -> Set[str]:
        """Get dependencies for a component."""
        cache_key = f"{component}_{include_transitive}"
        
        if cache_key not in self._dependency_cache:
            if include_transitive:
                # Get all nodes reachable from component
                dependencies = set()
                if component in self._graph:
                    try:
                        dependencies = set(nx.descendants(self._graph, component))
                    except nx.NetworkXError:
                        dependencies = set()
            else:
                # Get direct dependencies only
                dependencies = set(self._graph.successors(component))
            
            self._dependency_cache[cache_key] = dependencies
        
        return self._dependency_cache[cache_key]
    
    def get_reverse_dependencies(self, component: str, include_transitive: bool = False) -> Set[str]:
        """Get components that depend on this component."""
        cache_key = f"{component}_{include_transitive}"
        
        if cache_key not in self._reverse_dependency_cache:
            if include_transitive:
                # Get all nodes that can reach component
                dependents = set()
                if component in self._graph:
                    try:
                        dependents = set(nx.ancestors(self._graph, component))
                    except nx.NetworkXError:
                        dependents = set()
            else:
                # Get direct dependents only
                dependents = set(self._graph.predecessors(component))
            
            self._reverse_dependency_cache[cache_key] = dependents
        
        return self._reverse_dependency_cache[cache_key]
    
    def find_dependency_chains(self, source: str, target: str) -> List[List[str]]:
        """Find all dependency chains between two components."""
        try:
            if source not in self._graph or target not in self._graph:
                return []
            
            # Find all simple paths between source and target
            paths = list(nx.all_simple_paths(self._graph, source, target))
            return paths
            
        except nx.NetworkXError:
            return []
    
    def detect_circular_dependencies(self) -> List[List[str]]:
        """Detect circular dependencies in the graph."""
        try:
            cycles = list(nx.simple_cycles(self._graph))
            
            # Mark circular dependencies
            for cycle in cycles:
                for i in range(len(cycle)):
                    source = cycle[i]
                    target = cycle[(i + 1) % len(cycle)]
                    
                    if self._graph.has_edge(source, target):
                        self._graph[source][target]['dependency_type'] = DependencyType.CIRCULAR.value
            
            return cycles
            
        except Exception as e:
            logger.error(f"Error detecting circular dependencies: {e}")
            return []
    
    def get_component_criticality_score(self, component: str) -> float:
        """Calculate criticality score for a component (0.0 to 1.0)."""
        try:
            if component not in self._graph:
                return 0.0
            
            # Factors for criticality calculation
            direct_dependents = len(list(self._graph.predecessors(component)))
            transitive_dependents = len(self.get_reverse_dependencies(component, include_transitive=True))
            
            # Get component metadata
            comp_metadata = self.registry.get_component(component)
            is_critical = comp_metadata.critical if comp_metadata else False
            
            # Calculate score based on:
            # - Number of direct dependents (40%)
            # - Number of transitive dependents (30%)
            # - Whether marked as critical (20%)
            # - Component type criticality (10%)
            
            max_dependents = max(len(self._graph.nodes()), 1)
            direct_score = min(direct_dependents / max_dependents, 1.0) * 0.4
            transitive_score = min(transitive_dependents / max_dependents, 1.0) * 0.3
            critical_score = 0.2 if is_critical else 0.0
            
            # Component type criticality
            type_criticality = {
                ComponentType.DATABASE: 0.1,
                ComponentType.CACHE: 0.08,
                ComponentType.QUEUE: 0.08,
                ComponentType.API_ENDPOINT: 0.06,
                ComponentType.SERVICE: 0.05,
                ComponentType.ENGINE: 0.05,
                ComponentType.EXTERNAL_DEPENDENCY: 0.07
            }
            
            comp_type = comp_metadata.component_type if comp_metadata else ComponentType.SERVICE
            type_score = type_criticality.get(comp_type, 0.03)
            
            total_score = direct_score + transitive_score + critical_score + type_score
            return min(total_score, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating criticality score for {component}: {e}")
            return 0.0
    
    def _clear_caches(self):
        """Clear internal caches."""
        self._dependency_cache.clear()
        self._reverse_dependency_cache.clear()
        self._critical_paths.clear()
    
    def get_graph_statistics(self) -> Dict[str, Any]:
        """Get statistics about the dependency graph."""
        try:
            num_nodes = self._graph.number_of_nodes()
            num_edges = self._graph.number_of_edges()
            
            # Calculate graph metrics
            density = nx.density(self._graph) if num_nodes > 1 else 0.0
            
            # Find strongly connected components
            scc = list(nx.strongly_connected_components(self._graph))
            largest_scc_size = max(len(component) for component in scc) if scc else 0
            
            # Find cycles
            cycles = self.detect_circular_dependencies()
            
            # Calculate average dependencies per component
            avg_dependencies = num_edges / num_nodes if num_nodes > 0 else 0
            
            return {
                "nodes": num_nodes,
                "edges": num_edges,
                "density": density,
                "circular_dependencies": len(cycles),
                "strongly_connected_components": len(scc),
                "largest_scc_size": largest_scc_size,
                "average_dependencies_per_component": avg_dependencies,
                "last_analysis": self._last_analysis.isoformat() if self._last_analysis else None
            }
            
        except Exception as e:
            logger.error(f"Error calculating graph statistics: {e}")
            return {"error": str(e)}


class DependencyAnalyzer:
    """Analyzes component dependencies and their impacts."""
    
    def __init__(self, dependency_graph: DependencyGraph):
        self.graph = dependency_graph
        self._impact_cache: Dict[str, List[ImpactAnalysisResult]] = {}
    
    def analyze_failure_impact(self, failed_component: str, health_data: Optional[Dict[str, Any]] = None) -> List[ImpactAnalysisResult]:
        """Analyze the impact of a component failure."""
        if failed_component in self._impact_cache:
            return self._impact_cache[failed_component]
        
        impacts = []
        
        try:
            # Get all components that depend on the failed component
            affected_components = self.graph.get_reverse_dependencies(failed_component, include_transitive=True)
            
            for affected_comp in affected_components:
                impact = self._calculate_component_impact(failed_component, affected_comp, health_data)
                impacts.append(impact)
            
            # Sort by impact level and failure probability
            impacts.sort(key=lambda x: (x.impact_level.value, -x.failure_probability))
            
            self._impact_cache[failed_component] = impacts
            
        except Exception as e:
            logger.error(f"Error analyzing failure impact for {failed_component}: {e}")
        
        return impacts
    
    def _calculate_component_impact(
        self, 
        failed_component: str, 
        affected_component: str, 
        health_data: Optional[Dict[str, Any]]
    ) -> ImpactAnalysisResult:
        """Calculate impact on a specific component."""
        try:
            # Find dependency chains
            chains = self.graph.find_dependency_chains(affected_component, failed_component)
            shortest_chain = min(chains, key=len) if chains else [affected_component, failed_component]
            
            # Determine impact level based on dependency type and criticality
            impact_level = self._determine_impact_level(failed_component, affected_component, shortest_chain)
            
            # Calculate failure probability
            failure_probability = self._calculate_failure_probability(shortest_chain, health_data)
            
            # Estimate downtime
            downtime = self._estimate_downtime(impact_level, affected_component)
            
            # Generate mitigation suggestions
            mitigations = self._generate_mitigation_suggestions(failed_component, affected_component, impact_level)
            
            return ImpactAnalysisResult(
                affected_component=affected_component,
                impact_level=impact_level,
                dependency_chain=shortest_chain,
                failure_probability=failure_probability,
                estimated_downtime_minutes=downtime,
                mitigation_suggestions=mitigations,
                metadata={
                    "all_chains": chains,
                    "chain_count": len(chains),
                    "shortest_chain_length": len(shortest_chain)
                }
            )
            
        except Exception as e:
            logger.error(f"Error calculating impact for {affected_component}: {e}")
            return ImpactAnalysisResult(
                affected_component=affected_component,
                impact_level=ImpactLevel.LOW,
                dependency_chain=[affected_component, failed_component],
                failure_probability=0.5,
                estimated_downtime_minutes=30,
                metadata={"error": str(e)}
            )
    
    def _determine_impact_level(self, failed_component: str, affected_component: str, chain: List[str]) -> ImpactLevel:
        """Determine the impact level of a failure."""
        try:
            # Get component metadata
            failed_comp = self.graph.registry.get_component(failed_component)
            affected_comp = self.graph.registry.get_component(affected_component)
            
            # Check if components are critical
            failed_critical = failed_comp.critical if failed_comp else False
            affected_critical = affected_comp.critical if affected_comp else False
            
            # Check dependency type in the chain
            has_hard_dependency = False
            if len(chain) >= 2:
                for i in range(len(chain) - 1):
                    if self.graph._graph.has_edge(chain[i], chain[i + 1]):
                        edge_data = self.graph._graph[chain[i]][chain[i + 1]]
                        if edge_data.get('dependency_type') == DependencyType.HARD.value:
                            has_hard_dependency = True
                            break
            
            # Determine impact level
            if failed_critical and affected_critical and has_hard_dependency:
                return ImpactLevel.CRITICAL
            elif (failed_critical or affected_critical) and has_hard_dependency:
                return ImpactLevel.HIGH
            elif has_hard_dependency:
                return ImpactLevel.MEDIUM
            elif len(chain) <= 3:  # Short dependency chain
                return ImpactLevel.MEDIUM
            else:
                return ImpactLevel.LOW
            
        except Exception as e:
            logger.debug(f"Error determining impact level: {e}")
            return ImpactLevel.MEDIUM
    
    def _calculate_failure_probability(self, chain: List[str], health_data: Optional[Dict[str, Any]]) -> float:
        """Calculate the probability of failure propagating through the chain."""
        if not health_data:
            return 0.5  # Default probability
        
        try:
            # Base probability based on chain length (shorter chains = higher probability)
            base_prob = 1.0 / (1.0 + len(chain) * 0.1)
            
            # Adjust based on health status of components in chain
            unhealthy_count = 0
            degraded_count = 0
            
            for component in chain:
                comp_health = health_data.get(component, {})
                status = comp_health.get('status', HealthStatus.UNKNOWN.value)
                
                if status == HealthStatus.UNHEALTHY.value:
                    unhealthy_count += 1
                elif status == HealthStatus.DEGRADED.value:
                    degraded_count += 1
            
            # Increase probability based on unhealthy components
            health_multiplier = 1.0 + (unhealthy_count * 0.3) + (degraded_count * 0.1)
            
            return min(base_prob * health_multiplier, 1.0)
            
        except Exception as e:
            logger.debug(f"Error calculating failure probability: {e}")
            return 0.5
    
    def _estimate_downtime(self, impact_level: ImpactLevel, component: str) -> int:
        """Estimate downtime in minutes based on impact level."""
        base_downtime = {
            ImpactLevel.CRITICAL: 60,    # 1 hour
            ImpactLevel.HIGH: 30,        # 30 minutes
            ImpactLevel.MEDIUM: 15,      # 15 minutes
            ImpactLevel.LOW: 5,          # 5 minutes
            ImpactLevel.NONE: 0
        }
        
        # Adjust based on component type
        comp_metadata = self.graph.registry.get_component(component)
        if comp_metadata:
            if comp_metadata.component_type == ComponentType.DATABASE:
                return base_downtime[impact_level] * 2  # Databases take longer to recover
            elif comp_metadata.component_type == ComponentType.CACHE:
                return base_downtime[impact_level] // 2  # Caches recover quickly
        
        return base_downtime.get(impact_level, 15)
    
    def _generate_mitigation_suggestions(self, failed_component: str, affected_component: str, impact_level: ImpactLevel) -> List[str]:
        """Generate mitigation suggestions for the failure."""
        suggestions = []
        
        # General suggestions based on impact level
        if impact_level == ImpactLevel.CRITICAL:
            suggestions.extend([
                "Implement immediate failover procedures",
                "Activate disaster recovery protocols",
                "Consider manual intervention for critical processes"
            ])
        elif impact_level == ImpactLevel.HIGH:
            suggestions.extend([
                "Enable circuit breaker patterns",
                "Switch to backup services if available",
                "Implement graceful degradation"
            ])
        else:
            suggestions.extend([
                "Enable retry mechanisms with exponential backoff",
                "Queue requests for later processing",
                "Use cached data if available"
            ])
        
        # Component-specific suggestions
        failed_comp = self.graph.registry.get_component(failed_component)
        if failed_comp:
            if failed_comp.component_type == ComponentType.DATABASE:
                suggestions.append("Switch to read-only replica if available")
            elif failed_comp.component_type == ComponentType.CACHE:
                suggestions.append("Temporarily disable caching and use direct data access")
            elif failed_comp.component_type == ComponentType.API_ENDPOINT:
                suggestions.append("Route traffic to alternative API endpoints")
        
        return suggestions
    
    def analyze_cascading_failures(self, initial_failures: List[str], health_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze potential cascading failures from multiple initial failures."""
        all_impacts = []
        affected_components = set()
        
        for failed_component in initial_failures:
            impacts = self.analyze_failure_impact(failed_component, health_data)
            all_impacts.extend(impacts)
            
            for impact in impacts:
                affected_components.add(impact.affected_component)
        
        # Calculate overall system impact
        critical_impacts = [i for i in all_impacts if i.impact_level == ImpactLevel.CRITICAL]
        high_impacts = [i for i in all_impacts if i.impact_level == ImpactLevel.HIGH]
        
        return {
            "initial_failures": initial_failures,
            "total_affected_components": len(affected_components),
            "critical_impacts": len(critical_impacts),
            "high_impacts": len(high_impacts),
            "estimated_total_downtime_minutes": sum(i.estimated_downtime_minutes for i in all_impacts),
            "system_wide_failure_risk": len(critical_impacts) / max(len(affected_components), 1),
            "detailed_impacts": [
                {
                    "component": i.affected_component,
                    "impact_level": i.impact_level.value,
                    "chain": " -> ".join(i.dependency_chain),
                    "probability": i.failure_probability,
                    "downtime_minutes": i.estimated_downtime_minutes
                }
                for i in sorted(all_impacts, key=lambda x: (x.impact_level.value, -x.failure_probability))
            ]
        }


class CriticalPathFinder:
    """Identifies critical paths and bottlenecks in the system."""
    
    def __init__(self, dependency_graph: DependencyGraph):
        self.graph = dependency_graph
        self._critical_paths: List[CriticalPath] = []
    
    def find_critical_paths(self, max_paths: int = 10) -> List[CriticalPath]:
        """Find the most critical paths through the system."""
        self._critical_paths.clear()
        
        try:
            # Find all longest paths in the graph
            longest_paths = self._find_longest_paths()
            
            # Score and rank paths
            scored_paths = []
            for path in longest_paths:
                critical_path = self._analyze_path_criticality(path)
                scored_paths.append(critical_path)
            
            # Sort by risk score and take top paths
            scored_paths.sort(key=lambda x: x.risk_score, reverse=True)
            self._critical_paths = scored_paths[:max_paths]
            
            return self._critical_paths
            
        except Exception as e:
            logger.error(f"Error finding critical paths: {e}")
            return []
    
    def _find_longest_paths(self) -> List[List[str]]:
        """Find longest paths in the dependency graph."""
        try:
            # Use topological sort to find longest paths
            if not nx.is_directed_acyclic_graph(self.graph._graph):
                # Remove cycles first
                cycles = list(nx.simple_cycles(self.graph._graph))
                temp_graph = self.graph._graph.copy()
                
                for cycle in cycles:
                    if len(cycle) > 1:
                        temp_graph.remove_edge(cycle[-1], cycle[0])
            else:
                temp_graph = self.graph._graph
            
            longest_paths = []
            
            # Find all simple paths between nodes with no predecessors and nodes with no successors
            sources = [n for n, d in temp_graph.in_degree() if d == 0]
            sinks = [n for n, d in temp_graph.out_degree() if d == 0]
            
            for source in sources:
                for sink in sinks:
                    try:
                        paths = list(nx.all_simple_paths(temp_graph, source, sink))
                        longest_paths.extend(paths)
                    except nx.NetworkXNoPath:
                        continue
            
            # Filter to keep only longest paths (at least 3 nodes)
            min_length = 3
            return [path for path in longest_paths if len(path) >= min_length]
            
        except Exception as e:
            logger.error(f"Error finding longest paths: {e}")
            return []
    
    def _analyze_path_criticality(self, path: List[str]) -> CriticalPath:
        """Analyze the criticality of a specific path."""
        try:
            # Calculate total weight
            total_weight = 0.0
            for i in range(len(path) - 1):
                if self.graph._graph.has_edge(path[i], path[i + 1]):
                    edge_data = self.graph._graph[path[i]][path[i + 1]]
                    total_weight += edge_data.get('weight', 1.0)
            
            # Calculate risk score based on multiple factors
            risk_factors = []
            
            # Factor 1: Number of critical components in path
            critical_components = 0
            for component in path:
                comp_metadata = self.graph.registry.get_component(component)
                if comp_metadata and comp_metadata.critical:
                    critical_components += 1
            
            critical_factor = critical_components / len(path)
            risk_factors.append(critical_factor * 0.3)
            
            # Factor 2: Individual component criticality scores
            criticality_scores = [self.graph.get_component_criticality_score(comp) for comp in path]
            avg_criticality = sum(criticality_scores) / len(criticality_scores)
            risk_factors.append(avg_criticality * 0.4)
            
            # Factor 3: Path length (longer paths are riskier)
            length_factor = min(len(path) / 10, 1.0)  # Normalize to max 10 components
            risk_factors.append(length_factor * 0.2)
            
            # Factor 4: Edge weight (dependency strength)
            weight_factor = min(total_weight / len(path), 1.0)
            risk_factors.append(weight_factor * 0.1)
            
            risk_score = sum(risk_factors)
            
            # Identify bottlenecks (components with highest criticality scores)
            bottlenecks = []
            max_criticality = max(criticality_scores)
            if max_criticality > 0.7:  # High criticality threshold
                for i, score in enumerate(criticality_scores):
                    if score >= max_criticality * 0.9:  # Within 90% of max
                        bottlenecks.append(path[i])
            
            # Generate description
            description = f"Critical path with {len(path)} components"
            if bottlenecks:
                description += f", bottlenecks: {', '.join(bottlenecks)}"
            
            return CriticalPath(
                path=path,
                total_weight=total_weight,
                risk_score=risk_score,
                components_count=len(path),
                description=description,
                bottlenecks=bottlenecks
            )
            
        except Exception as e:
            logger.error(f"Error analyzing path criticality: {e}")
            return CriticalPath(
                path=path,
                total_weight=0.0,
                risk_score=0.0,
                components_count=len(path),
                description="Error analyzing path"
            )
    
    def get_bottleneck_analysis(self) -> Dict[str, Any]:
        """Analyze system bottlenecks across all critical paths."""
        bottleneck_counts = defaultdict(int)
        total_risk_by_component = defaultdict(float)
        
        for critical_path in self._critical_paths:
            for bottleneck in critical_path.bottlenecks:
                bottleneck_counts[bottleneck] += 1
                total_risk_by_component[bottleneck] += critical_path.risk_score
        
        # Sort bottlenecks by frequency and risk
        sorted_bottlenecks = sorted(
            bottleneck_counts.items(),
            key=lambda x: (x[1], total_risk_by_component[x[0]]),
            reverse=True
        )
        
        return {
            "top_bottlenecks": [
                {
                    "component": comp,
                    "frequency": count,
                    "total_risk": total_risk_by_component[comp],
                    "avg_risk": total_risk_by_component[comp] / count,
                    "criticality_score": self.graph.get_component_criticality_score(comp)
                }
                for comp, count in sorted_bottlenecks[:10]
            ],
            "total_critical_paths": len(self._critical_paths),
            "analysis_timestamp": datetime.utcnow().isoformat()
        }


# Factory functions and utilities

def create_dependency_graph(registry: Optional[ComponentRegistry] = None) -> DependencyGraph:
    """Create and initialize a dependency graph."""
    return DependencyGraph(registry)


def build_dependencies_from_registry(graph: DependencyGraph) -> None:
    """Build dependencies from component registry metadata."""
    components = graph.registry.list_components()
    
    for component in components:
        for dep_name in component.dependencies:
            dependency = DependencyEdge(
                source=component.name,
                target=dep_name,
                dependency_type=DependencyType.HARD,  # Default to hard dependency
                description=f"Dependency from {component.name} to {dep_name}",
                weight=1.0
            )
            graph.add_dependency(dependency)
    
    logger.info(f"Built {graph._graph.number_of_edges()} dependencies from registry")


def create_analyzer(graph: DependencyGraph) -> DependencyAnalyzer:
    """Create a dependency analyzer."""
    return DependencyAnalyzer(graph)


def create_critical_path_finder(graph: DependencyGraph) -> CriticalPathFinder:
    """Create a critical path finder."""
    return CriticalPathFinder(graph)