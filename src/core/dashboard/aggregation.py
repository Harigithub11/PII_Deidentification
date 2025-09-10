"""
Data Aggregation Engine

Handles data aggregation, metric calculation, and query optimization
for dashboard widgets and business intelligence reporting.
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable, Tuple
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, deque
import statistics
import json

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import text, func, and_, or_

logger = logging.getLogger(__name__)


class AggregationType(str, Enum):
    """Types of data aggregation operations."""
    COUNT = "count"
    SUM = "sum"
    AVG = "average"
    MIN = "minimum" 
    MAX = "maximum"
    MEDIAN = "median"
    PERCENTILE = "percentile"
    DISTINCT_COUNT = "distinct_count"
    RATE = "rate"
    RATIO = "ratio"
    GROWTH = "growth"
    MOVING_AVERAGE = "moving_average"
    CUMULATIVE = "cumulative"


class TimeGranularity(str, Enum):
    """Time-based aggregation granularity."""
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    QUARTER = "quarter"
    YEAR = "year"


class DataSourceType(str, Enum):
    """Types of data sources for aggregation."""
    DATABASE = "database"
    API = "api"
    CACHE = "cache"
    FILE = "file"
    STREAM = "stream"
    WEBHOOK = "webhook"


@dataclass
class AggregationRule:
    """Rule defining how data should be aggregated."""
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    source_table: str = ""
    source_column: str = ""
    aggregation_type: AggregationType = AggregationType.COUNT
    time_column: Optional[str] = None
    time_granularity: Optional[TimeGranularity] = None
    group_by_columns: List[str] = field(default_factory=list)
    filters: Dict[str, Any] = field(default_factory=dict)
    having_conditions: Dict[str, Any] = field(default_factory=dict)
    order_by: Optional[str] = None
    limit: Optional[int] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    cache_duration_minutes: int = 5


class MetricDefinition(BaseModel):
    """Definition of a metric for calculation."""
    
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    
    # Data source configuration
    data_source: DataSourceType
    query_template: str  # SQL query template with placeholders
    
    # Aggregation settings
    aggregation_rules: List[AggregationRule] = Field(default_factory=list)
    time_range_hours: int = 24  # Default time window
    refresh_interval_minutes: int = 15
    
    # Calculation parameters
    calculation_method: str = "direct"  # direct, derived, calculated
    dependencies: List[UUID] = Field(default_factory=list)  # Other metrics this depends on
    formula: Optional[str] = None  # Formula for calculated metrics
    
    # Display and formatting
    unit: str = "count"
    format_string: str = "{value}"
    decimal_places: int = 2
    
    # Metadata
    category: str = "general"
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


@dataclass
class AggregationResult:
    """Result of a data aggregation operation."""
    metric_id: UUID
    timestamp: datetime
    value: Union[int, float, str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    dimensions: Dict[str, Any] = field(default_factory=dict)
    calculation_time_ms: int = 0
    cached: bool = False


class MetricAggregator:
    """
    Handles aggregation of individual metrics with caching and optimization.
    """
    
    def __init__(self, session: Optional[Session] = None):
        self._session = session
        self._cache: Dict[str, Tuple[Any, datetime]] = {}
        self._active_calculations: Dict[str, asyncio.Task] = {}
        
        # Statistical tracking
        self._calculation_times = deque(maxlen=100)
        self._cache_hit_count = 0
        self._cache_miss_count = 0
    
    async def calculate_metric(self, 
                             definition: MetricDefinition,
                             time_range: Optional[Tuple[datetime, datetime]] = None,
                             filters: Optional[Dict[str, Any]] = None) -> AggregationResult:
        """
        Calculate a metric value based on its definition.
        
        Args:
            definition: Metric definition
            time_range: Optional time range override
            filters: Additional filters to apply
            
        Returns:
            Aggregation result with calculated value
        """
        start_time = datetime.utcnow()
        
        try:
            # Generate cache key
            cache_key = self._generate_cache_key(definition, time_range, filters)
            
            # Check cache first
            cached_result = self._get_cached_result(cache_key, definition.refresh_interval_minutes)
            if cached_result:
                self._cache_hit_count += 1
                return cached_result
            
            self._cache_miss_count += 1
            
            # Prevent duplicate calculations
            if cache_key in self._active_calculations:
                return await self._active_calculations[cache_key]
            
            # Start calculation
            calculation_task = asyncio.create_task(
                self._perform_calculation(definition, time_range, filters)
            )
            self._active_calculations[cache_key] = calculation_task
            
            try:
                result = await calculation_task
                
                # Update timing
                calculation_time = (datetime.utcnow() - start_time).total_seconds() * 1000
                result.calculation_time_ms = int(calculation_time)
                self._calculation_times.append(calculation_time)
                
                # Cache result
                self._cache_result(cache_key, result)
                
                return result
                
            finally:
                # Clean up active calculation
                self._active_calculations.pop(cache_key, None)
                
        except Exception as e:
            logger.error(f"Failed to calculate metric {definition.id}: {e}")
            
            # Return error result
            return AggregationResult(
                metric_id=definition.id,
                timestamp=datetime.utcnow(),
                value=0,
                metadata={"error": str(e), "error_type": type(e).__name__},
                calculation_time_ms=(datetime.utcnow() - start_time).total_seconds() * 1000
            )
    
    async def _perform_calculation(self,
                                 definition: MetricDefinition,
                                 time_range: Optional[Tuple[datetime, datetime]],
                                 filters: Optional[Dict[str, Any]]) -> AggregationResult:
        """Perform the actual metric calculation."""
        
        if definition.calculation_method == "direct":
            return await self._calculate_direct_metric(definition, time_range, filters)
        elif definition.calculation_method == "derived":
            return await self._calculate_derived_metric(definition, time_range, filters)
        elif definition.calculation_method == "calculated":
            return await self._calculate_formula_metric(definition, time_range, filters)
        else:
            raise ValueError(f"Unknown calculation method: {definition.calculation_method}")
    
    async def _calculate_direct_metric(self,
                                     definition: MetricDefinition,
                                     time_range: Optional[Tuple[datetime, datetime]],
                                     filters: Optional[Dict[str, Any]]) -> AggregationResult:
        """Calculate metric directly from database query."""
        
        # Build query from template
        query = self._build_query(definition, time_range, filters)
        
        if definition.data_source == DataSourceType.DATABASE:
            result = await self._execute_database_query(query)
        elif definition.data_source == DataSourceType.API:
            result = await self._execute_api_query(definition, filters)
        elif definition.data_source == DataSourceType.CACHE:
            result = await self._execute_cache_query(definition, filters)
        else:
            raise ValueError(f"Unsupported data source: {definition.data_source}")
        
        return AggregationResult(
            metric_id=definition.id,
            timestamp=datetime.utcnow(),
            value=result.get("value", 0),
            metadata=result.get("metadata", {}),
            dimensions=result.get("dimensions", {})
        )
    
    async def _calculate_derived_metric(self,
                                      definition: MetricDefinition,
                                      time_range: Optional[Tuple[datetime, datetime]],
                                      filters: Optional[Dict[str, Any]]) -> AggregationResult:
        """Calculate metric derived from other metrics."""
        
        # Get dependency values
        dependency_values = {}
        for dep_id in definition.dependencies:
            # This would typically fetch from another aggregator or cache
            dependency_values[str(dep_id)] = 42  # Placeholder
        
        # Apply derived calculation logic
        value = self._apply_derived_calculation(definition, dependency_values)
        
        return AggregationResult(
            metric_id=definition.id,
            timestamp=datetime.utcnow(),
            value=value,
            metadata={"dependencies": dependency_values},
            dimensions={}
        )
    
    async def _calculate_formula_metric(self,
                                      definition: MetricDefinition,
                                      time_range: Optional[Tuple[datetime, datetime]],
                                      filters: Optional[Dict[str, Any]]) -> AggregationResult:
        """Calculate metric using custom formula."""
        
        if not definition.formula:
            raise ValueError("Formula is required for calculated metrics")
        
        # Get variables for formula
        variables = await self._get_formula_variables(definition, time_range, filters)
        
        # Evaluate formula safely
        try:
            value = self._evaluate_formula(definition.formula, variables)
        except Exception as e:
            raise ValueError(f"Formula evaluation failed: {e}")
        
        return AggregationResult(
            metric_id=definition.id,
            timestamp=datetime.utcnow(),
            value=value,
            metadata={"formula": definition.formula, "variables": variables},
            dimensions={}
        )
    
    def _build_query(self,
                    definition: MetricDefinition,
                    time_range: Optional[Tuple[datetime, datetime]],
                    filters: Optional[Dict[str, Any]]) -> str:
        """Build SQL query from template and parameters."""
        
        query = definition.query_template
        
        # Replace time range placeholders
        if time_range:
            query = query.replace("{{start_time}}", f"'{time_range[0].isoformat()}'")
            query = query.replace("{{end_time}}", f"'{time_range[1].isoformat()}'")
        else:
            # Use default time range
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=definition.time_range_hours)
            query = query.replace("{{start_time}}", f"'{start_time.isoformat()}'")
            query = query.replace("{{end_time}}", f"'{end_time.isoformat()}'")
        
        # Replace filter placeholders
        if filters:
            for key, value in filters.items():
                placeholder = f"{{{{{key}}}}}"
                if isinstance(value, str):
                    query = query.replace(placeholder, f"'{value}'")
                else:
                    query = query.replace(placeholder, str(value))
        
        return query
    
    async def _execute_database_query(self, query: str) -> Dict[str, Any]:
        """Execute database query and return result."""
        # This is a placeholder - would use actual database session
        # For now, return sample data
        return {
            "value": 42,
            "metadata": {"query": query, "rows_processed": 1000},
            "dimensions": {}
        }
    
    async def _execute_api_query(self, definition: MetricDefinition, filters: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute API query to fetch metric data."""
        # Placeholder for API integration
        return {"value": 24, "metadata": {"source": "api"}, "dimensions": {}}
    
    async def _execute_cache_query(self, definition: MetricDefinition, filters: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute cache query to fetch metric data."""
        # Placeholder for cache integration
        return {"value": 84, "metadata": {"source": "cache"}, "dimensions": {}}
    
    def _apply_derived_calculation(self, definition: MetricDefinition, dependencies: Dict[str, Any]) -> Union[int, float]:
        """Apply derived calculation logic."""
        # This would implement specific derivation logic
        # For now, return sum of dependencies
        return sum(v for v in dependencies.values() if isinstance(v, (int, float)))
    
    async def _get_formula_variables(self,
                                   definition: MetricDefinition,
                                   time_range: Optional[Tuple[datetime, datetime]],
                                   filters: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Get variables needed for formula evaluation."""
        # This would fetch required data for formula variables
        return {"a": 10, "b": 5, "c": 2}
    
    def _evaluate_formula(self, formula: str, variables: Dict[str, Any]) -> Union[int, float]:
        """Safely evaluate mathematical formula."""
        # Simple expression evaluator - in production would use safer evaluation
        try:
            # Replace variables in formula
            expr = formula
            for var_name, var_value in variables.items():
                expr = expr.replace(var_name, str(var_value))
            
            # Evaluate basic mathematical expressions
            # This is simplified - production would use ast.literal_eval or similar
            return eval(expr)
        except Exception as e:
            raise ValueError(f"Invalid formula: {formula}")
    
    def _generate_cache_key(self,
                          definition: MetricDefinition,
                          time_range: Optional[Tuple[datetime, datetime]],
                          filters: Optional[Dict[str, Any]]) -> str:
        """Generate cache key for metric calculation."""
        import hashlib
        
        key_data = {
            "metric_id": str(definition.id),
            "time_range": [t.isoformat() for t in time_range] if time_range else None,
            "filters": filters or {},
            "query_template": definition.query_template
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _get_cached_result(self, cache_key: str, refresh_interval_minutes: int) -> Optional[AggregationResult]:
        """Get cached result if not expired."""
        if cache_key in self._cache:
            result, cached_at = self._cache[cache_key]
            if datetime.utcnow() - cached_at < timedelta(minutes=refresh_interval_minutes):
                result.cached = True
                return result
        return None
    
    def _cache_result(self, cache_key: str, result: AggregationResult) -> None:
        """Cache calculation result."""
        self._cache[cache_key] = (result, datetime.utcnow())
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics for this aggregator."""
        avg_calc_time = statistics.mean(self._calculation_times) if self._calculation_times else 0
        total_requests = self._cache_hit_count + self._cache_miss_count
        hit_ratio = self._cache_hit_count / total_requests if total_requests > 0 else 0
        
        return {
            "total_calculations": len(self._calculation_times),
            "average_calculation_time_ms": round(avg_calc_time, 2),
            "cache_hit_count": self._cache_hit_count,
            "cache_miss_count": self._cache_miss_count,
            "cache_hit_ratio": round(hit_ratio, 4),
            "cached_entries": len(self._cache),
            "active_calculations": len(self._active_calculations)
        }


class DataAggregationEngine:
    """
    Main engine for coordinating data aggregation across multiple metrics
    and data sources with batch processing and optimization.
    """
    
    def __init__(self, session: Optional[Session] = None):
        self._session = session
        self._aggregators: Dict[str, MetricAggregator] = {}
        self._metric_definitions: Dict[UUID, MetricDefinition] = {}
        self._batch_queue: Dict[str, List[Tuple[MetricDefinition, Dict[str, Any]]]] = defaultdict(list)
        self._batch_processor_task: Optional[asyncio.Task] = None
        self._is_running = False
        
        logger.info("Data Aggregation Engine initialized")
    
    async def start(self) -> None:
        """Start the aggregation engine and batch processor."""
        if self._is_running:
            return
        
        self._is_running = True
        self._batch_processor_task = asyncio.create_task(self._batch_processor_loop())
        logger.info("Data Aggregation Engine started")
    
    async def stop(self) -> None:
        """Stop the aggregation engine."""
        self._is_running = False
        
        if self._batch_processor_task:
            self._batch_processor_task.cancel()
            try:
                await self._batch_processor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Data Aggregation Engine stopped")
    
    def register_metric(self, definition: MetricDefinition) -> None:
        """Register a metric definition."""
        self._metric_definitions[definition.id] = definition
        
        # Create dedicated aggregator if needed
        aggregator_key = f"{definition.data_source.value}_{definition.category}"
        if aggregator_key not in self._aggregators:
            self._aggregators[aggregator_key] = MetricAggregator(self._session)
        
        logger.info(f"Metric registered: {definition.id} - {definition.name}")
    
    def unregister_metric(self, metric_id: UUID) -> bool:
        """Unregister a metric definition."""
        if metric_id in self._metric_definitions:
            del self._metric_definitions[metric_id]
            logger.info(f"Metric unregistered: {metric_id}")
            return True
        return False
    
    async def calculate_metric(self,
                             metric_id: UUID,
                             time_range: Optional[Tuple[datetime, datetime]] = None,
                             filters: Optional[Dict[str, Any]] = None) -> AggregationResult:
        """Calculate a single metric."""
        if metric_id not in self._metric_definitions:
            raise ValueError(f"Metric not found: {metric_id}")
        
        definition = self._metric_definitions[metric_id]
        aggregator = self._get_aggregator_for_metric(definition)
        
        return await aggregator.calculate_metric(definition, time_range, filters)
    
    async def calculate_metrics_batch(self,
                                    metric_ids: List[UUID],
                                    time_range: Optional[Tuple[datetime, datetime]] = None,
                                    filters: Optional[Dict[str, Any]] = None) -> Dict[UUID, AggregationResult]:
        """Calculate multiple metrics in batch."""
        results = {}
        
        # Group metrics by aggregator for efficient processing
        aggregator_groups = defaultdict(list)
        for metric_id in metric_ids:
            if metric_id in self._metric_definitions:
                definition = self._metric_definitions[metric_id]
                aggregator = self._get_aggregator_for_metric(definition)
                aggregator_groups[aggregator].append((metric_id, definition))
        
        # Process each group concurrently
        tasks = []
        for aggregator, metrics in aggregator_groups.items():
            for metric_id, definition in metrics:
                task = asyncio.create_task(
                    aggregator.calculate_metric(definition, time_range, filters)
                )
                tasks.append((metric_id, task))
        
        # Collect results
        for metric_id, task in tasks:
            try:
                result = await task
                results[metric_id] = result
            except Exception as e:
                logger.error(f"Failed to calculate metric {metric_id}: {e}")
                results[metric_id] = AggregationResult(
                    metric_id=metric_id,
                    timestamp=datetime.utcnow(),
                    value=0,
                    metadata={"error": str(e)}
                )
        
        return results
    
    def queue_metric_calculation(self,
                               metric_id: UUID,
                               priority: str = "normal",
                               time_range: Optional[Tuple[datetime, datetime]] = None,
                               filters: Optional[Dict[str, Any]] = None) -> None:
        """Queue metric calculation for batch processing."""
        if metric_id not in self._metric_definitions:
            return
        
        definition = self._metric_definitions[metric_id]
        calculation_params = {
            "time_range": time_range,
            "filters": filters,
            "queued_at": datetime.utcnow()
        }
        
        self._batch_queue[priority].append((definition, calculation_params))
        logger.debug(f"Metric queued for calculation: {metric_id}")
    
    async def _batch_processor_loop(self) -> None:
        """Background loop for processing queued calculations."""
        while self._is_running:
            try:
                await self._process_batch_queue()
                await asyncio.sleep(5)  # Process every 5 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in batch processor: {e}")
                await asyncio.sleep(10)
    
    async def _process_batch_queue(self) -> None:
        """Process queued metric calculations."""
        if not any(self._batch_queue.values()):
            return
        
        # Process high priority first, then normal, then low
        for priority in ["high", "normal", "low"]:
            if not self._batch_queue[priority]:
                continue
            
            batch = self._batch_queue[priority][:10]  # Process up to 10 at a time
            self._batch_queue[priority] = self._batch_queue[priority][10:]
            
            # Process batch concurrently
            tasks = []
            for definition, params in batch:
                aggregator = self._get_aggregator_for_metric(definition)
                task = asyncio.create_task(
                    aggregator.calculate_metric(
                        definition,
                        params.get("time_range"),
                        params.get("filters")
                    )
                )
                tasks.append(task)
            
            # Wait for completion
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                logger.debug(f"Processed {len(tasks)} metrics from {priority} queue")
    
    def _get_aggregator_for_metric(self, definition: MetricDefinition) -> MetricAggregator:
        """Get appropriate aggregator for metric definition."""
        aggregator_key = f"{definition.data_source.value}_{definition.category}"
        
        if aggregator_key not in self._aggregators:
            self._aggregators[aggregator_key] = MetricAggregator(self._session)
        
        return self._aggregators[aggregator_key]
    
    def get_engine_statistics(self) -> Dict[str, Any]:
        """Get comprehensive engine statistics."""
        aggregator_stats = {}
        for key, aggregator in self._aggregators.items():
            aggregator_stats[key] = aggregator.get_performance_stats()
        
        total_queued = sum(len(queue) for queue in self._batch_queue.values())
        
        return {
            "total_registered_metrics": len(self._metric_definitions),
            "total_aggregators": len(self._aggregators),
            "queued_calculations": {
                priority: len(queue) for priority, queue in self._batch_queue.items()
            },
            "total_queued": total_queued,
            "is_running": self._is_running,
            "aggregator_performance": aggregator_stats
        }