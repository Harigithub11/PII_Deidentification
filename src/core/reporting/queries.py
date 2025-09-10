"""
Advanced Query Builder for Audit Data

Provides sophisticated querying capabilities for audit trails, user activities,
and system events with filtering, aggregation, and performance optimization.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from uuid import UUID
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import (
    and_, or_, not_, func, text, case, cast, Integer, String, DateTime,
    distinct, desc, asc, nullslast, nullsfirst
)
from sqlalchemy.orm import Session, Query, joinedload, selectinload
from sqlalchemy.sql import operators

from ..database.models import (
    AuditEvent, UserActivity, SystemEvent, SecurityEvent, 
    DataProcessingLog, User, UserSession, Document
)

logger = logging.getLogger(__name__)


class FilterOperator(str, Enum):
    """Supported filter operators."""
    EQUALS = "eq"
    NOT_EQUALS = "ne"
    IN = "in"
    NOT_IN = "not_in"
    LIKE = "like"
    ILIKE = "ilike"
    GREATER_THAN = "gt"
    GREATER_THAN_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_EQUAL = "lte"
    BETWEEN = "between"
    IS_NULL = "is_null"
    IS_NOT_NULL = "is_not_null"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"


class SortDirection(str, Enum):
    """Sort direction options."""
    ASC = "asc"
    DESC = "desc"


class AggregateFunction(str, Enum):
    """Supported aggregate functions."""
    COUNT = "count"
    SUM = "sum"
    AVG = "avg"
    MIN = "min"
    MAX = "max"
    DISTINCT_COUNT = "distinct_count"


@dataclass
class FilterCondition:
    """Individual filter condition."""
    field: str
    operator: FilterOperator
    value: Any
    table_alias: Optional[str] = None


@dataclass
class SortCondition:
    """Sort condition."""
    field: str
    direction: SortDirection
    table_alias: Optional[str] = None


@dataclass
class AggregateCondition:
    """Aggregate condition."""
    field: str
    function: AggregateFunction
    alias: str
    table_alias: Optional[str] = None


@dataclass
class ReportQuery:
    """Comprehensive query configuration."""
    start_date: datetime
    end_date: datetime
    filters: List[FilterCondition]
    sorts: List[SortCondition]
    aggregates: List[AggregateCondition]
    user_ids: List[UUID]
    resource_types: List[str]
    event_types: List[str]
    limit: Optional[int] = None
    offset: Optional[int] = None
    include_related: bool = False


class QueryBuilder:
    """Advanced query builder for audit data."""
    
    def __init__(self, session: Session):
        self.session = session
        
        # Field mappings for different tables
        self.field_mappings = {
            'audit_events': {
                'id': AuditEvent.id,
                'event_type': AuditEvent.event_type,
                'severity': AuditEvent.severity,
                'outcome': AuditEvent.outcome,
                'user_id': AuditEvent.user_id,
                'username': AuditEvent.username,
                'target_type': AuditEvent.target_type,
                'target_id': AuditEvent.target_id,
                'description': AuditEvent.event_description,
                'timestamp': AuditEvent.event_timestamp,
                'ip_address': AuditEvent.ip_address,
                'risk_score': AuditEvent.risk_score,
                'contains_pii': AuditEvent.contains_pii,
                'duration_ms': AuditEvent.duration_ms
            },
            'user_activities': {
                'id': UserActivity.id,
                'user_id': UserActivity.user_id,
                'activity_type': UserActivity.activity_type,
                'description': UserActivity.activity_description,
                'resource_type': UserActivity.resource_type,
                'resource_id': UserActivity.resource_id,
                'http_method': UserActivity.http_method,
                'endpoint': UserActivity.endpoint,
                'status_code': UserActivity.status_code,
                'response_time_ms': UserActivity.response_time_ms,
                'ip_address': UserActivity.ip_address,
                'is_suspicious': UserActivity.is_suspicious,
                'started_at': UserActivity.started_at,
                'completed_at': UserActivity.completed_at
            },
            'system_events': {
                'id': SystemEvent.id,
                'event_type': SystemEvent.event_type,
                'severity': SystemEvent.severity,
                'event_name': SystemEvent.event_name,
                'description': SystemEvent.event_description,
                'error_code': SystemEvent.error_code,
                'service_name': SystemEvent.service_name,
                'cpu_usage_percent': SystemEvent.cpu_usage_percent,
                'memory_usage_mb': SystemEvent.memory_usage_mb,
                'timestamp': SystemEvent.event_timestamp,
                'requires_attention': SystemEvent.requires_attention,
                'is_resolved': SystemEvent.is_resolved
            }
        }
    
    def build_audit_query(self, start_date: datetime, end_date: datetime,
                         filters: Dict[str, Any] = None, user_ids: List[UUID] = None,
                         resource_types: List[str] = None, event_types: List[str] = None,
                         limit: int = None, offset: int = None) -> ReportQuery:
        """
        Build a comprehensive audit query.
        
        Args:
            start_date: Query start date
            end_date: Query end date
            filters: Additional filters
            user_ids: Filter by specific user IDs
            resource_types: Filter by resource types
            event_types: Filter by event types
            limit: Result limit
            offset: Result offset
            
        Returns:
            ReportQuery object
        """
        filter_conditions = []
        
        # Convert basic filters to FilterCondition objects
        if filters:
            for field, value in filters.items():
                if field == 'severity':
                    filter_conditions.append(FilterCondition(
                        field='severity',
                        operator=FilterOperator.EQUALS,
                        value=value
                    ))
                elif field == 'outcome':
                    filter_conditions.append(FilterCondition(
                        field='outcome',
                        operator=FilterOperator.EQUALS,
                        value=value
                    ))
                elif field == 'ip_address':
                    filter_conditions.append(FilterCondition(
                        field='ip_address',
                        operator=FilterOperator.EQUALS,
                        value=value
                    ))
                elif field == 'risk_score_min':
                    filter_conditions.append(FilterCondition(
                        field='risk_score',
                        operator=FilterOperator.GREATER_THAN_EQUAL,
                        value=value
                    ))
                elif field == 'risk_score_max':
                    filter_conditions.append(FilterCondition(
                        field='risk_score',
                        operator=FilterOperator.LESS_THAN_EQUAL,
                        value=value
                    ))
                elif field == 'contains_pii':
                    filter_conditions.append(FilterCondition(
                        field='contains_pii',
                        operator=FilterOperator.EQUALS,
                        value=bool(value)
                    ))
        
        # Default sort by timestamp descending
        sort_conditions = [
            SortCondition(
                field='timestamp',
                direction=SortDirection.DESC
            )
        ]
        
        return ReportQuery(
            start_date=start_date,
            end_date=end_date,
            filters=filter_conditions,
            sorts=sort_conditions,
            aggregates=[],
            user_ids=user_ids or [],
            resource_types=resource_types or [],
            event_types=event_types or [],
            limit=limit,
            offset=offset,
            include_related=True
        )
    
    def execute_audit_query(self, query: ReportQuery) -> List[AuditEvent]:
        """
        Execute audit query and return results.
        
        Args:
            query: ReportQuery configuration
            
        Returns:
            List of AuditEvent objects
        """
        base_query = self.session.query(AuditEvent)
        
        # Apply time range filter
        base_query = base_query.filter(
            AuditEvent.event_timestamp >= query.start_date,
            AuditEvent.event_timestamp <= query.end_date
        )
        
        # Apply user ID filters
        if query.user_ids:
            base_query = base_query.filter(AuditEvent.user_id.in_(query.user_ids))
        
        # Apply resource type filters
        if query.resource_types:
            base_query = base_query.filter(AuditEvent.target_type.in_(query.resource_types))
        
        # Apply event type filters
        if query.event_types:
            base_query = base_query.filter(AuditEvent.event_type.in_(query.event_types))
        
        # Apply custom filters
        for filter_condition in query.filters:
            base_query = self._apply_filter(base_query, filter_condition, 'audit_events')
        
        # Apply sorting
        for sort_condition in query.sorts:
            base_query = self._apply_sort(base_query, sort_condition, 'audit_events')
        
        # Include related data if requested
        if query.include_related:
            base_query = base_query.options(
                joinedload(AuditEvent.user),
                joinedload(AuditEvent.session),
                selectinload(AuditEvent.details)
            )
        
        # Apply pagination
        if query.offset:
            base_query = base_query.offset(query.offset)
        if query.limit:
            base_query = base_query.limit(query.limit)
        
        return base_query.all()
    
    def execute_user_activity_query(self, query: ReportQuery) -> List[UserActivity]:
        """Execute user activity query."""
        base_query = self.session.query(UserActivity)
        
        # Apply time range filter
        base_query = base_query.filter(
            UserActivity.started_at >= query.start_date,
            UserActivity.started_at <= query.end_date
        )
        
        # Apply user ID filters
        if query.user_ids:
            base_query = base_query.filter(UserActivity.user_id.in_(query.user_ids))
        
        # Apply custom filters
        for filter_condition in query.filters:
            base_query = self._apply_filter(base_query, filter_condition, 'user_activities')
        
        # Apply sorting
        for sort_condition in query.sorts:
            base_query = self._apply_sort(base_query, sort_condition, 'user_activities')
        
        # Include related data if requested
        if query.include_related:
            base_query = base_query.options(
                joinedload(UserActivity.user),
                joinedload(UserActivity.session)
            )
        
        # Apply pagination
        if query.offset:
            base_query = base_query.offset(query.offset)
        if query.limit:
            base_query = base_query.limit(query.limit)
        
        return base_query.all()
    
    def execute_system_events_query(self, query: ReportQuery) -> List[SystemEvent]:
        """Execute system events query."""
        base_query = self.session.query(SystemEvent)
        
        # Apply time range filter
        base_query = base_query.filter(
            SystemEvent.event_timestamp >= query.start_date,
            SystemEvent.event_timestamp <= query.end_date
        )
        
        # Apply custom filters
        for filter_condition in query.filters:
            base_query = self._apply_filter(base_query, filter_condition, 'system_events')
        
        # Apply sorting
        for sort_condition in query.sorts:
            base_query = self._apply_sort(base_query, sort_condition, 'system_events')
        
        # Apply pagination
        if query.offset:
            base_query = base_query.offset(query.offset)
        if query.limit:
            base_query = base_query.limit(query.limit)
        
        return base_query.all()
    
    def execute_aggregate_query(self, query: ReportQuery, table: str = 'audit_events') -> List[Dict[str, Any]]:
        """
        Execute aggregate query for analytics.
        
        Args:
            query: ReportQuery with aggregate conditions
            table: Target table name
            
        Returns:
            List of aggregate results
        """
        if not query.aggregates:
            raise ValueError("No aggregate conditions specified")
        
        # Choose base model
        if table == 'audit_events':
            base_model = AuditEvent
            timestamp_field = AuditEvent.event_timestamp
        elif table == 'user_activities':
            base_model = UserActivity
            timestamp_field = UserActivity.started_at
        elif table == 'system_events':
            base_model = SystemEvent
            timestamp_field = SystemEvent.event_timestamp
        else:
            raise ValueError(f"Unsupported table: {table}")
        
        # Build aggregate query
        aggregate_fields = []
        for agg_condition in query.aggregates:
            field = self._get_field(agg_condition.field, table)
            
            if agg_condition.function == AggregateFunction.COUNT:
                aggregate_fields.append(func.count(field).label(agg_condition.alias))
            elif agg_condition.function == AggregateFunction.DISTINCT_COUNT:
                aggregate_fields.append(func.count(distinct(field)).label(agg_condition.alias))
            elif agg_condition.function == AggregateFunction.SUM:
                aggregate_fields.append(func.sum(field).label(agg_condition.alias))
            elif agg_condition.function == AggregateFunction.AVG:
                aggregate_fields.append(func.avg(field).label(agg_condition.alias))
            elif agg_condition.function == AggregateFunction.MIN:
                aggregate_fields.append(func.min(field).label(agg_condition.alias))
            elif agg_condition.function == AggregateFunction.MAX:
                aggregate_fields.append(func.max(field).label(agg_condition.alias))
        
        base_query = self.session.query(*aggregate_fields)
        base_query = base_query.filter(
            timestamp_field >= query.start_date,
            timestamp_field <= query.end_date
        )
        
        # Apply filters
        for filter_condition in query.filters:
            base_query = self._apply_filter(base_query, filter_condition, table)
        
        result = base_query.first()
        
        # Convert result to dictionary
        if result:
            return [{agg.alias: getattr(result, agg.alias) for agg in query.aggregates}]
        return []
    
    def build_time_series_query(self, start_date: datetime, end_date: datetime,
                              interval: str = 'day', metric_field: str = 'id',
                              table: str = 'audit_events',
                              filters: List[FilterCondition] = None) -> Dict[str, Any]:
        """
        Build time series query for trend analysis.
        
        Args:
            start_date: Start date
            end_date: End date
            interval: Time interval ('hour', 'day', 'week', 'month')
            metric_field: Field to count/aggregate
            table: Source table
            filters: Additional filters
            
        Returns:
            Time series data
        """
        # Choose base model and fields
        if table == 'audit_events':
            base_model = AuditEvent
            timestamp_field = AuditEvent.event_timestamp
        elif table == 'user_activities':
            base_model = UserActivity
            timestamp_field = UserActivity.started_at
        elif table == 'system_events':
            base_model = SystemEvent
            timestamp_field = SystemEvent.event_timestamp
        else:
            raise ValueError(f"Unsupported table: {table}")
        
        # PostgreSQL date truncation
        if interval == 'hour':
            time_bucket = func.date_trunc('hour', timestamp_field)
        elif interval == 'day':
            time_bucket = func.date_trunc('day', timestamp_field)
        elif interval == 'week':
            time_bucket = func.date_trunc('week', timestamp_field)
        elif interval == 'month':
            time_bucket = func.date_trunc('month', timestamp_field)
        else:
            time_bucket = func.date_trunc('day', timestamp_field)
        
        # Build query
        metric_column = self._get_field(metric_field, table)
        base_query = self.session.query(
            time_bucket.label('time_bucket'),
            func.count(metric_column).label('count')
        ).filter(
            timestamp_field >= start_date,
            timestamp_field <= end_date
        )
        
        # Apply additional filters
        if filters:
            for filter_condition in filters:
                base_query = self._apply_filter(base_query, filter_condition, table)
        
        # Group by time bucket and order
        base_query = base_query.group_by(time_bucket).order_by(time_bucket)
        
        results = base_query.all()
        
        return {
            'timestamps': [r.time_bucket.isoformat() for r in results],
            'values': [r.count for r in results],
            'interval': interval,
            'metric': metric_field,
            'total_points': len(results)
        }
    
    def build_distribution_query(self, field: str, table: str = 'audit_events',
                                start_date: datetime = None, end_date: datetime = None,
                                filters: List[FilterCondition] = None,
                                limit: int = 20) -> Dict[str, Any]:
        """
        Build distribution query for categorical data analysis.
        
        Args:
            field: Field to analyze distribution
            table: Source table
            start_date: Optional start date
            end_date: Optional end date
            filters: Additional filters
            limit: Limit results
            
        Returns:
            Distribution data
        """
        # Choose base model
        if table == 'audit_events':
            base_model = AuditEvent
            timestamp_field = AuditEvent.event_timestamp
        elif table == 'user_activities':
            base_model = UserActivity
            timestamp_field = UserActivity.started_at
        elif table == 'system_events':
            base_model = SystemEvent
            timestamp_field = SystemEvent.event_timestamp
        else:
            raise ValueError(f"Unsupported table: {table}")
        
        # Get field column
        field_column = self._get_field(field, table)
        
        # Build query
        base_query = self.session.query(
            field_column.label('category'),
            func.count().label('count')
        )
        
        # Apply date filters if provided
        if start_date and end_date:
            base_query = base_query.filter(
                timestamp_field >= start_date,
                timestamp_field <= end_date
            )
        
        # Apply additional filters
        if filters:
            for filter_condition in filters:
                base_query = self._apply_filter(base_query, filter_condition, table)
        
        # Group, order, and limit
        base_query = base_query.group_by(field_column).order_by(desc(func.count()))
        
        if limit:
            base_query = base_query.limit(limit)
        
        results = base_query.all()
        
        return {
            'field': field,
            'categories': [r.category for r in results],
            'counts': [r.count for r in results],
            'total_categories': len(results),
            'total_items': sum(r.count for r in results)
        }
    
    def _apply_filter(self, query: Query, filter_condition: FilterCondition, table: str) -> Query:
        """Apply individual filter condition to query."""
        field = self._get_field(filter_condition.field, table)
        
        if filter_condition.operator == FilterOperator.EQUALS:
            return query.filter(field == filter_condition.value)
        elif filter_condition.operator == FilterOperator.NOT_EQUALS:
            return query.filter(field != filter_condition.value)
        elif filter_condition.operator == FilterOperator.IN:
            return query.filter(field.in_(filter_condition.value))
        elif filter_condition.operator == FilterOperator.NOT_IN:
            return query.filter(~field.in_(filter_condition.value))
        elif filter_condition.operator == FilterOperator.LIKE:
            return query.filter(field.like(filter_condition.value))
        elif filter_condition.operator == FilterOperator.ILIKE:
            return query.filter(field.ilike(filter_condition.value))
        elif filter_condition.operator == FilterOperator.GREATER_THAN:
            return query.filter(field > filter_condition.value)
        elif filter_condition.operator == FilterOperator.GREATER_THAN_EQUAL:
            return query.filter(field >= filter_condition.value)
        elif filter_condition.operator == FilterOperator.LESS_THAN:
            return query.filter(field < filter_condition.value)
        elif filter_condition.operator == FilterOperator.LESS_THAN_EQUAL:
            return query.filter(field <= filter_condition.value)
        elif filter_condition.operator == FilterOperator.BETWEEN:
            if len(filter_condition.value) == 2:
                return query.filter(field.between(filter_condition.value[0], filter_condition.value[1]))
        elif filter_condition.operator == FilterOperator.IS_NULL:
            return query.filter(field.is_(None))
        elif filter_condition.operator == FilterOperator.IS_NOT_NULL:
            return query.filter(field.is_not(None))
        elif filter_condition.operator == FilterOperator.CONTAINS:
            return query.filter(field.contains(filter_condition.value))
        elif filter_condition.operator == FilterOperator.STARTS_WITH:
            return query.filter(field.startswith(filter_condition.value))
        elif filter_condition.operator == FilterOperator.ENDS_WITH:
            return query.filter(field.endswith(filter_condition.value))
        
        return query
    
    def _apply_sort(self, query: Query, sort_condition: SortCondition, table: str) -> Query:
        """Apply sort condition to query."""
        field = self._get_field(sort_condition.field, table)
        
        if sort_condition.direction == SortDirection.ASC:
            return query.order_by(asc(field))
        else:
            return query.order_by(desc(field))
    
    def _get_field(self, field_name: str, table: str):
        """Get SQLAlchemy field from field name and table."""
        if table in self.field_mappings and field_name in self.field_mappings[table]:
            return self.field_mappings[table][field_name]
        
        raise ValueError(f"Unknown field '{field_name}' for table '{table}'")
    
    def validate_query(self, query: ReportQuery) -> List[str]:
        """
        Validate query and return any errors.
        
        Args:
            query: ReportQuery to validate
            
        Returns:
            List of validation errors
        """
        errors = []
        
        # Validate date range
        if query.end_date <= query.start_date:
            errors.append("End date must be after start date")
        
        # Validate date range is not too large
        date_range = query.end_date - query.start_date
        if date_range.days > 365:
            errors.append("Date range cannot exceed 365 days")
        
        # Validate limit
        if query.limit and query.limit > 100000:
            errors.append("Query limit cannot exceed 100,000 records")
        
        # Validate filter fields
        for filter_condition in query.filters:
            if filter_condition.field not in self.field_mappings.get('audit_events', {}):
                errors.append(f"Unknown filter field: {filter_condition.field}")
        
        # Validate sort fields
        for sort_condition in query.sorts:
            if sort_condition.field not in self.field_mappings.get('audit_events', {}):
                errors.append(f"Unknown sort field: {sort_condition.field}")
        
        return errors
    
    def optimize_query(self, query: ReportQuery) -> ReportQuery:
        """
        Optimize query for better performance.
        
        Args:
            query: Original query
            
        Returns:
            Optimized query
        """
        optimized_query = query
        
        # Add reasonable limit if none specified
        if not optimized_query.limit:
            optimized_query.limit = 10000
        
        # Optimize sorts - limit to 2 sort conditions
        if len(optimized_query.sorts) > 2:
            optimized_query.sorts = optimized_query.sorts[:2]
        
        # Add index hints for common query patterns
        # This would depend on actual database indexes
        
        return optimized_query


class AuditQueryFilter:
    """Helper class for building common audit query filters."""
    
    @staticmethod
    def failed_logins() -> List[FilterCondition]:
        """Filter for failed login attempts."""
        return [
            FilterCondition('event_type', FilterOperator.IN, ['user_login']),
            FilterCondition('outcome', FilterOperator.EQUALS, 'failure')
        ]
    
    @staticmethod
    def high_risk_events() -> List[FilterCondition]:
        """Filter for high-risk security events."""
        return [
            FilterCondition('severity', FilterOperator.IN, ['high', 'critical']),
            FilterCondition('risk_score', FilterOperator.GREATER_THAN_EQUAL, 70)
        ]
    
    @staticmethod
    def pii_related_events() -> List[FilterCondition]:
        """Filter for PII-related events."""
        return [
            FilterCondition('contains_pii', FilterOperator.EQUALS, True)
        ]
    
    @staticmethod
    def user_activities(user_ids: List[UUID]) -> List[FilterCondition]:
        """Filter for specific user activities."""
        return [
            FilterCondition('user_id', FilterOperator.IN, user_ids)
        ]
    
    @staticmethod
    def off_hours_activity(business_start: int = 9, business_end: int = 17) -> List[FilterCondition]:
        """Filter for off-hours activity (requires custom SQL)."""
        # This would need custom SQL for hour extraction
        return []
    
    @staticmethod
    def ip_address_range(ip_addresses: List[str]) -> List[FilterCondition]:
        """Filter for specific IP addresses."""
        return [
            FilterCondition('ip_address', FilterOperator.IN, ip_addresses)
        ]