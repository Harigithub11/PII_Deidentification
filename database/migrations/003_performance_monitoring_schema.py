"""
Performance Monitoring Database Schema Migration

Creates tables and indexes for comprehensive performance monitoring,
including metrics storage, alert management, and performance analytics.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql, sqlite
from datetime import datetime


# Revision identifiers
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade():
    """Create performance monitoring schema."""
    
    # Performance Metrics Tables
    create_metric_points_table()
    create_metric_aggregates_table()
    create_metric_thresholds_table()
    
    # Alert Management Tables  
    create_performance_alerts_table()
    create_alert_rules_table()
    create_alert_escalations_table()
    
    # Tracing and Profiling Tables
    create_request_traces_table()
    create_performance_profiles_table()
    create_dependency_health_table()
    
    # Analytics Tables
    create_performance_baselines_table()
    create_capacity_forecasts_table()
    create_sla_metrics_table()
    
    # Create indexes for performance
    create_performance_indexes()


def downgrade():
    """Drop performance monitoring schema."""
    
    # Drop tables in reverse dependency order
    op.drop_table('sla_metrics')
    op.drop_table('capacity_forecasts') 
    op.drop_table('performance_baselines')
    op.drop_table('dependency_health')
    op.drop_table('performance_profiles')
    op.drop_table('request_traces')
    op.drop_table('alert_escalations')
    op.drop_table('alert_rules')
    op.drop_table('performance_alerts')
    op.drop_table('metric_thresholds')
    op.drop_table('metric_aggregates')
    op.drop_table('metric_points')


def create_metric_points_table():
    """Create table for individual metric data points."""
    op.create_table(
        'metric_points',
        sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('name', sa.String(255), nullable=False, index=True),
        sa.Column('value', sa.Float(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('metric_type', sa.Enum('counter', 'gauge', 'histogram', 'timer', 'rate', 
                                       name='metric_type_enum'), nullable=False),
        sa.Column('scope', sa.Enum('system', 'application', 'database', 'api', 'security', 
                                 'business', 'user', name='metric_scope_enum'), nullable=False),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, 
                 default=datetime.utcnow),
        
        # Indexes
        sa.Index('idx_metric_name_timestamp', 'name', 'timestamp'),
        sa.Index('idx_metric_scope_timestamp', 'scope', 'timestamp'),
        sa.Index('idx_metric_type_timestamp', 'metric_type', 'timestamp'),
        
        # Partitioning hint (would be implemented in PostgreSQL)
        postgresql_partition_by='RANGE (timestamp)'
    )


def create_metric_aggregates_table():
    """Create table for pre-computed metric aggregates."""
    op.create_table(
        'metric_aggregates',
        sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('name', sa.String(255), nullable=False, index=True),
        sa.Column('scope', sa.String(50), nullable=False),
        sa.Column('period', sa.Enum('minute', 'hour', 'day', 'week', 'month', 
                                  name='aggregate_period_enum'), nullable=False),
        sa.Column('start_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('count', sa.BigInteger(), nullable=False),
        sa.Column('min_value', sa.Float(), nullable=True),
        sa.Column('max_value', sa.Float(), nullable=True),
        sa.Column('avg_value', sa.Float(), nullable=True),
        sa.Column('sum_value', sa.Float(), nullable=True),
        sa.Column('std_dev', sa.Float(), nullable=True),
        sa.Column('p50_value', sa.Float(), nullable=True),
        sa.Column('p95_value', sa.Float(), nullable=True),
        sa.Column('p99_value', sa.Float(), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow),
        
        # Unique constraint to prevent duplicate aggregates
        sa.UniqueConstraint('name', 'scope', 'period', 'start_time', 
                          name='uq_metric_aggregates'),
        
        # Indexes
        sa.Index('idx_aggregate_name_period_time', 'name', 'period', 'start_time'),
        sa.Index('idx_aggregate_scope_period_time', 'scope', 'period', 'start_time')
    )


def create_metric_thresholds_table():
    """Create table for metric threshold definitions."""
    op.create_table(
        'metric_thresholds',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('metric_name', sa.String(255), nullable=False),
        sa.Column('scope', sa.String(50), nullable=False),
        sa.Column('threshold_type', sa.Enum('warning', 'critical', 'info', 
                                          name='threshold_type_enum'), nullable=False),
        sa.Column('operator', sa.Enum('gt', 'lt', 'eq', 'ne', 'gte', 'lte', 
                                    name='threshold_operator_enum'), nullable=False),
        sa.Column('value', sa.Float(), nullable=False),
        sa.Column('duration_minutes', sa.Integer(), nullable=False, default=5),
        sa.Column('enabled', sa.Boolean(), nullable=False, default=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow, onupdate=datetime.utcnow),
        
        # Indexes
        sa.Index('idx_threshold_metric_enabled', 'metric_name', 'enabled'),
        sa.Index('idx_threshold_scope', 'scope')
    )


def create_performance_alerts_table():
    """Create table for performance alerts."""
    op.create_table(
        'performance_alerts',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('alert_id', sa.String(64), nullable=False, unique=True, index=True),
        sa.Column('rule_name', sa.String(255), nullable=False),
        sa.Column('alert_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.Enum('low', 'medium', 'high', 'critical', 
                                    name='alert_severity_enum'), nullable=False),
        sa.Column('status', sa.Enum('open', 'acknowledged', 'resolved', 'suppressed',
                                  name='alert_status_enum'), nullable=False, default='open'),
        sa.Column('confidence', sa.Float(), nullable=False, default=1.0),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('metric_name', sa.String(255), nullable=False),
        sa.Column('current_value', sa.Float(), nullable=True),
        sa.Column('threshold_value', sa.Float(), nullable=True),
        sa.Column('first_occurrence', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_occurrence', sa.DateTime(timezone=True), nullable=False),
        sa.Column('occurrence_count', sa.Integer(), nullable=False, default=1),
        sa.Column('acknowledged_by', sa.String(100), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_by', sa.String(100), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow, onupdate=datetime.utcnow),
        
        # Indexes
        sa.Index('idx_alert_severity_status', 'severity', 'status'),
        sa.Index('idx_alert_metric_time', 'metric_name', 'first_occurrence'),
        sa.Index('idx_alert_rule_time', 'rule_name', 'first_occurrence')
    )


def create_alert_rules_table():
    """Create table for alert rule definitions."""
    op.create_table(
        'alert_rules',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('name', sa.String(255), nullable=False, unique=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('metric_pattern', sa.String(500), nullable=False),
        sa.Column('condition', sa.Text(), nullable=False),  # JSON condition logic
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('duration_minutes', sa.Integer(), nullable=False, default=5),
        sa.Column('cooldown_minutes', sa.Integer(), nullable=False, default=15),
        sa.Column('enabled', sa.Boolean(), nullable=False, default=True),
        sa.Column('notification_channels', sa.JSON(), nullable=True),
        sa.Column('labels', sa.JSON(), nullable=True),
        sa.Column('created_by', sa.String(100), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow, onupdate=datetime.utcnow),
        
        # Indexes
        sa.Index('idx_alert_rule_enabled', 'enabled'),
        sa.Index('idx_alert_rule_pattern', 'metric_pattern')
    )


def create_alert_escalations_table():
    """Create table for alert escalation policies."""
    op.create_table(
        'alert_escalations',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('alert_id', sa.String(64), nullable=False, 
                 sa.ForeignKey('performance_alerts.alert_id', ondelete='CASCADE')),
        sa.Column('escalation_level', sa.Integer(), nullable=False),
        sa.Column('escalation_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('notification_sent', sa.Boolean(), nullable=False, default=False),
        sa.Column('notification_channel', sa.String(100), nullable=False),
        sa.Column('notification_target', sa.String(255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow),
        
        # Indexes
        sa.Index('idx_escalation_alert_level', 'alert_id', 'escalation_level'),
        sa.Index('idx_escalation_time_sent', 'escalation_time', 'notification_sent')
    )


def create_request_traces_table():
    """Create table for distributed request tracing."""
    op.create_table(
        'request_traces',
        sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('trace_id', sa.String(64), nullable=False, index=True),
        sa.Column('span_id', sa.String(64), nullable=False, index=True),
        sa.Column('parent_span_id', sa.String(64), nullable=True),
        sa.Column('operation_name', sa.String(255), nullable=False),
        sa.Column('service_name', sa.String(100), nullable=False),
        sa.Column('start_time', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('duration_ms', sa.Float(), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('error', sa.Boolean(), nullable=False, default=False),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('logs', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow),
        
        # Indexes
        sa.Index('idx_trace_id_start_time', 'trace_id', 'start_time'),
        sa.Index('idx_service_operation_time', 'service_name', 'operation_name', 'start_time'),
        sa.Index('idx_span_duration', 'duration_ms'),
        sa.Index('idx_error_traces', 'error', 'start_time')
    )


def create_performance_profiles_table():
    """Create table for performance profiling data."""
    op.create_table(
        'performance_profiles',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('profile_id', sa.String(64), nullable=False, unique=True, index=True),
        sa.Column('profile_type', sa.Enum('cpu', 'memory', 'io', 'database', 'custom',
                                        name='profile_type_enum'), nullable=False),
        sa.Column('service_name', sa.String(100), nullable=False),
        sa.Column('function_name', sa.String(255), nullable=True),
        sa.Column('start_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('duration_seconds', sa.Float(), nullable=False),
        sa.Column('sample_count', sa.Integer(), nullable=False),
        sa.Column('profile_data', sa.JSON(), nullable=False),  # Serialized profile data
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow),
        
        # Indexes
        sa.Index('idx_profile_service_type_time', 'service_name', 'profile_type', 'start_time'),
        sa.Index('idx_profile_function_time', 'function_name', 'start_time'),
        sa.Index('idx_profile_duration', 'duration_seconds')
    )


def create_dependency_health_table():
    """Create table for external dependency health tracking."""
    op.create_table(
        'dependency_health',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('dependency_name', sa.String(100), nullable=False, index=True),
        sa.Column('dependency_type', sa.Enum('database', 'cache', 'api', 'service', 'queue',
                                           name='dependency_type_enum'), nullable=False),
        sa.Column('endpoint', sa.String(500), nullable=False),
        sa.Column('status', sa.Enum('healthy', 'degraded', 'unhealthy', 'unknown',
                                  name='dependency_status_enum'), nullable=False),
        sa.Column('response_time_ms', sa.Float(), nullable=True),
        sa.Column('success_rate_percent', sa.Float(), nullable=True),
        sa.Column('error_count', sa.Integer(), nullable=False, default=0),
        sa.Column('last_success_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_failure_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failure_reason', sa.Text(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('checked_at', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow),
        
        # Indexes
        sa.Index('idx_dependency_name_checked', 'dependency_name', 'checked_at'),
        sa.Index('idx_dependency_status_checked', 'status', 'checked_at'),
        sa.Index('idx_dependency_type_status', 'dependency_type', 'status')
    )


def create_performance_baselines_table():
    """Create table for performance baselines."""
    op.create_table(
        'performance_baselines',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('metric_name', sa.String(255), nullable=False),
        sa.Column('scope', sa.String(50), nullable=False),
        sa.Column('baseline_type', sa.Enum('daily', 'weekly', 'monthly', 'seasonal',
                                         name='baseline_type_enum'), nullable=False),
        sa.Column('period_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('period_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('avg_value', sa.Float(), nullable=False),
        sa.Column('min_value', sa.Float(), nullable=False),
        sa.Column('max_value', sa.Float(), nullable=False),
        sa.Column('std_dev', sa.Float(), nullable=False),
        sa.Column('p95_value', sa.Float(), nullable=False),
        sa.Column('p99_value', sa.Float(), nullable=False),
        sa.Column('sample_count', sa.Integer(), nullable=False),
        sa.Column('confidence_interval', sa.Float(), nullable=False),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow),
        
        # Unique constraint
        sa.UniqueConstraint('metric_name', 'scope', 'baseline_type', 'period_start',
                          name='uq_performance_baseline'),
        
        # Indexes
        sa.Index('idx_baseline_metric_type_period', 'metric_name', 'baseline_type', 'period_start'),
        sa.Index('idx_baseline_scope_type', 'scope', 'baseline_type')
    )


def create_capacity_forecasts_table():
    """Create table for capacity planning forecasts."""
    op.create_table(
        'capacity_forecasts',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('resource_name', sa.String(255), nullable=False),
        sa.Column('resource_type', sa.Enum('cpu', 'memory', 'disk', 'network', 'requests',
                                         name='resource_type_enum'), nullable=False),
        sa.Column('forecast_date', sa.Date(), nullable=False),
        sa.Column('predicted_value', sa.Float(), nullable=False),
        sa.Column('confidence_lower', sa.Float(), nullable=False),
        sa.Column('confidence_upper', sa.Float(), nullable=False),
        sa.Column('utilization_percent', sa.Float(), nullable=False),
        sa.Column('capacity_threshold', sa.Float(), nullable=False),
        sa.Column('days_to_threshold', sa.Integer(), nullable=True),
        sa.Column('forecast_model', sa.String(50), nullable=False),
        sa.Column('model_accuracy', sa.Float(), nullable=True),
        sa.Column('training_period_days', sa.Integer(), nullable=False),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow),
        
        # Indexes
        sa.Index('idx_forecast_resource_date', 'resource_name', 'forecast_date'),
        sa.Index('idx_forecast_type_date', 'resource_type', 'forecast_date'),
        sa.Index('idx_forecast_threshold_days', 'days_to_threshold')
    )


def create_sla_metrics_table():
    """Create table for SLA tracking and metrics."""
    op.create_table(
        'sla_metrics',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('service_name', sa.String(100), nullable=False),
        sa.Column('sla_type', sa.Enum('availability', 'response_time', 'throughput', 'error_rate',
                                    name='sla_type_enum'), nullable=False),
        sa.Column('period_type', sa.Enum('hour', 'day', 'week', 'month', 'quarter', 'year',
                                       name='sla_period_enum'), nullable=False),
        sa.Column('period_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('period_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('target_value', sa.Float(), nullable=False),
        sa.Column('actual_value', sa.Float(), nullable=False),
        sa.Column('achievement_percent', sa.Float(), nullable=False),
        sa.Column('violation_count', sa.Integer(), nullable=False, default=0),
        sa.Column('violation_duration_minutes', sa.Integer(), nullable=False, default=0),
        sa.Column('breach_status', sa.Enum('met', 'warning', 'breached', 'critical',
                                         name='breach_status_enum'), nullable=False),
        sa.Column('penalty_applied', sa.Boolean(), nullable=False, default=False),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=datetime.utcnow),
        
        # Indexes
        sa.Index('idx_sla_service_type_period', 'service_name', 'sla_type', 'period_start'),
        sa.Index('idx_sla_breach_status', 'breach_status', 'period_start'),
        sa.Index('idx_sla_achievement', 'achievement_percent')
    )


def create_performance_indexes():
    """Create additional performance-optimized indexes."""
    
    # Composite indexes for common query patterns
    op.create_index(
        'idx_metric_points_composite_1', 
        'metric_points',
        ['name', 'scope', 'timestamp']
    )
    
    op.create_index(
        'idx_metric_points_composite_2',
        'metric_points', 
        ['metric_type', 'timestamp', 'value']
    )
    
    # Index for alert correlation queries
    op.create_index(
        'idx_alerts_correlation',
        'performance_alerts',
        ['metric_name', 'severity', 'status', 'first_occurrence']
    )
    
    # Index for trace analysis
    op.create_index(
        'idx_traces_analysis',
        'request_traces',
        ['service_name', 'operation_name', 'duration_ms', 'start_time']
    )
    
    # Partial indexes for active monitoring
    op.execute("""
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_active_alerts 
        ON performance_alerts (severity, last_occurrence) 
        WHERE status IN ('open', 'acknowledged')
    """)
    
    op.execute("""
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_recent_metrics
        ON metric_points (name, timestamp DESC)
        WHERE timestamp > NOW() - INTERVAL '24 hours'
    """)