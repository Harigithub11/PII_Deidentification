"""Add batch processing tables

Revision ID: 002_batch_processing_tables
Revises: 001_initial_schema
Create Date: 2024-09-10 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002_batch_processing_tables'
down_revision = '001_initial_schema'
branch_labels = None
depends_on = None


def upgrade():
    """Add batch processing tables for asynchronous job management."""
    
    # Create batch processing enums
    create_batch_processing_enums()
    
    # Create batch processing tables
    create_batch_workers_table()
    create_batch_jobs_table()
    create_job_schedules_table()
    create_job_results_table()
    
    # Create indexes for performance
    create_batch_processing_indexes()
    
    # Add relationships to existing User table
    add_user_relationships()


def downgrade():
    """Remove batch processing tables."""
    
    # Drop tables in reverse dependency order
    op.drop_table('job_results')
    op.drop_table('job_schedules')
    op.drop_table('batch_jobs')
    op.drop_table('batch_workers')
    
    # Drop enums
    op.execute("DROP TYPE IF EXISTS worker_status")
    op.execute("DROP TYPE IF EXISTS job_priority")
    op.execute("DROP TYPE IF EXISTS batch_job_type")
    op.execute("DROP TYPE IF EXISTS batch_job_status")


def create_batch_processing_enums():
    """Create enums for batch processing."""
    
    # Batch job status enum
    batch_job_status = postgresql.ENUM(
        'pending', 'queued', 'running', 'paused', 'completed', 
        'failed', 'cancelled', 'timeout', 
        name='batch_job_status'
    )
    batch_job_status.create(op.get_bind())
    
    # Batch job type enum
    batch_job_type = postgresql.ENUM(
        'document_processing', 'pii_detection', 'bulk_redaction', 
        'compliance_validation', 'audit_generation', 'bulk_encryption',
        'policy_application', 'report_generation', 'custom',
        name='batch_job_type'
    )
    batch_job_type.create(op.get_bind())
    
    # Job priority enum
    job_priority = postgresql.ENUM(
        'low', 'normal', 'high', 'critical', 'urgent',
        name='job_priority'
    )
    job_priority.create(op.get_bind())
    
    # Worker status enum
    worker_status = postgresql.ENUM(
        'idle', 'busy', 'offline', 'error', 'maintenance',
        name='worker_status'
    )
    worker_status.create(op.get_bind())


def create_batch_workers_table():
    """Create batch_workers table."""
    op.create_table(
        'batch_workers',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('worker_name', sa.String(255), nullable=False),
        sa.Column('hostname', sa.String(255), nullable=False),
        sa.Column('pid', sa.Integer(), nullable=False),
        
        # Worker configuration
        sa.Column('worker_type', sa.String(50), nullable=False, server_default='standard'),
        sa.Column('supported_job_types', postgresql.ARRAY(sa.String(50)), nullable=False, server_default='{}'),
        sa.Column('max_concurrent_jobs', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('memory_limit_mb', sa.Integer(), nullable=False, server_default='2048'),
        sa.Column('cpu_cores', sa.Integer(), nullable=False, server_default='1'),
        
        # Status and health
        sa.Column('status', sa.Enum('idle', 'busy', 'offline', 'error', 'maintenance', name='worker_status'), 
                  nullable=False, server_default='offline'),
        sa.Column('current_jobs_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_jobs_processed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_jobs_failed', sa.Integer(), nullable=False, server_default='0'),
        
        # Timing information
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('last_heartbeat', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('last_job_completed_at', sa.DateTime(timezone=True), nullable=True),
        
        # Performance metrics
        sa.Column('average_job_duration_seconds', sa.Numeric(10, 3), nullable=True),
        sa.Column('success_rate', sa.Numeric(5, 2), nullable=True),
        sa.Column('current_memory_usage_mb', sa.Integer(), nullable=True),
        sa.Column('current_cpu_usage_percent', sa.Numeric(5, 2), nullable=True),
        
        # Worker metadata
        sa.Column('version', sa.String(50), nullable=False, server_default='1.0.0'),
        sa.Column('queue_names', postgresql.ARRAY(sa.String(100)), nullable=False, server_default='{}'),
        sa.Column('tags', postgresql.ARRAY(sa.String(50)), nullable=False, server_default='{}'),
        sa.Column('configuration', postgresql.JSONB(), nullable=False, server_default='{}'),
        
        # Error tracking
        sa.Column('consecutive_failures', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_error_message', sa.Text(), nullable=True),
        sa.Column('last_error_at', sa.DateTime(timezone=True), nullable=True),
        
        # Constraints
        sa.CheckConstraint('max_concurrent_jobs > 0', name='max_concurrent_positive'),
        sa.CheckConstraint('memory_limit_mb > 0', name='memory_limit_positive'),
        sa.CheckConstraint('cpu_cores > 0', name='cpu_cores_positive'),
        sa.CheckConstraint('current_jobs_count >= 0', name='current_jobs_non_negative'),
        sa.CheckConstraint('total_jobs_processed >= 0', name='total_jobs_non_negative'),
        sa.CheckConstraint('total_jobs_failed >= 0', name='total_failed_non_negative'),
        sa.CheckConstraint('average_job_duration_seconds IS NULL OR average_job_duration_seconds >= 0', 
                          name='avg_duration_non_negative'),
        sa.CheckConstraint('success_rate IS NULL OR success_rate BETWEEN 0 AND 100', 
                          name='worker_success_rate_range'),
        sa.CheckConstraint('current_memory_usage_mb IS NULL OR current_memory_usage_mb >= 0', 
                          name='current_memory_non_negative'),
        sa.CheckConstraint('current_cpu_usage_percent IS NULL OR current_cpu_usage_percent BETWEEN 0 AND 100', 
                          name='current_cpu_range'),
        sa.CheckConstraint('consecutive_failures >= 0', name='consecutive_failures_non_negative'),
        sa.CheckConstraint('last_heartbeat >= started_at', name='heartbeat_after_start'),
        sa.UniqueConstraint('hostname', 'pid', name='unique_worker_per_host_pid'),
        sa.UniqueConstraint('worker_name', name='unique_worker_name'),
    )


def create_batch_jobs_table():
    """Create batch_jobs table."""
    op.create_table(
        'batch_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('job_type', sa.Enum('document_processing', 'pii_detection', 'bulk_redaction', 
                                     'compliance_validation', 'audit_generation', 'bulk_encryption',
                                     'policy_application', 'report_generation', 'custom',
                                     name='batch_job_type'), nullable=False),
        
        # Job configuration
        sa.Column('parameters', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('priority', sa.Enum('low', 'normal', 'high', 'critical', 'urgent', name='job_priority'),
                  nullable=False, server_default='normal'),
        sa.Column('timeout_seconds', sa.Integer(), nullable=False, server_default='3600'),
        
        # Resource requirements
        sa.Column('max_workers', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('memory_limit_mb', sa.Integer(), nullable=False, server_default='1024'),
        sa.Column('cpu_limit_cores', sa.Numeric(3, 1), nullable=False, server_default='1.0'),
        
        # Input/Output
        sa.Column('input_data', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('output_location', sa.Text(), nullable=True),
        
        # Status and progress
        sa.Column('status', sa.Enum('pending', 'queued', 'running', 'paused', 'completed', 
                                   'failed', 'cancelled', 'timeout', name='batch_job_status'),
                  nullable=False, server_default='pending'),
        sa.Column('progress_percentage', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('current_step', sa.String(255), nullable=False, server_default='initialized'),
        sa.Column('steps_completed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_steps', sa.Integer(), nullable=False, server_default='1'),
        
        # Timing information
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('queued_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_heartbeat', sa.DateTime(timezone=True), nullable=True),
        
        # User and permissions
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('assigned_to', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('access_permissions', postgresql.ARRAY(postgresql.UUID(as_uuid=True)), 
                  nullable=False, server_default='{}'),
        
        # Error handling and retry
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('retry_delay_seconds', sa.Integer(), nullable=False, server_default='60'),
        
        # Dependencies and scheduling
        sa.Column('depends_on', postgresql.ARRAY(postgresql.UUID(as_uuid=True)), 
                  nullable=False, server_default='{}'),
        sa.Column('scheduled_at', sa.DateTime(timezone=True), nullable=True),
        
        # Results and error tracking
        sa.Column('result_summary', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('error_details', postgresql.JSONB(), nullable=False, server_default='{}'),
        
        # Audit and compliance
        sa.Column('compliance_standards', postgresql.ARRAY(sa.String(50)), 
                  nullable=False, server_default='{}'),
        sa.Column('audit_trail', postgresql.JSONB(), nullable=False, server_default='[]'),
        
        # Metadata
        sa.Column('tags', postgresql.ARRAY(sa.String(50)), nullable=False, server_default='{}'),
        sa.Column('custom_metadata', postgresql.JSONB(), nullable=False, server_default='{}'),
        
        # Worker assignment
        sa.Column('assigned_worker_id', postgresql.UUID(as_uuid=True), 
                  sa.ForeignKey('batch_workers.id'), nullable=True),
        
        # Constraints
        sa.CheckConstraint('progress_percentage BETWEEN 0 AND 100', name='progress_percentage_range'),
        sa.CheckConstraint('timeout_seconds >= 60', name='timeout_minimum'),
        sa.CheckConstraint('max_workers >= 1 AND max_workers <= 10', name='max_workers_range'),
        sa.CheckConstraint('memory_limit_mb >= 512', name='memory_limit_minimum'),
        sa.CheckConstraint('cpu_limit_cores >= 0.5 AND cpu_limit_cores <= 4.0', name='cpu_limit_range'),
        sa.CheckConstraint('steps_completed >= 0', name='steps_completed_non_negative'),
        sa.CheckConstraint('total_steps >= 1', name='total_steps_positive'),
        sa.CheckConstraint('max_retries >= 0 AND max_retries <= 10', name='max_retries_range'),
        sa.CheckConstraint('retry_count >= 0', name='retry_count_non_negative'),
        sa.CheckConstraint('retry_delay_seconds BETWEEN 30 AND 3600', name='retry_delay_range'),
        sa.CheckConstraint('completed_at IS NULL OR completed_at >= created_at', name='completion_after_creation'),
        sa.CheckConstraint('started_at IS NULL OR started_at >= queued_at', name='start_after_queue'),
        sa.UniqueConstraint('name', 'created_by', name='unique_job_name_per_user'),
    )


def create_job_schedules_table():
    """Create job_schedules table."""
    op.create_table(
        'job_schedules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), 
                  sa.ForeignKey('batch_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('schedule_name', sa.String(200), nullable=False),
        sa.Column('cron_expression', sa.String(100), nullable=False),
        sa.Column('timezone', sa.String(50), nullable=False, server_default='UTC'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        
        # Schedule timing
        sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_run_status', sa.Enum('pending', 'queued', 'running', 'paused', 'completed', 
                                            'failed', 'cancelled', 'timeout', name='batch_job_status'), 
                  nullable=True),
        
        # Schedule configuration
        sa.Column('max_runs', sa.Integer(), nullable=True),  # NULL = unlimited
        sa.Column('runs_completed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        
        # Error handling
        sa.Column('consecutive_failures', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_consecutive_failures', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('failure_notification_sent', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        
        # Metadata
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        
        # Constraints
        sa.CheckConstraint('max_runs IS NULL OR max_runs > 0', name='max_runs_positive'),
        sa.CheckConstraint('runs_completed >= 0', name='runs_completed_non_negative'),
        sa.CheckConstraint('consecutive_failures >= 0', name='consecutive_failures_non_negative'),
        sa.CheckConstraint('max_consecutive_failures > 0', name='max_consecutive_failures_positive'),
        sa.CheckConstraint('expires_at IS NULL OR expires_at > created_at', name='expiry_after_creation'),
        sa.UniqueConstraint('schedule_name', 'created_by', name='unique_schedule_name_per_user'),
    )


def create_job_results_table():
    """Create job_results table."""
    op.create_table(
        'job_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), 
                  sa.ForeignKey('batch_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('execution_id', sa.String(100), nullable=False),  # For tracking retries
        
        # Execution metadata
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('duration_seconds', sa.Numeric(10, 3), nullable=False),
        
        # Resource usage
        sa.Column('max_memory_mb', sa.Integer(), nullable=True),
        sa.Column('avg_cpu_percent', sa.Numeric(5, 2), nullable=True),
        sa.Column('disk_io_mb', sa.Integer(), nullable=True),
        
        # Results and metrics
        sa.Column('status', sa.Enum('pending', 'queued', 'running', 'paused', 'completed', 
                                   'failed', 'cancelled', 'timeout', name='batch_job_status'),
                  nullable=False),
        sa.Column('result_data', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('output_files', postgresql.ARRAY(sa.Text()), nullable=False, server_default='{}'),
        sa.Column('output_size_bytes', sa.BigInteger(), nullable=True),
        
        # Processing statistics
        sa.Column('items_processed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('items_successful', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('items_failed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('items_skipped', sa.Integer(), nullable=False, server_default='0'),
        
        # Error information
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('error_code', sa.String(50), nullable=True),
        sa.Column('error_details', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('stack_trace', sa.Text(), nullable=True),
        
        # Quality metrics
        sa.Column('success_rate', sa.Numeric(5, 2), nullable=True),
        sa.Column('quality_score', sa.Integer(), nullable=True),
        sa.Column('performance_rating', sa.String(20), nullable=True),
        
        # Worker information
        sa.Column('worker_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('batch_workers.id'), nullable=True),
        sa.Column('worker_hostname', sa.String(255), nullable=True),
        sa.Column('worker_version', sa.String(50), nullable=True),
        
        # Compliance and audit
        sa.Column('compliance_validated', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('audit_checksum', sa.String(64), nullable=True),
        sa.Column('retention_policy_applied', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        
        # Constraints
        sa.CheckConstraint('duration_seconds >= 0', name='duration_non_negative'),
        sa.CheckConstraint('max_memory_mb IS NULL OR max_memory_mb > 0', name='memory_positive'),
        sa.CheckConstraint('avg_cpu_percent IS NULL OR avg_cpu_percent BETWEEN 0 AND 100', name='cpu_percent_range'),
        sa.CheckConstraint('items_processed >= 0', name='items_processed_non_negative'),
        sa.CheckConstraint('items_successful >= 0', name='items_successful_non_negative'),
        sa.CheckConstraint('items_failed >= 0', name='items_failed_non_negative'),
        sa.CheckConstraint('items_skipped >= 0', name='items_skipped_non_negative'),
        sa.CheckConstraint('success_rate IS NULL OR success_rate BETWEEN 0 AND 100', name='success_rate_range'),
        sa.CheckConstraint('quality_score IS NULL OR quality_score BETWEEN 0 AND 100', name='quality_score_range'),
        sa.CheckConstraint('completed_at >= started_at', name='completion_after_start'),
        sa.UniqueConstraint('execution_id', 'job_id', name='unique_execution_per_job'),
    )


def create_batch_processing_indexes():
    """Create indexes for batch processing tables."""
    
    # BatchWorker indexes
    op.create_index('idx_batch_workers_status', 'batch_workers', ['status', 'last_heartbeat'])
    op.create_index('idx_batch_workers_hostname', 'batch_workers', ['hostname', 'pid'])
    op.create_index('idx_batch_workers_type', 'batch_workers', ['worker_type', 'status'])
    op.create_index('idx_batch_workers_heartbeat', 'batch_workers', ['last_heartbeat', 'status'])
    
    # BatchJob indexes
    op.create_index('idx_batch_jobs_status', 'batch_jobs', ['status', 'priority', 'created_at'])
    op.create_index('idx_batch_jobs_type', 'batch_jobs', ['job_type', 'status'])
    op.create_index('idx_batch_jobs_creator', 'batch_jobs', ['created_by', 'created_at'])
    op.create_index('idx_batch_jobs_worker', 'batch_jobs', ['assigned_worker_id', 'status'])
    op.create_index('idx_batch_jobs_scheduled', 'batch_jobs', ['scheduled_at', 'status'])
    op.create_index('idx_batch_jobs_heartbeat', 'batch_jobs', ['last_heartbeat', 'status'])
    
    # JobSchedule indexes
    op.create_index('idx_job_schedules_next_run', 'job_schedules', ['next_run_at', 'is_active'])
    op.create_index('idx_job_schedules_job', 'job_schedules', ['job_id', 'is_active'])
    op.create_index('idx_job_schedules_creator', 'job_schedules', ['created_by', 'created_at'])
    
    # JobResult indexes
    op.create_index('idx_job_results_job', 'job_results', ['job_id', 'started_at'])
    op.create_index('idx_job_results_execution', 'job_results', ['execution_id', 'job_id'])
    op.create_index('idx_job_results_worker', 'job_results', ['worker_id', 'completed_at'])
    op.create_index('idx_job_results_status', 'job_results', ['status', 'completed_at'])


def add_user_relationships():
    """Add batch processing relationships to existing User table if needed."""
    # Note: Relationships are handled at the ORM level in models.py
    # This is a placeholder for any additional database-level constraints
    pass