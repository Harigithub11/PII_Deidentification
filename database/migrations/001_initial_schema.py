"""Initial database schema migration

Revision ID: 001_initial_schema
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001_initial_schema'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """Create initial database schema."""
    
    # Enable required PostgreSQL extensions
    op.execute("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
    op.execute("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"")
    op.execute("CREATE EXTENSION IF NOT EXISTS \"pg_trgm\"")
    
    # Create ENUMS
    create_enums()
    
    # Create tables in dependency order
    create_lookup_tables()
    create_core_tables()
    create_audit_tables()
    create_policy_tables()
    create_metadata_tables()
    
    # Create indexes
    create_indexes()
    
    # Create functions and triggers
    create_functions_and_triggers()
    
    # Insert initial data
    insert_initial_data()


def downgrade():
    """Drop all tables and types."""
    
    # Drop tables in reverse dependency order
    drop_tables()
    
    # Drop enums
    drop_enums()
    
    # Drop extensions (optional, as they might be used by other schemas)
    # op.execute("DROP EXTENSION IF EXISTS \"pg_trgm\"")
    # op.execute("DROP EXTENSION IF EXISTS \"pgcrypto\"")
    # op.execute("DROP EXTENSION IF EXISTS \"uuid-ossp\"")


def create_enums():
    """Create PostgreSQL ENUM types."""
    
    # User and authentication enums
    op.execute("""
        CREATE TYPE user_role AS ENUM (
            'admin', 'user', 'auditor', 'data_processor', 'compliance_officer'
        )
    """)
    
    op.execute("""
        CREATE TYPE auth_type AS ENUM (
            'password', 'api_key', 'oauth2', 'ldap'
        )
    """)
    
    op.execute("""
        CREATE TYPE session_status AS ENUM (
            'active', 'expired', 'terminated', 'suspended'
        )
    """)
    
    # PII and redaction enums
    op.execute("""
        CREATE TYPE pii_type AS ENUM (
            'name', 'address', 'phone', 'email', 'date_of_birth', 'age', 'gender',
            'ssn', 'passport', 'driver_license', 'national_id', 'aadhar', 'pan',
            'credit_card', 'bank_account', 'routing_number', 'iban', 'income',
            'medical_record', 'medical_license', 'diagnosis', 'medication', 'treatment',
            'ip_address', 'url', 'crypto_address', 'organization', 'financial', 'number',
            'location', 'signature', 'photo'
        )
    """)
    
    op.execute("""
        CREATE TYPE redaction_method AS ENUM (
            'blackout', 'whiteout', 'blur', 'pixelate', 'pseudonymize', 'generalize', 'delete'
        )
    """)
    
    # Audit enums
    op.execute("""
        CREATE TYPE audit_event_type AS ENUM (
            'user_login', 'user_logout', 'user_created', 'user_updated', 'user_deleted',
            'user_locked', 'user_unlocked', 'password_changed', 'permission_changed',
            'document_uploaded', 'document_processed', 'document_downloaded', 'document_deleted',
            'pii_detected', 'pii_redacted', 'policy_applied', 'policy_created', 'policy_updated',
            'policy_deleted', 'system_startup', 'system_shutdown', 'system_error',
            'security_breach', 'unauthorized_access', 'data_export', 'data_import',
            'backup_created', 'backup_restored', 'configuration_changed', 'api_key_created',
            'api_key_revoked', 'session_expired', 'rate_limit_exceeded', 'compliance_violation'
        )
    """)
    
    op.execute("""
        CREATE TYPE audit_severity AS ENUM (
            'low', 'medium', 'high', 'critical'
        )
    """)
    
    op.execute("""
        CREATE TYPE audit_outcome AS ENUM (
            'success', 'failure', 'partial', 'error'
        )
    """)
    
    op.execute("""
        CREATE TYPE activity_type AS ENUM (
            'create', 'read', 'update', 'delete', 'download', 'upload', 'export',
            'import', 'login', 'logout', 'search', 'view', 'process', 'redact',
            'approve', 'reject'
        )
    """)
    
    # Processing and policy enums
    op.execute("""
        CREATE TYPE processing_status AS ENUM (
            'uploaded', 'queued', 'processing', 'completed', 'failed', 'cancelled',
            'expired', 'archived'
        )
    """)
    
    op.execute("""
        CREATE TYPE processing_stage AS ENUM (
            'upload_validation', 'file_analysis', 'content_extraction', 'pii_detection',
            'policy_application', 'redaction', 'quality_check', 'output_generation',
            'completion'
        )
    """)
    
    op.execute("""
        CREATE TYPE policy_status AS ENUM (
            'draft', 'pending_approval', 'active', 'deprecated', 'suspended', 'archived'
        )
    """)
    
    op.execute("""
        CREATE TYPE policy_change_type AS ENUM (
            'created', 'updated', 'activated', 'deprecated', 'suspended', 'archived',
            'rule_added', 'rule_removed', 'rule_modified', 'settings_changed'
        )
    """)
    
    op.execute("""
        CREATE TYPE policy_application_status AS ENUM (
            'pending', 'in_progress', 'completed', 'failed', 'partial', 'skipped'
        )
    """)
    
    op.execute("""
        CREATE TYPE validation_result AS ENUM (
            'valid', 'warning', 'error', 'not_applicable'
        )
    """)
    
    # Document and file enums
    op.execute("""
        CREATE TYPE document_type AS ENUM (
            'pdf', 'image', 'text', 'word', 'excel', 'powerpoint', 'csv', 'json',
            'xml', 'email', 'medical_record', 'form', 'contract', 'invoice', 'other'
        )
    """)
    
    op.execute("""
        CREATE TYPE file_format AS ENUM (
            'pdf', 'png', 'jpg', 'jpeg', 'tiff', 'tif', 'bmp', 'gif', 'webp',
            'txt', 'docx', 'doc', 'xlsx', 'xls', 'pptx', 'ppt', 'csv', 'json',
            'xml', 'html', 'rtf', 'eml', 'msg'
        )
    """)
    
    op.execute("""
        CREATE TYPE quality_level AS ENUM (
            'excellent', 'good', 'fair', 'poor', 'unacceptable'
        )
    """)


def create_lookup_tables():
    """Create lookup and configuration tables."""
    
    # Compliance standards
    op.create_table(
        'compliance_standards',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('code', sa.String(20), nullable=False, unique=True),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('jurisdiction', sa.String(100)),
        sa.Column('version', sa.String(20)),
        sa.Column('effective_date', sa.Date),
        sa.Column('website_url', sa.Text),
        sa.Column('documentation_url', sa.Text),
        sa.Column('is_active', sa.Boolean, nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now())
    )
    
    # PII type definitions
    op.create_table(
        'pii_type_definitions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('pii_type', postgresql.ENUM(name='pii_type'), nullable=False, unique=True),
        sa.Column('display_name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('category', sa.String(50), nullable=False),
        sa.Column('sensitivity_level', sa.Integer, nullable=False, default=5),
        sa.Column('regex_pattern', sa.Text),
        sa.Column('validation_rules', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('is_active', sa.Boolean, nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint('sensitivity_level BETWEEN 1 AND 10', name='pii_sensitivity_level_range')
    )
    
    # Redaction method definitions
    op.create_table(
        'redaction_method_definitions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('redaction_method', postgresql.ENUM(name='redaction_method'), nullable=False, unique=True),
        sa.Column('display_name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('configuration_schema', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('is_reversible', sa.Boolean, nullable=False, default=False),
        sa.Column('security_level', sa.Integer, nullable=False, default=5),
        sa.Column('is_active', sa.Boolean, nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint('security_level BETWEEN 1 AND 10', name='redaction_security_level_range')
    )


def create_core_tables():
    """Create core user management tables."""
    
    # Users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('username', sa.String(50), unique=True, nullable=False),
        sa.Column('email', sa.Text, nullable=False),  # Will be encrypted at application level
        sa.Column('full_name', sa.Text),  # Will be encrypted at application level
        sa.Column('password_hash', sa.Text, nullable=False),
        sa.Column('role', postgresql.ENUM(name='user_role'), nullable=False, default='user'),
        sa.Column('is_active', sa.Boolean, nullable=False, default=True),
        sa.Column('is_verified', sa.Boolean, nullable=False, default=False),
        sa.Column('failed_login_attempts', sa.Integer, nullable=False, default=0),
        sa.Column('locked_until', sa.DateTime(timezone=True)),
        sa.Column('last_login', sa.DateTime(timezone=True)),
        sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('two_factor_enabled', sa.Boolean, nullable=False, default=False),
        sa.Column('two_factor_secret', sa.Text),  # Will be encrypted at application level
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('version', sa.Integer, nullable=False, default=1),
        sa.CheckConstraint('length(username) >= 3', name='users_username_length'),
        sa.CheckConstraint('password_changed_at <= CURRENT_TIMESTAMP', name='users_password_changed_recent')
    )
    
    # User sessions
    op.create_table(
        'user_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('session_token', sa.Text, nullable=False, unique=True),
        sa.Column('refresh_token', sa.Text, unique=True),
        sa.Column('ip_address', postgresql.INET),
        sa.Column('user_agent', sa.Text),
        sa.Column('status', postgresql.ENUM(name='session_status'), nullable=False, default='active'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_accessed', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('terminated_at', sa.DateTime(timezone=True)),
        sa.Column('terminated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('termination_reason', sa.Text),
        sa.Column('location_country', sa.String(2)),
        sa.Column('location_city', sa.String(100)),
        sa.Column('device_fingerprint', sa.Text),
        sa.CheckConstraint('expires_at > created_at', name='user_sessions_expires_future')
    )
    
    # API keys
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('key_name', sa.String(100), nullable=False),
        sa.Column('key_hash', sa.Text, nullable=False, unique=True),
        sa.Column('key_prefix', sa.String(10), nullable=False),
        sa.Column('scopes', postgresql.ARRAY(sa.Text), nullable=False, server_default='{}'),
        sa.Column('is_active', sa.Boolean, nullable=False, default=True),
        sa.Column('expires_at', sa.DateTime(timezone=True)),
        sa.Column('last_used', sa.DateTime(timezone=True)),
        sa.Column('usage_count', sa.BigInteger, nullable=False, default=0),
        sa.Column('rate_limit_per_hour', sa.Integer, default=1000),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('revoked_at', sa.DateTime(timezone=True)),
        sa.Column('revoked_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('revocation_reason', sa.Text),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.UniqueConstraint('user_id', 'key_name')
    )
    
    # Data retention schedules
    op.create_table(
        'data_retention_schedules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('name', sa.String(100), nullable=False, unique=True),
        sa.Column('description', sa.Text),
        sa.Column('retention_period_days', sa.Integer, nullable=False),
        sa.Column('auto_deletion_enabled', sa.Boolean, nullable=False, default=False),
        sa.Column('compliance_standard_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('compliance_standards.id')),
        sa.Column('applies_to_pii_types', postgresql.ARRAY(postgresql.ENUM(name='pii_type')), server_default='{}'),
        sa.Column('deletion_method', postgresql.ENUM(name='redaction_method'), nullable=False, default='delete'),
        sa.Column('grace_period_days', sa.Integer, default=0),
        sa.Column('notification_days_before', postgresql.ARRAY(sa.Integer), server_default='{30,7,1}'),
        sa.Column('is_active', sa.Boolean, nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.CheckConstraint('retention_period_days > 0', name='retention_period_positive'),
        sa.CheckConstraint('grace_period_days >= 0', name='grace_period_non_negative')
    )
    
    # System configuration
    op.create_table(
        'system_configuration',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('config_key', sa.String(100), nullable=False, unique=True),
        sa.Column('config_value', sa.Text),
        sa.Column('config_type', sa.String(20), nullable=False, default='string'),
        sa.Column('description', sa.Text),
        sa.Column('is_encrypted', sa.Boolean, nullable=False, default=False),
        sa.Column('is_system_config', sa.Boolean, nullable=False, default=False),
        sa.Column('validation_regex', sa.Text),
        sa.Column('min_value', sa.Numeric),
        sa.Column('max_value', sa.Numeric),
        sa.Column('allowed_values', postgresql.ARRAY(sa.Text)),
        sa.Column('requires_restart', sa.Boolean, nullable=False, default=False),
        sa.Column('is_active', sa.Boolean, nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.CheckConstraint("config_type IN ('string', 'integer', 'boolean', 'json', 'encrypted')", name='config_type_check')
    )


def create_audit_tables():
    """Create audit and logging tables."""
    
    # Main audit events table
    op.create_table(
        'audit_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('event_id', sa.String(50), nullable=False, unique=True),
        sa.Column('event_type', postgresql.ENUM(name='audit_event_type'), nullable=False),
        sa.Column('severity', postgresql.ENUM(name='audit_severity'), nullable=False, default='medium'),
        sa.Column('outcome', postgresql.ENUM(name='audit_outcome'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('username', sa.String(50)),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('user_sessions.id')),
        sa.Column('api_key_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('api_keys.id')),
        sa.Column('impersonator_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('target_type', sa.String(50)),
        sa.Column('target_id', postgresql.UUID(as_uuid=True)),
        sa.Column('target_name', sa.String(255)),
        sa.Column('event_description', sa.Text, nullable=False),
        sa.Column('event_summary', sa.String(500)),
        sa.Column('request_method', sa.String(10)),
        sa.Column('request_url', sa.Text),
        sa.Column('request_headers', postgresql.JSONB),
        sa.Column('request_body', postgresql.JSONB),
        sa.Column('response_status', sa.Integer),
        sa.Column('response_size', sa.BigInteger),
        sa.Column('ip_address', postgresql.INET),
        sa.Column('user_agent', sa.Text),
        sa.Column('location_country', sa.String(2)),
        sa.Column('location_city', sa.String(100)),
        sa.Column('device_fingerprint', sa.Text),
        sa.Column('event_timestamp', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('duration_ms', sa.Integer),
        sa.Column('compliance_standards', postgresql.ARRAY(sa.String(20)), server_default='{}'),
        sa.Column('risk_score', sa.Integer),
        sa.Column('contains_pii', sa.Boolean, nullable=False, default=False),
        sa.Column('data_classification', sa.String(20), default='public'),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('tags', postgresql.ARRAY(sa.String(50)), server_default='{}'),
        sa.Column('event_hash', sa.Text),
        sa.Column('previous_event_hash', sa.Text),
        sa.CheckConstraint('risk_score IS NULL OR (risk_score BETWEEN 0 AND 100)', name='audit_risk_score_range'),
        sa.CheckConstraint("event_timestamp <= CURRENT_TIMESTAMP + INTERVAL '1 minute'", name='audit_events_future_timestamp')
    )
    
    # Audit event details
    op.create_table(
        'audit_event_details',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('audit_event_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('audit_events.id', ondelete='CASCADE'), nullable=False),
        sa.Column('detail_type', sa.String(50), nullable=False),
        sa.Column('detail_key', sa.String(100), nullable=False),
        sa.Column('detail_value', postgresql.JSONB),
        sa.Column('is_sensitive', sa.Boolean, nullable=False, default=False),
        sa.Column('encryption_key_id', sa.String(50)),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint('audit_event_id', 'detail_type', 'detail_key')
    )
    
    # User activities
    op.create_table(
        'user_activities',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('user_sessions.id')),
        sa.Column('activity_type', postgresql.ENUM(name='activity_type'), nullable=False),
        sa.Column('activity_description', sa.Text, nullable=False),
        sa.Column('resource_type', sa.String(50)),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True)),
        sa.Column('resource_name', sa.String(255)),
        sa.Column('http_method', sa.String(10)),
        sa.Column('endpoint', sa.String(500)),
        sa.Column('parameters', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('status_code', sa.Integer),
        sa.Column('response_time_ms', sa.Integer),
        sa.Column('response_size_bytes', sa.BigInteger),
        sa.Column('ip_address', postgresql.INET),
        sa.Column('user_agent', sa.Text),
        sa.Column('is_suspicious', sa.Boolean, nullable=False, default=False),
        sa.Column('suspicious_reason', sa.Text),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.CheckConstraint('completed_at IS NULL OR completed_at >= started_at', name='user_activities_completion_time')
    )
    
    # System events
    op.create_table(
        'system_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('event_type', sa.String(50), nullable=False),
        sa.Column('severity', postgresql.ENUM(name='audit_severity'), nullable=False, default='medium'),
        sa.Column('event_name', sa.String(100), nullable=False),
        sa.Column('event_description', sa.Text, nullable=False),
        sa.Column('error_code', sa.String(20)),
        sa.Column('error_message', sa.Text),
        sa.Column('stack_trace', sa.Text),
        sa.Column('service_name', sa.String(50)),
        sa.Column('service_version', sa.String(20)),
        sa.Column('server_hostname', sa.String(100)),
        sa.Column('process_id', sa.Integer),
        sa.Column('thread_id', sa.String(50)),
        sa.Column('cpu_usage_percent', sa.Numeric(5, 2)),
        sa.Column('memory_usage_mb', sa.BigInteger),
        sa.Column('disk_usage_percent', sa.Numeric(5, 2)),
        sa.Column('related_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('related_session_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('user_sessions.id')),
        sa.Column('related_request_id', sa.String(100)),
        sa.Column('event_timestamp', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('event_duration_ms', sa.Integer),
        sa.Column('context', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('requires_attention', sa.Boolean, nullable=False, default=False),
        sa.Column('is_resolved', sa.Boolean, nullable=False, default=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True)),
        sa.Column('resolved_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('resolution_notes', sa.Text)
    )
    
    # Access logs
    op.create_table(
        'access_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('user_sessions.id')),
        sa.Column('resource_type', sa.String(50), nullable=False),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True)),
        sa.Column('resource_path', sa.Text),
        sa.Column('action', sa.String(50), nullable=False),
        sa.Column('required_permission', sa.String(100)),
        sa.Column('permission_granted', sa.Boolean, nullable=False),
        sa.Column('permission_source', sa.String(50)),
        sa.Column('denial_reason', sa.Text),
        sa.Column('ip_address', postgresql.INET),
        sa.Column('user_agent', sa.Text),
        sa.Column('referer', sa.Text),
        sa.Column('request_id', sa.String(100)),
        sa.Column('data_classification', sa.String(20)),
        sa.Column('contains_pii', sa.Boolean, nullable=False, default=False),
        sa.Column('pii_types', postgresql.ARRAY(postgresql.ENUM(name='pii_type')), server_default='{}'),
        sa.Column('compliance_policy_id', postgresql.UUID(as_uuid=True)),
        sa.Column('policy_version', sa.Integer),
        sa.Column('compliance_notes', sa.Text),
        sa.Column('access_timestamp', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('access_duration_ms', sa.Integer),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}')
    )
    
    # Security events
    op.create_table(
        'security_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('event_type', sa.String(50), nullable=False),
        sa.Column('severity', postgresql.ENUM(name='audit_severity'), nullable=False, default='medium'),
        sa.Column('target_username', sa.String(50)),
        sa.Column('target_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('source_ip', postgresql.INET, nullable=False),
        sa.Column('source_country', sa.String(2)),
        sa.Column('source_city', sa.String(100)),
        sa.Column('user_agent', sa.Text),
        sa.Column('event_description', sa.Text, nullable=False),
        sa.Column('failure_reason', sa.Text),
        sa.Column('attempted_action', sa.String(100)),
        sa.Column('detected_by', sa.String(50)),
        sa.Column('detection_rules', postgresql.ARRAY(sa.Text)),
        sa.Column('confidence_score', sa.Integer),
        sa.Column('blocked', sa.Boolean, nullable=False, default=False),
        sa.Column('action_taken', sa.String(100)),
        sa.Column('notification_sent', sa.Boolean, nullable=False, default=False),
        sa.Column('event_timestamp', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('investigated', sa.Boolean, nullable=False, default=False),
        sa.Column('investigated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('investigation_notes', sa.Text),
        sa.Column('false_positive', sa.Boolean, nullable=False, default=False),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.CheckConstraint('confidence_score IS NULL OR (confidence_score BETWEEN 0 AND 100)', name='security_confidence_range')
    )
    
    # Data processing logs
    op.create_table(
        'data_processing_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('processing_activity', sa.String(100), nullable=False),
        sa.Column('legal_basis', sa.String(50), nullable=False),
        sa.Column('data_subject_id', postgresql.UUID(as_uuid=True)),
        sa.Column('data_subject_category', sa.String(50)),
        sa.Column('data_categories', postgresql.ARRAY(sa.String(50)), nullable=False),
        sa.Column('pii_types_processed', postgresql.ARRAY(postgresql.ENUM(name='pii_type')), server_default='{}'),
        sa.Column('data_source', sa.String(100)),
        sa.Column('data_volume_estimate', sa.String(20)),
        sa.Column('processing_purpose', sa.Text, nullable=False),
        sa.Column('processing_method', sa.String(50)),
        sa.Column('automated_decision_making', sa.Boolean, nullable=False, default=False),
        sa.Column('profiling_involved', sa.Boolean, nullable=False, default=False),
        sa.Column('data_recipients', postgresql.ARRAY(sa.String(100))),
        sa.Column('third_country_transfers', postgresql.ARRAY(sa.String(100))),
        sa.Column('transfer_safeguards', sa.Text),
        sa.Column('retention_period_days', sa.Integer),
        sa.Column('retention_justification', sa.Text),
        sa.Column('deletion_scheduled_date', sa.Date),
        sa.Column('consent_obtained', sa.Boolean),
        sa.Column('consent_timestamp', sa.DateTime(timezone=True)),
        sa.Column('consent_method', sa.String(50)),
        sa.Column('consent_withdrawn', sa.Boolean, nullable=False, default=False),
        sa.Column('consent_withdrawal_timestamp', sa.DateTime(timezone=True)),
        sa.Column('compliance_standard', sa.String(20), nullable=False),
        sa.Column('policy_version', sa.Integer),
        sa.Column('processing_started', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('processing_completed', sa.DateTime(timezone=True)),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.CheckConstraint('processing_completed IS NULL OR processing_completed >= processing_started', name='data_processing_logs_completion')
    )


def create_policy_tables():
    """Create policy management tables."""
    
    # Compliance policies
    op.create_table(
        'compliance_policies',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('version', sa.String(20), nullable=False, default='1.0.0'),
        sa.Column('policy_code', sa.String(50), nullable=False),
        sa.Column('compliance_standard_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('compliance_standards.id'), nullable=False),
        sa.Column('effective_date', sa.Date, nullable=False),
        sa.Column('expiration_date', sa.Date),
        sa.Column('status', postgresql.ENUM(name='policy_status'), nullable=False, default='draft'),
        sa.Column('priority', sa.Integer, nullable=False, default=5),
        sa.Column('strict_mode', sa.Boolean, nullable=False, default=False),
        sa.Column('enable_audit_logging', sa.Boolean, nullable=False, default=True),
        sa.Column('require_approval', sa.Boolean, nullable=False, default=False),
        sa.Column('allow_pseudonymization', sa.Boolean, nullable=False, default=True),
        sa.Column('allow_generalization', sa.Boolean, nullable=False, default=True),
        sa.Column('default_redaction_method', postgresql.ENUM(name='redaction_method'), nullable=False, default='blackout'),
        sa.Column('max_retention_days', sa.Integer),
        sa.Column('validation_required', sa.Boolean, nullable=False, default=True),
        sa.Column('auto_apply', sa.Boolean, nullable=False, default=False),
        sa.Column('requires_approval_from', postgresql.ARRAY(sa.Text), server_default='{}'),
        sa.Column('approved_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('approved_at', sa.DateTime(timezone=True)),
        sa.Column('approval_notes', sa.Text),
        sa.Column('parent_policy_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('compliance_policies.id')),
        sa.Column('policy_order', sa.Integer, default=0),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('tags', postgresql.ARRAY(sa.String(50)), server_default='{}'),
        sa.UniqueConstraint('policy_code', 'version'),
        sa.CheckConstraint('priority BETWEEN 1 AND 10', name='compliance_policies_priority_range'),
        sa.CheckConstraint('max_retention_days IS NULL OR max_retention_days > 0', name='max_retention_positive'),
        sa.CheckConstraint('expiration_date IS NULL OR expiration_date > effective_date', name='compliance_policies_effective_expiration')
    )
    
    # Policy rules
    op.create_table(
        'policy_rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('compliance_policies.id', ondelete='CASCADE'), nullable=False),
        sa.Column('rule_name', sa.String(100), nullable=False),
        sa.Column('rule_description', sa.Text),
        sa.Column('rule_order', sa.Integer, nullable=False, default=0),
        sa.Column('pii_type', postgresql.ENUM(name='pii_type'), nullable=False),
        sa.Column('redaction_method', postgresql.ENUM(name='redaction_method'), nullable=False),
        sa.Column('confidence_threshold', sa.Numeric(3, 2), nullable=False, default=0.80),
        sa.Column('retention_period_days', sa.Integer),
        sa.Column('auto_delete_enabled', sa.Boolean, nullable=False, default=False),
        sa.Column('conditions', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('exceptions', postgresql.ARRAY(sa.Text), server_default='{}'),
        sa.Column('context_requirements', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('legal_basis', sa.String(100)),
        sa.Column('regulation_reference', sa.Text),
        sa.Column('business_justification', sa.Text),
        sa.Column('is_active', sa.Boolean, nullable=False, default=True),
        sa.Column('is_mandatory', sa.Boolean, nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.UniqueConstraint('policy_id', 'pii_type'),
        sa.UniqueConstraint('policy_id', 'rule_name'),
        sa.CheckConstraint('confidence_threshold BETWEEN 0 AND 1', name='confidence_threshold_range'),
        sa.CheckConstraint('retention_period_days IS NULL OR retention_period_days >= 0', name='retention_period_non_negative')
    )
    
    # Policy versions
    op.create_table(
        'policy_versions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('compliance_policies.id', ondelete='CASCADE'), nullable=False),
        sa.Column('version_number', sa.String(20), nullable=False),
        sa.Column('previous_version_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('policy_versions.id')),
        sa.Column('change_type', postgresql.ENUM(name='policy_change_type'), nullable=False),
        sa.Column('change_summary', sa.String(500), nullable=False),
        sa.Column('change_description', sa.Text),
        sa.Column('changed_fields', postgresql.ARRAY(sa.Text)),
        sa.Column('change_reason', sa.Text),
        sa.Column('regulatory_requirement', sa.Text),
        sa.Column('impact_assessment', sa.Text),
        sa.Column('change_approved_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('change_approved_at', sa.DateTime(timezone=True)),
        sa.Column('validation_status', postgresql.ENUM(name='validation_result'), default='pending'),
        sa.Column('validation_notes', sa.Text),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('effective_from', sa.DateTime(timezone=True)),
        sa.Column('policy_snapshot', postgresql.JSONB, nullable=False),
        sa.Column('rules_snapshot', postgresql.JSONB, nullable=False),
        sa.UniqueConstraint('policy_id', 'version_number')
    )
    
    # Policy applications
    op.create_table(
        'policy_applications',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('compliance_policies.id'), nullable=False),
        sa.Column('policy_version_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('policy_versions.id')),
        sa.Column('target_type', sa.String(50), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_name', sa.String(255)),
        sa.Column('application_status', postgresql.ENUM(name='policy_application_status'), nullable=False, default='pending'),
        sa.Column('applied_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('applied_via', sa.String(50), default='automatic'),
        sa.Column('rules_applied', sa.Integer, default=0),
        sa.Column('rules_failed', sa.Integer, default=0),
        sa.Column('pii_items_processed', sa.Integer, default=0),
        sa.Column('pii_items_redacted', sa.Integer, default=0),
        sa.Column('validation_status', postgresql.ENUM(name='validation_result'), default='pending'),
        sa.Column('validation_errors', postgresql.ARRAY(sa.Text)),
        sa.Column('validation_warnings', postgresql.ARRAY(sa.Text)),
        sa.Column('compliance_score', sa.Integer),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('duration_seconds', sa.Integer),
        sa.Column('processing_summary', sa.Text),
        sa.Column('output_location', sa.Text),
        sa.Column('backup_location', sa.Text),
        sa.Column('error_message', sa.Text),
        sa.Column('error_details', postgresql.JSONB),
        sa.Column('retry_count', sa.Integer, default=0),
        sa.Column('max_retries', sa.Integer, default=3),
        sa.Column('audit_trail_id', postgresql.UUID(as_uuid=True)),
        sa.Column('compliance_notes', sa.Text),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.CheckConstraint('compliance_score IS NULL OR (compliance_score BETWEEN 0 AND 100)', name='compliance_score_range'),
        sa.CheckConstraint('completed_at IS NULL OR completed_at >= started_at', name='policy_applications_completion_check'),
        sa.CheckConstraint('rules_applied >= 0 AND rules_failed >= 0', name='policy_applications_rules_check')
    )
    
    # Policy rule executions
    op.create_table(
        'policy_rule_executions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('policy_application_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('policy_applications.id', ondelete='CASCADE'), nullable=False),
        sa.Column('policy_rule_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('policy_rules.id'), nullable=False),
        sa.Column('execution_order', sa.Integer, nullable=False),
        sa.Column('execution_status', postgresql.ENUM(name='policy_application_status'), nullable=False, default='pending'),
        sa.Column('input_data_type', sa.String(50)),
        sa.Column('input_data_size_bytes', sa.BigInteger),
        sa.Column('detected_pii_count', sa.Integer, default=0),
        sa.Column('pii_detections', postgresql.JSONB, nullable=False, server_default='[]'),
        sa.Column('confidence_scores', postgresql.ARRAY(sa.Numeric(3, 2))),
        sa.Column('redaction_method_used', postgresql.ENUM(name='redaction_method')),
        sa.Column('redacted_items_count', sa.Integer, default=0),
        sa.Column('redaction_success_rate', sa.Numeric(5, 2)),
        sa.Column('output_data_size_bytes', sa.BigInteger),
        sa.Column('output_location', sa.Text),
        sa.Column('processing_time_ms', sa.Integer),
        sa.Column('memory_usage_mb', sa.Integer),
        sa.Column('error_occurred', sa.Boolean, nullable=False, default=False),
        sa.Column('error_message', sa.Text),
        sa.Column('error_details', postgresql.JSONB),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.UniqueConstraint('policy_application_id', 'policy_rule_id')
    )


def create_metadata_tables():
    """Create document and metadata tables."""
    
    # Document metadata
    op.create_table(
        'document_metadata',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('document_name', sa.String(255), nullable=False),
        sa.Column('original_filename', sa.String(255), nullable=False),
        sa.Column('document_type', postgresql.ENUM(name='document_type'), nullable=False),
        sa.Column('file_format', postgresql.ENUM(name='file_format'), nullable=False),
        sa.Column('file_size_bytes', sa.BigInteger, nullable=False),
        sa.Column('file_checksum_md5', sa.String(32), nullable=False),
        sa.Column('file_checksum_sha256', sa.String(64), nullable=False),
        sa.Column('mime_type', sa.String(100)),
        sa.Column('page_count', sa.Integer, default=1),
        sa.Column('word_count', sa.Integer, default=0),
        sa.Column('character_count', sa.Integer, default=0),
        sa.Column('image_count', sa.Integer, default=0),
        sa.Column('primary_language', sa.String(10)),
        sa.Column('detected_languages', postgresql.ARRAY(sa.String(10)), server_default='{}'),
        sa.Column('text_encoding', sa.String(50), default='UTF-8'),
        sa.Column('security_classification', sa.String(20), default='internal'),
        sa.Column('contains_sensitive_data', sa.Boolean, nullable=False, default=False),
        sa.Column('sensitivity_score', sa.Integer),
        sa.Column('pii_detected', sa.Boolean, nullable=False, default=False),
        sa.Column('pii_types_found', postgresql.ARRAY(postgresql.ENUM(name='pii_type')), server_default='{}'),
        sa.Column('pii_item_count', sa.Integer, default=0),
        sa.Column('high_confidence_pii_count', sa.Integer, default=0),
        sa.Column('has_forms', sa.Boolean, nullable=False, default=False),
        sa.Column('has_tables', sa.Boolean, nullable=False, default=False),
        sa.Column('has_images', sa.Boolean, nullable=False, default=False),
        sa.Column('has_signatures', sa.Boolean, nullable=False, default=False),
        sa.Column('has_handwriting', sa.Boolean, nullable=False, default=False),
        sa.Column('text_quality', postgresql.ENUM(name='quality_level'), default='good'),
        sa.Column('image_quality', postgresql.ENUM(name='quality_level'), default='good'),
        sa.Column('ocr_confidence_avg', sa.Numeric(5, 2)),
        sa.Column('uploaded_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('processing_policy_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('compliance_policies.id')),
        sa.Column('processing_batch_id', postgresql.UUID(as_uuid=True)),
        sa.Column('original_file_path', sa.Text, nullable=False),
        sa.Column('processed_file_path', sa.Text),
        sa.Column('backup_file_path', sa.Text),
        sa.Column('thumbnail_path', sa.Text),
        sa.Column('uploaded_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('last_accessed', sa.DateTime(timezone=True)),
        sa.Column('expires_at', sa.DateTime(timezone=True)),
        sa.Column('retention_policy_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('data_retention_schedules.id')),
        sa.Column('compliance_validated', sa.Boolean, nullable=False, default=False),
        sa.Column('compliance_validation_date', sa.DateTime(timezone=True)),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('tags', postgresql.ARRAY(sa.String(50)), server_default='{}'),
        sa.CheckConstraint('file_size_bytes >= 0', name='file_size_non_negative'),
        sa.CheckConstraint('page_count >= 0', name='page_count_non_negative'),
        sa.CheckConstraint('word_count >= 0', name='word_count_non_negative'),
        sa.CheckConstraint('character_count >= 0', name='character_count_non_negative'),
        sa.CheckConstraint('image_count >= 0', name='image_count_non_negative'),
        sa.CheckConstraint('pii_item_count >= 0', name='pii_item_count_non_negative'),
        sa.CheckConstraint('high_confidence_pii_count >= 0', name='high_confidence_pii_count_non_negative'),
        sa.CheckConstraint('sensitivity_score IS NULL OR (sensitivity_score BETWEEN 0 AND 100)', name='sensitivity_score_range'),
        sa.CheckConstraint('ocr_confidence_avg IS NULL OR (ocr_confidence_avg BETWEEN 0 AND 100)', name='ocr_confidence_range'),
        sa.CheckConstraint('length(file_checksum_md5) = 32 AND length(file_checksum_sha256) = 64', name='document_metadata_checksum_length')
    )
    
    # Processing sessions
    op.create_table(
        'processing_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('session_name', sa.String(100)),
        sa.Column('session_type', sa.String(50), nullable=False, default='single_document'),
        sa.Column('session_priority', sa.Integer, nullable=False, default=3),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('compliance_policies.id'), nullable=False),
        sa.Column('policy_version_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('policy_versions.id')),
        sa.Column('processing_mode', sa.String(20), nullable=False, default='automatic'),
        sa.Column('status', postgresql.ENUM(name='processing_status'), nullable=False, default='queued'),
        sa.Column('current_stage', postgresql.ENUM(name='processing_stage')),
        sa.Column('progress_percentage', sa.Integer, default=0),
        sa.Column('document_count', sa.Integer, nullable=False, default=0),
        sa.Column('documents_processed', sa.Integer, nullable=False, default=0),
        sa.Column('documents_successful', sa.Integer, nullable=False, default=0),
        sa.Column('documents_failed', sa.Integer, nullable=False, default=0),
        sa.Column('total_pii_detected', sa.Integer, nullable=False, default=0),
        sa.Column('total_pii_redacted', sa.Integer, nullable=False, default=0),
        sa.Column('processing_time_seconds', sa.Integer),
        sa.Column('cpu_time_seconds', sa.Numeric(10, 2)),
        sa.Column('memory_peak_mb', sa.Integer),
        sa.Column('storage_used_mb', sa.Integer),
        sa.Column('overall_quality_score', sa.Numeric(5, 2)),
        sa.Column('average_confidence_score', sa.Numeric(5, 2)),
        sa.Column('initiated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('processed_by', sa.String(100)),
        sa.Column('worker_node', sa.String(100)),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('started_at', sa.DateTime(timezone=True)),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('estimated_completion', sa.DateTime(timezone=True)),
        sa.Column('error_count', sa.Integer, nullable=False, default=0),
        sa.Column('last_error_message', sa.Text),
        sa.Column('retry_count', sa.Integer, nullable=False, default=0),
        sa.Column('max_retries', sa.Integer, nullable=False, default=3),
        sa.Column('output_location', sa.Text),
        sa.Column('output_format', sa.String(20)),
        sa.Column('output_size_bytes', sa.BigInteger),
        sa.Column('audit_trail_id', postgresql.UUID(as_uuid=True)),
        sa.Column('compliance_report_generated', sa.Boolean, nullable=False, default=False),
        sa.Column('configuration', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('metrics', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.CheckConstraint('session_priority BETWEEN 1 AND 5', name='session_priority_range'),
        sa.CheckConstraint('progress_percentage BETWEEN 0 AND 100', name='progress_percentage_range'),
        sa.CheckConstraint('overall_quality_score IS NULL OR (overall_quality_score BETWEEN 0 AND 100)', name='overall_quality_score_range'),
        sa.CheckConstraint('average_confidence_score IS NULL OR (average_confidence_score BETWEEN 0 AND 100)', name='average_confidence_score_range'),
        sa.CheckConstraint('started_at IS NULL OR started_at >= created_at', name='processing_sessions_timing'),
        sa.CheckConstraint('completed_at IS NULL OR (started_at IS NOT NULL AND completed_at >= started_at)', name='processing_sessions_completion')
    )
    
    # Session documents
    op.create_table(
        'session_documents',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('processing_sessions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('document_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('document_metadata.id', ondelete='CASCADE'), nullable=False),
        sa.Column('processing_order', sa.Integer, nullable=False, default=0),
        sa.Column('status', postgresql.ENUM(name='processing_status'), nullable=False, default='queued'),
        sa.Column('current_stage', postgresql.ENUM(name='processing_stage')),
        sa.Column('progress_percentage', sa.Integer, default=0),
        sa.Column('pii_detected_count', sa.Integer, default=0),
        sa.Column('pii_redacted_count', sa.Integer, default=0),
        sa.Column('processing_time_seconds', sa.Integer),
        sa.Column('quality_score', sa.Numeric(5, 2)),
        sa.Column('confidence_score', sa.Numeric(5, 2)),
        sa.Column('added_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('started_at', sa.DateTime(timezone=True)),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('error_message', sa.Text),
        sa.Column('retry_count', sa.Integer, nullable=False, default=0),
        sa.Column('output_file_path', sa.Text),
        sa.Column('output_size_bytes', sa.BigInteger),
        sa.Column('processing_notes', sa.Text),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.UniqueConstraint('session_id', 'document_id'),
        sa.CheckConstraint('progress_percentage BETWEEN 0 AND 100', name='session_document_progress_range'),
        sa.CheckConstraint('quality_score IS NULL OR (quality_score BETWEEN 0 AND 100)', name='session_document_quality_range'),
        sa.CheckConstraint('confidence_score IS NULL OR (confidence_score BETWEEN 0 AND 100)', name='session_document_confidence_range')
    )
    
    # File storage
    op.create_table(
        'file_storage',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('storage_key', sa.String(255), nullable=False, unique=True),
        sa.Column('file_name', sa.String(255), nullable=False),
        sa.Column('file_path', sa.Text, nullable=False),
        sa.Column('storage_provider', sa.String(50), nullable=False, default='local'),
        sa.Column('storage_bucket', sa.String(100)),
        sa.Column('storage_region', sa.String(50)),
        sa.Column('storage_class', sa.String(50), default='standard'),
        sa.Column('file_size_bytes', sa.BigInteger, nullable=False),
        sa.Column('content_type', sa.String(100)),
        sa.Column('content_encoding', sa.String(50)),
        sa.Column('is_encrypted', sa.Boolean, nullable=False, default=False),
        sa.Column('encryption_key_id', sa.String(100)),
        sa.Column('encryption_algorithm', sa.String(50)),
        sa.Column('access_level', sa.String(20), nullable=False, default='private'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('last_accessed', sa.DateTime(timezone=True)),
        sa.Column('expires_at', sa.DateTime(timezone=True)),
        sa.Column('archived_at', sa.DateTime(timezone=True)),
        sa.Column('access_count', sa.BigInteger, nullable=False, default=0),
        sa.Column('download_count', sa.BigInteger, nullable=False, default=0),
        sa.Column('checksum_md5', sa.String(32)),
        sa.Column('checksum_sha256', sa.String(64)),
        sa.Column('integrity_verified', sa.Boolean, nullable=False, default=False),
        sa.Column('integrity_check_date', sa.DateTime(timezone=True)),
        sa.Column('is_backup', sa.Boolean, nullable=False, default=False),
        sa.Column('original_file_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('file_storage.id')),
        sa.Column('version_number', sa.Integer, default=1),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('tags', postgresql.ARRAY(sa.String(50)), server_default='{}'),
        sa.CheckConstraint('file_size_bytes >= 0', name='file_storage_size_non_negative')
    )
    
    # Redaction metadata
    op.create_table(
        'redaction_metadata',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('uuid_generate_v4()')),
        sa.Column('document_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('document_metadata.id', ondelete='CASCADE'), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('processing_sessions.id')),
        sa.Column('redaction_type', sa.String(50), nullable=False),
        sa.Column('redaction_method', postgresql.ENUM(name='redaction_method'), nullable=False),
        sa.Column('page_number', sa.Integer),
        sa.Column('x_coordinate', sa.Integer),
        sa.Column('y_coordinate', sa.Integer),
        sa.Column('width', sa.Integer),
        sa.Column('height', sa.Integer),
        sa.Column('original_text', sa.Text),  # Will be encrypted at application level
        sa.Column('redacted_text', sa.Text),
        sa.Column('pii_type', postgresql.ENUM(name='pii_type'), nullable=False),
        sa.Column('confidence_score', sa.Numeric(5, 2), nullable=False),
        sa.Column('detection_model', sa.String(100)),
        sa.Column('detection_version', sa.String(20)),
        sa.Column('detection_parameters', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('manually_reviewed', sa.Boolean, nullable=False, default=False),
        sa.Column('reviewed_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('reviewed_at', sa.DateTime(timezone=True)),
        sa.Column('review_decision', sa.String(20)),
        sa.Column('review_notes', sa.Text),
        sa.Column('redaction_quality', postgresql.ENUM(name='quality_level'), default='good'),
        sa.Column('needs_review', sa.Boolean, nullable=False, default=False),
        sa.Column('policy_rule_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('policy_rules.id')),
        sa.Column('compliance_justification', sa.Text),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('processed_at', sa.DateTime(timezone=True)),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.CheckConstraint('page_number IS NULL OR page_number >= 1', name='page_number_positive'),
        sa.CheckConstraint('x_coordinate IS NULL OR x_coordinate >= 0', name='x_coordinate_non_negative'),
        sa.CheckConstraint('y_coordinate IS NULL OR y_coordinate >= 0', name='y_coordinate_non_negative'),
        sa.CheckConstraint('width IS NULL OR width >= 0', name='width_non_negative'),
        sa.CheckConstraint('height IS NULL OR height >= 0', name='height_non_negative'),
        sa.CheckConstraint('confidence_score BETWEEN 0 AND 100', name='redaction_confidence_range')
    )


def create_indexes():
    """Create database indexes for performance."""
    
    # Core table indexes
    op.create_index('idx_users_username', 'users', ['username'])
    op.create_index('idx_users_role_active', 'users', ['role', 'is_active'])
    op.create_index('idx_users_created_at', 'users', ['created_at'])
    
    op.create_index('idx_user_sessions_user_id', 'user_sessions', ['user_id'])
    op.create_index('idx_user_sessions_status_expires', 'user_sessions', ['status', 'expires_at'])
    
    op.create_index('idx_api_keys_user_id', 'api_keys', ['user_id'])
    
    # Audit table indexes
    op.create_index('idx_audit_events_timestamp', 'audit_events', [sa.text('event_timestamp DESC')])
    op.create_index('idx_audit_events_user_id', 'audit_events', ['user_id'])
    op.create_index('idx_audit_events_type_severity', 'audit_events', ['event_type', 'severity'])
    
    op.create_index('idx_user_activities_user_date', 'user_activities', ['user_id', sa.text('started_at DESC')])
    
    op.create_index('idx_system_events_timestamp', 'system_events', [sa.text('event_timestamp DESC')])
    
    # Policy table indexes
    op.create_index('idx_compliance_policies_code_version', 'compliance_policies', ['policy_code', 'version'])
    op.create_index('idx_compliance_policies_standard', 'compliance_policies', ['compliance_standard_id', 'status'])
    
    op.create_index('idx_policy_rules_policy_id', 'policy_rules', ['policy_id', 'rule_order'])
    
    op.create_index('idx_policy_applications_policy_id', 'policy_applications', ['policy_id', sa.text('started_at DESC')])
    op.create_index('idx_policy_applications_target', 'policy_applications', ['target_type', 'target_id'])
    
    # Document metadata indexes
    op.create_index('idx_document_metadata_uploaded', 'document_metadata', [sa.text('uploaded_at DESC')])
    op.create_index('idx_document_metadata_uploaded_by', 'document_metadata', ['uploaded_by', sa.text('uploaded_at DESC')])
    op.create_index('idx_document_metadata_checksum_md5', 'document_metadata', ['file_checksum_md5'])
    op.create_index('idx_document_metadata_checksum_sha256', 'document_metadata', ['file_checksum_sha256'])
    
    op.create_index('idx_processing_sessions_policy', 'processing_sessions', ['policy_id', sa.text('created_at DESC')])
    op.create_index('idx_processing_sessions_status', 'processing_sessions', ['status', sa.text('created_at DESC')])
    
    op.create_index('idx_session_documents_session', 'session_documents', ['session_id', 'processing_order'])
    
    op.create_index('idx_redaction_metadata_document', 'redaction_metadata', ['document_id', 'page_number'])
    op.create_index('idx_redaction_metadata_pii_type', 'redaction_metadata', ['pii_type', sa.text('confidence_score DESC')])


def create_functions_and_triggers():
    """Create database functions and triggers."""
    
    # Function to update updated_at timestamp
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ language 'plpgsql';
    """)
    
    # Apply update trigger to tables with updated_at
    tables_with_updated_at = [
        'users', 'api_keys', 'compliance_standards', 'pii_type_definitions',
        'redaction_method_definitions', 'data_retention_schedules', 'system_configuration',
        'compliance_policies', 'policy_rules'
    ]
    
    for table in tables_with_updated_at:
        op.execute(f"""
            CREATE TRIGGER update_{table}_updated_at 
            BEFORE UPDATE ON {table}
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        """)
    
    # Function to generate audit event hash
    op.execute("""
        CREATE OR REPLACE FUNCTION generate_audit_event_hash(
            p_event_id VARCHAR(50),
            p_event_type audit_event_type,
            p_user_id UUID,
            p_event_timestamp TIMESTAMP WITH TIME ZONE,
            p_event_description TEXT
        ) RETURNS TEXT AS $$
        BEGIN
            RETURN encode(
                digest(
                    CONCAT(
                        COALESCE(p_event_id, ''),
                        p_event_type::text,
                        COALESCE(p_user_id::text, ''),
                        p_event_timestamp::text,
                        COALESCE(p_event_description, '')
                    ),
                    'sha256'
                ),
                'hex'
            );
        END;
        $$ LANGUAGE plpgsql IMMUTABLE;
    """)
    
    # Function to update audit chain hash
    op.execute("""
        CREATE OR REPLACE FUNCTION update_audit_chain_hash()
        RETURNS TRIGGER AS $$
        DECLARE
            prev_hash TEXT;
        BEGIN
            -- Get the hash of the previous event
            SELECT event_hash INTO prev_hash
            FROM audit_events
            WHERE event_timestamp < NEW.event_timestamp
            ORDER BY event_timestamp DESC, id DESC
            LIMIT 1;
            
            -- Generate hash for current event
            NEW.event_hash := generate_audit_event_hash(
                NEW.event_id,
                NEW.event_type,
                NEW.user_id,
                NEW.event_timestamp,
                NEW.event_description
            );
            
            -- Set previous hash for chain integrity
            NEW.previous_event_hash := prev_hash;
            
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    
    # Trigger to automatically generate audit chain
    op.execute("""
        CREATE TRIGGER audit_events_chain_trigger
            BEFORE INSERT ON audit_events
            FOR EACH ROW
            EXECUTE FUNCTION update_audit_chain_hash();
    """)


def insert_initial_data():
    """Insert initial reference data."""
    
    # Insert compliance standards
    op.execute("""
        INSERT INTO compliance_standards (code, name, description, jurisdiction, version, effective_date) VALUES
        ('GDPR', 'General Data Protection Regulation', 'EU regulation on data protection and privacy', 'European Union', '2018', '2018-05-25'),
        ('HIPAA', 'Health Insurance Portability and Accountability Act', 'US healthcare data protection regulation', 'United States', '1996', '1996-08-21'),
        ('NDHM', 'National Digital Health Mission', 'India health data protection guidelines', 'India', '2020', '2020-08-15'),
        ('CCPA', 'California Consumer Privacy Act', 'California state privacy regulation', 'California, USA', '2018', '2020-01-01'),
        ('PIPEDA', 'Personal Information Protection and Electronic Documents Act', 'Canadian federal privacy law', 'Canada', '2000', '2001-01-01');
    """)
    
    # Insert PII type definitions
    op.execute("""
        INSERT INTO pii_type_definitions (pii_type, display_name, description, category, sensitivity_level) VALUES
        ('name', 'Full Name', 'Person full name including first and last name', 'personal', 7),
        ('email', 'Email Address', 'Electronic mail address', 'contact', 6),
        ('phone', 'Phone Number', 'Telephone or mobile phone number', 'contact', 6),
        ('address', 'Physical Address', 'Residential or business address', 'location', 7),
        ('ssn', 'Social Security Number', 'US Social Security Number', 'identification', 10),
        ('credit_card', 'Credit Card Number', 'Credit or debit card number', 'financial', 10),
        ('date_of_birth', 'Date of Birth', 'Person birth date', 'personal', 8),
        ('medical_record', 'Medical Record Number', 'Healthcare record identifier', 'medical', 9),
        ('ip_address', 'IP Address', 'Internet Protocol address', 'technical', 5),
        ('aadhar', 'Aadhaar Number', 'India Aadhaar unique identification number', 'identification', 10),
        ('pan', 'PAN Number', 'India Permanent Account Number', 'financial', 9);
    """)
    
    # Insert redaction method definitions
    op.execute("""
        INSERT INTO redaction_method_definitions (redaction_method, display_name, description, is_reversible, security_level) VALUES
        ('blackout', 'Blackout', 'Replace with black rectangles', false, 8),
        ('whiteout', 'Whiteout', 'Replace with white rectangles', false, 8),
        ('blur', 'Blur', 'Apply blur effect to sensitive areas', false, 6),
        ('pixelate', 'Pixelate', 'Apply pixelation effect', false, 7),
        ('pseudonymize', 'Pseudonymize', 'Replace with consistent pseudonyms', true, 9),
        ('generalize', 'Generalize', 'Replace with generalized categories', false, 5),
        ('delete', 'Delete', 'Completely remove the data', false, 10);
    """)
    
    # Insert default retention schedules
    op.execute("""
        INSERT INTO data_retention_schedules (name, description, retention_period_days, compliance_standard_id) VALUES
        ('Standard 7-Year Retention', 'Standard business record retention for 7 years', 2555, 
            (SELECT id FROM compliance_standards WHERE code = 'HIPAA')),
        ('GDPR 3-Year Retention', 'GDPR compliant 3-year retention period', 1095, 
            (SELECT id FROM compliance_standards WHERE code = 'GDPR')),
        ('Short-Term 30-Day Retention', 'Short-term retention for temporary data', 30, NULL);
    """)


def drop_tables():
    """Drop all tables in reverse dependency order."""
    
    # Drop metadata tables
    op.drop_table('redaction_metadata')
    op.drop_table('session_documents')
    op.drop_table('file_storage')
    op.drop_table('processing_sessions')
    op.drop_table('document_metadata')
    
    # Drop policy tables
    op.drop_table('policy_rule_executions')
    op.drop_table('policy_applications')
    op.drop_table('policy_versions')
    op.drop_table('policy_rules')
    op.drop_table('compliance_policies')
    
    # Drop audit tables
    op.drop_table('data_processing_logs')
    op.drop_table('security_events')
    op.drop_table('access_logs')
    op.drop_table('system_events')
    op.drop_table('user_activities')
    op.drop_table('audit_event_details')
    op.drop_table('audit_events')
    
    # Drop core tables
    op.drop_table('system_configuration')
    op.drop_table('data_retention_schedules')
    op.drop_table('api_keys')
    op.drop_table('user_sessions')
    op.drop_table('users')
    
    # Drop lookup tables
    op.drop_table('redaction_method_definitions')
    op.drop_table('pii_type_definitions')
    op.drop_table('compliance_standards')


def drop_enums():
    """Drop all ENUM types."""
    
    enums_to_drop = [
        'quality_level', 'file_format', 'document_type', 'validation_result',
        'policy_application_status', 'policy_change_type', 'policy_status',
        'processing_stage', 'processing_status', 'activity_type', 'audit_outcome',
        'audit_severity', 'audit_event_type', 'redaction_method', 'pii_type',
        'session_status', 'auth_type', 'user_role'
    ]
    
    for enum_name in enums_to_drop:
        op.execute(f"DROP TYPE IF EXISTS {enum_name} CASCADE")