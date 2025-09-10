-- Audit Tables SQL Schema for PII De-identification System
-- Comprehensive audit logging for compliance and security monitoring
-- Version: 1.0.0

-- =============================================================================
-- AUDIT ENUMS AND TYPES
-- =============================================================================

-- Event types for audit logging
CREATE TYPE audit_event_type AS ENUM (
    'user_login',
    'user_logout',
    'user_created',
    'user_updated',
    'user_deleted',
    'user_locked',
    'user_unlocked',
    'password_changed',
    'permission_changed',
    'document_uploaded',
    'document_processed',
    'document_downloaded',
    'document_deleted',
    'pii_detected',
    'pii_redacted',
    'policy_applied',
    'policy_created',
    'policy_updated',
    'policy_deleted',
    'system_startup',
    'system_shutdown',
    'system_error',
    'security_breach',
    'unauthorized_access',
    'data_export',
    'data_import',
    'backup_created',
    'backup_restored',
    'configuration_changed',
    'api_key_created',
    'api_key_revoked',
    'session_expired',
    'rate_limit_exceeded',
    'compliance_violation'
);

-- Event severity levels
CREATE TYPE audit_severity AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);

-- Audit outcome
CREATE TYPE audit_outcome AS ENUM (
    'success',
    'failure',
    'partial',
    'error'
);

-- Activity types for user activities
CREATE TYPE activity_type AS ENUM (
    'create',
    'read',
    'update',
    'delete',
    'download',
    'upload',
    'export',
    'import',
    'login',
    'logout',
    'search',
    'view',
    'process',
    'redact',
    'approve',
    'reject'
);

-- =============================================================================
-- MAIN AUDIT TABLES
-- =============================================================================

-- Main audit events table (immutable)
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id VARCHAR(50) NOT NULL UNIQUE, -- Human readable event ID
    event_type audit_event_type NOT NULL,
    severity audit_severity NOT NULL DEFAULT 'medium',
    outcome audit_outcome NOT NULL,
    
    -- Actor information (who performed the action)
    user_id UUID REFERENCES users(id),
    username VARCHAR(50), -- Denormalized for performance
    session_id UUID REFERENCES user_sessions(id),
    api_key_id UUID REFERENCES api_keys(id),
    impersonator_id UUID REFERENCES users(id), -- If acting on behalf of another user
    
    -- Target information (what was acted upon)
    target_type VARCHAR(50), -- 'document', 'user', 'policy', 'system', etc.
    target_id UUID, -- ID of the target object
    target_name VARCHAR(255), -- Human readable name of target
    
    -- Event details
    event_description TEXT NOT NULL,
    event_summary VARCHAR(500), -- Short summary for quick viewing
    
    -- Request/Response information
    request_method VARCHAR(10), -- HTTP method if applicable
    request_url TEXT, -- Request URL if applicable
    request_headers JSONB, -- Request headers (sensitive data removed)
    request_body JSONB, -- Request body (PII removed)
    response_status INTEGER, -- HTTP status code
    response_size BIGINT, -- Response size in bytes
    
    -- Location and device information
    ip_address INET,
    user_agent TEXT,
    location_country VARCHAR(2),
    location_city VARCHAR(100),
    device_fingerprint TEXT,
    
    -- Timing information
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    duration_ms INTEGER, -- Event duration in milliseconds
    
    -- Compliance and risk information
    compliance_standards VARCHAR(20)[], -- Which standards this event relates to
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    contains_pii BOOLEAN NOT NULL DEFAULT false,
    data_classification VARCHAR(20) DEFAULT 'public', -- public, internal, confidential, restricted
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',
    tags VARCHAR(50)[] DEFAULT '{}',
    
    -- Integrity and immutability
    event_hash TEXT, -- Hash for integrity verification
    previous_event_hash TEXT, -- Chain hash for immutability
    
    CONSTRAINT audit_events_future_timestamp CHECK (event_timestamp <= CURRENT_TIMESTAMP + INTERVAL '1 minute')
);

-- Detailed audit event information (for complex events)
CREATE TABLE audit_event_details (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_event_id UUID NOT NULL REFERENCES audit_events(id) ON DELETE CASCADE,
    detail_type VARCHAR(50) NOT NULL, -- 'before', 'after', 'context', 'pii_detected', etc.
    detail_key VARCHAR(100) NOT NULL,
    detail_value JSONB,
    is_sensitive BOOLEAN NOT NULL DEFAULT false,
    encryption_key_id VARCHAR(50), -- If value is encrypted
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(audit_event_id, detail_type, detail_key)
);

-- User activity tracking (high-level user actions)
CREATE TABLE user_activities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID REFERENCES user_sessions(id),
    activity_type activity_type NOT NULL,
    
    -- Activity details
    activity_description TEXT NOT NULL,
    resource_type VARCHAR(50), -- Type of resource accessed
    resource_id UUID, -- ID of resource
    resource_name VARCHAR(255), -- Name of resource
    
    -- Request information
    http_method VARCHAR(10),
    endpoint VARCHAR(500),
    parameters JSONB DEFAULT '{}',
    
    -- Response information
    status_code INTEGER,
    response_time_ms INTEGER,
    response_size_bytes BIGINT,
    
    -- Location and security
    ip_address INET,
    user_agent TEXT,
    is_suspicious BOOLEAN NOT NULL DEFAULT false,
    suspicious_reason TEXT,
    
    -- Timing
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    CONSTRAINT user_activities_completion_time CHECK (completed_at IS NULL OR completed_at >= started_at)
);

-- System events and errors
CREATE TABLE system_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL,
    severity audit_severity NOT NULL DEFAULT 'medium',
    
    -- Event information
    event_name VARCHAR(100) NOT NULL,
    event_description TEXT NOT NULL,
    error_code VARCHAR(20),
    error_message TEXT,
    stack_trace TEXT,
    
    -- System information
    service_name VARCHAR(50),
    service_version VARCHAR(20),
    server_hostname VARCHAR(100),
    process_id INTEGER,
    thread_id VARCHAR(50),
    
    -- Performance metrics
    cpu_usage_percent DECIMAL(5,2),
    memory_usage_mb BIGINT,
    disk_usage_percent DECIMAL(5,2),
    
    -- Related objects
    related_user_id UUID REFERENCES users(id),
    related_session_id UUID REFERENCES user_sessions(id),
    related_request_id VARCHAR(100),
    
    -- Timing
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_duration_ms INTEGER,
    
    -- Additional context
    context JSONB DEFAULT '{}',
    
    -- Monitoring flags
    requires_attention BOOLEAN NOT NULL DEFAULT false,
    is_resolved BOOLEAN NOT NULL DEFAULT false,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by UUID REFERENCES users(id),
    resolution_notes TEXT
);

-- =============================================================================
-- ACCESS AND PERMISSION LOGGING
-- =============================================================================

-- Detailed access logs for sensitive operations
CREATE TABLE access_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    session_id UUID REFERENCES user_sessions(id),
    
    -- Access details
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    resource_path TEXT,
    action VARCHAR(50) NOT NULL, -- 'view', 'download', 'edit', 'delete', etc.
    
    -- Permission information
    required_permission VARCHAR(100),
    permission_granted BOOLEAN NOT NULL,
    permission_source VARCHAR(50), -- 'role', 'explicit', 'policy', etc.
    denial_reason TEXT,
    
    -- Request context
    ip_address INET,
    user_agent TEXT,
    referer TEXT,
    request_id VARCHAR(100),
    
    -- Data sensitivity
    data_classification VARCHAR(20),
    contains_pii BOOLEAN NOT NULL DEFAULT false,
    pii_types pii_type[] DEFAULT '{}',
    
    -- Compliance tracking
    compliance_policy_id UUID, -- Reference to applied policy
    policy_version INTEGER,
    compliance_notes TEXT,
    
    -- Timing
    access_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    access_duration_ms INTEGER,
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}'
);

-- Failed login attempts and security events
CREATE TABLE security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL, -- 'failed_login', 'brute_force', 'suspicious_activity', etc.
    severity audit_severity NOT NULL DEFAULT 'medium',
    
    -- Target information
    target_username VARCHAR(50),
    target_user_id UUID REFERENCES users(id),
    
    -- Source information
    source_ip INET NOT NULL,
    source_country VARCHAR(2),
    source_city VARCHAR(100),
    user_agent TEXT,
    
    -- Event details
    event_description TEXT NOT NULL,
    failure_reason TEXT,
    attempted_action VARCHAR(100),
    
    -- Detection information
    detected_by VARCHAR(50), -- 'system', 'user_report', 'automated_scan', etc.
    detection_rules TEXT[],
    confidence_score INTEGER CHECK (confidence_score BETWEEN 0 AND 100),
    
    -- Response information
    blocked BOOLEAN NOT NULL DEFAULT false,
    action_taken VARCHAR(100),
    notification_sent BOOLEAN NOT NULL DEFAULT false,
    
    -- Timing
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Investigation tracking
    investigated BOOLEAN NOT NULL DEFAULT false,
    investigated_by UUID REFERENCES users(id),
    investigation_notes TEXT,
    false_positive BOOLEAN NOT NULL DEFAULT false,
    
    -- Metadata
    metadata JSONB DEFAULT '{}'
);

-- =============================================================================
-- COMPLIANCE AND REGULATORY LOGGING
-- =============================================================================

-- Data processing activities log (GDPR compliance)
CREATE TABLE data_processing_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    processing_activity VARCHAR(100) NOT NULL,
    legal_basis VARCHAR(50) NOT NULL, -- 'consent', 'contract', 'legal_obligation', etc.
    
    -- Data subject information
    data_subject_id UUID, -- Could reference users or be external
    data_subject_category VARCHAR(50), -- 'customer', 'employee', 'patient', etc.
    
    -- Data information
    data_categories VARCHAR(50)[] NOT NULL, -- Types of personal data processed
    pii_types_processed pii_type[] DEFAULT '{}',
    data_source VARCHAR(100),
    data_volume_estimate VARCHAR(20), -- 'low', 'medium', 'high'
    
    -- Processing details
    processing_purpose TEXT NOT NULL,
    processing_method VARCHAR(50),
    automated_decision_making BOOLEAN NOT NULL DEFAULT false,
    profiling_involved BOOLEAN NOT NULL DEFAULT false,
    
    -- Recipients and transfers
    data_recipients VARCHAR(100)[],
    third_country_transfers VARCHAR(100)[],
    transfer_safeguards TEXT,
    
    -- Retention information
    retention_period_days INTEGER,
    retention_justification TEXT,
    deletion_scheduled_date DATE,
    
    -- Consent tracking (if applicable)
    consent_obtained BOOLEAN,
    consent_timestamp TIMESTAMP WITH TIME ZONE,
    consent_method VARCHAR(50),
    consent_withdrawn BOOLEAN NOT NULL DEFAULT false,
    consent_withdrawal_timestamp TIMESTAMP WITH TIME ZONE,
    
    -- Compliance metadata
    compliance_standard VARCHAR(20) NOT NULL,
    policy_version INTEGER,
    
    -- Timing
    processing_started TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processing_completed TIMESTAMP WITH TIME ZONE,
    
    -- Additional context
    metadata JSONB DEFAULT '{}',
    
    CONSTRAINT data_processing_logs_completion CHECK (
        processing_completed IS NULL OR processing_completed >= processing_started
    )
);

-- =============================================================================
-- AUDIT TRAIL INTEGRITY FUNCTIONS
-- =============================================================================

-- Function to generate event hash for integrity
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

-- Function to update audit chain hash
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

-- Trigger to automatically generate audit chain
CREATE TRIGGER audit_events_chain_trigger
    BEFORE INSERT ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION update_audit_chain_hash();

-- =============================================================================
-- AUDIT PARTITIONING (for performance with large volumes)
-- =============================================================================

-- Partition audit_events by month for better performance
-- Note: This would be implemented with native PostgreSQL partitioning

-- Create partitioned table for audit_events (example for monthly partitioning)
-- This would replace the main audit_events table in production

-- =============================================================================
-- AUDIT RETENTION AND CLEANUP
-- =============================================================================

-- Function to cleanup old audit data based on retention policy
CREATE OR REPLACE FUNCTION cleanup_audit_data(retention_days INTEGER DEFAULT 2555)
RETURNS INTEGER AS $$
DECLARE
    cutoff_date TIMESTAMP WITH TIME ZONE;
    deleted_count INTEGER := 0;
BEGIN
    cutoff_date := CURRENT_TIMESTAMP - (retention_days || ' days')::INTERVAL;
    
    -- Archive old audit events to a separate table or external storage
    -- before deletion in production
    
    -- Delete old audit event details first (FK constraint)
    DELETE FROM audit_event_details
    WHERE audit_event_id IN (
        SELECT id FROM audit_events 
        WHERE event_timestamp < cutoff_date
    );
    
    -- Delete old audit events
    DELETE FROM audit_events WHERE event_timestamp < cutoff_date;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Delete old user activities
    DELETE FROM user_activities WHERE started_at < cutoff_date;
    
    -- Delete old system events
    DELETE FROM system_events WHERE event_timestamp < cutoff_date;
    
    -- Delete old access logs
    DELETE FROM access_logs WHERE access_timestamp < cutoff_date;
    
    -- Delete old security events (keep longer for security analysis)
    DELETE FROM security_events 
    WHERE event_timestamp < (cutoff_date - INTERVAL '365 days');
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- AUDIT SEARCH AND REPORTING VIEWS
-- =============================================================================

-- View for audit event summary (for dashboards)
CREATE VIEW audit_event_summary AS
SELECT 
    DATE_TRUNC('day', event_timestamp) as event_date,
    event_type,
    severity,
    outcome,
    COUNT(*) as event_count,
    COUNT(DISTINCT user_id) as unique_users,
    COUNT(CASE WHEN contains_pii THEN 1 END) as pii_events,
    COUNT(CASE WHEN severity IN ('high', 'critical') THEN 1 END) as high_severity_events
FROM audit_events
WHERE event_timestamp >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY DATE_TRUNC('day', event_timestamp), event_type, severity, outcome
ORDER BY event_date DESC, event_type;

-- View for user activity summary
CREATE VIEW user_activity_summary AS
SELECT 
    u.username,
    u.role,
    DATE_TRUNC('day', ua.started_at) as activity_date,
    ua.activity_type,
    COUNT(*) as activity_count,
    COUNT(CASE WHEN ua.is_suspicious THEN 1 END) as suspicious_activities,
    AVG(ua.response_time_ms) as avg_response_time_ms
FROM user_activities ua
JOIN users u ON ua.user_id = u.id
WHERE ua.started_at >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY u.username, u.role, DATE_TRUNC('day', ua.started_at), ua.activity_type
ORDER BY activity_date DESC, u.username;

-- Comments for documentation
COMMENT ON TABLE audit_events IS 'Immutable audit log of all system events with integrity chain';
COMMENT ON TABLE audit_event_details IS 'Detailed information for complex audit events';
COMMENT ON TABLE user_activities IS 'High-level tracking of user actions and behaviors';
COMMENT ON TABLE system_events IS 'System-level events, errors, and performance metrics';
COMMENT ON TABLE access_logs IS 'Detailed access logs for sensitive operations and resources';
COMMENT ON TABLE security_events IS 'Security-related events, failed logins, and suspicious activities';
COMMENT ON TABLE data_processing_logs IS 'GDPR-compliant logging of personal data processing activities';

-- Create indexes for better performance (will be in separate file)
-- These are defined here as comments for reference
/*
CREATE INDEX CONCURRENTLY idx_audit_events_timestamp ON audit_events (event_timestamp DESC);
CREATE INDEX CONCURRENTLY idx_audit_events_user_id ON audit_events (user_id);
CREATE INDEX CONCURRENTLY idx_audit_events_type_severity ON audit_events (event_type, severity);
CREATE INDEX CONCURRENTLY idx_user_activities_user_date ON user_activities (user_id, started_at DESC);
CREATE INDEX CONCURRENTLY idx_access_logs_resource ON access_logs (resource_type, resource_id);
CREATE INDEX CONCURRENTLY idx_security_events_ip ON security_events (source_ip, event_timestamp DESC);
*/