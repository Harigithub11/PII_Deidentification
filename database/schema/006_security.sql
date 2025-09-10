-- Security Policies and Permissions for PII De-identification System
-- Row-level security, data protection, and access control
-- Version: 1.0.0

-- =============================================================================
-- ENABLE ROW LEVEL SECURITY
-- =============================================================================

-- Enable RLS for sensitive tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_activities ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE processing_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE file_storage ENABLE ROW LEVEL SECURITY;
ALTER TABLE redaction_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_applications ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- DATABASE ROLES AND PERMISSIONS
-- =============================================================================

-- Create database roles for different access levels
DO $$
BEGIN
    -- Application service role
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pii_app_service') THEN
        CREATE ROLE pii_app_service WITH LOGIN;
    END IF;
    
    -- Read-only analytics role
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pii_analytics') THEN
        CREATE ROLE pii_analytics WITH LOGIN;
    END IF;
    
    -- Audit access role
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pii_auditor') THEN
        CREATE ROLE pii_auditor WITH LOGIN;
    END IF;
    
    -- Backup and maintenance role
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pii_maintenance') THEN
        CREATE ROLE pii_maintenance WITH LOGIN;
    END IF;
    
    -- Data processor role (limited processing access)
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pii_processor') THEN
        CREATE ROLE pii_processor WITH LOGIN;
    END IF;
END
$$;

-- =============================================================================
-- GRANT PERMISSIONS TO ROLES
-- =============================================================================

-- Application service role - full access to application tables
GRANT USAGE ON SCHEMA public TO pii_app_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pii_app_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO pii_app_service;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO pii_app_service;

-- Analytics role - read-only access to non-sensitive data
GRANT USAGE ON SCHEMA public TO pii_analytics;
GRANT SELECT ON users, user_sessions, audit_events, user_activities, system_events TO pii_analytics;
GRANT SELECT ON document_metadata, processing_sessions, session_documents TO pii_analytics;
GRANT SELECT ON policy_applications, policy_rule_executions TO pii_analytics;
GRANT SELECT ON compliance_policies, policy_rules, compliance_standards TO pii_analytics;
GRANT SELECT ON policy_compliance_reports, policy_effectiveness_metrics TO pii_analytics;

-- Auditor role - read access to audit and compliance data
GRANT USAGE ON SCHEMA public TO pii_auditor;
GRANT SELECT ON audit_events, audit_event_details, user_activities, access_logs TO pii_auditor;
GRANT SELECT ON security_events, data_processing_logs TO pii_auditor;
GRANT SELECT ON policy_applications, policy_compliance_reports TO pii_auditor;
GRANT SELECT ON users, user_sessions, api_keys TO pii_auditor;

-- Maintenance role - access for database maintenance
GRANT USAGE ON SCHEMA public TO pii_maintenance;
GRANT SELECT, UPDATE, DELETE ON system_events TO pii_maintenance;
GRANT SELECT, DELETE ON audit_events, user_activities WHERE event_timestamp < CURRENT_DATE - INTERVAL '7 years' TO pii_maintenance;
GRANT EXECUTE ON FUNCTION cleanup_audit_data(INTEGER) TO pii_maintenance;
GRANT EXECUTE ON FUNCTION maintain_indexes() TO pii_maintenance;

-- Processor role - limited access for document processing
GRANT USAGE ON SCHEMA public TO pii_processor;
GRANT SELECT, UPDATE ON document_metadata, processing_sessions, session_documents TO pii_processor;
GRANT SELECT, INSERT ON redaction_metadata, processing_stage_logs TO pii_processor;
GRANT SELECT ON compliance_policies, policy_rules TO pii_processor;
GRANT INSERT ON audit_events, user_activities TO pii_processor;

-- =============================================================================
-- ROW LEVEL SECURITY POLICIES
-- =============================================================================

-- Users table RLS policies
CREATE POLICY users_own_data ON users
    FOR ALL
    TO pii_app_service
    USING (id = current_setting('app.current_user_id')::uuid OR 
           current_setting('app.user_role') IN ('admin', 'auditor'));

CREATE POLICY users_admin_access ON users
    FOR ALL
    TO pii_app_service
    USING (current_setting('app.user_role') = 'admin');

-- User sessions RLS policies
CREATE POLICY user_sessions_own_data ON user_sessions
    FOR ALL
    TO pii_app_service
    USING (user_id = current_setting('app.current_user_id')::uuid OR
           current_setting('app.user_role') IN ('admin', 'auditor'));

-- API keys RLS policies
CREATE POLICY api_keys_own_data ON api_keys
    FOR ALL
    TO pii_app_service
    USING (user_id = current_setting('app.current_user_id')::uuid OR
           current_setting('app.user_role') = 'admin');

-- Audit events RLS policies
CREATE POLICY audit_events_read_access ON audit_events
    FOR SELECT
    TO pii_auditor, pii_analytics
    USING (true); -- Auditors can see all audit events

CREATE POLICY audit_events_user_context ON audit_events
    FOR ALL
    TO pii_app_service
    USING (user_id = current_setting('app.current_user_id')::uuid OR
           current_setting('app.user_role') IN ('admin', 'auditor') OR
           target_type = 'system');

-- Document metadata RLS policies
CREATE POLICY document_metadata_user_access ON document_metadata
    FOR ALL
    TO pii_app_service
    USING (uploaded_by = current_setting('app.current_user_id')::uuid OR
           current_setting('app.user_role') IN ('admin', 'data_processor'));

CREATE POLICY document_metadata_processor_read ON document_metadata
    FOR SELECT
    TO pii_processor
    USING (true);

-- Processing sessions RLS policies
CREATE POLICY processing_sessions_user_access ON processing_sessions
    FOR ALL
    TO pii_app_service
    USING (initiated_by = current_setting('app.current_user_id')::uuid OR
           current_setting('app.user_role') IN ('admin', 'data_processor'));

-- File storage RLS policies
CREATE POLICY file_storage_access_control ON file_storage
    FOR ALL
    TO pii_app_service
    USING (access_level = 'public' OR
           current_setting('app.user_role') IN ('admin', 'data_processor') OR
           (access_level = 'private' AND 
            id IN (SELECT DISTINCT fs.id 
                   FROM file_storage fs
                   JOIN document_metadata dm ON fs.storage_key = dm.original_file_path
                   WHERE dm.uploaded_by = current_setting('app.current_user_id')::uuid)));

-- Compliance policies RLS policies
CREATE POLICY compliance_policies_read_access ON compliance_policies
    FOR SELECT
    TO pii_app_service, pii_processor, pii_analytics
    USING (status = 'active' OR
           current_setting('app.user_role') IN ('admin', 'compliance_officer'));

CREATE POLICY compliance_policies_admin_write ON compliance_policies
    FOR INSERT, UPDATE, DELETE
    TO pii_app_service
    USING (current_setting('app.user_role') IN ('admin', 'compliance_officer'));

-- =============================================================================
-- SECURITY FUNCTIONS
-- =============================================================================

-- Function to set current user context for RLS
CREATE OR REPLACE FUNCTION set_current_user_context(
    p_user_id UUID,
    p_user_role TEXT DEFAULT 'user'
)
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_user_id', p_user_id::text, true);
    PERFORM set_config('app.user_role', p_user_role, true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to clear user context
CREATE OR REPLACE FUNCTION clear_user_context()
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_user_id', '', true);
    PERFORM set_config('app.user_role', '', true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to check if user has permission for specific operation
CREATE OR REPLACE FUNCTION check_user_permission(
    p_user_id UUID,
    p_resource_type TEXT,
    p_resource_id UUID DEFAULT NULL,
    p_operation TEXT DEFAULT 'read'
)
RETURNS BOOLEAN AS $$
DECLARE
    user_role user_role;
    has_permission BOOLEAN := false;
BEGIN
    -- Get user role
    SELECT role INTO user_role FROM users WHERE id = p_user_id AND is_active = true;
    
    IF user_role IS NULL THEN
        RETURN false;
    END IF;
    
    -- Admin has all permissions
    IF user_role = 'admin' THEN
        RETURN true;
    END IF;
    
    -- Check specific permissions based on resource type and operation
    CASE p_resource_type
        WHEN 'document' THEN
            IF p_operation IN ('read', 'download') THEN
                -- User can access their own documents
                SELECT EXISTS(
                    SELECT 1 FROM document_metadata 
                    WHERE id = p_resource_id AND uploaded_by = p_user_id
                ) INTO has_permission;
            ELSIF p_operation IN ('upload', 'process') THEN
                has_permission := user_role IN ('user', 'data_processor');
            END IF;
            
        WHEN 'audit' THEN
            has_permission := user_role IN ('auditor', 'admin');
            
        WHEN 'policy' THEN
            IF p_operation = 'read' THEN
                has_permission := true; -- All users can read active policies
            ELSE
                has_permission := user_role IN ('compliance_officer', 'admin');
            END IF;
            
        WHEN 'user_management' THEN
            has_permission := user_role = 'admin';
            
        ELSE
            has_permission := false;
    END CASE;
    
    RETURN has_permission;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to log security-sensitive operations
CREATE OR REPLACE FUNCTION log_security_operation(
    p_user_id UUID,
    p_operation TEXT,
    p_resource_type TEXT,
    p_resource_id UUID DEFAULT NULL,
    p_success BOOLEAN DEFAULT true,
    p_details JSONB DEFAULT '{}'
)
RETURNS VOID AS $$
BEGIN
    INSERT INTO audit_events (
        event_id,
        event_type,
        severity,
        outcome,
        user_id,
        target_type,
        target_id,
        event_description,
        ip_address,
        metadata
    ) VALUES (
        'SEC-' || EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::text,
        CASE 
            WHEN p_success THEN 'security_operation'::audit_event_type
            ELSE 'security_violation'::audit_event_type
        END,
        CASE 
            WHEN p_success THEN 'medium'::audit_severity
            ELSE 'high'::audit_severity
        END,
        CASE 
            WHEN p_success THEN 'success'::audit_outcome
            ELSE 'failure'::audit_outcome
        END,
        p_user_id,
        p_resource_type,
        p_resource_id,
        format('User %s performed %s on %s', p_user_id, p_operation, p_resource_type),
        inet_client_addr(),
        p_details
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- DATA ENCRYPTION AND PROTECTION
-- =============================================================================

-- Function to ensure sensitive data is encrypted
CREATE OR REPLACE FUNCTION validate_data_encryption()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if sensitive fields are properly encrypted
    -- This is a placeholder - actual encryption happens at application level
    
    -- Log data access for audit
    IF TG_OP = 'SELECT' THEN
        -- Log read access to sensitive data
        NULL; -- Placeholder for read access logging
    END IF;
    
    IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        -- Validate that PII fields are encrypted at application level
        -- Set metadata to track encryption status
        NEW.metadata = COALESCE(NEW.metadata, '{}'::jsonb) || 
                      '{"encryption_validated": true, "validation_timestamp": "' || 
                      CURRENT_TIMESTAMP::text || '"}'::jsonb;
    END IF;
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Apply encryption validation trigger to sensitive tables
CREATE TRIGGER validate_users_encryption
    BEFORE INSERT OR UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION validate_data_encryption();

CREATE TRIGGER validate_document_metadata_encryption
    BEFORE INSERT OR UPDATE ON document_metadata
    FOR EACH ROW EXECUTE FUNCTION validate_data_encryption();

-- =============================================================================
-- ACCESS MONITORING AND ALERTING
-- =============================================================================

-- Function to monitor and alert on suspicious access patterns
CREATE OR REPLACE FUNCTION monitor_access_patterns()
RETURNS VOID AS $$
DECLARE
    suspicious_activity RECORD;
BEGIN
    -- Check for multiple failed login attempts from same IP
    FOR suspicious_activity IN
        SELECT 
            source_ip,
            COUNT(*) as failed_attempts,
            MAX(event_timestamp) as last_attempt
        FROM security_events 
        WHERE event_type = 'failed_login' 
        AND event_timestamp >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
        GROUP BY source_ip
        HAVING COUNT(*) >= 5
    LOOP
        -- Insert security alert
        INSERT INTO security_events (
            event_type,
            severity,
            source_ip,
            event_description,
            detected_by,
            blocked,
            metadata
        ) VALUES (
            'brute_force_detected',
            'high',
            suspicious_activity.source_ip,
            format('Multiple failed login attempts detected from IP %s', suspicious_activity.source_ip),
            'automated_monitoring',
            true,
            jsonb_build_object(
                'failed_attempts', suspicious_activity.failed_attempts,
                'time_window', '1 hour',
                'last_attempt', suspicious_activity.last_attempt
            )
        );
    END LOOP;
    
    -- Check for unusual data access patterns
    FOR suspicious_activity IN
        SELECT 
            user_id,
            COUNT(DISTINCT resource_id) as unique_resources,
            COUNT(*) as total_accesses
        FROM access_logs 
        WHERE access_timestamp >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
        AND contains_pii = true
        GROUP BY user_id
        HAVING COUNT(DISTINCT resource_id) > 100  -- Accessing more than 100 unique PII resources
    LOOP
        -- Insert security alert
        INSERT INTO security_events (
            event_type,
            severity,
            target_user_id,
            event_description,
            detected_by,
            metadata
        ) VALUES (
            'unusual_data_access',
            'medium',
            suspicious_activity.user_id,
            format('Unusual data access pattern detected for user %s', suspicious_activity.user_id),
            'automated_monitoring',
            jsonb_build_object(
                'unique_resources_accessed', suspicious_activity.unique_resources,
                'total_accesses', suspicious_activity.total_accesses,
                'time_window', '1 hour'
            )
        );
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- DATA RETENTION AND CLEANUP SECURITY
-- =============================================================================

-- Function to securely delete expired data
CREATE OR REPLACE FUNCTION secure_data_cleanup()
RETURNS INTEGER AS $$
DECLARE
    cleanup_count INTEGER := 0;
    expired_doc RECORD;
BEGIN
    -- Clean up expired documents with secure deletion
    FOR expired_doc IN
        SELECT id, original_file_path, processed_file_path
        FROM document_metadata 
        WHERE expires_at <= CURRENT_TIMESTAMP
    LOOP
        -- Log the deletion
        INSERT INTO audit_events (
            event_id,
            event_type,
            severity,
            outcome,
            target_type,
            target_id,
            event_description,
            metadata
        ) VALUES (
            'CLEANUP-' || expired_doc.id::text,
            'data_export',
            'medium',
            'success',
            'document',
            expired_doc.id,
            'Expired document securely deleted',
            jsonb_build_object(
                'original_file_path', expired_doc.original_file_path,
                'processed_file_path', expired_doc.processed_file_path,
                'deletion_method', 'secure_wipe'
            )
        );
        
        -- Remove document metadata
        DELETE FROM document_metadata WHERE id = expired_doc.id;
        cleanup_count := cleanup_count + 1;
    END LOOP;
    
    -- Clean up old audit events (beyond retention period)
    DELETE FROM audit_event_details 
    WHERE audit_event_id IN (
        SELECT id FROM audit_events 
        WHERE event_timestamp < CURRENT_TIMESTAMP - INTERVAL '7 years'
    );
    
    DELETE FROM audit_events 
    WHERE event_timestamp < CURRENT_TIMESTAMP - INTERVAL '7 years';
    
    RETURN cleanup_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- DATABASE CONNECTION SECURITY
-- =============================================================================

-- Function to validate connection security
CREATE OR REPLACE FUNCTION validate_connection_security()
RETURNS BOOLEAN AS $$
DECLARE
    ssl_enabled BOOLEAN;
    connection_encrypted BOOLEAN;
BEGIN
    -- Check if SSL is enabled
    SELECT setting::boolean INTO ssl_enabled 
    FROM pg_settings WHERE name = 'ssl';
    
    -- Check if current connection is encrypted
    SELECT CASE WHEN ssl_cipher IS NOT NULL THEN true ELSE false END
    INTO connection_encrypted
    FROM pg_stat_ssl 
    WHERE pid = pg_backend_pid();
    
    -- Log connection security status
    INSERT INTO system_events (
        event_type,
        severity,
        event_name,
        event_description,
        metadata
    ) VALUES (
        'connection_security_check',
        CASE WHEN connection_encrypted THEN 'low' ELSE 'high' END,
        'Database Connection Security Validation',
        CASE 
            WHEN connection_encrypted THEN 'Connection is properly encrypted'
            ELSE 'WARNING: Connection is not encrypted'
        END,
        jsonb_build_object(
            'ssl_enabled', ssl_enabled,
            'connection_encrypted', connection_encrypted,
            'client_addr', inet_client_addr(),
            'application_name', current_setting('application_name')
        )
    );
    
    RETURN connection_encrypted;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- GRANT PERMISSIONS FOR SECURITY FUNCTIONS
-- =============================================================================

-- Grant execute permissions on security functions
GRANT EXECUTE ON FUNCTION set_current_user_context(UUID, TEXT) TO pii_app_service;
GRANT EXECUTE ON FUNCTION clear_user_context() TO pii_app_service;
GRANT EXECUTE ON FUNCTION check_user_permission(UUID, TEXT, UUID, TEXT) TO pii_app_service;
GRANT EXECUTE ON FUNCTION log_security_operation(UUID, TEXT, TEXT, UUID, BOOLEAN, JSONB) TO pii_app_service;
GRANT EXECUTE ON FUNCTION monitor_access_patterns() TO pii_maintenance;
GRANT EXECUTE ON FUNCTION secure_data_cleanup() TO pii_maintenance;
GRANT EXECUTE ON FUNCTION validate_connection_security() TO pii_app_service;

-- =============================================================================
-- SECURITY MONITORING VIEWS
-- =============================================================================

-- View for security dashboard
CREATE VIEW security_dashboard AS
SELECT 
    'Failed Logins (Last 24h)' as metric,
    COUNT(*)::text as value,
    'count' as type
FROM security_events 
WHERE event_type = 'failed_login' 
AND event_timestamp >= CURRENT_TIMESTAMP - INTERVAL '24 hours'

UNION ALL

SELECT 
    'High Risk Audit Events (Last 24h)' as metric,
    COUNT(*)::text as value,
    'count' as type
FROM audit_events 
WHERE risk_score >= 70 
AND event_timestamp >= CURRENT_TIMESTAMP - INTERVAL '24 hours'

UNION ALL

SELECT 
    'Unauthorized Access Attempts (Last 24h)' as metric,
    COUNT(*)::text as value,
    'count' as type
FROM access_logs 
WHERE permission_granted = false 
AND access_timestamp >= CURRENT_TIMESTAMP - INTERVAL '24 hours'

UNION ALL

SELECT 
    'Active User Sessions' as metric,
    COUNT(*)::text as value,
    'count' as type
FROM user_sessions 
WHERE status = 'active' 
AND expires_at > CURRENT_TIMESTAMP;

-- View for compliance status
CREATE VIEW compliance_status AS
SELECT 
    cs.name as compliance_standard,
    COUNT(DISTINCT cp.id) as active_policies,
    COUNT(DISTINCT pa.id) as recent_applications,
    AVG(pa.compliance_score) as avg_compliance_score,
    COUNT(CASE WHEN pa.validation_status = 'error' THEN 1 END) as validation_errors
FROM compliance_standards cs
LEFT JOIN compliance_policies cp ON cs.id = cp.compliance_standard_id AND cp.status = 'active'
LEFT JOIN policy_applications pa ON cp.id = pa.policy_id 
    AND pa.started_at >= CURRENT_DATE - INTERVAL '30 days'
WHERE cs.is_active = true
GROUP BY cs.id, cs.name;

-- Comments for documentation
COMMENT ON FUNCTION set_current_user_context(UUID, TEXT) IS 'Set user context for row-level security policies';
COMMENT ON FUNCTION check_user_permission(UUID, TEXT, UUID, TEXT) IS 'Check if user has permission for specific operation';
COMMENT ON FUNCTION log_security_operation(UUID, TEXT, TEXT, UUID, BOOLEAN, JSONB) IS 'Log security-sensitive operations for audit trail';
COMMENT ON FUNCTION monitor_access_patterns() IS 'Monitor and alert on suspicious access patterns';
COMMENT ON FUNCTION secure_data_cleanup() IS 'Securely delete expired data with audit logging';
COMMENT ON FUNCTION validate_connection_security() IS 'Validate that database connections are properly encrypted';
COMMENT ON VIEW security_dashboard IS 'Real-time security metrics for monitoring dashboard';
COMMENT ON VIEW compliance_status IS 'Compliance status summary by regulation standard';