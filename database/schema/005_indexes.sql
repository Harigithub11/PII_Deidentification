-- Database Indexes and Performance Optimization for PII De-identification System
-- Comprehensive indexing strategy for optimal query performance
-- Version: 1.0.0

-- =============================================================================
-- CORE TABLES INDEXES
-- =============================================================================

-- Users table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_username 
    ON users (username);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_encrypted 
    ON users USING hash (email); -- Hash index for encrypted email lookups

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_role_active 
    ON users (role, is_active);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_created_at 
    ON users (created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_last_login 
    ON users (last_login DESC) WHERE last_login IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_failed_attempts 
    ON users (failed_login_attempts) WHERE failed_login_attempts > 0;

-- User sessions indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_user_id 
    ON user_sessions (user_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_token 
    ON user_sessions USING hash (session_token);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_status_expires 
    ON user_sessions (status, expires_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_ip_address 
    ON user_sessions (ip_address);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_last_accessed 
    ON user_sessions (last_accessed DESC);

-- API keys indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_api_keys_user_id 
    ON api_keys (user_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_api_keys_hash 
    ON api_keys USING hash (key_hash);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_api_keys_active_expires 
    ON api_keys (is_active, expires_at) WHERE expires_at IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_api_keys_last_used 
    ON api_keys (last_used DESC) WHERE last_used IS NOT NULL;

-- Lookup tables indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pii_type_definitions_category 
    ON pii_type_definitions (category, is_active);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_compliance_standards_code 
    ON compliance_standards (code, is_active);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_data_retention_schedules_active 
    ON data_retention_schedules (is_active, retention_period_days);

-- =============================================================================
-- AUDIT TABLES INDEXES
-- =============================================================================

-- Audit events indexes (primary audit table)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_timestamp 
    ON audit_events (event_timestamp DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_user_id 
    ON audit_events (user_id, event_timestamp DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_type_severity 
    ON audit_events (event_type, severity);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_outcome 
    ON audit_events (outcome, event_timestamp DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_target 
    ON audit_events (target_type, target_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_ip_address 
    ON audit_events (ip_address) WHERE ip_address IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_contains_pii 
    ON audit_events (contains_pii, event_timestamp DESC) WHERE contains_pii = true;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_compliance 
    ON audit_events USING gin (compliance_standards);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_risk_score 
    ON audit_events (risk_score DESC) WHERE risk_score > 50;

-- Composite indexes for common audit queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_user_type_date 
    ON audit_events (user_id, event_type, event_timestamp DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_severity_date 
    ON audit_events (severity, event_timestamp DESC) 
    WHERE severity IN ('high', 'critical');

-- Audit event details indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_event_details_event_id 
    ON audit_event_details (audit_event_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_event_details_type_key 
    ON audit_event_details (detail_type, detail_key);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_event_details_sensitive 
    ON audit_event_details (is_sensitive, created_at DESC) WHERE is_sensitive = true;

-- User activities indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_user_date 
    ON user_activities (user_id, started_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_type 
    ON user_activities (activity_type, started_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_resource 
    ON user_activities (resource_type, resource_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_suspicious 
    ON user_activities (is_suspicious, started_at DESC) WHERE is_suspicious = true;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_ip_address 
    ON user_activities (ip_address);

-- System events indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_system_events_timestamp 
    ON system_events (event_timestamp DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_system_events_type_severity 
    ON system_events (event_type, severity);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_system_events_service 
    ON system_events (service_name, event_timestamp DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_system_events_requires_attention 
    ON system_events (requires_attention, event_timestamp DESC) 
    WHERE requires_attention = true;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_system_events_unresolved 
    ON system_events (is_resolved, event_timestamp DESC) WHERE is_resolved = false;

-- Access logs indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_logs_user_timestamp 
    ON access_logs (user_id, access_timestamp DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_logs_resource 
    ON access_logs (resource_type, resource_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_logs_permission_denied 
    ON access_logs (permission_granted, access_timestamp DESC) 
    WHERE permission_granted = false;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_logs_contains_pii 
    ON access_logs (contains_pii, access_timestamp DESC) WHERE contains_pii = true;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_logs_pii_types 
    ON access_logs USING gin (pii_types);

-- Security events indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_ip_timestamp 
    ON security_events (source_ip, event_timestamp DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_type_severity 
    ON security_events (event_type, severity);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_blocked 
    ON security_events (blocked, event_timestamp DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_uninvestigated 
    ON security_events (investigated, event_timestamp DESC) WHERE investigated = false;

-- Data processing logs indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_data_processing_logs_subject 
    ON data_processing_logs (data_subject_id, processing_started DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_data_processing_logs_standard 
    ON data_processing_logs (compliance_standard, processing_started DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_data_processing_logs_consent 
    ON data_processing_logs (consent_obtained, processing_started DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_data_processing_logs_pii_types 
    ON data_processing_logs USING gin (pii_types_processed);

-- =============================================================================
-- POLICY TABLES INDEXES
-- =============================================================================

-- Compliance policies indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_compliance_policies_code_version 
    ON compliance_policies (policy_code, version);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_compliance_policies_standard 
    ON compliance_policies (compliance_standard_id, status);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_compliance_policies_active 
    ON compliance_policies (status, effective_date DESC) 
    WHERE status = 'active';

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_compliance_policies_effective 
    ON compliance_policies (effective_date, expiration_date);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_compliance_policies_parent 
    ON compliance_policies (parent_policy_id, policy_order);

-- Policy rules indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_rules_policy_id 
    ON policy_rules (policy_id, rule_order);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_rules_pii_type 
    ON policy_rules (pii_type, is_active);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_rules_redaction_method 
    ON policy_rules (redaction_method, is_active);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_rules_mandatory 
    ON policy_rules (is_mandatory, is_active);

-- Policy versions indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_versions_policy_id 
    ON policy_versions (policy_id, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_versions_change_type 
    ON policy_versions (change_type, created_at DESC);

-- Policy applications indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_applications_policy_id 
    ON policy_applications (policy_id, started_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_applications_target 
    ON policy_applications (target_type, target_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_applications_status 
    ON policy_applications (application_status, started_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_applications_user 
    ON policy_applications (applied_by, started_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_applications_validation 
    ON policy_applications (validation_status, completed_at DESC);

-- Policy rule executions indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_rule_executions_application 
    ON policy_rule_executions (policy_application_id, execution_order);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_rule_executions_rule 
    ON policy_rule_executions (policy_rule_id, started_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_rule_executions_errors 
    ON policy_rule_executions (error_occurred, started_at DESC) 
    WHERE error_occurred = true;

-- =============================================================================
-- METADATA TABLES INDEXES
-- =============================================================================

-- Document metadata indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_filename 
    ON document_metadata (original_filename);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_type_format 
    ON document_metadata (document_type, file_format);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_uploaded 
    ON document_metadata (uploaded_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_uploaded_by 
    ON document_metadata (uploaded_by, uploaded_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_checksum_md5 
    ON document_metadata (file_checksum_md5);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_checksum_sha256 
    ON document_metadata (file_checksum_sha256);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_pii_detected 
    ON document_metadata (pii_detected, uploaded_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_pii_types 
    ON document_metadata USING gin (pii_types_found);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_classification 
    ON document_metadata (security_classification, contains_sensitive_data);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_expires 
    ON document_metadata (expires_at) WHERE expires_at IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_policy 
    ON document_metadata (processing_policy_id);

-- Processing sessions indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_processing_sessions_policy 
    ON processing_sessions (policy_id, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_processing_sessions_status 
    ON processing_sessions (status, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_processing_sessions_user 
    ON processing_sessions (initiated_by, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_processing_sessions_type 
    ON processing_sessions (session_type, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_processing_sessions_stage 
    ON processing_sessions (current_stage, status);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_processing_sessions_completed 
    ON processing_sessions (completed_at DESC) WHERE completed_at IS NOT NULL;

-- Session documents indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_session_documents_session 
    ON session_documents (session_id, processing_order);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_session_documents_document 
    ON session_documents (document_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_session_documents_status 
    ON session_documents (status, added_at DESC);

-- File storage indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_storage_key 
    ON file_storage (storage_key);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_storage_path 
    ON file_storage (file_path);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_storage_provider 
    ON file_storage (storage_provider, storage_bucket);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_storage_expires 
    ON file_storage (expires_at) WHERE expires_at IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_storage_encrypted 
    ON file_storage (is_encrypted, encryption_algorithm);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_storage_accessed 
    ON file_storage (last_accessed DESC) WHERE last_accessed IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_storage_checksum_sha256 
    ON file_storage (checksum_sha256);

-- File access logs indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_access_logs_file 
    ON file_access_logs (file_storage_id, accessed_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_access_logs_user 
    ON file_access_logs (user_id, accessed_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_access_logs_type 
    ON file_access_logs (access_type, accessed_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_access_logs_unauthorized 
    ON file_access_logs (authorized, accessed_at DESC) WHERE authorized = false;

-- Redaction metadata indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_redaction_metadata_document 
    ON redaction_metadata (document_id, page_number);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_redaction_metadata_session 
    ON redaction_metadata (session_id, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_redaction_metadata_pii_type 
    ON redaction_metadata (pii_type, confidence_score DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_redaction_metadata_method 
    ON redaction_metadata (redaction_method, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_redaction_metadata_reviewed 
    ON redaction_metadata (manually_reviewed, needs_review);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_redaction_metadata_policy_rule 
    ON redaction_metadata (policy_rule_id);

-- Processing stage logs indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_processing_stage_logs_session 
    ON processing_stage_logs (session_id, stage_order);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_processing_stage_logs_stage 
    ON processing_stage_logs (stage, status);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_processing_stage_logs_errors 
    ON processing_stage_logs (error_occurred, started_at DESC) 
    WHERE error_occurred = true;

-- Batch processing jobs indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_batch_processing_jobs_type 
    ON batch_processing_jobs (job_type, is_active);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_batch_processing_jobs_scheduled 
    ON batch_processing_jobs (is_scheduled, next_run_time) 
    WHERE is_scheduled = true;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_batch_processing_jobs_status 
    ON batch_processing_jobs (status, created_at DESC);

-- Batch job runs indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_batch_job_runs_job 
    ON batch_job_runs (job_id, started_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_batch_job_runs_status 
    ON batch_job_runs (status, started_at DESC);

-- =============================================================================
-- PARTIAL INDEXES FOR COMMON QUERY PATTERNS
-- =============================================================================

-- Active entities only
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_active_recent 
    ON users (last_login DESC) 
    WHERE is_active = true AND last_login >= CURRENT_DATE - INTERVAL '30 days';

-- Failed processing sessions
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_processing_sessions_failed 
    ON processing_sessions (created_at DESC) 
    WHERE status = 'failed';

-- High-risk audit events
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_high_risk 
    ON audit_events (event_timestamp DESC) 
    WHERE risk_score >= 70 OR severity IN ('high', 'critical');

-- Expired documents
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_expired 
    ON document_metadata (expires_at) 
    WHERE expires_at <= CURRENT_TIMESTAMP;

-- Pending approvals
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_approval_requests_pending 
    ON policy_approval_requests (requested_at DESC) 
    WHERE status IN ('pending', 'in_review');

-- =============================================================================
-- COMPOSITE INDEXES FOR COMPLEX QUERIES
-- =============================================================================

-- User activity analysis
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_analysis 
    ON user_activities (user_id, activity_type, started_at DESC, is_suspicious);

-- Document processing pipeline
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_processing_pipeline 
    ON session_documents (session_id, status, processing_order, started_at);

-- Audit trail analysis
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_trail 
    ON audit_events (target_type, target_id, event_type, event_timestamp DESC);

-- Policy compliance tracking
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_applications_compliance 
    ON policy_applications (policy_id, validation_status, started_at DESC);

-- File lifecycle management
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_storage_lifecycle 
    ON file_storage (storage_class, created_at, last_accessed, expires_at);

-- =============================================================================
-- FULL-TEXT SEARCH INDEXES
-- =============================================================================

-- Enable full-text search on descriptions and text fields
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_description_fts 
    ON audit_events USING gin (to_tsvector('english', event_description));

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_name_fts 
    ON document_metadata USING gin (to_tsvector('english', document_name));

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_rules_description_fts 
    ON policy_rules USING gin (to_tsvector('english', rule_description));

-- =============================================================================
-- EXPRESSION INDEXES
-- =============================================================================

-- Date-based expressions for time-series queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_date_trunc_day 
    ON audit_events (date_trunc('day', event_timestamp));

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_date_trunc_hour 
    ON user_activities (date_trunc('hour', started_at));

-- Case-insensitive searches
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_username_lower 
    ON users (lower(username));

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_document_metadata_filename_lower 
    ON document_metadata (lower(original_filename));

-- =============================================================================
-- MAINTENANCE AND MONITORING
-- =============================================================================

-- Function to analyze index usage
CREATE OR REPLACE FUNCTION analyze_index_usage()
RETURNS TABLE (
    schemaname TEXT,
    tablename TEXT,
    indexname TEXT,
    index_scans BIGINT,
    index_tup_read BIGINT,
    index_tup_fetch BIGINT,
    usage_ratio NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ps.schemaname::TEXT,
        ps.tablename::TEXT,
        ps.indexrelname::TEXT,
        ps.idx_scan,
        ps.idx_tup_read,
        ps.idx_tup_fetch,
        CASE 
            WHEN ps.idx_scan = 0 THEN 0
            ELSE ROUND((ps.idx_tup_read::NUMERIC / ps.idx_scan), 2)
        END as usage_ratio
    FROM pg_stat_user_indexes ps
    JOIN pg_indexes pi ON ps.indexrelname = pi.indexname
    WHERE ps.schemaname = 'public'
    ORDER BY ps.idx_scan DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to identify unused indexes
CREATE OR REPLACE FUNCTION find_unused_indexes()
RETURNS TABLE (
    schemaname TEXT,
    tablename TEXT,
    indexname TEXT,
    index_size TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ps.schemaname::TEXT,
        ps.tablename::TEXT,
        ps.indexrelname::TEXT,
        pg_size_pretty(pg_relation_size(ps.indexrelid))::TEXT
    FROM pg_stat_user_indexes ps
    JOIN pg_indexes pi ON ps.indexrelname = pi.indexname
    WHERE ps.schemaname = 'public'
    AND ps.idx_scan = 0
    AND pi.indexname NOT LIKE '%_pkey'
    ORDER BY pg_relation_size(ps.indexrelid) DESC;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- INDEX MAINTENANCE SCHEDULE
-- =============================================================================

-- Function for routine index maintenance
CREATE OR REPLACE FUNCTION maintain_indexes()
RETURNS VOID AS $$
DECLARE
    rec RECORD;
BEGIN
    -- Reindex tables with high update frequency
    FOR rec IN 
        SELECT schemaname, tablename 
        FROM pg_stat_user_tables 
        WHERE schemaname = 'public' 
        AND (n_tup_upd + n_tup_del) > 10000
    LOOP
        EXECUTE 'REINDEX TABLE ' || quote_ident(rec.schemaname) || '.' || quote_ident(rec.tablename);
    END LOOP;
    
    -- Update table statistics
    ANALYZE;
END;
$$ LANGUAGE plpgsql;

-- Comments for documentation
COMMENT ON FUNCTION analyze_index_usage() IS 'Analyze index usage statistics to identify performance patterns';
COMMENT ON FUNCTION find_unused_indexes() IS 'Find indexes that are not being used and may be candidates for removal';
COMMENT ON FUNCTION maintain_indexes() IS 'Perform routine index maintenance including reindexing and statistics updates';

-- Performance monitoring queries (as comments for reference)
/*
-- Query to check index usage:
SELECT * FROM analyze_index_usage();

-- Query to find unused indexes:
SELECT * FROM find_unused_indexes();

-- Query to check table statistics:
SELECT 
    schemaname,
    tablename,
    n_tup_ins + n_tup_upd + n_tup_del as total_modifications,
    n_tup_ins,
    n_tup_upd,
    n_tup_del,
    last_analyze,
    last_autoanalyze
FROM pg_stat_user_tables 
WHERE schemaname = 'public'
ORDER BY total_modifications DESC;

-- Query to check index bloat:
SELECT 
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexrelid)) as index_size,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch
FROM pg_stat_user_indexes 
WHERE schemaname = 'public'
ORDER BY pg_relation_size(indexrelid) DESC;
*/