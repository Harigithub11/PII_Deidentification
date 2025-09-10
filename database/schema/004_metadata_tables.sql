-- Metadata Tables SQL Schema for PII De-identification System
-- Tables for document metadata, processing sessions, and file management
-- Version: 1.0.0

-- =============================================================================
-- METADATA ENUMS AND TYPES
-- =============================================================================

-- Document types
CREATE TYPE document_type AS ENUM (
    'pdf',
    'image',
    'text',
    'word',
    'excel',
    'powerpoint',
    'csv',
    'json',
    'xml',
    'email',
    'medical_record',
    'form',
    'contract',
    'invoice',
    'other'
);

-- File formats
CREATE TYPE file_format AS ENUM (
    'pdf',
    'png',
    'jpg',
    'jpeg',
    'tiff',
    'tif',
    'bmp',
    'gif',
    'webp',
    'txt',
    'docx',
    'doc',
    'xlsx',
    'xls',
    'pptx',
    'ppt',
    'csv',
    'json',
    'xml',
    'html',
    'rtf',
    'eml',
    'msg'
);

-- Processing status
CREATE TYPE processing_status AS ENUM (
    'uploaded',
    'queued',
    'processing',
    'completed',
    'failed',
    'cancelled',
    'expired',
    'archived'
);

-- Processing stages
CREATE TYPE processing_stage AS ENUM (
    'upload_validation',
    'file_analysis',
    'content_extraction',
    'pii_detection',
    'policy_application',
    'redaction',
    'quality_check',
    'output_generation',
    'completion'
);

-- Quality levels
CREATE TYPE quality_level AS ENUM (
    'excellent',
    'good',
    'fair',
    'poor',
    'unacceptable'
);

-- =============================================================================
-- DOCUMENT AND FILE METADATA
-- =============================================================================

-- Main document metadata table
CREATE TABLE document_metadata (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Document identification
    document_name VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    document_type document_type NOT NULL,
    file_format file_format NOT NULL,
    
    -- File properties
    file_size_bytes BIGINT NOT NULL CHECK (file_size_bytes >= 0),
    file_checksum_md5 VARCHAR(32) NOT NULL,
    file_checksum_sha256 VARCHAR(64) NOT NULL,
    mime_type VARCHAR(100),
    
    -- Content properties
    page_count INTEGER DEFAULT 1 CHECK (page_count >= 0),
    word_count INTEGER DEFAULT 0 CHECK (word_count >= 0),
    character_count INTEGER DEFAULT 0 CHECK (character_count >= 0),
    image_count INTEGER DEFAULT 0 CHECK (image_count >= 0),
    
    -- Language and encoding
    primary_language VARCHAR(10), -- ISO 639-1 language code
    detected_languages VARCHAR(10)[] DEFAULT '{}',
    text_encoding VARCHAR(50) DEFAULT 'UTF-8',
    
    -- Security and classification
    security_classification VARCHAR(20) DEFAULT 'internal', -- public, internal, confidential, restricted
    contains_sensitive_data BOOLEAN NOT NULL DEFAULT false,
    sensitivity_score INTEGER CHECK (sensitivity_score BETWEEN 0 AND 100),
    
    -- PII content analysis
    pii_detected BOOLEAN NOT NULL DEFAULT false,
    pii_types_found pii_type[] DEFAULT '{}',
    pii_item_count INTEGER DEFAULT 0 CHECK (pii_item_count >= 0),
    high_confidence_pii_count INTEGER DEFAULT 0 CHECK (high_confidence_pii_count >= 0),
    
    -- Document structure
    has_forms BOOLEAN NOT NULL DEFAULT false,
    has_tables BOOLEAN NOT NULL DEFAULT false,
    has_images BOOLEAN NOT NULL DEFAULT false,
    has_signatures BOOLEAN NOT NULL DEFAULT false,
    has_handwriting BOOLEAN NOT NULL DEFAULT false,
    
    -- Quality metrics
    text_quality quality_level DEFAULT 'good',
    image_quality quality_level DEFAULT 'good',
    ocr_confidence_avg DECIMAL(5,2) CHECK (ocr_confidence_avg BETWEEN 0 AND 100),
    
    -- Processing metadata
    uploaded_by UUID REFERENCES users(id),
    processing_policy_id UUID REFERENCES compliance_policies(id),
    processing_batch_id UUID, -- For batch processing
    
    -- File locations
    original_file_path TEXT NOT NULL,
    processed_file_path TEXT,
    backup_file_path TEXT,
    thumbnail_path TEXT,
    
    -- Timestamps
    uploaded_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    
    -- Audit and compliance
    retention_policy_id UUID REFERENCES data_retention_schedules(id),
    compliance_validated BOOLEAN NOT NULL DEFAULT false,
    compliance_validation_date TIMESTAMP WITH TIME ZONE,
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',
    tags VARCHAR(50)[] DEFAULT '{}',
    
    CONSTRAINT document_metadata_checksum_length CHECK (
        length(file_checksum_md5) = 32 AND length(file_checksum_sha256) = 64
    )
);

-- Processing sessions for tracking document processing workflows
CREATE TABLE processing_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_name VARCHAR(100),
    
    -- Session identification
    session_type VARCHAR(50) NOT NULL DEFAULT 'single_document', -- 'single_document', 'batch', 'scheduled'
    session_priority INTEGER NOT NULL DEFAULT 3 CHECK (session_priority BETWEEN 1 AND 5),
    
    -- Processing configuration
    policy_id UUID NOT NULL REFERENCES compliance_policies(id),
    policy_version_id UUID REFERENCES policy_versions(id),
    processing_mode VARCHAR(20) NOT NULL DEFAULT 'automatic', -- 'automatic', 'manual', 'review'
    
    -- Session status
    status processing_status NOT NULL DEFAULT 'queued',
    current_stage processing_stage,
    progress_percentage INTEGER DEFAULT 0 CHECK (progress_percentage BETWEEN 0 AND 100),
    
    -- Document scope
    document_count INTEGER NOT NULL DEFAULT 0,
    documents_processed INTEGER NOT NULL DEFAULT 0,
    documents_successful INTEGER NOT NULL DEFAULT 0,
    documents_failed INTEGER NOT NULL DEFAULT 0,
    
    -- Processing metrics
    total_pii_detected INTEGER NOT NULL DEFAULT 0,
    total_pii_redacted INTEGER NOT NULL DEFAULT 0,
    processing_time_seconds INTEGER,
    
    -- Resource usage
    cpu_time_seconds DECIMAL(10,2),
    memory_peak_mb INTEGER,
    storage_used_mb INTEGER,
    
    -- Quality metrics
    overall_quality_score DECIMAL(5,2) CHECK (overall_quality_score BETWEEN 0 AND 100),
    average_confidence_score DECIMAL(5,2) CHECK (average_confidence_score BETWEEN 0 AND 100),
    
    -- User and system information
    initiated_by UUID REFERENCES users(id),
    processed_by VARCHAR(100), -- System/service that processed
    worker_node VARCHAR(100), -- Processing worker/node identifier
    
    -- Timing
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    estimated_completion TIMESTAMP WITH TIME ZONE,
    
    -- Error handling
    error_count INTEGER NOT NULL DEFAULT 0,
    last_error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    
    -- Output information
    output_location TEXT,
    output_format VARCHAR(20),
    output_size_bytes BIGINT,
    
    -- Audit and compliance
    audit_trail_id UUID, -- Link to audit events
    compliance_report_generated BOOLEAN NOT NULL DEFAULT false,
    
    -- Additional metadata
    configuration JSONB DEFAULT '{}',
    metrics JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    
    CONSTRAINT processing_sessions_timing CHECK (
        started_at IS NULL OR started_at >= created_at
    ),
    CONSTRAINT processing_sessions_completion CHECK (
        completed_at IS NULL OR (started_at IS NOT NULL AND completed_at >= started_at)
    )
);

-- Documents in processing sessions (many-to-many relationship)
CREATE TABLE session_documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES processing_sessions(id) ON DELETE CASCADE,
    document_id UUID NOT NULL REFERENCES document_metadata(id) ON DELETE CASCADE,
    
    -- Processing details for this document
    processing_order INTEGER NOT NULL DEFAULT 0,
    status processing_status NOT NULL DEFAULT 'queued',
    current_stage processing_stage,
    progress_percentage INTEGER DEFAULT 0 CHECK (progress_percentage BETWEEN 0 AND 100),
    
    -- Processing results
    pii_detected_count INTEGER DEFAULT 0,
    pii_redacted_count INTEGER DEFAULT 0,
    processing_time_seconds INTEGER,
    
    -- Quality and confidence
    quality_score DECIMAL(5,2) CHECK (quality_score BETWEEN 0 AND 100),
    confidence_score DECIMAL(5,2) CHECK (confidence_score BETWEEN 0 AND 100),
    
    -- Timing
    added_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Error handling
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    
    -- Output
    output_file_path TEXT,
    output_size_bytes BIGINT,
    
    -- Metadata
    processing_notes TEXT,
    metadata JSONB DEFAULT '{}',
    
    UNIQUE(session_id, document_id)
);

-- =============================================================================
-- FILE MANAGEMENT AND STORAGE
-- =============================================================================

-- File storage locations and management
CREATE TABLE file_storage (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- File identification
    storage_key VARCHAR(255) NOT NULL UNIQUE, -- Unique storage identifier
    file_name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    
    -- Storage metadata
    storage_provider VARCHAR(50) NOT NULL DEFAULT 'local', -- 'local', 's3', 'azure', 'gcp'
    storage_bucket VARCHAR(100),
    storage_region VARCHAR(50),
    storage_class VARCHAR(50) DEFAULT 'standard', -- 'standard', 'cold', 'archive'
    
    -- File properties
    file_size_bytes BIGINT NOT NULL CHECK (file_size_bytes >= 0),
    content_type VARCHAR(100),
    content_encoding VARCHAR(50),
    
    -- Security
    is_encrypted BOOLEAN NOT NULL DEFAULT false,
    encryption_key_id VARCHAR(100),
    encryption_algorithm VARCHAR(50),
    access_level VARCHAR(20) NOT NULL DEFAULT 'private', -- 'public', 'private', 'restricted'
    
    -- Lifecycle management
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    archived_at TIMESTAMP WITH TIME ZONE,
    
    -- Usage tracking
    access_count BIGINT NOT NULL DEFAULT 0,
    download_count BIGINT NOT NULL DEFAULT 0,
    
    -- Integrity
    checksum_md5 VARCHAR(32),
    checksum_sha256 VARCHAR(64),
    integrity_verified BOOLEAN NOT NULL DEFAULT false,
    integrity_check_date TIMESTAMP WITH TIME ZONE,
    
    -- Backup and versioning
    is_backup BOOLEAN NOT NULL DEFAULT false,
    original_file_id UUID REFERENCES file_storage(id),
    version_number INTEGER DEFAULT 1,
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',
    tags VARCHAR(50)[] DEFAULT '{}'
);

-- File access logs for detailed tracking
CREATE TABLE file_access_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_storage_id UUID NOT NULL REFERENCES file_storage(id) ON DELETE CASCADE,
    
    -- Access details
    access_type VARCHAR(20) NOT NULL, -- 'read', 'write', 'delete', 'download', 'copy'
    access_method VARCHAR(50), -- 'api', 'web', 'cli', 'system'
    
    -- User context
    user_id UUID REFERENCES users(id),
    session_id UUID REFERENCES user_sessions(id),
    ip_address INET,
    user_agent TEXT,
    
    -- Request details
    request_id VARCHAR(100),
    bytes_transferred BIGINT DEFAULT 0,
    duration_ms INTEGER,
    
    -- Result
    success BOOLEAN NOT NULL DEFAULT true,
    status_code INTEGER,
    error_message TEXT,
    
    -- Timing
    accessed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Security and compliance
    authorized BOOLEAN NOT NULL DEFAULT true,
    permission_source VARCHAR(50), -- 'user_role', 'policy', 'explicit'
    
    -- Additional context
    purpose VARCHAR(100), -- Purpose of access
    metadata JSONB DEFAULT '{}'
);

-- =============================================================================
-- REDACTION AND PROCESSING METADATA
-- =============================================================================

-- Redaction operations metadata
CREATE TABLE redaction_metadata (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID NOT NULL REFERENCES document_metadata(id) ON DELETE CASCADE,
    session_id UUID REFERENCES processing_sessions(id),
    
    -- Redaction details
    redaction_type VARCHAR(50) NOT NULL, -- 'text', 'image', 'structured_data'
    redaction_method redaction_method NOT NULL,
    
    -- Location information
    page_number INTEGER CHECK (page_number >= 1),
    x_coordinate INTEGER CHECK (x_coordinate >= 0),
    y_coordinate INTEGER CHECK (y_coordinate >= 0),
    width INTEGER CHECK (width >= 0),
    height INTEGER CHECK (height >= 0),
    
    -- Content information
    original_text TEXT, -- Encrypted at application level
    redacted_text TEXT,
    pii_type pii_type NOT NULL,
    confidence_score DECIMAL(5,2) NOT NULL CHECK (confidence_score BETWEEN 0 AND 100),
    
    -- Detection metadata
    detection_model VARCHAR(100),
    detection_version VARCHAR(20),
    detection_parameters JSONB DEFAULT '{}',
    
    -- Manual review
    manually_reviewed BOOLEAN NOT NULL DEFAULT false,
    reviewed_by UUID REFERENCES users(id),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_decision VARCHAR(20), -- 'approved', 'rejected', 'modified'
    review_notes TEXT,
    
    -- Redaction quality
    redaction_quality quality_level DEFAULT 'good',
    needs_review BOOLEAN NOT NULL DEFAULT false,
    
    -- Policy compliance
    policy_rule_id UUID REFERENCES policy_rules(id),
    compliance_justification TEXT,
    
    -- Timing
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP WITH TIME ZONE,
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}'
);

-- Processing stage details and performance metrics
CREATE TABLE processing_stage_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES processing_sessions(id) ON DELETE CASCADE,
    document_id UUID REFERENCES document_metadata(id),
    
    -- Stage information
    stage processing_stage NOT NULL,
    stage_name VARCHAR(100) NOT NULL,
    stage_order INTEGER NOT NULL DEFAULT 0,
    
    -- Status and progress
    status processing_status NOT NULL DEFAULT 'queued',
    progress_percentage INTEGER DEFAULT 0 CHECK (progress_percentage BETWEEN 0 AND 100),
    
    -- Processing details
    processor_name VARCHAR(100), -- Name of the processing component
    processor_version VARCHAR(20),
    processing_parameters JSONB DEFAULT '{}',
    
    -- Performance metrics
    cpu_time_seconds DECIMAL(10,2),
    memory_used_mb INTEGER,
    processing_time_ms INTEGER,
    
    -- Input/Output
    input_size_bytes BIGINT,
    output_size_bytes BIGINT,
    items_processed INTEGER DEFAULT 0,
    items_successful INTEGER DEFAULT 0,
    items_failed INTEGER DEFAULT 0,
    
    -- Quality metrics
    quality_score DECIMAL(5,2) CHECK (quality_score BETWEEN 0 AND 100),
    confidence_score DECIMAL(5,2) CHECK (confidence_score BETWEEN 0 AND 100),
    
    -- Timing
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Error handling
    error_occurred BOOLEAN NOT NULL DEFAULT false,
    error_message TEXT,
    error_details JSONB,
    warning_count INTEGER DEFAULT 0,
    
    -- Additional metrics and metadata
    stage_metrics JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    
    UNIQUE(session_id, document_id, stage),
    CONSTRAINT processing_stage_logs_completion CHECK (
        completed_at IS NULL OR completed_at >= started_at
    )
);

-- =============================================================================
-- BATCH AND SCHEDULED PROCESSING
-- =============================================================================

-- Batch processing jobs
CREATE TABLE batch_processing_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Job identification
    job_name VARCHAR(100) NOT NULL,
    job_description TEXT,
    job_type VARCHAR(50) NOT NULL DEFAULT 'document_processing', -- 'document_processing', 'cleanup', 'report_generation'
    
    -- Scheduling
    is_scheduled BOOLEAN NOT NULL DEFAULT false,
    schedule_expression VARCHAR(100), -- Cron expression
    next_run_time TIMESTAMP WITH TIME ZONE,
    
    -- Job configuration
    policy_id UUID REFERENCES compliance_policies(id),
    processing_parameters JSONB DEFAULT '{}',
    max_concurrent_documents INTEGER DEFAULT 5,
    timeout_minutes INTEGER DEFAULT 60,
    
    -- Job status
    status processing_status NOT NULL DEFAULT 'queued',
    current_run_id UUID,
    
    -- Execution history
    total_runs INTEGER NOT NULL DEFAULT 0,
    successful_runs INTEGER NOT NULL DEFAULT 0,
    failed_runs INTEGER NOT NULL DEFAULT 0,
    last_run_at TIMESTAMP WITH TIME ZONE,
    last_run_duration_seconds INTEGER,
    last_run_status processing_status,
    
    -- Resource limits
    max_memory_mb INTEGER DEFAULT 2048,
    max_cpu_cores INTEGER DEFAULT 2,
    max_storage_mb INTEGER DEFAULT 10240,
    
    -- Notifications
    notify_on_completion BOOLEAN NOT NULL DEFAULT false,
    notify_on_failure BOOLEAN NOT NULL DEFAULT true,
    notification_recipients TEXT[],
    
    -- Job metadata
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT true,
    
    -- Additional configuration
    metadata JSONB DEFAULT '{}'
);

-- Batch job execution runs
CREATE TABLE batch_job_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID NOT NULL REFERENCES batch_processing_jobs(id) ON DELETE CASCADE,
    
    -- Run identification
    run_number INTEGER NOT NULL,
    triggered_by VARCHAR(50) NOT NULL DEFAULT 'schedule', -- 'schedule', 'manual', 'api'
    triggered_by_user UUID REFERENCES users(id),
    
    -- Run status
    status processing_status NOT NULL DEFAULT 'queued',
    
    -- Processing scope
    documents_queued INTEGER NOT NULL DEFAULT 0,
    documents_processed INTEGER NOT NULL DEFAULT 0,
    documents_successful INTEGER NOT NULL DEFAULT 0,
    documents_failed INTEGER NOT NULL DEFAULT 0,
    documents_skipped INTEGER NOT NULL DEFAULT 0,
    
    -- Performance metrics
    processing_time_seconds INTEGER,
    cpu_time_seconds DECIMAL(10,2),
    memory_peak_mb INTEGER,
    storage_used_mb INTEGER,
    
    -- Results
    total_pii_detected INTEGER NOT NULL DEFAULT 0,
    total_pii_redacted INTEGER NOT NULL DEFAULT 0,
    output_files_generated INTEGER NOT NULL DEFAULT 0,
    
    -- Timing
    scheduled_at TIMESTAMP WITH TIME ZONE,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Error handling
    error_count INTEGER NOT NULL DEFAULT 0,
    warning_count INTEGER NOT NULL DEFAULT 0,
    last_error_message TEXT,
    
    -- Output and logs
    log_file_path TEXT,
    output_summary JSONB DEFAULT '{}',
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',
    
    UNIQUE(job_id, run_number),
    CONSTRAINT batch_job_runs_timing CHECK (
        started_at IS NULL OR 
        (scheduled_at IS NULL OR started_at >= scheduled_at) AND
        (completed_at IS NULL OR completed_at >= started_at)
    )
);

-- =============================================================================
-- TRIGGERS FOR METADATA MANAGEMENT
-- =============================================================================

-- Update timestamps
CREATE TRIGGER update_processing_sessions_updated_at 
    BEFORE UPDATE ON processing_sessions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_batch_processing_jobs_updated_at 
    BEFORE UPDATE ON batch_processing_jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to update file access tracking
CREATE OR REPLACE FUNCTION update_file_access_stats()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE file_storage 
    SET 
        access_count = access_count + 1,
        last_accessed = CURRENT_TIMESTAMP
    WHERE id = NEW.file_storage_id;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for file access tracking
CREATE TRIGGER file_access_tracking_trigger
    AFTER INSERT ON file_access_logs
    FOR EACH ROW
    EXECUTE FUNCTION update_file_access_stats();

-- =============================================================================
-- USEFUL VIEWS FOR METADATA QUERIES
-- =============================================================================

-- Document processing summary view
CREATE VIEW document_processing_summary AS
SELECT 
    dm.id,
    dm.document_name,
    dm.document_type,
    dm.file_size_bytes,
    dm.pii_detected,
    dm.pii_item_count,
    ps.status as processing_status,
    ps.progress_percentage,
    ps.started_at as processing_started,
    ps.completed_at as processing_completed,
    ps.processing_time_seconds,
    cp.name as policy_name
FROM document_metadata dm
LEFT JOIN session_documents sd ON dm.id = sd.document_id
LEFT JOIN processing_sessions ps ON sd.session_id = ps.id
LEFT JOIN compliance_policies cp ON ps.policy_id = cp.id
WHERE ps.id IS NOT NULL OR dm.uploaded_at >= CURRENT_DATE - INTERVAL '30 days';

-- Processing performance metrics view
CREATE VIEW processing_performance_metrics AS
SELECT 
    DATE_TRUNC('day', ps.started_at) as processing_date,
    ps.policy_id,
    cp.name as policy_name,
    COUNT(*) as sessions_count,
    AVG(ps.processing_time_seconds) as avg_processing_time,
    SUM(ps.document_count) as total_documents,
    SUM(ps.documents_successful) as successful_documents,
    SUM(ps.documents_failed) as failed_documents,
    AVG(ps.overall_quality_score) as avg_quality_score,
    SUM(ps.total_pii_detected) as total_pii_detected,
    SUM(ps.total_pii_redacted) as total_pii_redacted
FROM processing_sessions ps
JOIN compliance_policies cp ON ps.policy_id = cp.id
WHERE ps.started_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY DATE_TRUNC('day', ps.started_at), ps.policy_id, cp.name
ORDER BY processing_date DESC;

-- Comments for documentation
COMMENT ON TABLE document_metadata IS 'Comprehensive metadata for all documents including PII analysis';
COMMENT ON TABLE processing_sessions IS 'Processing workflow sessions with metrics and status tracking';
COMMENT ON TABLE session_documents IS 'Many-to-many relationship between sessions and documents';
COMMENT ON TABLE file_storage IS 'File storage management with lifecycle and security metadata';
COMMENT ON TABLE file_access_logs IS 'Detailed access logging for all file operations';
COMMENT ON TABLE redaction_metadata IS 'Detailed metadata for each redaction operation performed';
COMMENT ON TABLE processing_stage_logs IS 'Performance and status logs for each processing stage';
COMMENT ON TABLE batch_processing_jobs IS 'Batch and scheduled processing job definitions';
COMMENT ON TABLE batch_job_runs IS 'Execution history and metrics for batch processing jobs';