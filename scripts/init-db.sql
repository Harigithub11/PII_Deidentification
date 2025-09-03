-- AI De-identification System Database Schema
-- Phase 1: MVP Core Infrastructure

-- Create necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Documents table - stores uploaded document metadata
CREATE TABLE documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    original_filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    upload_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) NOT NULL DEFAULT 'uploaded',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Processing jobs table - tracks document processing workflow
CREATE TABLE processing_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    job_type VARCHAR(50) NOT NULL, -- 'ocr', 'pii_detection', 'redaction'
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed'
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    result_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- PII detections table - stores identified PII instances
CREATE TABLE pii_detections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    detection_type VARCHAR(100) NOT NULL, -- 'PERSON', 'EMAIL', 'PHONE', etc.
    detected_text TEXT NOT NULL,
    confidence_score DECIMAL(3,2) NOT NULL,
    start_position INTEGER NOT NULL,
    end_position INTEGER NOT NULL,
    page_number INTEGER,
    bounding_box JSONB, -- For visual PII detection (Phase 3)
    redaction_applied BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Audit trail table - comprehensive logging for compliance
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID REFERENCES documents(id) ON DELETE CASCADE,
    action VARCHAR(100) NOT NULL, -- 'upload', 'process', 'redact', 'download'
    user_id VARCHAR(100), -- For future user management
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Redacted documents table - stores processed document information
CREATE TABLE redacted_documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    original_document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    redacted_file_path VARCHAR(500) NOT NULL,
    redaction_method VARCHAR(50) NOT NULL, -- 'mask', 'replace', 'delete'
    total_redactions INTEGER NOT NULL DEFAULT 0,
    redaction_summary JSONB, -- Summary of what was redacted
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Configuration policies table - stores PII detection and redaction policies
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    pii_types JSONB NOT NULL, -- Array of PII types to detect
    confidence_threshold DECIMAL(3,2) NOT NULL DEFAULT 0.8,
    redaction_method VARCHAR(50) NOT NULL DEFAULT 'mask',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Performance metrics table - for monitoring and optimization
CREATE TABLE performance_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID REFERENCES documents(id) ON DELETE CASCADE,
    processing_stage VARCHAR(50) NOT NULL,
    duration_ms INTEGER NOT NULL,
    memory_usage_mb INTEGER,
    cpu_usage_percent DECIMAL(5,2),
    success BOOLEAN NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for optimal query performance
CREATE INDEX idx_documents_status ON documents(status);
CREATE INDEX idx_documents_created_at ON documents(created_at);
CREATE INDEX idx_processing_jobs_document_id ON processing_jobs(document_id);
CREATE INDEX idx_processing_jobs_status ON processing_jobs(status);
CREATE INDEX idx_pii_detections_document_id ON pii_detections(document_id);
CREATE INDEX idx_pii_detections_type ON pii_detections(detection_type);
CREATE INDEX idx_audit_logs_document_id ON audit_logs(document_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_redacted_documents_original ON redacted_documents(original_document_id);

-- Update triggers for updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_documents_updated_at BEFORE UPDATE ON documents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_processing_jobs_updated_at BEFORE UPDATE ON processing_jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_policies_updated_at BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default policy configurations
INSERT INTO policies (policy_name, description, pii_types, confidence_threshold, redaction_method) VALUES
('HIPAA_Compliant', 'Standard HIPAA compliance policy for healthcare data', 
 '["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "SSN", "DATE_TIME", "LOCATION", "MEDICAL_LICENSE"]'::jsonb, 
 0.85, 'mask'),
('GDPR_Compliant', 'GDPR compliance policy for European data protection', 
 '["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "IBAN_CODE", "CREDIT_CARD", "DATE_TIME", "LOCATION", "IP_ADDRESS"]'::jsonb, 
 0.80, 'mask'),
('PCI_DSS', 'PCI DSS compliance for payment card data', 
 '["CREDIT_CARD", "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"]'::jsonb, 
 0.90, 'replace');

-- Grant necessary permissions (if using specific application user)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO deidentify_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO deidentify_user;