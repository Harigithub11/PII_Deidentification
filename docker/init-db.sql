-- Database initialization script for PII De-identification System
-- This script creates the necessary databases and extensions

-- Create the main application database (already created by POSTGRES_DB)
-- But ensure it exists and has proper settings
SELECT 'CREATE DATABASE pii_system' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'pii_system')\gexec

-- Create Airflow database
CREATE DATABASE airflow;

-- Switch to pii_system database for extensions
\c pii_system;

-- Enable necessary PostgreSQL extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- Create database schema for versioning
CREATE SCHEMA IF NOT EXISTS pii_system;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS monitoring;

-- Grant privileges to pii_user
GRANT ALL PRIVILEGES ON DATABASE pii_system TO pii_user;
GRANT ALL PRIVILEGES ON DATABASE airflow TO pii_user;
GRANT ALL PRIVILEGES ON SCHEMA pii_system TO pii_user;
GRANT ALL PRIVILEGES ON SCHEMA audit TO pii_user;
GRANT ALL PRIVILEGES ON SCHEMA monitoring TO pii_user;

-- Switch to airflow database for extensions
\c airflow;

-- Enable necessary PostgreSQL extensions for Airflow
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Grant privileges for airflow database
GRANT ALL PRIVILEGES ON DATABASE airflow TO pii_user;

-- Create initial application tables (basic structure)
\c pii_system;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    hashed_password VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    is_superuser BOOLEAN DEFAULT false,
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE
);

-- Documents table
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_size BIGINT,
    file_type VARCHAR(50),
    content_hash VARCHAR(64),
    status VARCHAR(50) DEFAULT 'uploaded',
    processing_started_at TIMESTAMP WITH TIME ZONE,
    processing_completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Processing Jobs table
CREATE TABLE IF NOT EXISTS processing_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID REFERENCES documents(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    job_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    priority INTEGER DEFAULT 0,
    parameters JSONB,
    result JSONB,
    error_message TEXT,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- PII Detection Results table
CREATE TABLE IF NOT EXISTS pii_detection_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID REFERENCES documents(id) ON DELETE CASCADE,
    job_id UUID REFERENCES processing_jobs(id) ON DELETE CASCADE,
    pii_type VARCHAR(100) NOT NULL,
    confidence_score DECIMAL(5,4),
    location_data JSONB,
    original_text TEXT,
    redacted_text TEXT,
    method_used VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Audit Log table (in audit schema)
CREATE TABLE IF NOT EXISTS audit.audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- System Metrics table (in monitoring schema)
CREATE TABLE IF NOT EXISTS monitoring.system_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(15,4),
    tags JSONB,
    collected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Component Health table (in monitoring schema)
CREATE TABLE IF NOT EXISTS monitoring.component_health (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    component_name VARCHAR(100) NOT NULL,
    component_type VARCHAR(50),
    status VARCHAR(20) NOT NULL,
    health_score DECIMAL(3,2),
    last_check_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    details JSONB,
    error_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);
CREATE INDEX IF NOT EXISTS idx_processing_jobs_document_id ON processing_jobs(document_id);
CREATE INDEX IF NOT EXISTS idx_processing_jobs_status ON processing_jobs(status);
CREATE INDEX IF NOT EXISTS idx_pii_results_document_id ON pii_detection_results(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit.audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit.audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_metrics_name_collected ON monitoring.system_metrics(metric_name, collected_at);
CREATE INDEX IF NOT EXISTS idx_component_health_name ON monitoring.component_health(component_name);

-- Insert default admin user (password: admin123)
-- Note: This should be changed in production
INSERT INTO users (id, username, email, full_name, hashed_password, is_active, is_superuser, role)
VALUES (
    uuid_generate_v4(),
    'admin',
    'admin@example.com',
    'System Administrator',
    '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', -- admin123
    true,
    true,
    'admin'
) ON CONFLICT (username) DO NOTHING;

-- Insert default regular user (password: user123)
INSERT INTO users (id, username, email, full_name, hashed_password, is_active, is_superuser, role)
VALUES (
    uuid_generate_v4(),
    'user',
    'user@example.com',
    'Regular User',
    '$2b$12$4C4s6K4s6K4s6K4s6K4s6O9p36WQoeG6Lruj3vjPGga31lW', -- user123
    true,
    false,
    'user'
) ON CONFLICT (username) DO NOTHING;

-- Create trigger function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at columns
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    
CREATE TRIGGER update_documents_updated_at BEFORE UPDATE ON documents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    
CREATE TRIGGER update_processing_jobs_updated_at BEFORE UPDATE ON processing_jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions on all tables to pii_user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO pii_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA audit TO pii_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA monitoring TO pii_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO pii_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA audit TO pii_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA monitoring TO pii_user;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO pii_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT ALL PRIVILEGES ON TABLES TO pii_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA monitoring GRANT ALL PRIVILEGES ON TABLES TO pii_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO pii_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT ALL PRIVILEGES ON SEQUENCES TO pii_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA monitoring GRANT ALL PRIVILEGES ON SEQUENCES TO pii_user;

-- Log initialization completion
INSERT INTO audit.audit_log (user_id, action, resource_type, details)
VALUES (
    NULL,
    'database_initialized',
    'system',
    '{"message": "Database initialization completed", "timestamp": "' || CURRENT_TIMESTAMP || '"}'::jsonb
);