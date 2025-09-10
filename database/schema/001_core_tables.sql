-- Core Tables SQL Schema for PII De-identification System
-- PostgreSQL Database Schema for audit logs, metadata, and policies
-- Version: 1.0.0

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- =============================================================================
-- ENUMS AND TYPES
-- =============================================================================

-- User roles
CREATE TYPE user_role AS ENUM (
    'admin',
    'user',
    'auditor',
    'data_processor',
    'compliance_officer'
);

-- Authentication types
CREATE TYPE auth_type AS ENUM (
    'password',
    'api_key',
    'oauth2',
    'ldap'
);

-- Session status
CREATE TYPE session_status AS ENUM (
    'active',
    'expired',
    'terminated',
    'suspended'
);

-- PII types (matches the Python enum)
CREATE TYPE pii_type AS ENUM (
    'name',
    'address',
    'phone',
    'email',
    'date_of_birth',
    'age',
    'gender',
    'ssn',
    'passport',
    'driver_license',
    'national_id',
    'aadhar',
    'pan',
    'credit_card',
    'bank_account',
    'routing_number',
    'iban',
    'income',
    'medical_record',
    'medical_license',
    'diagnosis',
    'medication',
    'treatment',
    'ip_address',
    'url',
    'crypto_address',
    'organization',
    'financial',
    'number',
    'location',
    'signature',
    'photo'
);

-- Redaction methods (matches the Python enum)
CREATE TYPE redaction_method AS ENUM (
    'blackout',
    'whiteout',
    'blur',
    'pixelate',
    'pseudonymize',
    'generalize',
    'delete'
);

-- =============================================================================
-- CORE USER MANAGEMENT TABLES
-- =============================================================================

-- Users table with encrypted PII
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email TEXT NOT NULL, -- Will be encrypted at application level
    full_name TEXT, -- Will be encrypted at application level
    password_hash TEXT NOT NULL,
    role user_role NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_verified BOOLEAN NOT NULL DEFAULT false,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    last_login TIMESTAMP WITH TIME ZONE,
    password_changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    two_factor_enabled BOOLEAN NOT NULL DEFAULT false,
    two_factor_secret TEXT, -- Encrypted at application level
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Audit fields
    version INTEGER NOT NULL DEFAULT 1,
    
    CONSTRAINT users_username_length CHECK (length(username) >= 3),
    CONSTRAINT users_password_changed_recent CHECK (password_changed_at <= CURRENT_TIMESTAMP)
);

-- User sessions for tracking active sessions
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token TEXT NOT NULL UNIQUE,
    refresh_token TEXT UNIQUE,
    ip_address INET,
    user_agent TEXT,
    status session_status NOT NULL DEFAULT 'active',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_accessed TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    terminated_at TIMESTAMP WITH TIME ZONE,
    terminated_by UUID REFERENCES users(id),
    termination_reason TEXT,
    
    -- Security metadata
    location_country VARCHAR(2),
    location_city VARCHAR(100),
    device_fingerprint TEXT,
    
    CONSTRAINT user_sessions_expires_future CHECK (expires_at > created_at)
);

-- API keys for programmatic access
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_name VARCHAR(100) NOT NULL,
    key_hash TEXT NOT NULL UNIQUE, -- Hash of the actual key
    key_prefix VARCHAR(10) NOT NULL, -- First few chars for identification
    scopes TEXT[] NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used TIMESTAMP WITH TIME ZONE,
    usage_count BIGINT NOT NULL DEFAULT 0,
    rate_limit_per_hour INTEGER DEFAULT 1000,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES users(id),
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID REFERENCES users(id),
    revocation_reason TEXT,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    UNIQUE(user_id, key_name)
);

-- =============================================================================
-- LOOKUP TABLES
-- =============================================================================

-- PII type definitions (master data)
CREATE TABLE pii_type_definitions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pii_type pii_type NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    sensitivity_level INTEGER NOT NULL DEFAULT 5 CHECK (sensitivity_level BETWEEN 1 AND 10),
    regex_pattern TEXT,
    validation_rules JSONB DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Redaction method definitions
CREATE TABLE redaction_method_definitions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    redaction_method redaction_method NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    configuration_schema JSONB DEFAULT '{}',
    is_reversible BOOLEAN NOT NULL DEFAULT false,
    security_level INTEGER NOT NULL DEFAULT 5 CHECK (security_level BETWEEN 1 AND 10),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Compliance standards lookup
CREATE TABLE compliance_standards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(20) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    jurisdiction VARCHAR(100),
    version VARCHAR(20),
    effective_date DATE,
    website_url TEXT,
    documentation_url TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- CONFIGURATION TABLES
-- =============================================================================

-- Data retention schedules
CREATE TABLE data_retention_schedules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    retention_period_days INTEGER NOT NULL CHECK (retention_period_days > 0),
    auto_deletion_enabled BOOLEAN NOT NULL DEFAULT false,
    compliance_standard_id UUID REFERENCES compliance_standards(id),
    applies_to_pii_types pii_type[] DEFAULT '{}',
    deletion_method redaction_method NOT NULL DEFAULT 'delete',
    grace_period_days INTEGER DEFAULT 0 CHECK (grace_period_days >= 0),
    notification_days_before INTEGER[] DEFAULT '{30, 7, 1}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id)
);

-- System configuration
CREATE TABLE system_configuration (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT,
    config_type VARCHAR(20) NOT NULL DEFAULT 'string' CHECK (config_type IN ('string', 'integer', 'boolean', 'json', 'encrypted')),
    description TEXT,
    is_encrypted BOOLEAN NOT NULL DEFAULT false,
    is_system_config BOOLEAN NOT NULL DEFAULT false,
    validation_regex TEXT,
    min_value NUMERIC,
    max_value NUMERIC,
    allowed_values TEXT[],
    requires_restart BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID REFERENCES users(id)
);

-- =============================================================================
-- TRIGGERS FOR AUTOMATIC TIMESTAMP UPDATES
-- =============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply update trigger to all tables with updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_pii_type_definitions_updated_at BEFORE UPDATE ON pii_type_definitions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_redaction_method_definitions_updated_at BEFORE UPDATE ON redaction_method_definitions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_compliance_standards_updated_at BEFORE UPDATE ON compliance_standards
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_data_retention_schedules_updated_at BEFORE UPDATE ON data_retention_schedules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_system_configuration_updated_at BEFORE UPDATE ON system_configuration
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- INITIAL DATA INSERTS
-- =============================================================================

-- Insert default compliance standards
INSERT INTO compliance_standards (code, name, description, jurisdiction, version, effective_date) VALUES
('GDPR', 'General Data Protection Regulation', 'EU regulation on data protection and privacy', 'European Union', '2018', '2018-05-25'),
('HIPAA', 'Health Insurance Portability and Accountability Act', 'US healthcare data protection regulation', 'United States', '1996', '1996-08-21'),
('NDHM', 'National Digital Health Mission', 'India health data protection guidelines', 'India', '2020', '2020-08-15'),
('CCPA', 'California Consumer Privacy Act', 'California state privacy regulation', 'California, USA', '2018', '2020-01-01'),
('PIPEDA', 'Personal Information Protection and Electronic Documents Act', 'Canadian federal privacy law', 'Canada', '2000', '2001-01-01');

-- Insert default PII type definitions
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

-- Insert default redaction methods
INSERT INTO redaction_method_definitions (redaction_method, display_name, description, is_reversible, security_level) VALUES
('blackout', 'Blackout', 'Replace with black rectangles', false, 8),
('whiteout', 'Whiteout', 'Replace with white rectangles', false, 8),
('blur', 'Blur', 'Apply blur effect to sensitive areas', false, 6),
('pixelate', 'Pixelate', 'Apply pixelation effect', false, 7),
('pseudonymize', 'Pseudonymize', 'Replace with consistent pseudonyms', true, 9),
('generalize', 'Generalize', 'Replace with generalized categories', false, 5),
('delete', 'Delete', 'Completely remove the data', false, 10);

-- Insert default retention schedule
INSERT INTO data_retention_schedules (name, description, retention_period_days, compliance_standard_id) VALUES
('Standard 7-Year Retention', 'Standard business record retention for 7 years', 2555, 
    (SELECT id FROM compliance_standards WHERE code = 'HIPAA')),
('GDPR 3-Year Retention', 'GDPR compliant 3-year retention period', 1095, 
    (SELECT id FROM compliance_standards WHERE code = 'GDPR')),
('Short-Term 30-Day Retention', 'Short-term retention for temporary data', 30, NULL);

-- Comments for documentation
COMMENT ON TABLE users IS 'User accounts with encrypted PII fields and comprehensive audit trail';
COMMENT ON TABLE user_sessions IS 'Active user sessions with security metadata and tracking';
COMMENT ON TABLE api_keys IS 'API keys for programmatic access with usage tracking and rate limiting';
COMMENT ON TABLE pii_type_definitions IS 'Master definitions of PII types with validation rules';
COMMENT ON TABLE redaction_method_definitions IS 'Available redaction methods with security levels';
COMMENT ON TABLE compliance_standards IS 'Supported compliance frameworks and regulations';
COMMENT ON TABLE data_retention_schedules IS 'Data retention policies linked to compliance standards';
COMMENT ON TABLE system_configuration IS 'System-wide configuration parameters with validation';