-- Policy Management Tables SQL Schema for PII De-identification System
-- Tables for managing compliance policies, rules, and their application
-- Version: 1.0.0

-- =============================================================================
-- POLICY ENUMS AND TYPES
-- =============================================================================

-- Policy status
CREATE TYPE policy_status AS ENUM (
    'draft',
    'pending_approval',
    'active',
    'deprecated',
    'suspended',
    'archived'
);

-- Policy change types
CREATE TYPE policy_change_type AS ENUM (
    'created',
    'updated',
    'activated',
    'deprecated',
    'suspended',
    'archived',
    'rule_added',
    'rule_removed',
    'rule_modified',
    'settings_changed'
);

-- Policy application status
CREATE TYPE policy_application_status AS ENUM (
    'pending',
    'in_progress',
    'completed',
    'failed',
    'partial',
    'skipped'
);

-- Validation result
CREATE TYPE validation_result AS ENUM (
    'valid',
    'warning',
    'error',
    'not_applicable'
);

-- =============================================================================
-- COMPLIANCE POLICY TABLES
-- =============================================================================

-- Main compliance policies table
CREATE TABLE compliance_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    version VARCHAR(20) NOT NULL DEFAULT '1.0.0',
    
    -- Policy identification
    policy_code VARCHAR(50) NOT NULL, -- Unique code like 'GDPR-2024-001'
    compliance_standard_id UUID NOT NULL REFERENCES compliance_standards(id),
    
    -- Policy metadata
    effective_date DATE NOT NULL,
    expiration_date DATE,
    status policy_status NOT NULL DEFAULT 'draft',
    priority INTEGER NOT NULL DEFAULT 5 CHECK (priority BETWEEN 1 AND 10),
    
    -- Policy configuration
    strict_mode BOOLEAN NOT NULL DEFAULT false,
    enable_audit_logging BOOLEAN NOT NULL DEFAULT true,
    require_approval BOOLEAN NOT NULL DEFAULT false,
    allow_pseudonymization BOOLEAN NOT NULL DEFAULT true,
    allow_generalization BOOLEAN NOT NULL DEFAULT true,
    default_redaction_method redaction_method NOT NULL DEFAULT 'blackout',
    max_retention_days INTEGER CHECK (max_retention_days > 0),
    
    -- Validation settings
    validation_required BOOLEAN NOT NULL DEFAULT true,
    auto_apply BOOLEAN NOT NULL DEFAULT false,
    
    -- Approval workflow
    requires_approval_from user_role[] DEFAULT '{}',
    approved_by UUID REFERENCES users(id),
    approved_at TIMESTAMP WITH TIME ZONE,
    approval_notes TEXT,
    
    -- Policy hierarchy
    parent_policy_id UUID REFERENCES compliance_policies(id),
    policy_order INTEGER DEFAULT 0,
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',
    tags VARCHAR(50)[] DEFAULT '{}',
    
    UNIQUE(policy_code, version),
    CONSTRAINT compliance_policies_effective_expiration CHECK (
        expiration_date IS NULL OR expiration_date > effective_date
    ),
    CONSTRAINT compliance_policies_approval_required CHECK (
        status != 'active' OR approved_by IS NOT NULL
    )
);

-- Policy rules (detailed rules within each policy)
CREATE TABLE policy_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID NOT NULL REFERENCES compliance_policies(id) ON DELETE CASCADE,
    
    -- Rule identification
    rule_name VARCHAR(100) NOT NULL,
    rule_description TEXT,
    rule_order INTEGER NOT NULL DEFAULT 0,
    
    -- PII handling rule
    pii_type pii_type NOT NULL,
    redaction_method redaction_method NOT NULL,
    confidence_threshold DECIMAL(3,2) NOT NULL DEFAULT 0.80 CHECK (confidence_threshold BETWEEN 0 AND 1),
    
    -- Retention settings
    retention_period_days INTEGER CHECK (retention_period_days >= 0),
    auto_delete_enabled BOOLEAN NOT NULL DEFAULT false,
    
    -- Rule conditions and exceptions
    conditions JSONB DEFAULT '{}', -- Conditions when this rule applies
    exceptions TEXT[] DEFAULT '{}', -- List of exceptions
    context_requirements JSONB DEFAULT '{}', -- Required context for rule application
    
    -- Rule metadata
    legal_basis VARCHAR(100), -- Legal basis for this rule (GDPR compliance)
    regulation_reference TEXT, -- Reference to specific regulation section
    business_justification TEXT,
    
    -- Rule status
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_mandatory BOOLEAN NOT NULL DEFAULT true,
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',
    
    UNIQUE(policy_id, pii_type),
    UNIQUE(policy_id, rule_name)
);

-- Policy versions and change history
CREATE TABLE policy_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID NOT NULL REFERENCES compliance_policies(id) ON DELETE CASCADE,
    
    -- Version information
    version_number VARCHAR(20) NOT NULL,
    previous_version_id UUID REFERENCES policy_versions(id),
    change_type policy_change_type NOT NULL,
    
    -- Change details
    change_summary VARCHAR(500) NOT NULL,
    change_description TEXT,
    changed_fields TEXT[], -- List of fields that changed
    
    -- Change context
    change_reason TEXT,
    regulatory_requirement TEXT,
    impact_assessment TEXT,
    
    -- Approval and validation
    change_approved_by UUID REFERENCES users(id),
    change_approved_at TIMESTAMP WITH TIME ZONE,
    validation_status validation_result DEFAULT 'pending',
    validation_notes TEXT,
    
    -- Timing
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL REFERENCES users(id),
    effective_from TIMESTAMP WITH TIME ZONE,
    
    -- Snapshot of policy state at this version
    policy_snapshot JSONB NOT NULL, -- Complete policy configuration
    rules_snapshot JSONB NOT NULL, -- All rules at this version
    
    UNIQUE(policy_id, version_number)
);

-- =============================================================================
-- POLICY APPLICATION AND TRACKING
-- =============================================================================

-- Policy applications to documents/processes
CREATE TABLE policy_applications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID NOT NULL REFERENCES compliance_policies(id),
    policy_version_id UUID REFERENCES policy_versions(id),
    
    -- Target information
    target_type VARCHAR(50) NOT NULL, -- 'document', 'batch', 'user_data', etc.
    target_id UUID NOT NULL,
    target_name VARCHAR(255),
    
    -- Application details
    application_status policy_application_status NOT NULL DEFAULT 'pending',
    applied_by UUID REFERENCES users(id),
    applied_via VARCHAR(50) DEFAULT 'automatic', -- 'automatic', 'manual', 'batch'
    
    -- Processing information
    rules_applied INTEGER DEFAULT 0,
    rules_failed INTEGER DEFAULT 0,
    pii_items_processed INTEGER DEFAULT 0,
    pii_items_redacted INTEGER DEFAULT 0,
    
    -- Validation results
    validation_status validation_result DEFAULT 'pending',
    validation_errors TEXT[],
    validation_warnings TEXT[],
    compliance_score INTEGER CHECK (compliance_score BETWEEN 0 AND 100),
    
    -- Timing information
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,
    
    -- Results and output
    processing_summary TEXT,
    output_location TEXT, -- Where processed document/data is stored
    backup_location TEXT, -- Where original is backed up
    
    -- Error handling
    error_message TEXT,
    error_details JSONB,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    
    -- Audit and compliance
    audit_trail_id UUID, -- Reference to detailed audit log
    compliance_notes TEXT,
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',
    
    CONSTRAINT policy_applications_completion_check CHECK (
        completed_at IS NULL OR completed_at >= started_at
    ),
    CONSTRAINT policy_applications_rules_check CHECK (
        rules_applied >= 0 AND rules_failed >= 0
    )
);

-- Policy rule execution details
CREATE TABLE policy_rule_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_application_id UUID NOT NULL REFERENCES policy_applications(id) ON DELETE CASCADE,
    policy_rule_id UUID NOT NULL REFERENCES policy_rules(id),
    
    -- Execution details
    execution_order INTEGER NOT NULL,
    execution_status policy_application_status NOT NULL DEFAULT 'pending',
    
    -- Input data
    input_data_type VARCHAR(50), -- 'text', 'image', 'structured', etc.
    input_data_size_bytes BIGINT,
    detected_pii_count INTEGER DEFAULT 0,
    
    -- PII detection results
    pii_detections JSONB DEFAULT '[]', -- Array of detected PII items
    confidence_scores DECIMAL(3,2)[], -- Confidence scores for each detection
    
    -- Redaction results
    redaction_method_used redaction_method,
    redacted_items_count INTEGER DEFAULT 0,
    redaction_success_rate DECIMAL(5,2), -- Percentage of successful redactions
    
    -- Output data
    output_data_size_bytes BIGINT,
    output_location TEXT,
    
    -- Performance metrics
    processing_time_ms INTEGER,
    memory_usage_mb INTEGER,
    
    -- Error handling
    error_occurred BOOLEAN NOT NULL DEFAULT false,
    error_message TEXT,
    error_details JSONB,
    
    -- Timing
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',
    
    UNIQUE(policy_application_id, policy_rule_id)
);

-- =============================================================================
-- POLICY COMPLIANCE AND MONITORING
-- =============================================================================

-- Policy compliance reports
CREATE TABLE policy_compliance_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Report metadata
    report_name VARCHAR(100) NOT NULL,
    report_type VARCHAR(50) NOT NULL, -- 'daily', 'weekly', 'monthly', 'audit', 'custom'
    report_period_start DATE NOT NULL,
    report_period_end DATE NOT NULL,
    
    -- Scope
    policies_included UUID[] NOT NULL, -- Array of policy IDs
    compliance_standards VARCHAR(20)[] DEFAULT '{}',
    target_types VARCHAR(50)[] DEFAULT '{}', -- Types of targets covered
    
    -- Compliance metrics
    total_applications INTEGER NOT NULL DEFAULT 0,
    successful_applications INTEGER NOT NULL DEFAULT 0,
    failed_applications INTEGER NOT NULL DEFAULT 0,
    compliance_rate DECIMAL(5,2), -- Success rate percentage
    
    -- PII processing metrics
    total_pii_items_processed BIGINT NOT NULL DEFAULT 0,
    total_pii_items_redacted BIGINT NOT NULL DEFAULT 0,
    pii_redaction_rate DECIMAL(5,2),
    
    -- Performance metrics
    average_processing_time_seconds DECIMAL(10,2),
    total_processing_time_hours DECIMAL(10,2),
    peak_processing_time_seconds INTEGER,
    
    -- Issues and violations
    policy_violations INTEGER NOT NULL DEFAULT 0,
    critical_issues INTEGER NOT NULL DEFAULT 0,
    warnings_issued INTEGER NOT NULL DEFAULT 0,
    
    -- Report generation
    generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    generated_by UUID NOT NULL REFERENCES users(id),
    report_status VARCHAR(20) NOT NULL DEFAULT 'completed',
    
    -- Report data
    detailed_results JSONB NOT NULL, -- Detailed compliance data
    summary_statistics JSONB DEFAULT '{}',
    recommendations TEXT[],
    
    -- Report distribution
    recipients TEXT[], -- Email addresses or user IDs
    sent_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT policy_compliance_reports_period CHECK (report_period_end >= report_period_start),
    CONSTRAINT policy_compliance_reports_rates CHECK (
        compliance_rate IS NULL OR (compliance_rate >= 0 AND compliance_rate <= 100)
    )
);

-- Policy effectiveness metrics
CREATE TABLE policy_effectiveness_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID NOT NULL REFERENCES compliance_policies(id),
    
    -- Measurement period
    measurement_date DATE NOT NULL,
    measurement_period_days INTEGER NOT NULL DEFAULT 1,
    
    -- Application metrics
    total_applications INTEGER NOT NULL DEFAULT 0,
    successful_applications INTEGER NOT NULL DEFAULT 0,
    failed_applications INTEGER NOT NULL DEFAULT 0,
    average_processing_time_seconds DECIMAL(10,2),
    
    -- Detection effectiveness
    true_positives INTEGER NOT NULL DEFAULT 0,
    false_positives INTEGER NOT NULL DEFAULT 0,
    true_negatives INTEGER NOT NULL DEFAULT 0,
    false_negatives INTEGER NOT NULL DEFAULT 0,
    precision_score DECIMAL(5,4), -- TP / (TP + FP)
    recall_score DECIMAL(5,4), -- TP / (TP + FN)
    f1_score DECIMAL(5,4), -- 2 * (precision * recall) / (precision + recall)
    
    -- Compliance metrics
    compliance_violations INTEGER NOT NULL DEFAULT 0,
    data_breach_incidents INTEGER NOT NULL DEFAULT 0,
    regulatory_findings INTEGER NOT NULL DEFAULT 0,
    
    -- User satisfaction
    user_feedback_score DECIMAL(3,2), -- 1-5 scale
    user_complaints INTEGER NOT NULL DEFAULT 0,
    training_requests INTEGER NOT NULL DEFAULT 0,
    
    -- Cost and efficiency
    processing_cost_estimate DECIMAL(10,2),
    manual_review_hours DECIMAL(8,2),
    automation_rate DECIMAL(5,2), -- Percentage of automated processing
    
    -- Improvement tracking
    improvement_suggestions TEXT[],
    configuration_changes_needed BOOLEAN NOT NULL DEFAULT false,
    
    -- Metadata
    collected_by UUID REFERENCES users(id),
    collection_method VARCHAR(50), -- 'automatic', 'manual', 'survey'
    data_quality_score INTEGER CHECK (data_quality_score BETWEEN 1 AND 10),
    
    -- Additional context
    metadata JSONB DEFAULT '{}',
    
    UNIQUE(policy_id, measurement_date)
);

-- =============================================================================
-- POLICY APPROVAL WORKFLOW
-- =============================================================================

-- Policy approval requests and workflow
CREATE TABLE policy_approval_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID NOT NULL REFERENCES compliance_policies(id),
    policy_version_id UUID REFERENCES policy_versions(id),
    
    -- Request details
    request_type VARCHAR(50) NOT NULL, -- 'new_policy', 'policy_update', 'rule_change', etc.
    request_summary VARCHAR(500) NOT NULL,
    request_description TEXT,
    business_justification TEXT,
    regulatory_requirement TEXT,
    
    -- Approval workflow
    requested_by UUID NOT NULL REFERENCES users(id),
    assigned_to UUID REFERENCES users(id),
    approval_required_from user_role[] NOT NULL,
    current_approver_role user_role,
    
    -- Request status
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'in_review', 'approved', 'rejected', 'withdrawn'
    priority INTEGER NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 5),
    
    -- Impact assessment
    impact_level VARCHAR(20) NOT NULL DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    affected_systems TEXT[],
    affected_users_count INTEGER,
    implementation_effort_hours INTEGER,
    risk_assessment TEXT,
    
    -- Timing
    requested_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    due_date TIMESTAMP WITH TIME ZONE,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    approved_at TIMESTAMP WITH TIME ZONE,
    implemented_at TIMESTAMP WITH TIME ZONE,
    
    -- Decision details
    final_decision VARCHAR(20), -- 'approved', 'rejected', 'withdrawn'
    decision_rationale TEXT,
    conditions TEXT[], -- Conditions attached to approval
    
    -- Follow-up
    review_required_after_days INTEGER,
    monitoring_required BOOLEAN NOT NULL DEFAULT false,
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',
    
    CONSTRAINT policy_approval_requests_timing CHECK (
        reviewed_at IS NULL OR reviewed_at >= requested_at
    )
);

-- Approval workflow steps and history
CREATE TABLE policy_approval_steps (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    approval_request_id UUID NOT NULL REFERENCES policy_approval_requests(id) ON DELETE CASCADE,
    
    -- Step details
    step_order INTEGER NOT NULL,
    step_name VARCHAR(100) NOT NULL,
    step_description TEXT,
    required_role user_role NOT NULL,
    
    -- Assignee
    assigned_to UUID REFERENCES users(id),
    assigned_at TIMESTAMP WITH TIME ZONE,
    
    -- Step status
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'in_progress', 'completed', 'skipped'
    completed_by UUID REFERENCES users(id),
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Decision
    decision VARCHAR(20), -- 'approve', 'reject', 'request_changes', 'delegate'
    comments TEXT,
    conditions TEXT[],
    
    -- Timing constraints
    due_date TIMESTAMP WITH TIME ZONE,
    estimated_hours INTEGER,
    actual_hours DECIMAL(4,2),
    
    -- Escalation
    escalated BOOLEAN NOT NULL DEFAULT false,
    escalated_to UUID REFERENCES users(id),
    escalated_at TIMESTAMP WITH TIME ZONE,
    escalation_reason TEXT,
    
    UNIQUE(approval_request_id, step_order)
);

-- =============================================================================
-- TRIGGERS AND FUNCTIONS
-- =============================================================================

-- Function to update policy updated_at timestamp
CREATE TRIGGER update_compliance_policies_updated_at 
    BEFORE UPDATE ON compliance_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_policy_rules_updated_at 
    BEFORE UPDATE ON policy_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to create policy version on policy changes
CREATE OR REPLACE FUNCTION create_policy_version()
RETURNS TRIGGER AS $$
BEGIN
    -- Only create version if this is an update (not insert)
    IF TG_OP = 'UPDATE' THEN
        INSERT INTO policy_versions (
            policy_id,
            version_number,
            change_type,
            change_summary,
            created_by,
            policy_snapshot,
            rules_snapshot
        ) VALUES (
            NEW.id,
            NEW.version,
            'updated',
            'Policy updated',
            NEW.updated_by,
            to_jsonb(NEW),
            (SELECT jsonb_agg(to_jsonb(pr)) FROM policy_rules pr WHERE pr.policy_id = NEW.id)
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically create policy versions
CREATE TRIGGER compliance_policies_version_trigger
    AFTER UPDATE ON compliance_policies
    FOR EACH ROW
    WHEN (OLD.version IS DISTINCT FROM NEW.version)
    EXECUTE FUNCTION create_policy_version();

-- =============================================================================
-- USEFUL VIEWS FOR POLICY MANAGEMENT
-- =============================================================================

-- Active policies view
CREATE VIEW active_policies AS
SELECT 
    cp.*,
    cs.name as compliance_standard_name,
    COUNT(pr.id) as rule_count,
    COUNT(CASE WHEN pr.is_active THEN 1 END) as active_rule_count
FROM compliance_policies cp
JOIN compliance_standards cs ON cp.compliance_standard_id = cs.id
LEFT JOIN policy_rules pr ON cp.id = pr.policy_id
WHERE cp.status = 'active'
    AND cp.effective_date <= CURRENT_DATE
    AND (cp.expiration_date IS NULL OR cp.expiration_date > CURRENT_DATE)
GROUP BY cp.id, cs.name;

-- Policy application summary view
CREATE VIEW policy_application_summary AS
SELECT 
    cp.name as policy_name,
    cp.version,
    DATE_TRUNC('day', pa.started_at) as application_date,
    pa.application_status,
    COUNT(*) as application_count,
    AVG(pa.compliance_score) as avg_compliance_score,
    SUM(pa.pii_items_processed) as total_pii_processed,
    SUM(pa.pii_items_redacted) as total_pii_redacted
FROM policy_applications pa
JOIN compliance_policies cp ON pa.policy_id = cp.id
WHERE pa.started_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY cp.name, cp.version, DATE_TRUNC('day', pa.started_at), pa.application_status
ORDER BY application_date DESC;

-- Comments for documentation
COMMENT ON TABLE compliance_policies IS 'Master table for compliance policies with approval workflow';
COMMENT ON TABLE policy_rules IS 'Detailed PII handling rules within each compliance policy';
COMMENT ON TABLE policy_versions IS 'Version history and change tracking for policies';
COMMENT ON TABLE policy_applications IS 'Records of policy applications to documents and data';
COMMENT ON TABLE policy_rule_executions IS 'Detailed execution results for individual policy rules';
COMMENT ON TABLE policy_compliance_reports IS 'Generated compliance reports and metrics';
COMMENT ON TABLE policy_effectiveness_metrics IS 'Metrics for measuring policy effectiveness over time';
COMMENT ON TABLE policy_approval_requests IS 'Approval workflow for policy changes';
COMMENT ON TABLE policy_approval_steps IS 'Individual steps in the policy approval workflow';