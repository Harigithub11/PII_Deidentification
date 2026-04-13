"""
SQLAlchemy ORM Models for PII De-identification System Database Schema

This module contains all the SQLAlchemy models that correspond to the PostgreSQL
database schema. All sensitive fields use encrypted types from encrypted_fields.py.
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from uuid import uuid4, UUID

from sqlalchemy import (
    Column, String, Integer, BigInteger, Boolean, Text, DateTime, Date,
    ForeignKey, ARRAY, Numeric, Enum as SQLEnum, CheckConstraint,
    UniqueConstraint, Index, INET
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, validates
from sqlalchemy.sql import func

from .encrypted_fields import (
    EncryptedString, EncryptedText, EncryptedJSON, EncryptedEmailType,
    EncryptedPhoneType, EncryptedSSNType
)

# Base class for all models
Base = declarative_base()


# =============================================================================
# ENUMS (matching PostgreSQL enums)
# =============================================================================

class UserRole:
    ADMIN = "admin"
    USER = "user"
    AUDITOR = "auditor"
    DATA_PROCESSOR = "data_processor"
    COMPLIANCE_OFFICER = "compliance_officer"


class AuthType:
    PASSWORD = "password"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    LDAP = "ldap"


class SessionStatus:
    ACTIVE = "active"
    EXPIRED = "expired"
    TERMINATED = "terminated"
    SUSPENDED = "suspended"


class PIIType:
    NAME = "name"
    ADDRESS = "address"
    PHONE = "phone"
    EMAIL = "email"
    DATE_OF_BIRTH = "date_of_birth"
    AGE = "age"
    GENDER = "gender"
    SSN = "ssn"
    PASSPORT = "passport"
    DRIVER_LICENSE = "driver_license"
    NATIONAL_ID = "national_id"
    AADHAR = "aadhar"
    PAN = "pan"
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT = "bank_account"
    ROUTING_NUMBER = "routing_number"
    IBAN = "iban"
    INCOME = "income"
    MEDICAL_RECORD = "medical_record"
    MEDICAL_LICENSE = "medical_license"
    DIAGNOSIS = "diagnosis"
    MEDICATION = "medication"
    TREATMENT = "treatment"
    IP_ADDRESS = "ip_address"
    URL = "url"
    CRYPTO_ADDRESS = "crypto_address"
    ORGANIZATION = "organization"
    FINANCIAL = "financial"
    NUMBER = "number"
    LOCATION = "location"
    SIGNATURE = "signature"
    PHOTO = "photo"


class RedactionMethod:
    BLACKOUT = "blackout"
    WHITEOUT = "whiteout"
    BLUR = "blur"
    PIXELATE = "pixelate"
    PSEUDONYMIZE = "pseudonymize"
    GENERALIZE = "generalize"
    DELETE = "delete"


class AuditEventType:
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    DOCUMENT_UPLOADED = "document_uploaded"
    DOCUMENT_PROCESSED = "document_processed"
    PII_DETECTED = "pii_detected"
    PII_REDACTED = "pii_redacted"
    POLICY_APPLIED = "policy_applied"
    SECURITY_BREACH = "security_breach"


class AuditSeverity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditOutcome:
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    ERROR = "error"


class ProcessingStatus:
    UPLOADED = "uploaded"
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    ARCHIVED = "archived"


class PolicyStatus:
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


# =============================================================================
# MIXINS FOR COMMON FUNCTIONALITY
# =============================================================================

class TimestampMixin:
    """Mixin for created_at and updated_at timestamps."""
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc)
    )


class AuditMixin:
    """Mixin for audit fields (created_by, updated_by)."""
    created_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'))
    updated_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'))


class MetadataMixin:
    """Mixin for additional metadata JSONB field."""
    additional_metadata = Column(JSONB, nullable=False, default=dict, server_default='{}')


# =============================================================================
# CORE USER MANAGEMENT MODELS
# =============================================================================

class User(Base, TimestampMixin, AuditMixin, MetadataMixin):
    """User accounts with encrypted PII fields."""
    __tablename__ = 'users'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(EncryptedEmailType(), nullable=False)  # Encrypted
    full_name = Column(EncryptedString(200), nullable=True)  # Encrypted
    password_hash = Column(Text, nullable=False)
    role = Column(
        SQLEnum(
            UserRole.ADMIN, UserRole.USER, UserRole.AUDITOR,
            UserRole.DATA_PROCESSOR, UserRole.COMPLIANCE_OFFICER,
            name='user_role'
        ),
        nullable=False,
        default=UserRole.USER
    )
    is_active = Column(Boolean, nullable=False, default=True)
    is_verified = Column(Boolean, nullable=False, default=False)
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    password_changed_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    two_factor_enabled = Column(Boolean, nullable=False, default=False)
    two_factor_secret = Column(EncryptedString(100), nullable=True)  # Encrypted
    version = Column(Integer, nullable=False, default=1)

    # Relationships
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    audit_events = relationship("AuditEvent", back_populates="user")
    created_policies = relationship(
        "CompliancePolicy", 
        foreign_keys="CompliancePolicy.created_by",
        back_populates="creator"
    )

    # Constraints
    __table_args__ = (
        CheckConstraint('length(username) >= 3', name='users_username_length'),
        CheckConstraint('password_changed_at <= CURRENT_TIMESTAMP', name='users_password_changed_recent'),
        Index('idx_users_role_active', 'role', 'is_active'),
    )

    @validates('email')
    def validate_email(self, key, email):
        if email and '@' not in email:
            raise ValueError("Invalid email format")
        return email

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"


class UserSession(Base, MetadataMixin):
    """User sessions for tracking active sessions."""
    __tablename__ = 'user_sessions'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    session_token = Column(Text, nullable=False, unique=True)
    refresh_token = Column(Text, unique=True, nullable=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    status = Column(
        SQLEnum(
            SessionStatus.ACTIVE, SessionStatus.EXPIRED,
            SessionStatus.TERMINATED, SessionStatus.SUSPENDED,
            name='session_status'
        ),
        nullable=False,
        default=SessionStatus.ACTIVE
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_accessed = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    terminated_at = Column(DateTime(timezone=True), nullable=True)
    terminated_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    termination_reason = Column(Text, nullable=True)
    location_country = Column(String(2), nullable=True)
    location_city = Column(String(100), nullable=True)
    device_fingerprint = Column(Text, nullable=True)

    # Relationships
    user = relationship("User", back_populates="sessions")

    # Constraints
    __table_args__ = (
        CheckConstraint('expires_at > created_at', name='user_sessions_expires_future'),
        Index('idx_user_sessions_user_id', 'user_id'),
        Index('idx_user_sessions_status_expires', 'status', 'expires_at'),
    )


class APIKey(Base, TimestampMixin, MetadataMixin):
    """API keys for programmatic access."""
    __tablename__ = 'api_keys'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    key_name = Column(String(100), nullable=False)
    key_hash = Column(Text, nullable=False, unique=True)
    key_prefix = Column(String(10), nullable=False)
    scopes = Column(ARRAY(Text), nullable=False, default=list)
    is_active = Column(Boolean, nullable=False, default=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used = Column(DateTime(timezone=True), nullable=True)
    usage_count = Column(BigInteger, nullable=False, default=0)
    rate_limit_per_hour = Column(Integer, default=1000)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    revocation_reason = Column(Text, nullable=True)

    # Relationships
    user = relationship("User", back_populates="api_keys")

    # Constraints
    __table_args__ = (
        UniqueConstraint('user_id', 'key_name'),
        Index('idx_api_keys_user_id', 'user_id'),
    )


# =============================================================================
# LOOKUP AND CONFIGURATION MODELS
# =============================================================================

class ComplianceStandard(Base, TimestampMixin):
    """Compliance standards lookup table."""
    __tablename__ = 'compliance_standards'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    code = Column(String(20), nullable=False, unique=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    jurisdiction = Column(String(100), nullable=True)
    version = Column(String(20), nullable=True)
    effective_date = Column(Date, nullable=True)
    website_url = Column(Text, nullable=True)
    documentation_url = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)

    # Relationships
    policies = relationship("CompliancePolicy", back_populates="compliance_standard")


class PIITypeDefinition(Base, TimestampMixin):
    """PII type definitions with validation rules."""
    __tablename__ = 'pii_type_definitions'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    pii_type = Column(
        SQLEnum(*[getattr(PIIType, attr) for attr in dir(PIIType) if not attr.startswith('_')], 
                name='pii_type'),
        nullable=False,
        unique=True
    )
    display_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(50), nullable=False)
    sensitivity_level = Column(Integer, nullable=False, default=5)
    regex_pattern = Column(Text, nullable=True)
    validation_rules = Column(JSONB, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)

    # Constraints
    __table_args__ = (
        CheckConstraint('sensitivity_level BETWEEN 1 AND 10', name='pii_sensitivity_level_range'),
    )


class RedactionMethodDefinition(Base, TimestampMixin):
    """Redaction method definitions."""
    __tablename__ = 'redaction_method_definitions'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    redaction_method = Column(
        SQLEnum(*[getattr(RedactionMethod, attr) for attr in dir(RedactionMethod) if not attr.startswith('_')],
                name='redaction_method'),
        nullable=False,
        unique=True
    )
    display_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    configuration_schema = Column(JSONB, nullable=False, default=dict)
    is_reversible = Column(Boolean, nullable=False, default=False)
    security_level = Column(Integer, nullable=False, default=5)
    is_active = Column(Boolean, nullable=False, default=True)

    # Constraints
    __table_args__ = (
        CheckConstraint('security_level BETWEEN 1 AND 10', name='redaction_security_level_range'),
    )


class DataRetentionSchedule(Base, TimestampMixin, AuditMixin):
    """Data retention schedules."""
    __tablename__ = 'data_retention_schedules'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    retention_period_days = Column(Integer, nullable=False)
    auto_deletion_enabled = Column(Boolean, nullable=False, default=False)
    compliance_standard_id = Column(
        PG_UUID(as_uuid=True), 
        ForeignKey('compliance_standards.id'), 
        nullable=True
    )
    applies_to_pii_types = Column(ARRAY(Text), default=list)
    deletion_method = Column(
        SQLEnum(*[getattr(RedactionMethod, attr) for attr in dir(RedactionMethod) if not attr.startswith('_')],
                name='redaction_method'),
        nullable=False,
        default=RedactionMethod.DELETE
    )
    grace_period_days = Column(Integer, default=0)
    notification_days_before = Column(ARRAY(Integer), default=[30, 7, 1])
    is_active = Column(Boolean, nullable=False, default=True)

    # Relationships
    compliance_standard = relationship("ComplianceStandard")

    # Constraints
    __table_args__ = (
        CheckConstraint('retention_period_days > 0', name='retention_period_positive'),
        CheckConstraint('grace_period_days >= 0', name='grace_period_non_negative'),
    )


# =============================================================================
# AUDIT AND LOGGING MODELS
# =============================================================================

class AuditEvent(Base, MetadataMixin):
    """Main audit events table with integrity chain."""
    __tablename__ = 'audit_events'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    event_id = Column(String(50), nullable=False, unique=True)
    event_type = Column(
        SQLEnum(*[getattr(AuditEventType, attr) for attr in dir(AuditEventType) if not attr.startswith('_')],
                name='audit_event_type'),
        nullable=False
    )
    severity = Column(
        SQLEnum(
            AuditSeverity.LOW, AuditSeverity.MEDIUM,
            AuditSeverity.HIGH, AuditSeverity.CRITICAL,
            name='audit_severity'
        ),
        nullable=False,
        default=AuditSeverity.MEDIUM
    )
    outcome = Column(
        SQLEnum(
            AuditOutcome.SUCCESS, AuditOutcome.FAILURE,
            AuditOutcome.PARTIAL, AuditOutcome.ERROR,
            name='audit_outcome'
        ),
        nullable=False
    )
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    username = Column(String(50), nullable=True)
    session_id = Column(PG_UUID(as_uuid=True), ForeignKey('user_sessions.id'), nullable=True)
    api_key_id = Column(PG_UUID(as_uuid=True), ForeignKey('api_keys.id'), nullable=True)
    impersonator_id = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    target_type = Column(String(50), nullable=True)
    target_id = Column(PG_UUID(as_uuid=True), nullable=True)
    target_name = Column(String(255), nullable=True)
    event_description = Column(Text, nullable=False)
    event_summary = Column(String(500), nullable=True)
    request_method = Column(String(10), nullable=True)
    request_url = Column(Text, nullable=True)
    request_headers = Column(JSONB, nullable=True)
    request_body = Column(JSONB, nullable=True)
    response_status = Column(Integer, nullable=True)
    response_size = Column(BigInteger, nullable=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    location_country = Column(String(2), nullable=True)
    location_city = Column(String(100), nullable=True)
    device_fingerprint = Column(Text, nullable=True)
    event_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    duration_ms = Column(Integer, nullable=True)
    compliance_standards = Column(ARRAY(String(20)), default=list)
    risk_score = Column(Integer, nullable=True)
    contains_pii = Column(Boolean, nullable=False, default=False)
    data_classification = Column(String(20), default='public')
    tags = Column(ARRAY(String(50)), default=list)
    event_hash = Column(Text, nullable=True)
    previous_event_hash = Column(Text, nullable=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="audit_events")
    session = relationship("UserSession")
    api_key = relationship("APIKey")
    details = relationship("AuditEventDetail", back_populates="audit_event", cascade="all, delete-orphan")

    # Constraints
    __table_args__ = (
        CheckConstraint('risk_score IS NULL OR (risk_score BETWEEN 0 AND 100)', name='audit_risk_score_range'),
        CheckConstraint('event_timestamp <= CURRENT_TIMESTAMP + INTERVAL \'1 minute\'', name='audit_events_future_timestamp'),
        Index('idx_audit_events_timestamp', 'event_timestamp'),
        Index('idx_audit_events_user_id', 'user_id'),
        Index('idx_audit_events_type_severity', 'event_type', 'severity'),
    )


class AuditEventDetail(Base):
    """Detailed audit event information for complex events."""
    __tablename__ = 'audit_event_details'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    audit_event_id = Column(
        PG_UUID(as_uuid=True), 
        ForeignKey('audit_events.id', ondelete='CASCADE'), 
        nullable=False
    )
    detail_type = Column(String(50), nullable=False)
    detail_key = Column(String(100), nullable=False)
    detail_value = Column(JSONB, nullable=True)
    is_sensitive = Column(Boolean, nullable=False, default=False)
    encryption_key_id = Column(String(50), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    audit_event = relationship("AuditEvent", back_populates="details")

    # Constraints
    __table_args__ = (
        UniqueConstraint('audit_event_id', 'detail_type', 'detail_key'),
    )


class UserActivity(Base, MetadataMixin):
    """High-level user activity tracking."""
    __tablename__ = 'user_activities'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    session_id = Column(PG_UUID(as_uuid=True), ForeignKey('user_sessions.id'), nullable=True)
    activity_type = Column(String(50), nullable=False)  # 'create', 'read', 'update', 'delete', etc.
    activity_description = Column(Text, nullable=False)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(PG_UUID(as_uuid=True), nullable=True)
    resource_name = Column(String(255), nullable=True)
    http_method = Column(String(10), nullable=True)
    endpoint = Column(String(500), nullable=True)
    parameters = Column(JSONB, nullable=False, default=dict)
    status_code = Column(Integer, nullable=True)
    response_time_ms = Column(Integer, nullable=True)
    response_size_bytes = Column(BigInteger, nullable=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    is_suspicious = Column(Boolean, nullable=False, default=False)
    suspicious_reason = Column(Text, nullable=True)
    started_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    user = relationship("User")
    session = relationship("UserSession")

    # Constraints
    __table_args__ = (
        CheckConstraint('completed_at IS NULL OR completed_at >= started_at', name='user_activities_completion_time'),
        Index('idx_user_activities_user_date', 'user_id', 'started_at'),
    )


class SystemEvent(Base):
    """System events and errors."""
    __tablename__ = 'system_events'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    event_type = Column(String(50), nullable=False)
    severity = Column(
        SQLEnum(
            AuditSeverity.LOW, AuditSeverity.MEDIUM,
            AuditSeverity.HIGH, AuditSeverity.CRITICAL,
            name='audit_severity'
        ),
        nullable=False,
        default=AuditSeverity.MEDIUM
    )
    event_name = Column(String(100), nullable=False)
    event_description = Column(Text, nullable=False)
    error_code = Column(String(20), nullable=True)
    error_message = Column(Text, nullable=True)
    stack_trace = Column(Text, nullable=True)
    service_name = Column(String(50), nullable=True)
    service_version = Column(String(20), nullable=True)
    server_hostname = Column(String(100), nullable=True)
    process_id = Column(Integer, nullable=True)
    thread_id = Column(String(50), nullable=True)
    cpu_usage_percent = Column(Numeric(5, 2), nullable=True)
    memory_usage_mb = Column(BigInteger, nullable=True)
    disk_usage_percent = Column(Numeric(5, 2), nullable=True)
    related_user_id = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    related_session_id = Column(PG_UUID(as_uuid=True), ForeignKey('user_sessions.id'), nullable=True)
    related_request_id = Column(String(100), nullable=True)
    event_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    event_duration_ms = Column(Integer, nullable=True)
    context = Column(JSONB, nullable=False, default=dict)
    requires_attention = Column(Boolean, nullable=False, default=False)
    is_resolved = Column(Boolean, nullable=False, default=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    resolution_notes = Column(Text, nullable=True)

    # Relationships
    related_user = relationship("User", foreign_keys=[related_user_id])
    resolver = relationship("User", foreign_keys=[resolved_by])

    # Indexes
    __table_args__ = (
        Index('idx_system_events_timestamp', 'event_timestamp'),
        Index('idx_system_events_type_severity', 'event_type', 'severity'),
    )


# =============================================================================
# POLICY MANAGEMENT MODELS
# =============================================================================

class CompliancePolicy(Base, TimestampMixin, AuditMixin, MetadataMixin):
    """Main compliance policies table."""
    __tablename__ = 'compliance_policies'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    version = Column(String(20), nullable=False, default='1.0.0')
    policy_code = Column(String(50), nullable=False)
    compliance_standard_id = Column(
        PG_UUID(as_uuid=True), 
        ForeignKey('compliance_standards.id'), 
        nullable=False
    )
    effective_date = Column(Date, nullable=False)
    expiration_date = Column(Date, nullable=True)
    status = Column(
        SQLEnum(
            PolicyStatus.DRAFT, PolicyStatus.PENDING_APPROVAL,
            PolicyStatus.ACTIVE, PolicyStatus.DEPRECATED,
            PolicyStatus.SUSPENDED, PolicyStatus.ARCHIVED,
            name='policy_status'
        ),
        nullable=False,
        default=PolicyStatus.DRAFT
    )
    priority = Column(Integer, nullable=False, default=5)
    strict_mode = Column(Boolean, nullable=False, default=False)
    enable_audit_logging = Column(Boolean, nullable=False, default=True)
    require_approval = Column(Boolean, nullable=False, default=False)
    allow_pseudonymization = Column(Boolean, nullable=False, default=True)
    allow_generalization = Column(Boolean, nullable=False, default=True)
    default_redaction_method = Column(
        SQLEnum(*[getattr(RedactionMethod, attr) for attr in dir(RedactionMethod) if not attr.startswith('_')],
                name='redaction_method'),
        nullable=False,
        default=RedactionMethod.BLACKOUT
    )
    max_retention_days = Column(Integer, nullable=True)
    validation_required = Column(Boolean, nullable=False, default=True)
    auto_apply = Column(Boolean, nullable=False, default=False)
    requires_approval_from = Column(ARRAY(Text), default=list)
    approved_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    approval_notes = Column(Text, nullable=True)
    parent_policy_id = Column(PG_UUID(as_uuid=True), ForeignKey('compliance_policies.id'), nullable=True)
    policy_order = Column(Integer, default=0)
    tags = Column(ARRAY(String(50)), default=list)

    # Relationships
    compliance_standard = relationship("ComplianceStandard", back_populates="policies")
    creator = relationship("User", foreign_keys=[AuditMixin.created_by], back_populates="created_policies")
    approver = relationship("User", foreign_keys=[approved_by])
    parent_policy = relationship("CompliancePolicy", remote_side=[id])
    rules = relationship("PolicyRule", back_populates="policy", cascade="all, delete-orphan")
    versions = relationship("PolicyVersion", back_populates="policy", cascade="all, delete-orphan")
    applications = relationship("PolicyApplication", back_populates="policy")

    # Constraints
    __table_args__ = (
        UniqueConstraint('policy_code', 'version'),
        CheckConstraint('priority BETWEEN 1 AND 10', name='compliance_policies_priority_range'),
        CheckConstraint('max_retention_days IS NULL OR max_retention_days > 0', name='max_retention_positive'),
        CheckConstraint('expiration_date IS NULL OR expiration_date > effective_date', name='compliance_policies_effective_expiration'),
        Index('idx_compliance_policies_code_version', 'policy_code', 'version'),
        Index('idx_compliance_policies_standard', 'compliance_standard_id', 'status'),
    )


class PolicyRule(Base, TimestampMixin, AuditMixin, MetadataMixin):
    """Policy rules within each compliance policy."""
    __tablename__ = 'policy_rules'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    policy_id = Column(
        PG_UUID(as_uuid=True), 
        ForeignKey('compliance_policies.id', ondelete='CASCADE'), 
        nullable=False
    )
    rule_name = Column(String(100), nullable=False)
    rule_description = Column(Text, nullable=True)
    rule_order = Column(Integer, nullable=False, default=0)
    pii_type = Column(
        SQLEnum(*[getattr(PIIType, attr) for attr in dir(PIIType) if not attr.startswith('_')], 
                name='pii_type'),
        nullable=False
    )
    redaction_method = Column(
        SQLEnum(*[getattr(RedactionMethod, attr) for attr in dir(RedactionMethod) if not attr.startswith('_')],
                name='redaction_method'),
        nullable=False
    )
    confidence_threshold = Column(Numeric(3, 2), nullable=False, default=0.80)
    retention_period_days = Column(Integer, nullable=True)
    auto_delete_enabled = Column(Boolean, nullable=False, default=False)
    conditions = Column(JSONB, nullable=False, default=dict)
    exceptions = Column(ARRAY(Text), default=list)
    context_requirements = Column(JSONB, nullable=False, default=dict)
    legal_basis = Column(String(100), nullable=True)
    regulation_reference = Column(Text, nullable=True)
    business_justification = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    is_mandatory = Column(Boolean, nullable=False, default=True)

    # Relationships
    policy = relationship("CompliancePolicy", back_populates="rules")
    executions = relationship("PolicyRuleExecution", back_populates="rule")

    # Constraints
    __table_args__ = (
        UniqueConstraint('policy_id', 'pii_type'),
        UniqueConstraint('policy_id', 'rule_name'),
        CheckConstraint('confidence_threshold BETWEEN 0 AND 1', name='confidence_threshold_range'),
        CheckConstraint('retention_period_days IS NULL OR retention_period_days >= 0', name='retention_period_non_negative'),
        Index('idx_policy_rules_policy_id', 'policy_id', 'rule_order'),
    )


class PolicyVersion(Base, MetadataMixin):
    """Policy versions and change history."""
    __tablename__ = 'policy_versions'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    policy_id = Column(
        PG_UUID(as_uuid=True), 
        ForeignKey('compliance_policies.id', ondelete='CASCADE'), 
        nullable=False
    )
    version_number = Column(String(20), nullable=False)
    previous_version_id = Column(PG_UUID(as_uuid=True), ForeignKey('policy_versions.id'), nullable=True)
    change_type = Column(String(50), nullable=False)  # 'created', 'updated', 'activated', etc.
    change_summary = Column(String(500), nullable=False)
    change_description = Column(Text, nullable=True)
    changed_fields = Column(ARRAY(Text), nullable=True)
    change_reason = Column(Text, nullable=True)
    regulatory_requirement = Column(Text, nullable=True)
    impact_assessment = Column(Text, nullable=True)
    change_approved_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    change_approved_at = Column(DateTime(timezone=True), nullable=True)
    validation_status = Column(String(20), default='pending')
    validation_notes = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    created_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    effective_from = Column(DateTime(timezone=True), nullable=True)
    policy_snapshot = Column(JSONB, nullable=False)
    rules_snapshot = Column(JSONB, nullable=False)

    # Relationships
    policy = relationship("CompliancePolicy", back_populates="versions")
    creator = relationship("User", foreign_keys=[created_by])
    approver = relationship("User", foreign_keys=[change_approved_by])

    # Constraints
    __table_args__ = (
        UniqueConstraint('policy_id', 'version_number'),
        Index('idx_policy_versions_policy_id', 'policy_id', 'created_at'),
    )


class PolicyApplication(Base, MetadataMixin):
    """Policy applications to documents/processes."""
    __tablename__ = 'policy_applications'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    policy_id = Column(PG_UUID(as_uuid=True), ForeignKey('compliance_policies.id'), nullable=False)
    policy_version_id = Column(PG_UUID(as_uuid=True), ForeignKey('policy_versions.id'), nullable=True)
    target_type = Column(String(50), nullable=False)
    target_id = Column(PG_UUID(as_uuid=True), nullable=False)
    target_name = Column(String(255), nullable=True)
    application_status = Column(
        SQLEnum(
            'pending', 'in_progress', 'completed', 'failed', 'partial', 'skipped',
            name='policy_application_status'
        ),
        nullable=False,
        default='pending'
    )
    applied_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    applied_via = Column(String(50), default='automatic')
    rules_applied = Column(Integer, default=0)
    rules_failed = Column(Integer, default=0)
    pii_items_processed = Column(Integer, default=0)
    pii_items_redacted = Column(Integer, default=0)
    validation_status = Column(String(20), default='pending')
    validation_errors = Column(ARRAY(Text), nullable=True)
    validation_warnings = Column(ARRAY(Text), nullable=True)
    compliance_score = Column(Integer, nullable=True)
    started_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    processing_summary = Column(Text, nullable=True)
    output_location = Column(Text, nullable=True)
    backup_location = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    error_details = Column(JSONB, nullable=True)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    audit_trail_id = Column(PG_UUID(as_uuid=True), nullable=True)
    compliance_notes = Column(Text, nullable=True)

    # Relationships
    policy = relationship("CompliancePolicy", back_populates="applications")
    applier = relationship("User")
    rule_executions = relationship("PolicyRuleExecution", back_populates="application", cascade="all, delete-orphan")

    # Constraints
    __table_args__ = (
        CheckConstraint('compliance_score IS NULL OR (compliance_score BETWEEN 0 AND 100)', name='compliance_score_range'),
        CheckConstraint('completed_at IS NULL OR completed_at >= started_at', name='policy_applications_completion_check'),
        CheckConstraint('rules_applied >= 0 AND rules_failed >= 0', name='policy_applications_rules_check'),
        Index('idx_policy_applications_policy_id', 'policy_id', 'started_at'),
        Index('idx_policy_applications_target', 'target_type', 'target_id'),
    )


class PolicyRuleExecution(Base, MetadataMixin):
    """Policy rule execution details."""
    __tablename__ = 'policy_rule_executions'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    policy_application_id = Column(
        PG_UUID(as_uuid=True), 
        ForeignKey('policy_applications.id', ondelete='CASCADE'), 
        nullable=False
    )
    policy_rule_id = Column(PG_UUID(as_uuid=True), ForeignKey('policy_rules.id'), nullable=False)
    execution_order = Column(Integer, nullable=False)
    execution_status = Column(
        SQLEnum(
            'pending', 'in_progress', 'completed', 'failed', 'partial', 'skipped',
            name='policy_application_status'
        ),
        nullable=False,
        default='pending'
    )
    input_data_type = Column(String(50), nullable=True)
    input_data_size_bytes = Column(BigInteger, nullable=True)
    detected_pii_count = Column(Integer, default=0)
    pii_detections = Column(JSONB, nullable=False, default=list)
    confidence_scores = Column(ARRAY(Numeric(3, 2)), nullable=True)
    redaction_method_used = Column(
        SQLEnum(*[getattr(RedactionMethod, attr) for attr in dir(RedactionMethod) if not attr.startswith('_')],
                name='redaction_method'),
        nullable=True
    )
    redacted_items_count = Column(Integer, default=0)
    redaction_success_rate = Column(Numeric(5, 2), nullable=True)
    output_data_size_bytes = Column(BigInteger, nullable=True)
    output_location = Column(Text, nullable=True)
    processing_time_ms = Column(Integer, nullable=True)
    memory_usage_mb = Column(Integer, nullable=True)
    error_occurred = Column(Boolean, nullable=False, default=False)
    error_message = Column(Text, nullable=True)
    error_details = Column(JSONB, nullable=True)
    started_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    application = relationship("PolicyApplication", back_populates="rule_executions")
    rule = relationship("PolicyRule", back_populates="executions")

    # Constraints
    __table_args__ = (
        UniqueConstraint('policy_application_id', 'policy_rule_id'),
        Index('idx_policy_rule_executions_application', 'policy_application_id', 'execution_order'),
    )


# =============================================================================
# DOCUMENT AND METADATA MODELS
# =============================================================================

class DocumentMetadata(Base, MetadataMixin):
    """Document metadata with PII analysis."""
    __tablename__ = 'document_metadata'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    document_name = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    document_type = Column(String(50), nullable=False)  # Enum would be defined similarly
    file_format = Column(String(50), nullable=False)
    file_size_bytes = Column(BigInteger, nullable=False)
    file_checksum_md5 = Column(String(32), nullable=False)
    file_checksum_sha256 = Column(String(64), nullable=False)
    mime_type = Column(String(100), nullable=True)
    page_count = Column(Integer, default=1)
    word_count = Column(Integer, default=0)
    character_count = Column(Integer, default=0)
    image_count = Column(Integer, default=0)
    primary_language = Column(String(10), nullable=True)
    detected_languages = Column(ARRAY(String(10)), default=list)
    text_encoding = Column(String(50), default='UTF-8')
    security_classification = Column(String(20), default='internal')
    contains_sensitive_data = Column(Boolean, nullable=False, default=False)
    sensitivity_score = Column(Integer, nullable=True)
    pii_detected = Column(Boolean, nullable=False, default=False)
    pii_types_found = Column(ARRAY(Text), default=list)
    pii_item_count = Column(Integer, default=0)
    high_confidence_pii_count = Column(Integer, default=0)
    has_forms = Column(Boolean, nullable=False, default=False)
    has_tables = Column(Boolean, nullable=False, default=False)
    has_images = Column(Boolean, nullable=False, default=False)
    has_signatures = Column(Boolean, nullable=False, default=False)
    has_handwriting = Column(Boolean, nullable=False, default=False)
    text_quality = Column(String(20), default='good')
    image_quality = Column(String(20), default='good')
    ocr_confidence_avg = Column(Numeric(5, 2), nullable=True)
    uploaded_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    processing_policy_id = Column(PG_UUID(as_uuid=True), ForeignKey('compliance_policies.id'), nullable=True)
    processing_batch_id = Column(PG_UUID(as_uuid=True), nullable=True)
    original_file_path = Column(Text, nullable=False)
    processed_file_path = Column(Text, nullable=True)
    backup_file_path = Column(Text, nullable=True)
    thumbnail_path = Column(Text, nullable=True)
    uploaded_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    last_accessed = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    retention_policy_id = Column(PG_UUID(as_uuid=True), ForeignKey('data_retention_schedules.id'), nullable=True)
    compliance_validated = Column(Boolean, nullable=False, default=False)
    compliance_validation_date = Column(DateTime(timezone=True), nullable=True)
    tags = Column(ARRAY(String(50)), default=list)

    # Relationships
    uploader = relationship("User")
    processing_policy = relationship("CompliancePolicy")
    retention_policy = relationship("DataRetentionSchedule")
    session_documents = relationship("SessionDocument", back_populates="document")
    redactions = relationship("RedactionMetadata", back_populates="document", cascade="all, delete-orphan")

    # Constraints
    __table_args__ = (
        CheckConstraint('file_size_bytes >= 0', name='file_size_non_negative'),
        CheckConstraint('page_count >= 0', name='page_count_non_negative'),
        CheckConstraint('word_count >= 0', name='word_count_non_negative'),
        CheckConstraint('character_count >= 0', name='character_count_non_negative'),
        CheckConstraint('image_count >= 0', name='image_count_non_negative'),
        CheckConstraint('pii_item_count >= 0', name='pii_item_count_non_negative'),
        CheckConstraint('high_confidence_pii_count >= 0', name='high_confidence_pii_count_non_negative'),
        CheckConstraint('sensitivity_score IS NULL OR (sensitivity_score BETWEEN 0 AND 100)', name='sensitivity_score_range'),
        CheckConstraint('ocr_confidence_avg IS NULL OR (ocr_confidence_avg BETWEEN 0 AND 100)', name='ocr_confidence_range'),
        CheckConstraint('length(file_checksum_md5) = 32 AND length(file_checksum_sha256) = 64', name='document_metadata_checksum_length'),
        Index('idx_document_metadata_uploaded', 'uploaded_at'),
        Index('idx_document_metadata_uploaded_by', 'uploaded_by', 'uploaded_at'),
        Index('idx_document_metadata_checksum_md5', 'file_checksum_md5'),
        Index('idx_document_metadata_checksum_sha256', 'file_checksum_sha256'),
    )


class ProcessingSession(Base, MetadataMixin):
    """Processing sessions for workflow tracking."""
    __tablename__ = 'processing_sessions'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    session_name = Column(String(100), nullable=True)
    session_type = Column(String(50), nullable=False, default='single_document')
    session_priority = Column(Integer, nullable=False, default=3)
    policy_id = Column(PG_UUID(as_uuid=True), ForeignKey('compliance_policies.id'), nullable=False)
    policy_version_id = Column(PG_UUID(as_uuid=True), ForeignKey('policy_versions.id'), nullable=True)
    processing_mode = Column(String(20), nullable=False, default='automatic')
    status = Column(
        SQLEnum(
            ProcessingStatus.UPLOADED, ProcessingStatus.QUEUED,
            ProcessingStatus.PROCESSING, ProcessingStatus.COMPLETED,
            ProcessingStatus.FAILED, ProcessingStatus.CANCELLED,
            ProcessingStatus.EXPIRED, ProcessingStatus.ARCHIVED,
            name='processing_status'
        ),
        nullable=False,
        default=ProcessingStatus.QUEUED
    )
    current_stage = Column(String(50), nullable=True)
    progress_percentage = Column(Integer, default=0)
    document_count = Column(Integer, nullable=False, default=0)
    documents_processed = Column(Integer, nullable=False, default=0)
    documents_successful = Column(Integer, nullable=False, default=0)
    documents_failed = Column(Integer, nullable=False, default=0)
    total_pii_detected = Column(Integer, nullable=False, default=0)
    total_pii_redacted = Column(Integer, nullable=False, default=0)
    processing_time_seconds = Column(Integer, nullable=True)
    cpu_time_seconds = Column(Numeric(10, 2), nullable=True)
    memory_peak_mb = Column(Integer, nullable=True)
    storage_used_mb = Column(Integer, nullable=True)
    overall_quality_score = Column(Numeric(5, 2), nullable=True)
    average_confidence_score = Column(Numeric(5, 2), nullable=True)
    initiated_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    processed_by = Column(String(100), nullable=True)
    worker_node = Column(String(100), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    estimated_completion = Column(DateTime(timezone=True), nullable=True)
    error_count = Column(Integer, nullable=False, default=0)
    last_error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, nullable=False, default=0)
    max_retries = Column(Integer, nullable=False, default=3)
    output_location = Column(Text, nullable=True)
    output_format = Column(String(20), nullable=True)
    output_size_bytes = Column(BigInteger, nullable=True)
    audit_trail_id = Column(PG_UUID(as_uuid=True), nullable=True)
    compliance_report_generated = Column(Boolean, nullable=False, default=False)
    configuration = Column(JSONB, nullable=False, default=dict)
    metrics = Column(JSONB, nullable=False, default=dict)

    # Relationships
    policy = relationship("CompliancePolicy")
    policy_version = relationship("PolicyVersion")
    initiator = relationship("User")
    session_documents = relationship("SessionDocument", back_populates="session", cascade="all, delete-orphan")

    # Constraints
    __table_args__ = (
        CheckConstraint('session_priority BETWEEN 1 AND 5', name='session_priority_range'),
        CheckConstraint('progress_percentage BETWEEN 0 AND 100', name='progress_percentage_range'),
        CheckConstraint('overall_quality_score IS NULL OR (overall_quality_score BETWEEN 0 AND 100)', name='overall_quality_score_range'),
        CheckConstraint('average_confidence_score IS NULL OR (average_confidence_score BETWEEN 0 AND 100)', name='average_confidence_score_range'),
        CheckConstraint('started_at IS NULL OR started_at >= created_at', name='processing_sessions_timing'),
        CheckConstraint('completed_at IS NULL OR (started_at IS NOT NULL AND completed_at >= started_at)', name='processing_sessions_completion'),
        Index('idx_processing_sessions_policy', 'policy_id', 'created_at'),
        Index('idx_processing_sessions_status', 'status', 'created_at'),
    )


class SessionDocument(Base, MetadataMixin):
    """Many-to-many relationship between sessions and documents."""
    __tablename__ = 'session_documents'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    session_id = Column(
        PG_UUID(as_uuid=True), 
        ForeignKey('processing_sessions.id', ondelete='CASCADE'), 
        nullable=False
    )
    document_id = Column(
        PG_UUID(as_uuid=True), 
        ForeignKey('document_metadata.id', ondelete='CASCADE'), 
        nullable=False
    )
    processing_order = Column(Integer, nullable=False, default=0)
    status = Column(
        SQLEnum(
            ProcessingStatus.UPLOADED, ProcessingStatus.QUEUED,
            ProcessingStatus.PROCESSING, ProcessingStatus.COMPLETED,
            ProcessingStatus.FAILED, ProcessingStatus.CANCELLED,
            ProcessingStatus.EXPIRED, ProcessingStatus.ARCHIVED,
            name='processing_status'
        ),
        nullable=False,
        default=ProcessingStatus.QUEUED
    )
    current_stage = Column(String(50), nullable=True)
    progress_percentage = Column(Integer, default=0)
    pii_detected_count = Column(Integer, default=0)
    pii_redacted_count = Column(Integer, default=0)
    processing_time_seconds = Column(Integer, nullable=True)
    quality_score = Column(Numeric(5, 2), nullable=True)
    confidence_score = Column(Numeric(5, 2), nullable=True)
    added_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, nullable=False, default=0)
    output_file_path = Column(Text, nullable=True)
    output_size_bytes = Column(BigInteger, nullable=True)
    processing_notes = Column(Text, nullable=True)

    # Relationships
    session = relationship("ProcessingSession", back_populates="session_documents")
    document = relationship("DocumentMetadata", back_populates="session_documents")

    # Constraints
    __table_args__ = (
        UniqueConstraint('session_id', 'document_id'),
        CheckConstraint('progress_percentage BETWEEN 0 AND 100', name='session_document_progress_range'),
        CheckConstraint('quality_score IS NULL OR (quality_score BETWEEN 0 AND 100)', name='session_document_quality_range'),
        CheckConstraint('confidence_score IS NULL OR (confidence_score BETWEEN 0 AND 100)', name='session_document_confidence_range'),
        Index('idx_session_documents_session', 'session_id', 'processing_order'),
    )


class RedactionMetadata(Base, MetadataMixin):
    """Detailed metadata for redaction operations."""
    __tablename__ = 'redaction_metadata'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    document_id = Column(
        PG_UUID(as_uuid=True), 
        ForeignKey('document_metadata.id', ondelete='CASCADE'), 
        nullable=False
    )
    session_id = Column(PG_UUID(as_uuid=True), ForeignKey('processing_sessions.id'), nullable=True)
    redaction_type = Column(String(50), nullable=False)
    redaction_method = Column(
        SQLEnum(*[getattr(RedactionMethod, attr) for attr in dir(RedactionMethod) if not attr.startswith('_')],
                name='redaction_method'),
        nullable=False
    )
    page_number = Column(Integer, nullable=True)
    x_coordinate = Column(Integer, nullable=True)
    y_coordinate = Column(Integer, nullable=True)
    width = Column(Integer, nullable=True)
    height = Column(Integer, nullable=True)
    original_text = Column(EncryptedText(), nullable=True)  # Encrypted
    redacted_text = Column(Text, nullable=True)
    pii_type = Column(
        SQLEnum(*[getattr(PIIType, attr) for attr in dir(PIIType) if not attr.startswith('_')], 
                name='pii_type'),
        nullable=False
    )
    confidence_score = Column(Numeric(5, 2), nullable=False)
    detection_model = Column(String(100), nullable=True)
    detection_version = Column(String(20), nullable=True)
    detection_parameters = Column(JSONB, nullable=False, default=dict)
    manually_reviewed = Column(Boolean, nullable=False, default=False)
    reviewed_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    review_decision = Column(String(20), nullable=True)
    review_notes = Column(Text, nullable=True)
    redaction_quality = Column(String(20), default='good')
    needs_review = Column(Boolean, nullable=False, default=False)
    policy_rule_id = Column(PG_UUID(as_uuid=True), ForeignKey('policy_rules.id'), nullable=True)
    compliance_justification = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    processed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    document = relationship("DocumentMetadata", back_populates="redactions")
    session = relationship("ProcessingSession")
    reviewer = relationship("User")
    policy_rule = relationship("PolicyRule")

    # Constraints
    __table_args__ = (
        CheckConstraint('page_number IS NULL OR page_number >= 1', name='page_number_positive'),
        CheckConstraint('x_coordinate IS NULL OR x_coordinate >= 0', name='x_coordinate_non_negative'),
        CheckConstraint('y_coordinate IS NULL OR y_coordinate >= 0', name='y_coordinate_non_negative'),
        CheckConstraint('width IS NULL OR width >= 0', name='width_non_negative'),
        CheckConstraint('height IS NULL OR height >= 0', name='height_non_negative'),
        CheckConstraint('confidence_score BETWEEN 0 AND 100', name='redaction_confidence_range'),
        Index('idx_redaction_metadata_document', 'document_id', 'page_number'),
        Index('idx_redaction_metadata_pii_type', 'pii_type', 'confidence_score'),
    )


# =============================================================================
# BATCH PROCESSING MODELS
# =============================================================================

class BatchJobStatus:
    """Batch job status enumeration."""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class BatchJobType:
    """Batch job type enumeration."""
    DOCUMENT_PROCESSING = "document_processing"
    PII_DETECTION = "pii_detection"
    BULK_REDACTION = "bulk_redaction"
    COMPLIANCE_VALIDATION = "compliance_validation"
    AUDIT_GENERATION = "audit_generation"
    BULK_ENCRYPTION = "bulk_encryption"
    POLICY_APPLICATION = "policy_application"
    REPORT_GENERATION = "report_generation"
    CUSTOM = "custom"


class JobPriority:
    """Job priority enumeration."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"
    URGENT = "urgent"


class WorkerStatus:
    """Worker status enumeration."""
    IDLE = "idle"
    BUSY = "busy"
    OFFLINE = "offline"
    ERROR = "error"
    MAINTENANCE = "maintenance"


class BatchJob(Base, MetadataMixin):
    """Database model for batch jobs with comprehensive tracking."""
    __tablename__ = 'batch_jobs'

    # Primary identification
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    job_type = Column(
        SQLEnum(*[getattr(BatchJobType, attr) for attr in dir(BatchJobType) if not attr.startswith('_')],
                name='batch_job_type'),
        nullable=False
    )
    
    # Job configuration
    parameters = Column(JSONB, nullable=False, default=dict)
    priority = Column(
        SQLEnum(*[getattr(JobPriority, attr) for attr in dir(JobPriority) if not attr.startswith('_')],
                name='job_priority'),
        nullable=False,
        default='normal'
    )
    timeout_seconds = Column(Integer, nullable=False, default=3600)
    
    # Resource requirements
    max_workers = Column(Integer, nullable=False, default=1)
    memory_limit_mb = Column(Integer, nullable=False, default=1024)
    cpu_limit_cores = Column(Numeric(3, 1), nullable=False, default=1.0)
    
    # Input/Output
    input_data = Column(JSONB, nullable=False, default=dict)
    output_location = Column(Text, nullable=True)
    
    # Status and progress
    status = Column(
        SQLEnum(*[getattr(BatchJobStatus, attr) for attr in dir(BatchJobStatus) if not attr.startswith('_')],
                name='batch_job_status'),
        nullable=False,
        default='pending'
    )
    progress_percentage = Column(Integer, nullable=False, default=0)
    current_step = Column(String(255), nullable=False, default='initialized')
    steps_completed = Column(Integer, nullable=False, default=0)
    total_steps = Column(Integer, nullable=False, default=1)
    
    # Timing information
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now()
    )
    queued_at = Column(DateTime(timezone=True), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    last_heartbeat = Column(DateTime(timezone=True), nullable=True)
    
    # User and permissions
    created_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    assigned_to = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    access_permissions = Column(ARRAY(PG_UUID(as_uuid=True)), nullable=False, default=list)
    
    # Error handling and retry
    max_retries = Column(Integer, nullable=False, default=3)
    retry_count = Column(Integer, nullable=False, default=0)
    retry_delay_seconds = Column(Integer, nullable=False, default=60)
    
    # Dependencies and scheduling
    depends_on = Column(ARRAY(PG_UUID(as_uuid=True)), nullable=False, default=list)
    scheduled_at = Column(DateTime(timezone=True), nullable=True)
    
    # Results and error tracking
    result_summary = Column(JSONB, nullable=False, default=dict)
    error_message = Column(Text, nullable=True)
    error_details = Column(JSONB, nullable=False, default=dict)
    
    # Audit and compliance
    compliance_standards = Column(ARRAY(String(50)), nullable=False, default=list)
    audit_trail = Column(JSONB, nullable=False, default=list)
    
    # Metadata
    tags = Column(ARRAY(String(50)), nullable=False, default=list)
    custom_metadata = Column(JSONB, nullable=False, default=dict)
    
    # Worker assignment
    assigned_worker_id = Column(PG_UUID(as_uuid=True), ForeignKey('batch_workers.id'), nullable=True)
    
    # Relationships
    creator = relationship("User", foreign_keys=[created_by], back_populates="created_jobs")
    assignee = relationship("User", foreign_keys=[assigned_to], back_populates="assigned_jobs")
    assigned_worker = relationship("BatchWorker", back_populates="jobs")
    job_results = relationship("JobResult", back_populates="job", cascade="all, delete-orphan")
    schedules = relationship("JobSchedule", back_populates="job", cascade="all, delete-orphan")
    
    # Constraints and indexes
    __table_args__ = (
        CheckConstraint('progress_percentage BETWEEN 0 AND 100', name='progress_percentage_range'),
        CheckConstraint('timeout_seconds >= 60', name='timeout_minimum'),
        CheckConstraint('max_workers >= 1 AND max_workers <= 10', name='max_workers_range'),
        CheckConstraint('memory_limit_mb >= 512', name='memory_limit_minimum'),
        CheckConstraint('cpu_limit_cores >= 0.5 AND cpu_limit_cores <= 4.0', name='cpu_limit_range'),
        CheckConstraint('steps_completed >= 0', name='steps_completed_non_negative'),
        CheckConstraint('total_steps >= 1', name='total_steps_positive'),
        CheckConstraint('max_retries >= 0 AND max_retries <= 10', name='max_retries_range'),
        CheckConstraint('retry_count >= 0', name='retry_count_non_negative'),
        CheckConstraint('retry_delay_seconds BETWEEN 30 AND 3600', name='retry_delay_range'),
        CheckConstraint('completed_at IS NULL OR completed_at >= created_at', name='completion_after_creation'),
        CheckConstraint('started_at IS NULL OR started_at >= queued_at', name='start_after_queue'),
        Index('idx_batch_jobs_status', 'status', 'priority', 'created_at'),
        Index('idx_batch_jobs_type', 'job_type', 'status'),
        Index('idx_batch_jobs_creator', 'created_by', 'created_at'),
        Index('idx_batch_jobs_worker', 'assigned_worker_id', 'status'),
        Index('idx_batch_jobs_scheduled', 'scheduled_at', 'status'),
        Index('idx_batch_jobs_heartbeat', 'last_heartbeat', 'status'),
        UniqueConstraint('name', 'created_by', name='unique_job_name_per_user'),
    )

    def add_audit_entry(self, action: str, details: dict = None):
        """Add entry to audit trail."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "details": details or {}
        }
        if self.audit_trail is None:
            self.audit_trail = []
        self.audit_trail.append(entry)

    def update_progress(self, percentage: int, step: str = None, steps_completed: int = None):
        """Update job progress information."""
        self.progress_percentage = max(0, min(100, percentage))
        if step:
            self.current_step = step
        if steps_completed is not None:
            self.steps_completed = steps_completed
        self.last_heartbeat = datetime.now(timezone.utc)

    def is_expired(self) -> bool:
        """Check if job has exceeded timeout."""
        if not self.started_at:
            return False
        elapsed = datetime.now(timezone.utc) - self.started_at
        return elapsed.total_seconds() > self.timeout_seconds

    def can_retry(self) -> bool:
        """Check if job can be retried."""
        return self.retry_count < self.max_retries

    def get_runtime_seconds(self) -> float:
        """Get job runtime in seconds."""
        if not self.started_at:
            return 0.0
        end_time = self.completed_at or datetime.now(timezone.utc)
        return (end_time - self.started_at).total_seconds()


class JobSchedule(Base, MetadataMixin):
    """Database model for job scheduling and recurring jobs."""
    __tablename__ = 'job_schedules'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    job_id = Column(PG_UUID(as_uuid=True), ForeignKey('batch_jobs.id', ondelete='CASCADE'), nullable=False)
    schedule_name = Column(String(200), nullable=False)
    cron_expression = Column(String(100), nullable=False)
    timezone = Column(String(50), nullable=False, default='UTC')
    is_active = Column(Boolean, nullable=False, default=True)
    
    # Schedule timing
    next_run_at = Column(DateTime(timezone=True), nullable=False)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    last_run_status = Column(
        SQLEnum(*[getattr(BatchJobStatus, attr) for attr in dir(BatchJobStatus) if not attr.startswith('_')],
                name='batch_job_status'),
        nullable=True
    )
    
    # Schedule configuration
    max_runs = Column(Integer, nullable=True)  # NULL = unlimited
    runs_completed = Column(Integer, nullable=False, default=0)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Error handling
    consecutive_failures = Column(Integer, nullable=False, default=0)
    max_consecutive_failures = Column(Integer, nullable=False, default=3)
    failure_notification_sent = Column(Boolean, nullable=False, default=False)
    
    # Metadata
    description = Column(Text, nullable=True)
    created_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )
    
    # Relationships
    job = relationship("BatchJob", back_populates="schedules")
    creator = relationship("User", back_populates="job_schedules")
    
    # Constraints and indexes
    __table_args__ = (
        CheckConstraint('max_runs IS NULL OR max_runs > 0', name='max_runs_positive'),
        CheckConstraint('runs_completed >= 0', name='runs_completed_non_negative'),
        CheckConstraint('consecutive_failures >= 0', name='consecutive_failures_non_negative'),
        CheckConstraint('max_consecutive_failures > 0', name='max_consecutive_failures_positive'),
        CheckConstraint('expires_at IS NULL OR expires_at > created_at', name='expiry_after_creation'),
        Index('idx_job_schedules_next_run', 'next_run_at', 'is_active'),
        Index('idx_job_schedules_job', 'job_id', 'is_active'),
        Index('idx_job_schedules_creator', 'created_by', 'created_at'),
        UniqueConstraint('schedule_name', 'created_by', name='unique_schedule_name_per_user'),
    )


class JobResult(Base, MetadataMixin):
    """Database model for detailed job execution results."""
    __tablename__ = 'job_results'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    job_id = Column(PG_UUID(as_uuid=True), ForeignKey('batch_jobs.id', ondelete='CASCADE'), nullable=False)
    execution_id = Column(String(100), nullable=False)  # For tracking retries
    
    # Execution metadata
    started_at = Column(DateTime(timezone=True), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=False)
    duration_seconds = Column(Numeric(10, 3), nullable=False)
    
    # Resource usage
    max_memory_mb = Column(Integer, nullable=True)
    avg_cpu_percent = Column(Numeric(5, 2), nullable=True)
    disk_io_mb = Column(Integer, nullable=True)
    
    # Results and metrics
    status = Column(
        SQLEnum(*[getattr(BatchJobStatus, attr) for attr in dir(BatchJobStatus) if not attr.startswith('_')],
                name='batch_job_status'),
        nullable=False
    )
    result_data = Column(JSONB, nullable=False, default=dict)
    output_files = Column(ARRAY(Text), nullable=False, default=list)
    output_size_bytes = Column(BigInteger, nullable=True)
    
    # Processing statistics
    items_processed = Column(Integer, nullable=False, default=0)
    items_successful = Column(Integer, nullable=False, default=0)
    items_failed = Column(Integer, nullable=False, default=0)
    items_skipped = Column(Integer, nullable=False, default=0)
    
    # Error information
    error_message = Column(Text, nullable=True)
    error_code = Column(String(50), nullable=True)
    error_details = Column(JSONB, nullable=False, default=dict)
    stack_trace = Column(Text, nullable=True)
    
    # Quality metrics
    success_rate = Column(Numeric(5, 2), nullable=True)
    quality_score = Column(Integer, nullable=True)
    performance_rating = Column(String(20), nullable=True)
    
    # Worker information
    worker_id = Column(PG_UUID(as_uuid=True), ForeignKey('batch_workers.id'), nullable=True)
    worker_hostname = Column(String(255), nullable=True)
    worker_version = Column(String(50), nullable=True)
    
    # Compliance and audit
    compliance_validated = Column(Boolean, nullable=False, default=False)
    audit_checksum = Column(String(64), nullable=True)
    retention_policy_applied = Column(Boolean, nullable=False, default=False)
    
    # Relationships
    job = relationship("BatchJob", back_populates="job_results")
    worker = relationship("BatchWorker", back_populates="job_results")
    
    # Constraints and indexes
    __table_args__ = (
        CheckConstraint('duration_seconds >= 0', name='duration_non_negative'),
        CheckConstraint('max_memory_mb IS NULL OR max_memory_mb > 0', name='memory_positive'),
        CheckConstraint('avg_cpu_percent IS NULL OR avg_cpu_percent BETWEEN 0 AND 100', name='cpu_percent_range'),
        CheckConstraint('items_processed >= 0', name='items_processed_non_negative'),
        CheckConstraint('items_successful >= 0', name='items_successful_non_negative'),
        CheckConstraint('items_failed >= 0', name='items_failed_non_negative'),
        CheckConstraint('items_skipped >= 0', name='items_skipped_non_negative'),
        CheckConstraint('success_rate IS NULL OR success_rate BETWEEN 0 AND 100', name='success_rate_range'),
        CheckConstraint('quality_score IS NULL OR quality_score BETWEEN 0 AND 100', name='quality_score_range'),
        CheckConstraint('completed_at >= started_at', name='completion_after_start'),
        Index('idx_job_results_job', 'job_id', 'started_at'),
        Index('idx_job_results_execution', 'execution_id', 'job_id'),
        Index('idx_job_results_worker', 'worker_id', 'completed_at'),
        Index('idx_job_results_status', 'status', 'completed_at'),
        UniqueConstraint('execution_id', 'job_id', name='unique_execution_per_job'),
    )


class BatchWorker(Base, MetadataMixin):
    """Database model for batch processing workers."""
    __tablename__ = 'batch_workers'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    worker_name = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=False)
    pid = Column(Integer, nullable=False)
    
    # Worker configuration
    worker_type = Column(String(50), nullable=False, default='standard')
    supported_job_types = Column(ARRAY(String(50)), nullable=False, default=list)
    max_concurrent_jobs = Column(Integer, nullable=False, default=1)
    memory_limit_mb = Column(Integer, nullable=False, default=2048)
    cpu_cores = Column(Integer, nullable=False, default=1)
    
    # Status and health
    status = Column(
        SQLEnum(*[getattr(WorkerStatus, attr) for attr in dir(WorkerStatus) if not attr.startswith('_')],
                name='worker_status'),
        nullable=False,
        default='offline'
    )
    current_jobs_count = Column(Integer, nullable=False, default=0)
    total_jobs_processed = Column(Integer, nullable=False, default=0)
    total_jobs_failed = Column(Integer, nullable=False, default=0)
    
    # Timing information
    started_at = Column(DateTime(timezone=True), nullable=False)
    last_heartbeat = Column(DateTime(timezone=True), nullable=False)
    last_job_completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Performance metrics
    average_job_duration_seconds = Column(Numeric(10, 3), nullable=True)
    success_rate = Column(Numeric(5, 2), nullable=True)
    current_memory_usage_mb = Column(Integer, nullable=True)
    current_cpu_usage_percent = Column(Numeric(5, 2), nullable=True)
    
    # Worker metadata
    version = Column(String(50), nullable=False)
    queue_names = Column(ARRAY(String(100)), nullable=False, default=list)
    tags = Column(ARRAY(String(50)), nullable=False, default=list)
    configuration = Column(JSONB, nullable=False, default=dict)
    
    # Error tracking
    consecutive_failures = Column(Integer, nullable=False, default=0)
    last_error_message = Column(Text, nullable=True)
    last_error_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    jobs = relationship("BatchJob", back_populates="assigned_worker")
    job_results = relationship("JobResult", back_populates="worker")
    
    # Constraints and indexes
    __table_args__ = (
        CheckConstraint('max_concurrent_jobs > 0', name='max_concurrent_positive'),
        CheckConstraint('memory_limit_mb > 0', name='memory_limit_positive'),
        CheckConstraint('cpu_cores > 0', name='cpu_cores_positive'),
        CheckConstraint('current_jobs_count >= 0', name='current_jobs_non_negative'),
        CheckConstraint('total_jobs_processed >= 0', name='total_jobs_non_negative'),
        CheckConstraint('total_jobs_failed >= 0', name='total_failed_non_negative'),
        CheckConstraint('average_job_duration_seconds IS NULL OR average_job_duration_seconds >= 0', 
                       name='avg_duration_non_negative'),
        CheckConstraint('success_rate IS NULL OR success_rate BETWEEN 0 AND 100', name='worker_success_rate_range'),
        CheckConstraint('current_memory_usage_mb IS NULL OR current_memory_usage_mb >= 0', 
                       name='current_memory_non_negative'),
        CheckConstraint('current_cpu_usage_percent IS NULL OR current_cpu_usage_percent BETWEEN 0 AND 100', 
                       name='current_cpu_range'),
        CheckConstraint('consecutive_failures >= 0', name='consecutive_failures_non_negative'),
        CheckConstraint('last_heartbeat >= started_at', name='heartbeat_after_start'),
        Index('idx_batch_workers_status', 'status', 'last_heartbeat'),
        Index('idx_batch_workers_hostname', 'hostname', 'pid'),
        Index('idx_batch_workers_type', 'worker_type', 'status'),
        Index('idx_batch_workers_heartbeat', 'last_heartbeat', 'status'),
        UniqueConstraint('hostname', 'pid', name='unique_worker_per_host_pid'),
        UniqueConstraint('worker_name', name='unique_worker_name'),
    )

    def is_healthy(self) -> bool:
        """Check if worker is healthy based on recent heartbeat."""
        if self.status == WorkerStatus.OFFLINE:
            return False
        
        # Consider worker unhealthy if no heartbeat in last 5 minutes
        if not self.last_heartbeat:
            return False
            
        time_since_heartbeat = datetime.now(timezone.utc) - self.last_heartbeat
        return time_since_heartbeat.total_seconds() < 300

    def get_load_percentage(self) -> float:
        """Get current load as percentage of capacity."""
        if self.max_concurrent_jobs == 0:
            return 100.0
        return (self.current_jobs_count / self.max_concurrent_jobs) * 100

    def can_accept_job(self, job_type: str = None) -> bool:
        """Check if worker can accept a new job."""
        if self.status != WorkerStatus.IDLE:
            return False
        if self.current_jobs_count >= self.max_concurrent_jobs:
            return False
        if job_type and job_type not in self.supported_job_types:
            return False
        return True


# Add relationships to User model
User.created_jobs = relationship("BatchJob", foreign_keys="BatchJob.created_by", back_populates="creator")
User.assigned_jobs = relationship("BatchJob", foreign_keys="BatchJob.assigned_to", back_populates="assignee")
User.job_schedules = relationship("JobSchedule", back_populates="creator")


def __repr__(self):
    """Generic __repr__ method for all models."""
    return f"<{self.__class__.__name__}(id={getattr(self, 'id', 'N/A')})>"


# Add __repr__ to all model classes
for name, obj in list(globals().items()):
    if isinstance(obj, type) and issubclass(obj, Base) and obj is not Base:
        if not hasattr(obj, '__repr__'):
            obj.__repr__ = __repr__