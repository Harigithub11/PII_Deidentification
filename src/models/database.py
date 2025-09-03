"""
Database models for AI De-identification System
"""
from datetime import datetime
from decimal import Decimal
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, 
    JSON, Numeric, String, Text, BigInteger, INET
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

Base = declarative_base()


class Document(Base):
    """Stores uploaded document metadata"""
    __tablename__ = "documents"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    original_filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_size = Column(BigInteger, nullable=False)
    mime_type = Column(String(100), nullable=False)
    upload_timestamp = Column(DateTime(timezone=True), default=func.now())
    status = Column(String(50), nullable=False, default="uploaded")
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    
    # Relationships
    processing_jobs = relationship("ProcessingJob", back_populates="document", cascade="all, delete-orphan")
    pii_detections = relationship("PIIDetection", back_populates="document", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="document", cascade="all, delete-orphan")
    redacted_documents = relationship("RedactedDocument", back_populates="original_document", cascade="all, delete-orphan")
    performance_metrics = relationship("PerformanceMetric", back_populates="document", cascade="all, delete-orphan")


class ProcessingJob(Base):
    """Tracks document processing workflow"""
    __tablename__ = "processing_jobs"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    document_id = Column(PG_UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    job_type = Column(String(50), nullable=False)  # 'ocr', 'pii_detection', 'redaction'
    status = Column(String(50), nullable=False, default="pending")  # 'pending', 'running', 'completed', 'failed'
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
    result_data = Column(JSON)
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    
    # Relationships
    document = relationship("Document", back_populates="processing_jobs")


class PIIDetection(Base):
    """Stores identified PII instances"""
    __tablename__ = "pii_detections"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    document_id = Column(PG_UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    detection_type = Column(String(100), nullable=False)  # 'PERSON', 'EMAIL', 'PHONE', etc.
    detected_text = Column(Text, nullable=False)
    confidence_score = Column(Numeric(3, 2), nullable=False)
    start_position = Column(Integer, nullable=False)
    end_position = Column(Integer, nullable=False)
    page_number = Column(Integer)
    bounding_box = Column(JSON)  # For visual PII detection (Phase 3)
    redaction_applied = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    # Relationships
    document = relationship("Document", back_populates="pii_detections")


class AuditLog(Base):
    """Comprehensive logging for compliance"""
    __tablename__ = "audit_logs"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    document_id = Column(PG_UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"))
    action = Column(String(100), nullable=False)  # 'upload', 'process', 'redact', 'download'
    user_id = Column(String(100))  # For future user management
    details = Column(JSON)
    ip_address = Column(INET)
    user_agent = Column(Text)
    timestamp = Column(DateTime(timezone=True), default=func.now())
    
    # Relationships
    document = relationship("Document", back_populates="audit_logs")


class RedactedDocument(Base):
    """Stores processed document information"""
    __tablename__ = "redacted_documents"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    original_document_id = Column(PG_UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    redacted_file_path = Column(String(500), nullable=False)
    redaction_method = Column(String(50), nullable=False)  # 'mask', 'replace', 'delete'
    total_redactions = Column(Integer, nullable=False, default=0)
    redaction_summary = Column(JSON)  # Summary of what was redacted
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    # Relationships
    original_document = relationship("Document", back_populates="redacted_documents")


class Policy(Base):
    """Stores PII detection and redaction policies"""
    __tablename__ = "policies"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    policy_name = Column(String(100), nullable=False, unique=True)
    description = Column(Text)
    pii_types = Column(JSON, nullable=False)  # Array of PII types to detect
    confidence_threshold = Column(Numeric(3, 2), nullable=False, default=0.8)
    redaction_method = Column(String(50), nullable=False, default="mask")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())


class PerformanceMetric(Base):
    """For monitoring and optimization"""
    __tablename__ = "performance_metrics"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    document_id = Column(PG_UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"))
    processing_stage = Column(String(50), nullable=False)
    duration_ms = Column(Integer, nullable=False)
    memory_usage_mb = Column(Integer)
    cpu_usage_percent = Column(Numeric(5, 2))
    success = Column(Boolean, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=func.now())
    
    # Relationships
    document = relationship("Document", back_populates="performance_metrics")