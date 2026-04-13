"""
Simplified Database Setup for AI De-identification System
Avoids Windows-specific import issues while providing enterprise functionality
"""
import sqlite3
import os
from pathlib import Path
from sqlalchemy import create_engine, text, MetaData, Table, Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime
import logging

# Password hashing
try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    PASSLIB_AVAILABLE = True
except ImportError:
    # Fallback for simple password hashing if passlib not available
    import hashlib
    PASSLIB_AVAILABLE = False
    logger.warning("passlib not available, using basic password hashing")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database URL
DATABASE_URL = "sqlite:///./data/pii_system.db"

# Create declarative base
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    full_name = Column(String(100))
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default='user')
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Document(Base):
    __tablename__ = 'documents'
    
    id = Column(Integer, primary_key=True)
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255))
    file_path = Column(String(500))
    redacted_file_path = Column(String(500))  # Path to redacted document
    file_size = Column(Integer)
    mime_type = Column(String(100))
    status = Column(String(20), default='uploaded')
    uploaded_by = Column(Integer)  # User ID who uploaded
    redaction_method = Column(String(50))  # Type of redaction applied
    redaction_date = Column(DateTime)  # When redaction was performed
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

class PIIDetectionResult(Base):
    __tablename__ = 'pii_detection_results'
    
    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, nullable=False)
    entity_type = Column(String(50), nullable=False)
    entity_text = Column(Text)
    confidence_score = Column(String(10))
    start_position = Column(Integer)
    end_position = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)

class BatchJob(Base):
    __tablename__ = 'batch_jobs'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    job_type = Column(String(50), default='pii_detection')
    status = Column(String(20), default='pending')
    progress = Column(Integer, default=0)
    total_documents = Column(Integer, default=0)
    processed_documents = Column(Integer, default=0)
    failed_documents = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)

class AuditLog(Base):
    __tablename__ = 'audit_logs'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))
    resource_id = Column(String(50))
    details = Column(Text)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class SystemSettings(Base):
    __tablename__ = 'system_settings'

    id = Column(Integer, primary_key=True)
    organization_name = Column(String(200), default='Healthcare Corp')
    timezone = Column(String(50), default='utc')
    auto_save_settings = Column(Boolean, default=True)
    dark_mode = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ProcessingSettings(Base):
    __tablename__ = 'processing_settings'

    id = Column(Integer, primary_key=True)
    default_redaction_method = Column(String(50), default='blackout')
    detection_sensitivity = Column(String(20), default='high')
    batch_processing_enabled = Column(Boolean, default=True)
    max_batch_size = Column(Integer, default=50)
    concurrent_jobs = Column(Integer, default=5)
    # PII Entity Types (JSON stored as string)
    enabled_pii_entities = Column(Text, default='["SSN","Email","Phone","Address","Credit Card","Passport","Driver License","Medical ID","Bank Account","Tax ID","Insurance Number","Date of Birth"]')
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ComplianceSettings(Base):
    __tablename__ = 'compliance_settings'

    id = Column(Integer, primary_key=True)
    gdpr_enabled = Column(Boolean, default=True)
    hipaa_enabled = Column(Boolean, default=True)
    pci_dss_enabled = Column(Boolean, default=False)
    data_retention_days = Column(Integer, default=2555)
    archive_after_days = Column(Integer, default=365)
    audit_logging_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SecuritySettings(Base):
    __tablename__ = 'security_settings'

    id = Column(Integer, primary_key=True)
    two_factor_enabled = Column(Boolean, default=True)
    session_timeout_enabled = Column(Boolean, default=True)
    session_duration_minutes = Column(Integer, default=60)
    max_login_attempts = Column(Integer, default=3)
    password_min_length = Column(Boolean, default=True)
    password_require_uppercase = Column(Boolean, default=True)
    password_require_special = Column(Boolean, default=True)
    password_require_numbers = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class NotificationSettings(Base):
    __tablename__ = 'notification_settings'

    id = Column(Integer, primary_key=True)
    email_notifications_enabled = Column(Boolean, default=True)
    job_completion_alerts = Column(Boolean, default=True)
    system_health_alerts = Column(Boolean, default=True)
    compliance_alerts = Column(Boolean, default=True)
    notification_email = Column(String(255), default='admin@healthcarecorp.com')
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Password hashing utility functions
def hash_password(password: str) -> str:
    """Hash a password using bcrypt or fallback method"""
    if PASSLIB_AVAILABLE:
        return pwd_context.hash(password)
    else:
        # Simple fallback - not recommended for production
        return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    if PASSLIB_AVAILABLE:
        return pwd_context.verify(plain_password, hashed_password)
    else:
        # Simple fallback verification
        return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password

def create_database():
    """Create the database and all tables"""
    try:
        # Ensure data directory exists
        data_dir = Path("./data")
        data_dir.mkdir(exist_ok=True)
        
        # Create engine
        engine = create_engine(DATABASE_URL, echo=True)
        
        # Create all tables
        Base.metadata.create_all(engine)
        
        logger.info("Database tables created successfully")
        
        # Create session factory
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        
        # Test connection
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            assert result.scalar() == 1
            logger.info("Database connection test successful")
        
        return engine, SessionLocal
        
    except Exception as e:
        logger.error(f"Database creation failed: {e}")
        raise

def populate_sample_data(SessionLocal):
    """Populate database with sample data"""
    try:
        db = SessionLocal()
        
        # Create sample user
        if not db.query(User).filter(User.username == "admin").first():
            admin_password = "admin123"  # Default password - should be changed in production
            admin_user = User(
                username="admin",
                email="admin@example.com",
                full_name="System Administrator",
                hashed_password=hash_password(admin_password),
                role="admin"
            )
            db.add(admin_user)
            logger.info("Default admin user created with username 'admin' and password 'admin123'")
        
        # Create sample documents
        if not db.query(Document).first():
            sample_doc = Document(
                filename="sample_document.txt",
                original_filename="sample_document.txt",
                file_path="./data/input/sample_document.txt",
                file_size=1024,
                mime_type="text/plain",
                status="processed"
            )
            db.add(sample_doc)
        
        # Create sample batch jobs
        if not db.query(BatchJob).first():
            job1 = BatchJob(
                name="Document Processing Job 1",
                status="completed",
                progress=100,
                total_documents=5,
                processed_documents=5,
                started_at=datetime(2024, 1, 1, 10, 0),
                completed_at=datetime(2024, 1, 1, 10, 5)
            )

            job2 = BatchJob(
                name="Document Processing Job 2",
                status="running",
                progress=45,
                total_documents=10,
                processed_documents=4,
                started_at=datetime(2024, 1, 1, 11, 0)
            )

            db.add(job1)
            db.add(job2)

        # Initialize default settings
        if not db.query(SystemSettings).first():
            system_settings = SystemSettings()
            db.add(system_settings)
            logger.info("Default system settings created")

        if not db.query(ProcessingSettings).first():
            processing_settings = ProcessingSettings()
            db.add(processing_settings)
            logger.info("Default processing settings created")

        if not db.query(ComplianceSettings).first():
            compliance_settings = ComplianceSettings()
            db.add(compliance_settings)
            logger.info("Default compliance settings created")

        if not db.query(SecuritySettings).first():
            security_settings = SecuritySettings()
            db.add(security_settings)
            logger.info("Default security settings created")

        if not db.query(NotificationSettings).first():
            notification_settings = NotificationSettings()
            db.add(notification_settings)
            logger.info("Default notification settings created")
        
        db.commit()
        db.close()
        
        logger.info("Sample data populated successfully")
        
    except Exception as e:
        logger.error(f"Failed to populate sample data: {e}")
        if 'db' in locals():
            db.rollback()
            db.close()
        raise

def test_database_operations(SessionLocal):
    """Test basic database operations"""
    try:
        db = SessionLocal()
        
        # Test user query
        users = db.query(User).all()
        logger.info(f"Found {len(users)} users in database")
        
        # Test document query
        documents = db.query(Document).all()
        logger.info(f"Found {len(documents)} documents in database")
        
        # Test batch job query
        jobs = db.query(BatchJob).all()
        logger.info(f"Found {len(jobs)} batch jobs in database")
        
        # Test joining tables
        job_with_docs = db.query(BatchJob).filter(BatchJob.status == "completed").first()
        if job_with_docs:
            logger.info(f"Found completed job: {job_with_docs.name}")
        
        db.close()
        
        logger.info("Database operations test successful")
        return True
        
    except Exception as e:
        logger.error(f"Database operations test failed: {e}")
        if 'db' in locals():
            db.close()
        return False

if __name__ == "__main__":
    print("Setting up AI De-identification System Database...")
    
    try:
        # Create database
        engine, SessionLocal = create_database()
        
        # Populate sample data
        populate_sample_data(SessionLocal)
        
        # Test operations
        success = test_database_operations(SessionLocal)
        
        if success:
            print("✅ Database setup completed successfully!")
            print(f"Database file: {Path('./data/pii_system.db').absolute()}")
            print("Tables created: users, documents, pii_detection_results, batch_jobs, audit_logs")
        else:
            print("❌ Database setup completed with errors")
            
    except Exception as e:
        print(f"❌ Database setup failed: {e}")