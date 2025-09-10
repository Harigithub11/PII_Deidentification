# Database Schema Documentation

This directory contains the complete PostgreSQL database schema for the PII De-identification System, including SQL files, SQLAlchemy ORM models, and Alembic migrations.

## Overview

The database schema is designed to support:
- **Audit Logging**: Comprehensive audit trail with immutable logs
- **Policy Management**: Flexible compliance policy framework (GDPR, HIPAA, NDHM)
- **Document Processing**: Metadata tracking and processing workflows
- **Security**: Row-level security, encryption, and access control
- **Performance**: Optimized indexes and partitioning strategies

## Directory Structure

```
database/
├── schema/                     # SQL schema definitions
│   ├── 001_core_tables.sql     # Core tables (users, sessions, lookups)
│   ├── 002_audit_tables.sql    # Audit logging tables
│   ├── 003_policy_tables.sql   # Policy management tables
│   ├── 004_metadata_tables.sql # Document and processing metadata
│   ├── 005_indexes.sql         # Performance indexes
│   └── 006_security.sql        # Security policies and permissions
├── migrations/                 # Alembic database migrations
│   ├── env.py                  # Migration environment setup
│   ├── alembic.ini             # Alembic configuration
│   ├── script.py.mako          # Migration template
│   └── 001_initial_schema.py   # Initial schema migration
└── README.md                   # This file
```

## Database Schema Components

### Core Tables
- **users**: User accounts with encrypted PII
- **user_sessions**: Active user sessions with security metadata
- **api_keys**: API key management with usage tracking
- **compliance_standards**: Supported compliance frameworks
- **pii_type_definitions**: Master PII type definitions
- **data_retention_schedules**: Data retention policies

### Audit Tables
- **audit_events**: Immutable audit log with integrity chain
- **audit_event_details**: Detailed event information
- **user_activities**: High-level user action tracking
- **system_events**: System-level events and errors
- **access_logs**: Detailed access logging
- **security_events**: Security incidents and monitoring
- **data_processing_logs**: GDPR-compliant processing logs

### Policy Management Tables
- **compliance_policies**: Master policy definitions
- **policy_rules**: Individual PII handling rules
- **policy_versions**: Policy change tracking
- **policy_applications**: Policy application logs
- **policy_rule_executions**: Detailed rule execution results

### Metadata Tables
- **document_metadata**: Comprehensive document information
- **processing_sessions**: Processing workflow tracking
- **session_documents**: Document-session relationships
- **file_storage**: File storage and lifecycle management
- **redaction_metadata**: Detailed redaction operations

## Key Features

### 1. Security and Privacy
- **Encryption**: All PII fields use application-level encryption
- **Row-Level Security**: Fine-grained access control
- **Audit Trail**: Complete immutable audit log
- **Data Classification**: Automatic sensitivity scoring

### 2. Compliance Support
- **Multi-Standard**: GDPR, HIPAA, NDHM support
- **Policy Framework**: Flexible rule-based policies
- **Retention Management**: Automated data retention
- **Breach Tracking**: Security incident management

### 3. Performance Optimization
- **Comprehensive Indexes**: Optimized for common queries
- **Partitioning Ready**: Designed for large-scale deployments
- **Query Optimization**: Efficient relationship structures
- **Monitoring Functions**: Built-in performance analysis

### 4. Data Integrity
- **Referential Integrity**: Proper foreign key relationships
- **Check Constraints**: Data validation at database level
- **Audit Chain**: Cryptographic integrity verification
- **Version Control**: Complete change history

## Installation and Setup

### 1. PostgreSQL Setup
```bash
# Create database
createdb pii_deidentification

# Create user (optional)
createuser -P pii_user
```

### 2. Schema Installation

#### Option A: Direct SQL Execution
```bash
# Execute schema files in order
psql -d pii_deidentification -f database/schema/001_core_tables.sql
psql -d pii_deidentification -f database/schema/002_audit_tables.sql
psql -d pii_deidentification -f database/schema/003_policy_tables.sql
psql -d pii_deidentification -f database/schema/004_metadata_tables.sql
psql -d pii_deidentification -f database/schema/005_indexes.sql
psql -d pii_deidentification -f database/schema/006_security.sql
```

#### Option B: Alembic Migration (Recommended)
```bash
# Install Python dependencies
pip install alembic sqlalchemy psycopg2-binary

# Set database URL
export DATABASE_URL="postgresql://username:password@localhost/pii_deidentification"

# Run migration
cd database/migrations
alembic upgrade head
```

### 3. Configuration

#### Environment Variables
```bash
# Database connection
DATABASE_URL="postgresql://username:password@localhost/pii_deidentification"
DATABASE_POOL_SIZE=10
DATABASE_ECHO=false

# Migration-specific URL (if different)
MIGRATION_DATABASE_URL="postgresql://admin:password@localhost/pii_deidentification"
```

## Usage Examples

### 1. Creating a New Migration
```bash
cd database/migrations
alembic revision --autogenerate -m "Add new feature"
alembic upgrade head
```

### 2. Rolling Back Migration
```bash
alembic downgrade -1  # Go back one migration
alembic downgrade base  # Go back to beginning
```

### 3. Using SQLAlchemy Models
```python
from src.core.database.models import User, AuditEvent
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Create session
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Query users
users = session.query(User).filter(User.is_active == True).all()

# Create audit event
audit_event = AuditEvent(
    event_id="USR-001",
    event_type="user_login",
    severity="medium",
    outcome="success",
    user_id=user.id,
    event_description="User logged in successfully"
)
session.add(audit_event)
session.commit()
```

## Security Considerations

### 1. Row-Level Security (RLS)
- Enabled on all sensitive tables
- User context required for access
- Role-based access control

### 2. Data Encryption
- PII fields encrypted at application level
- Encryption keys managed securely
- Support for key rotation

### 3. Audit Requirements
- All data access logged
- Immutable audit trail
- Compliance reporting support

## Performance Guidelines

### 1. Index Usage
- Use provided indexes for queries
- Monitor index usage with built-in functions
- Consider additional indexes for custom queries

### 2. Partitioning
- Audit tables designed for monthly partitioning
- Document metadata can be partitioned by date
- Consider partitioning for large deployments

### 3. Maintenance
- Regular `VACUUM` and `ANALYZE`
- Index maintenance functions provided
- Automated cleanup procedures available

## Monitoring and Maintenance

### 1. Health Checks
```sql
-- Check table sizes
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) 
FROM pg_tables WHERE schemaname = 'public' ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Check index usage
SELECT * FROM analyze_index_usage();

-- Find unused indexes
SELECT * FROM find_unused_indexes();
```

### 2. Performance Analysis
```sql
-- Query performance
SELECT query, mean_time, calls, total_time 
FROM pg_stat_statements 
ORDER BY mean_time DESC LIMIT 10;

-- Table statistics
SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del, last_analyze
FROM pg_stat_user_tables 
WHERE schemaname = 'public';
```

### 3. Security Monitoring
```sql
-- Security dashboard
SELECT * FROM security_dashboard;

-- Compliance status
SELECT * FROM compliance_status;

-- Recent security events
SELECT event_type, severity, COUNT(*) 
FROM security_events 
WHERE event_timestamp >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY event_type, severity
ORDER BY COUNT(*) DESC;
```

## Troubleshooting

### Common Issues

1. **Migration Conflicts**
   - Ensure database is in clean state
   - Check for manual schema changes
   - Use `alembic history` to verify state

2. **Permission Errors**
   - Verify database user permissions
   - Check RLS policies are properly configured
   - Ensure application user context is set

3. **Performance Issues**
   - Run `ANALYZE` on affected tables
   - Check for missing indexes
   - Review query execution plans

4. **Encryption Issues**
   - Verify encryption keys are properly configured
   - Check application-level encryption setup
   - Ensure encrypted fields are handled correctly

## Support and Documentation

- **Database Documentation**: See inline SQL comments
- **Model Documentation**: Check SQLAlchemy model docstrings  
- **Migration Logs**: Review Alembic migration history
- **Performance Metrics**: Use built-in monitoring functions

## Contributing

When modifying the schema:

1. **Create Migration**: Always use Alembic migrations for changes
2. **Update Models**: Keep SQLAlchemy models in sync
3. **Test Thoroughly**: Verify migrations work both up and down
4. **Document Changes**: Update this README and inline comments
5. **Performance Impact**: Consider index and query impact

## License

This database schema is part of the PII De-identification System and follows the same licensing terms as the main project.