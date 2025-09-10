# Production Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the Local AI-Powered De-identification System in a production environment with full HIPAA compliance.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Infrastructure Requirements](#infrastructure-requirements)
3. [Security Configuration](#security-configuration)
4. [Database Setup](#database-setup)
5. [Application Deployment](#application-deployment)
6. [Monitoring Setup](#monitoring-setup)
7. [Compliance Configuration](#compliance-configuration)
8. [Testing and Validation](#testing-and-validation)
9. [Go-Live Checklist](#go-live-checklist)
10. [Maintenance and Operations](#maintenance-and-operations)

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+ or RHEL 8+) or Windows Server 2019+
- **Memory**: Minimum 16GB RAM (32GB recommended)
- **Storage**: Minimum 500GB SSD (1TB recommended)
- **CPU**: Minimum 8 cores (16 cores recommended)
- **Network**: 1Gbps network connection

### Software Requirements

- **Python**: 3.8 or higher
- **Docker**: 20.10 or higher (for containerized deployment)
- **PostgreSQL**: 13 or higher
- **Redis**: 6.0 or higher
- **Nginx**: 1.18 or higher
- **SSL Certificate**: Valid SSL certificate for HTTPS

### Compliance Requirements

- **HIPAA Compliance**: Ensure hosting environment meets HIPAA requirements
- **BAA**: Execute Business Associate Agreement with hosting provider
- **Audit Logging**: Centralized audit logging capability
- **Backup and Recovery**: HIPAA-compliant backup and recovery procedures

## Infrastructure Requirements

### Network Architecture

```
Internet
    │
    ▼
[Load Balancer / WAF]
    │
    ▼
[Reverse Proxy (Nginx)]
    │
    ▼
[Application Servers] ←→ [Database Cluster]
    │                      │
    ▼                      ▼
[Redis Cache]         [Backup Storage]
    │
    ▼
[Monitoring & Logging]
```

### Security Zones

- **DMZ**: Web application firewall, load balancer
- **Application Tier**: Application servers, reverse proxy
- **Data Tier**: Database servers, Redis cache
- **Management Tier**: Monitoring, logging, backup systems

### High Availability Configuration

- **Load Balancing**: Active-active load balancing across multiple app servers
- **Database**: Master-slave replication with automatic failover
- **Storage**: RAID configuration with hot spares
- **Network**: Redundant network connections

## Security Configuration

### Firewall Rules

```bash
# Allow HTTPS traffic
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow SSH from management network only
iptables -A INPUT -p tcp --dport 22 -s 10.0.100.0/24 -j ACCEPT

# Allow database access from app servers only
iptables -A INPUT -p tcp --dport 5432 -s 10.0.1.0/24 -j ACCEPT

# Allow Redis access from app servers only
iptables -A INPUT -p tcp --dport 6379 -s 10.0.1.0/24 -j ACCEPT

# Drop all other traffic
iptables -P INPUT DROP
iptables -P FORWARD DROP
```

### SSL/TLS Configuration

#### Nginx SSL Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Certificate
    ssl_certificate /etc/ssl/certs/your-domain.crt;
    ssl_certificate_key /etc/ssl/private/your-domain.key;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://app-servers;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Certificate Management

```bash
# Install Let's Encrypt Certbot
sudo apt-get install certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com

# Set up automatic renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## Database Setup

### PostgreSQL Installation and Configuration

```bash
# Install PostgreSQL
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql
CREATE DATABASE deidentification_db;
CREATE USER deident_user WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE deidentification_db TO deident_user;
\q
```

### Database Security Configuration

```bash
# Edit postgresql.conf
sudo nano /etc/postgresql/13/main/postgresql.conf

# Configure security settings
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'
shared_preload_libraries = 'pg_stat_statements'
log_statement = 'all'
log_min_duration_statement = 0
```

### Database Encryption

```sql
-- Enable transparent data encryption
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create encrypted columns
ALTER TABLE processed_documents ADD COLUMN encrypted_content BYTEA;
UPDATE processed_documents SET encrypted_content = pgp_sym_encrypt(content, 'encryption_key');
ALTER TABLE processed_documents DROP COLUMN content;
```

### Backup Configuration

```bash
#!/bin/bash
# Database backup script

BACKUP_DIR="/backup/postgresql"
DATE=$(date +"%Y%m%d_%H%M%S")
DB_NAME="deidentification_db"

# Create encrypted backup
pg_dump -h localhost -U deident_user $DB_NAME | \
gpg --symmetric --cipher-algo AES256 --compress-algo 1 --output $BACKUP_DIR/backup_$DATE.sql.gpg

# Upload to secure storage
aws s3 cp $BACKUP_DIR/backup_$DATE.sql.gpg s3://secure-backup-bucket/

# Cleanup local backups older than 7 days
find $BACKUP_DIR -name "backup_*.sql.gpg" -mtime +7 -delete
```

## Application Deployment

### Docker Deployment

#### Dockerfile

```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

#### Docker Compose Production

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://deident_user:${DB_PASSWORD}@db:5432/deidentification_db
      - REDIS_URL=redis://redis:6379
      - SECRET_KEY=${SECRET_KEY}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
    depends_on:
      - db
      - redis
    restart: always
    volumes:
      - ./logs:/app/logs
      - ./uploads:/app/uploads

  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=deidentification_db
      - POSTGRES_USER=deident_user
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./config/postgresql.conf:/etc/postgresql/postgresql.conf
    restart: always

  redis:
    image: redis:6-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    restart: always

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./config/nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl
    depends_on:
      - app
    restart: always

volumes:
  postgres_data:
```

### Environment Configuration

Create `.env` file:

```env
# Database Configuration
DATABASE_URL=postgresql://deident_user:secure_password@localhost:5432/deidentification_db
DB_PASSWORD=secure_password

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=secure_redis_password

# Security Configuration
SECRET_KEY=your-secret-key-here
ENCRYPTION_KEY=your-encryption-key-here
JWT_SECRET=your-jwt-secret-here

# HIPAA Compliance
AUDIT_LOG_RETENTION_DAYS=2555  # 7 years
COMPLIANCE_MODE=production
MONITORING_ENABLED=true

# Email Configuration
SMTP_SERVER=smtp.yourdomain.com
SMTP_PORT=587
SMTP_USER=alerts@yourdomain.com
SMTP_PASSWORD=smtp_password

# Logging Configuration
LOG_LEVEL=INFO
LOG_FORMAT=json
AUDIT_LOG_PATH=/var/log/deidentification/audit.log
```

### Application Configuration

```python
# config/production.py
import os
from typing import Optional

class ProductionConfig:
    # Database
    DATABASE_URL = os.getenv("DATABASE_URL")
    
    # Security
    SECRET_KEY = os.getenv("SECRET_KEY")
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
    JWT_SECRET = os.getenv("JWT_SECRET")
    
    # HIPAA Compliance
    HIPAA_COMPLIANCE_MODE = True
    AUDIT_LOGGING_ENABLED = True
    ENCRYPTION_REQUIRED = True
    
    # Performance
    MAX_WORKERS = 8
    REQUEST_TIMEOUT = 300
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    
    # Monitoring
    MONITORING_ENABLED = True
    ALERT_EMAIL = os.getenv("ALERT_EMAIL")
    
    # Backup
    BACKUP_ENABLED = True
    BACKUP_SCHEDULE = "0 2 * * *"  # Daily at 2 AM
```

## Monitoring Setup

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'deidentification-app'
    static_configs:
      - targets: ['app:8000']
    metrics_path: '/metrics'
    
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']
      
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
      
  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']
```

### Grafana Dashboard Configuration

```json
{
  "dashboard": {
    "title": "HIPAA De-identification System",
    "panels": [
      {
        "title": "Compliance Score",
        "type": "stat",
        "targets": [
          {
            "expr": "compliance_score",
            "legendFormat": "Compliance Score"
          }
        ]
      },
      {
        "title": "Processing Volume",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(documents_processed_total[5m])",
            "legendFormat": "Documents/sec"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, http_request_duration_seconds_bucket)",
            "legendFormat": "95th percentile"
          }
        ]
      }
    ]
  }
}
```

### Log Management

#### Fluentd Configuration

```yaml
# fluentd.conf
<source>
  @type tail
  path /var/log/deidentification/audit.log
  pos_file /var/log/fluentd/audit.log.pos
  tag audit.deidentification
  format json
</source>

<source>
  @type tail
  path /var/log/deidentification/application.log
  pos_file /var/log/fluentd/application.log.pos
  tag app.deidentification
  format json
</source>

<match **>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name deidentification-logs
  type_name _doc
</match>
```

## Compliance Configuration

### Audit Logging Configuration

```python
# audit_config.py
AUDIT_EVENTS = [
    'document_processing',
    'phi_detection',
    'user_authentication',
    'data_access',
    'configuration_change',
    'system_startup',
    'system_shutdown',
    'backup_creation',
    'backup_restoration'
]

AUDIT_LOG_FORMAT = {
    'timestamp': 'iso8601',
    'event_type': 'string',
    'user_id': 'string',
    'session_id': 'string',
    'source_ip': 'string',
    'resource_accessed': 'string',
    'action': 'string',
    'outcome': 'string',
    'additional_data': 'json'
}

RETENTION_POLICIES = {
    'audit_logs': 2555,  # 7 years in days
    'access_logs': 1095,  # 3 years in days
    'performance_logs': 365  # 1 year in days
}
```

### Encryption Configuration

```python
# encryption_config.py
from cryptography.fernet import Fernet
import os

class EncryptionConfig:
    # AES-256 encryption key
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
    
    # Key rotation schedule
    KEY_ROTATION_SCHEDULE = 90  # days
    
    # Encryption algorithms
    SUPPORTED_ALGORITHMS = [
        'AES-256-GCM',
        'AES-256-CBC',
        'RSA-2048',
        'RSA-4096'
    ]
    
    # Database encryption
    DB_ENCRYPTION_ENABLED = True
    DB_ENCRYPTION_ALGORITHM = 'AES-256-GCM'
    
    # File encryption
    FILE_ENCRYPTION_ENABLED = True
    FILE_ENCRYPTION_ALGORITHM = 'AES-256-GCM'
    
    # Transit encryption
    TLS_VERSION = 'TLSv1.3'
    CIPHER_SUITES = [
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256'
    ]
```

## Testing and Validation

### Pre-Deployment Testing

```bash
#!/bin/bash
# Pre-deployment test suite

echo "Running pre-deployment tests..."

# 1. System requirements check
python scripts/check_requirements.py

# 2. Configuration validation
python scripts/validate_config.py

# 3. Database connectivity test
python scripts/test_database.py

# 4. Security configuration test
python scripts/test_security.py

# 5. Compliance test suite
pytest tests/test_hipaa_compliance.py -v

# 6. Performance test
pytest tests/test_performance.py -v

# 7. Integration test
pytest tests/test_integration.py -v

echo "Pre-deployment tests completed."
```

### Health Check Endpoints

```python
# health_check.py
from fastapi import APIRouter, HTTPException
import psutil
import asyncio

router = APIRouter()

@router.get("/health")
async def health_check():
    checks = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": {}
    }
    
    # Database connectivity
    try:
        await database.execute("SELECT 1")
        checks["checks"]["database"] = "healthy"
    except Exception as e:
        checks["checks"]["database"] = "unhealthy"
        checks["status"] = "degraded"
    
    # Redis connectivity
    try:
        await redis.ping()
        checks["checks"]["redis"] = "healthy"
    except Exception as e:
        checks["checks"]["redis"] = "unhealthy"
        checks["status"] = "degraded"
    
    # System resources
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    checks["checks"]["memory"] = {
        "status": "healthy" if memory.percent < 80 else "warning",
        "usage_percent": memory.percent
    }
    
    checks["checks"]["disk"] = {
        "status": "healthy" if disk.percent < 80 else "warning",
        "usage_percent": disk.percent
    }
    
    return checks
```

### Load Testing

```bash
#!/bin/bash
# Load testing script using Apache Bench

echo "Starting load test..."

# Test 1: Basic load test
ab -n 1000 -c 10 -H "Authorization: Bearer ${JWT_TOKEN}" \
   https://your-domain.com/api/v1/deidentify

# Test 2: High concurrency test
ab -n 5000 -c 50 -H "Authorization: Bearer ${JWT_TOKEN}" \
   https://your-domain.com/api/v1/deidentify

# Test 3: Sustained load test
ab -n 10000 -c 25 -t 300 -H "Authorization: Bearer ${JWT_TOKEN}" \
   https://your-domain.com/api/v1/deidentify

echo "Load test completed."
```

## Go-Live Checklist

### Security Checklist

- [ ] SSL certificates installed and configured
- [ ] Firewall rules implemented and tested
- [ ] Database encryption enabled and verified
- [ ] Password policies enforced
- [ ] Multi-factor authentication configured
- [ ] Security headers implemented
- [ ] Vulnerability scan completed with no critical issues
- [ ] Penetration testing completed
- [ ] Security incident response plan in place

### Compliance Checklist

- [ ] HIPAA compliance assessment completed
- [ ] Business Associate Agreements executed
- [ ] Audit logging enabled and tested
- [ ] Data retention policies implemented
- [ ] Backup and recovery procedures tested
- [ ] Disaster recovery plan documented
- [ ] Compliance monitoring enabled
- [ ] Staff training completed
- [ ] Policies and procedures documented

### Operational Checklist

- [ ] Application deployed and tested
- [ ] Database configured and optimized
- [ ] Monitoring and alerting configured
- [ ] Log management system operational
- [ ] Backup system configured and tested
- [ ] Performance testing completed
- [ ] Load balancing configured
- [ ] Health checks implemented
- [ ] Documentation updated

### Performance Checklist

- [ ] Response time requirements met (< 5 seconds)
- [ ] Throughput requirements met (> 10 docs/sec)
- [ ] Availability target met (> 99.9%)
- [ ] Resource utilization optimized
- [ ] Scalability testing completed
- [ ] Database performance optimized
- [ ] CDN configured (if applicable)
- [ ] Caching strategy implemented

## Maintenance and Operations

### Regular Maintenance Tasks

#### Daily Tasks
- [ ] Monitor system health and performance
- [ ] Review security alerts and incidents
- [ ] Check backup completion status
- [ ] Monitor compliance metrics
- [ ] Review audit logs for anomalies

#### Weekly Tasks
- [ ] Review performance metrics and trends
- [ ] Analyze security logs
- [ ] Test backup restoration procedures
- [ ] Update security signatures and rules
- [ ] Review capacity utilization

#### Monthly Tasks
- [ ] Security patch assessment and installation
- [ ] Performance tuning and optimization
- [ ] Compliance reporting
- [ ] Capacity planning review
- [ ] Disaster recovery testing

#### Quarterly Tasks
- [ ] Comprehensive security assessment
- [ ] HIPAA compliance audit
- [ ] Business continuity plan testing
- [ ] Performance benchmark testing
- [ ] Documentation review and updates

### Backup and Recovery Procedures

#### Backup Schedule
- **Full Backup**: Daily at 2:00 AM
- **Incremental Backup**: Every 6 hours
- **Transaction Log Backup**: Every 15 minutes
- **Configuration Backup**: After any changes

#### Recovery Procedures

```bash
#!/bin/bash
# Database recovery procedure

# 1. Stop application
systemctl stop deidentification-app

# 2. Restore database
pg_restore -h localhost -U postgres -d deidentification_db backup_file.sql

# 3. Verify data integrity
psql -h localhost -U postgres -d deidentification_db -c "SELECT count(*) FROM processed_documents;"

# 4. Start application
systemctl start deidentification-app

# 5. Verify system functionality
curl -f https://your-domain.com/health || exit 1
```

### Security Incident Response

#### Incident Classification
- **P1**: Critical security incident (data breach, system compromise)
- **P2**: High security incident (failed authentication attempts, malware detection)
- **P3**: Medium security incident (policy violation, suspicious activity)
- **P4**: Low security incident (informational alerts)

#### Response Procedures

1. **Detection and Analysis**
   - Monitor security alerts and logs
   - Investigate and classify incidents
   - Document findings and evidence

2. **Containment and Eradication**
   - Isolate affected systems
   - Remove threats and vulnerabilities
   - Patch security weaknesses

3. **Recovery and Lessons Learned**
   - Restore services to normal operation
   - Monitor for recurring issues
   - Update procedures and controls

### Performance Optimization

#### Application Tuning
- Optimize database queries and indexes
- Implement caching strategies
- Tune application server settings
- Optimize resource allocation

#### Database Tuning
- Regular VACUUM and ANALYZE operations
- Index optimization and maintenance
- Query performance analysis
- Connection pooling configuration

#### Infrastructure Tuning
- Load balancer optimization
- Network configuration tuning
- Storage performance optimization
- Memory and CPU utilization tuning

### Troubleshooting Guide

#### Common Issues and Solutions

**Issue**: High response times
```bash
# Check system resources
top
iostat -x 1
free -m

# Check database performance
SELECT * FROM pg_stat_activity WHERE state = 'active';
SELECT * FROM pg_stat_user_tables ORDER BY seq_tup_read DESC;

# Check application logs
tail -f /var/log/deidentification/application.log
```

**Issue**: Database connectivity problems
```bash
# Check database status
systemctl status postgresql
pg_isready -h localhost -p 5432

# Check connections
SELECT count(*) FROM pg_stat_activity;
SELECT state, count(*) FROM pg_stat_activity GROUP BY state;

# Check configuration
cat /etc/postgresql/13/main/postgresql.conf | grep listen
```

**Issue**: SSL certificate issues
```bash
# Check certificate validity
openssl x509 -in /etc/ssl/certs/your-domain.crt -text -noout
openssl x509 -in /etc/ssl/certs/your-domain.crt -checkend 86400

# Test SSL configuration
openssl s_client -connect your-domain.com:443
```

### Contact Information

#### Emergency Contacts
- **System Administrator**: admin@yourdomain.com
- **Security Officer**: security@yourdomain.com
- **Compliance Officer**: compliance@yourdomain.com
- **On-call Engineer**: +1-555-123-4567

#### Support Resources
- **Documentation**: https://docs.yourdomain.com
- **Issue Tracking**: https://support.yourdomain.com
- **Knowledge Base**: https://kb.yourdomain.com

---

**Document Version**: 1.0  
**Last Updated**: December 2024  
**Next Review**: June 2025