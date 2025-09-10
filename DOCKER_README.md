# Docker Containerization Guide

This document provides comprehensive instructions for deploying the PII De-identification System using Docker containers.

## 🐳 Overview

The containerized deployment includes:
- **Main API Application** - FastAPI-based REST API
- **PostgreSQL Database** - Primary data storage
- **Redis** - Caching and message broker
- **Celery Workers** - Background task processing
- **Airflow** - Workflow orchestration
- **Frontend** - React-based web interface
- **Monitoring Stack** - Prometheus + Grafana (optional)

## 📋 Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 8GB+ RAM recommended
- 20GB+ available disk space

### Quick Setup

```bash
# Automated setup (recommended)
chmod +x docker-setup.sh
./docker-setup.sh
```

## 🚀 Quick Start

### Development Environment

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Build and start services
docker-compose up -d

# 3. Access the application
# API: http://localhost:8000
# Frontend: http://localhost:3000
# Airflow: http://localhost:8080
```

### Production Environment

```bash
# 1. Setup production environment
cp .env.production .env
# Edit .env with your production settings

# 2. Use production deployment script
./docker-deploy.sh production up

# 3. Enable monitoring (optional)
docker-compose --profile monitoring up -d
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Load Balancer (Nginx)                   │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────┴───────────────────────────────────┐
│                    API Layer (FastAPI)                     │
├─────────────────────────────────────────────────────────────┤
│                 Background Processing                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐│
│  │   Celery    │ │   Airflow   │ │    Component Monitor    ││
│  │   Workers   │ │  Scheduler  │ │      & Alerts          ││
│  └─────────────┘ └─────────────┘ └─────────────────────────┘│
├─────────────────────────────────────────────────────────────┤
│                  Storage & Cache Layer                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐│
│  │ PostgreSQL  │ │    Redis    │ │     File Storage       ││
│  │  Database   │ │    Cache    │ │    (Encrypted)         ││
│  └─────────────┘ └─────────────┘ └─────────────────────────┘│
├─────────────────────────────────────────────────────────────┤
│               Monitoring & Observability                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐│
│  │ Prometheus  │ │   Grafana   │ │     Health Checks      ││
│  │   Metrics   │ │ Dashboards  │ │     & Alerting         ││
│  └─────────────┘ └─────────────┘ └─────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## 📁 File Structure

```
docker/
├── Dockerfile.api          # Main application container
├── Dockerfile.worker       # Airflow worker container
├── Dockerfile.frontend     # React frontend container
├── nginx.conf              # Nginx configuration
├── nginx-prod.conf         # Production Nginx config
├── init-db.sql             # Database initialization
├── prometheus.yml          # Metrics collection config
├── grafana-datasources.yml # Grafana data sources
└── redis-prod.conf         # Production Redis config

docker-compose.yml          # Main compose file
docker-compose.prod.yml     # Production compose file
docker-compose.override.yml # Development overrides

.env.docker                 # Docker environment template
.env.production            # Production environment template

docker-setup.sh            # Automated setup script
docker-build.sh            # Build automation script
docker-deploy.sh           # Deployment management script
```

## ⚙️ Configuration

### Environment Variables

Key environment variables to configure:

```bash
# Security (REQUIRED - Change in production)
SECRET_KEY=your-super-secret-key-change-in-production
POSTGRES_PASSWORD=secure-database-password
REDIS_PASSWORD=secure-redis-password
AIRFLOW_FERNET_KEY=base64-encoded-fernet-key

# Application Settings
DEBUG=false
LOG_LEVEL=INFO
ENABLE_GPU=false

# Database
DATABASE_URL=postgresql://user:pass@postgres:5432/pii_system
DATABASE_POOL_SIZE=10

# Processing
MAX_CONCURRENT_JOBS=4
CELERY_WORKER_CONCURRENCY=2

# Monitoring
COMPONENT_MONITORING_ENABLED=true
ENABLE_METRICS=true
```

### Service Ports

| Service | Port | Description |
|---------|------|-------------|
| API | 8000 | Main application API |
| Frontend | 3000 | React web interface |
| Airflow | 8080 | Workflow management |
| PostgreSQL | 5432 | Database (internal) |
| Redis | 6379 | Cache/broker (internal) |
| Prometheus | 9090 | Metrics collection |
| Grafana | 3001 | Monitoring dashboards |

## 🚢 Deployment

### Development Deployment

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Scale services
docker-compose up -d --scale api=2 --scale celery-worker=3

# Stop services
docker-compose down
```

### Production Deployment

```bash
# Use production compose file
docker-compose -f docker-compose.prod.yml up -d

# Or use deployment script
./docker-deploy.sh production up

# Enable monitoring stack
docker-compose -f docker-compose.prod.yml --profile monitoring up -d
```

### Health Checks

```bash
# Check service health
docker-compose ps

# API health
curl http://localhost:8000/health

# Component monitoring
curl http://localhost:8000/api/v1/components/health/summary

# Database connectivity
docker-compose exec postgres pg_isready
```

## 📊 Monitoring

### Built-in Monitoring

The system includes comprehensive monitoring:

- **Component Health Monitoring** - 104+ system components
- **API Performance Metrics** - Response times, error rates
- **Resource Usage** - CPU, memory, disk usage
- **Business Metrics** - Documents processed, PII detected

### Access Monitoring Dashboards

```bash
# Component monitoring dashboard
http://localhost:8000/api/v1/components/system/status

# Prometheus metrics
http://localhost:9090

# Grafana dashboards (if enabled)
http://localhost:3001
# Default: admin / admin123
```

### Key Metrics

- Documents processed per hour
- PII detection accuracy rates
- System resource utilization
- API response times
- Error rates and failures

## 🔧 Maintenance

### Backup and Restore

```bash
# Create backup
./docker-deploy.sh production backup

# List backups
ls -la backups/

# Restore from backup
./docker-deploy.sh production restore backups/20231201_120000/
```

### Log Management

```bash
# View service logs
docker-compose logs -f [service-name]

# Application logs
docker-compose logs -f api

# Database logs
docker-compose logs -f postgres

# Worker logs
docker-compose logs -f celery-worker
```

### Updates and Upgrades

```bash
# Pull latest images
docker-compose pull

# Rebuild and restart
docker-compose up -d --build

# Rolling update (production)
docker-compose -f docker-compose.prod.yml up -d --scale api=2
# Wait for health checks
docker-compose -f docker-compose.prod.yml up -d --scale api=1
```

## 🔒 Security

### Production Security Checklist

- [ ] Change all default passwords and secrets
- [ ] Use secure environment variables
- [ ] Enable SSL/TLS certificates
- [ ] Configure firewall rules
- [ ] Set up reverse proxy with security headers
- [ ] Enable audit logging
- [ ] Configure backup encryption
- [ ] Set up monitoring alerts

### Security Features

- **Encrypted Data Storage** - All PII data encrypted at rest
- **Secure Communication** - TLS encryption for API endpoints
- **Access Control** - Role-based authentication and authorization
- **Audit Logging** - Complete audit trail of all operations
- **Input Validation** - Comprehensive input sanitization
- **Rate Limiting** - Protection against abuse

## 🐛 Troubleshooting

### Common Issues

#### Services Won't Start
```bash
# Check Docker daemon
docker info

# Check compose file syntax
docker-compose config

# View detailed logs
docker-compose logs
```

#### Database Connection Issues
```bash
# Check database status
docker-compose exec postgres pg_isready

# Reset database
docker-compose down -v
docker-compose up -d postgres
```

#### Memory Issues
```bash
# Check container resource usage
docker stats

# Increase Docker memory limits
# Docker Desktop: Settings > Resources > Memory
```

#### Model Loading Issues
```bash
# Check model directory permissions
docker-compose exec api ls -la /app/models/

# Rebuild with fresh models
docker-compose down
docker volume rm pii-de-identification_app_models
docker-compose up -d
```

### Performance Tuning

#### Database Optimization
```bash
# Increase connection pool
DATABASE_POOL_SIZE=20

# Enable query optimization
DATABASE_ECHO=false
```

#### Worker Scaling
```bash
# Increase worker concurrency
CELERY_WORKER_CONCURRENCY=4
MAX_CONCURRENT_JOBS=8

# Scale worker containers
docker-compose up -d --scale celery-worker=3
```

#### Memory Management
```bash
# Limit container memory
deploy:
  resources:
    limits:
      memory: 4G
      cpus: '2.0'
```

## 📞 Support

### Getting Help

1. **Check Logs**: Always start with service logs
2. **Health Endpoints**: Use built-in health checks
3. **Component Monitor**: Check system component status
4. **Documentation**: Review API documentation at `/docs`

### Useful Commands

```bash
# Complete system health check
curl http://localhost:8000/api/v1/components/system/status

# Service status
docker-compose ps

# Resource usage
docker stats

# Clean up unused resources
docker system prune -a --volumes
```

## 🎯 Best Practices

### Development
- Use development override file for local changes
- Mount source code as volumes for hot reloading
- Use separate databases for dev/test/prod
- Enable debug logging and endpoints

### Production
- Use production compose file with resource limits
- Enable monitoring and alerting
- Set up automated backups
- Use load balancers for high availability
- Implement proper secret management
- Regular security updates

### Scaling
- Monitor resource usage continuously
- Scale services based on load patterns
- Use horizontal scaling for stateless services
- Consider container orchestration (Kubernetes) for large deployments

---

**🛡️ Built with ❤️ by Team 404fixed! - Secure, Scalable, and Production-Ready**