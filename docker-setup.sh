#!/bin/bash

# Docker Setup Script for PII De-identification System
# This script handles initial setup and configuration

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}   PII De-identification Setup       ${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Function to print status
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to generate secure random string
generate_secret() {
    local length=${1:-32}
    openssl rand -hex "$length" 2>/dev/null || head -c "$length" /dev/urandom | od -A n -t x1 | tr -d ' \n'
}

# Function to generate Fernet key for Airflow
generate_fernet_key() {
    python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || \
    echo "your-fernet-key-change-in-production-must-be-32-url-safe-base64-encoded-bytes"
}

print_status "Starting Docker setup for PII De-identification System..."

# Check prerequisites
print_status "Checking prerequisites..."

# Check Docker
if ! command -v docker > /dev/null 2>&1; then
    print_error "Docker is not installed. Please install Docker first."
    echo "Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose > /dev/null 2>&1; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    echo "Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

print_status "✅ All prerequisites met"

# Create necessary directories
print_status "Creating directory structure..."
mkdir -p {data/{input,processing,output,audit,temp},models/{cache,downloads},logs,backups,config/policies,orchestration}
print_status "✅ Directory structure created"

# Setup environment file
print_status "Setting up environment configuration..."

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        print_status "Copied .env.example to .env"
    elif [ -f "env.example" ]; then
        cp env.example .env
        print_status "Copied env.example to .env"
    else
        print_warning "No example environment file found, creating basic .env"
        cat > .env << EOF
# Basic configuration - customize as needed
DEBUG=true
SECRET_KEY=$(generate_secret)
POSTGRES_PASSWORD=$(generate_secret 16)
REDIS_PASSWORD=$(generate_secret 16)
AIRFLOW_FERNET_KEY=$(generate_fernet_key)
AIRFLOW_SECRET_KEY=$(generate_secret)
EOF
    fi
    
    # Generate secure secrets if they don't exist
    print_status "Generating secure secrets..."
    
    # Replace default secrets with secure ones
    sed -i.bak "s/your-secret-key-here-change-in-production/$(generate_secret)/g" .env
    sed -i.bak "s/your-encryption-key-here-change-in-production/$(generate_secret)/g" .env
    sed -i.bak "s/pii_secure_password/$(generate_secret 16)/g" .env
    sed -i.bak "s/redis_secure_password/$(generate_secret 16)/g" .env
    sed -i.bak "s/your-fernet-key-change-in-production/$(generate_fernet_key)/g" .env
    sed -i.bak "s/your-airflow-secret-key/$(generate_secret)/g" .env
    
    # Remove backup file
    rm -f .env.bak
    
    print_status "✅ Environment file configured with secure secrets"
else
    print_warning ".env file already exists, skipping creation"
fi

# Setup docker-compose override for development
if [ ! -f "docker-compose.override.yml" ]; then
    print_status "Creating development override..."
    cat > docker-compose.override.yml << 'EOF'
version: '3.8'

services:
  api:
    volumes:
      - ./src:/app/src:ro
      - ./config:/app/config:ro
    environment:
      - DEBUG=true
      - LOG_LEVEL=DEBUG
      - ENABLE_RELOAD=true
    ports:
      - "8000:8000"

  celery-worker:
    volumes:
      - ./src:/app/src:ro
      - ./config:/app/config:ro
    environment:
      - DEBUG=true
      - LOG_LEVEL=DEBUG

  airflow-webserver:
    volumes:
      - ./orchestration:/opt/airflow/dags
      - ./src:/opt/airflow/src:ro
    environment:
      - AIRFLOW__WEBSERVER__RELOAD_ON_PLUGIN_CHANGE=True

  frontend:
    environment:
      - CHOKIDAR_USEPOLLING=true
    volumes:
      - ./frontend/src:/app/src:ro
EOF
    print_status "✅ Development override created"
fi

# Create initial configuration files
print_status "Creating configuration files..."

# Create a basic policy configuration
if [ ! -f "config/policies/default.yml" ]; then
    mkdir -p config/policies
    cat > config/policies/default.yml << 'EOF'
# Default PII Detection Policy
name: "Default Policy"
version: "1.0"
description: "Default policy for PII detection and anonymization"

pii_types:
  - name: "email"
    enabled: true
    confidence_threshold: 0.8
    anonymization: "mask"
  
  - name: "phone"
    enabled: true
    confidence_threshold: 0.8
    anonymization: "redact"
  
  - name: "ssn"
    enabled: true
    confidence_threshold: 0.9
    anonymization: "redact"
  
  - name: "credit_card"
    enabled: true
    confidence_threshold: 0.9
    anonymization: "redact"

processing:
  enable_ocr: true
  enable_visual_detection: true
  enable_context_analysis: true
  batch_size: 10
  timeout_minutes: 30
EOF
    print_status "✅ Default policy configuration created"
fi

# Create orchestration directory with sample DAG
if [ ! -f "orchestration/sample_dag.py" ]; then
    cat > orchestration/sample_dag.py << 'EOF'
"""
Sample Airflow DAG for PII De-identification System
"""
from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator

default_args = {
    'owner': 'pii-system',
    'depends_on_past': False,
    'start_date': datetime(2023, 1, 1),
    'email_on_failure': False,
    'email_on_retry': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=5)
}

dag = DAG(
    'sample_pii_processing',
    default_args=default_args,
    description='Sample PII processing workflow',
    schedule_interval=timedelta(days=1),
    catchup=False
)

def hello_world():
    print("Hello from PII De-identification System!")

hello_task = PythonOperator(
    task_id='hello_world',
    python_callable=hello_world,
    dag=dag
)
EOF
    print_status "✅ Sample Airflow DAG created"
fi

# Set proper permissions
print_status "Setting permissions..."
chmod +x docker-build.sh docker-deploy.sh
chmod 755 data/ logs/ models/ backups/ -R
print_status "✅ Permissions set"

# Build images
print_status "Building Docker images..."
if [ -x "./docker-build.sh" ]; then
    ./docker-build.sh latest
else
    docker-compose build
fi
print_status "✅ Docker images built"

# Initialize database and start services
print_status "Initializing and starting services..."
docker-compose up -d postgres redis

# Wait for database to be ready
print_status "Waiting for database to be ready..."
sleep 10

# Run database initialization
docker-compose up airflow-init
print_status "✅ Database initialized"

# Start all services
docker-compose up -d
print_status "✅ All services started"

# Wait for services to be healthy
print_status "Waiting for services to be healthy..."
sleep 30

# Check service status
print_status "Checking service status..."
docker-compose ps

echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}        Setup Complete! 🎉          ${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""
print_status "PII De-identification System is now ready!"
echo ""
echo "Application URLs:"
echo "  📊 API Documentation: http://localhost:8000/docs"
echo "  🌐 Frontend: http://localhost:3000"
echo "  🔄 Airflow: http://localhost:8080"
echo "  📈 Health Check: http://localhost:8000/health"
echo ""
echo "Default Credentials:"
echo "  API Admin: admin / admin123"
echo "  API User: user / user123"
echo "  Airflow: admin / admin123"
echo ""
echo "Useful Commands:"
echo "  View logs: docker-compose logs -f [service]"
echo "  Stop services: docker-compose down"
echo "  Restart: docker-compose restart"
echo "  Scale services: docker-compose up -d --scale api=2"
echo ""
echo "Configuration Files:"
echo "  Environment: .env"
echo "  Policies: config/policies/"
echo "  Workflows: orchestration/"
echo ""
print_status "For production deployment, use:"
print_status "./docker-deploy.sh production up"
echo ""
print_status "Happy processing! 🛡️"