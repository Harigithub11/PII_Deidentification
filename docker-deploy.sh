#!/bin/bash

# Docker Deployment Script for PII De-identification System
# This script handles deployment of the containerized application

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="pii-de-identification"
ENVIRONMENT=${1:-development}
ACTION=${2:-up}
COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE} PII De-identification Deployment   ${NC}"
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

# Function to show usage
show_usage() {
    echo "Usage: $0 [environment] [action]"
    echo ""
    echo "Environments:"
    echo "  development (default) - Local development deployment"
    echo "  production           - Production deployment"
    echo "  staging             - Staging deployment"
    echo ""
    echo "Actions:"
    echo "  up (default)        - Start services"
    echo "  down               - Stop services"
    echo "  restart            - Restart services"
    echo "  logs               - View logs"
    echo "  status             - Show service status"
    echo "  health             - Check service health"
    echo "  scale              - Scale services"
    echo "  backup             - Backup data"
    echo "  restore            - Restore data"
    echo ""
    exit 1
}

# Check if help is requested
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_usage
fi

print_status "Environment: $ENVIRONMENT"
print_status "Action: $ACTION"

# Set environment-specific configurations
case $ENVIRONMENT in
    "development")
        ENV_FILE=".env"
        COMPOSE_PROFILES=""
        ;;
    "staging")
        ENV_FILE=".env.docker"
        COMPOSE_PROFILES=""
        ;;
    "production")
        ENV_FILE=".env.production"
        COMPOSE_PROFILES="--profile monitoring"
        ;;
    *)
        print_error "Unknown environment: $ENVIRONMENT"
        show_usage
        ;;
esac

# Check if environment file exists
if [ ! -f "$ENV_FILE" ]; then
    print_error "Environment file $ENV_FILE not found!"
    if [ "$ENVIRONMENT" = "production" ]; then
        print_warning "For production deployment, copy .env.production and customize it"
    else
        print_warning "Copy .env.example to $ENV_FILE and customize it"
    fi
    exit 1
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Load environment variables
export $(grep -v '^#' "$ENV_FILE" | xargs)

# Function to wait for service health
wait_for_service() {
    local service_name=$1
    local max_attempts=30
    local attempt=0
    
    print_status "Waiting for $service_name to be healthy..."
    
    while [ $attempt -lt $max_attempts ]; do
        if docker-compose ps | grep "$service_name" | grep -q "healthy"; then
            print_status "✅ $service_name is healthy"
            return 0
        fi
        
        attempt=$((attempt + 1))
        echo -n "."
        sleep 2
    done
    
    print_error "❌ $service_name failed to become healthy"
    return 1
}

# Function to check service health
check_health() {
    print_status "Checking service health..."
    
    services=("postgres" "redis" "api" "celery-worker" "airflow-webserver")
    
    for service in "${services[@]}"; do
        if docker-compose ps | grep -q "$service"; then
            health_status=$(docker-compose ps | grep "$service" | awk '{print $4}')
            if echo "$health_status" | grep -q "healthy\|Up"; then
                print_status "✅ $service: $health_status"
            else
                print_warning "⚠️  $service: $health_status"
            fi
        else
            print_warning "⚠️  $service: Not running"
        fi
    done
}

# Function to show service logs
show_logs() {
    local service=${3:-""}
    if [ -n "$service" ]; then
        print_status "Showing logs for $service..."
        docker-compose --env-file "$ENV_FILE" logs -f "$service"
    else
        print_status "Showing logs for all services..."
        docker-compose --env-file "$ENV_FILE" logs -f
    fi
}

# Function to scale services
scale_services() {
    print_status "Scaling services for $ENVIRONMENT environment..."
    
    case $ENVIRONMENT in
        "production")
            docker-compose --env-file "$ENV_FILE" up -d \
                --scale api=2 \
                --scale celery-worker=3
            ;;
        "staging")
            docker-compose --env-file "$ENV_FILE" up -d \
                --scale api=1 \
                --scale celery-worker=2
            ;;
        *)
            print_warning "No scaling configuration for $ENVIRONMENT"
            ;;
    esac
}

# Function to backup data
backup_data() {
    print_status "Creating backup..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    backup_dir="./backups/$timestamp"
    
    mkdir -p "$backup_dir"
    
    # Backup database
    print_status "Backing up database..."
    docker-compose exec postgres pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > "$backup_dir/database.sql"
    
    # Backup volumes
    print_status "Backing up application data..."
    docker run --rm -v pii-de-identification_app_data:/data -v "$PWD/$backup_dir":/backup alpine tar czf /backup/app_data.tar.gz -C /data .
    
    # Backup models
    print_status "Backing up models..."
    docker run --rm -v pii-de-identification_app_models:/data -v "$PWD/$backup_dir":/backup alpine tar czf /backup/models.tar.gz -C /data .
    
    print_status "✅ Backup completed: $backup_dir"
}

# Function to restore data
restore_data() {
    local backup_dir=${3:-""}
    
    if [ -z "$backup_dir" ]; then
        print_error "Please specify backup directory: $0 $ENVIRONMENT restore [backup_dir]"
        exit 1
    fi
    
    if [ ! -d "$backup_dir" ]; then
        print_error "Backup directory $backup_dir not found!"
        exit 1
    fi
    
    print_status "Restoring from backup: $backup_dir"
    print_warning "This will overwrite existing data. Continue? (y/N)"
    read -r response
    
    if [ "$response" != "y" ] && [ "$response" != "Y" ]; then
        print_status "Restore cancelled"
        exit 0
    fi
    
    # Restore database
    if [ -f "$backup_dir/database.sql" ]; then
        print_status "Restoring database..."
        docker-compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" < "$backup_dir/database.sql"
    fi
    
    # Restore volumes
    if [ -f "$backup_dir/app_data.tar.gz" ]; then
        print_status "Restoring application data..."
        docker run --rm -v pii-de-identification_app_data:/data -v "$PWD/$backup_dir":/backup alpine tar xzf /backup/app_data.tar.gz -C /data
    fi
    
    if [ -f "$backup_dir/models.tar.gz" ]; then
        print_status "Restoring models..."
        docker run --rm -v pii-de-identification_app_models:/data -v "$PWD/$backup_dir":/backup alpine tar xzf /backup/models.tar.gz -C /data
    fi
    
    print_status "✅ Restore completed"
}

# Main action handler
case $ACTION in
    "up")
        print_status "Starting services in $ENVIRONMENT mode..."
        
        # Pre-deployment checks
        print_status "Running pre-deployment checks..."
        
        # Create necessary directories
        mkdir -p logs backups
        
        # Start services
        if [ "$ENVIRONMENT" = "production" ]; then
            docker-compose --env-file "$ENV_FILE" $COMPOSE_PROFILES up -d
            
            # Wait for critical services
            wait_for_service "postgres"
            wait_for_service "redis"
            wait_for_service "api"
            
            # Scale services for production
            scale_services
        else
            docker-compose --env-file "$ENV_FILE" up -d
        fi
        
        # Show status
        echo ""
        print_status "Services started! Here's the status:"
        docker-compose --env-file "$ENV_FILE" ps
        
        echo ""
        print_status "Application URLs:"
        echo "  API: http://localhost:${API_PORT:-8000}"
        echo "  Frontend: http://localhost:${FRONTEND_PORT:-3000}"
        echo "  Airflow: http://localhost:${AIRFLOW_PORT:-8080}"
        
        if [ "$ENVIRONMENT" = "production" ]; then
            echo "  Prometheus: http://localhost:9090"
            echo "  Grafana: http://localhost:3001"
        fi
        ;;
        
    "down")
        print_status "Stopping services..."
        docker-compose --env-file "$ENV_FILE" down
        print_status "✅ Services stopped"
        ;;
        
    "restart")
        print_status "Restarting services..."
        docker-compose --env-file "$ENV_FILE" restart
        print_status "✅ Services restarted"
        ;;
        
    "logs")
        show_logs "$@"
        ;;
        
    "status")
        print_status "Service status:"
        docker-compose --env-file "$ENV_FILE" ps
        ;;
        
    "health")
        check_health
        ;;
        
    "scale")
        scale_services
        ;;
        
    "backup")
        backup_data
        ;;
        
    "restore")
        restore_data "$@"
        ;;
        
    *)
        print_error "Unknown action: $ACTION"
        show_usage
        ;;
esac

echo ""
print_status "Deployment operation completed! 🎉"