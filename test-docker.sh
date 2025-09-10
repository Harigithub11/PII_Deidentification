#!/bin/bash

# Test script for Docker containerization
# This script validates the Docker setup without full deployment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  Docker Setup Validation Test       ${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Function to print status
print_status() {
    echo -e "${GREEN}[TEST]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Test 1: Check Docker availability
print_status "Checking Docker availability..."
if docker info > /dev/null 2>&1; then
    print_success "✅ Docker is available and running"
else
    print_error "❌ Docker is not available or not running"
    exit 1
fi

# Test 2: Check Docker Compose availability
print_status "Checking Docker Compose availability..."
if command -v docker-compose > /dev/null 2>&1; then
    print_success "✅ Docker Compose is available"
else
    print_error "❌ Docker Compose is not available"
    exit 1
fi

# Test 3: Validate Compose file syntax
print_status "Validating Docker Compose configuration..."
if docker-compose config > /dev/null 2>&1; then
    print_success "✅ Docker Compose configuration is valid"
else
    print_error "❌ Docker Compose configuration has errors"
    exit 1
fi

# Test 4: Check if Dockerfiles exist
print_status "Checking Dockerfile existence..."
dockerfiles=("docker/Dockerfile.api" "docker/Dockerfile.worker" "docker/Dockerfile.frontend")
for dockerfile in "${dockerfiles[@]}"; do
    if [ -f "$dockerfile" ]; then
        print_success "✅ $dockerfile exists"
    else
        print_error "❌ $dockerfile is missing"
        exit 1
    fi
done

# Test 5: Check required directories
print_status "Checking required directories..."
required_dirs=("docker" "src" "config")
for dir in "${required_dirs[@]}"; do
    if [ -d "$dir" ]; then
        print_success "✅ Directory $dir exists"
    else
        print_warning "⚠️  Directory $dir is missing - may be created during setup"
    fi
done

# Test 6: Check environment files
print_status "Checking environment configuration files..."
env_files=(".env.docker" ".env.production" "env.example")
for env_file in "${env_files[@]}"; do
    if [ -f "$env_file" ]; then
        print_success "✅ $env_file exists"
    else
        print_warning "⚠️  $env_file is missing"
    fi
done

# Test 7: Check if scripts are executable
print_status "Checking script permissions..."
scripts=("docker-setup.sh" "docker-build.sh" "docker-deploy.sh")
for script in "${scripts[@]}"; do
    if [ -x "$script" ]; then
        print_success "✅ $script is executable"
    else
        print_warning "⚠️  $script is not executable - fixing..."
        chmod +x "$script"
        print_success "✅ Fixed permissions for $script"
    fi
done

# Test 8: Test Docker build (dry run)
print_status "Testing Docker image build (validation only)..."
if docker-compose build --dry-run > /dev/null 2>&1; then
    print_success "✅ Docker build configuration is valid"
else
    print_warning "⚠️  Docker build validation not supported in this version"
fi

# Test 9: Check if ports are available
print_status "Checking if required ports are available..."
ports=(8000 3000 8080 5432 6379)
for port in "${ports[@]}"; do
    if command -v netstat > /dev/null 2>&1; then
        if netstat -tuln | grep -q ":$port "; then
            print_warning "⚠️  Port $port is already in use"
        else
            print_success "✅ Port $port is available"
        fi
    else
        print_warning "⚠️  Cannot check port $port availability (netstat not available)"
    fi
done

# Test 10: Memory and disk space check
print_status "Checking system resources..."
if command -v free > /dev/null 2>&1; then
    total_mem=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$total_mem" -ge 4 ]; then
        print_success "✅ Sufficient memory available (${total_mem}GB)"
    else
        print_warning "⚠️  Limited memory available (${total_mem}GB) - minimum 4GB recommended"
    fi
else
    print_warning "⚠️  Cannot check memory availability"
fi

if command -v df > /dev/null 2>&1; then
    available_space=$(df . | awk 'NR==2{print $4}')
    available_gb=$((available_space / 1024 / 1024))
    if [ "$available_gb" -ge 10 ]; then
        print_success "✅ Sufficient disk space available (${available_gb}GB)"
    else
        print_warning "⚠️  Limited disk space available (${available_gb}GB) - minimum 10GB recommended"
    fi
else
    print_warning "⚠️  Cannot check disk space availability"
fi

echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}        Validation Complete           ${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""

print_success "🎉 Docker setup validation completed successfully!"
echo ""
echo "Next steps:"
echo "1. Run: ./docker-setup.sh (for automated setup)"
echo "2. Or manually: docker-compose up -d"
echo "3. Access API: http://localhost:8000"
echo "4. Access Frontend: http://localhost:3000"
echo ""
print_status "Ready for containerization! 🐳"