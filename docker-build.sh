#!/bin/bash

# Docker Build Script for PII De-identification System
# This script builds all Docker images for the application

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="pii-de-identification"
VERSION=${1:-latest}
BUILD_NO_CACHE=${BUILD_NO_CACHE:-false}
PUSH_IMAGES=${PUSH_IMAGES:-false}
DOCKER_REGISTRY=${DOCKER_REGISTRY:-}

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE} PII De-identification System Builder ${NC}"
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

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose > /dev/null 2>&1; then
    print_error "docker-compose is not installed. Please install it and try again."
    exit 1
fi

print_status "Starting build process..."
print_status "Project: $PROJECT_NAME"
print_status "Version: $VERSION"
print_status "No cache: $BUILD_NO_CACHE"
print_status "Push images: $PUSH_IMAGES"

# Set build args
BUILD_ARGS=""
if [ "$BUILD_NO_CACHE" = "true" ]; then
    BUILD_ARGS="--no-cache"
fi

# Function to build individual images
build_image() {
    local service_name=$1
    local dockerfile_path=$2
    local image_name="${PROJECT_NAME}-${service_name}"
    
    if [ -n "$DOCKER_REGISTRY" ]; then
        image_name="${DOCKER_REGISTRY}/${image_name}"
    fi
    
    print_status "Building $service_name image..."
    
    if docker build $BUILD_ARGS \
        -f "$dockerfile_path" \
        -t "${image_name}:${VERSION}" \
        -t "${image_name}:latest" \
        .; then
        print_status "✅ Successfully built $service_name image"
        
        # Push image if requested
        if [ "$PUSH_IMAGES" = "true" ] && [ -n "$DOCKER_REGISTRY" ]; then
            print_status "Pushing $service_name image..."
            docker push "${image_name}:${VERSION}"
            docker push "${image_name}:latest"
            print_status "✅ Successfully pushed $service_name image"
        fi
    else
        print_error "❌ Failed to build $service_name image"
        exit 1
    fi
    
    echo ""
}

# Build all images
print_status "Building API image..."
build_image "api" "docker/Dockerfile.api"

print_status "Building Worker image..."
build_image "worker" "docker/Dockerfile.worker"

# Only build frontend if the directory exists
if [ -d "frontend" ]; then
    print_status "Building Frontend image..."
    build_image "frontend" "docker/Dockerfile.frontend"
else
    print_warning "Frontend directory not found, skipping frontend build"
fi

# Build using docker-compose for verification
print_status "Verifying build with docker-compose..."
if docker-compose build --no-cache; then
    print_status "✅ Docker-compose build successful"
else
    print_error "❌ Docker-compose build failed"
    exit 1
fi

# Show built images
print_status "Built images:"
docker images | grep "$PROJECT_NAME" | head -10

echo ""
print_status "Build completed successfully! 🎉"
echo ""

# Print usage instructions
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}         Usage Instructions          ${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo "To start the application:"
echo "  docker-compose up -d"
echo ""
echo "To start with monitoring:"
echo "  docker-compose --profile monitoring up -d"
echo ""
echo "To stop the application:"
echo "  docker-compose down"
echo ""
echo "To view logs:"
echo "  docker-compose logs -f [service-name]"
echo ""
echo "To scale services:"
echo "  docker-compose up -d --scale api=2 --scale celery-worker=3"
echo ""
print_status "Happy containerizing! 🐳"