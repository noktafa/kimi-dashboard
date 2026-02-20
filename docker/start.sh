#!/bin/bash
# ============================================
# Kimi Ecosystem - Startup Script
# ============================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ============================================
# Helper Functions
# ============================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ============================================
# Pre-flight Checks
# ============================================

check_docker() {
    log_info "Checking Docker installation..."
    if ! command -v docker &>/dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &>/dev/null; then
        log_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi
    log_success "Docker is ready"
}

check_docker_compose() {
    log_info "Checking Docker Compose..."
    if command -v docker-compose &>/dev/null; then
        COMPOSE_CMD="docker-compose"
    elif docker compose version &>/dev/null; then
        COMPOSE_CMD="docker compose"
    else
        log_error "Docker Compose is not installed."
        exit 1
    fi
    log_success "Docker Compose is ready ($COMPOSE_CMD)"
}

check_env_file() {
    log_info "Checking environment configuration..."
    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            log_warn ".env file not found, copying from .env.example"
            cp .env.example .env
            log_warn "Please review and update .env with your settings"
        else
            log_error "No .env or .env.example file found"
            exit 1
        fi
    fi
    log_success "Environment file is ready"
}

# ============================================
# Service Management
# ============================================

start_services() {
    log_info "Starting Kimi Ecosystem services..."
    
    # Pull latest images if needed
    log_info "Pulling latest base images..."
    $COMPOSE_CMD pull --ignore-pull-failures 2>/dev/null || true
    
    # Build and start services
    log_info "Building and starting services..."
    $COMPOSE_CMD up --build -d
    
    log_success "Services started successfully!"
}

start_with_monitoring() {
    log_info "Starting Kimi Ecosystem with monitoring..."
    
    $COMPOSE_CMD --profile monitoring up --build -d
    
    log_success "Services started with monitoring!"
}

stop_services() {
    log_info "Stopping Kimi Ecosystem services..."
    $COMPOSE_CMD down
    log_success "Services stopped"
}

stop_and_clean() {
    log_warn "Stopping services and removing volumes..."
    $COMPOSE_CMD down -v
    log_success "Services stopped and data cleaned"
}

show_status() {
    log_info "Service Status:"
    $COMPOSE_CMD ps
}

show_logs() {
    local service=$1
    if [ -n "$service" ]; then
        $COMPOSE_CMD logs -f "$service"
    else
        $COMPOSE_CMD logs -f
    fi
}

# ============================================
# Health Checks
# ============================================

wait_for_healthy() {
    log_info "Waiting for services to be healthy..."
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        local healthy=true
        
        # Check each service
        for service in postgres redis; do
            if ! $COMPOSE_CMD ps "$service" | grep -q "healthy"; then
                healthy=false
                break
            fi
        done
        
        if [ "$healthy" = true ]; then
            log_success "All infrastructure services are healthy!"
            return 0
        fi
        
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    log_error "Services did not become healthy in time"
    return 1
}

show_endpoints() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}Kimi Ecosystem is running!${NC}"
    echo "=========================================="
    echo ""
    echo "Access Points:"
    echo "  Dashboard:     http://localhost"
    echo "  API Gateway:   http://localhost/api/"
    echo "  Dashboard Alt: http://localhost:3000"
    echo ""
    echo "Direct Service Ports:"
    echo "  Security Auditor:  http://localhost:8000"
    echo "  SysAdmin AI:      http://localhost:8001"
    echo "  Convergence Loop: http://localhost:8002"
    echo ""
    echo "Infrastructure:"
    echo "  PostgreSQL: localhost:5432"
    echo "  Redis:      localhost:6379"
    echo ""
    
    if $COMPOSE_CMD ps | grep -q "grafana"; then
        echo "Monitoring:"
        echo "  Grafana:    http://localhost:3001"
        echo "  Prometheus: http://localhost:9090"
        echo ""
    fi
    
    echo "Useful Commands:"
    echo "  View logs:    ./start.sh logs [service]"
    echo "  Status:       ./start.sh status"
    echo "  Stop:         ./start.sh stop"
    echo "  Restart:      ./start.sh restart"
    echo "=========================================="
}

# ============================================
# Main
# ============================================

show_help() {
    cat <<EOF
Kimi Ecosystem - Docker Compose Management Script

Usage: $0 [command] [options]

Commands:
  up, start         Start all services (default)
  up-monitoring     Start with monitoring stack
  down, stop        Stop all services
  clean             Stop and remove all data (volumes)
  restart           Restart all services
  status            Show service status
  logs [service]    Show logs (optionally for specific service)
  health            Check service health
  help              Show this help message

Examples:
  $0                    # Start all services
  $0 up-monitoring      # Start with Prometheus + Grafana
  $0 logs nginx         # View nginx logs
  $0 clean              # Full cleanup

EOF
}

case "${1:-up}" in
    up|start|"")
        check_docker
        check_docker_compose
        check_env_file
        start_services
        wait_for_healthy
        show_endpoints
        ;;
    up-monitoring|start-monitoring)
        check_docker
        check_docker_compose
        check_env_file
        start_with_monitoring
        wait_for_healthy
        show_endpoints
        ;;
    down|stop)
        stop_services
        ;;
    clean)
        read -p "This will delete all data. Are you sure? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            stop_and_clean
        else
            log_info "Cancelled"
        fi
        ;;
    restart)
        stop_services
        start_services
        wait_for_healthy
        show_endpoints
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "$2"
        ;;
    health)
        wait_for_healthy
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
