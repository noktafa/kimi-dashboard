# Kimi Ecosystem - Docker Compose Setup

A production-ready Docker Compose configuration for the entire Kimi ecosystem.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Nginx (80/443)                       │
│                    Reverse Proxy + Load Balancer             │
└──────────────┬──────────────────────────────────────────────┘
               │
    ┌──────────┼──────────┬──────────────┐
    │          │          │              │
    ▼          ▼          ▼              ▼
┌────────┐ ┌────────┐ ┌────────┐ ┌──────────────┐
│Security│ │SysAdmin│ │Conver- │ │  Dashboard   │
│Auditor │ │   AI   │ │gence   │ │   (Web UI)   │
│ :8000  │ │ :8001  │ │ :8002  │ │    :3000     │
└────┬───┘ └────┬───┘ └────┬───┘ └──────────────┘
     │          │          │
     └──────────┴──────────┘
                │
    ┌───────────┴───────────┐
    │                       │
    ▼                       ▼
┌─────────┐           ┌─────────┐
│PostgreSQL│           │  Redis  │
│  :5432   │           │  :6379  │
└─────────┘           └─────────┘
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| nginx | 80, 443 | Reverse proxy and load balancer |
| kimi-security-auditor | 8000 | Security scanning service |
| kimi-sysadmin-ai | 8001 | System administration AI API |
| kimi-convergence-loop | 8002 | Orchestration service |
| kimi-dashboard | 3000 | Web UI (via nginx:80) |
| postgres | 5432 | State storage |
| redis | 6379 | Event bus and caching |

## Quick Start

### 1. One-Command Startup

```bash
./start.sh
```

Or with Docker Compose directly:

```bash
docker-compose up -d
```

### 2. With Monitoring (Prometheus + Grafana)

```bash
./start.sh up-monitoring
```

### 3. Access the Services

- **Dashboard**: http://localhost
- **API Gateway**: http://localhost/api/
- **Security Auditor**: http://localhost:8000
- **SysAdmin AI**: http://localhost:8001
- **Convergence Loop**: http://localhost:8002
- **Grafana** (if enabled): http://localhost:3001

## Management Commands

```bash
# Start all services
./start.sh up

# Start with monitoring
./start.sh up-monitoring

# Stop all services
./start.sh stop

# View service status
./start.sh status

# View logs
./start.sh logs
./start.sh logs nginx

# Restart services
./start.sh restart

# Clean up (removes volumes!)
./start.sh clean

# Show help
./start.sh help
```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_PASSWORD` | - | Database password |
| `REDIS_PASSWORD` | - | Redis password |
| `LOG_LEVEL` | INFO | Application log level |
| `SCAN_INTERVAL` | 3600 | Security scan interval (seconds) |
| `CONVERGENCE_INTERVAL` | 60 | Convergence loop interval (seconds) |

### Networks

- `kimi-backend`: External-facing services (172.20.0.0/16)
- `kimi-internal`: Internal service communication (172.21.0.0/16)

## Production Deployment

### 1. Update Environment Variables

```bash
# Generate secure passwords
openssl rand -base64 32

# Update .env with production values
nano .env
```

### 2. Enable SSL

Place your SSL certificates in `nginx/ssl/`:
- `nginx/ssl/cert.pem`
- `nginx/ssl/key.pem`

Update `nginx/nginx.conf` to enable HTTPS.

### 3. Resource Limits

Services have resource limits configured in `docker-compose.yml`. Adjust based on your infrastructure.

### 4. Backup Strategy

```bash
# Backup PostgreSQL
docker exec kimi-postgres pg_dump -U kimi kimi_ecosystem > backup.sql

# Backup Redis
docker exec kimi-redis redis-cli SAVE
docker cp kimi-redis:/data/dump.rdb ./backup/
```

## Health Checks

All services include health checks:

- **HTTP Services**: `/health` endpoint
- **PostgreSQL**: `pg_isready`
- **Redis**: `redis-cli ping`

## Monitoring

When enabled with `--profile monitoring`:

- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3001 (admin/admin)

## Troubleshooting

### Services Not Starting

```bash
# Check logs
./start.sh logs

# Check specific service
./start.sh logs kimi-security-auditor

# Verify environment
docker-compose config
```

### Database Connection Issues

```bash
# Check PostgreSQL health
docker-compose ps postgres

# Connect to database
docker exec -it kimi-postgres psql -U kimi -d kimi_ecosystem
```

### Reset Everything

```bash
# WARNING: This deletes all data!
./start.sh clean
```

## Development

### Building Individual Services

```bash
docker-compose build kimi-security-auditor
docker-compose up -d kimi-security-auditor
```

### Hot Reload (Development Mode)

Mount source code as volumes in `docker-compose.override.yml`.

## License

MIT
