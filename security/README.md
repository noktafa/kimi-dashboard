# Kimi Ecosystem Security

Production-ready authentication and TLS for the Kimi ecosystem.

## Overview

This security module provides:

- **API Key Authentication** - Simple header-based auth for service-to-service communication
- **JWT Bearer Tokens** - Stateful authentication with role-based claims
- **Role-Based Access Control (RBAC)** - Admin, Operator, and Viewer roles
- **TLS Encryption** - Auto-generated self-signed certificates with mutual TLS support
- **Session Management** - HTTP-only, secure, SameSite cookies for dashboard
- **WebSocket Authentication** - Token-based auth for real-time connections

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Kimi Dashboard                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Login Page   │  │ Session      │  │ Proxy Auth to        │  │
│  │ (user/pass)  │→ │ Cookies      │→ │ Backend Services     │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   Security    │    │   SysAdmin    │    │  Convergence  │
│   Auditor     │    │      AI       │    │     Loop      │
│  :8000        │    │   :8001       │    │   :8002       │
├───────────────┤    ├───────────────┤    ├───────────────┤
│ • API Key     │    │ • API Key     │    │ • API Key     │
│ • JWT         │    │ • JWT         │    │ • JWT         │
│ • TLS         │    │ • RBAC        │    │ • WebSocket   │
│               │    │ • Safety      │    │   Auth        │
│               │    │   Checks      │    │ • TLS         │
└───────────────┘    └───────────────┘    └───────────────┘
```

## Quick Start

```bash
# Run setup script
cd /root/.openclaw/workspace/kimi-ecosystem/security
./setup.sh

# Source the environment variables (as shown by setup.sh)
export SECURITY_AUDITOR_TLS_CERT=$(pwd)/certs/security-auditor/tls.crt
export SECURITY_AUDITOR_TLS_KEY=$(pwd)/certs/security-auditor/tls.key
export SECURITY_AUDITOR_JWT_SECRET=$(openssl rand -base64 32)
# ... etc for other services

# Start services (in separate terminals)
cd kimi-security-auditor/src && python main.py
cd kimi-sysadmin-ai/src && python main.py
cd kimi-convergence-loop/src && python main.py
cd kimi-dashboard/src && python main.py
```

## Components

### 1. Shared Security Library (`shared/`)

Common authentication and TLS utilities used by all services.

**Key Features:**
- `AuthManager` - JWT and API key management
- `TLSManager` - SSL context creation and certificate handling
- `Role` and `Permission` enums - RBAC definitions
- FastAPI dependencies - `get_current_user`, `optional_auth`

**Usage:**
```python
from auth import AuthManager, Role, Permission, get_current_user

auth_manager = AuthManager(config)

# Generate API key
api_key = auth_manager.generate_api_key("service-name", Role.OPERATOR)

# Create JWT token
token = auth_manager.create_token("user123", Role.ADMIN)

# Verify token
payload = auth_manager.verify_token(token)

# Check permission
if auth_manager.has_permission(payload, Permission.EXECUTE_COMMAND):
    # Allow command execution
```

### 2. Security Auditor (`kimi-security-auditor/`)

Security scanning service with API key and JWT authentication.

**Features:**
- `X-API-Key` header authentication
- JWT bearer token support
- TLS termination
- Permission-based scan operations

**Endpoints:**
- `GET /health` - Health check (no auth required)
- `GET /` - Service info (auth required)
- `POST /scan` - Start scan (requires `create:scan`)
- `GET /scans/{id}` - Get scan results (requires `read:scans`)
- `DELETE /scans/{id}` - Delete scan (requires `delete:scan`)

### 3. SysAdmin AI (`kimi-sysadmin-ai/`)

System administration service with RBAC and safety checks.

**Features:**
- Role-based access control (admin/operator/viewer)
- Safety checks for destructive commands
- Command approval workflow for high-risk operations
- Audit logging

**Safety Levels:**
- **Critical** (`rm -rf`, `mkfs`, etc.) - Admin only
- **High** (`sudo`, `useradd`, etc.) - Operator+ with approval
- **Low** - All authenticated users

### 4. Convergence Loop (`kimi-convergence-loop/`)

Orchestration service with WebSocket authentication.

**Features:**
- WebSocket auth handshake with short-lived tokens
- Authenticated connection manager
- Permission-based broadcasting
- Session tokens for dashboard integration

**WebSocket Flow:**
1. Client requests WebSocket token via `POST /auth/ws-token`
2. Client connects to `/ws?token=<token>`
3. Server validates token and accepts connection
4. Messages are broadcast based on permissions

### 5. Dashboard (`kimi-dashboard/`)

Web dashboard with session-based authentication.

**Features:**
- Login page with username/password
- HTTP-only, secure, SameSite session cookies
- Proxy authentication to backend services
- Automatic JWT token generation for API calls

**Default Users:**
- `admin` / `admin` - Full access
- `operator` / `operator` - Can execute commands
- `viewer` / `viewer` - Read-only

## Configuration

Each service has a YAML configuration file in `config/`:

```yaml
service:
  host: "0.0.0.0"
  port: 8000
  log_level: "info"

auth:
  jwt_secret: ""  # Set via env var
  jwt_algorithm: "HS256"
  jwt_expiry_hours: 24
  require_auth: true

tls:
  enabled: true
  cert_path: "${SERVICE_TLS_CERT}"
  key_path: "${SERVICE_TLS_KEY}"
  ca_path: "${SERVICE_TLS_CA}"
  verify_client: false
```

Environment variables override YAML settings:
- `{SERVICE}_JWT_SECRET` - JWT signing secret
- `{SERVICE}_TLS_CERT` - Certificate path
- `{SERVICE}_TLS_KEY` - Private key path
- `{SERVICE}_TLS_CA` - CA certificate path

## Certificate Management

### Generate Certificates

```bash
# Generate CA and service certificates
python shared/generate_certs.py --output-dir certs

# Generate with custom validity
python shared/generate_certs.py \
    --output-dir certs \
    --ca-validity-days 3650 \
    --service-validity-days 365
```

### Certificate Structure

```
certs/
├── ca.crt              # CA certificate (distribute to clients)
├── ca.key              # CA private key (keep secure!)
├── security-auditor/
│   ├── tls.crt         # Service certificate
│   └── tls.key         # Service private key
├── sysadmin-ai/
│   ├── tls.crt
│   └── tls.key
├── convergence-loop/
│   ├── tls.crt
│   └── tls.key
├── dashboard/
│   ├── tls.crt
│   └── tls.key
└── clients/
    └── dashboard-client.crt  # Client cert for mTLS
```

## API Key Management

### Generate API Keys

```bash
# Generate a new API key
python shared/generate_api_key.py my-service --role operator

# Save to config file
python shared/generate_api_key.py my-service --role operator --config security.yaml
```

### Using API Keys

```bash
# Health check with API key
curl -k -H "X-API-Key: kimi_xxxxxxxx" https://localhost:8000/health

# Start a scan
curl -k -X POST \
  -H "X-API-Key: kimi_xxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "scan_type": "full"}' \
  https://localhost:8000/scan
```

### Using JWT Tokens

```bash
# Get a token (requires API key)
curl -k -X POST \
  "https://localhost:8000/auth/token?user_id=user123&role=operator&api_key=kimi_xxx"

# Use token
curl -k -H "Authorization: Bearer eyJ..." https://localhost:8000/
```

## Role-Based Access Control

### Roles

| Role | Description | Permissions |
|------|-------------|-------------|
| `admin` | Full system access | All permissions |
| `operator` | Can execute commands | Read + Create + Execute |
| `viewer` | Read-only access | Read only |

### Permissions

| Permission | Description | Required Role |
|------------|-------------|---------------|
| `read:health` | View health status | Any |
| `read:scans` | View scan results | Viewer+ |
| `create:scan` | Start new scans | Operator+ |
| `delete:scan` | Delete scan history | Admin |
| `execute:command` | Run commands | Operator+ |
| `manage:users` | User management | Admin |

## Security Considerations

### Production Checklist

- [ ] Change default passwords
- [ ] Use proper CA-signed certificates
- [ ] Enable client certificate verification (mTLS)
- [ ] Store secrets in a secrets manager (Vault, etc.)
- [ ] Use Redis for session storage (distributed)
- [ ] Enable audit logging
- [ ] Set up log aggregation
- [ ] Configure rate limiting
- [ ] Enable request/response logging
- [ ] Set up monitoring and alerting

### Secrets Management

**Don't commit secrets to version control!**

Use environment variables or a secrets manager:

```bash
# Development
export SECURITY_AUDITOR_JWT_SECRET=$(openssl rand -base64 32)

# Production (example with HashiCorp Vault)
export SECURITY_AUDITOR_JWT_SECRET=$(vault kv get -field=jwt_secret secret/kimi/security-auditor)
```

## Testing

```bash
# Test health endpoint (no auth)
curl -k https://localhost:8000/health

# Test with API key
curl -k -H "X-API-Key: kimi_xxx" https://localhost:8000/

# Test with JWT
curl -k -H "Authorization: Bearer eyJ..." https://localhost:8000/

# Test permission denied (viewer trying admin action)
curl -k -H "X-API-Key: kimi_viewer_key" -X DELETE https://localhost:8000/scans/123
```

## Troubleshooting

### Certificate Errors

```bash
# Trust the CA certificate (Linux)
sudo cp certs/ca.crt /usr/local/share/ca-certificates/kimi-ca.crt
sudo update-ca-certificates

# Or use -k flag with curl to skip verification
curl -k https://localhost:8000/health
```

### Authentication Errors

```bash
# Check if auth is required
curl -k https://localhost:8000/health
# Should show "authenticated: false" if no auth provided

# Verify API key
curl -k -H "X-API-Key: your-key" https://localhost:8000/health
```

### Port Already in Use

```bash
# Find process using port
lsof -i :8000

# Kill process
kill -9 <PID>
```

## License

MIT License - See LICENSE file for details.