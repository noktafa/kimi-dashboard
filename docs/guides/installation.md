# Installation Guide

## System Requirements

- Python 3.9 or higher
- pip or poetry for package management
- (Optional) Docker for containerized deployment
- (Optional) OPA (Open Policy Agent) for advanced policy enforcement

## Quick Install

### Using pip

```bash
# Install all components
pip install kimi-security-auditor kimi-sysadmin-ai kimi-convergence-loop kimi-dashboard

# Or install individually
pip install kimi-security-auditor
pip install kimi-sysadmin-ai
pip install kimi-convergence-loop
pip install kimi-dashboard
```

### Using the Makefile

```bash
# Clone the repository
git clone https://github.com/kimi-ecosystem/kimi-ecosystem.git
cd kimi-ecosystem

# Install all packages in development mode
make install-dev

# Or install specific components
make install-auditor
make install-sysadmin
make install-convergence
make install-dashboard
```

## Development Installation

### Setup Virtual Environment

```bash
# Create virtual environment
python -m venv .venv

# Activate
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# Install development dependencies
make install-dev
```

### Verify Installation

```bash
# Check CLI tools are available
kimi-audit --version
kimi-admin --version
kimi-converge --version
kimi-dashboard --version
```

## Configuration

### Environment Variables

Create a `.env` file or export these variables:

```bash
# OpenAI API (required for sysadmin-ai)
export OPENAI_API_KEY="your-api-key"
export OPENAI_BASE_URL="https://api.openai.com/v1"  # Optional

# OPA (optional)
export OPA_URL="http://localhost:8181"

# Dashboard (optional)
export DASHBOARD_PORT="8766"
export CONVERGENCE_WS_URL="ws://localhost:8765"
```

### Configuration Files

Create `~/.config/kimi/config.yaml`:

```yaml
# Security Auditor
auditor:
  timeout: 30
  max_depth: 3
  concurrency: 10

# Sysadmin AI
sysadmin:
  require_confirmation: true
  max_timeout: 300
  safety:
    blocklist:
      - "custom_dangerous_command"
    graylist:
      - "semi_sensitive_command"

# Convergence Loop
convergence:
  max_iterations: 10
  convergence_threshold: 0.95
  timeout_seconds: 3600

# Dashboard
dashboard:
  host: "0.0.0.0"
  port: 8766
  db_path: "~/.local/share/kimi/dashboard.db"
```

## Docker Installation

### Using Pre-built Images

```bash
# Pull images
docker pull kimisec/auditor:latest
docker pull kimisec/sysadmin:latest
docker pull kimisec/convergence:latest
docker pull kimisec/dashboard:latest

# Run security auditor
docker run --rm kimisec/auditor:latest kimi-audit https://example.com

# Run sysadmin AI interactively
docker run -it --rm kimisec/sysadmin:latest kimi-admin chat

# Run dashboard
docker run -p 8766:8766 kimisec/dashboard:latest
```

### Building Images Locally

```bash
# Build all images
make docker-all

# Or build individually
docker build -t kimisec/auditor ./kimi-security-auditor
docker build -t kimisec/sysadmin ./kimi-sysadmin-ai
docker build -t kimisec/convergence ./kimi-convergence-loop
docker build -t kimisec/dashboard ./kimi-dashboard
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  auditor:
    image: kimisec/auditor:latest
    volumes:
      - ./reports:/reports
    command: kimi-audit https://example.com -o /reports/audit.md

  sysadmin:
    image: kimisec/sysadmin:latest
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  convergence:
    image: kimisec/convergence:latest
    volumes:
      - ./config:/config
      - ./reports:/reports
    command: kimi-converge run --config /config/convergence.yaml

  dashboard:
    image: kimisec/dashboard:latest
    ports:
      - "8766:8766"
    environment:
      - DASHBOARD_HOST=0.0.0.0
      - DASHBOARD_PORT=8766
```

Run with:

```bash
docker-compose up -d dashboard
docker-compose run auditor
docker-compose run convergence
```

## Kubernetes Installation

### Using Helm

```bash
# Add Helm repository
helm repo add kimi https://charts.kimi-ecosystem.dev
helm repo update

# Install components
helm install kimi-auditor kimi/auditor
helm install kimi-sysadmin kimi/sysadmin
helm install kimi-convergence kimi/convergence
helm install kimi-dashboard kimi/dashboard
```

### Manual Installation

Apply the Kubernetes manifests:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/auditor.yaml
kubectl apply -f k8s/sysadmin.yaml
kubectl apply -f k8s/convergence.yaml
kubectl apply -f k8s/dashboard.yaml
```

## Troubleshooting

### Common Issues

#### Import Errors

```bash
# If you get "ModuleNotFoundError", ensure you're in the virtual environment
source .venv/bin/activate

# Reinstall packages
pip install -e ./kimi-security-auditor --force-reinstall
```

#### Permission Denied

```bash
# If CLI commands not found, check PATH
export PATH="$HOME/.local/bin:$PATH"

# Or use Python module syntax
python -m kimi_security_auditor.cli --help
```

#### OPA Connection Issues

```bash
# Check OPA is running
curl http://localhost:8181/health

# The sysadmin-ai will fall back to Python backend if OPA is unavailable
```

### Getting Help

- 📖 Documentation: https://docs.kimi-ecosystem.dev
- 🐛 Issues: https://github.com/kimi-ecosystem/kimi-ecosystem/issues
- 💬 Discord: https://discord.gg/kimi-ecosystem
