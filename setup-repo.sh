#!/bin/bash
# Bulletproof repo setup for kimi ecosystem

set -e

echo "=== Creating Bulletproof Kimi Ecosystem Repo ==="

REPO_DIR="/root/.openclaw/workspace/kimi-ecosystem"
cd "$REPO_DIR"

# Clean up pycache and temp files
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
find . -type f -name ".DS_Store" -delete 2>/dev/null || true

# Create main README
cat > README.md << 'EOF'
# Kimi Ecosystem

[![CI/CD](https://github.com/noktafa/kimi-ecosystem/actions/workflows/ci.yml/badge.svg)](https://github.com/noktafa/kimi-ecosystem/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A self-improving infrastructure security platform that diagnoses, fixes, attacks, and validates in a continuous loop until systems converge on a secure state.

## 🚀 Quick Start

```bash
# Clone and install
git clone https://github.com/noktafa/kimi-ecosystem.git
cd kimi-ecosystem
make install

# Run demo against vulnerable infrastructure
./demo/run_demo.sh

# Start dashboard
make dashboard
```

## 📦 Components

| Component | Purpose | CLI |
|-----------|---------|-----|
| **kimi-security-auditor** | Web vulnerability scanner | `kimi-audit` |
| **kimi-sysadmin-ai** | AI-powered safe system admin | `kimi-admin` |
| **kimi-convergence-loop** | Self-healing pipeline | `kimi-converge` |
| **kimi-dashboard** | Real-time visualization | Web UI |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    kimi-convergence-loop                     │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐     │
│  │Diagnose │ → │   Fix   │ → │ Attack  │ → │Validate │     │
│  └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘     │
│       │             │             │             │           │
│       ▼             ▼             ▼             ▼           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           WebSocket Event Bus                        │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
┌─────────────────────┐      ┌─────────────────────┐
│ kimi-security-auditor│      │   kimi-sysadmin-ai  │
│ • 17 attack modules  │      │ • 99 safety rules   │
│ • SQLi, XSS, XXE...  │      │ • Policy engine     │
└─────────────────────┘      └─────────────────────┘
```

## 🛡️ Safety First

kimi-sysadmin-ai implements defense in depth:
- **99 block patterns**: rm -rf, mkfs, reverse shells, credential access
- **86 gray patterns**: Package managers, service control (require confirmation)
- **4 executor backends**: Host, Docker, Kubernetes, SSH

## 📊 Dashboard

Live executive dashboard with:
- Risk score gauge (0-100)
- Compliance badges (PCI DSS, SOC 2, ISO 27001)
- Infrastructure health (5 servers)
- Animated threat map
- Real-time convergence progress

## 🧪 Demo

Run against intentionally vulnerable infrastructure:

```bash
cd demo
./run_demo.sh
```

Scans 5 DigitalOcean servers with real vulnerabilities:
- SQL Injection
- Command Injection
- XSS
- XXE
- IDOR
- Weak Authentication

## 📖 Documentation

- [Installation Guide](docs/guides/installation.md)
- [Quick Start](docs/guides/quickstart.md)
- [Security Testing](docs/guides/security-testing.md)
- [API Reference](docs/api/)

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) file.
EOF

# Create LICENSE
cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2026 Kimi Ecosystem Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
EOF

# Create CONTRIBUTING.md
cat > CONTRIBUTING.md << 'EOF'
# Contributing to Kimi Ecosystem

## Development Setup

```bash
git clone https://github.com/noktafa/kimi-ecosystem.git
cd kimi-ecosystem
make install-dev
```

## Testing

```bash
make test          # Run all tests
make test-cov      # With coverage
make lint          # Run linters
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Run tests and linting
4. Submit PR with clear description

## Code Style

- Python: Black, Ruff, mypy
- TypeScript: ESLint, Prettier
- Commits: Conventional commits
EOF

# Create root Makefile
cat > Makefile << 'EOF'
.PHONY: install install-dev test lint format build dashboard clean

install:
	pip install -e ./kimi-security-auditor
	pip install -e ./kimi-sysadmin-ai
	pip install -e ./kimi-convergence-loop
	pip install -e ./kimi-dashboard

install-dev: install
	pip install -r requirements-dev.txt

test:
	pytest */tests/ -v

test-cov:
	pytest */tests/ --cov=src --cov-report=html

lint:
	ruff check */src
	mypy */src

format:
	black */src
	ruff format */src

build:
	python -m build */pyproject.toml

dashboard:
	cd kimi-dashboard && python3 -m kimi_dashboard.server --port 8766

demo:
	cd demo && ./run_demo.sh

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf */build */dist */*.egg-info

docker-up:
	cd docker && ./start.sh

docker-down:
	cd docker && docker-compose down
EOF

# Create requirements-dev.txt
cat > requirements-dev.txt << 'EOF'
pytest>=7.0.0
pytest-cov>=4.0.0
pytest-asyncio>=0.21.0
black>=23.0.0
ruff>=0.1.0
mypy>=1.0.0
httpx>=0.25.0
EOF

# Create .gitignore
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
ENV/
env/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Testing
.pytest_cache/
.coverage
htmlcov/
.tox/

# Database
*.db
*.sqlite
*.sqlite3

# Logs
*.log
logs/

# Environment
.env
.env.local

# OS
.DS_Store
Thumbs.db

# Docker
.docker/

# Node
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
EOF

echo "=== Bulletproof repo structure created ==="
ls -la "$REPO_DIR"/*.md "$REPO_DIR"/Makefile "$REPO_DIR"/.gitignore 2>/dev/null
