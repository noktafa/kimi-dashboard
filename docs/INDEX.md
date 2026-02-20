# Documentation Index

## Complete Documentation Structure

```
kimi-ecosystem/docs/
├── README.md                          # Main documentation entry point
├── architecture/
│   ├── overview.md                    # System architecture diagrams (Mermaid)
│   └── interactions.md                # Component interaction flows
├── api/
│   ├── security-auditor.md            # Security Auditor API reference
│   ├── sysadmin-ai.md                 # Sysadmin AI API reference
│   ├── convergence-loop.md            # Convergence Loop API reference
│   └── dashboard.md                   # Dashboard API reference
├── guides/
│   ├── installation.md                # Installation instructions
│   ├── quickstart.md                  # 5-minute quick start
│   ├── security-testing.md            # Security testing guide
│   ├── safety.md                      # Safety controls guide
│   ├── convergence-config.md          # Configuration guide
│   └── troubleshooting.md             # Troubleshooting guide
└── examples/
    ├── python-integration.md          # Python integration examples
    ├── cicd-integration.md            # CI/CD integration examples
    └── custom-plugins.md              # Custom plugin development
```

## Quick Reference

### Getting Started
1. [Installation](guides/installation.md) - Set up the ecosystem
2. [Quick Start](guides/quickstart.md) - Your first 5 minutes

### Architecture
- [System Overview](architecture/overview.md) - High-level architecture with Mermaid diagrams
- [Component Interactions](architecture/interactions.md) - How components communicate

### API Documentation
- [Security Auditor](api/security-auditor.md) - Vulnerability scanning API
- [Sysadmin AI](api/sysadmin-ai.md) - Safe command execution API
- [Convergence Loop](api/convergence-loop.md) - Pipeline orchestration API
- [Dashboard](api/dashboard.md) - Real-time monitoring API

### Guides
- [Security Testing](guides/security-testing.md) - Using the auditor effectively
- [Safety](guides/safety.md) - Understanding safety controls
- [Configuration](guides/convergence-config.md) - Tuning the convergence loop
- [Troubleshooting](guides/troubleshooting.md) - Common issues and solutions

### Examples
- [Python Integration](examples/python-integration.md) - Using libraries directly
- [CI/CD Integration](examples/cicd-integration.md) - GitHub Actions, GitLab CI, etc.
- [Custom Plugins](examples/custom-plugins.md) - Extending the ecosystem

## Infrastructure Files

```
kimi-ecosystem/
├── .github/workflows/ci.yml           # GitHub Actions CI/CD workflow
└── Makefile                           # Common development tasks
```

### Makefile Targets

| Target | Description |
|--------|-------------|
| `make install` | Install all packages |
| `make install-dev` | Install with development dependencies |
| `make test` | Run all tests |
| `make lint` | Run all linters |
| `make format` | Format code with black |
| `make build` | Build all packages |
| `make docker-all` | Build all Docker images |
| `make clean` | Clean build artifacts |
| `make docs` | Build documentation |
| `make release` | Full release process |

### CI/CD Workflow

The GitHub Actions workflow (`.github/workflows/ci.yml`) includes:

- **Lint & Format**: black, ruff, mypy
- **Unit Tests**: pytest with coverage for all components
- **Integration Tests**: End-to-end testing
- **Security Scans**: SARIF output for GitHub Security
- **Build**: Package building and distribution
- **Docker**: Multi-image builds
- **Documentation**: MkDocs build and deploy

## Statistics

| Category | Files | Lines |
|----------|-------|-------|
| Architecture | 2 | ~400 |
| API Docs | 4 | ~1,800 |
| Guides | 6 | ~2,400 |
| Examples | 3 | ~1,600 |
| **Total** | **15** | **~6,200** |

## Contributing

To contribute to the documentation:

1. Follow the existing structure and style
2. Use Mermaid for diagrams
3. Include code examples where applicable
4. Test all commands before submitting
5. Update this index when adding new pages
