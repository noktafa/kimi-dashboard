# Kimi Ecosystem Documentation

Welcome to the comprehensive documentation for the Kimi Ecosystem - a self-improving infrastructure security platform.

## Overview

The Kimi Ecosystem is a suite of integrated tools designed to automate security auditing, safe system administration, and continuous infrastructure improvement through an iterative convergence loop.

## Components

| Component | Purpose | CLI | Status |
|-----------|---------|-----|--------|
| **kimi-security-auditor** | Web vulnerability scanner | `kimi-audit` | ✅ Production Ready |
| **kimi-sysadmin-ai** | AI-powered safe system admin | `kimi-admin` | ✅ Production Ready |
| **kimi-convergence-loop** | Self-healing infrastructure pipeline | `kimi-converge` | ✅ Production Ready |
| **kimi-dashboard** | Real-time visualization | `kimi-dashboard` | ✅ Production Ready |

## Quick Navigation

### Getting Started
- [Installation Guide](guides/installation.md) - Set up the entire ecosystem
- [Quick Start Tutorial](guides/quickstart.md) - Your first 5 minutes

### Architecture
- [System Overview](architecture/overview.md) - High-level architecture diagrams
- [Component Interactions](architecture/interactions.md) - How components communicate
- [Data Flow](architecture/data-flow.md) - Information flow through the system

### API Documentation
- [Security Auditor API](api/security-auditor.md) - Programmatic vulnerability scanning
- [Sysadmin AI API](api/sysadmin-ai.md) - Safe command execution
- [Convergence Loop API](api/convergence-loop.md) - Pipeline orchestration
- [Dashboard API](api/dashboard.md) - Real-time monitoring

### Guides
- [Security Testing Guide](guides/security-testing.md) - Using the auditor effectively
- [Safety Guide](guides/safety.md) - How sysadmin-ai protects your systems
- [Convergence Configuration](guides/convergence-config.md) - Tuning the loop
- [Troubleshooting](guides/troubleshooting.md) - Common issues and solutions

### Integration Examples
- [Python Integration](examples/python-integration.md) - Using libraries directly
- [CI/CD Integration](examples/cicd-integration.md) - GitHub Actions, GitLab CI
- [Custom Plugins](examples/custom-plugins.md) - Extending the ecosystem

### Development
- [Contributing](development/contributing.md) - How to contribute
- [Testing](development/testing.md) - Running the test suite
- [Release Process](development/releases.md) - Versioning and releases

## Philosophy

**Iterate until secure.** The convergence loop continuously diagnoses, fixes, attacks, and validates your infrastructure until no new issues are found.

## Safety First

The ecosystem implements comprehensive safety controls:

- **99 block patterns** for dangerous commands
- **86 gray patterns** requiring confirmation
- **Policy engine** with OPA/Rego support
- **Multi-layered validation** before any system changes

## Support

- 📧 Email: support@kimi-ecosystem.dev
- 💬 Discord: [Join our community](https://discord.gg/kimi-ecosystem)
- 🐛 Issues: [GitHub Issues](https://github.com/kimi-ecosystem/kimi-ecosystem/issues)

## License

MIT License - See [LICENSE](../LICENSE) for details.
