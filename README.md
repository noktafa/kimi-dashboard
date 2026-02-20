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
