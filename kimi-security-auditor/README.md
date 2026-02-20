# Kimi Security Auditor

A comprehensive web application security auditing tool designed for penetration testers and security researchers.

## Features

### Reconnaissance
- **Technology Detection**: Identifies web servers, frameworks, databases, CMS, and more
- **Web Crawler**: Discovers pages and endpoints through recursive crawling
- **Hidden Path Discovery**: Checks for common sensitive paths (admin, api, backup, etc.)
- **API Endpoint Discovery**: Finds REST API endpoints through pattern matching

### Vulnerability Scanning

#### Injection Vulnerabilities
- **SQL Injection**: Error-based, time-based blind, and boolean-based blind detection
- **NoSQL Injection**: MongoDB and Redis injection detection (operators, JSON-based)
- **Command Injection**: Detects OS command execution vulnerabilities
- **SSTI (Server-Side Template Injection)**: Jinja2, Twig, Django, ERB, and more
- **XXE (XML External Entity)**: File disclosure, blind XXE, SVG upload XXE

#### Configuration & Headers
- **CORS Misconfiguration**: Wildcard with credentials, arbitrary origin reflection, null origin
- **Security Headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Cookie Security**: Secure, HttpOnly, SameSite flag analysis
- **Information Disclosure**: Server header analysis

#### File & Path Vulnerabilities
- **Directory Traversal**: Path traversal with multiple encoding bypasses (Linux & Windows)
- **File Upload**: Dangerous extensions, MIME bypass, double extension, magic bytes bypass

#### Authentication & Session
- **JWT Security**: Weak secrets, algorithm confusion, missing expiration, sensitive data exposure

### Reporting
- **Markdown**: Human-readable reports with severity indicators
- **SARIF**: Standard format for integration with CI/CD pipelines
- **JSON**: Machine-readable format for further processing
- **Console**: Rich-formatted terminal output

## Installation

```bash
# Clone the repository
git clone https://github.com/kimi-ecosystem/kimi-security-auditor.git
cd kimi-security-auditor

# Install in development mode
pip install -e .

# Or install from PyPI (when available)
pip install kimi-security-auditor
```

## Usage

### Basic Scan

```bash
kimi-audit https://example.com
```

### Save Report

```bash
# Markdown report
kimi-audit https://example.com -o report.md

# JSON report
kimi-audit https://example.com -f json -o report.json

# SARIF report (for GitHub/CodeQL integration)
kimi-audit https://example.com -f sarif -o results.sarif
```

### Selective Scanning

```bash
# Skip reconnaissance (faster)
kimi-audit https://example.com --no-recon

# Skip specific vulnerability tests
kimi-audit https://example.com --no-nosql --no-ssti --no-xxe

# Only security headers and CORS
kimi-audit https://example.com --no-recon --no-sql --no-cmd --no-jwt --no-nosql --no-ssti --no-xxe --no-traversal --no-upload

# Custom timeout and crawl depth
kimi-audit https://example.com --timeout 60 --max-depth 5
```

## Command Reference

```
Usage: kimi-audit [OPTIONS] TARGET

Options:
  -o, --output PATH       Output file path
  -f, --format [auto|markdown|md|json|sarif|console]
                          Output format  [default: auto]
  --no-recon              Skip reconnaissance phase
  --no-sql                Skip SQL injection scans
  --no-cmd                Skip command injection scans
  --no-jwt                Skip JWT scans
  --no-nosql              Skip NoSQL injection scans
  --no-ssti               Skip SSTI scans
  --no-xxe                Skip XXE scans
  --no-cors               Skip CORS checks
  --no-headers            Skip security headers analysis
  --no-traversal          Skip directory traversal scans
  --no-upload             Skip file upload vulnerability scans
  -t, --timeout FLOAT     Request timeout in seconds  [default: 30.0]
  -d, --max-depth INTEGER Maximum crawl depth  [default: 3]
  -v, --verbose           Verbose output
  --help                  Show this message and exit.
```

## Python API

```python
import asyncio
from kimi_security_auditor import SecurityAuditor

async def scan():
    auditor = SecurityAuditor("https://example.com")
    result = await auditor.run()
    
    print(f"Found {len(result.findings)} vulnerabilities")
    for finding in result.findings:
        print(f"- {finding.title} ({finding.severity.value})")

asyncio.run(scan())
```

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src/
ruff check src/

# Type checking
mypy src/
```

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper permission before scanning any system you do not own.
