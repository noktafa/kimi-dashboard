# Kimi Ecosystem Convergence Demo

A complete demonstration of the Kimi Security Auditor scanning vulnerable infrastructure deployed on DigitalOcean.

## Overview

This demo orchestrates a full convergence loop demonstration that:
- Scans 5 DigitalOcean servers with kimi-audit
- Collects real findings from the vulnerable applications
- Displays results in a clean, formatted console output
- Shows before/after security posture
- Generates professional executive summary reports

## Target Infrastructure

| Server | IP Address | Type | Description |
|--------|------------|------|-------------|
| Load Balancer | 167.172.71.245 | Nginx | Traffic distribution layer |
| API Server 1 | 178.128.117.238 | Flask | Vulnerable web application |
| API Server 2 | 152.42.220.203 | Flask | Vulnerable web application |
| Database | 152.42.222.84 | PostgreSQL | Data storage layer |
| Cache | 167.71.196.196 | Redis | Caching layer |

## Files

- **demo.py** - Main orchestration script that runs the convergence loop
- **report_template.md** - Professional report template with executive summary
- **run_demo.sh** - One-command demo runner with colored output
- **reports/** - Generated reports directory (created on first run)

## Usage

### Quick Start

```bash
./run_demo.sh
```

### Python Script Directly

```bash
python3 demo.py
```

### Options

```bash
# Generate only markdown report
./run_demo.sh --format markdown

# Generate only JSON report
./run_demo.sh --format json

# Custom report directory
./run_demo.sh --report-dir /path/to/reports

# Skip console display (batch mode)
./run_demo.sh --no-display
```

## Vulnerabilities Tested

The demo scans for:

- **SQL Injection** - Database query manipulation
- **Command Injection** - OS command execution
- **Cross-Site Scripting (XSS)** - Client-side script injection
- **Insecure Deserialization** - Object injection attacks
- **IDOR** - Insecure Direct Object References
- **Security Headers** - Missing or misconfigured headers
- **CORS Misconfiguration** - Cross-origin policy issues
- **File Upload** - Unrestricted file uploads
- **Directory Traversal** - Path traversal attacks
- **XXE** - XML External Entity injection

## Report Format

The generated reports include:

1. **Executive Summary** - High-level risk assessment
2. **Risk Score** - Numerical risk rating (0-100)
3. **Findings by Severity** - Categorized vulnerability list
4. **Remediation Timeline** - Prioritized fix schedule
5. **Compliance Mapping** - OWASP, PCI-DSS, NIST alignment

## Output Example

```
╔══════════════════════════════════════════════════════════════╗
║                 CONVERGENCE DEMO RESULTS                     ║
╚══════════════════════════════════════════════════════════════╝

Overall Risk Score: 85/100 (CRITICAL)

┌──────────────────┬────────┬──────────┬───────┬────────┬─────┬─────┬───────┐
│ Target           │ Type   │ Critical │ High  │ Medium │ Low │ Info│ Total │
├──────────────────┼────────┼──────────┼───────┼────────┼─────┼─────┼───────┤
│ API Server 1     │ flask  │ 3        │ 5     │ 4      │ 2   │ 3   │ 17    │
│ API Server 2     │ flask  │ 3        │ 5     │ 4      │ 2   │ 3   │ 17    │
│ Load Balancer    │ nginx  │ 0        │ 1     │ 2      │ 3   │ 2   │ 8     │
│ ...              │ ...    │ ...      │ ...   │ ...    │ ... │ ... │ ...   │
└──────────────────┴────────┴──────────┴───────┴────────┴─────┴─────┴───────┘
```

## Requirements

- Python 3.8+
- httpx
- click
- rich
- kimi-security-auditor (from parent directory)

## Exit Codes

- `0` - Demo completed successfully, no critical findings
- `1` - Demo completed, critical/high vulnerabilities found
- `130` - Interrupted by user (Ctrl+C)
- Other - Error occurred

## Notes

- The demo produces real data from the actual infrastructure
- No mocks or simulated data are used
- Scan duration depends on network latency and target response times
- Reports are timestamped to avoid overwriting previous results
