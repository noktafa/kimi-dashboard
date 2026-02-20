# Security Testing Guide

## Overview

This guide covers how to effectively use the Kimi Security Auditor to identify vulnerabilities in your web applications.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Scanning Strategies](#scanning-strategies)
3. [Understanding Findings](#understanding-findings)
4. [False Positives](#false-positives)
5. [Advanced Techniques](#advanced-techniques)
6. [Reporting](#reporting)
7. [Integration](#integration)

## Getting Started

### Basic Scan

Start with a basic scan to understand your target:

```bash
# Basic scan with all modules
kimi-audit https://example.com

# Save to file
kimi-audit https://example.com -o report.md

# JSON output for automation
kimi-audit https://example.com -f json -o report.json
```

### Understanding the Output

```
🔍 Kimi Security Auditor
═══════════════════════════════════════════════════

Target: https://example.com
Started: 2024-01-15 10:00:00
Duration: 45.2s

───────────────────────────────────────────────────
FINDINGS SUMMARY
───────────────────────────────────────────────────

Critical: 1  ████████████████████████████████████
High:     2  ████████████████████
Medium:   3  ████████████
Low:      5  ████████
Info:     8  ████

Total: 19 findings
```

## Scanning Strategies

### 1. Black Box Testing

Test without any prior knowledge:

```bash
# Full reconnaissance and attack
kimi-audit https://example.com

# Skip recon for faster scanning (if you know the endpoints)
kimi-audit https://example.com --no-recon
```

### 2. White Box Testing

With knowledge of the application:

```python
from kimi_security_auditor import SecurityAuditor

# Target specific endpoints you know
auditor = SecurityAuditor("https://example.com")

# Scan specific endpoints
findings = await auditor.run_attacks([
    "/api/users",
    "/api/admin",
    "/api/login"
])
```

### 3. API Testing

For REST APIs:

```bash
# API-focused scan
kimi-audit https://api.example.com/v1

# With authentication
kimi-audit https://api.example.com/v1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-API-Key: $API_KEY"
```

### 4. Incremental Scanning

For large applications:

```bash
# Scan specific modules
kimi-audit https://example.com --no-cmd --no-jwt  # SQLi only
kimi-audit https://example.com --no-sql --no-jwt  # Command injection only
kimi-audit https://example.com --no-sql --no-cmd  # JWT only
```

## Understanding Findings

### Severity Levels

| Severity | Description | Action Required |
|----------|-------------|-----------------|
| **Critical** | Immediate exploitation possible | Fix within 24 hours |
| **High** | Significant security impact | Fix within 1 week |
| **Medium** | Moderate security impact | Fix within 1 month |
| **Low** | Minor security issue | Fix in next release |
| **Info** | Informational | Review and document |

### Confidence Levels

| Confidence | Meaning |
|------------|---------|
| **Certain** | Verified vulnerability |
| **High** | Very likely vulnerability |
| **Medium** | Likely vulnerability |
| **Low** | Possible vulnerability |
| **Tentative** | Requires manual verification |

### Reading a Finding

```markdown
## 🔴 SQL Injection (Error-based) - MySQL

**Severity:** Critical  
**Confidence:** High  
**Target:** https://example.com/search?q=test  
**Parameter:** q

### Description
Error-based SQL injection vulnerability detected in parameter 'q'. 
The application returned a database error when a malicious payload was submitted.

### Evidence
```
Database error: You have an error in your SQL syntax; 
check the manual that corresponds to your MySQL server 
version for the right syntax to use near ''' at line 1
```

### Payload
```
' OR '1'='1
```

### Remediation
1. Use parameterized queries/prepared statements
2. Validate and sanitize all user input
3. Apply principle of least privilege to database accounts

### References
- https://owasp.org/www-community/attacks/SQL_Injection
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
```

## False Positives

### Common False Positives

1. **SQL Error Messages**
   - Some applications show generic errors that look like SQL errors
   - Verify by checking if the error contains actual SQL syntax

2. **Command Injection**
   - Some applications intentionally execute commands
   - Check if the output is expected behavior

3. **JWT Weak Secrets**
   - Test tokens might use weak secrets intentionally
   - Verify in production environment

### Verification Steps

```python
from kimi_security_auditor import SecurityAuditor

async def verify_finding():
    auditor = SecurityAuditor("https://example.com")
    
    # Re-run with specific payload
    finding = await auditor.verify_payload(
        url="https://example.com/search",
        parameter="q",
        payload="' OR '1'='1",
        expected_behavior="database_error"
    )
    
    # Manual verification
    print(f"Verified: {finding.verified}")
```

## Advanced Techniques

### 1. Custom Payloads

```python
from kimi_security_auditor.attacks import SQLInjectionScanner

class CustomScanner(SQLInjectionScanner):
    # Add application-specific payloads
    TIME_PAYLOADS = [
        "' AND SLEEP(5) -- ",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
        # Custom payloads for your application
        "' UNION SELECT SLEEP(5) -- ",
    ]

async with httpx.AsyncClient() as client:
    scanner = CustomScanner(client)
    findings = await scanner.scan_url(url)
```

### 2. Authentication Handling

```python
from kimi_security_auditor import SecurityAuditor
import httpx

async def authenticated_scan():
    # Create client with authentication
    cookies = httpx.Cookies()
    cookies.set("session", "your-session-cookie")
    
    headers = {
        "Authorization": "Bearer your-token",
        "X-Custom-Header": "value"
    }
    
    async with httpx.AsyncClient(
        cookies=cookies,
        headers=headers
    ) as client:
        auditor = SecurityAuditor(
            "https://example.com",
            client=client
        )
        return await auditor.run()
```

### 3. Rate Limiting and Delays

```python
from kimi_security_auditor import SecurityAuditor

# Respectful scanning with delays
auditor = SecurityAuditor(
    "https://example.com",
    delay_between_requests=1.0,  # 1 second delay
    max_concurrent=5             # Limit concurrency
)
```

### 4. Scope Control

```python
# Limit scan to specific paths
auditor = SecurityAuditor(
    "https://example.com",
    allowed_paths=["/api/*", "/admin/*"],
    excluded_paths=[/logout", "/health"]
)
```

## Reporting

### SARIF for CI/CD

```bash
# Generate SARIF for GitHub/CodeQL
kimi-audit https://example.com -f sarif -o results.sarif

# Upload to GitHub
gh codeql upload-results --sarif=results.sarif
```

### Custom Reports

```python
from kimi_security_auditor.reporting import MarkdownReporter
from datetime import datetime

class CustomReporter(MarkdownReporter):
    def generate(self, result):
        report = f"""# Security Audit Report

**Generated:** {datetime.now().isoformat()}  
**Target:** {result.target}

## Executive Summary

This report contains {len(result.findings)} findings...

## Findings by Category

"""
        # Custom categorization
        categories = self.categorize_findings(result.findings)
        for category, findings in categories.items():
            report += f"\n### {category}\n\n"
            for finding in findings:
                report += self.format_finding(finding)
        
        return report
```

## Integration

### GitHub Actions

```yaml
name: Security Audit

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install auditor
        run: pip install kimi-security-auditor
      
      - name: Run security audit
        run: kimi-audit https://staging.example.com -f sarif -o results.sarif
      
      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### Slack Notifications

```python
import httpx
from kimi_security_auditor import SecurityAuditor

async def scan_with_notification():
    auditor = SecurityAuditor("https://example.com")
    result = await auditor.run()
    
    # Send critical findings to Slack
    critical = result.get_findings_by_severity(Severity.CRITICAL)
    if critical:
        await send_slack_alert(critical)

async def send_slack_alert(findings):
    webhook_url = "https://hooks.slack.com/services/..."
    
    message = {
        "text": f"🚨 {len(findings)} critical vulnerabilities found!",
        "attachments": [
            {
                "color": "danger",
                "fields": [
                    {"title": f.title, "value": f.description, "short": False}
                    for f in findings[:5]
                ]
            }
        ]
    }
    
    async with httpx.AsyncClient() as client:
        await client.post(webhook_url, json=message)
```

## Best Practices

### 1. Scope Definition

Always define clear scope before scanning:

```python
# Document what you're testing
scope = {
    "target": "https://example.com",
    "allowed_paths": ["/api/*"],
    "excluded_paths": ["/api/webhooks/*"],
    "rate_limit": "10 req/sec",
    "testing_window": "2024-01-15 02:00-04:00 UTC"
}
```

### 2. Responsible Disclosure

```markdown
## Vulnerability Disclosure Process

1. **Discovery**: Document the vulnerability
2. **Verification**: Confirm it's exploitable
3. **Report**: Notify the security team
4. **Remediation**: Allow time for fixes
5. **Verification**: Confirm fix works
6. **Disclosure**: Public disclosure (if applicable)
```

### 3. Continuous Monitoring

```python
# Schedule regular scans
import asyncio
from datetime import timedelta

async def continuous_monitoring():
    while True:
        result = await run_security_scan()
        
        if result.has_critical_findings():
            await send_alert(result)
        
        # Wait until next scan
        await asyncio.sleep(timedelta(hours=24).total_seconds())
```

## Troubleshooting

### Common Issues

1. **Connection Timeouts**
   ```bash
   # Increase timeout
   kimi-audit https://example.com --timeout 60
   ```

2. **Rate Limiting**
   ```bash
   # Add delays between requests
   kimi-audit https://example.com --delay 1.0
   ```

3. **Large Applications**
   ```bash
   # Limit crawl depth
   kimi-audit https://example.com --max-depth 2
   ```

### Debug Mode

```bash
# Verbose output
kimi-audit https://example.com -v

# Very verbose
kimi-audit https://example.com -vv
```
