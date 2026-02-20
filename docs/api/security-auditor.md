# Security Auditor API Documentation

## Overview

The Kimi Security Auditor provides both a command-line interface and a programmatic Python API for comprehensive web application security scanning.

## Installation

```bash
pip install kimi-security-auditor
```

## Core Classes

### `SecurityAuditor`

Main entry point for security scanning.

```python
from kimi_security_auditor import SecurityAuditor
from kimi_security_auditor.models import ScanResult, Finding, Severity

async def scan_target():
    auditor = SecurityAuditor("https://example.com")
    result = await auditor.run()
    
    print(f"Found {len(result.findings)} vulnerabilities")
    for finding in result.findings:
        print(f"- {finding.title} ({finding.severity.value})")
```

#### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | required | Target URL to scan |
| `timeout` | `float` | `30.0` | Request timeout in seconds |
| `max_depth` | `int` | `3` | Maximum crawl depth |
| `concurrency` | `int` | `10` | Concurrent request limit |

#### Methods

##### `async run() -> ScanResult`

Execute a full security scan.

```python
result = await auditor.run()
```

##### `async run_recon() -> ReconResult`

Run only reconnaissance phase.

```python
recon = await auditor.run_recon()
print(f"Found {len(recon.endpoints)} endpoints")
```

##### `async run_attacks(endpoints: List[str]) -> List[Finding]`

Run attack modules against specific endpoints.

```python
findings = await auditor.run_attacks(["/api/users", "/admin"])
```

### `ScanResult`

Container for scan results.

```python
from kimi_security_auditor.models import ScanResult

# Properties
result.target          # Target URL
result.start_time      # Scan start time
result.end_time        # Scan end time
result.findings        # List of Finding objects
result.metadata        # Additional scan metadata

# Methods
result.get_findings_by_severity(Severity.CRITICAL)
result.get_summary()   # Dict of severity counts
result.to_dict()       # Convert to dictionary
result.to_json()       # Convert to JSON string
```

### `Finding`

Represents a discovered vulnerability.

```python
from kimi_security_auditor.models import Finding, Severity, Confidence

finding = Finding(
    title="SQL Injection",
    description="SQL injection vulnerability detected",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    target="https://example.com/search",
    finding_type="sql_injection_error",
    evidence="Database error: You have an error in your SQL syntax",
    remediation="Use parameterized queries",
    references=["https://owasp.org/..."],
    parameter="q",
    payload="' OR '1'='1",
)
```

#### Finding Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `title` | `str` | Short vulnerability name |
| `description` | `str` | Detailed description |
| `severity` | `Severity` | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `confidence` | `Confidence` | CERTAIN, HIGH, MEDIUM, LOW, TENTATIVE |
| `target` | `str` | Affected URL/endpoint |
| `finding_type` | `str` | Machine-readable type identifier |
| `evidence` | `Optional[str]` | Proof of vulnerability |
| `remediation` | `Optional[str]` | Fix recommendation |
| `references` | `List[str]` | External references |
| `parameter` | `Optional[str]` | Vulnerable parameter |
| `payload` | `Optional[str]` | Payload that triggered finding |
| `timestamp` | `datetime` | When finding was discovered |
| `metadata` | `Dict[str, Any]` | Additional data |

## Scanner Modules

### SQL Injection Scanner

```python
from kimi_security_auditor.attacks import SQLInjectionScanner
import httpx

async def scan_sql_injection():
    async with httpx.AsyncClient() as client:
        scanner = SQLInjectionScanner(client)
        
        # Scan URL parameters
        findings = await scanner.scan_url(
            "https://example.com/search?q=test",
            parameters=["q", "category"]
        )
        
        # Scan form inputs
        form_findings = await scanner.scan_form(
            "https://example.com/login",
            form_data={"username": "", "password": ""}
        )
```

#### Detection Methods

| Method | Description | Severity |
|--------|-------------|----------|
| Error-based | Database error messages | CRITICAL |
| Time-based blind | Time delay detection | HIGH |
| Boolean-based blind | True/false differential | HIGH |
| Union-based | UNION query detection | CRITICAL |

### Command Injection Scanner

```python
from kimi_security_auditor.attacks import CommandInjectionScanner

async def scan_command_injection():
    async with httpx.AsyncClient() as client:
        scanner = CommandInjectionScanner(client)
        
        findings = await scanner.scan_url(
            "https://example.com/ping?host=127.0.0.1",
            parameters=["host"]
        )
```

### JWT Scanner

```python
from kimi_security_auditor.attacks import JWTScanner

async def scan_jwt():
    async with httpx.AsyncClient() as client:
        scanner = JWTScanner(client)
        findings = await scanner.scan("https://example.com/api")
```

#### JWT Checks

| Check | Description | Severity |
|-------|-------------|----------|
| Weak secrets | Tests common secrets | CRITICAL |
| Algorithm confusion | None/None algorithm | CRITICAL |
| Missing expiration | No exp claim | MEDIUM |
| Sensitive data | Passwords in claims | HIGH |

## Reporting

### Markdown Report

```python
from kimi_security_auditor.reporting import MarkdownReporter

reporter = MarkdownReporter()
report = reporter.generate(result)

with open("report.md", "w") as f:
    f.write(report)
```

### SARIF Report

```python
from kimi_security_auditor.reporting import SARIFReporter

reporter = SARIFReporter()
report = reporter.generate(result)

with open("results.sarif", "w") as f:
    f.write(report)
```

### JSON Report

```python
import json

# ScanResult has built-in JSON serialization
json_report = result.to_json(indent=2)
```

## Advanced Usage

### Custom Payloads

```python
from kimi_security_auditor.attacks import SQLInjectionScanner

class CustomSQLScanner(SQLInjectionScanner):
    # Override default payloads
    TIME_PAYLOADS = [
        "' AND SLEEP(10) -- ",
        "' AND pg_sleep(10) -- ",
        "'; WAITFOR DELAY '0:0:10' -- ",
    ]
```

### Concurrent Scanning

```python
import asyncio

async def scan_multiple(targets: List[str]):
    auditors = [SecurityAuditor(t) for t in targets]
    
    # Run all scans concurrently
    results = await asyncio.gather(
        *[a.run() for a in auditors],
        return_exceptions=True
    )
    
    return results
```

### Custom Event Handlers

```python
from kimi_security_auditor import SecurityAuditor

class AuditingWithProgress:
    def __init__(self):
        self.findings = []
    
    def on_finding(self, finding):
        print(f"🔍 Found: {finding.title}")
        self.findings.append(finding)
    
    async def scan(self, target: str):
        auditor = SecurityAuditor(target)
        auditor.on_finding = self.on_finding
        return await auditor.run()
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AUDITOR_TIMEOUT` | Default request timeout | `30.0` |
| `AUDITOR_MAX_DEPTH` | Default crawl depth | `3` |
| `AUDITOR_USER_AGENT` | HTTP User-Agent string | `kimi-security-auditor/0.1.0` |

### Programmatic Configuration

```python
from kimi_security_auditor import SecurityAuditor

auditor = SecurityAuditor(
    target="https://example.com",
    timeout=60.0,
    max_depth=5,
    concurrency=20,
    headers={
        "Authorization": "Bearer token123",
        "X-Custom-Header": "value"
    }
)
```

## Error Handling

```python
import httpx
from kimi_security_auditor import SecurityAuditor

async def safe_scan():
    try:
        auditor = SecurityAuditor("https://example.com")
        result = await auditor.run()
        return result
    except httpx.TimeoutException:
        print("Scan timed out")
    except httpx.NetworkError:
        print("Network error - check connectivity")
    except Exception as e:
        print(f"Unexpected error: {e}")
```

## Integration Examples

### With FastAPI

```python
from fastapi import FastAPI
from kimi_security_auditor import SecurityAuditor

app = FastAPI()

@app.post("/scan")
async def scan_endpoint(target: str):
    auditor = SecurityAuditor(target)
    result = await auditor.run()
    return result.to_dict()
```

### With Celery

```python
from celery import Celery
from kimi_security_auditor import SecurityAuditor

app = Celery('security')

@app.task
def scan_task(target: str):
    import asyncio
    auditor = SecurityAuditor(target)
    result = asyncio.run(auditor.run())
    return result.to_dict()
```
