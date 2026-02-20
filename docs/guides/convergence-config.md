# Convergence Configuration Guide

## Overview

This guide explains how to configure the Kimi Convergence Loop for your specific use case.

## Configuration File Structure

```yaml
# convergence.yaml

# =============================================================================
# Loop Settings
# =============================================================================
loop:
  max_iterations: 10              # Maximum iterations before stopping
  convergence_threshold: 0.95      # Threshold for considering converged
  timeout_seconds: 3600            # Total pipeline timeout
  backoff_seconds: 5               # Delay between iterations

# =============================================================================
# Target Configuration
# =============================================================================
target: "https://example.com"     # Target URL or path

# =============================================================================
# Pipeline Steps
# =============================================================================
steps:
  diagnose:
    enabled: true
    tool: kimi-security-auditor
    args: [--deep-scan]
    env:
      AUDITOR_TIMEOUT: "60"
  
  fix:
    enabled: true
    tool: kimi-sysadmin-ai
    args: [--auto-apply]
    env:
      OPENAI_API_KEY: "${OPENAI_API_KEY}"
  
  attack:
    enabled: true
    tool: kimi-security-auditor
    args: [--attack-mode]
  
  validate:
    enabled: true
    tool: pytest
    args: [-v, --tb=short]
    working_dir: "./tests"

# =============================================================================
# Event Configuration
# =============================================================================
events:
  webhook_url: "http://localhost:8766/events"
  emit_interval: 5
  buffer_size: 1000

# =============================================================================
# Notifications
# =============================================================================
notifications:
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    on_events: [CONVERGENCE_REACHED, ERROR]
  
  email:
    smtp_host: "smtp.example.com"
    smtp_port: 587
    username: "${EMAIL_USER}"
    password: "${EMAIL_PASS}"
    to: ["admin@example.com"]
    on_events: [ERROR]
```

## Step Configuration

### Diagnose Step

The diagnose step discovers issues in your system:

```yaml
steps:
  diagnose:
    enabled: true
    tool: kimi-security-auditor
    args:
      - --deep-scan          # Thorough scanning
      - --timeout=60         # Per-request timeout
      - --max-depth=5        # Crawl depth
    env:
      AUDITOR_USER_AGENT: "KimiSecurity/1.0"
```

### Fix Step

The fix step applies remediation:

```yaml
steps:
  fix:
    enabled: true
    tool: kimi-sysadmin-ai
    args:
      - --auto-apply         # Auto-apply safe fixes
      - --dry-run            # Preview changes (no actual changes)
    env:
      OPENAI_API_KEY: "${OPENAI_API_KEY}"
      SYSADMIN_REQUIRE_CONFIRMATION: "false"
```

### Attack Step

The attack step attempts to exploit vulnerabilities:

```yaml
steps:
  attack:
    enabled: true
    tool: kimi-security-auditor
    args:
      - --attack-mode        # Aggressive testing
      - --include-safe       # Include safe exploits only
```

### Validate Step

The validate step verifies fixes:

```yaml
steps:
  validate:
    enabled: true
    tool: pytest
    args:
      - -v                   # Verbose output
      - --tb=short           # Short traceback
      - --cov=src            # Coverage
    working_dir: "./tests"
    timeout: 300
```

## Use Case Examples

### Web Application Security

```yaml
# webapp-security.yaml
target: "https://myapp.com"

loop:
  max_iterations: 10
  timeout_seconds: 7200  # 2 hours

steps:
  diagnose:
    enabled: true
    tool: kimi-security-auditor
    args: [--deep-scan, --include-jwt, --include-api]
  
  fix:
    enabled: true
    tool: custom-remediation-script
    args: [--auto-fix]
  
  attack:
    enabled: true
    tool: kimi-security-auditor
    args: [--attack-mode, --exclude-destructive]
  
  validate:
    enabled: true
    tool: curl
    args: [-f, https://myapp.com/health]
```

### Infrastructure Hardening

```yaml
# infrastructure-hardening.yaml
target: "/etc"

loop:
  max_iterations: 5
  timeout_seconds: 3600

steps:
  diagnose:
    enabled: true
    tool: lynis
    args: [audit, system]
  
  fix:
    enabled: true
    tool: kimi-sysadmin-ai
    args: [--apply-hardening]
  
  attack:
    enabled: true
    tool: nmap
    args: [-sV, --script=vuln]
  
  validate:
    enabled: true
    tool: lynis
    args: [audit, system, --quick]
```

### CI/CD Pipeline

```yaml
# cicd-pipeline.yaml
target: "."

loop:
  max_iterations: 3
  timeout_seconds: 600

steps:
  diagnose:
    enabled: true
    tool: bandit
    args: [-r, src/]
  
  fix:
    enabled: false  # Manual review required
  
  attack:
    enabled: true
    tool: safety
    args: [check]
  
  validate:
    enabled: true
    tool: pytest
    args: [--cov=src, --cov-fail-under=80]
```

## Advanced Configuration

### Custom Steps

```yaml
steps:
  custom_step:
    enabled: true
    tool: /path/to/custom/script.py
    args: [--arg1, value1]
    env:
      CUSTOM_VAR: "value"
    working_dir: "./custom"
    timeout: 120
```

### Conditional Steps

```yaml
steps:
  diagnose:
    enabled: true
    
  fix:
    enabled: true
    condition: "diagnose.findings.length > 0"
    
  attack:
    enabled: true
    condition: "fix.applied > 0"
```

### Parallel Execution

```yaml
steps:
  diagnose_parallel:
    enabled: true
    parallel:
      - tool: kimi-security-auditor
        args: [--module=sql]
      - tool: kimi-security-auditor
        args: [--module=cmd]
      - tool: kimi-security-auditor
        args: [--module=jwt]
```

## Environment Variables

Use environment variables in your configuration:

```yaml
target: "${TARGET_URL}"

steps:
  fix:
    env:
      OPENAI_API_KEY: "${OPENAI_API_KEY}"
      API_BASE_URL: "${API_BASE_URL:-https://api.openai.com/v1}"
```

Variable syntax:
- `${VAR}` - Required variable
- `${VAR:-default}` - Variable with default value
- `${VAR:?error}` - Required variable with error message

## Validation

Validate your configuration:

```bash
# Check configuration syntax
kimi-converge validate --config convergence.yaml

# Dry run (show what would happen)
kimi-converge run --config convergence.yaml --dry-run
```
