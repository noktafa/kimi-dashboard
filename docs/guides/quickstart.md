# Quick Start Tutorial

Welcome to the Kimi Ecosystem! This tutorial will get you up and running in 5 minutes.

## Prerequisites

- Python 3.9+ installed
- Basic familiarity with command line
- (Optional) An OpenAI API key for AI features

## Step 1: Installation

```bash
# Install all components
pip install kimi-security-auditor kimi-sysadmin-ai kimi-convergence-loop kimi-dashboard

# Verify installation
kimi-audit --version
kimi-admin --version
```

## Step 2: Run Your First Security Scan

```bash
# Scan a website for vulnerabilities
kimi-audit https://example.com -o report.md

# View the report
cat report.md
```

Example output:
```
🔍 Kimi Security Auditor Report
═══════════════════════════════════════════════════

Target: https://example.com
Duration: 45.2s
Findings: 3

───────────────────────────────────────────────────
FINDINGS SUMMARY
───────────────────────────────────────────────────

Critical: 0
High:     1  ████████████████████
Medium:   1  ████████████
Low:      1  ████████
```

## Step 3: Safe System Administration

```bash
# Check a command would be safe
kimi-admin check "ls -la"
# Output: ✅ Safe to execute

kimi-admin check "rm -rf /"
# Output: ❌ Blocked: Command matches dangerous pattern

# Execute a safe command
kimi-admin run "df -h"

# Start interactive chat (requires OPENAI_API_KEY)
export OPENAI_API_KEY="your-key"
kimi-admin chat
```

## Step 4: Run the Convergence Loop

Create a configuration file `convergence.yaml`:

```yaml
loop:
  max_iterations: 5
  timeout_seconds: 600

steps:
  diagnose:
    enabled: true
    tool: kimi-security-auditor
  
  fix:
    enabled: true
    tool: kimi-sysadmin-ai
  
  attack:
    enabled: true
    tool: kimi-security-auditor
  
  validate:
    enabled: true
    tool: echo
    args: ["Validation passed"]
```

Run the loop:

```bash
kimi-converge run --config convergence.yaml
```

## Step 5: View the Dashboard

```bash
# Start the dashboard
kimi-dashboard

# Open browser
open http://localhost:8766
```

## Next Steps

- Read the [Security Testing Guide](security-testing.md)
- Learn about [Safety Controls](safety.md)
- Explore [Python Integration](../examples/python-integration.md)
- Check out the [API Documentation](../api/)

## Common Commands

```bash
# Security scanning
kimi-audit https://target.com                    # Basic scan
kimi-audit https://target.com -f json            # JSON output
kimi-audit https://target.com --no-recon         # Skip reconnaissance

# System administration
kimi-admin run "command"                         # Execute safely
kimi-admin check "command"                       # Check safety only
kimi-admin chat                                  # Interactive AI

# Convergence loop
kimi-converge run                                # Run with default config
kimi-converge run --config custom.yaml           # Custom config
kimi-converge status                             # Check status

# Dashboard
kimi-dashboard                                   # Start server
kimi-dashboard --port 8080                       # Custom port
```

## Getting Help

```bash
# Get help for any command
kimi-audit --help
kimi-admin --help
kimi-converge --help
kimi-dashboard --help
```
