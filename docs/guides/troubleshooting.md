# Troubleshooting Guide

## Common Issues and Solutions

### Installation Issues

#### pip install fails

**Problem:** `pip install` fails with compilation errors.

**Solution:**
```bash
# Ensure you have Python 3.9+
python --version

# Upgrade pip
pip install --upgrade pip

# Install build dependencies
pip install wheel setuptools

# Try installation again
pip install kimi-security-auditor
```

#### ModuleNotFoundError

**Problem:** `ModuleNotFoundError: No module named 'kimi_security_auditor'`

**Solution:**
```bash
# Ensure virtual environment is activated
source .venv/bin/activate

# Verify installation
pip list | grep kimi

# Reinstall if needed
pip install -e ./kimi-security-auditor --force-reinstall
```

### Security Auditor Issues

#### Connection Timeouts

**Problem:** Scan fails with timeout errors.

**Solution:**
```bash
# Increase timeout
kimi-audit https://example.com --timeout 60

# Reduce concurrency
kimi-audit https://example.com --concurrency 5

# Add delay between requests
kimi-audit https://example.com --delay 1.0
```

#### False Positives

**Problem:** Too many false positive findings.

**Solution:**
```bash
# Adjust confidence threshold
kimi-audit https://example.com --min-confidence high

# Skip certain tests
kimi-audit https://example.com --no-boolean-sql

# Use custom payload list
kimi-audit https://example.com --payloads-file custom-payloads.txt
```

### Sysadmin AI Issues

#### Command Blocked

**Problem:** Safe command is being blocked.

**Solution:**
```python
# Check why command is blocked
from kimi_sysadmin_ai import SafetyFilter

filter = SafetyFilter()
result = filter.check("your-command")
print(result.reason)

# If it's a false positive, use --confirm flag
kimi-admin run "your-command" --confirm
```

#### OPA Connection Failed

**Problem:** `OPA connection failed, using Python fallback`

**Solution:**
```bash
# Check OPA is running
curl http://localhost:8181/health

# Start OPA if needed
docker run -d -p 8181:8181 openpolicyagent/opa:latest run --server

# Or disable OPA and use Python backend
export OPA_ENABLED=false
```

### Convergence Loop Issues

#### Pipeline Stuck

**Problem:** Pipeline appears to be stuck.

**Solution:**
```bash
# Check current state
kimi-converge status

# View logs
kimi-converge logs --follow

# Cancel and restart
kimi-converge cancel
kimi-converge run --config convergence.yaml
```

#### Not Converging

**Problem:** Pipeline runs indefinitely without converging.

**Solution:**
```yaml
# In convergence.yaml, adjust settings:
loop:
  max_iterations: 5  # Limit iterations
  convergence_threshold: 0.90  # Lower threshold
  
steps:
  fix:
    enabled: true
    args: [--aggressive-fixes]  # Apply more fixes
```

### Dashboard Issues

#### Cannot Connect

**Problem:** Cannot connect to dashboard WebSocket.

**Solution:**
```bash
# Check dashboard is running
curl http://localhost:8766/health

# Check port availability
lsof -i :8766

# Restart dashboard
kimi-dashboard --port 8766

# Check firewall settings
sudo ufw allow 8766
```

#### No Data Displayed

**Problem:** Dashboard shows no sessions or data.

**Solution:**
```bash
# Check convergence loop is emitting events
kimi-converge run --config convergence.yaml -v

# Verify WebSocket URL
export CONVERGENCE_WS_URL=ws://localhost:8765

# Check database permissions
ls -la dashboard.db
```

## Debug Mode

Enable verbose logging:

```bash
# All components
export KIMI_LOG_LEVEL=DEBUG

# Specific component
export AUDITOR_LOG_LEVEL=DEBUG
export SYSADMIN_LOG_LEVEL=DEBUG
export CONVERGENCE_LOG_LEVEL=DEBUG
```

## Getting Help

If you're still experiencing issues:

1. Check the logs: `~/.local/share/kimi/logs/`
2. Run with debug output: `-vv` flag
3. Check GitHub Issues: https://github.com/kimi-ecosystem/kimi-ecosystem/issues
4. Join Discord: https://discord.gg/kimi-ecosystem

## Diagnostic Commands

```bash
# Check versions
kimi-audit --version
kimi-admin --version
kimi-converge --version
kimi-dashboard --version

# Check health
kimi-audit --health-check
kimi-admin --health-check
kimi-converge --health-check
kimi-dashboard --health-check

# Run diagnostics
kimi-doctor
```
