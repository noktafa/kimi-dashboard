# Sysadmin AI API Documentation

## Overview

The Kimi Sysadmin AI provides a secure interface for AI-powered system administration with comprehensive safety controls and policy enforcement.

## Installation

```bash
pip install kimi-sysadmin-ai
```

## Core Classes

### `SafetyFilter`

The first line of defense against dangerous commands.

```python
from kimi_sysadmin_ai import SafetyFilter
from kimi_sysadmin_ai.safety import SafetyLevel

filter = SafetyFilter()

# Check a command
result = filter.check("ls -la")
print(result.level)      # SafetyLevel.SAFE
print(result.reason)     # "Command passed safety checks"

# Blocked command
result = filter.check("rm -rf /")
print(result.level)      # SafetyLevel.BLOCK
print(result.reason)     # "Command matches dangerous pattern: rm -rf /"

# Gray command (requires confirmation)
result = filter.check("apt install nginx")
print(result.level)      # SafetyLevel.GRAY
print(result.reason)     # "Command requires confirmation: apt install..."
```

#### Methods

##### `check(command: str) -> SafetyResult`

Analyze a command and return safety classification.

##### `is_safe(command: str) -> bool`

Quick check if command is safe (no confirmation needed).

```python
if filter.is_safe("ls -la"):
    execute("ls -la")
```

##### `is_blocked(command: str) -> bool`

Check if command is blocked.

```python
if filter.is_blocked("rm -rf /"):
    raise SecurityError("Command blocked")
```

### `PolicyEngine`

Advanced policy enforcement with OPA/Rego support.

```python
from kimi_sysadmin_ai import PolicyEngine, PolicyInput

engine = PolicyEngine()

# Create policy input
input_data = PolicyInput(
    command="docker ps",
    user="admin",
    working_dir="/home/admin",
    environment={"PATH": "/usr/bin"},
    executor_type="host"
)

# Evaluate policy
result = engine.evaluate(input_data)
print(result.decision)   # PolicyDecision.ALLOW
print(result.reason)     # "Policy allowed the command"
```

#### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `opa_url` | `Optional[str]` | `None` | OPA server URL |
| `policy_file` | `Optional[str]` | `None` | Path to Rego policy |
| `use_opa` | `bool` | `True` | Try OPA before fallback |

#### Methods

##### `evaluate(input_data: PolicyInput) -> PolicyResult`

Evaluate policy against input data.

##### `can_execute(input_data: PolicyInput) -> bool`

Quick check if command can be executed.

```python
if engine.can_execute(input_data):
    execute_command(command)
```

##### `get_backend_info() -> Dict[str, Any]`

Get information about available backends.

```python
info = engine.get_backend_info()
print(info)
# {
#     "python_backend": {"available": True},
#     "opa_backend": {"available": True, "url": "http://localhost:8181"}
# }
```

### `LLMClient`

Interface to OpenAI-compatible LLM APIs.

```python
from kimi_sysadmin_ai import LLMClient

client = LLMClient(
    api_key="your-api-key",
    base_url="https://api.openai.com/v1",  # Optional
    model="gpt-4"
)

# Simple chat
response = await client.chat("What's the disk usage?")
print(response)

# With tools
response = await client.chat_with_tools(
    "Check disk usage",
    tools=[{
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Run a shell command",
            "parameters": {...}
        }
    }]
)
```

#### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | `str` | required | OpenAI API key |
| `base_url` | `Optional[str]` | `None` | Custom API endpoint |
| `model` | `str` | `"gpt-4"` | Model to use |
| `temperature` | `float` | `0.1` | Sampling temperature |

### `HostExecutor`

Safe command execution on the host system.

```python
from kimi_sysadmin_ai import HostExecutor, SafetyFilter

executor = HostExecutor(
    safety_filter=SafetyFilter(),
    policy_engine=PolicyEngine(),
    require_confirmation=True
)

# Execute with full safety checks
result = await executor.execute("ls -la")
print(result.stdout)
print(result.stderr)
print(result.returncode)

# Execute without confirmation (dangerous commands blocked)
result = await executor.execute("cat /etc/passwd", confirm=True)
```

#### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `safety_filter` | `SafetyFilter` | `SafetyFilter()` | Safety filter instance |
| `policy_engine` | `PolicyEngine` | `PolicyEngine()` | Policy engine instance |
| `require_confirmation` | `bool` | `True` | Require confirmation for gray commands |
| `working_dir` | `Optional[str]` | `None` | Default working directory |

#### Methods

##### `async execute(command: str, confirm: bool = False) -> ExecutionResult`

Execute a command with safety checks.

```python
result = await executor.execute("df -h")
print(result.stdout)     # Command output
print(result.stderr)     # Error output
print(result.returncode) # Exit code
print(result.duration)   # Execution time
```

##### `check(command: str) -> Tuple[SafetyResult, PolicyResult]`

Check if command would be allowed without executing.

```python
safety, policy = executor.check("apt update")
print(f"Safety: {safety.level}")
print(f"Policy: {policy.decision}")
```

## Safety Levels

### Blocklist Patterns

The following command patterns are **always blocked**:

```python
# Mass deletion
r'rm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/'        # rm -rf /
r'rm\s+-[a-zA-Z]*f[a-zA-Z]*\s+/'        # rm -f /
r'rm\s+.*\*.*'                          # rm with wildcards

# Filesystem destruction
r'mkfs\.\w+\s+/dev/'                     # mkfs on devices
r'dd\s+.*of=/dev/[sh]d[a-z]'            # dd to disks

# Reverse shells
r'bash\s+-i\s*>&\s*/dev/tcp/'           # Bash reverse shell
r'nc\s+-[a-zA-Z]*e[a-zA-Z]*\s+'         # Netcat with exec
r'python\d*\s+-c\s*.*socket.*connect'   # Python reverse shell

# Credential access
r'cat\s+/etc/shadow'                     # Shadow file access
r'cat\s+/root/\.ssh/'                    # SSH key access
r'cat\s+~/.aws/credentials'             # AWS credentials

# System destruction
r':\(\)\s*\{\s*:\|:\s*&\s*\};\s*:'     # Fork bomb
```

### Graylist Patterns

The following require **user confirmation**:

```python
# Package management
r'apt\s+(install|remove|purge)'
r'pip\s+(install|uninstall)'
r'npm\s+(install|uninstall)'

# Service management
r'systemctl\s+(start|stop|restart)'
r'service\s+\w+\s+(start|stop)'

# Container operations
r'docker\s+(run|exec|rm|stop|kill)'
r'kubectl\s+(delete|apply|exec)'

# Permission changes
r'chmod\s+-R\s+777'
r'chown\s+-R\s+\w+:\w+\s+/'`
```

## Policy Configuration

### Python Backend Rules

Default rules for the Python policy backend:

```python
rules = [
    {
        "name": "block_root_destructive",
        "description": "Block destructive commands as root",
        "condition": {
            "user": "root",
            "command_patterns": ["rm -rf /", "mkfs", "dd if=/dev/zero"]
        },
        "action": "deny"
    },
    {
        "name": "allow_readonly",
        "description": "Allow read-only commands",
        "condition": {
            "command_patterns": ["^ls", "^cat", "^grep", "^ps", "^df"]
        },
        "action": "allow"
    }
]
```

### OPA/Rego Integration

```python
from kimi_sysadmin_ai import PolicyEngine

# Connect to OPA server
engine = PolicyEngine(
    opa_url="http://localhost:8181",
    policy_file="/path/to/policy.rego"
)

# Check if OPA is available
info = engine.get_backend_info()
if info["opa_backend"]["available"]:
    print("Using OPA for policy enforcement")
```

Example Rego policy:

```rego
package sysadmin

import future.keywords.if
import future.keywords.in

default allow := false

# Allow read-only commands
allow if {
    input.command in ["ls", "cat", "grep", "ps", "df", "du"]
}

# Deny destructive commands as root
deny if {
    input.user == "root"
    regex.match("rm -rf /|mkfs|dd if=/dev/zero", input.command)
}
```

## Advanced Usage

### Custom Safety Filter

```python
from kimi_sysadmin_ai.safety import SafetyFilter, SafetyLevel

class CustomSafetyFilter(SafetyFilter):
    def __init__(self):
        super().__init__()
        # Add custom block patterns
        self.block_patterns.append(
            re.compile(r'custom_dangerous_command', re.IGNORECASE)
        )
        # Add custom gray patterns
        self.gray_patterns.append(
            re.compile(r'semi_dangerous', re.IGNORECASE)
        )

filter = CustomSafetyFilter()
```

### Interactive Confirmation

```python
from kimi_sysadmin_ai import HostExecutor

class InteractiveExecutor(HostExecutor):
    async def confirm(self, command: str, reason: str) -> bool:
        print(f"\n⚠️  Command requires confirmation:")
        print(f"   Command: {command}")
        print(f"   Reason: {reason}")
        
        response = input("Execute? [y/N]: ")
        return response.lower() == 'y'

executor = InteractiveExecutor()
result = await executor.execute("apt update")  # Will prompt for confirmation
```

### Audit Logging

```python
import logging
from kimi_sysadmin_ai import HostExecutor

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sysadmin-ai")

class AuditedExecutor(HostExecutor):
    async def execute(self, command: str, confirm: bool = False):
        logger.info(f"Executing: {command}")
        
        result = await super().execute(command, confirm)
        
        logger.info(f"Completed: {command} (exit: {result.returncode})")
        return result

executor = AuditedExecutor()
```

## Integration Examples

### With FastAPI

```python
from fastapi import FastAPI, HTTPException
from kimi_sysadmin_ai import HostExecutor, SafetyFilter

app = FastAPI()
executor = HostExecutor()

@app.post("/execute")
async def execute_command(command: str, confirm: bool = False):
    # Pre-check
    safety = SafetyFilter().check(command)
    if safety.level.value == "block":
        raise HTTPException(403, f"Command blocked: {safety.reason}")
    
    # Execute
    result = await executor.execute(command, confirm)
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode
    }
```

### With Celery

```python
from celery import Celery
from kimi_sysadmin_ai import HostExecutor

app = Celery('sysadmin')
executor = HostExecutor()

@app.task
def run_command_task(command: str):
    import asyncio
    result = asyncio.run(executor.execute(command))
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode
    }
```

## Error Handling

```python
from kimi_sysadmin_ai import HostExecutor
from kimi_sysadmin_ai.safety import SafetyLevel

async def safe_execute():
    executor = HostExecutor()
    
    try:
        result = await executor.execute("rm -rf /")
    except PermissionError as e:
        print(f"Permission denied: {e}")
    except SecurityError as e:
        print(f"Security violation: {e}")
    except TimeoutError:
        print("Command timed out")
    except Exception as e:
        print(f"Unexpected error: {e}")
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key | required |
| `OPENAI_BASE_URL` | Custom API endpoint | `None` |
| `OPA_URL` | OPA server URL | `http://localhost:8181` |
| `SYSADMIN_REQUIRE_CONFIRMATION` | Require confirmation | `true` |
| `SYSADMIN_MAX_TIMEOUT` | Max command timeout | `300` |
