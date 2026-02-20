# kimi-sysadmin-ai Specification

## Overview
A secure sysadmin AI assistant that can safely execute system administration tasks with comprehensive safety controls.

## Core Components

### 1. LLM Client
- OpenAI-compatible API client
- Tool calling support for:
  - `run_command`: Execute shell commands
  - `read_file`: Read file contents
  - `write_file`: Write file contents
  - `list_directory`: List directory contents
  - `get_system_info`: Get system information

### 2. Policy Engine
- Rego/OPA support for policy evaluation
- Python fallback when OPA is unavailable
- Policy-based command approval/denial

### 3. Safety Filters
- **Blocklist**: Destructive commands that are always blocked
  - `rm -rf`, `mkfs`, `dd` to disk devices
  - Reverse shell patterns
  - Credential access attempts
  - Network exfiltration patterns
- **Graylist**: Commands requiring confirmation
  - Package installations
  - System service modifications
  - Network configuration changes

### 4. Executors
- **Host Executor**: Direct execution on host system
- **Docker Executor**: Execution in Docker containers
- **Kubernetes Executor**: Execution in K8s pods

### 5. CLI Entry Point
- Command: `kimi-admin`
- Interactive and non-interactive modes

## Project Structure
```
kimi-sysadmin-ai/
├── pyproject.toml
├── src/
│   └── kimi_sysadmin_ai/
│       ├── __init__.py
│       ├── cli.py
│       ├── llm_client.py
│       ├── policy_engine.py
│       ├── safety.py
│       ├── executors/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── host.py
│       │   ├── docker.py
│       │   └── kubernetes.py
│       └── policies/
│           └── default.rego
├── tests/
│   └── test_safety.py
└── README.md
```

## Safety Requirements
- All commands pass through safety filters before execution
- Blocked commands are rejected with clear explanations
- Graylisted commands require user confirmation
- All executions are logged
- Credentials and secrets are never exposed
