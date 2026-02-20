# Kimi Sysadmin AI

A secure system administration AI assistant with comprehensive safety controls.

## Features

- **LLM Integration**: OpenAI-compatible API with tool calling
- **Safety Filters**: Blocklist for dangerous commands, graylist for confirmation
- **Policy Engine**: Rego/OPA support with Python fallback
- **Multiple Executors**: Host, Docker, and Kubernetes execution
- **CLI Interface**: Interactive chat and command execution

## Installation

```bash
pip install -e .
```

Or with optional dependencies:

```bash
# With OPA support
pip install -e ".[opa]"

# Development dependencies
pip install -e ".[dev]"
```

## Quick Start

Set your OpenAI API key:

```bash
export OPENAI_API_KEY="your-api-key"
```

Check system status:

```bash
kimi-admin status
```

Run a command with safety checks:

```bash
kimi-admin run "ls -la"
```

Start interactive chat:

```bash
kimi-admin chat
```

Check if a command would be allowed:

```bash
kimi-admin check "rm -rf /"
```

## Safety

The safety layer blocks these categories of commands:

- **Destructive**: `rm -rf /`, `mkfs`, `dd` to disks
- **Reverse Shells**: bash/nc/python reverse shells
- **Credential Access**: `/etc/shadow`, SSH keys, AWS credentials
- **Network Exfiltration**: Data exfiltration via network tools

Graylisted commands (require confirmation):

- Package management (`apt install`, `pip install`)
- Service control (`systemctl restart`)
- Container operations (`docker run`, `kubectl delete`)
- Permission changes (`chmod 777`)

## Configuration

Environment variables:

- `OPENAI_API_KEY`: Your OpenAI API key
- `OPENAI_BASE_URL`: Custom API endpoint (optional)
- `OPA_URL`: OPA server URL (default: http://localhost:8181)

## License

MIT
