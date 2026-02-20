# Kimi Convergence Loop

A self-healing pipeline that iteratively diagnoses, fixes, attacks, and validates systems until convergence.

## Overview

The convergence loop is a state machine that continuously improves system security and stability through an iterative process:

1. **Diagnose** - Analyze the system for issues
2. **Fix** - Apply fixes to discovered issues
3. **Attack** - Attempt to break/exploit the system
4. **Validate** - Verify fixes work and system is stable

The loop continues until convergence (no changes needed) or max iterations reached.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Convergence Loop                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐     │
│  │ Diagnose│──▶│   Fix   │──▶│ Attack  │──▶│ Validate│     │
│  └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘     │
│       │             │             │             │           │
│       └─────────────┴─────────────┴─────────────┘           │
│                         │                                   │
│                         ▼                                   │
│              ┌─────────────────────┐                        │
│              │   State Machine     │                        │
│              │  (loop until done)  │                        │
│              └─────────────────────┘                        │
│                         │                                   │
│                         ▼                                   │
│              ┌─────────────────────┐                        │
│              │     Event Bus       │──▶ Dashboard           │
│              └─────────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Run with default config
kimi-converge

# Run with custom config
kimi-converge --config /path/to/config.yaml

# Run with specific target
kimi-converge --target /path/to/project --max-iterations 10
```

## Configuration

Configuration is loaded from YAML files:

```yaml
# config.yaml
loop:
  max_iterations: 10
  convergence_threshold: 0.95
  timeout_seconds: 3600

steps:
  diagnose:
    enabled: true
    tool: kimi-security-auditor
    args: [--deep-scan]
  
  fix:
    enabled: true
    tool: kimi-sysadmin-ai
    args: [--auto-apply]
  
  attack:
    enabled: true
    tool: custom-pentest
    args: [--lightweight]
  
  validate:
    enabled: true
    tool: pytest
    args: [-v, --tb=short]

events:
  webhook_url: https://dashboard.example.com/events
  emit_interval: 5
```

## Pipeline Steps

### 1. Diagnose

Calls external diagnostic tools (e.g., `kimi-security-auditor`) to analyze the system and identify issues.

**Input:** Target path/system
**Output:** List of issues with severity and recommendations

### 2. Fix

Calls external fixing tools (e.g., `kimi-sysadmin-ai`) to apply fixes to diagnosed issues.

**Input:** List of issues from Diagnose step
**Output:** List of applied fixes

### 3. Attack

Calls external attack/penetration testing tools to attempt to break the system.

**Input:** Target path/system
**Output:** List of vulnerabilities found

### 4. Validate

Calls external validation tools (e.g., `pytest`) to verify the system works correctly.

**Input:** Target path/system
**Output:** Test results, coverage metrics

## State Machine

The state machine manages the convergence loop:

```
States:
  - IDLE
  - DIAGNOSING
  - FIXING
  - ATTACKING
  - VALIDATING
  - CONVERGED
  - FAILED

Transitions:
  IDLE ──▶ DIAGNOSING
  DIAGNOSING ──▶ FIXING (issues found)
  DIAGNOSING ──▶ ATTACKING (no issues)
  FIXING ──▶ ATTACKING
  ATTACKING ──▶ VALIDATING
  VALIDATING ──▶ CONVERGED (no changes, tests pass)
  VALIDATING ──▶ DIAGNOSING (changes made or tests fail)
  ANY ──▶ FAILED (error or timeout)
```

## Event Bus

The event bus emits structured events for dashboard integration:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "session_id": "uuid",
  "iteration": 3,
  "state": "VALIDATING",
  "event_type": "step_complete",
  "data": {
    "step": "validate",
    "result": "passed",
    "metrics": {...}
  }
}
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy src/kimi_convergence_loop
```
