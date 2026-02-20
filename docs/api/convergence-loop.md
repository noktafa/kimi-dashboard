# Convergence Loop API Documentation

## Overview

The Kimi Convergence Loop provides a state machine-driven pipeline for iterative system improvement through diagnose-fix-attack-validate cycles.

## Installation

```bash
pip install kimi-convergence-loop
```

## Core Classes

### `Pipeline`

Main orchestrator for the convergence loop.

```python
from kimi_convergence_loop import Pipeline, Config

# Load configuration
config = Config.load("convergence.yaml")

# Create pipeline
pipeline = Pipeline(config)

# Run the pipeline
result = await pipeline.run()

print(f"Success: {result.success}")
print(f"Iterations: {result.iterations}")
print(f"Converged: {result.convergence_reached}")
print(f"Duration: {result.duration_seconds}s")
```

#### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | `Config` | required | Pipeline configuration |
| `event_bus` | `EventBus` | `None` | Custom event bus |

#### Methods

##### `async run() -> PipelineResult`

Execute the convergence pipeline.

```python
result = await pipeline.run()

# Check results
if result.convergence_reached:
    print("✅ System converged to secure state")
elif not result.success:
    print(f"❌ Pipeline failed: {result.error}")
else:
    print(f"⚠️ Max iterations reached without convergence")
```

##### `stop() -> None`

Stop the pipeline gracefully.

```python
# Stop after current iteration
pipeline.stop()
```

### `Config`

Configuration for the convergence pipeline.

```python
from kimi_convergence_loop import Config, load_config

# Load from YAML file
config = load_config("convergence.yaml")

# Or create programmatically
config = Config(
    target="/path/to/project",
    loop={
        "max_iterations": 10,
        "convergence_threshold": 0.95,
        "timeout_seconds": 3600,
        "backoff_seconds": 5
    },
    steps={
        "diagnose": {
            "enabled": True,
            "tool": "kimi-security-auditor",
            "args": ["--deep-scan"]
        },
        "fix": {
            "enabled": True,
            "tool": "kimi-sysadmin-ai",
            "args": ["--auto-apply"]
        },
        "attack": {
            "enabled": True,
            "tool": "kimi-security-auditor",
            "args": ["--attack-mode"]
        },
        "validate": {
            "enabled": True,
            "tool": "pytest",
            "args": ["-v"]
        }
    },
    events={
        "webhook_url": "http://localhost:8766/events",
        "emit_interval": 5
    }
)
```

#### Configuration Schema

```yaml
# convergence.yaml
loop:
  max_iterations: 10           # Maximum iterations before stopping
  convergence_threshold: 0.95   # Threshold for considering converged
  timeout_seconds: 3600         # Total pipeline timeout
  backoff_seconds: 5            # Delay between iterations

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
    tool: kimi-security-auditor
    args: [--attack-mode]
  
  validate:
    enabled: true
    tool: pytest
    args: [-v, --tb=short]

events:
  webhook_url: http://localhost:8766/events
  emit_interval: 5
```

### `StateMachine`

Manages pipeline state transitions.

```python
from kimi_convergence_loop import StateMachine, State, Transition

sm = StateMachine()

# Get current state
print(sm.state)  # State.IDLE

# Check if transition is valid
if sm.can_transition(Transition.START):
    sm.transition(Transition.START)

# Register state change handlers
def on_diagnosing(from_state, to_state, transition, data):
    print(f"Started diagnosing from {from_state.name}")

sm.on_state(State.DIAGNOSING, on_diagnosing)

# Get transition history
for entry in sm.history:
    print(f"{entry.from_state.name} -> {entry.to_state.name}")
```

#### States

| State | Description |
|-------|-------------|
| `IDLE` | Initial state, waiting to start |
| `DIAGNOSING` | Running diagnostic scans |
| `FIXING` | Applying fixes to issues |
| `ATTACKING` | Attempting to exploit vulnerabilities |
| `VALIDATING` | Verifying fixes and stability |
| `CONVERGED` | Pipeline completed successfully |
| `FAILED` | Pipeline failed |

#### Transitions

| Transition | From -> To | Description |
|------------|------------|-------------|
| `START` | IDLE -> DIAGNOSING | Begin pipeline |
| `DIAGNOSIS_COMPLETE` | DIAGNOSING -> FIXING | Diagnosis finished |
| `FIX_COMPLETE` | FIXING -> ATTACKING | Fixes applied |
| `ATTACK_COMPLETE` | ATTACKING -> VALIDATING | Attack phase done |
| `CONVERGE` | VALIDATING -> CONVERGED | System converged |
| `RETRY` | VALIDATING -> IDLE | Start next iteration |
| `FAIL` | Any -> FAILED | Error occurred |

### `EventBus`

Event streaming for dashboard integration.

```python
from kimi_convergence_loop import EventBus, EventType

# Create event bus
bus = EventBus(
    session_id="my-session",
    webhook_url="http://localhost:8766/events",
    emit_interval=5
)

# Register handlers
@bus.register_handler
def on_event(event):
    print(f"[{event.event_type.name}] {event.data}")

# Start event bus
await bus.start()

# Emit events
await bus.emit(EventType.STEP_STARTED, {"step": "diagnose"})
await bus.emit(EventType.STEP_COMPLETE, {"step": "diagnose"})

# Stop event bus
await bus.stop()
```

#### Event Types

| Event Type | Description |
|------------|-------------|
| `SESSION_STARTED` | Pipeline session started |
| `SESSION_ENDED` | Pipeline session ended |
| `ITERATION_STARTED` | New iteration began |
| `ITERATION_ENDED` | Iteration completed |
| `STATE_CHANGED` | State machine transition |
| `STEP_STARTED` | Pipeline step started |
| `STEP_COMPLETE` | Pipeline step completed |
| `STEP_FAILED` | Pipeline step failed |
| `CONVERGENCE_REACHED` | System converged |
| `ERROR` | Error occurred |
| `METRICS` | Metrics update |

#### Event Structure

```python
{
    "event_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z",
    "session_id": "session-uuid",
    "iteration": 3,
    "state": "VALIDATING",
    "event_type": "STEP_COMPLETE",
    "data": {
        "step": "validate",
        "result": "passed"
    }
}
```

## Pipeline Steps

### `DiagnoseStep`

Discovers issues in the target system.

```python
from kimi_convergence_loop.steps import DiagnoseStep

step = DiagnoseStep(
    config={
        "enabled": True,
        "tool": "kimi-security-auditor",
        "args": ["--deep-scan"]
    },
    event_bus=bus
)

context = {"target": "https://example.com"}
result = await step.execute(context)

print(f"Found {len(result.findings)} issues")
for finding in result.findings:
    print(f"- {finding.title}")
```

### `FixStep`

Applies fixes to discovered issues.

```python
from kimi_convergence_loop.steps import FixStep

step = FixStep(
    config={
        "enabled": True,
        "tool": "kimi-sysadmin-ai",
        "args": ["--auto-apply"]
    },
    event_bus=bus
)

context = {
    "target": "https://example.com",
    "findings": findings  # From DiagnoseStep
}

result = await step.execute(context)
print(f"Applied {len(result.fixes_applied)} fixes")
```

### `AttackStep`

Attempts to exploit vulnerabilities.

```python
from kimi_convergence_loop.steps import AttackStep

step = AttackStep(
    config={
        "enabled": True,
        "tool": "kimi-security-auditor",
        "args": ["--attack-mode"]
    },
    event_bus=bus
)

context = {"target": "https://example.com"}
result = await step.execute(context)

print(f"Found {len(result.findings)} vulnerabilities")
```

### `ValidateStep`

Verifies system stability and fix effectiveness.

```python
from kimi_convergence_loop.steps import ValidateStep

step = ValidateStep(
    config={
        "enabled": True,
        "tool": "pytest",
        "args": ["-v"]
    },
    event_bus=bus
)

context = {"target": "/path/to/project"}
result = await step.execute(context)

if result.success:
    print("✅ All tests passed")
else:
    print(f"❌ {result.metrics.get('tests_failed', 0)} tests failed")
```

## Advanced Usage

### Custom Step Implementation

```python
from kimi_convergence_loop.steps import Step, StepResult
from dataclasses import dataclass

@dataclass
class CustomStepResult(StepResult):
    custom_metric: int = 0

class CustomStep(Step):
    def __init__(self, config, event_bus):
        super().__init__("custom", config, event_bus)
    
    async def execute(self, context: dict) -> CustomStepResult:
        await self.emit_start()
        
        # Custom logic here
        result = CustomStepResult(
            step_name=self.name,
            success=True,
            custom_metric=42
        )
        
        await self.emit_complete(result)
        return result
```

### Convergence Criteria

```python
from kimi_convergence_loop import Pipeline, Config

class CustomPipeline(Pipeline):
    def _check_convergence(self, results: list) -> bool:
        """Custom convergence logic."""
        # Check if no new findings in last 3 iterations
        recent_findings = [
            r for r in results[-3:] 
            if r.step_name == "diagnose"
        ]
        
        if len(recent_findings) < 3:
            return False
        
        # Converged if no findings in last 3 iterations
        return all(
            len(r.findings) == 0 
            for r in recent_findings
        )
```

### Event Replay

```python
from kimi_convergence_loop import EventBus

class ReplayableEventBus(EventBus):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.all_events = []
    
    async def emit(self, event_type, data):
        event = await super().emit(event_type, data)
        self.all_events.append(event)
        return event
    
    def replay(self, handler):
        """Replay all events to a new handler."""
        for event in self.all_events:
            handler(event)
```

## Integration Examples

### With FastAPI

```python
from fastapi import FastAPI, BackgroundTasks
from kimi_convergence_loop import Pipeline, Config

app = FastAPI()
pipelines = {}

@app.post("/pipelines")
async def create_pipeline(config: dict):
    pipeline_id = str(uuid.uuid4())
    config_obj = Config(**config)
    pipelines[pipeline_id] = Pipeline(config_obj)
    return {"pipeline_id": pipeline_id}

@app.post("/pipelines/{pipeline_id}/run")
async def run_pipeline(pipeline_id: str, background: BackgroundTasks):
    pipeline = pipelines[pipeline_id]
    
    async def run():
        result = await pipeline.run()
        # Store result
    
    background.add_task(run)
    return {"status": "started"}

@app.get("/pipelines/{pipeline_id}/status")
async def get_status(pipeline_id: str):
    pipeline = pipelines[pipeline_id]
    return {
        "state": pipeline.state_machine.state.name,
        "iteration": pipeline._iteration
    }
```

### With Celery

```python
from celery import Celery
from kimi_convergence_loop import Pipeline, Config

app = Celery('convergence')

@app.task
def run_convergence(config_dict: dict):
    import asyncio
    
    config = Config(**config_dict)
    pipeline = Pipeline(config)
    
    result = asyncio.run(pipeline.run())
    
    return {
        "success": result.success,
        "iterations": result.iterations,
        "converged": result.convergence_reached,
        "duration": result.duration_seconds
    }
```

## Error Handling

```python
from kimi_convergence_loop import Pipeline, Config

async def safe_run():
    config = Config.load("convergence.yaml")
    pipeline = Pipeline(config)
    
    try:
        result = await pipeline.run()
        
        if result.convergence_reached:
            print("✅ Convergence achieved")
        elif result.final_state.name == "FAILED":
            print(f"❌ Pipeline failed: {result.error}")
        else:
            print(f"⚠️ Did not converge after {result.iterations} iterations")
            
    except TimeoutError:
        print("Pipeline timed out")
    except Exception as e:
        print(f"Unexpected error: {e}")
```

## Metrics and Monitoring

```python
from kimi_convergence_loop import Pipeline

class MonitoredPipeline(Pipeline):
    async def run(self):
        import time
        start = time.time()
        
        result = await super().run()
        
        # Calculate metrics
        metrics = {
            "total_duration": time.time() - start,
            "iterations": result.iterations,
            "findings_per_iteration": [
                len(r.findings) for r in result.step_results
                if r.step_name == "diagnose"
            ],
            "fixes_per_iteration": [
                len(r.fixes_applied) for r in result.step_results
                if r.step_name == "fix"
            ]
        }
        
        # Send to monitoring
        await self.send_metrics(metrics)
        
        return result
```
