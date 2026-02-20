# Component Interactions

## Inter-Component Communication

### Overview

The Kimi Ecosystem components communicate through multiple channels:

1. **Direct API Calls** - Synchronous request/response
2. **Event Bus** - Asynchronous event streaming
3. **Shared Database** - Persistent state storage
4. **WebSocket** - Real-time bidirectional communication

### Communication Matrix

| From / To | Auditor | Sysadmin | Convergence | Dashboard |
|-----------|---------|----------|-------------|-----------|
| **Auditor** | - | - | API | Events |
| **Sysadmin** | - | - | API | Events |
| **Convergence** | CLI/API | CLI/API | - | WebSocket |
| **Dashboard** | - | - | WebSocket | - |

## Detailed Interaction Flows

### 1. Security Audit Flow

```mermaid
sequenceDiagram
    participant User
    participant Conv as Convergence Loop
    participant EB as Event Bus
    participant Audit as Security Auditor
    participant Target as Target System
    participant DB as Database

    User->>Conv: Start audit
    Conv->>EB: emit(STEP_STARTED, diagnose)
    
    Conv->>Audit: run_scan(target)
    Audit->>Target: HTTP requests
    Target-->>Audit: Responses
    
    loop For each vulnerability found
        Audit->>Audit: Analyze response
        Audit-->>Conv: Finding object
    end
    
    Audit-->>Conv: ScanResult
    Conv->>DB: Store findings
    Conv->>EB: emit(STEP_COMPLETE, findings)
```

### 2. Safe Command Execution Flow

```mermaid
sequenceDiagram
    participant Conv as Convergence Loop
    participant Sys as Sysadmin AI
    participant SF as Safety Filter
    participant PE as Policy Engine
    participant Exec as Executor
    participant Host as Host System

    Conv->>Sys: execute(command)
    
    Sys->>SF: check(command)
    alt Blocked
        SF-->>Sys: SafetyResult(BLOCK)
        Sys-->>Conv: ExecutionError("Blocked")
    else Gray
        SF-->>Sys: SafetyResult(GRAY)
        Sys->>Conv: Request confirmation
        Conv-->>Sys: Approved
    else Safe
        SF-->>Sys: SafetyResult(SAFE)
    end
    
    Sys->>PE: evaluate(input)
    alt Denied
        PE-->>Sys: PolicyResult(DENY)
        Sys-->>Conv: ExecutionError("Policy denied")
    else Allowed
        PE-->>Sys: PolicyResult(ALLOW)
    end
    
    Sys->>Exec: execute(command)
    Exec->>Host: Run command
    Host-->>Exec: Output
    Exec-->>Sys: ExecutionResult
    Sys-->>Conv: ExecutionResult
```

### 3. Convergence Loop Iteration

```mermaid
sequenceDiagram
    participant Pipeline
    participant Diag as Diagnose Step
    participant Fix as Fix Step
    participant Attack as Attack Step
    participant Val as Validate Step
    participant Auditor
    participant Sysadmin
    participant EB as Event Bus

    Note over Pipeline: Iteration N
    
    Pipeline->>EB: emit(ITERATION_STARTED)
    
    %% Diagnose Phase
    Pipeline->>Diag: execute()
    Diag->>Auditor: scan(target)
    Auditor-->>Diag: findings[]
    Diag-->>Pipeline: StepResult(findings)
    Pipeline->>EB: emit(STEP_COMPLETE, diagnose)
    
    %% Fix Phase
    Pipeline->>Fix: execute(findings)
    loop For each finding
        Fix->>Sysadmin: run(fix_command)
        Sysadmin-->>Fix: result
    end
    Fix-->>Pipeline: StepResult(fixes_applied)
    Pipeline->>EB: emit(STEP_COMPLETE, fix)
    
    %% Attack Phase
    Pipeline->>Attack: execute()
    Attack->>Auditor: attack(target)
    Auditor-->>Attack: vulnerabilities[]
    Attack-->>Pipeline: StepResult(vulnerabilities)
    Pipeline->>EB: emit(STEP_COMPLETE, attack)
    
    %% Validate Phase
    Pipeline->>Val: execute()
    Val->>Sysadmin: run(tests)
    Sysadmin-->>Val: test_results
    Val-->>Pipeline: StepResult(tests_pass)
    Pipeline->>EB: emit(STEP_COMPLETE, validate)
    
    alt Converged
        Pipeline->>EB: emit(CONVERGENCE_REACHED)
    else Continue
        Pipeline->>EB: emit(ITERATION_ENDED)
    end
```

### 4. Dashboard Real-Time Updates

```mermaid
sequenceDiagram
    participant User
    participant Dashboard
    participant WS as WebSocket Server
    participant Conv as Convergence Loop
    participant EB as Event Bus
    participant DB as Database

    User->>Dashboard: Open dashboard
    Dashboard->>WS: Connect ws://localhost:8765
    WS-->>Dashboard: Connection established
    
    Dashboard->>DB: GET /api/sessions
    DB-->>Dashboard: Session list
    Dashboard->>User: Display sessions
    
    loop Real-time updates
        Conv->>EB: emit(event)
        EB->>WS: Broadcast event
        WS->>Dashboard: WebSocket message
        Dashboard->>User: UI update
    end
    
    User->>Dashboard: View session details
    Dashboard->>DB: GET /api/sessions/{id}
    DB-->>Dashboard: Session details
    Dashboard->>User: Display details
```

## API Integration Patterns

### REST API Pattern

```python
# Synchronous API call pattern
import httpx

async def call_auditor_api(target: str) -> ScanResult:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/api/v1/scan",
            json={"target": target, "modules": ["sql", "cmd", "jwt"]}
        )
        return ScanResult.from_dict(response.json())
```

### Event Bus Pattern

```python
# Asynchronous event handling
from kimi_convergence_loop import EventBus, EventType

async def handle_events():
    bus = EventBus(webhook_url="http://localhost:8766/events")
    
    @bus.on(EventType.STEP_COMPLETE)
    async def on_step_complete(event):
        print(f"Step {event.data['step']} completed")
    
    await bus.start()
```

### WebSocket Pattern

```python
# Real-time bidirectional communication
import websockets
import json

async def dashboard_client():
    uri = "ws://localhost:8765"
    async with websockets.connect(uri) as ws:
        # Subscribe to events
        await ws.send(json.dumps({"action": "subscribe", "events": ["*"]}))
        
        async for message in ws:
            event = json.loads(message)
            update_ui(event)
```

## Data Synchronization

### Eventual Consistency Model

```mermaid
flowchart LR
    subgraph Source["Event Source"]
        A[Component A]
    end

    subgraph Bus["Message Bus"]
        Q[Event Queue]
    end

    subgraph Sinks["Event Sinks"]
        B[Component B]
        C[Component C]
        D[Database]
    end

    A -->|publish| Q
    Q -->|consume| B
    Q -->|consume| C
    Q -->|persist| D

    style Bus fill:#fff3e0
```

### State Reconciliation

When components need to synchronize state:

1. **Source of Truth**: SQLite database for persistent state
2. **Event Log**: Immutable event stream for replay
3. **Snapshot**: Periodic state snapshots for fast recovery

```python
# State reconciliation example
class StateReconciler:
    def __init__(self, db: Database, event_bus: EventBus):
        self.db = db
        self.event_bus = event_bus
    
    async def get_current_state(self, session_id: str) -> SessionState:
        # Get base state from database
        state = await self.db.get_session(session_id)
        
        # Replay events since last snapshot
        events = await self.event_bus.get_events_since(
            session_id, 
            state.last_event_timestamp
        )
        
        for event in events:
            state = self.apply_event(state, event)
        
        return state
```

## Error Handling

### Circuit Breaker Pattern

```mermaid
stateDiagram-v2
    [*] --> CLOSED
    
    CLOSED --> OPEN: Failure threshold reached
    CLOSED --> CLOSED: Success
    
    OPEN --> HALF_OPEN: Timeout expired
    OPEN --> OPEN: Request blocked
    
    HALF_OPEN --> CLOSED: Success
    HALF_OPEN --> OPEN: Failure
```

### Retry with Exponential Backoff

```python
import asyncio
from typing import Callable, TypeVar

T = TypeVar('T')

async def with_retry(
    fn: Callable[[], T],
    max_retries: int = 3,
    base_delay: float = 1.0
) -> T:
    for attempt in range(max_retries):
        try:
            return await fn()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            
            delay = base_delay * (2 ** attempt)
            await asyncio.sleep(delay)
```

## Security in Communication

### Authentication Flow

```mermaid
sequenceDiagram
    participant Client
    participant Auth as Auth Service
    participant API as API Server
    participant Resource

    Client->>Auth: Authenticate(credentials)
    Auth-->>Client: JWT token
    
    Client->>API: Request + Authorization: Bearer {token}
    API->>API: Validate token
    API->>Resource: Forward request
    Resource-->>API: Response
    API-->>Client: Response
```

### mTLS for Internal Communication

```yaml
# Example configuration for mutual TLS
internal_communication:
  tls:
    enabled: true
    mode: mutual
    client_cert: /certs/client.crt
    client_key: /certs/client.key
    ca_cert: /certs/ca.crt
```
