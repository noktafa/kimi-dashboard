# Kimi Dashboard Integration

This document describes how to integrate the dashboard with the convergence loop.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Convergence Loop                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   Pipeline   │───▶│  EventBus    │───▶│  WebSocket   │       │
│  │              │    │              │    │   Server     │       │
│  └──────────────┘    └──────────────┘    └──────┬───────┘       │
└─────────────────────────────────────────────────┼───────────────┘
                                                  │
                                                  │ ws://localhost:8765
                                                  │
┌─────────────────────────────────────────────────┼───────────────┐
│                     Dashboard                    │               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────┴───────┐       │
│  │   Web UI     │◀───│  FastAPI     │◀───│   Bridge     │       │
│  │  (React/Vue) │    │   Server     │    │  (WebSocket) │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│                                                                  │
│  ┌──────────────┐                                               │
│  │   SQLite     │                                               │
│  │   Database   │                                               │
│  └──────────────┘                                               │
└─────────────────────────────────────────────────────────────────┘
```

## Usage

### 1. Start the Convergence Loop with WebSocket Server

Modify your convergence loop to use the `WebSocketEventBus`:

```python
from kimi_convergence_loop.pipeline import Pipeline
from kimi_convergence_loop.config import load_config
from kimi_convergence_loop.websocket_server import WebSocketEventBus

# Create WebSocket-enabled event bus
event_bus = WebSocketEventBus(
    ws_host="0.0.0.0",
    ws_port=8765,
)

# Load config and create pipeline
config = load_config()
pipeline = Pipeline(config, event_bus=event_bus)

# Run pipeline
result = await pipeline.run()
```

Or use the CLI with WebSocket support (when implemented):
```bash
kimi-converge --websocket --ws-port 8765
```

### 2. Start the Dashboard

```bash
# Connect to convergence loop
kimi-dashboard --convergence-url ws://localhost:8765

# Or use environment variables
export CONVERGENCE_WS_URL=ws://localhost:8765
kimi-dashboard

# For testing with mock data
kimi-dashboard --mock

# With custom host/port
kimi-dashboard --host 0.0.0.0 --port 8766
```

### 3. Open Dashboard in Browser

Navigate to `http://localhost:8766` to view the dashboard.

## API Endpoints

- `GET /` - Dashboard UI
- `GET /api/state` - Current convergence state
- `GET /api/sessions` - Historical sessions
- `GET /api/sessions/{id}/events` - Events for a specific session
- `GET /api/stats` - Aggregate statistics
- `WS /ws` - WebSocket for real-time updates

## Environment Variables

### Dashboard
- `DASHBOARD_HOST` - Server host (default: 0.0.0.0)
- `DASHBOARD_PORT` - Server port (default: 8766)
- `CONVERGENCE_WS_URL` - WebSocket URL for convergence loop (default: ws://localhost:8765)
- `DASHBOARD_DB_PATH` - SQLite database path (default: ./dashboard.db)
- `DASHBOARD_MOCK` - Use mock data (default: false)

### Convergence Loop
- `CONVERGENCE_WS_HOST` - WebSocket server host (default: 0.0.0.0)
- `CONVERGENCE_WS_PORT` - WebSocket server port (default: 8765)

## Event Types

The dashboard recognizes these event types:

- `SESSION_STARTED` - New convergence session started
- `SESSION_ENDED` - Session completed
- `ITERATION_STARTED` - New iteration started
- `ITERATION_ENDED` - Iteration completed
- `STATE_CHANGED` - Pipeline state changed
- `STEP_STARTED` - Step execution started
- `STEP_COMPLETE` - Step execution completed
- `STEP_FAILED` - Step execution failed
- `CONVERGENCE_REACHED` - Convergence achieved
- `ERROR` - Error occurred
- `METRICS` - Metrics update

## States

Pipeline states visualized in the dashboard:

1. **IDLE** - Waiting to start
2. **DIAGNOSING** - Analyzing system for issues
3. **FIXING** - Applying fixes
4. **ATTACKING** - Testing/attacking to find vulnerabilities
5. **VALIDATING** - Validating fixes
6. **CONVERGED** - System is stable and secure
