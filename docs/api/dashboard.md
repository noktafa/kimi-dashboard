# Dashboard API Documentation

## Overview

The Kimi Dashboard provides real-time monitoring and visualization of convergence loop executions through a WebSocket-based API and REST endpoints.

## Installation

```bash
pip install kimi-dashboard
```

## Server API

### Starting the Server

```python
from kimi_dashboard import start_server

# Start with defaults
start_server()

# Or with custom configuration
start_server(
    host="0.0.0.0",
    port=8766,
    convergence_ws_url="ws://localhost:8765",
    db_path="./dashboard.db"
)
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DASHBOARD_HOST` | Server bind address | `0.0.0.0` |
| `DASHBOARD_PORT` | Server port | `8766` |
| `CONVERGENCE_WS_URL` | Convergence loop WebSocket | `ws://localhost:8765` |
| `DASHBOARD_DB_PATH` | SQLite database path | `./dashboard.db` |

## WebSocket API

### Connection

```javascript
const ws = new WebSocket('ws://localhost:8766');

ws.onopen = () => {
    console.log('Connected to dashboard');
    
    // Subscribe to events
    ws.send(JSON.stringify({
        action: 'subscribe',
        events: ['*']  // or ['STEP_COMPLETE', 'CONVERGENCE_REACHED']
    }));
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
};

ws.onerror = (error) => {
    console.error('WebSocket error:', error);
};

ws.onclose = () => {
    console.log('Disconnected');
};
```

### Message Protocol

#### Client → Server

```javascript
// Subscribe to events
{
    "action": "subscribe",
    "events": ["STEP_STARTED", "STEP_COMPLETE", "CONVERGENCE_REACHED"]
}

// Unsubscribe from events
{
    "action": "unsubscribe",
    "events": ["STEP_STARTED"]
}

// Get session list
{
    "action": "list_sessions",
    "limit": 10,
    "offset": 0
}

// Get session details
{
    "action": "get_session",
    "session_id": "uuid-here"
}

// Ping (keepalive)
{
    "action": "ping"
}
```

#### Server → Client

```javascript
// Event broadcast
{
    "type": "event",
    "timestamp": "2024-01-15T10:30:00Z",
    "session_id": "uuid",
    "iteration": 3,
    "state": "VALIDATING",
    "event_type": "STEP_COMPLETE",
    "data": {
        "step": "validate",
        "result": "passed"
    }
}

// Session list response
{
    "type": "response",
    "request_action": "list_sessions",
    "data": {
        "sessions": [
            {
                "session_id": "uuid",
                "start_time": "2024-01-15T10:00:00Z",
                "status": "running",
                "current_iteration": 3,
                "target": "https://example.com"
            }
        ],
        "total": 1
    }
}

// Pong response
{
    "type": "pong",
    "timestamp": "2024-01-15T10:30:01Z"
}
```

## REST API

### Sessions

#### List Sessions

```http
GET /api/sessions?limit=10&offset=0
```

Response:
```json
{
    "sessions": [
        {
            "session_id": "550e8400-e29b-41d4-a716-446655440000",
            "start_time": "2024-01-15T10:00:00Z",
            "end_time": null,
            "status": "running",
            "current_iteration": 3,
            "target": "https://example.com",
            "final_state": null
        }
    ],
    "total": 1,
    "limit": 10,
    "offset": 0
}
```

#### Get Session Details

```http
GET /api/sessions/{session_id}
```

Response:
```json
{
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "start_time": "2024-01-15T10:00:00Z",
    "end_time": null,
    "status": "running",
    "target": "https://example.com",
    "config": {
        "max_iterations": 10,
        "timeout_seconds": 3600
    },
    "current_state": "VALIDATING",
    "current_iteration": 3,
    "metrics": {
        "total_findings": 5,
        "total_fixes": 3,
        "total_vulnerabilities": 2,
        "tests_passed": 2,
        "tests_failed": 0
    }
}
```

#### Get Session Events

```http
GET /api/sessions/{session_id}/events?limit=100&offset=0
```

Response:
```json
{
    "events": [
        {
            "event_id": "uuid",
            "timestamp": "2024-01-15T10:30:00Z",
            "event_type": "STEP_COMPLETE",
            "iteration": 3,
            "state": "VALIDATING",
            "data": {
                "step": "validate",
                "result": "passed"
            }
        }
    ],
    "total": 150
}
```

### Metrics

#### Get System Metrics

```http
GET /api/metrics
```

Response:
```json
{
    "total_sessions": 42,
    "active_sessions": 3,
    "converged_sessions": 35,
    "failed_sessions": 4,
    "average_iterations": 4.5,
    "average_duration": 1200,
    "findings_by_severity": {
        "critical": 12,
        "high": 45,
        "medium": 89,
        "low": 156,
        "info": 234
    }
}
```

#### Get Session Metrics

```http
GET /api/sessions/{session_id}/metrics
```

Response:
```json
{
    "session_id": "uuid",
    "iterations": 5,
    "duration_seconds": 1800,
    "findings_per_iteration": [8, 5, 3, 1, 0],
    "fixes_per_iteration": [5, 3, 2, 1, 0],
    "step_durations": {
        "diagnose": [120, 100, 95, 90, 85],
        "fix": [200, 150, 100, 80, 0],
        "attack": [300, 280, 250, 200, 180],
        "validate": [180, 170, 160, 150, 140]
    }
}
```

## Python Client API

### DashboardClient

```python
from kimi_dashboard import DashboardClient

client = DashboardClient("http://localhost:8766")

# List sessions
sessions = await client.list_sessions(limit=10)
for session in sessions:
    print(f"{session.session_id}: {session.status}")

# Get session details
details = await client.get_session("uuid-here")
print(f"Current state: {details.current_state}")
print(f"Iteration: {details.current_iteration}")

# Get events
events = await client.get_events("uuid-here", limit=100)
for event in events:
    print(f"[{event.event_type}] {event.timestamp}")

# Get metrics
metrics = await client.get_metrics()
print(f"Total sessions: {metrics.total_sessions}")
```

### WebSocketClient

```python
from kimi_dashboard import WebSocketClient

class MyWebSocketClient(WebSocketClient):
    async def on_event(self, event):
        print(f"Event: {event.event_type}")
        if event.event_type == "CONVERGENCE_REACHED":
            print("🎉 Convergence reached!")
    
    async def on_connect(self):
        print("Connected to dashboard")
        await self.subscribe(["*"])
    
    async def on_disconnect(self):
        print("Disconnected from dashboard")

# Connect and listen
client = MyWebSocketClient("ws://localhost:8766")
await client.connect()

# Keep listening
await client.run_forever()
```

## Real-Time Updates

### Event Stream Processing

```python
from kimi_dashboard import WebSocketClient, EventType

class EventProcessor:
    def __init__(self):
        self.findings = []
        self.current_iteration = 0
    
    async def handle_event(self, event):
        if event.event_type == EventType.ITERATION_STARTED:
            self.current_iteration = event.iteration
            print(f"\n--- Iteration {self.current_iteration} ---")
        
        elif event.event_type == EventType.STEP_COMPLETE:
            step = event.data.get('step')
            print(f"✅ {step} complete")
        
        elif event.event_type == EventType.STEP_FAILED:
            step = event.data.get('step')
            error = event.data.get('error')
            print(f"❌ {step} failed: {error}")
        
        elif event.event_type == EventType.CONVERGENCE_REACHED:
            iterations = event.data.get('iterations')
            print(f"\n🎉 Converged after {iterations} iterations!")

# Usage
processor = EventProcessor()
client = WebSocketClient("ws://localhost:8766")
client.on_event = processor.handle_event
await client.connect()
```

### Live Metrics Dashboard

```python
import asyncio
from kimi_dashboard import DashboardClient

async def live_metrics():
    client = DashboardClient("http://localhost:8766")
    
    while True:
        metrics = await client.get_metrics()
        
        # Clear screen (Unix)
        print("\033[2J\033[H")
        
        print("=" * 50)
        print("KIMI DASHBOARD - LIVE METRICS")
        print("=" * 50)
        print(f"Active Sessions: {metrics.active_sessions}")
        print(f"Total Sessions: {metrics.total_sessions}")
        print(f"Converged: {metrics.converged_sessions}")
        print(f"Failed: {metrics.failed_sessions}")
        print()
        print("Findings by Severity:")
        for severity, count in metrics.findings_by_severity.items():
            print(f"  {severity}: {count}")
        
        await asyncio.sleep(5)

# Run
asyncio.run(live_metrics())
```

## Custom Widgets

### Creating a Custom Widget

```python
from kimi_dashboard.widgets import Widget, WidgetConfig

class CustomChartWidget(Widget):
    def __init__(self, config: WidgetConfig):
        super().__init__(config)
        self.data = []
    
    async def on_event(self, event):
        if event.event_type == "STEP_COMPLETE":
            self.data.append({
                "timestamp": event.timestamp,
                "step": event.data.get("step"),
                "iteration": event.iteration
            })
            await self.update()
    
    async def render(self):
        # Return widget state for frontend
        return {
            "type": "chart",
            "data": self.data,
            "options": {
                "title": "Step Completion Times",
                "x": "timestamp",
                "y": "iteration"
            }
        }

# Register widget
from kimi_dashboard import register_widget

register_widget("custom_chart", CustomChartWidget)
```

## Integration Examples

### With React Frontend

```javascript
// useDashboard.js
import { useEffect, useState } from 'react';

export function useDashboard(sessionId) {
    const [events, setEvents] = useState([]);
    const [connected, setConnected] = useState(false);
    
    useEffect(() => {
        const ws = new WebSocket('ws://localhost:8766');
        
        ws.onopen = () => {
            setConnected(true);
            ws.send(JSON.stringify({
                action: 'subscribe',
                events: ['*']
            }));
        };
        
        ws.onmessage = (message) => {
            const data = JSON.parse(message.data);
            if (data.type === 'event') {
                setEvents(prev => [...prev, data]);
            }
        };
        
        ws.onclose = () => setConnected(false);
        
        return () => ws.close();
    }, [sessionId]);
    
    return { events, connected };
}
```

### With Grafana

```python
from kimi_dashboard.exporters import GrafanaExporter

exporter = GrafanaExporter(
    dashboard_url="http://localhost:8766",
    prometheus_port=9090
)

# Start Prometheus metrics endpoint
exporter.start()

# Metrics available at http://localhost:9090/metrics
```

## Error Handling

```python
from kimi_dashboard import DashboardClient, WebSocketClient
from kimi_dashboard.exceptions import (
    ConnectionError,
    SessionNotFoundError,
    APIError
)

async def safe_dashboard_operations():
    # REST API error handling
    client = DashboardClient("http://localhost:8766")
    
    try:
        session = await client.get_session("invalid-uuid")
    except SessionNotFoundError:
        print("Session not found")
    except APIError as e:
        print(f"API error: {e.status_code} - {e.message}")
    
    # WebSocket error handling
    ws_client = WebSocketClient("ws://localhost:8766")
    
    try:
        await ws_client.connect()
    except ConnectionError:
        print("Failed to connect to dashboard")
        return
    
    try:
        await ws_client.run_forever()
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        await ws_client.disconnect()
```
