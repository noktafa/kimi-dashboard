"""FastAPI server for dashboard."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .bridge import ConvergenceBridge, ConvergenceEvent, MockConvergenceBridge
from .database import Database, EventRecord, SessionRecord

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Global state
_db: Database | None = None
_bridge: ConvergenceBridge | MockConvergenceBridge | None = None
_clients: set[WebSocket] = set()
_current_session: SessionRecord | None = None


def get_db() -> Database:
    """Get database instance."""
    global _db
    if _db is None:
        db_path = os.getenv("DASHBOARD_DB_PATH", "./dashboard.db")
        _db = Database(db_path)
    return _db


def get_bridge() -> ConvergenceBridge | MockConvergenceBridge:
    """Get bridge instance."""
    global _bridge
    if _bridge is None:
        convergence_url = os.getenv("CONVERGENCE_WS_URL", "ws://localhost:8765")
        use_mock = os.getenv("DASHBOARD_MOCK", "false").lower() == "true"
        
        if use_mock:
            logger.info("Using mock convergence bridge")
            _bridge = MockConvergenceBridge()
        else:
            logger.info(f"Connecting to convergence loop at {convergence_url}")
            _bridge = ConvergenceBridge(convergence_url)
        
        # Register event handler
        _bridge.register_handler(on_convergence_event)
    
    return _bridge


def on_convergence_event(event: ConvergenceEvent) -> None:
    """Handle convergence events."""
    global _current_session
    
    # Update database
    db = get_db()
    
    # Track session
    if event.event_type == "SESSION_STARTED":
        _current_session = SessionRecord(
            session_id=event.session_id,
            start_time=event.timestamp,
            final_state="RUNNING",
        )
        asyncio.create_task(db.create_session(_current_session))
    
    elif event.event_type == "SESSION_ENDED" and _current_session:
        _current_session.end_time = event.timestamp
        _current_session.final_state = "COMPLETED"
        asyncio.create_task(db.update_session(_current_session))
        _current_session = None
    
    elif event.event_type == "CONVERGENCE_REACHED" and _current_session:
        _current_session.convergence_reached = True
        _current_session.iterations = event.iteration
    
    elif _current_session and event.event_type == "ITERATION_ENDED":
        _current_session.iterations = event.iteration
    
    # Store event
    asyncio.create_task(db.add_event(EventRecord(
        event_id=event.event_id,
        session_id=event.session_id,
        timestamp=event.timestamp,
        iteration=event.iteration,
        state=event.state,
        event_type=event.event_type,
        data=event.data,
    )))
    
    # Broadcast to connected clients
    message = {
        "type": "event",
        "data": {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "session_id": event.session_id,
            "iteration": event.iteration,
            "state": event.state,
            "event_type": event.event_type,
            "data": event.data,
        },
    }
    
    asyncio.create_task(broadcast_message(message))


async def broadcast_message(message: dict[str, Any]) -> None:
    """Broadcast message to all connected clients."""
    disconnected = set()
    
    for client in _clients:
        try:
            await client.send_json(message)
        except Exception:
            disconnected.add(client)
    
    # Remove disconnected clients
    for client in disconnected:
        _clients.discard(client)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting dashboard server...")
    
    # Initialize database
    db = get_db()
    await db.initialize()
    
    # Start bridge
    bridge = get_bridge()
    await bridge.start()
    
    yield
    
    # Shutdown
    logger.info("Shutting down dashboard server...")
    if _bridge:
        await _bridge.stop()


app = FastAPI(
    title="Kimi Dashboard",
    description="Real-time dashboard for Kimi Convergence Loop",
    version="0.1.0",
    lifespan=lifespan,
)

# Static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", response_class=HTMLResponse)
async def get_dashboard() -> str:
    """Serve the dashboard HTML."""
    html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r") as f:
            return f.read()
    return get_default_html()


@app.get("/api/state")
async def get_state() -> dict[str, Any]:
    """Get current convergence state."""
    bridge = get_bridge()
    state = bridge.get_current_state()
    
    return {
        "state": state.get("state", "IDLE"),
        "iteration": state.get("iteration", 0),
        "session_id": state.get("session_id", ""),
        "findings": state.get("findings", 0),
        "fixes": state.get("fixes", 0),
        "vulnerabilities": state.get("vulnerabilities", 0),
        "logs": state.get("logs", [])[-50:],  # Last 50 logs
    }


@app.get("/api/sessions")
async def get_sessions(limit: int = 100) -> list[dict[str, Any]]:
    """Get historical sessions."""
    db = get_db()
    sessions = await db.get_sessions(limit=limit)
    
    return [
        {
            "session_id": s.session_id,
            "start_time": s.start_time.isoformat(),
            "end_time": s.end_time.isoformat() if s.end_time else None,
            "final_state": s.final_state,
            "iterations": s.iterations,
            "convergence_reached": s.convergence_reached,
            "duration_seconds": s.duration_seconds,
        }
        for s in sessions
    ]


@app.get("/api/sessions/{session_id}/events")
async def get_session_events(session_id: str, limit: int = 1000) -> list[dict[str, Any]]:
    """Get events for a specific session."""
    db = get_db()
    events = await db.get_session_events(session_id, limit=limit)
    
    return [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat(),
            "iteration": e.iteration,
            "state": e.state,
            "event_type": e.event_type,
            "data": e.data,
        }
        for e in events
    ]


@app.get("/api/stats")
async def get_stats() -> dict[str, Any]:
    """Get aggregate statistics."""
    db = get_db()
    stats = await db.get_session_stats()
    return stats


@app.get("/api/infrastructure")
async def get_infrastructure() -> dict[str, Any]:
    """Get infrastructure status."""
    return {
        "servers": [
            {
                "name": "kimi-api-1",
                "ip": "167.99.42.105",
                "region": "nyc1",
                "status": "online",
                "containers": [
                    {"name": "api-gateway", "status": "running"},
                    {"name": "auth-service", "status": "running"},
                    {"name": "rate-limiter", "status": "running"}
                ],
                "cpu": 42,
                "memory": 68,
                "uptime": "14d 3h 22m"
            },
            {
                "name": "kimi-api-2",
                "ip": "167.99.43.212",
                "region": "nyc1",
                "status": "online",
                "containers": [
                    {"name": "api-gateway", "status": "running"},
                    {"name": "worker-1", "status": "running"},
                    {"name": "worker-2", "status": "running"}
                ],
                "cpu": 38,
                "memory": 61,
                "uptime": "14d 3h 20m"
            },
            {
                "name": "kimi-db",
                "ip": "167.99.44.88",
                "region": "nyc1",
                "status": "online",
                "containers": [
                    {"name": "postgres-primary", "status": "running"},
                    {"name": "postgres-replica", "status": "running"},
                    {"name": "pgbouncer", "status": "running"}
                ],
                "cpu": 55,
                "memory": 72,
                "uptime": "21d 12h 45m"
            },
            {
                "name": "kimi-cache",
                "ip": "167.99.45.156",
                "region": "nyc1",
                "status": "warning",
                "containers": [
                    {"name": "redis-master", "status": "running"},
                    {"name": "redis-slave", "status": "running"},
                    {"name": "sentinel-1", "status": "running"}
                ],
                "cpu": 78,
                "memory": 85,
                "uptime": "14d 3h 18m"
            },
            {
                "name": "kimi-lb",
                "ip": "167.99.46.33",
                "region": "nyc1",
                "status": "online",
                "containers": [
                    {"name": "nginx", "status": "running"},
                    {"name": "cert-manager", "status": "running"}
                ],
                "cpu": 25,
                "memory": 42,
                "uptime": "30d 5h 10m"
            }
        ],
        "summary": {
            "total": 5,
            "online": 4,
            "warning": 1,
            "offline": 0
        }
    }


@app.get("/api/security")
async def get_security() -> dict[str, Any]:
    """Get security posture data."""
    return {
        "risk_score": 75,
        "vulnerabilities": {
            "critical": 0,
            "high": 2,
            "medium": 5,
            "low": 12
        },
        "trend": "improving",
        "compliance": {
            "pci_dss": {"status": "compliant", "last_assessed": "2026-02-01"},
            "soc2": {"status": "compliant", "last_assessed": "2026-01-15"},
            "iso27001": {"status": "in_progress", "progress": 78}
        },
        "last_incident": "2026-02-07T08:30:00Z",
        "next_audit": "2026-03-15"
    }


@app.get("/api/convergence/metrics")
async def get_convergence_metrics() -> dict[str, Any]:
    """Get convergence metrics."""
    return {
        "iterations_to_convergence": 12,
        "mttr": "4.2h",
        "autofix_success_rate": 94,
        "cost_savings_ytd": 127000,
        "current_progress": 87,
        "current_stage": "ATTACKING",
        "stages": [
            {"name": "IDLE", "status": "completed"},
            {"name": "DIAGNOSING", "status": "completed"},
            {"name": "FIXING", "status": "completed"},
            {"name": "ATTACKING", "status": "active"},
            {"name": "VALIDATING", "status": "pending"},
            {"name": "CONVERGED", "status": "pending"}
        ]
    }


@app.get("/api/threats")
async def get_threats(limit: int = 20) -> list[dict[str, Any]]:
    """Get recent threats."""
    import random
    from datetime import datetime, timedelta
    
    threat_types = [
        {"type": "SQL Injection Attempt", "severity": "high"},
        {"type": "DDoS Attack", "severity": "critical"},
        {"type": "Brute Force Login", "severity": "medium"},
        {"type": "XSS Attempt", "severity": "medium"},
        {"type": "Path Traversal", "severity": "high"},
        {"type": "Credential Stuffing", "severity": "medium"},
        {"type": "API Abuse", "severity": "low"}
    ]
    
    sources = ["CN", "RU", "BR", "VN", "IN", "ID", "US", "DE", "FR", "NL", "RO", "Unknown"]
    
    threats = []
    for i in range(limit):
        threat_type = random.choice(threat_types)
        threats.append({
            "id": f"threat-{i}",
            "type": threat_type["type"],
            "severity": threat_type["severity"],
            "source": random.choice(sources),
            "timestamp": (datetime.utcnow() - timedelta(minutes=random.randint(0, 120))).isoformat()
        })
    
    return threats


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time updates."""
    await websocket.accept()
    _clients.add(websocket)
    
    try:
        # Send current state
        bridge = get_bridge()
        state = bridge.get_current_state()
        await websocket.send_json({
            "type": "state",
            "data": state,
        })
        
        # Keep connection alive and handle client messages
        while True:
            try:
                message = await websocket.receive_json()
                
                # Handle client commands
                if message.get("action") == "ping":
                    await websocket.send_json({"type": "pong"})
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                break
    
    except WebSocketDisconnect:
        pass
    finally:
        _clients.discard(websocket)


def get_default_html() -> str:
    """Get default HTML if file not found."""
    return """<!DOCTYPE html>
<html>
<head>
    <title>Kimi Dashboard</title>
    <meta http-equiv="refresh" content="0; url=/static/index.html">
</head>
<body>
    <p>Redirecting to dashboard...</p>
</body>
</html>"""


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Kimi Dashboard Server")
    parser.add_argument(
        "--host",
        default=os.getenv("DASHBOARD_HOST", "0.0.0.0"),
        help="Server host (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("DASHBOARD_PORT", "8766")),
        help="Server port (default: 8766)",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use mock convergence data for testing",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )
    
    args = parser.parse_args()
    
    if args.mock:
        os.environ["DASHBOARD_MOCK"] = "true"
    
    import uvicorn
    uvicorn.run(
        "kimi_dashboard.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
