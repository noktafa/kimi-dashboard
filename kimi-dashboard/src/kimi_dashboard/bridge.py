"""WebSocket bridge to convergence loop event bus."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

import websockets
from websockets.exceptions import ConnectionClosed

logger = logging.getLogger(__name__)


@dataclass
class ConvergenceEvent:
    """Event from convergence loop."""
    
    event_id: str
    timestamp: datetime
    session_id: str
    iteration: int
    state: str
    event_type: str
    data: dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConvergenceEvent":
        """Create from dictionary."""
        ts = data.get("timestamp", "")
        if isinstance(ts, str):
            try:
                timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()
        
        return cls(
            event_id=data.get("event_id", ""),
            timestamp=timestamp,
            session_id=data.get("session_id", ""),
            iteration=data.get("iteration", 0),
            state=data.get("state", "IDLE"),
            event_type=data.get("event_type", "UNKNOWN"),
            data=data.get("data", {}),
        )


class ConvergenceBridge:
    """Bridge to convergence loop WebSocket."""
    
    def __init__(
        self,
        url: str = "ws://localhost:8765",
        reconnect_interval: float = 5.0,
    ):
        self.url = url
        self.reconnect_interval = reconnect_interval
        self._handlers: list[Callable[[ConvergenceEvent], None]] = []
        self._running = False
        self._websocket: websockets.WebSocketClientProtocol | None = None
        self._task: asyncio.Task | None = None
        self._current_state: dict[str, Any] = {
            "state": "IDLE",
            "iteration": 0,
            "session_id": "",
            "findings": 0,
            "fixes": 0,
            "vulnerabilities": 0,
            "logs": [],
        }
    
    def register_handler(self, handler: Callable[[ConvergenceEvent], None]) -> None:
        """Register an event handler."""
        self._handlers.append(handler)
    
    def unregister_handler(self, handler: Callable[[ConvergenceEvent], None]) -> None:
        """Unregister an event handler."""
        if handler in self._handlers:
            self._handlers.remove(handler)
    
    def get_current_state(self) -> dict[str, Any]:
        """Get current convergence state."""
        return self._current_state.copy()
    
    async def start(self) -> None:
        """Start the bridge connection."""
        self._running = True
        self._task = asyncio.create_task(self._connect_loop())
    
    async def stop(self) -> None:
        """Stop the bridge connection."""
        self._running = False
        
        if self._websocket:
            try:
                await self._websocket.close()
            except Exception as e:
                logger.warning(f"Error closing websocket: {e}")
        
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
    
    async def _connect_loop(self) -> None:
        """Main connection loop with reconnection."""
        while self._running:
            try:
                logger.info(f"Connecting to convergence loop at {self.url}")
                async with websockets.connect(self.url) as websocket:
                    self._websocket = websocket
                    logger.info("Connected to convergence loop")
                    await self._handle_messages(websocket)
            except ConnectionRefusedError:
                logger.warning(f"Connection refused to {self.url}, retrying...")
            except ConnectionClosed:
                logger.warning("Connection closed, reconnecting...")
            except Exception as e:
                logger.error(f"Bridge error: {e}")
            
            if self._running:
                await asyncio.sleep(self.reconnect_interval)
    
    async def _handle_messages(
        self,
        websocket: websockets.WebSocketClientProtocol,
    ) -> None:
        """Handle incoming messages."""
        async for message in websocket:
            try:
                data = json.loads(message)
                
                # Handle different message formats
                if isinstance(data, list):
                    # Batch of events
                    for event_data in data:
                        await self._process_event(event_data)
                elif isinstance(data, dict):
                    if "events" in data:
                        # Wrapped batch
                        for event_data in data["events"]:
                            await self._process_event(event_data)
                    else:
                        # Single event
                        await self._process_event(data)
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON: {message[:100]}")
            except Exception as e:
                logger.error(f"Error processing message: {e}")
    
    async def _process_event(self, data: dict[str, Any]) -> None:
        """Process a single event."""
        try:
            event = ConvergenceEvent.from_dict(data)
            
            # Update current state
            self._update_state(event)
            
            # Notify handlers
            for handler in self._handlers:
                try:
                    handler(event)
                except Exception as e:
                    logger.error(f"Handler error: {e}")
        except Exception as e:
            logger.error(f"Error processing event: {e}")
    
    def _update_state(self, event: ConvergenceEvent) -> None:
        """Update current state from event."""
        self._current_state["state"] = event.state
        self._current_state["iteration"] = event.iteration
        self._current_state["session_id"] = event.session_id
        
        # Add to logs
        log_entry = {
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "iteration": event.iteration,
            "state": event.state,
            "data": event.data,
        }
        self._current_state["logs"].append(log_entry)
        
        # Keep only last 1000 logs
        if len(self._current_state["logs"]) > 1000:
            self._current_state["logs"] = self._current_state["logs"][-1000:]
        
        # Update metrics from event data
        if "findings" in event.data:
            self._current_state["findings"] = len(event.data["findings"])
        if "fixes" in event.data:
            self._current_state["fixes"] = len(event.data["fixes"])
        if "vulnerabilities" in event.data:
            self._current_state["vulnerabilities"] = len(event.data["vulnerabilities"])


class MockConvergenceBridge:
    """Mock bridge for testing/demo purposes."""
    
    STATES = ["IDLE", "DIAGNOSING", "FIXING", "ATTACKING", "VALIDATING", "CONVERGED"]
    
    def __init__(self):
        self._handlers: list[Callable[[ConvergenceEvent], None]] = []
        self._running = False
        self._task: asyncio.Task | None = None
        self._iteration = 0
        self._state_index = 0
        self._current_state: dict[str, Any] = {
            "state": "IDLE",
            "iteration": 0,
            "session_id": "mock-session-001",
            "findings": 0,
            "fixes": 0,
            "vulnerabilities": 0,
            "logs": [],
        }
    
    def register_handler(self, handler: Callable[[ConvergenceEvent], None]) -> None:
        self._handlers.append(handler)
    
    def unregister_handler(self, handler: Callable[[ConvergenceEvent], None]) -> None:
        if handler in self._handlers:
            self._handlers.remove(handler)
    
    def get_current_state(self) -> dict[str, Any]:
        return self._current_state.copy()
    
    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._mock_loop())
    
    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
    
    async def _mock_loop(self) -> None:
        """Generate mock events."""
        import uuid
        
        session_id = f"mock-session-{uuid.uuid4().hex[:8]}"
        self._current_state["session_id"] = session_id
        
        # Emit session started
        await self._emit_event(
            session_id=session_id,
            event_type="SESSION_STARTED",
            data={"session_id": session_id},
        )
        
        while self._running:
            await asyncio.sleep(2)
            
            if not self._running:
                break
            
            # Progress through states
            current_state = self.STATES[self._state_index]
            
            if current_state == "IDLE":
                self._iteration += 1
                self._current_state["iteration"] = self._iteration
                await self._emit_event(
                    session_id=session_id,
                    event_type="ITERATION_STARTED",
                    data={"iteration": self._iteration},
                )
            
            elif current_state == "DIAGNOSING":
                findings = [f"Issue {i+1}" for i in range(3)]
                self._current_state["findings"] = len(findings)
                await self._emit_event(
                    session_id=session_id,
                    event_type="STEP_COMPLETE",
                    data={"step": "diagnose", "findings": findings},
                )
            
            elif current_state == "FIXING":
                fixes = [f"Fix {i+1}" for i in range(3)]
                self._current_state["fixes"] = len(fixes)
                await self._emit_event(
                    session_id=session_id,
                    event_type="STEP_COMPLETE",
                    data={"step": "fix", "fixes": fixes},
                )
            
            elif current_state == "ATTACKING":
                vulns = [f"Vuln {i+1}" for i in range(2)]
                self._current_state["vulnerabilities"] = len(vulns)
                await self._emit_event(
                    session_id=session_id,
                    event_type="STEP_COMPLETE",
                    data={"step": "attack", "vulnerabilities": vulns},
                )
            
            elif current_state == "VALIDATING":
                await self._emit_event(
                    session_id=session_id,
                    event_type="STEP_COMPLETE",
                    data={"step": "validate", "success": True},
                )
                
                # Check for convergence (after 3 iterations)
                if self._iteration >= 3:
                    self._state_index = self.STATES.index("CONVERGED")
                    await self._emit_event(
                        session_id=session_id,
                        event_type="CONVERGENCE_REACHED",
                        data={"iterations": self._iteration},
                    )
                    break
            
            # Move to next state
            if current_state != "CONVERGED":
                self._state_index = (self._state_index + 1) % (len(self.STATES) - 1)
                if self.STATES[self._state_index] == "IDLE":
                    self._state_index = 1  # Skip IDLE, go to DIAGNOSING
                
                new_state = self.STATES[self._state_index]
                self._current_state["state"] = new_state
                
                await self._emit_event(
                    session_id=session_id,
                    event_type="STATE_CHANGED",
                    data={"from": current_state, "to": new_state},
                )
        
        # Session ended
        await self._emit_event(
            session_id=session_id,
            event_type="SESSION_ENDED",
            data={"iterations": self._iteration},
        )
    
    async def _emit_event(
        self,
        session_id: str,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """Emit a mock event."""
        import uuid
        
        event = ConvergenceEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            session_id=session_id,
            iteration=self._iteration,
            state=self._current_state["state"],
            event_type=event_type,
            data=data,
        )
        
        # Update logs
        log_entry = {
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "iteration": event.iteration,
            "state": event.state,
            "data": event.data,
        }
        self._current_state["logs"].append(log_entry)
        
        # Notify handlers
        for handler in self._handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Handler error: {e}")
