"""Event bus for dashboard integration and logging."""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable

import httpx


class EventType(Enum):
    """Types of events emitted by the convergence loop."""
    
    SESSION_STARTED = auto()
    SESSION_ENDED = auto()
    ITERATION_STARTED = auto()
    ITERATION_ENDED = auto()
    STATE_CHANGED = auto()
    STEP_STARTED = auto()
    STEP_COMPLETE = auto()
    STEP_FAILED = auto()
    CONVERGENCE_REACHED = auto()
    ERROR = auto()
    METRICS = auto()


@dataclass
class Event:
    """Event emitted by the convergence loop."""
    
    timestamp: datetime
    session_id: str
    iteration: int
    state: str
    event_type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "session_id": self.session_id,
            "iteration": self.iteration,
            "state": self.state,
            "event_type": self.event_type.name,
            "data": self.data,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class EventBus:
    """Event bus for emitting and handling events."""
    
    def __init__(
        self,
        session_id: str | None = None,
        webhook_url: str = "",
        emit_interval: int = 5,
        buffer_size: int = 1000,
    ):
        self.session_id = session_id or str(uuid.uuid4())
        self.webhook_url = webhook_url
        self.emit_interval = emit_interval
        self.buffer_size = buffer_size
        
        self._handlers: list[Callable[[Event], None]] = []
        self._buffer: list[Event] = []
        self._lock = asyncio.Lock()
        self._emit_task: asyncio.Task | None = None
        self._running = False
        self._iteration = 0
        self._state = "IDLE"
    
    def register_handler(self, handler: Callable[[Event], None]) -> None:
        """Register an event handler."""
        self._handlers.append(handler)
    
    def unregister_handler(self, handler: Callable[[Event], None]) -> None:
        """Unregister an event handler."""
        if handler in self._handlers:
            self._handlers.remove(handler)
    
    def set_iteration(self, iteration: int) -> None:
        """Set the current iteration number."""
        self._iteration = iteration
    
    def set_state(self, state: str) -> None:
        """Set the current state."""
        self._state = state
    
    async def emit(
        self,
        event_type: EventType,
        data: dict[str, Any] | None = None,
    ) -> Event:
        """Emit an event."""
        event = Event(
            timestamp=datetime.now(timezone.utc),
            session_id=self.session_id,
            iteration=self._iteration,
            state=self._state,
            event_type=event_type,
            data=data or {},
        )
        
        # Call synchronous handlers
        for handler in self._handlers:
            try:
                handler(event)
            except Exception as e:
                print(f"Event handler error: {e}")
        
        # Buffer for async emission
        async with self._lock:
            self._buffer.append(event)
            if len(self._buffer) > self.buffer_size:
                # Drop oldest events if buffer is full
                self._buffer = self._buffer[-self.buffer_size:]
        
        return event
    
    async def start(self) -> None:
        """Start the event bus."""
        self._running = True
        
        if self.webhook_url:
            self._emit_task = asyncio.create_task(self._emit_loop())
        
        await self.emit(EventType.SESSION_STARTED, {
            "session_id": self.session_id,
            "webhook_url": self.webhook_url,
        })
    
    async def stop(self) -> None:
        """Stop the event bus."""
        await self.emit(EventType.SESSION_ENDED, {
            "session_id": self.session_id,
        })
        
        self._running = False
        
        if self._emit_task:
            self._emit_task.cancel()
            try:
                await self._emit_task
            except asyncio.CancelledError:
                pass
        
        # Flush remaining events
        await self._flush_events()
    
    async def _emit_loop(self) -> None:
        """Background loop for emitting events to webhook."""
        while self._running:
            try:
                await asyncio.sleep(self.emit_interval)
                await self._flush_events()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Event emit error: {e}")
    
    async def _flush_events(self) -> None:
        """Flush buffered events to webhook."""
        if not self.webhook_url:
            return
        
        async with self._lock:
            events_to_send = self._buffer.copy()
            self._buffer.clear()
        
        if not events_to_send:
            return
        
        try:
            async with httpx.AsyncClient() as client:
                payload = {
                    "session_id": self.session_id,
                    "events": [e.to_dict() for e in events_to_send],
                }
                
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    timeout=30.0,
                )
                response.raise_for_status()
        except Exception as e:
            # Put events back in buffer for retry
            async with self._lock:
                self._buffer = events_to_send + self._buffer
                if len(self._buffer) > self.buffer_size:
                    self._buffer = self._buffer[:self.buffer_size]
            
            print(f"Webhook error: {e}")


class ConsoleEventHandler:
    """Handler that prints events to console."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        from rich.console import Console
        from rich.json import JSON
        from rich.panel import Panel
        self.console = Console()
        self.JSON = JSON
        self.Panel = Panel
    
    def __call__(self, event: Event) -> None:
        """Handle an event."""
        if event.event_type in (EventType.STEP_STARTED, EventType.STEP_COMPLETE, EventType.ERROR):
            color = {
                EventType.STEP_STARTED: "blue",
                EventType.STEP_COMPLETE: "green",
                EventType.ERROR: "red",
            }.get(event.event_type, "white")
            
            self.console.print(
                f"[{color}][{event.event_type.name}][/{color}] "
                f"Iteration {event.iteration}: {event.data.get('step', event.state)}"
            )
            
            if self.verbose and event.data:
                self.console.print(self.JSON.from_data(event.data))
        
        elif event.event_type == EventType.CONVERGENCE_REACHED:
            self.console.print(
                self.Panel(
                    f"[green]Convergence reached after {event.iteration} iterations![/green]",
                    title="Success",
                    border_style="green",
                )
            )
        
        elif event.event_type == EventType.STATE_CHANGED:
            if self.verbose:
                self.console.print(
                    f"[dim]State: {event.data.get('from')} -> {event.data.get('to')}[/dim]"
                )
