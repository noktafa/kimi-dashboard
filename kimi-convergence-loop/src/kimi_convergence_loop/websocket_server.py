"""WebSocket event server for convergence loop integration."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict
from datetime import datetime
from typing import Any

import websockets
from websockets.server import WebSocketServerProtocol

from .event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)


class WebSocketEventServer:
    """WebSocket server that broadcasts convergence events."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8765):
        self.host = host
        self.port = port
        self._clients: set[WebSocketServerProtocol] = set()
        self._server = None
        self._running = False
    
    async def start(self) -> None:
        """Start the WebSocket server."""
        self._running = True
        self._server = await websockets.serve(
            self._handle_client,
            self.host,
            self.port,
        )
        logger.info(f"WebSocket event server started on ws://{self.host}:{self.port}")
    
    async def stop(self) -> None:
        """Stop the WebSocket server."""
        self._running = False
        
        # Close all client connections
        if self._clients:
            await asyncio.gather(
                *[client.close() for client in self._clients],
                return_exceptions=True,
            )
        
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        
        logger.info("WebSocket event server stopped")
    
    async def _handle_client(self, websocket: WebSocketServerProtocol, path: str) -> None:
        """Handle a new client connection."""
        self._clients.add(websocket)
        logger.info(f"Client connected: {websocket.remote_address}")
        
        try:
            # Send welcome message
            await websocket.send(json.dumps({
                "type": "connected",
                "timestamp": datetime.now().isoformat(),
            }))
            
            # Keep connection alive and handle client messages
            async for message in websocket:
                try:
                    data = json.loads(message)
                    
                    # Handle ping
                    if data.get("action") == "ping":
                        await websocket.send(json.dumps({"type": "pong"}))
                
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON from client: {message[:100]}")
        
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self._clients.discard(websocket)
            logger.info(f"Client disconnected: {websocket.remote_address}")
    
    async def broadcast_event(self, event: Event) -> None:
        """Broadcast an event to all connected clients."""
        if not self._clients:
            return
        
        message = json.dumps(event.to_dict())
        
        # Send to all clients, removing disconnected ones
        disconnected = set()
        for client in self._clients:
            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
            except Exception as e:
                logger.error(f"Error sending to client: {e}")
                disconnected.add(client)
        
        # Clean up disconnected clients
        for client in disconnected:
            self._clients.discard(client)


class WebSocketEventBus(EventBus):
    """EventBus that also broadcasts to WebSocket clients."""
    
    def __init__(
        self,
        session_id: str | None = None,
        webhook_url: str = "",
        emit_interval: int = 5,
        buffer_size: int = 1000,
        ws_host: str = "0.0.0.0",
        ws_port: int = 8765,
    ):
        super().__init__(session_id, webhook_url, emit_interval, buffer_size)
        self._ws_server = WebSocketEventServer(ws_host, ws_port)
        self._ws_task: asyncio.Task | None = None
    
    async def start(self) -> None:
        """Start the event bus and WebSocket server."""
        # Start WebSocket server
        await self._ws_server.start()
        
        # Start parent
        await super().start()
    
    async def stop(self) -> None:
        """Stop the event bus and WebSocket server."""
        # Stop parent
        await super().stop()
        
        # Stop WebSocket server
        await self._ws_server.stop()
    
    async def emit(
        self,
        event_type: EventType,
        data: dict[str, Any] | None = None,
    ) -> Event:
        """Emit an event to all handlers and WebSocket clients."""
        # Emit via parent (handlers, webhook, buffer)
        event = await super().emit(event_type, data)
        
        # Broadcast to WebSocket clients
        await self._ws_server.broadcast_event(event)
        
        return event
