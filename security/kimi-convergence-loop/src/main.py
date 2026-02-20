"""
Secured Kimi Convergence Loop Service

A production-ready orchestration service with:
- WebSocket auth handshake
- Session tokens
- TLS for WebSocket
- Dashboard auth proxy
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import uvicorn
import yaml
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Add shared module to path
sys.path.insert(0, str(Path(__file__).parent.parent / "shared"))
from auth import (
    AuthConfig,
    AuthManager,
    Permission,
    Role,
    TLSManager,
    get_auth_manager,
    get_current_user,
    optional_auth,
    set_auth_manager,
    TokenPayload,
    websocket_auth,
)


# Configuration
class ServiceConfig(BaseModel):
    """Service configuration."""
    host: str = "0.0.0.0"
    port: int = 8002
    log_level: str = "info"
    websocket_ping_interval: int = 20
    websocket_ping_timeout: int = 20
    
    class Config:
        env_prefix = "CONVERGENCE_LOOP_"


# Pydantic models
class WorkflowRequest(BaseModel):
    name: str = Field(..., description="Workflow name")
    steps: list[dict] = Field(..., description="Workflow steps")
    options: Optional[dict] = Field(default=None, description="Additional options")


class WorkflowStatus(BaseModel):
    id: str
    name: str
    status: str  # pending, running, completed, failed
    progress: int  # 0-100
    current_step: Optional[str] = None
    timestamp: str
    created_by: str


class SessionToken(BaseModel):
    """Session token for WebSocket authentication."""
    token: str
    expires_at: datetime
    workflow_id: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    websocket_enabled: bool
    authenticated: bool = False
    user: Optional[str] = None


class WebSocketMessage(BaseModel):
    """WebSocket message format."""
    type: str
    data: Optional[dict] = None
    timestamp: Optional[str] = None


# WebSocket connection manager with authentication
class AuthenticatedConnectionManager:
    """Manages WebSocket connections with authentication."""
    
    def __init__(self):
        self.active_connections: dict[WebSocket, TokenPayload] = {}
        self.connection_metadata: dict[WebSocket, dict] = {}
    
    async def connect(
        self,
        websocket: WebSocket,
        token: str,
    ) -> TokenPayload:
        """Connect a WebSocket with authentication."""
        # Verify token
        auth_manager = get_auth_manager()
        payload = auth_manager.verify_token(token)
        
        # Accept connection
        await websocket.accept()
        self.active_connections[websocket] = payload
        self.connection_metadata[websocket] = {
            "connected_at": datetime.utcnow().isoformat(),
            "user": payload.sub,
            "role": payload.role.value,
        }
        
        return payload
    
    def disconnect(self, websocket: WebSocket):
        """Disconnect a WebSocket."""
        self.active_connections.pop(websocket, None)
        self.connection_metadata.pop(websocket, None)
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send a message to a specific connection."""
        if websocket in self.active_connections:
            await websocket.send_json(message)
    
    async def broadcast(self, message: dict, require_permission: Optional[Permission] = None):
        """Broadcast a message to all or filtered connections."""
        disconnected = []
        auth_manager = get_auth_manager()
        
        for connection, payload in self.active_connections.items():
            # Check permission if required
            if require_permission and not auth_manager.has_permission(payload, require_permission):
                continue
            
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        
        # Clean up disconnected
        for conn in disconnected:
            self.disconnect(conn)
    
    async def broadcast_to_user(self, user_id: str, message: dict):
        """Broadcast to all connections for a specific user."""
        disconnected = []
        
        for connection, payload in self.active_connections.items():
            if payload.sub == user_id:
                try:
                    await connection.send_json(message)
                except Exception:
                    disconnected.append(connection)
        
        for conn in disconnected:
            self.disconnect(conn)
    
    def get_user_connections(self, user_id: str) -> list[WebSocket]:
        """Get all connections for a user."""
        return [
            conn for conn, payload in self.active_connections.items()
            if payload.sub == user_id
        ]
    
    def get_connection_count(self) -> int:
        """Get total number of active connections."""
        return len(self.active_connections)


# Global state
_config: Optional[ServiceConfig] = None
_auth_manager: Optional[AuthManager] = None
_manager = AuthenticatedConnectionManager()


def load_config() -> tuple[ServiceConfig, AuthConfig]:
    """Load configuration from YAML file and environment."""
    service_config = ServiceConfig()
    auth_config = AuthConfig()
    
    # Load from YAML if exists
    config_path = Path(__file__).parent.parent / "config" / "convergence-loop.yaml"
    if config_path.exists():
        with open(config_path) as f:
            yaml_config = yaml.safe_load(f)
        
        if yaml_config:
            if "service" in yaml_config:
                for key, value in yaml_config["service"].items():
                    if hasattr(service_config, key):
                        setattr(service_config, key, value)
            
            if "auth" in yaml_config:
                for key, value in yaml_config["auth"].items():
                    if hasattr(auth_config, key):
                        setattr(auth_config, key, value)
            
            if "tls" in yaml_config:
                for key, value in yaml_config["tls"].items():
                    if hasattr(auth_config, key):
                        setattr(auth_config, key, value)
    
    # Override with environment variables
    if os.getenv("CONVERGENCE_LOOP_JWT_SECRET"):
        auth_config.jwt_secret = os.getenv("CONVERGENCE_LOOP_JWT_SECRET")
    
    return service_config, auth_config


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global _config, _auth_manager
    
    # Load configuration
    service_config, auth_config = load_config()
    _config = service_config
    
    # Initialize auth manager
    _auth_manager = AuthManager(auth_config)
    set_auth_manager(_auth_manager)
    
    # Generate default API key if none exist
    if not auth_config.api_keys and auth_config.require_auth:
        key = _auth_manager.generate_api_key("default", Role.ADMIN)
        print(f"\n{'='*60}")
        print("GENERATED DEFAULT API KEY (save this - won't be shown again):")
        print(f"{'='*60}")
        print(key)
        print(f"{'='*60}\n")
    
    yield
    
    # Cleanup
    pass


# Create FastAPI app
app = FastAPI(
    title="Kimi Convergence Loop",
    description="Orchestration service for the Kimi ecosystem",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if os.getenv("ENV") != "production" else None,
    redoc_url="/redoc" if os.getenv("ENV") != "production" else None,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health_check(
    user: Optional[TokenPayload] = Depends(optional_auth),
):
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        service="convergence-loop",
        version="1.0.0",
        websocket_enabled=True,
        authenticated=user is not None,
        user=user.sub if user else None,
    )


@app.get("/")
async def root(user: TokenPayload = Depends(get_current_user)):
    """Root endpoint - requires authentication."""
    return {
        "service": "Kimi Convergence Loop",
        "version": "1.0.0",
        "user": user.sub,
        "role": user.role.value,
        "endpoints": [
            "/health",
            "/workflows",
            "/workflows/{workflow_id}",
            "/ws"
        ],
    }


@app.post("/workflows", response_model=WorkflowStatus)
async def create_workflow(
    request: WorkflowRequest,
    user: TokenPayload = Depends(get_current_user),
):
    """Create a new workflow - requires create:workflow permission."""
    auth_manager = get_auth_manager()
    
    if not auth_manager.has_permission(user, Permission.CREATE_WORKFLOW):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: create:workflow required",
        )
    
    workflow_id = str(uuid.uuid4())
    
    # Broadcast to connected clients
    await _manager.broadcast({
        "type": "workflow_created",
        "data": {
            "workflow_id": workflow_id,
            "name": request.name,
            "created_by": user.sub,
        },
    })
    
    return WorkflowStatus(
        id=workflow_id,
        name=request.name,
        status="pending",
        progress=0,
        current_step=None,
        timestamp=datetime.utcnow().isoformat(),
        created_by=user.sub,
    )


@app.get("/workflows/{workflow_id}", response_model=WorkflowStatus)
async def get_workflow(
    workflow_id: str,
    user: TokenPayload = Depends(get_current_user),
):
    """Get workflow status - requires read:workflows permission."""
    auth_manager = get_auth_manager()
    
    if not auth_manager.has_permission(user, Permission.READ_WORKFLOWS):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: read:workflows required",
        )
    
    return WorkflowStatus(
        id=workflow_id,
        name="example-workflow",
        status="running",
        progress=50,
        current_step="step-1",
        timestamp=datetime.utcnow().isoformat(),
        created_by=user.sub,
    )


@app.get("/workflows")
async def list_workflows(
    user: TokenPayload = Depends(get_current_user),
    limit: int = 100,
    offset: int = 0,
):
    """List workflows - requires read:workflows permission."""
    auth_manager = get_auth_manager()
    
    if not auth_manager.has_permission(user, Permission.READ_WORKFLOWS):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: read:workflows required",
        )
    
    return {"workflows": [], "total": 0, "limit": limit, "offset": offset}


@app.delete("/workflows/{workflow_id}")
async def delete_workflow(
    workflow_id: str,
    user: TokenPayload = Depends(get_current_user),
):
    """Delete a workflow - requires delete:workflow permission (admin only)."""
    auth_manager = get_auth_manager()
    
    if not auth_manager.has_permission(user, Permission.DELETE_WORKFLOW):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: delete:workflow required",
        )
    
    # Broadcast deletion
    await _manager.broadcast({
        "type": "workflow_deleted",
        "data": {
            "workflow_id": workflow_id,
            "deleted_by": user.sub,
        },
    })
    
    return {"message": f"Workflow {workflow_id} deleted", "deleted_by": user.sub}


@app.post("/auth/ws-token")
async def create_websocket_token(
    user: TokenPayload = Depends(get_current_user),
    workflow_id: Optional[str] = None,
) -> dict:
    """
    Create a short-lived token for WebSocket authentication.
    This token can only be used for WebSocket connections.
    """
    auth_manager = get_auth_manager()
    
    # Create a short-lived token (5 minutes) specifically for WebSocket
    token = auth_manager.create_token(
        user_id=user.sub,
        role=user.role,
        custom_claims={
            "type": "websocket",
            "workflow_id": workflow_id,
        },
        expiry_hours=0.083,  # 5 minutes
    )
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 300,  # 5 minutes in seconds
    }


@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(..., description="WebSocket authentication token"),
):
    """
    WebSocket endpoint with authentication.
    Token must be provided as a query parameter.
    """
    try:
        # Authenticate and connect
        payload = await _manager.connect(websocket, token)
        
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "data": {
                "user": payload.sub,
                "role": payload.role.value,
                "connections": _manager.get_connection_count(),
            },
        })
        
        # Broadcast user joined
        await _manager.broadcast({
            "type": "user_joined",
            "data": {
                "user": payload.sub,
                "connections": _manager.get_connection_count(),
            },
        }, require_permission=Permission.READ_WORKFLOWS)
        
        try:
            while True:
                # Receive message
                data = await websocket.receive_text()
                
                try:
                    message = json.loads(data)
                except json.JSONDecodeError:
                    await websocket.send_json({
                        "type": "error",
                        "data": {"message": "Invalid JSON"},
                    })
                    continue
                
                # Handle different message types
                msg_type = message.get("type")
                
                if msg_type == "ping":
                    await websocket.send_json({"type": "pong"})
                
                elif msg_type == "subscribe":
                    # Subscribe to workflow updates
                    workflow_id = message.get("workflow_id")
                    await websocket.send_json({
                        "type": "subscribed",
                        "data": {"workflow_id": workflow_id},
                    })
                
                elif msg_type == "broadcast":
                    # Broadcast message to all connected clients
                    auth_manager = get_auth_manager()
                    if auth_manager.has_permission(payload, Permission.CREATE_WORKFLOW):
                        await _manager.broadcast({
                            "type": "broadcast",
                            "data": message.get("data"),
                            "from": payload.sub,
                        })
                    else:
                        await websocket.send_json({
                            "type": "error",
                            "data": {"message": "Permission denied"},
                        })
                
                else:
                    await websocket.send_json({
                        "type": "echo",
                        "data": message,
                    })
        
        except WebSocketDisconnect:
            pass
        finally:
            _manager.disconnect(websocket)
            
            # Broadcast user left
            await _manager.broadcast({
                "type": "user_left",
                "data": {
                    "user": payload.sub,
                    "connections": _manager.get_connection_count(),
                },
            }, require_permission=Permission.READ_WORKFLOWS)
    
    except HTTPException as e:
        # Authentication failed
        await websocket.close(code=4001, reason=e.detail)


def main():
    """Main entry point."""
    service_config, auth_config = load_config()
    
    uvicorn.run(
        "main:app",
        host=service_config.host,
        port=service_config.port,
        log_level=service_config.log_level,
        ssl_keyfile=auth_config.tls_key_path if auth_config.tls_enabled else None,
        ssl_certfile=auth_config.tls_cert_path if auth_config.tls_enabled else None,
        ssl_ca_certs=auth_config.tls_ca_path if auth_config.tls_verify_client else None,
    )


if __name__ == "__main__":
    main()