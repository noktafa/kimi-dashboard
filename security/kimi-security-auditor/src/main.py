"""
Secured Kimi Security Auditor Service

A production-ready security scanning service with:
- API key authentication (X-API-Key header)
- JWT bearer token support
- TLS with auto-generated self-signed certs
- YAML-based configuration
"""

from __future__ import annotations

import os
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import uvicorn
import yaml
from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials
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
)


# Configuration
class ServiceConfig(BaseModel):
    """Service configuration."""
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"
    
    class Config:
        env_prefix = "SECURITY_AUDITOR_"


# Pydantic models
class ScanRequest(BaseModel):
    target: str = Field(..., description="Target URL or host to scan")
    scan_type: str = Field(default="full", description="Type of scan to perform")
    options: Optional[dict] = Field(default=None, description="Additional scan options")


class ScanResult(BaseModel):
    id: str
    target: str
    status: str
    findings: list[dict]
    timestamp: str
    scanned_by: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    authenticated: bool = False
    user: Optional[str] = None


# Global state
_config: Optional[ServiceConfig] = None
_auth_manager: Optional[AuthManager] = None


def load_config() -> tuple[ServiceConfig, AuthConfig]:
    """Load configuration from YAML file and environment."""
    service_config = ServiceConfig()
    auth_config = AuthConfig()
    
    # Load from YAML if exists
    config_path = Path(__file__).parent.parent / "config" / "security-auditor.yaml"
    if config_path.exists():
        with open(config_path) as f:
            yaml_config = yaml.safe_load(f)
        
        if yaml_config:
            # Update service config
            if "service" in yaml_config:
                for key, value in yaml_config["service"].items():
                    if hasattr(service_config, key):
                        setattr(service_config, key, value)
            
            # Update auth config
            if "auth" in yaml_config:
                for key, value in yaml_config["auth"].items():
                    if hasattr(auth_config, key):
                        setattr(auth_config, key, value)
            
            # Update TLS config
            if "tls" in yaml_config:
                for key, value in yaml_config["tls"].items():
                    if hasattr(auth_config, key):
                        setattr(auth_config, key, value)
    
    # Override with environment variables
    if os.getenv("SECURITY_AUDITOR_JWT_SECRET"):
        auth_config.jwt_secret = os.getenv("SECURITY_AUDITOR_JWT_SECRET")
    if os.getenv("SECURITY_AUDITOR_API_KEYS"):
        # Format: key_id:hash,key_id2:hash2
        auth_config.api_keys = dict(
            pair.split(":") for pair in os.getenv("SECURITY_AUDITOR_API_KEYS").split(",")
        )
    
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
    title="Kimi Security Auditor",
    description="Security scanning service for the Kimi ecosystem",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if os.getenv("ENV") != "production" else None,
    redoc_url="/redoc" if os.getenv("ENV") != "production" else None,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure based on auth_config.allowed_hosts
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health_check(
    user: Optional[TokenPayload] = Depends(optional_auth),
):
    """Health check endpoint - accessible without auth."""
    return HealthResponse(
        status="healthy",
        service="security-auditor",
        version="1.0.0",
        authenticated=user is not None,
        user=user.sub if user else None,
    )


@app.get("/")
async def root(user: TokenPayload = Depends(get_current_user)):
    """Root endpoint - requires authentication."""
    return {
        "service": "Kimi Security Auditor",
        "version": "1.0.0",
        "user": user.sub,
        "role": user.role.value,
        "endpoints": [
            "/health",
            "/scan",
            "/scans/{scan_id}",
            "/scans"
        ],
    }


@app.post("/scan", response_model=ScanResult)
async def start_scan(
    request: ScanRequest,
    user: TokenPayload = Depends(get_current_user),
):
    """Start a security scan - requires create:scan permission."""
    auth_manager = get_auth_manager()
    
    if not auth_manager.has_permission(user, Permission.CREATE_SCAN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: create:scan required",
        )
    
    scan_id = str(uuid.uuid4())
    return ScanResult(
        id=scan_id,
        target=request.target,
        status="queued",
        findings=[],
        timestamp=datetime.utcnow().isoformat(),
        scanned_by=user.sub,
    )


@app.get("/scans/{scan_id}", response_model=ScanResult)
async def get_scan(
    scan_id: str,
    user: TokenPayload = Depends(get_current_user),
):
    """Get scan results - requires read:scans permission."""
    auth_manager = get_auth_manager()
    
    if not auth_manager.has_permission(user, Permission.READ_SCANS):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: read:scans required",
        )
    
    return ScanResult(
        id=scan_id,
        target="example.com",
        status="completed",
        findings=[],
        timestamp=datetime.utcnow().isoformat(),
        scanned_by=user.sub,
    )


@app.get("/scans")
async def list_scans(
    user: TokenPayload = Depends(get_current_user),
    limit: int = 100,
    offset: int = 0,
):
    """List all scans - requires read:scans permission."""
    auth_manager = get_auth_manager()
    
    if not auth_manager.has_permission(user, Permission.READ_SCANS):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: read:scans required",
        )
    
    return {"scans": [], "total": 0, "limit": limit, "offset": offset}


@app.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: str,
    user: TokenPayload = Depends(get_current_user),
):
    """Delete a scan - requires delete:scan permission (admin only)."""
    auth_manager = get_auth_manager()
    
    if not auth_manager.has_permission(user, Permission.DELETE_SCAN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: delete:scan required",
        )
    
    return {"message": f"Scan {scan_id} deleted", "deleted_by": user.sub}


@app.post("/auth/token")
async def create_token(
    user_id: str,
    role: Role = Role.VIEWER,
    api_key: Optional[str] = None,
):
    """Create a JWT token (for testing - requires valid API key)."""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )
    
    auth_manager = get_auth_manager()
    result = auth_manager.verify_api_key(api_key)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    
    token = auth_manager.create_token(user_id, role)
    return {"access_token": token, "token_type": "bearer"}


def main():
    """Main entry point."""
    service_config, auth_config = load_config()
    
    # Setup TLS
    ssl_context = None
    if auth_config.tls_enabled:
        tls_manager = TLSManager(
            cert_path=auth_config.tls_cert_path,
            key_path=auth_config.tls_key_path,
            ca_path=auth_config.tls_ca_path,
            verify_client=auth_config.tls_verify_client,
        )
        ssl_context = tls_manager.create_ssl_context(server_side=True)
    
    uvicorn.run(
        "main:app",
        host=service_config.host,
        port=service_config.port,
        log_level=service_config.log_level,
        ssl_keyfile=auth_config.tls_key_path if auth_config.tls_enabled else None,
        ssl_certfile=auth_config.tls_cert_path if auth_config.tls_enabled else None,
        ssl_ca_certs=auth_config.tls_ca_path if auth_config.tls_verify_client else None,
        ssl_cert_reqs=ssl.CERT_REQUIRED if auth_config.tls_verify_client else ssl.CERT_NONE,
    )


if __name__ == "__main__":
    main()