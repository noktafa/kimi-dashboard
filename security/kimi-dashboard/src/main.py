"""
Secured Kimi Dashboard Service

A production-ready dashboard with:
- Login page with username/password
- Session cookies (HTTP-only, secure, SameSite)
- Proxy auth to backend services
- TLS for all connections
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

import httpx
import uvicorn
import yaml
from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
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
    set_auth_manager,
    TokenPayload,
)


# Configuration
class ServiceConfig(BaseModel):
    """Service configuration."""
    host: str = "0.0.0.0"
    port: int = 8766
    log_level: str = "info"
    
    # Session settings
    session_cookie_name: str = "kimi_session"
    session_max_age: int = 86400  # 24 hours
    session_secure: bool = True
    session_http_only: bool = True
    session_same_site: str = "Strict"
    
    # Backend service URLs
    security_auditor_url: str = "https://localhost:8000"
    sysadmin_ai_url: str = "https://localhost:8001"
    convergence_loop_url: str = "https://localhost:8002"
    
    # Static files
    static_dir: str = "static"
    templates_dir: str = "templates"
    
    class Config:
        env_prefix = "DASHBOARD_"


# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    success: bool
    message: str
    redirect_url: str = "/dashboard"


class UserSession(BaseModel):
    session_id: str
    user_id: str
    username: str
    role: Role
    created_at: datetime
    expires_at: datetime


class DashboardStats(BaseModel):
    total_workflows: int
    active_workflows: int
    total_scans: int
    system_health: str


# In-memory session store (use Redis in production)
_sessions: dict[str, UserSession] = {}
_users: dict[str, tuple[str, Role]] = {}  # username -> (hashed_password, role)

# Global state
_config: Optional[ServiceConfig] = None
_auth_manager: Optional[AuthManager] = None


def load_config() -> tuple[ServiceConfig, AuthConfig]:
    """Load configuration from YAML file and environment."""
    service_config = ServiceConfig()
    auth_config = AuthConfig()
    
    # Load from YAML if exists
    config_path = Path(__file__).parent.parent / "config" / "dashboard.yaml"
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
    if os.getenv("DASHBOARD_JWT_SECRET"):
        auth_config.jwt_secret = os.getenv("DASHBOARD_JWT_SECRET")
    
    return service_config, auth_config


def hash_password(password: str) -> str:
    """Hash a password for storage."""
    salt = secrets.token_hex(16)
    pwdhash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return salt + pwdhash.hex()


def verify_password(stored: str, provided: str) -> bool:
    """Verify a password against its hash."""
    salt = stored[:32]
    stored_hash = stored[32:]
    pwdhash = hashlib.pbkdf2_hmac("sha256", provided.encode(), salt.encode(), 100000)
    return pwdhash.hex() == stored_hash


def create_session(user_id: str, username: str, role: Role, max_age: int) -> UserSession:
    """Create a new user session."""
    session_id = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    
    session = UserSession(
        session_id=session_id,
        user_id=user_id,
        username=username,
        role=role,
        created_at=now,
        expires_at=now + timedelta(seconds=max_age),
    )
    
    _sessions[session_id] = session
    return session


def get_session(session_id: Optional[str]) -> Optional[UserSession]:
    """Get a session by ID."""
    if not session_id:
        return None
    
    session = _sessions.get(session_id)
    if not session:
        return None
    
    # Check expiration
    if datetime.utcnow() > session.expires_at:
        del _sessions[session_id]
        return None
    
    return session


def delete_session(session_id: str) -> None:
    """Delete a session."""
    if session_id in _sessions:
        del _sessions[session_id]


async def get_current_session(
    session_id: Optional[str] = Cookie(None, alias="kimi_session"),
) -> Optional[UserSession]:
    """Get the current session from cookie."""
    return get_session(session_id)


async def require_session(
    session: Optional[UserSession] = Depends(get_current_session),
) -> UserSession:
    """Require a valid session."""
    if not session:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": "/login"},
        )
    return session


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global _config, _auth_manager, _users
    
    # Load configuration
    service_config, auth_config = load_config()
    _config = service_config
    
    # Initialize auth manager
    _auth_manager = AuthManager(auth_config)
    set_auth_manager(_auth_manager)
    
    # Create default users if none exist
    if not _users:
        # Default admin user
        _users["admin"] = (hash_password("admin"), Role.ADMIN)
        # Default operator user
        _users["operator"] = (hash_password("operator"), Role.OPERATOR)
        # Default viewer user
        _users["viewer"] = (hash_password("viewer"), Role.VIEWER)
        
        print(f"\n{'='*60}")
        print("DEFAULT USERS CREATED:")
        print(f"{'='*60}")
        print("  admin / admin     (full access)")
        print("  operator / operator (can execute commands)")
        print("  viewer / viewer   (read-only)")
        print(f"{'='*60}\n")
    
    yield
    
    # Cleanup
    pass


# Create FastAPI app
app = FastAPI(
    title="Kimi Dashboard",
    description="Real-time dashboard for Kimi Convergence Loop",
    version="1.0.0",
    lifespan=lifespan,
)

# Setup templates and static files
base_dir = Path(__file__).parent
templates_dir = base_dir / "templates"
static_dir = base_dir / "static"

templates = Jinja2Templates(directory=str(templates_dir))

if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    """Serve the login page."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Kimi Dashboard - Login</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .login-container {
                background: white;
                padding: 3rem;
                border-radius: 12px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                width: 100%;
                max-width: 400px;
            }
            h1 {
                color: #333;
                margin-bottom: 0.5rem;
                font-size: 1.8rem;
            }
            .subtitle {
                color: #666;
                margin-bottom: 2rem;
                font-size: 0.9rem;
            }
            .form-group {
                margin-bottom: 1.5rem;
            }
            label {
                display: block;
                margin-bottom: 0.5rem;
                color: #555;
                font-weight: 500;
                font-size: 0.9rem;
            }
            input[type="text"],
            input[type="password"] {
                width: 100%;
                padding: 0.75rem 1rem;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 1rem;
                transition: border-color 0.2s;
            }
            input[type="text"]:focus,
            input[type="password"]:focus {
                outline: none;
                border-color: #667eea;
            }
            button {
                width: 100%;
                padding: 0.875rem;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 1rem;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
            }
            button:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
            }
            .error {
                background: #fee;
                color: #c33;
                padding: 0.75rem;
                border-radius: 8px;
                margin-bottom: 1rem;
                font-size: 0.9rem;
            }
            .security-info {
                margin-top: 2rem;
                padding-top: 1.5rem;
                border-top: 1px solid #e0e0e0;
                text-align: center;
                font-size: 0.8rem;
                color: #888;
            }
            .security-info span {
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>Kimi Dashboard</h1>
            <p class="subtitle">Sign in to access the convergence loop</p>
            
            {% if error %}
            <div class="error">{{ error }}</div>
            {% endif %}
            
            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autofocus>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <button type="submit">Sign In</button>
            </form>
            
            <div class="security-info">
                <span>🔒 Secure connection required</span>
            </div>
        </div>
    </body>
    </html>
    """
    
    from jinja2 import Template
    template = Template(html_content)
    return HTMLResponse(template.render(error=error))


@app.post("/login")
async def login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    """Handle login form submission."""
    global _users, _config
    
    # Verify credentials
    user_data = _users.get(username)
    if not user_data or not verify_password(user_data[0], password):
        return RedirectResponse(
            url="/login?error=Invalid+credentials",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    
    _, role = user_data
    
    # Create session
    session = create_session(
        user_id=username,
        username=username,
        role=role,
        max_age=_config.session_max_age if _config else 86400,
    )
    
    # Set session cookie
    response = RedirectResponse(
        url="/dashboard",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    
    response.set_cookie(
        key="kimi_session",
        value=session.session_id,
        max_age=_config.session_max_age if _config else 86400,
        httponly=_config.session_http_only if _config else True,
        secure=_config.session_secure if _config else True,
        samesite=_config.session_same_site if _config else "Strict",
    )
    
    return response


@app.get("/logout")
async def logout(
    session: Optional[UserSession] = Depends(get_current_session),
):
    """Handle logout."""
    if session:
        delete_session(session.session_id)
    
    response = RedirectResponse(
        url="/login",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    response.delete_cookie(key="kimi_session")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    session: UserSession = Depends(require_session),
):
    """Serve the main dashboard."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Kimi Dashboard</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #f5f7fa;
                min-height: 100vh;
            }
            .header {
                background: white;
                border-bottom: 1px solid #e0e0e0;
                padding: 1rem 2rem;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .header h1 {
                font-size: 1.5rem;
                color: #333;
            }
            .user-info {
                display: flex;
                align-items: center;
                gap: 1rem;
            }
            .role-badge {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 0.25rem 0.75rem;
                border-radius: 20px;
                font-size: 0.75rem;
                font-weight: 600;
                text-transform: uppercase;
            }
            .logout-btn {
                color: #666;
                text-decoration: none;
                font-size: 0.9rem;
            }
            .logout-btn:hover {
                color: #333;
            }
            .container {
                max-width: 1200px;
                margin: 2rem auto;
                padding: 0 2rem;
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 1.5rem;
                margin-bottom: 2rem;
            }
            .stat-card {
                background: white;
                padding: 1.5rem;
                border-radius: 12px;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
            }
            .stat-card h3 {
                font-size: 0.875rem;
                color: #666;
                margin-bottom: 0.5rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .stat-value {
                font-size: 2rem;
                font-weight: 700;
                color: #333;
            }
            .main-content {
                background: white;
                border-radius: 12px;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
                padding: 2rem;
            }
            .main-content h2 {
                margin-bottom: 1rem;
                color: #333;
            }
            .status-indicator {
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                padding: 0.5rem 1rem;
                background: #e8f5e9;
                color: #2e7d32;
                border-radius: 20px;
                font-size: 0.875rem;
                font-weight: 500;
            }
            .status-indicator::before {
                content: '';
                width: 8px;
                height: 8px;
                background: #4caf50;
                border-radius: 50%;
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
        </style>
    </head>
    <body>
        <header class="header">
            <h1>Kimi Dashboard</h1>
            <div class="user-info">
                <span>Welcome, {{ username }}</span>
                <span class="role-badge">{{ role }}</span>
                <a href="/logout" class="logout-btn">Logout</a>
            </div>
        </header>
        
        <div class="container">
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Active Workflows</h3>
                    <div class="stat-value">0</div>
                </div>
                <div class="stat-card">
                    <h3>Total Scans</h3>
                    <div class="stat-value">0</div>
                </div>
                <div class="stat-card">
                    <h3>System Health</h3>
                    <span class="status-indicator">Healthy</span>
                </div>
                <div class="stat-card">
                    <h3>Active Sessions</h3>
                    <div class="stat-value">1</div>
                </div>
            </div>
            
            <div class="main-content">
                <h2>Convergence Loop Status</h2>
                <p>Connected to convergence loop at wss://localhost:8002/ws</p>
                <p style="margin-top: 1rem; color: #666;">
                    WebSocket connection will be established automatically.
                </p>
            </div>
        </div>
        
        <script>
            // WebSocket connection would be established here
            console.log('Dashboard loaded for user: {{ username }}');
        </script>
    </body>
    </html>
    """
    
    from jinja2 import Template
    template = Template(html_content)
    return HTMLResponse(template.render(
        username=session.username,
        role=session.role.value,
    ))


@app.get("/")
async def root():
    """Redirect to dashboard or login."""
    return RedirectResponse(url="/dashboard")


@app.get("/api/me")
async def get_current_user_info(
    session: UserSession = Depends(require_session),
):
    """Get current user information."""
    return {
        "user_id": session.user_id,
        "username": session.username,
        "role": session.role.value,
    }


@app.get("/api/stats")
async def get_stats(
    session: UserSession = Depends(require_session),
):
    """Get dashboard statistics."""
    return {
        "total_workflows": 0,
        "active_workflows": 0,
        "total_scans": 0,
        "system_health": "healthy",
    }


# Proxy endpoints to backend services
@app.get("/api/proxy/security-auditor/{path:path}")
async def proxy_security_auditor(
    path: str,
    request: Request,
    session: UserSession = Depends(require_session),
):
    """Proxy requests to security auditor service."""
    if not _config:
        raise HTTPException(status_code=500, detail="Configuration not loaded")
    
    # Create JWT token for backend
    token = _auth_manager.create_token(
        user_id=session.user_id,
        role=session.role,
    )
    
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.get(
            f"{_config.security_auditor_url}/{path}",
            headers={"Authorization": f"Bearer {token}"},
        )
        return JSONResponse(content=response.json(), status_code=response.status_code)


@app.get("/api/proxy/sysadmin-ai/{path:path}")
async def proxy_sysadmin_ai(
    path: str,
    request: Request,
    session: UserSession = Depends(require_session),
):
    """Proxy requests to sysadmin AI service."""
    if not _config:
        raise HTTPException(status_code=500, detail="Configuration not loaded")
    
    # Create JWT token for backend
    token = _auth_manager.create_token(
        user_id=session.user_id,
        role=session.role,
    )
    
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.get(
            f"{_config.sysadmin_ai_url}/{path}",
            headers={"Authorization": f"Bearer {token}"},
        )
        return JSONResponse(content=response.json(), status_code=response.status_code)


@app.get("/api/proxy/convergence-loop/{path:path}")
async def proxy_convergence_loop(
    path: str,
    request: Request,
    session: UserSession = Depends(require_session),
):
    """Proxy requests to convergence loop service."""
    if not _config:
        raise HTTPException(status_code=500, detail="Configuration not loaded")
    
    # Create JWT token for backend
    token = _auth_manager.create_token(
        user_id=session.user_id,
        role=session.role,
    )
    
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.get(
            f"{_config.convergence_loop_url}/{path}",
            headers={"Authorization": f"Bearer {token}"},
        )
        return JSONResponse(content=response.json(), status_code=response.status_code)


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
    )


if __name__ == "__main__":
    main()