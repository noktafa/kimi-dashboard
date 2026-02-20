"""
Shared authentication and TLS library for the Kimi ecosystem.

This module provides common security utilities used across all services:
- JWT token generation and validation
- API key authentication
- Role-based access control (RBAC)
- TLS certificate management
- Authentication middleware for FastAPI
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import ssl
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

import jwt
from fastapi import Depends, HTTPException, Security, WebSocketException, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field


class Role(str, Enum):
    """User roles for RBAC."""
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Permission(str, Enum):
    """Permissions for fine-grained access control."""
    # Read permissions
    READ_HEALTH = "read:health"
    READ_SCANS = "read:scans"
    READ_HOSTS = "read:hosts"
    READ_TASKS = "read:tasks"
    READ_WORKFLOWS = "read:workflows"
    READ_DASHBOARD = "read:dashboard"
    
    # Write permissions
    CREATE_SCAN = "create:scan"
    CREATE_TASK = "create:task"
    CREATE_WORKFLOW = "create:workflow"
    
    # Destructive permissions
    DELETE_SCAN = "delete:scan"
    DELETE_TASK = "delete:task"
    DELETE_WORKFLOW = "delete:workflow"
    EXECUTE_COMMAND = "execute:command"
    MANAGE_USERS = "manage:users"
    MANAGE_CERTS = "manage:certs"


# Role to permissions mapping
ROLE_PERMISSIONS: dict[Role, list[Permission]] = {
    Role.ADMIN: list(Permission),  # All permissions
    Role.OPERATOR: [
        Permission.READ_HEALTH,
        Permission.READ_SCANS,
        Permission.READ_HOSTS,
        Permission.READ_TASKS,
        Permission.READ_WORKFLOWS,
        Permission.READ_DASHBOARD,
        Permission.CREATE_SCAN,
        Permission.CREATE_TASK,
        Permission.CREATE_WORKFLOW,
        Permission.EXECUTE_COMMAND,
    ],
    Role.VIEWER: [
        Permission.READ_HEALTH,
        Permission.READ_SCANS,
        Permission.READ_HOSTS,
        Permission.READ_TASKS,
        Permission.READ_WORKFLOWS,
        Permission.READ_DASHBOARD,
    ],
}


class TokenPayload(BaseModel):
    """JWT token payload."""
    sub: str = Field(..., description="Subject (user ID)")
    role: Role = Field(..., description="User role")
    permissions: list[Permission] = Field(default_factory=list)
    iat: datetime = Field(..., description="Issued at")
    exp: datetime = Field(..., description="Expiration")
    jti: str = Field(..., description="Token ID")


class AuthConfig(BaseModel):
    """Authentication configuration."""
    # JWT settings
    jwt_secret: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    jwt_algorithm: str = "HS256"
    jwt_expiry_hours: int = 24
    jwt_refresh_hours: int = 168  # 7 days
    
    # API key settings
    api_keys: dict[str, str] = Field(default_factory=dict)  # key_id -> hashed_key
    api_key_header: str = "X-API-Key"
    
    # TLS settings
    tls_enabled: bool = True
    tls_cert_path: Optional[str] = None
    tls_key_path: Optional[str] = None
    tls_ca_path: Optional[str] = None
    tls_verify_client: bool = False
    
    # Security settings
    require_auth: bool = True
    allowed_hosts: list[str] = Field(default_factory=lambda: ["*"])
    cors_origins: list[str] = Field(default_factory=list)
    
    class Config:
        env_prefix = "KIMI_AUTH_"


class AuthManager:
    """Centralized authentication manager."""
    
    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig()
        self._api_key_cache: dict[str, tuple[str, Role]] = {}  # key_id -> (hashed_key, role)
        self._revoked_tokens: set[str] = set()
    
    def generate_api_key(self, key_id: str, role: Role = Role.VIEWER) -> str:
        """Generate a new API key."""
        raw_key = f"kimi_{secrets.token_urlsafe(32)}"
        hashed_key = self._hash_key(raw_key)
        self.config.api_keys[key_id] = hashed_key
        self._api_key_cache[key_id] = (hashed_key, role)
        return raw_key
    
    def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key."""
        if key_id in self.config.api_keys:
            del self.config.api_keys[key_id]
            self._api_key_cache.pop(key_id, None)
            return True
        return False
    
    def _hash_key(self, key: str) -> str:
        """Hash an API key for storage."""
        return hashlib.sha256(key.encode()).hexdigest()
    
    def verify_api_key(self, key: str) -> Optional[tuple[str, Role]]:
        """Verify an API key and return (key_id, role)."""
        hashed = self._hash_key(key)
        
        # Check cache first
        for key_id, (stored_hash, role) in self._api_key_cache.items():
            if hmac.compare_digest(hashed, stored_hash):
                return key_id, role
        
        # Check stored keys
        for key_id, stored_hash in self.config.api_keys.items():
            if hmac.compare_digest(hashed, stored_hash):
                # Cache for next time
                role = Role.VIEWER  # Default role for API keys
                self._api_key_cache[key_id] = (stored_hash, role)
                return key_id, role
        
        return None
    
    def create_token(
        self,
        user_id: str,
        role: Role,
        custom_claims: Optional[dict[str, Any]] = None,
        expiry_hours: Optional[int] = None,
    ) -> str:
        """Create a JWT token."""
        now = datetime.utcnow()
        jti = secrets.token_urlsafe(16)
        
        payload = {
            "sub": user_id,
            "role": role.value,
            "permissions": [p.value for p in ROLE_PERMISSIONS.get(role, [])],
            "iat": now,
            "exp": now + timedelta(hours=expiry_hours or self.config.jwt_expiry_hours),
            "jti": jti,
        }
        
        if custom_claims:
            payload.update(custom_claims)
        
        return jwt.encode(
            payload,
            self.config.jwt_secret,
            algorithm=self.config.jwt_algorithm,
        )
    
    def verify_token(self, token: str) -> TokenPayload:
        """Verify a JWT token and return the payload."""
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_secret,
                algorithms=[self.config.jwt_algorithm],
            )
            
            # Check if token is revoked
            if payload.get("jti") in self._revoked_tokens:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                )
            
            return TokenPayload(
                sub=payload["sub"],
                role=Role(payload["role"]),
                permissions=[Permission(p) for p in payload.get("permissions", [])],
                iat=payload["iat"],
                exp=payload["exp"],
                jti=payload["jti"],
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
            )
        except jwt.InvalidTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}",
            )
    
    def revoke_token(self, jti: str) -> None:
        """Revoke a token by its JTI."""
        self._revoked_tokens.add(jti)
    
    def refresh_token(self, token: str) -> str:
        """Refresh an expiring token."""
        payload = self.verify_token(token)
        
        # Check if token is eligible for refresh
        time_to_expiry = payload.exp - datetime.utcnow()
        refresh_window = timedelta(hours=self.config.jwt_refresh_hours)
        
        if time_to_expiry > refresh_window:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token is not eligible for refresh yet",
            )
        
        # Revoke old token
        self.revoke_token(payload.jti)
        
        # Create new token
        return self.create_token(
            user_id=payload.sub,
            role=payload.role,
        )
    
    def has_permission(self, token_payload: TokenPayload, permission: Permission) -> bool:
        """Check if a token has a specific permission."""
        return permission in token_payload.permissions
    
    def require_permission(self, permission: Permission) -> Callable:
        """Create a dependency that requires a specific permission."""
        async def check_permission(
            credentials: HTTPAuthorizationCredentials = Security(HTTPBearer()),
        ) -> TokenPayload:
            payload = self.verify_token(credentials.credentials)
            if not self.has_permission(payload, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission.value} required",
                )
            return payload
        return check_permission


# Global auth manager instance
_auth_manager: Optional[AuthManager] = None


def get_auth_manager() -> AuthManager:
    """Get the global auth manager instance."""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager


def set_auth_manager(manager: AuthManager) -> None:
    """Set the global auth manager instance."""
    global _auth_manager
    _auth_manager = manager


# FastAPI security schemes
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    api_key: Optional[str] = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> TokenPayload:
    """
    FastAPI dependency to get the current authenticated user.
    Supports both API key and JWT bearer token authentication.
    """
    auth_manager = get_auth_manager()
    
    # Try API key first
    if api_key:
        result = auth_manager.verify_api_key(api_key)
        if result:
            key_id, role = result
            return TokenPayload(
                sub=f"apikey:{key_id}",
                role=role,
                permissions=ROLE_PERMISSIONS.get(role, []),
                iat=datetime.utcnow(),
                exp=datetime.utcnow() + timedelta(hours=1),
                jti=secrets.token_urlsafe(16),
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Try JWT bearer token
    if bearer:
        return auth_manager.verify_token(bearer.credentials)
    
    # No credentials provided
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def optional_auth(
    api_key: Optional[str] = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> Optional[TokenPayload]:
    """Optional authentication - returns None if no credentials provided."""
    try:
        return await get_current_user(api_key, bearer)
    except HTTPException:
        return None


async def websocket_auth(token: str) -> TokenPayload:
    """
    Authenticate WebSocket connections.
    Token should be provided as a query parameter or initial message.
    """
    auth_manager = get_auth_manager()
    
    try:
        return auth_manager.verify_token(token)
    except HTTPException as e:
        raise WebSocketException(code=4001, reason=e.detail)


class TLSManager:
    """Manages TLS certificates and SSL contexts."""
    
    def __init__(
        self,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        ca_path: Optional[str] = None,
        verify_client: bool = False,
    ):
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path
        self.verify_client = verify_client
    
    def create_ssl_context(self, server_side: bool = True) -> ssl.SSLContext:
        """Create an SSL context for TLS connections."""
        if server_side:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            if self.cert_path and self.key_path:
                context.load_cert_chain(self.cert_path, self.key_path)
            
            if self.verify_client and self.ca_path:
                context.load_verify_locations(self.ca_path)
                context.verify_mode = ssl.CERT_REQUIRED
        else:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            
            if self.ca_path:
                context.load_verify_locations(self.ca_path)
            
            if self.cert_path and self.key_path:
                context.load_cert_chain(self.cert_path, self.key_path)
        
        # Modern TLS settings
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS")
        
        return context
    
    @staticmethod
    def generate_self_signed_cert(
        hostname: str = "localhost",
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
    ) -> tuple[str, str]:
        """Generate a self-signed certificate for development/testing."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        
        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kimi Ecosystem"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
                x509.DNSName("*." + hostname),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.IPAddress(ipaddress.ip_address("::1")),
            ]),
            critical=False,
        ).sign(key, hashes.SHA256())
        
        # Write certificate
        cert_file = cert_path or tempfile.mktemp(suffix=".crt")
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Write private key
        key_file = key_path or tempfile.mktemp(suffix=".key")
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        
        return cert_file, key_file


# Import for self-signed cert generation
import ipaddress


__all__ = [
    "Role",
    "Permission",
    "ROLE_PERMISSIONS",
    "TokenPayload",
    "AuthConfig",
    "AuthManager",
    "get_auth_manager",
    "set_auth_manager",
    "get_current_user",
    "optional_auth",
    "websocket_auth",
    "TLSManager",
    "api_key_header",
    "bearer_scheme",
]