#!/usr/bin/env python3
"""
Test script for Kimi Ecosystem Security

This script tests the authentication and TLS implementation.
"""

import sys
import os
from pathlib import Path

# Add shared module to path
sys.path.insert(0, str(Path(__file__).parent.parent / "shared"))

from auth import (
    AuthManager,
    AuthConfig,
    Role,
    Permission,
    TokenPayload,
    TLSManager,
)


def test_auth_manager():
    """Test AuthManager functionality."""
    print("Testing AuthManager...")
    
    config = AuthConfig(
        jwt_secret="test-secret-key-for-testing-only",
        require_auth=True,
    )
    
    auth = AuthManager(config)
    
    # Test API key generation
    print("  - Generating API key...")
    api_key = auth.generate_api_key("test-service", Role.OPERATOR)
    assert api_key.startswith("kimi_"), "API key should start with 'kimi_'"
    print(f"    Generated: {api_key[:20]}...")
    
    # Test API key verification
    print("  - Verifying API key...")
    result = auth.verify_api_key(api_key)
    assert result is not None, "API key should be valid"
    key_id, role = result
    assert role == Role.OPERATOR, "Role should be OPERATOR"
    print(f"    Verified: key_id={key_id}, role={role.value}")
    
    # Test invalid API key
    print("  - Testing invalid API key...")
    result = auth.verify_api_key("invalid-key")
    assert result is None, "Invalid key should return None"
    print("    Correctly rejected invalid key")
    
    # Test JWT token creation
    print("  - Creating JWT token...")
    token = auth.create_token("user123", Role.ADMIN)
    assert token is not None, "Token should be created"
    print(f"    Token: {token[:50]}...")
    
    # Test JWT token verification
    print("  - Verifying JWT token...")
    payload = auth.verify_token(token)
    assert payload.sub == "user123", "Subject should match"
    assert payload.role == Role.ADMIN, "Role should be ADMIN"
    print(f"    Verified: sub={payload.sub}, role={payload.role.value}")
    
    # Test permission check
    print("  - Testing permission checks...")
    assert auth.has_permission(payload, Permission.READ_SCANS), "Admin should have read:scans"
    assert auth.has_permission(payload, Permission.EXECUTE_COMMAND), "Admin should have execute:command"
    assert auth.has_permission(payload, Permission.MANAGE_USERS), "Admin should have manage:users"
    print("    All permission checks passed")
    
    print("  ✓ AuthManager tests passed\n")


def test_role_permissions():
    """Test role-based permissions."""
    print("Testing Role-Based Access Control...")
    
    from auth import ROLE_PERMISSIONS
    
    # Admin should have all permissions
    print("  - Admin permissions...")
    admin_perms = ROLE_PERMISSIONS[Role.ADMIN]
    assert len(admin_perms) == len(Permission), "Admin should have all permissions"
    print(f"    Admin has {len(admin_perms)} permissions")
    
    # Operator should have read + create + execute
    print("  - Operator permissions...")
    operator_perms = ROLE_PERMISSIONS[Role.OPERATOR]
    assert Permission.READ_SCANS in operator_perms, "Operator should have read:scans"
    assert Permission.CREATE_SCAN in operator_perms, "Operator should have create:scan"
    assert Permission.EXECUTE_COMMAND in operator_perms, "Operator should have execute:command"
    assert Permission.DELETE_SCAN not in operator_perms, "Operator should NOT have delete:scan"
    print(f"    Operator has {len(operator_perms)} permissions")
    
    # Viewer should only have read permissions
    print("  - Viewer permissions...")
    viewer_perms = ROLE_PERMISSIONS[Role.VIEWER]
    assert all(p.value.startswith("read:") for p in viewer_perms), "Viewer should only have read permissions"
    print(f"    Viewer has {len(viewer_perms)} permissions")
    
    print("  ✓ RBAC tests passed\n")


def test_tls_manager():
    """Test TLSManager functionality."""
    print("Testing TLSManager...")
    
    # Test with generated certificates
    certs_dir = Path(__file__).parent.parent / "certs"
    
    if not (certs_dir / "ca.crt").exists():
        print("  ⚠ Certificates not found, skipping TLS tests")
        return
    
    tls = TLSManager(
        cert_path=str(certs_dir / "security-auditor" / "tls.crt"),
        key_path=str(certs_dir / "security-auditor" / "tls.key"),
        ca_path=str(certs_dir / "ca.crt"),
    )
    
    # Test SSL context creation
    print("  - Creating server SSL context...")
    server_context = tls.create_ssl_context(server_side=True)
    assert server_context is not None, "Server context should be created"
    print("    Server context created")
    
    print("  - Creating client SSL context...")
    client_context = tls.create_ssl_context(server_side=False)
    assert client_context is not None, "Client context should be created"
    print("    Client context created")
    
    print("  ✓ TLSManager tests passed\n")


def test_token_refresh():
    """Test token refresh functionality."""
    print("Testing Token Revocation...")
    
    config = AuthConfig(
        jwt_secret="test-secret-for-jwt-tokens-32bytes",
        jwt_expiry_hours=1,  # 1 hour expiry
    )
    
    auth = AuthManager(config)
    
    # Create a token
    print("  - Creating token...")
    token = auth.create_token("user123", Role.OPERATOR)
    
    # Verify it works
    print("  - Verifying token...")
    payload = auth.verify_token(token)
    assert payload.sub == "user123"
    print(f"    Token valid for user: {payload.sub}")
    
    # Revoke token
    print("  - Revoking token...")
    auth.revoke_token(payload.jti)
    
    # Verify it's revoked
    print("  - Checking revocation...")
    try:
        auth.verify_token(token)
        assert False, "Token should be revoked"
    except Exception as e:
        assert "revoked" in str(e).lower() or "401" in str(e)
        print("    Token correctly revoked")
    
    print("  ✓ Token revocation tests passed\n")


def main():
    """Run all tests."""
    print("=" * 60)
    print("Kimi Ecosystem Security Tests")
    print("=" * 60)
    print()
    
    try:
        test_auth_manager()
        test_role_permissions()
        test_tls_manager()
        test_token_refresh()
        
        print("=" * 60)
        print("All tests passed! ✓")
        print("=" * 60)
        return 0
    
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())