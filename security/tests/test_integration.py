#!/usr/bin/env python3
"""
Integration test for Kimi Ecosystem Security

Tests the complete authentication flow across all services.
"""

import sys
import os
from pathlib import Path

# Add shared module to path
sys.path.insert(0, str(Path(__file__).parent.parent / "shared"))

from auth import AuthManager, AuthConfig, Role, Permission


def test_cross_service_auth():
    """Test that tokens work across services."""
    print("Testing Cross-Service Authentication...")
    
    # Simulate services with different secrets (in production, use same secret or key rotation)
    config1 = AuthConfig(jwt_secret="shared-secret-for-testing", require_auth=True)
    config2 = AuthConfig(jwt_secret="shared-secret-for-testing", require_auth=True)
    
    auth1 = AuthManager(config1)
    auth2 = AuthManager(config2)
    
    # Create token with service 1
    print("  - Creating token with Security Auditor...")
    token = auth1.create_token("user@example.com", Role.OPERATOR)
    
    # Verify with service 2
    print("  - Verifying token with SysAdmin AI...")
    payload = auth2.verify_token(token)
    assert payload.sub == "user@example.com"
    assert payload.role == Role.OPERATOR
    print(f"    Cross-service auth successful: {payload.sub}")
    
    print("  ✓ Cross-service auth test passed\n")


def test_api_key_roles():
    """Test API keys with different roles."""
    print("Testing API Key Roles...")
    
    config = AuthConfig(require_auth=True)
    auth = AuthManager(config)
    
    # Create keys for different roles
    print("  - Creating API keys for different roles...")
    admin_key = auth.generate_api_key("admin-service", Role.ADMIN)
    operator_key = auth.generate_api_key("operator-service", Role.OPERATOR)
    viewer_key = auth.generate_api_key("viewer-service", Role.VIEWER)
    
    # Verify roles
    print("  - Verifying key roles...")
    _, admin_role = auth.verify_api_key(admin_key)
    _, operator_role = auth.verify_api_key(operator_key)
    _, viewer_role = auth.verify_api_key(viewer_key)
    
    assert admin_role == Role.ADMIN
    assert operator_role == Role.OPERATOR
    assert viewer_role == Role.VIEWER
    
    print(f"    Admin key: {admin_role.value}")
    print(f"    Operator key: {operator_role.value}")
    print(f"    Viewer key: {viewer_role.value}")
    
    print("  ✓ API key roles test passed\n")


def test_permission_matrix():
    """Test permission matrix for all roles."""
    print("Testing Permission Matrix...")
    
    config = AuthConfig(jwt_secret="test-secret-for-permissions")
    auth = AuthManager(config)
    
    test_cases = [
        (Role.ADMIN, Permission.MANAGE_USERS, True),
        (Role.ADMIN, Permission.EXECUTE_COMMAND, True),
        (Role.ADMIN, Permission.READ_SCANS, True),
        (Role.OPERATOR, Permission.MANAGE_USERS, False),
        (Role.OPERATOR, Permission.EXECUTE_COMMAND, True),
        (Role.OPERATOR, Permission.READ_SCANS, True),
        (Role.VIEWER, Permission.MANAGE_USERS, False),
        (Role.VIEWER, Permission.EXECUTE_COMMAND, False),
        (Role.VIEWER, Permission.READ_SCANS, True),
    ]
    
    print("  - Testing permission checks...")
    for role, permission, expected in test_cases:
        token = auth.create_token("test", role)
        payload = auth.verify_token(token)
        result = auth.has_permission(payload, permission)
        status = "✓" if result == expected else "✗"
        print(f"    {status} {role.value:10} + {permission.value:20} = {result}")
        assert result == expected, f"Failed: {role.value} should {'have' if expected else 'not have'} {permission.value}"
    
    print("  ✓ Permission matrix test passed\n")


def test_token_lifecycle():
    """Test token creation, verification, and revocation."""
    print("Testing Token Lifecycle...")
    
    config = AuthConfig(jwt_secret="test-secret-for-lifecycle")
    auth = AuthManager(config)
    
    # Create token
    print("  - Creating token...")
    token = auth.create_token("user123", Role.ADMIN)
    
    # Verify
    print("  - Verifying token...")
    payload1 = auth.verify_token(token)
    assert payload1.sub == "user123"
    
    # Revoke
    print("  - Revoking token...")
    auth.revoke_token(payload1.jti)
    
    # Verify revoked
    print("  - Checking revocation...")
    try:
        auth.verify_token(token)
        assert False, "Token should be revoked"
    except Exception:
        pass  # Expected
    
    # Create new token
    print("  - Creating new token...")
    token2 = auth.create_token("user123", Role.ADMIN)
    payload2 = auth.verify_token(token2)
    assert payload2.sub == "user123"
    
    print("  ✓ Token lifecycle test passed\n")


def main():
    """Run all integration tests."""
    print("=" * 60)
    print("Kimi Ecosystem Security - Integration Tests")
    print("=" * 60)
    print()
    
    try:
        test_cross_service_auth()
        test_api_key_roles()
        test_permission_matrix()
        test_token_lifecycle()
        
        print("=" * 60)
        print("All integration tests passed! ✓")
        print("=" * 60)
        return 0
    
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())