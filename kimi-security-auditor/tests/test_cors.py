"""
Tests for CORS checker.
"""

import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock

from kimi_security_auditor.attacks.cors import CORSChecker
from kimi_security_auditor.models import Finding, Severity, Confidence


@pytest.fixture
def mock_client():
    """Create a mock HTTP client."""
    client = MagicMock(spec=httpx.AsyncClient)
    return client


@pytest.fixture
def checker(mock_client):
    """Create a CORS checker instance."""
    return CORSChecker(mock_client)


@pytest.mark.asyncio
async def test_parse_cors_headers(checker):
    """Test CORS header parsing."""
    headers = httpx.Headers({
        'Access-Control-Allow-Origin': 'https://example.com',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'GET, POST',
    })
    
    result = checker._parse_cors_headers(headers)
    
    assert result['access-control-allow-origin'] == 'https://example.com'
    assert result['access-control-allow-credentials'] == 'true'
    assert result['access-control-allow-methods'] == 'GET, POST'


@pytest.mark.asyncio
async def test_origin_reflection_wildcard_with_credentials(mock_client, checker):
    """Test detection of wildcard with credentials."""
    response = MagicMock()
    response.headers = httpx.Headers({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
    })
    
    mock_client.get = AsyncMock(return_value=response)
    
    url = "http://example.com/api"
    findings = await checker.scan_url(url)
    
    assert len(findings) > 0
    assert any(f.finding_type == "cors_wildcard_credentials" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_arbitrary_origin_reflection(mock_client, checker):
    """Test detection of arbitrary origin reflection."""
    response = MagicMock()
    response.headers = httpx.Headers({
        'Access-Control-Allow-Origin': 'https://evil-cors-test.com',
    })
    
    mock_client.get = AsyncMock(return_value=response)
    
    url = "http://example.com/api"
    findings = await checker.scan_url(url)
    
    assert len(findings) > 0
    assert any(f.finding_type == "cors_arbitrary_origin" for f in findings)


@pytest.mark.asyncio
async def test_null_origin_allowed(mock_client, checker):
    """Test detection of null origin allowance."""
    response = MagicMock()
    response.headers = httpx.Headers({
        'Access-Control-Allow-Origin': 'null',
    })
    
    mock_client.get = AsyncMock(return_value=response)
    
    url = "http://example.com/api"
    findings = await checker.scan_url(url)
    
    assert len(findings) > 0
    assert any(f.finding_type == "cors_null_origin" for f in findings)


@pytest.mark.asyncio
async def test_preflight_dangerous_methods(mock_client, checker):
    """Test detection of dangerous methods in preflight."""
    response = MagicMock()
    response.headers = httpx.Headers({
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, PUT',
    })
    
    mock_client.options = AsyncMock(return_value=response)
    
    url = "http://example.com/api"
    findings = await checker.scan_url(url)
    
    assert len(findings) > 0
    assert any(f.finding_type == "cors_dangerous_methods" for f in findings)


@pytest.mark.asyncio
async def test_secure_cors_no_findings(mock_client, checker):
    """Test that secure CORS configuration produces no findings."""
    # Mock GET response with secure CORS
    get_response = MagicMock()
    get_response.headers = httpx.Headers({
        'Access-Control-Allow-Origin': 'https://trusted-site.com',
    })
    
    # Mock OPTIONS response
    options_response = MagicMock()
    options_response.headers = httpx.Headers({
        'Access-Control-Allow-Methods': 'GET, POST',
        'Access-Control-Allow-Headers': 'Content-Type',
    })
    
    mock_client.get = AsyncMock(return_value=get_response)
    mock_client.options = AsyncMock(return_value=options_response)
    
    url = "http://example.com/api"
    findings = await checker.scan_url(url)
    
    # Should not find critical issues with secure config
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 0
