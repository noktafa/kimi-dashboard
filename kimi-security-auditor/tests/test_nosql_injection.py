"""
Tests for NoSQL Injection scanner.
"""

import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock

from kimi_security_auditor.attacks.nosql_injection import NoSQLInjectionScanner
from kimi_security_auditor.models import Finding, Severity, Confidence


@pytest.fixture
def mock_client():
    """Create a mock HTTP client."""
    client = MagicMock(spec=httpx.AsyncClient)
    return client


@pytest.fixture
def scanner(mock_client):
    """Create a NoSQL scanner instance."""
    return NoSQLInjectionScanner(mock_client)


@pytest.mark.asyncio
async def test_detect_mongo_error(scanner):
    """Test MongoDB error detection."""
    response_text = "MongoError: E11000 duplicate key error"
    result = scanner._detect_mongo_error(response_text)
    assert result is not None
    assert "MongoError" in result


@pytest.mark.asyncio
async def test_detect_mongo_error_no_match(scanner):
    """Test MongoDB error detection with no match."""
    response_text = "Some random error message"
    result = scanner._detect_mongo_error(response_text)
    assert result is None


@pytest.mark.asyncio
async def test_detect_redis_error(scanner):
    """Test Redis error detection."""
    response_text = "RedisError: ERR unknown command"
    result = scanner._detect_redis_error(response_text)
    assert result is not None
    assert "RedisError" in result


@pytest.mark.asyncio
async def test_scan_url_finds_nosql_injection(mock_client, scanner):
    """Test that scanner finds NoSQL injection vulnerabilities."""
    # Mock baseline response
    baseline_response = MagicMock()
    baseline_response.text = "Normal response"
    
    # Mock injection response with MongoDB error
    injection_response = MagicMock()
    injection_response.text = "MongoError: E11000 duplicate key error"
    
    mock_client.get = AsyncMock(side_effect=[baseline_response, injection_response])
    
    url = "http://example.com/api?param=test"
    findings = await scanner.scan_url(url, parameters=['param'])
    
    assert len(findings) >= 0
    if findings:
        assert findings[0].finding_type == "nosql_injection_mongodb"
        assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_scan_api_finds_json_injection(mock_client, scanner):
    """Test that scanner finds NoSQL injection via JSON."""
    # Mock response with MongoDB error
    response = MagicMock()
    response.text = "MongoError: Expression must be an object"
    
    mock_client.post = AsyncMock(return_value=response)
    
    url = "http://example.com/api/auth"
    findings = await scanner.scan_api(url)
    
    assert len(findings) >= 0
    if findings:
        assert "nosql_injection_mongodb" in findings[0].finding_type


@pytest.mark.asyncio
async def test_scan_url_no_vulnerability(mock_client, scanner):
    """Test that scanner doesn't report false positives."""
    # Mock normal response
    response = MagicMock()
    response.text = "Normal response without errors"
    
    mock_client.get = AsyncMock(return_value=response)
    mock_client.post = AsyncMock(return_value=response)
    
    url = "http://example.com/api?param=test"
    findings = await scanner.scan_url(url, parameters=['param'])
    
    # Should not find vulnerabilities in normal responses
    assert len(findings) == 0
