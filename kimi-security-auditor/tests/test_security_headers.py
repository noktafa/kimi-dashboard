"""
Tests for Security Headers analyzer.
"""

import pytest
import httpx
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from kimi_security_auditor.attacks.security_headers import SecurityHeadersAnalyzer
from kimi_security_auditor.models import Finding, Severity, Confidence


@pytest.fixture
def mock_client():
    """Create a mock HTTP client."""
    client = MagicMock(spec=httpx.AsyncClient)
    return client


@pytest.fixture
def analyzer(mock_client):
    """Create a security headers analyzer instance."""
    return SecurityHeadersAnalyzer(mock_client)


@pytest.mark.asyncio
async def test_missing_hsts(mock_client, analyzer):
    """Test detection of missing HSTS header."""
    response = MagicMock()
    response.headers = httpx.Headers({})
    response.cookies.jar = []
    
    mock_client.get = AsyncMock(return_value=response)
    
    url = "http://example.com"
    findings = await analyzer.scan_url(url)
    
    hsts_findings = [f for f in findings if f.finding_type == "missing_hsts"]
    assert len(hsts_findings) > 0
    assert hsts_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_weak_hsts(mock_client, analyzer):
    """Test detection of weak HSTS configuration."""
    response = MagicMock()
    response.headers = httpx.Headers({
        'Strict-Transport-Security': 'max-age=3600',  # Too short
    })
    response.cookies.jar = []
    
    mock_client.get = AsyncMock(return_value=response)
    
    url = "http://example.com"
    findings = await analyzer.scan_url(url)
    
    hsts_findings = [f for f in findings if f.finding_type == "weak_hsts"]
    assert len(hsts_findings) > 0
    assert hsts_findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_missing_csp(mock_client, analyzer):
    """Test detection of missing CSP header."""
    response = MagicMock()
    response.headers = httpx.Headers({})
    response.cookies.jar = []
    
    mock_client.get = AsyncMock(return_value=response)
    
    url = "http://example.com"
    findings = await analyzer.scan_url(url)
    
    csp_findings = [f for f in findings if f.finding_type == "missing_csp"]
    assert len(csp_findings) > 0
    assert csp_findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_weak_csp(mock_client, analyzer):
    """Test detection of weak CSP configuration."""
    response = MagicMock()
    response.headers = httpx.Headers({
        'Content-Security-Policy': "default-src * 'unsafe-inline' 'unsafe-eval'",
    })
    response.cookies.jar = []
    
    mock_client.get = AsyncMock(return_value=response)
    
    url = "http://example.com"
    findings = await analyzer.scan_url(url)
    
    csp_findings = [f for f in findings if f.finding_type == "weak_csp"]
    assert len(csp_findings) > 0
    assert csp_findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_missing_frame_options(mock_client, analyzer):
    """Test detection of missing X-Frame-Options."""
    response = MagicMock()
    response.headers = httpx.Headers({})
    response.cookies.jar = []
    
    mock_client.get = AsyncMock(return_value=response)
    
    url = "http://example.com"
    findings = await analyzer.scan_url(url)
    
    frame_findings = [f for f in findings if f.finding_type == "missing_frame_options"]
    assert len(frame_findings) > 0


@pytest.mark.asyncio
async def test_missing_content_type_options(mock_client, analyzer):
    """Test detection of missing X-Content-Type-Options."""
    response = MagicMock()
    response.headers = httpx.Headers({})
    response.cookies.jar = []
    
    mock_client.get = AsyncMock(return_value=response)
    
    url = "http://example.com"
    findings = await analyzer.scan_url(url)
    
    ct_findings = [f for f in findings if f.finding_type == "missing_content_type_options"]
    assert len(ct_findings) > 0


@pytest.mark.asyncio
async def test_information_disclosure_headers(mock_client, analyzer):
    """Test detection of information disclosure headers."""
    response = MagicMock()
    response.headers = httpx.Headers({
        'Server': 'Apache/2.4.41',
        'X-Powered-By': 'PHP/7.4.3',
    })
    response.cookies.jar = []
    
    mock_client.get = AsyncMock(return_value=response)
    
    url = "http://example.com"
    findings = await analyzer.scan_url(url)
    
    disclosure_findings = [f for f in findings if 'info_disclosure' in f.finding_type]
    assert len(disclosure_findings) >= 2


@pytest.mark.asyncio
async def test_secure_headers_no_findings(mock_client, analyzer):
    """Test that secure headers produce minimal findings."""
    response = MagicMock()
    response.headers = httpx.Headers({
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=()',
    })
    response.cookies.jar = []
    
    mock_client.get = AsyncMock(return_value=response)
    
    url = "http://example.com"
    findings = await analyzer.scan_url(url)
    
    # Should have no critical or high findings with secure headers
    high_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(high_findings) == 0
