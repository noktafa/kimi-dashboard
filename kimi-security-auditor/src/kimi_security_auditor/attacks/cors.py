"""
CORS (Cross-Origin Resource Sharing) misconfiguration checker.
"""

import re
import urllib.parse
from typing import List, Optional, Dict

import httpx

from ..models import Finding, Severity, Confidence


class CORSChecker:
    """Checker for CORS misconfigurations."""
    
    # Dangerous origins to test
    TEST_ORIGINS = [
        'https://evil.com',
        'http://evil.com',
        'https://attacker.com',
        'http://attacker.com',
        'null',
        'file://',
        'https://' + 'a' * 50 + '.com',  # Long origin
    ]
    
    # Subdomain takeover patterns
    SUBDOMAIN_ORIGINS = [
        'https://subdomain.target.com.evil.com',
        'https://evil.target.com',
    ]
    
    # Common localhost origins
    LOCALHOST_ORIGINS = [
        'http://localhost',
        'https://localhost',
        'http://localhost:8080',
        'http://127.0.0.1',
        'https://127.0.0.1',
        'http://127.0.0.1:8080',
        'http://0.0.0.0',
        'http://[::1]',
    ]
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    def _parse_cors_headers(self, headers: httpx.Headers) -> Dict[str, str]:
        """Parse CORS-related headers from response."""
        cors_headers = {}
        
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower in ('access-control-allow-origin',
                           'access-control-allow-credentials',
                           'access-control-allow-methods',
                           'access-control-allow-headers',
                           'access-control-expose-headers',
                           'access-control-max-age'):
                cors_headers[key_lower] = value
        
        return cors_headers
    
    async def _test_origin_reflection(self, url: str) -> Optional[Finding]:
        """Test if server reflects arbitrary Origin headers."""
        
        test_origin = 'https://evil-cors-test.com'
        
        try:
            response = await self.client.get(
                url,
                headers={'Origin': test_origin},
                follow_redirects=True
            )
            
            cors_headers = self._parse_cors_headers(response.headers)
            allow_origin = cors_headers.get('access-control-allow-origin', '')
            allow_credentials = cors_headers.get('access-control-allow-credentials', '').lower()
            
            # Check for wildcard with credentials (very dangerous)
            if allow_origin == '*' and allow_credentials == 'true':
                return Finding(
                    title="CORS Misconfiguration: Wildcard with Credentials",
                    description="The server allows any origin (*) to make authenticated requests. "
                               "This is a critical security misconfiguration that allows attackers "
                               "to make cross-origin requests with user credentials.",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    target=url,
                    finding_type="cors_wildcard_credentials",
                    evidence=f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                    remediation="Never use wildcard (*) with Access-Control-Allow-Credentials: true. "
                               "Explicitly specify allowed origins. "
                               "Validate the Origin header against a whitelist.",
                    references=[
                        "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                        "https://portswigger.net/web-security/cors",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                    ],
                )
            
            # Check for arbitrary origin reflection
            if allow_origin == test_origin:
                if allow_credentials == 'true':
                    return Finding(
                        title="CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
                        description="The server reflects arbitrary Origin headers and allows credentials. "
                                   "This allows any website to make authenticated cross-origin requests.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CERTAIN,
                        target=url,
                        finding_type="cors_arbitrary_origin_credentials",
                        evidence=f"Access-Control-Allow-Origin: {allow_origin}\nAccess-Control-Allow-Credentials: true",
                        remediation="Validate the Origin header against a strict whitelist. "
                                   "Never reflect arbitrary origins when credentials are allowed. "
                                   "Implement proper CORS origin validation.",
                        references=[
                            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                            "https://portswigger.net/web-security/cors",
                        ],
                    )
                else:
                    return Finding(
                        title="CORS Misconfiguration: Arbitrary Origin Reflection",
                        description="The server reflects arbitrary Origin headers. "
                                   "This allows any website to make cross-origin requests (without credentials).",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="cors_arbitrary_origin",
                        evidence=f"Access-Control-Allow-Origin: {allow_origin}",
                        remediation="Validate the Origin header against a strict whitelist. "
                                   "Only allow specific, trusted origins.",
                        references=[
                            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                            "https://portswigger.net/web-security/cors",
                        ],
                    )
            
            # Check for null origin
            if allow_origin == 'null':
                return Finding(
                    title="CORS Misconfiguration: Null Origin Allowed",
                    description="The server allows 'null' origin. This can be exploited by attackers "
                               "using sandboxed iframes or local HTML files.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    target=url,
                    finding_type="cors_null_origin",
                    evidence="Access-Control-Allow-Origin: null",
                    remediation="Remove 'null' from allowed origins. "
                               "Explicitly specify valid origins instead.",
                    references=[
                        "https://portswigger.net/web-security/cors",
                    ],
                )
                    
        except Exception:
            pass
        
        return None
    
    async def _test_subdomain_trust(self, url: str, target_domain: str) -> Optional[Finding]:
        """Test for overly permissive subdomain trust."""
        
        # Extract base domain
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.netloc
        
        # Test with attacker subdomain
        test_origins = [
            f'https://evil.{hostname}',
            f'https://{hostname}.evil.com',
        ]
        
        for test_origin in test_origins:
            try:
                response = await self.client.get(
                    url,
                    headers={'Origin': test_origin},
                    follow_redirects=True
                )
                
                cors_headers = self._parse_cors_headers(response.headers)
                allow_origin = cors_headers.get('access-control-allow-origin', '')
                
                if allow_origin == test_origin:
                    return Finding(
                        title="CORS Misconfiguration: Overly Permissive Subdomain Trust",
                        description=f"The server allows requests from arbitrary subdomains. "
                                   f"Origin '{test_origin}' was accepted.",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="cors_subdomain_trust",
                        evidence=f"Access-Control-Allow-Origin: {allow_origin}",
                        remediation="Only allow specific, trusted subdomains. "
                                   "Validate the full origin, not just the domain suffix. "
                                   "Use an explicit whitelist of allowed origins.",
                        references=[
                            "https://portswigger.net/web-security/cors",
                        ],
                    )
                    
            except Exception:
                continue
        
        return None
    
    async def _test_localhost_origins(self, url: str) -> Optional[Finding]:
        """Test if localhost origins are allowed."""
        
        allowed_localhosts = []
        
        for origin in self.LOCALHOST_ORIGINS:
            try:
                response = await self.client.get(
                    url,
                    headers={'Origin': origin},
                    follow_redirects=True
                )
                
                cors_headers = self._parse_cors_headers(response.headers)
                allow_origin = cors_headers.get('access-control-allow-origin', '')
                
                if allow_origin == origin:
                    allowed_localhosts.append(origin)
                    
            except Exception:
                continue
        
        if allowed_localhosts:
            return Finding(
                title="CORS Misconfiguration: Localhost Origins Allowed",
                description="The server allows CORS requests from localhost origins. "
                           "This can be exploited if an attacker has local access or "
                           "can run a local web server on the victim's machine.",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                target=url,
                finding_type="cors_localhost_allowed",
                evidence=f"Allowed origins: {', '.join(allowed_localhosts)}",
                remediation="Remove localhost origins from production CORS configuration. "
                           "Use environment-specific CORS settings.",
                references=[
                    "https://portswigger.net/web-security/cors",
                ],
            )
        
        return None
    
    async def _test_preflight(self, url: str) -> List[Finding]:
        """Test CORS preflight handling."""
        findings = []
        
        try:
            # Send OPTIONS request
            response = await self.client.options(
                url,
                headers={
                    'Origin': 'https://evil.com',
                    'Access-Control-Request-Method': 'DELETE',
                    'Access-Control-Request-Headers': 'X-Custom-Header',
                },
                follow_redirects=True
            )
            
            cors_headers = self._parse_cors_headers(response.headers)
            
            # Check if dangerous methods are allowed
            allow_methods = cors_headers.get('access-control-allow-methods', '')
            dangerous_methods = ['DELETE', 'PUT', 'PATCH']
            allowed_dangerous = [m for m in dangerous_methods if m in allow_methods.upper()]
            
            if allowed_dangerous:
                findings.append(Finding(
                    title="CORS: Dangerous HTTP Methods Allowed",
                    description=f"The server allows potentially dangerous HTTP methods via CORS: "
                               f"{', '.join(allowed_dangerous)}. "
                               f"This may allow attackers to modify resources cross-origin.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    target=url,
                    finding_type="cors_dangerous_methods",
                    evidence=f"Access-Control-Allow-Methods: {allow_methods}",
                    remediation="Only allow necessary HTTP methods. "
                               "Avoid allowing DELETE, PUT, or PATCH unless required. "
                               "Validate the Origin header before allowing dangerous methods.",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                    ],
                ))
            
            # Check for overly permissive headers
            allow_headers = cors_headers.get('access-control-allow-headers', '')
            sensitive_headers = ['authorization', 'cookie', 'x-auth-token', 'x-csrf-token']
            allowed_sensitive = [h for h in sensitive_headers if h in allow_headers.lower()]
            
            if allowed_sensitive and cors_headers.get('access-control-allow-origin') == '*':
                findings.append(Finding(
                    title="CORS: Sensitive Headers with Wildcard Origin",
                    description=f"The server allows sensitive headers ({', '.join(allowed_sensitive)}) "
                               f"with wildcard origin. This may expose sensitive information.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    target=url,
                    finding_type="cors_sensitive_headers_wildcard",
                    evidence=f"Access-Control-Allow-Headers: {allow_headers}",
                    remediation="Don't allow sensitive headers with wildcard origins. "
                               "Explicitly specify allowed origins when handling credentials.",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                    ],
                ))
                
        except Exception:
            pass
        
        return findings
    
    async def scan_url(self, url: str) -> List[Finding]:
        """Scan a URL for CORS misconfigurations."""
        findings = []
        
        # Test origin reflection
        finding = await self._test_origin_reflection(url)
        if finding:
            findings.append(finding)
        
        # Test subdomain trust
        finding = await self._test_subdomain_trust(url, '')
        if finding:
            findings.append(finding)
        
        # Test localhost origins
        finding = await self._test_localhost_origins(url)
        if finding:
            findings.append(finding)
        
        # Test preflight
        preflight_findings = await self._test_preflight(url)
        findings.extend(preflight_findings)
        
        return findings
    
    async def scan_api_endpoint(self, url: str) -> List[Finding]:
        """Scan an API endpoint specifically for CORS issues."""
        return await self.scan_url(url)
