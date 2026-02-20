"""
Security headers analyzer for checking HTTP security headers.
"""

from typing import Dict, List, Optional, Any

import httpx

from ..models import Finding, Severity, Confidence


class SecurityHeadersAnalyzer:
    """Analyzer for HTTP security headers."""
    
    # Security headers and their recommended values
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'recommended': True,
            'description': 'HTTP Strict Transport Security (HSTS)',
            'recommendation': 'max-age=31536000; includeSubDomains; preload',
            'missing_severity': Severity.HIGH,
        },
        'Content-Security-Policy': {
            'recommended': True,
            'description': 'Content Security Policy',
            'recommendation': 'default-src \'self\'; script-src \'self\'; object-src \'none\'',
            'missing_severity': Severity.MEDIUM,
        },
        'X-Content-Type-Options': {
            'recommended': True,
            'description': 'Prevents MIME type sniffing',
            'recommendation': 'nosniff',
            'missing_severity': Severity.MEDIUM,
        },
        'X-Frame-Options': {
            'recommended': True,
            'description': 'Clickjacking protection',
            'recommendation': 'DENY or SAMEORIGIN',
            'missing_severity': Severity.MEDIUM,
        },
        'X-XSS-Protection': {
            'recommended': False,  # Deprecated but still checked
            'description': 'Legacy XSS filter (deprecated)',
            'recommendation': '0 (disabled to avoid bypasses)',
            'missing_severity': Severity.LOW,
        },
        'Referrer-Policy': {
            'recommended': True,
            'description': 'Controls referrer information',
            'recommendation': 'strict-origin-when-cross-origin or no-referrer',
            'missing_severity': Severity.LOW,
        },
        'Permissions-Policy': {
            'recommended': True,
            'description': 'Feature Policy for browser APIs',
            'recommendation': 'camera=(), microphone=(), geolocation=()',
            'missing_severity': Severity.LOW,
        },
        'Cross-Origin-Embedder-Policy': {
            'recommended': True,
            'description': 'Cross-Origin Embedder Policy',
            'recommendation': 'require-corp',
            'missing_severity': Severity.LOW,
        },
        'Cross-Origin-Opener-Policy': {
            'recommended': True,
            'description': 'Cross-Origin Opener Policy',
            'recommendation': 'same-origin',
            'missing_severity': Severity.LOW,
        },
        'Cross-Origin-Resource-Policy': {
            'recommended': True,
            'description': 'Cross-Origin Resource Policy',
            'recommendation': 'same-origin',
            'missing_severity': Severity.LOW,
        },
    }
    
    # Headers that should NOT be present (information disclosure)
    SENSITIVE_HEADERS = {
        'Server': Severity.LOW,
        'X-Powered-By': Severity.LOW,
        'X-AspNet-Version': Severity.LOW,
        'X-AspNetMvc-Version': Severity.LOW,
    }
    
    # Cookies that should have security flags
    COOKIE_FLAGS = ['Secure', 'HttpOnly', 'SameSite']
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    def _get_header(self, headers: httpx.Headers, name: str) -> Optional[str]:
        """Get header value case-insensitively."""
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return None
    
    def _check_hsts(self, value: Optional[str]) -> Optional[Finding]:
        """Check HSTS header configuration."""
        if not value:
            return Finding(
                title="Missing Security Header: HSTS",
                description="HTTP Strict Transport Security (HSTS) header is missing. "
                           "This allows the site to be accessed over insecure HTTP connections, "
                           "making it vulnerable to SSL stripping attacks.",
                severity=Severity.HIGH,
                confidence=Confidence.CERTAIN,
                target="HTTP Headers",
                finding_type="missing_hsts",
                evidence="Strict-Transport-Security header not present",
                remediation="Add the Strict-Transport-Security header with a long max-age. "
                           "Example: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                    "https://hstspreload.org/",
                ],
            )
        
        issues = []
        
        if 'max-age' not in value.lower():
            issues.append("Missing max-age directive")
        else:
            # Extract max-age value
            import re
            match = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
            if match:
                max_age = int(match.group(1))
                if max_age < 31536000:  # Less than 1 year
                    issues.append(f"max-age too short ({max_age} seconds, recommend 31536000)")
        
        if 'includesubdomains' not in value.lower():
            issues.append("Missing includeSubDomains directive")
        
        if issues:
            return Finding(
                title="Weak HSTS Configuration",
                description=f"HSTS header is present but has configuration issues: {'; '.join(issues)}",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                target="HTTP Headers",
                finding_type="weak_hsts",
                evidence=f"HSTS value: {value}",
                remediation="Configure HSTS with: max-age=31536000; includeSubDomains; preload",
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                ],
            )
        
        return None
    
    def _check_csp(self, value: Optional[str]) -> Optional[Finding]:
        """Check Content Security Policy header."""
        if not value:
            return Finding(
                title="Missing Security Header: Content-Security-Policy",
                description="Content Security Policy (CSP) header is missing. "
                           "CSP helps prevent XSS attacks by controlling which resources "
                           "the browser is allowed to load.",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                target="HTTP Headers",
                finding_type="missing_csp",
                evidence="Content-Security-Policy header not present",
                remediation="Implement a strict CSP header. Start with: "
                           "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    "https://csp-evaluator.withgoogle.com/",
                ],
            )
        
        issues = []
        dangerous_directives = ["unsafe-inline", "unsafe-eval", "*"]
        
        for directive in dangerous_directives:
            if directive in value:
                issues.append(f"Contains dangerous directive: {directive}")
        
        if 'default-src' not in value:
            issues.append("Missing default-src directive")
        
        if issues:
            return Finding(
                title="Weak Content Security Policy",
                description=f"CSP header has security issues: {'; '.join(issues)}",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                target="HTTP Headers",
                finding_type="weak_csp",
                evidence=f"CSP value: {value[:100]}...",
                remediation="Remove 'unsafe-inline' and 'unsafe-eval' where possible. "
                           "Avoid using wildcard (*) sources. "
                           "Use nonces or hashes for inline scripts.",
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    "https://csp-evaluator.withgoogle.com/",
                ],
            )
        
        return None
    
    def _check_frame_options(self, value: Optional[str]) -> Optional[Finding]:
        """Check X-Frame-Options header."""
        if not value:
            return Finding(
                title="Missing Security Header: X-Frame-Options",
                description="X-Frame-Options header is missing. "
                           "This allows the site to be embedded in iframes, "
                           "making it vulnerable to clickjacking attacks.",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                target="HTTP Headers",
                finding_type="missing_frame_options",
                evidence="X-Frame-Options header not present",
                remediation="Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN. "
                           "Alternatively, use CSP frame-ancestors directive.",
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                ],
            )
        
        valid_values = ['deny', 'sameorigin', 'allow-from']
        if value.lower() not in valid_values and not value.lower().startswith('allow-from'):
            return Finding(
                title="Invalid X-Frame-Options Value",
                description=f"X-Frame-Options has an invalid or unsafe value: {value}",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                target="HTTP Headers",
                finding_type="invalid_frame_options",
                evidence=f"X-Frame-Options: {value}",
                remediation="Use X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                ],
            )
        
        return None
    
    def _check_content_type_options(self, value: Optional[str]) -> Optional[Finding]:
        """Check X-Content-Type-Options header."""
        if not value:
            return Finding(
                title="Missing Security Header: X-Content-Type-Options",
                description="X-Content-Type-Options header is missing. "
                           "This allows browsers to MIME-sniff responses, "
                           "potentially leading to XSS attacks.",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                target="HTTP Headers",
                finding_type="missing_content_type_options",
                evidence="X-Content-Type-Options header not present",
                remediation="Add X-Content-Type-Options: nosniff",
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
                ],
            )
        
        if value.lower() != 'nosniff':
            return Finding(
                title="Invalid X-Content-Type-Options Value",
                description=f"X-Content-Type-Options has invalid value: {value}",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                target="HTTP Headers",
                finding_type="invalid_content_type_options",
                evidence=f"X-Content-Type-Options: {value}",
                remediation="Use X-Content-Type-Options: nosniff",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
                ],
            )
        
        return None
    
    def _check_referrer_policy(self, value: Optional[str]) -> Optional[Finding]:
        """Check Referrer-Policy header."""
        if not value:
            return Finding(
                title="Missing Security Header: Referrer-Policy",
                description="Referrer-Policy header is missing. "
                           "This may leak sensitive information in the Referer header "
                           "when navigating to external sites.",
                severity=Severity.LOW,
                confidence=Confidence.CERTAIN,
                target="HTTP Headers",
                finding_type="missing_referrer_policy",
                evidence="Referrer-Policy header not present",
                remediation="Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                ],
            )
        
        # Check for unsafe values
        unsafe_values = ['unsafe-url', 'origin-when-cross-origin']
        if any(uv in value.lower() for uv in unsafe_values):
            return Finding(
                title="Weak Referrer-Policy",
                description=f"Referrer-Policy may leak sensitive information: {value}",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                target="HTTP Headers",
                finding_type="weak_referrer_policy",
                evidence=f"Referrer-Policy: {value}",
                remediation="Use Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                ],
            )
        
        return None
    
    def _check_permissions_policy(self, value: Optional[str]) -> Optional[Finding]:
        """Check Permissions-Policy header."""
        if not value:
            return Finding(
                title="Missing Security Header: Permissions-Policy",
                description="Permissions-Policy (Feature-Policy) header is missing. "
                           "This allows websites to use powerful browser features "
                           "without explicit permission.",
                severity=Severity.LOW,
                confidence=Confidence.CERTAIN,
                target="HTTP Headers",
                finding_type="missing_permissions_policy",
                evidence="Permissions-Policy header not present",
                remediation="Add Permissions-Policy to restrict access to browser features. "
                           "Example: Permissions-Policy: camera=(), microphone=(), geolocation=()",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                ],
            )
        
        return None
    
    def _check_sensitive_headers(self, headers: httpx.Headers) -> List[Finding]:
        """Check for headers that disclose sensitive information."""
        findings = []
        
        for header_name, severity in self.SENSITIVE_HEADERS.items():
            value = self._get_header(headers, header_name)
            if value:
                findings.append(Finding(
                    title=f"Information Disclosure: {header_name}",
                    description=f"The {header_name} header discloses technology information "
                               f"that could aid attackers in targeting specific vulnerabilities.",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    target="HTTP Headers",
                    finding_type=f"info_disclosure_{header_name.lower().replace('-', '_')}",
                    evidence=f"{header_name}: {value}",
                    remediation=f"Remove the {header_name} header or configure the server "
                               f"to not expose version information.",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                    ],
                ))
        
        return findings
    
    def _check_cookies(self, response: httpx.Response) -> List[Finding]:
        """Check cookie security flags."""
        findings = []
        
        for cookie in response.cookies.jar:
            cookie_name = cookie.name if hasattr(cookie, 'name') else str(cookie)
            
            # Check Secure flag
            if hasattr(cookie, 'secure') and not cookie.secure:
                findings.append(Finding(
                    title=f"Insecure Cookie: {cookie_name} (Missing Secure Flag)",
                    description=f"Cookie '{cookie_name}' is missing the Secure flag. "
                               f"It may be transmitted over unencrypted HTTP connections.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    target="HTTP Cookies",
                    finding_type="insecure_cookie_missing_secure",
                    evidence=f"Cookie: {cookie_name}",
                    remediation="Set the Secure flag on all cookies to ensure they are only "
                               "transmitted over HTTPS.",
                    references=[
                        "https://owasp.org/www-community/controls/SecureCookieAttribute",
                    ],
                ))
            
            # Check HttpOnly flag
            if hasattr(cookie, 'has_nonstandard_attr'):
                if not cookie.has_nonstandard_attr('HttpOnly') and not getattr(cookie, 'httponly', False):
                    findings.append(Finding(
                        title=f"Insecure Cookie: {cookie_name} (Missing HttpOnly Flag)",
                        description=f"Cookie '{cookie_name}' is missing the HttpOnly flag. "
                                   f"It may be accessible to JavaScript, making it vulnerable to XSS theft.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        target="HTTP Cookies",
                        finding_type="insecure_cookie_missing_httponly",
                        evidence=f"Cookie: {cookie_name}",
                        remediation="Set the HttpOnly flag on session cookies and other sensitive cookies "
                                   "to prevent JavaScript access.",
                        references=[
                            "https://owasp.org/www-community/HttpOnly",
                        ],
                    ))
            
            # Check SameSite attribute
            if hasattr(cookie, 'get_nonstandard_attr'):
                samesite = cookie.get_nonstandard_attr('SameSite')
                if not samesite:
                    findings.append(Finding(
                        title=f"Insecure Cookie: {cookie_name} (Missing SameSite)",
                        description=f"Cookie '{cookie_name}' is missing the SameSite attribute. "
                                   f"It may be vulnerable to CSRF attacks.",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        target="HTTP Cookies",
                        finding_type="insecure_cookie_missing_samesite",
                        evidence=f"Cookie: {cookie_name}",
                        remediation="Set SameSite=Strict or SameSite=Lax on cookies to prevent CSRF attacks. "
                                   "Use SameSite=None only for cross-domain scenarios with Secure flag.",
                        references=[
                            "https://owasp.org/www-community/SameSite",
                        ],
                    ))
        
        return findings
    
    async def scan_url(self, url: str) -> List[Finding]:
        """Scan a URL for security header issues."""
        findings = []
        
        try:
            response = await self.client.get(url, follow_redirects=True)
            headers = response.headers
            
            # Check HSTS
            hsts = self._get_header(headers, 'Strict-Transport-Security')
            finding = self._check_hsts(hsts)
            if finding:
                findings.append(finding)
            
            # Check CSP
            csp = self._get_header(headers, 'Content-Security-Policy')
            finding = self._check_csp(csp)
            if finding:
                findings.append(finding)
            
            # Check X-Frame-Options
            frame_options = self._get_header(headers, 'X-Frame-Options')
            finding = self._check_frame_options(frame_options)
            if finding:
                findings.append(finding)
            
            # Check X-Content-Type-Options
            content_type_options = self._get_header(headers, 'X-Content-Type-Options')
            finding = self._check_content_type_options(content_type_options)
            if finding:
                findings.append(finding)
            
            # Check Referrer-Policy
            referrer_policy = self._get_header(headers, 'Referrer-Policy')
            finding = self._check_referrer_policy(referrer_policy)
            if finding:
                findings.append(finding)
            
            # Check Permissions-Policy
            permissions_policy = self._get_header(headers, 'Permissions-Policy')
            finding = self._check_permissions_policy(permissions_policy)
            if finding:
                findings.append(finding)
            
            # Check for information disclosure headers
            disclosure_findings = self._check_sensitive_headers(headers)
            findings.extend(disclosure_findings)
            
            # Check cookies
            cookie_findings = self._check_cookies(response)
            findings.extend(cookie_findings)
            
        except Exception as e:
            print(f"Error analyzing security headers for {url}: {e}")
        
        return findings
    
    async def get_headers_summary(self, url: str) -> Dict[str, Any]:
        """Get a summary of all security headers."""
        summary = {
            'present': {},
            'missing': [],
            'cookies': [],
        }
        
        try:
            response = await self.client.get(url, follow_redirects=True)
            headers = response.headers
            
            for header_name in self.SECURITY_HEADERS.keys():
                value = self._get_header(headers, header_name)
                if value:
                    summary['present'][header_name] = value
                elif self.SECURITY_HEADERS[header_name]['recommended']:
                    summary['missing'].append(header_name)
            
            # Add cookies info
            for cookie in response.cookies.jar:
                cookie_info = {
                    'name': cookie.name if hasattr(cookie, 'name') else str(cookie),
                    'secure': getattr(cookie, 'secure', False),
                    'httponly': getattr(cookie, 'httponly', False),
                }
                if hasattr(cookie, 'get_nonstandard_attr'):
                    cookie_info['samesite'] = cookie.get_nonstandard_attr('SameSite')
                summary['cookies'].append(cookie_info)
                
        except Exception as e:
            summary['error'] = str(e)
        
        return summary
