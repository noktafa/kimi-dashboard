"""
File upload vulnerability scanner for detecting insecure file upload functionality.
"""

import re
from typing import Dict, List, Optional, Tuple

import httpx

from ..models import Finding, Severity, Confidence


class FileUploadScanner:
    """Scanner for file upload vulnerabilities."""
    
    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = [
        # Web shells
        '.php', '.php3', '.php4', '.php5', '.phtml', '.phar',
        '.asp', '.aspx', '.ascx', '.ashx', '.asmx',
        '.jsp', '.jspx', '.jsw', '.jsv', '.jspf',
        '.cfm', '.cfml', '.cfc',
        '.rb', '.rhtml',
        '.py', '.pyc', '.pyo',
        '.pl', '.cgi',
        '.sh', '.bash', '.zsh',
        '.cmd', '.bat', '.com',
        '.exe', '.dll', '.scr',
        # Config files
        '.htaccess', '.htpasswd',
        '.config', '.conf',
        '.ini', '.env',
        '.yaml', '.yml',
        '.json', '.xml',
        # Scripts
        '.js', '.vbs', '.wsf',
        '.ps1', '.psm1', '.psd1',
        # Other dangerous
        '.war', '.ear',
        '.jar',
        '.swf',
    ]
    
    # Double extension patterns
    DOUBLE_EXTENSIONS = [
        '.php.jpg', '.php.png', '.php.gif',
        '.asp.jpg', '.aspx.jpg',
        '.jsp.jpg', '.jsp.png',
        '.phtml.jpg', '.phtml.png',
    ]
    
    # Null byte variants
    NULL_BYTE_EXTENSIONS = [
        '.php%00.jpg',
        '.asp%00.jpg',
        '.jsp%00.jpg',
    ]
    
    # MIME type bypass payloads
    MIME_BYPASS_PAYLOADS = [
        ('shell.php', 'image/jpeg', b'GIF89a\x00\x3c?php echo "shell"; ?\x3e'),
        ('shell.jpg.php', 'image/jpeg', b'\x3c?php echo "shell"; ?\x3e'),
        ('shell.php.jpg', 'application/x-php', b'\x3c?php echo "shell"; ?\x3e'),
        ('.htaccess', 'text/plain', b'AddType application/x-httpd-php .jpg'),
        ('shell.phtml', 'image/jpeg', b'\x3c?php echo "shell"; ?\x3e'),
        ('shell.php5', 'image/jpeg', b'\x3c?php echo "shell"; ?\x3e'),
        ('shell.jsp', 'image/jpeg', b'\x3c% out.println("shell"); %\x3e'),
        ('shell.asp', 'image/jpeg', b'\x3c% Response.Write("shell") %\x3e'),
        ('shell.aspx', 'image/jpeg', b'\x3c%@ Page Language="C#" %\x3e\x3c% Response.Write("shell"); %\x3e'),
    ]
    
    # Magic bytes for common file types
    MAGIC_BYTES = {
        'jpeg': (b'\xff\xd8\xff', 'image/jpeg'),
        'png': (b'\x89PNG\r\n\x1a\n', 'image/png'),
        'gif': (b'GIF89a', 'image/gif'),
        'pdf': (b'%PDF', 'application/pdf'),
    }
    
    # Indicators of successful upload
    SUCCESS_INDICATORS = [
        'upload successful',
        'file uploaded',
        'upload complete',
        'successfully uploaded',
        'file saved',
        'upload ok',
    ]
    
    # Indicators of file execution
    EXECUTION_INDICATORS = [
        'shell',
        'phpinfo',
        'eval',
        'system',
    ]
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    def _is_dangerous_extension(self, filename: str) -> bool:
        """Check if file has a dangerous extension."""
        filename_lower = filename.lower()
        for ext in self.DANGEROUS_EXTENSIONS:
            if filename_lower.endswith(ext):
                return True
        return False
    
    def _check_success_indicators(self, response_text: str) -> Optional[str]:
        """Check for upload success indicators in response."""
        for indicator in self.SUCCESS_INDICATORS:
            if indicator in response_text.lower():
                return indicator
        return None
    
    async def _test_extension_validation(self, url: str, 
                                          file_param: str = "file") -> List[Finding]:
        """Test if server properly validates file extensions."""
        findings = []
        
        # Test with dangerous extensions
        for ext in ['.php', '.asp', '.jsp', '.py', '.rb', '.sh']:
            test_filename = f'test{ext}'
            
            try:
                files = {
                    file_param: (test_filename, b'\x3c?php echo "test"; ?\x3e', 'application/octet-stream')
                }
                
                response = await self.client.post(url, files=files, follow_redirects=True)
                
                success = self._check_success_indicators(response.text)
                if success:
                    findings.append(Finding(
                        title=f"Dangerous File Upload Allowed ({ext})",
                        description=f"The server accepts uploads with dangerous extension '{ext}'. "
                                   f"This may allow attackers to upload executable code.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="file_upload_dangerous_extension",
                        evidence=f"Server accepted file with extension: {ext}",
                        remediation="Implement strict extension allowlisting. "
                                   f"Block dangerous extensions like {', '.join(self.DANGEROUS_EXTENSIONS[:10])}. "
                                   "Validate extensions on the server side, not just client side.",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                            "https://portswigger.net/web-security/file-upload",
                        ],
                        payload=test_filename,
                    ))
                    
            except Exception:
                continue
        
        return findings
    
    async def _test_mime_type_bypass(self, url: str,
                                      file_param: str = "file") -> List[Finding]:
        """Test MIME type validation bypasses."""
        findings = []
        
        for filename, content_type, content in self.MIME_BYPASS_PAYLOADS:
            try:
                files = {
                    file_param: (filename, content, content_type)
                }
                
                response = await self.client.post(url, files=files, follow_redirects=True)
                
                success = self._check_success_indicators(response.text)
                if success:
                    findings.append(Finding(
                        title="File Upload MIME Type Bypass",
                        description=f"The server accepted file '{filename}' with content-type '{content_type}'. "
                                   f"MIME type validation may be insufficient or bypassable.",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="file_upload_mime_bypass",
                        evidence=f"Accepted: {filename} as {content_type}",
                        remediation="Validate file extensions independently of MIME types. "
                                   "Check file content/magic bytes server-side. "
                                   "Store uploaded files outside web root or use proper content-type headers.",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                            "https://portswigger.net/web-security/file-upload",
                        ],
                        payload=filename,
                    ))
                    
            except Exception:
                continue
        
        return findings
    
    async def _test_double_extension(self, url: str,
                                      file_param: str = "file") -> List[Finding]:
        """Test double extension bypasses."""
        findings = []
        
        for ext in self.DOUBLE_EXTENSIONS:
            filename = f'test{ext}'
            
            try:
                files = {
                    file_param: (filename, b'\x3c?php echo "test"; ?\x3e', 'image/jpeg')
                }
                
                response = await self.client.post(url, files=files, follow_redirects=True)
                
                success = self._check_success_indicators(response.text)
                if success:
                    findings.append(Finding(
                        title="File Upload Double Extension Bypass",
                        description=f"The server accepted file with double extension '{ext}'. "
                                   f"The server may incorrectly parse the extension, allowing code execution.",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="file_upload_double_extension",
                        evidence=f"Accepted file: {filename}",
                        remediation="Use proper extension extraction (get the last extension only). "
                                   "Validate against a strict allowlist of safe extensions. "
                                   "Consider using a library for secure file handling.",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                        ],
                        payload=filename,
                    ))
                    
            except Exception:
                continue
        
        return findings
    
    async def _test_magic_bytes_validation(self, url: str,
                                            file_param: str = "file") -> List[Finding]:
        """Test if server validates file magic bytes."""
        findings = []
        
        # Create PHP file with JPEG magic bytes
        for file_type, (magic, mime) in self.MAGIC_BYTES.items():
            content = magic + b'\x00' * 100 + b'\x3c?php echo "shell"; ?\x3e'
            filename = f'shell.{file_type}.php'
            
            try:
                files = {
                    file_param: (filename, content, mime)
                }
                
                response = await self.client.post(url, files=files, follow_redirects=True)
                
                success = self._check_success_indicators(response.text)
                if success:
                    findings.append(Finding(
                        title="File Upload Magic Bytes Bypass",
                        description=f"The server accepted PHP code disguised as {file_type}. "
                                   f"The server validates magic bytes but doesn't properly validate content.",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="file_upload_magic_bytes_bypass",
                        evidence=f"Accepted file: {filename} with {file_type} magic bytes",
                        remediation="Validate both magic bytes AND file extension. "
                                   "Use a proper file type detection library. "
                                   "Consider converting/re-encoding uploaded images.",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                        ],
                        payload=filename,
                    ))
                    
            except Exception:
                continue
        
        return findings
    
    async def _test_size_limits(self, url: str,
                                 file_param: str = "file") -> List[Finding]:
        """Test for size limit issues."""
        findings = []
        
        # Test with very large file
        large_content = b'A' * (10 * 1024 * 1024)  # 10MB
        
        try:
            files = {
                file_param: ('large.jpg', large_content, 'image/jpeg')
            }
            
            response = await self.client.post(url, files=files, follow_redirects=True, timeout=30.0)
            
            # If accepted without error, might indicate missing size limits
            if response.status_code == 200:
                findings.append(Finding(
                    title="File Upload Size Limit Not Enforced",
                    description="The server accepted a very large file (10MB+). "
                               "Missing size limits could lead to DoS attacks via disk space exhaustion.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    target=url,
                    finding_type="file_upload_no_size_limit",
                    evidence="Server accepted 10MB+ file",
                    remediation="Implement strict file size limits. "
                               "Validate size on server side before processing. "
                               "Configure web server upload limits.",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                    ],
                ))
                
        except httpx.TimeoutException:
            # Timeout might indicate processing large file
            findings.append(Finding(
                title="File Upload Size Limit - Possible DoS",
                description="Large file upload caused timeout. "
                           "The server may be vulnerable to DoS via large file uploads.",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                target=url,
                finding_type="file_upload_dos_possible",
                evidence="Timeout when uploading large file",
                remediation="Implement strict file size limits and timeouts. "
                           "Use streaming uploads with size checks.",
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                ],
            ))
        except Exception:
            pass
        
        return findings
    
    async def _test_path_traversal_in_filename(self, url: str,
                                                file_param: str = "file") -> List[Finding]:
        """Test for path traversal in filename."""
        findings = []
        
        traversal_filenames = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '../../../shell.php',
            '..\\..\\..\\shell.asp',
        ]
        
        for filename in traversal_filenames:
            try:
                files = {
                    file_param: (filename, b'test content', 'text/plain')
                }
                
                response = await self.client.post(url, files=files, follow_redirects=True)
                
                # Check for file content disclosure or successful upload
                if 'root:x:0:0:' in response.text or 'for 16-bit app support' in response.text:
                    findings.append(Finding(
                        title="File Upload Path Traversal",
                        description="The server is vulnerable to path traversal in filename. "
                                   "Attackers can write files to arbitrary locations.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="file_upload_path_traversal",
                        evidence=f"Path traversal in filename: {filename}",
                        remediation="Sanitize filenames by removing path components. "
                                   "Use basename() or equivalent to extract only the filename. "
                                   "Validate filenames against a strict pattern.",
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://portswigger.net/web-security/file-upload",
                        ],
                        payload=filename,
                    ))
                    break
                    
            except Exception:
                continue
        
        return findings
    
    async def scan_upload_endpoint(self, url: str, 
                                    file_param: str = "file") -> List[Finding]:
        """Scan a file upload endpoint for vulnerabilities."""
        findings = []
        
        # Test dangerous extensions
        ext_findings = await self._test_extension_validation(url, file_param)
        findings.extend(ext_findings)
        
        # Test MIME type bypass
        mime_findings = await self._test_mime_type_bypass(url, file_param)
        findings.extend(mime_findings)
        
        # Test double extensions
        double_findings = await self._test_double_extension(url, file_param)
        findings.extend(double_findings)
        
        # Test magic bytes bypass
        magic_findings = await self._test_magic_bytes_validation(url, file_param)
        findings.extend(magic_findings)
        
        # Test size limits
        size_findings = await self._test_size_limits(url, file_param)
        findings.extend(size_findings)
        
        # Test path traversal
        path_findings = await self._test_path_traversal_in_filename(url, file_param)
        findings.extend(path_findings)
        
        return findings
    
    async def detect_upload_endpoints(self, url: str) -> List[str]:
        """Detect potential file upload endpoints on a page."""
        upload_indicators = []
        
        try:
            response = await self.client.get(url, follow_redirects=True)
            text = response.text.lower()
            
            # Look for upload-related patterns
            patterns = [
                r'input[^>]*type=["\']?file["\']?',
                r'enctype=["\']?multipart/form-data["\']?',
                r'upload',
                r'fileupload',
                r'choose file',
                r'select file',
                r'browse',
                r'attach',
                r'attachment',
            ]
            
            for pattern in patterns:
                if re.search(pattern, text):
                    upload_indicators.append(pattern)
                    
        except Exception:
            pass
        
        return upload_indicators
