"""
Command Injection scanner for detecting OS command injection vulnerabilities.
"""

import re
import urllib.parse
from typing import Dict, List, Optional

import httpx

from ..models import Finding, Severity, Confidence


class CommandInjectionScanner:
    """Scanner for command injection vulnerabilities."""
    
    # Command injection payloads
    PAYLOADS = [
        ";id",
        ";whoami",
        ";uname -a",
        "|id",
        "|whoami",
        "`id`",
        "$(id)",
        ";cat /etc/passwd",
        "|cat /etc/passwd",
        ";dir",
        "|dir",
        "&id",
        "&&id",
        "||id",
        ";echo 'test'",
        "|echo 'test'",
        "`echo test`",
        "$(echo test)",
        ";sleep 5",
        "|sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
    ]
    
    # Indicators of successful command injection
    INDICATORS = {
        'id': [
            r'uid=\d+\(\w+\)\s+gid=\d+',
            r'uid=\d+ gid=\d+',
        ],
        'whoami': [
            r'^[a-zA-Z0-9_\-]+$',
        ],
        'uname': [
            r'Linux\s+\w+',
            r'Darwin\s+\w+',
        ],
        'passwd': [
            r'root:x:0:0:',
            r'bin:x:1:1:',
        ],
        'dir': [
            r'Volume\s+in\s+drive',
            r'Directory\s+of',
        ],
    }
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    def _check_indicators(self, response_text: str, payload: str) -> Optional[str]:
        """Check if response contains command output indicators."""
        for cmd, patterns in self.INDICATORS.items():
            if cmd in payload.lower():
                for pattern in patterns:
                    match = re.search(pattern, response_text, re.MULTILINE)
                    if match:
                        return match.group(0)
        return None
    
    async def scan_url(self, url: str, parameters: Optional[List[str]] = None) -> List[Finding]:
        """Scan a URL for command injection vulnerabilities."""
        findings = []
        
        # Get baseline response
        try:
            baseline_response = await self.client.get(url, follow_redirects=True)
            baseline_text = baseline_response.text
        except Exception:
            baseline_text = ""
        
        # Extract parameters if not provided
        if parameters is None:
            parsed = urllib.parse.urlparse(url)
            parameters = list(urllib.parse.parse_qs(parsed.query).keys())
        
        for param in parameters:
            for payload in self.PAYLOADS:
                try:
                    parsed = urllib.parse.urlparse(url)
                    params = urllib.parse.parse_qs(parsed.query)
                    params[param] = payload
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    
                    response = await self.client.get(test_url, follow_redirects=True)
                    
                    # Check for command output indicators
                    indicator = self._check_indicators(response.text, payload)
                    if indicator and indicator not in baseline_text:
                        findings.append(Finding(
                            title="Command Injection",
                            description=f"Command injection vulnerability detected in parameter '{param}'. "
                                       f"The application executes system commands based on user input.",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            target=url,
                            finding_type="command_injection",
                            evidence=f"Command output detected: {indicator}",
                            remediation="Never pass user input directly to system commands. "
                                       "Use allowlists for permitted values. "
                                       "If necessary, use parameterized APIs or proper escaping.",
                            references=[
                                "https://owasp.org/www-community/attacks/Command_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                            ],
                            parameter=param,
                            payload=payload,
                        ))
                        break  # Found injection for this parameter
                        
                except Exception:
                    continue
        
        return findings
    
    async def scan_form(self, url: str, form_data: Dict[str, str]) -> List[Finding]:
        """Scan a form for command injection vulnerabilities."""
        findings = []
        
        # Get baseline response
        try:
            baseline_response = await self.client.post(url, data={k: "test" for k in form_data.keys()}, follow_redirects=True)
            baseline_text = baseline_response.text
        except Exception:
            baseline_text = ""
        
        for param in form_data.keys():
            for payload in self.PAYLOADS:
                try:
                    test_data = {k: "test" for k in form_data.keys()}
                    test_data[param] = payload
                    
                    response = await self.client.post(url, data=test_data, follow_redirects=True)
                    
                    # Check for command output indicators
                    indicator = self._check_indicators(response.text, payload)
                    if indicator and indicator not in baseline_text:
                        findings.append(Finding(
                            title="Command Injection",
                            description=f"Command injection vulnerability detected in form parameter '{param}'.",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            target=url,
                            finding_type="command_injection",
                            evidence=f"Command output detected: {indicator}",
                            remediation="Never pass user input directly to system commands. "
                                       "Use allowlists for permitted values.",
                            references=[
                                "https://owasp.org/www-community/attacks/Command_Injection",
                            ],
                            parameter=param,
                            payload=payload,
                        ))
                        break
                        
                except Exception:
                    continue
        
        return findings
