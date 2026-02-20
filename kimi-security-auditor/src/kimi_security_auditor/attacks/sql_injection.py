"""
SQL Injection scanner for detecting SQL injection vulnerabilities.
"""

import re
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple

import httpx

from ..models import Finding, Severity, Confidence


class SQLInjectionScanner:
    """Scanner for SQL injection vulnerabilities."""
    
    # Error-based detection patterns
    ERROR_PATTERNS = {
        'MySQL': [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"MySQL.*Driver",
            r"mysqli_.*",
        ],
        'PostgreSQL': [
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::Error",
        ],
        'Microsoft SQL Server': [
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL.*Server.*Driver",
            r"Warning.*mssql_.*",
            r"(\W|\A)SQL.*Server.*[0-9a-fA-F]{8}",
            r"Exception.*\WSystem\.Data\.SqlClient\.",
            r"Exception.*\WRoadhouse\.Cms\.",
        ],
        'Oracle': [
            r"\bORA-\d{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"Warning.*ora_.*",
        ],
        'SQLite': [
            r"SQLite/JDBCDriver",
            r"SQLite.*Driver",
            r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::",
            r"\[SQLite_ERROR\]",
            r"SQL Error.*unrecognized token",
            r"SQL Error.*syntax error",
            r"sqlite3\.OperationalError",
            r"SQLite3::SQLException",
        ],
    }
    
    # Time-based detection payloads
    TIME_PAYLOADS = [
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
        "' AND SLEEP(5) -- ",
        "'; WAITFOR DELAY '0:0:5' -- ",
        "' AND pg_sleep(5) -- ",
        "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END) -- ",
        "' UNION SELECT * FROM (SELECT SLEEP(5))a -- ",
        "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
        "1; WAITFOR DELAY '0:0:5'",
    ]
    
    # Boolean-based detection payloads (true/false pairs)
    BOOLEAN_PAYLOADS = [
        ("' AND '1'='1", "' AND '1'='2"),
        ("' AND 1=1 -- ", "' AND 1=2 -- "),
        ("' OR '1'='1", "' OR '1'='2"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("1' AND 1=1 -- ", "1' AND 1=2 -- "),
    ]
    
    # Union-based payloads
    UNION_PAYLOADS = [
        "' UNION SELECT NULL -- ",
        "' UNION SELECT NULL,NULL -- ",
        "' UNION SELECT NULL,NULL,NULL -- ",
        "' UNION SELECT 1,2,3 -- ",
        "' UNION SELECT 'test','test2','test3' -- ",
    ]
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        self.findings: List[Finding] = []
    
    def _detect_error(self, response_text: str) -> Optional[Tuple[str, str]]:
        """Detect SQL error messages in response."""
        for db_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return db_type, match.group(0)
        return None
    
    async def _test_error_based(self, url: str, param: str, method: str = "GET") -> Optional[Finding]:
        """Test for error-based SQL injection."""
        error_payloads = [
            "'",
            "''",
            "'\"",
            "';",
            "'--",
            "'/*",
            "1'",
            "1''",
            "' OR '1'='1",
            "' AND 1=1",
        ]
        
        # Get baseline response
        try:
            if method == "GET":
                baseline_response = await self.client.get(url, follow_redirects=True)
            else:
                baseline_response = await self.client.post(url, data={param: "test"}, follow_redirects=True)
            baseline_text = baseline_response.text
        except Exception:
            return None
        
        for payload in error_payloads:
            try:
                if method == "GET":
                    parsed = urllib.parse.urlparse(url)
                    params = urllib.parse.parse_qs(parsed.query)
                    params[param] = payload
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    response = await self.client.get(test_url, follow_redirects=True)
                else:
                    response = await self.client.post(url, data={param: payload}, follow_redirects=True)
                
                # Check for SQL errors
                error_result = self._detect_error(response.text)
                if error_result:
                    db_type, error_msg = error_result
                    
                    # Verify it's actually an injection (check if baseline doesn't have error)
                    if not self._detect_error(baseline_text):
                        return Finding(
                            title=f"SQL Injection (Error-based) - {db_type}",
                            description=f"Error-based SQL injection vulnerability detected in parameter '{param}'. "
                                       f"The application returned a database error when a malicious payload was submitted.",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            target=url,
                            finding_type="sql_injection_error",
                            evidence=f"Database error: {error_msg}",
                            remediation="Use parameterized queries/prepared statements. "
                                       "Validate and sanitize all user input. "
                                       "Apply the principle of least privilege to database accounts.",
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            ],
                            parameter=param,
                            payload=payload,
                        )
                        
            except Exception:
                continue
        
        return None
    
    async def _test_time_based(self, url: str, param: str, method: str = "GET") -> Optional[Finding]:
        """Test for time-based blind SQL injection."""
        
        for payload in self.TIME_PAYLOADS:
            try:
                start_time = time.time()
                
                if method == "GET":
                    parsed = urllib.parse.urlparse(url)
                    params = urllib.parse.parse_qs(parsed.query)
                    params[param] = payload
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    response = await self.client.get(test_url, follow_redirects=True, timeout=10.0)
                else:
                    response = await self.client.post(url, data={param: payload}, follow_redirects=True, timeout=10.0)
                
                elapsed = time.time() - start_time
                
                # If response took significantly longer, likely time-based injection
                if elapsed >= 4.0:  # Expected 5 second delay, allow some margin
                    return Finding(
                        title="SQL Injection (Time-based Blind)",
                        description=f"Time-based blind SQL injection vulnerability detected in parameter '{param}'. "
                                   f"The application exhibited a time delay when a time-based payload was submitted.",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="sql_injection_time",
                        evidence=f"Response time: {elapsed:.2f}s (expected delay: 5s)",
                        remediation="Use parameterized queries/prepared statements. "
                                   "Implement proper input validation and sanitization.",
                        references=[
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        ],
                        parameter=param,
                        payload=payload,
                    )
                    
            except httpx.TimeoutException:
                # Timeout likely means the injection worked
                return Finding(
                    title="SQL Injection (Time-based Blind)",
                    description=f"Time-based blind SQL injection vulnerability detected in parameter '{param}'. "
                               f"The request timed out, indicating the time-based payload was executed.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    target=url,
                    finding_type="sql_injection_time",
                    evidence="Request timeout after time-based payload",
                    remediation="Use parameterized queries/prepared statements.",
                    references=[
                        "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                    ],
                    parameter=param,
                    payload=payload,
                )
            except Exception:
                continue
        
        return None
    
    async def _test_boolean_based(self, url: str, param: str, method: str = "GET") -> Optional[Finding]:
        """Test for boolean-based blind SQL injection."""
        
        for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
            try:
                # Test true condition
                if method == "GET":
                    parsed = urllib.parse.urlparse(url)
                    params = urllib.parse.parse_qs(parsed.query)
                    
                    params[param] = true_payload
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    true_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    true_response = await self.client.get(true_url, follow_redirects=True)
                    
                    params[param] = false_payload
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    false_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    false_response = await self.client.get(false_url, follow_redirects=True)
                else:
                    true_response = await self.client.post(url, data={param: true_payload}, follow_redirects=True)
                    false_response = await self.client.post(url, data={param: false_payload}, follow_redirects=True)
                
                # Compare responses
                true_len = len(true_response.text)
                false_len = len(false_response.text)
                
                # If responses differ significantly, likely boolean-based injection
                if abs(true_len - false_len) > 50:  # Significant difference threshold
                    return Finding(
                        title="SQL Injection (Boolean-based Blind)",
                        description=f"Boolean-based blind SQL injection vulnerability detected in parameter '{param}'. "
                                   f"The application responds differently to true/false SQL conditions.",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        target=url,
                        finding_type="sql_injection_boolean",
                        evidence=f"True response length: {true_len}, False response length: {false_len}",
                        remediation="Use parameterized queries/prepared statements. "
                                   "Implement proper input validation.",
                        references=[
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        ],
                        parameter=param,
                        payload=f"True: {true_payload}, False: {false_payload}",
                    )
                    
            except Exception:
                continue
        
        return None
    
    async def scan_url(self, url: str, parameters: Optional[List[str]] = None) -> List[Finding]:
        """Scan a URL for SQL injection vulnerabilities."""
        findings = []
        
        # Extract parameters if not provided
        if parameters is None:
            parsed = urllib.parse.urlparse(url)
            parameters = list(urllib.parse.parse_qs(parsed.query).keys())
        
        for param in parameters:
            # Test error-based
            finding = await self._test_error_based(url, param)
            if finding:
                findings.append(finding)
                continue  # Skip other tests if error-based found
            
            # Test time-based
            finding = await self._test_time_based(url, param)
            if finding:
                findings.append(finding)
                continue
            
            # Test boolean-based
            finding = await self._test_boolean_based(url, param)
            if finding:
                findings.append(finding)
        
        return findings
    
    async def scan_form(self, url: str, form_data: Dict[str, str]) -> List[Finding]:
        """Scan a form for SQL injection vulnerabilities."""
        findings = []
        
        for param in form_data.keys():
            # Test error-based
            finding = await self._test_error_based(url, param, method="POST")
            if finding:
                findings.append(finding)
                continue
            
            # Test time-based
            finding = await self._test_time_based(url, param, method="POST")
            if finding:
                findings.append(finding)
                continue
            
            # Test boolean-based
            finding = await self._test_boolean_based(url, param, method="POST")
            if finding:
                findings.append(finding)
        
        return findings
