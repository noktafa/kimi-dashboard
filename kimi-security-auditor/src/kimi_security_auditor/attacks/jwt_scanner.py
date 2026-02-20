"""
JWT scanner for detecting JWT security issues.
"""

import re
from typing import Dict, List, Optional, Any

import httpx
import jwt

from ..models import Finding, Severity, Confidence


class JWTScanner:
    """Scanner for JWT security issues."""
    
    # Common weak secrets
    WEAK_SECRETS = [
        "secret",
        "secret123",
        "password",
        "password123",
        "123456",
        "admin",
        "jwt",
        "token",
        "key",
        "supersecret",
        "your-256-bit-secret",
        "your-secret-key",
        "HS256",
        "HS512",
        "shhh",
        "mysecret",
        "secretkey",
        "jwt-secret",
        "api-secret",
        "dev-secret",
        "test-secret",
        "changeme",
        "default",
        "null",
        "none",
        "",
    ]
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    def _extract_jwt(self, text: str) -> List[str]:
        """Extract JWT tokens from text."""
        # JWT pattern: base64.base64.base64 (with optional padding)
        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        return re.findall(jwt_pattern, text)
    
    def _decode_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode JWT without verification."""
        try:
            # Decode without verification to inspect contents
            decoded = jwt.decode(token, options={"verify_signature": False})
            return decoded
        except Exception:
            return None
    
    def _check_weak_secret(self, token: str) -> Optional[str]:
        """Check if JWT uses a weak secret."""
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get('alg', '')
            
            # Only check HMAC algorithms
            if algorithm not in ['HS256', 'HS384', 'HS512']:
                return None
            
            for secret in self.WEAK_SECRETS:
                try:
                    jwt.decode(token, secret, algorithms=[algorithm])
                    return secret
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
                    
        except Exception:
            pass
        
        return None
    
    def _check_algorithm_confusion(self, token: str) -> Optional[Finding]:
        """Check for algorithm confusion vulnerability (none/None)."""
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get('alg', '')
            
            if algorithm.lower() == 'none':
                return Finding(
                    title="JWT Algorithm Confusion (None Algorithm)",
                    description="JWT token uses the 'none' algorithm, which allows anyone to forge tokens.",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    target="JWT Token",
                    finding_type="jwt_none_algorithm",
                    evidence=f"Algorithm: {algorithm}",
                    remediation="Reject tokens with 'none' algorithm. "
                               "Explicitly specify allowed algorithms when verifying JWTs.",
                    references=[
                        "https://owasp.org/www-community/attacks/jwt_none_algorithm",
                        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                    ],
                )
            
            # Check for algorithm switching possibility
            if algorithm in ['RS256', 'RS384', 'RS512']:
                # Try to decode with HMAC (algorithm confusion)
                try:
                    # This is a simplified check - real attack would need the public key
                    return Finding(
                        title="JWT Potential Algorithm Confusion",
                        description=f"JWT uses asymmetric algorithm ({algorithm}). "
                                   f"If the public key is exposed, an attacker could use it as HMAC secret.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        target="JWT Token",
                        finding_type="jwt_algorithm_confusion",
                        evidence=f"Algorithm: {algorithm}",
                        remediation="Use different keys for different algorithms. "
                                   "Validate the algorithm explicitly. "
                                   "Don't expose public keys in client-accessible locations.",
                        references=[
                            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                        ],
                    )
                except Exception:
                    pass
                    
        except Exception:
            pass
        
        return None
    
    async def scan(self, url: str) -> List[Finding]:
        """Scan for JWT-related vulnerabilities."""
        findings = []
        found_tokens = set()
        
        try:
            response = await self.client.get(url, follow_redirects=True)
            
            # Extract tokens from response
            tokens = self._extract_jwt(response.text)
            
            # Check cookies for JWT
            for cookie in response.cookies.jar:
                cookie_value = str(cookie.value) if hasattr(cookie, 'value') else str(cookie)
                tokens.extend(self._extract_jwt(cookie_value))
            
            # Check Authorization header in request (if we have it)
            auth_header = response.request.headers.get('authorization', '')
            if auth_header.startswith('Bearer '):
                tokens.append(auth_header[7:])
            
            for token in tokens:
                if token in found_tokens:
                    continue
                found_tokens.add(token)
                
                # Decode and inspect token
                decoded = self._decode_jwt(token)
                if decoded:
                    # Check for sensitive data exposure
                    sensitive_claims = ['password', 'ssn', 'credit_card', 'secret', 'key']
                    exposed = [claim for claim in sensitive_claims if claim in str(decoded).lower()]
                    
                    if exposed:
                        findings.append(Finding(
                            title="JWT Sensitive Data Exposure",
                            description=f"JWT token contains potentially sensitive claims: {', '.join(exposed)}",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            target=url,
                            finding_type="jwt_sensitive_data",
                            evidence=f"Claims: {list(decoded.keys())}",
                            remediation="Don't store sensitive data in JWT claims. "
                                       "JWTs are base64 encoded but not encrypted.",
                            references=[
                                "https://owasp.org/www-community/attacks/JWT_Security",
                            ],
                        ))
                    
                    # Check for weak secret
                    weak_secret = self._check_weak_secret(token)
                    if weak_secret:
                        findings.append(Finding(
                            title="JWT Weak Secret",
                            description=f"JWT token uses a weak or guessable secret: '{weak_secret}'",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CERTAIN,
                            target=url,
                            finding_type="jwt_weak_secret",
                            evidence=f"Secret cracked: {weak_secret}",
                            remediation="Use a strong, randomly generated secret (at least 256 bits). "
                                       "Store secrets securely (environment variables, key management service). "
                                       "Rotate secrets regularly.",
                            references=[
                                "https://owasp.org/www-community/attacks/JWT_Security",
                                "https://tools.ietf.org/html/rfc7518",
                            ],
                        ))
                    
                    # Check algorithm
                    alg_finding = self._check_algorithm_confusion(token)
                    if alg_finding:
                        findings.append(alg_finding)
                    
                    # Check expiration
                    if 'exp' not in decoded:
                        findings.append(Finding(
                            title="JWT Missing Expiration",
                            description="JWT token does not have an expiration claim (exp). "
                                       "Tokens without expiration remain valid indefinitely.",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            target=url,
                            finding_type="jwt_no_expiration",
                            evidence=f"Claims: {list(decoded.keys())}",
                            remediation="Always include an 'exp' (expiration) claim in JWTs. "
                                       "Set appropriate expiration times based on use case.",
                            references=[
                                "https://tools.ietf.org/html/rfc7519#section-4.1.4",
                            ],
                        ))
            
        except Exception as e:
            print(f"Error during JWT scan: {e}")
        
        return findings
