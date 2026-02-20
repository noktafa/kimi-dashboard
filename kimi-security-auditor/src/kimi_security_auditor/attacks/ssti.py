"""
SSTI (Server-Side Template Injection) scanner for various template engines.
"""

import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

import httpx

from ..models import Finding, Severity, Confidence


class SSTIScanner:
    """Scanner for Server-Side Template Injection vulnerabilities."""
    
    # Template engine detection patterns
    ENGINE_PATTERNS = {
        'Jinja2': [
            r'jinja2\.exceptions',
            r'TemplateSyntaxError',
            r'UndefinedError',
            r'jinja2\.runtime',
        ],
        'Twig': [
            r'Twig_Error',
            r'Twig\\Error',
            r'Unexpected token',
            r'Unknown tag',
        ],
        'Smarty': [
            r'SmartyCompilerException',
            r'SmartyException',
            r'syntax error:',
        ],
        'Freemarker': [
            r'freemarker\.core',
            r'FreemarkerTemplateException',
            r'Expression \w+ is undefined',
        ],
        'Velocity': [
            r'org\.apache\.velocity',
            r'VelocityException',
        ],
        'ERB': [
            r'erb:\d+:',
            r'syntax error, unexpected',
            r'NameError.*undefined',
        ],
        'Django': [
            r'django\.template',
            r'TemplateSyntaxError',
            r'Invalid filter',
        ],
        'Mako': [
            r'mako\.exceptions',
            r'SyntaxException',
        ],
        'Handlebars': [
            r'Handlebars\.Exception',
            r'Mustache',
        ],
        'Pug/Jade': [
            r'Pug.*Error',
            r'Jade.*Error',
        ],
    }
    
    # SSTI payloads organized by engine
    PAYLOADS = {
        'Jinja2': [
            ('{{7*7}}', '49'),
            ('{{7*\'7\'}}', '7777777'),
            ('{{config}}', 'config'),
            ('{{self.__dict__}}', '__dict__'),
            ('{{\'\'.__class__.__mro__[1].__subclasses__()}}', '__subclasses__'),
            ('{{request.application.__globals__}}', 'application'),
        ],
        'Twig': [
            ('{{7*7}}', '49'),
            ('{{7*\'7\'}}', '49'),
            ('{{_self.env.registerUndefinedFilterCallback(\'system\')}}', 'registerUndefinedFilterCallback'),
            ('{{dump()}}', 'dump'),
        ],
        'Smarty': [
            ('{7*7}', '49'),
            ('{php}echo 7*7;{/php}', '49'),
            ('{$smarty.version}', 'version'),
        ],
        'Freemarker': [
            ('${7*7}', '49'),
            ('${7*\'7\'}', '49'),
            ('${.version}', 'version'),
            ('${\'\'.getClass().forName(\'java.lang.Runtime\')}', 'getClass'),
        ],
        'Velocity': [
            ('#set($x=7*7)${x}', '49'),
            ('$class.inspect(\'java.lang.Runtime\')', 'inspect'),
        ],
        'ERB': [
            ('<%= 7*7 %>', '49'),
            ('<%= \'7\'*7 %>', '7777777'),
            ('<%= Dir.pwd %>', 'pwd'),
            ('<%= require \'ostruct\'; OpenStruct.new.to_h %>', 'ostruct'),
        ],
        'Django': [
            ('{{7*7}}', '49'),
            ('{% debug %}', 'debug'),
            ('{{request}}', 'request'),
        ],
        'Mako': [
            ('${7*7}', '49'),
            ('<% import os %>', 'import'),
            ('<%\nimport os\n%>', 'import'),
        ],
        'Handlebars': [
            ('{{#with \"s\" as |string|}}{{#with \"e\"}}{{this.constructor.constructor}}', 'constructor'),
        ],
        'Pug/Jade': [
            ('#{7*7}', '49'),
            ('!{global.process.mainModule.require(\'os\').platform()}', 'platform'),
        ],
    }
    
    # Generic polyglot payloads that work across multiple engines
    POLYGLOT_PAYLOADS = [
        ('${7*7}', '49'),
        ('{{7*7}}', '49'),
        ('<%= 7*7 %>', '49'),
        ('#{7*7}', '49'),
        ('{7*7}', '49'),
        ('${T(java.lang.Runtime).getRuntime()}', 'Runtime'),
        ('{{\'7\'*7}}', '7777777'),
        ('{{7*\'7\'}}', '7777777'),
        ('{{config.items()}}', 'items'),
        ('{{request}}', 'request'),
        ('{{self}}', 'self'),
        ('{php}phpinfo();{/php}', 'phpinfo'),
    ]
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    def _detect_engine(self, response_text: str) -> Optional[Tuple[str, str]]:
        """Detect template engine from error messages."""
        for engine, patterns in self.ENGINE_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return engine, match.group(0)
        return None
    
    async def _test_payload(self, url: str, param: str, payload: str, 
                           expected_indicator: str, method: str = "GET") -> Optional[Dict]:
        """Test a single SSTI payload."""
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
            
            # Check if expected indicator is in response
            if expected_indicator in response.text:
                return {
                    'payload': payload,
                    'indicator': expected_indicator,
                    'response': response.text,
                }
            
            # Check for template errors that indicate SSTI
            engine_detection = self._detect_engine(response.text)
            if engine_detection:
                return {
                    'payload': payload,
                    'engine': engine_detection[0],
                    'error': engine_detection[1],
                    'response': response.text,
                }
                
        except Exception:
            pass
        
        return None
    
    async def _test_generic_ssti(self, url: str, param: str, 
                                  method: str = "GET") -> Optional[Finding]:
        """Test for SSTI using generic polyglot payloads."""
        
        # Get baseline
        try:
            if method == "GET":
                baseline_response = await self.client.get(url, follow_redirects=True)
            else:
                baseline_response = await self.client.post(url, data={param: "test"},
                                                           follow_redirects=True)
            baseline_text = baseline_response.text
        except Exception:
            return None
        
        for payload, indicator in self.POLYGLOT_PAYLOADS:
            result = await self._test_payload(url, param, payload, indicator, method)
            
            if result:
                # Verify it's actually SSTI (not just reflected)
                if indicator in result.get('response', '') and \
                   indicator not in baseline_text:
                    
                    engine = result.get('engine', 'Unknown')
                    evidence = result.get('error') or f"Payload executed: {payload} -> {indicator}"
                    
                    return Finding(
                        title=f"Server-Side Template Injection (SSTI) - {engine}",
                        description=f"SSTI vulnerability detected in parameter '{param}'. "
                                   f"The application appears to execute user input as template code.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        target=url,
                        finding_type="ssti",
                        evidence=evidence,
                        remediation="Avoid passing user input directly to template engines. "
                                   "Use context-aware auto-escaping. "
                                   "Implement strict input validation and sanitization. "
                                   "Consider using a sandboxed template environment.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection",
                            "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection",
                            "https://portswigger.net/web-security/server-side-template-injection",
                        ],
                        parameter=param,
                        payload=payload,
                    )
        
        return None
    
    async def _test_engine_specific(self, url: str, param: str,
                                     method: str = "GET") -> Optional[Finding]:
        """Test for SSTI using engine-specific payloads."""
        
        for engine, payloads in self.PAYLOADS.items():
            for payload, indicator in payloads:
                result = await self._test_payload(url, param, payload, indicator, method)
                
                if result:
                    evidence = result.get('error') or f"Payload executed: {payload}"
                    
                    return Finding(
                        title=f"Server-Side Template Injection ({engine})",
                        description=f"SSTI vulnerability detected in parameter '{param}' "
                                   f"using {engine} template engine specific payload.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CERTAIN,
                        target=url,
                        finding_type="ssti",
                        evidence=evidence,
                        remediation=f"Sanitize user input before passing to {engine} templates. "
                                   f"Use the template engine's auto-escaping features. "
                                   f"Consider using a restricted template environment.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection",
                            "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection",
                        ],
                        parameter=param,
                        payload=payload,
                    )
        
        return None
    
    async def scan_url(self, url: str, parameters: Optional[List[str]] = None) -> List[Finding]:
        """Scan a URL for SSTI vulnerabilities."""
        findings = []
        
        if parameters is None:
            parsed = urllib.parse.urlparse(url)
            parameters = list(urllib.parse.parse_qs(parsed.query).keys())
        
        for param in parameters:
            # Test with generic payloads first
            finding = await self._test_generic_ssti(url, param)
            if finding:
                findings.append(finding)
                continue
            
            # Test with engine-specific payloads
            finding = await self._test_engine_specific(url, param)
            if finding:
                findings.append(finding)
        
        return findings
    
    async def scan_form(self, url: str, form_data: Dict[str, str]) -> List[Finding]:
        """Scan a form for SSTI vulnerabilities."""
        findings = []
        
        for param in form_data.keys():
            finding = await self._test_generic_ssti(url, param, method="POST")
            if finding:
                findings.append(finding)
                continue
            
            finding = await self._test_engine_specific(url, param, method="POST")
            if finding:
                findings.append(finding)
        
        return findings
    
    async def detect_template_engine(self, url: str) -> List[Finding]:
        """Detect which template engine is being used."""
        findings = []
        
        # Send a payload that might trigger an error revealing the engine
        error_triggering_payloads = [
            '{{ invalid_syntax! }}',
            '${ invalid}',
            '<%= invalid %>',
            '{invalid}',
        ]
        
        for payload in error_triggering_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                
                # Add payload to a common parameter name
                test_param = 'name' if 'name' not in params else 'q'
                params[test_param] = payload
                
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                
                response = await self.client.get(test_url, follow_redirects=True)
                
                engine_detection = self._detect_engine(response.text)
                if engine_detection:
                    engine, error = engine_detection
                    findings.append(Finding(
                        title=f"Template Engine Detected ({engine})",
                        description=f"The application appears to use {engine} template engine. "
                                   f"This information can be used to craft targeted SSTI payloads.",
                        severity=Severity.INFO,
                        confidence=Confidence.MEDIUM,
                        target=url,
                        finding_type="template_engine_detected",
                        evidence=f"Error message: {error}",
                        remediation="Configure the application to not expose detailed error messages. "
                                   "Use generic error pages in production.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection",
                        ],
                        payload=payload,
                    ))
                    break
                    
            except Exception:
                continue
        
        return findings
