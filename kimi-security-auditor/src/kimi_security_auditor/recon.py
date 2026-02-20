"""
Reconnaissance module for technology detection, crawling, and endpoint discovery.
"""

import re
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup


@dataclass
class Technology:
    """Detected technology on a target."""
    name: str
    category: str  # e.g., 'web-server', 'framework', 'database', 'language'
    version: Optional[str] = None
    confidence: int = 100  # 0-100
    evidence: List[str] = field(default_factory=list)


@dataclass
class Endpoint:
    """Discovered endpoint/URL."""
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    form_inputs: List[Dict[str, str]] = field(default_factory=list)
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    title: Optional[str] = None


class TechDetector:
    """Detects technologies used by a web application."""
    
    # Technology signatures: name -> (category, headers_patterns, body_patterns, version_regex)
    SIGNATURES = {
        # Web Servers
        'Apache': ('web-server', ['Server: Apache'], [], r'Apache/([\d.]+)'),
        'Nginx': ('web-server', ['Server: nginx'], [], r'nginx/([\d.]+)'),
        'IIS': ('web-server', ['Server: Microsoft-IIS'], [], r'Microsoft-IIS/([\d.]+)'),
        'Caddy': ('web-server', ['Server: Caddy'], [], None),
        'lighttpd': ('web-server', ['Server: lighttpd'], [], r'lighttpd/([\d.]+)'),
        
        # Frameworks
        'Django': ('framework', [], ['csrfmiddlewaretoken', '__debug__', 'django'], r'Django/([\d.]+)'),
        'Flask': ('framework', ['X-Powered-By: Flask'], [], None),
        'Express': ('framework', ['X-Powered-By: Express'], [], None),
        'Laravel': ('framework', [], ['laravel_session', 'csrf-token'], None),
        'Spring': ('framework', ['X-Application-Context'], [], None),
        'ASP.NET': ('framework', ['X-AspNet-Version', 'X-Powered-By: ASP.NET'], [], r'ASP\.NET.*?(\d+\.\d+)'),
        'Ruby on Rails': ('framework', ['X-Runtime'], [], r'Rails/([\d.]+)'),
        
        # Databases (indirect detection)
        'MySQL': ('database', [], ['MySQL', 'mysqli'], None),
        'PostgreSQL': ('database', [], ['PostgreSQL', 'pg_'], None),
        'MongoDB': ('database', [], ['MongoDB', 'mongodb'], None),
        'SQLite': ('database', [], ['SQLite', 'sqlite3'], None),
        
        # Languages
        'PHP': ('language', ['X-Powered-By: PHP'], ['<?php'], r'PHP/([\d.]+)'),
        'Python': ('language', [], ['WSGIServer', 'Python'], r'Python/([\d.]+)'),
        'Node.js': ('language', [], ['Node.js', 'node.js'], None),
        'Ruby': ('language', [], ['Rack', 'Ruby'], None),
        'Java': ('language', [], ['JSESSIONID', 'java'], None),
        'ASP': ('language', ['X-Powered-By: ASP'], [], None),
        
        # JavaScript Frameworks
        'React': ('js-framework', [], ['reactroot', 'data-react', '__REACT__'], None),
        'Vue.js': ('js-framework', [], ['vue.js', 'v-', '__VUE__'], None),
        'Angular': ('js-framework', [], ['ng-', 'angular'], None),
        'jQuery': ('js-framework', [], ['jquery'], r'jquery[/-]([\d.]+)'),
        
        # CMS
        'WordPress': ('cms', [], ['wp-content', 'wp-includes', 'wordpress'], None),
        'Drupal': ('cms', [], ['drupal', 'Drupal'], None),
        'Joomla': ('cms', [], ['joomla', 'Joomla'], None),
        
        # Security
        'ModSecurity': ('waf', ['Server: ModSecurity'], [], None),
        'Cloudflare': ('waf', ['CF-RAY', 'Server: cloudflare'], [], None),
        'AWS WAF': ('waf', ['X-AMZ-CF-ID'], [], None),
    }
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    async def detect(self, url: str) -> List[Technology]:
        """Detect technologies at the given URL."""
        technologies = []
        
        try:
            response = await self.client.get(url, follow_redirects=True)
            headers = dict(response.headers)
            body = response.text
            
            for tech_name, signature in self.SIGNATURES.items():
                category, header_patterns, body_patterns, version_regex = signature
                
                detected = False
                evidence = []
                version = None
                confidence = 0
                
                # Check headers
                for pattern in header_patterns:
                    header_name = pattern.split(':')[0] if ':' in pattern else pattern
                    header_value = headers.get(header_name, '')
                    if pattern.lower() in f"{header_name}: {header_value}".lower():
                        detected = True
                        evidence.append(f"Header: {header_name}: {header_value}")
                        confidence += 40
                        
                        # Extract version
                        if version_regex:
                            match = re.search(version_regex, header_value)
                            if match:
                                version = match.group(1)
                
                # Check body
                for pattern in body_patterns:
                    if pattern.lower() in body.lower():
                        detected = True
                        evidence.append(f"Body contains: {pattern}")
                        confidence += 30
                        
                        # Extract version from body
                        if version_regex and not version:
                            match = re.search(version_regex, body)
                            if match:
                                version = match.group(1)
                
                if detected:
                    technologies.append(Technology(
                        name=tech_name,
                        category=category,
                        version=version,
                        confidence=min(confidence, 100),
                        evidence=evidence
                    ))
            
            # Detect cookies
            cookies = response.cookies
            for cookie in cookies.jar:
                cookie_name = cookie.name if hasattr(cookie, 'name') else str(cookie)
                if 'session' in cookie_name.lower():
                    technologies.append(Technology(
                        name=f"Session Cookie ({cookie_name})",
                        category='session',
                        confidence=90,
                        evidence=[f"Cookie: {cookie_name}"]
                    ))
            
        except Exception as e:
            print(f"Error during tech detection: {e}")
        
        return technologies


class WebCrawler:
    """Crawls a web application to discover pages and endpoints."""
    
    def __init__(self, client: httpx.AsyncClient, max_depth: int = 3, max_pages: int = 50):
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.endpoints: List[Endpoint] = []
        
        # Common paths to check
        self.common_paths = [
            '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
            '/admin', '/login', '/api', '/api/v1', '/api/v2',
            '/swagger', '/swagger-ui.html', '/api-docs',
            '/.env', '/.git/config', '/.htaccess',
            '/phpinfo.php', '/info.php', '/test.php',
            '/backup', '/backups', '/old', '/temp',
            '/config', '/configuration', '/settings',
            '/debug', '/console', '/status',
        ]
    
    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """Normalize and filter URLs."""
        try:
            parsed = urllib.parse.urlparse(url)
            base_parsed = urllib.parse.urlparse(base_url)
            
            # Skip non-HTTP schemes
            if parsed.scheme and parsed.scheme not in ('http', 'https'):
                return None
            
            # Skip anchors and javascript
            if url.startswith('#') or url.startswith('javascript:'):
                return None
            
            # Handle relative URLs
            if not parsed.netloc:
                url = urllib.parse.urljoin(base_url, url)
            
            # Only crawl same domain
            parsed = urllib.parse.urlparse(url)
            if parsed.netloc != base_parsed.netloc:
                return None
            
            # Normalize
            url = url.split('#')[0]  # Remove fragment
            url = url.rstrip('/')
            
            return url
        except Exception:
            return None
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all links from a BeautifulSoup object."""
        links = []
        
        # Anchor tags
        for tag in soup.find_all('a', href=True):
            url = self._normalize_url(tag['href'], base_url)
            if url:
                links.append(url)
        
        # Form actions
        for tag in soup.find_all('form', action=True):
            url = self._normalize_url(tag['action'], base_url)
            if url:
                links.append(url)
        
        # Script src
        for tag in soup.find_all('script', src=True):
            url = self._normalize_url(tag['src'], base_url)
            if url:
                links.append(url)
        
        # Link href
        for tag in soup.find_all('link', href=True):
            url = self._normalize_url(tag['href'], base_url)
            if url:
                links.append(url)
        
        return list(set(links))
    
    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Extract form information from a page."""
        forms = []
        
        for form in soup.find_all('form'):
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'id': input_tag.get('id', ''),
                }
                form_info['inputs'].append(input_info)
            
            forms.append(form_info)
        
        return forms
    
    def _extract_parameters(self, url: str) -> List[str]:
        """Extract query parameters from a URL."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return list(params.keys())
    
    async def crawl(self, start_url: str) -> List[Endpoint]:
        """Crawl starting from the given URL."""
        self.visited.clear()
        self.endpoints.clear()
        
        to_visit = [(start_url, 0)]  # (url, depth)
        base_domain = urllib.parse.urlparse(start_url).netloc
        
        while to_visit and len(self.visited) < self.max_pages:
            url, depth = to_visit.pop(0)
            
            if url in self.visited or depth > self.max_depth:
                continue
            
            self.visited.add(url)
            
            try:
                response = await self.client.get(url, follow_redirects=True)
                
                endpoint = Endpoint(
                    url=url,
                    method="GET",
                    parameters=self._extract_parameters(url),
                    status_code=response.status_code,
                    content_type=response.headers.get('content-type', '').split(';')[0],
                )
                
                # Parse HTML for more info
                if 'text/html' in response.headers.get('content-type', ''):
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Get title
                    title_tag = soup.find('title')
                    if title_tag:
                        endpoint.title = title_tag.get_text(strip=True)
                    
                    # Extract forms
                    endpoint.form_inputs = self._extract_forms(soup)
                    
                    # Find new links if we haven't reached max depth
                    if depth < self.max_depth:
                        links = self._extract_links(soup, url)
                        for link in links:
                            if link not in self.visited:
                                to_visit.append((link, depth + 1))
                
                self.endpoints.append(endpoint)
                
            except Exception as e:
                print(f"Error crawling {url}: {e}")
        
        return self.endpoints
    
    async def discover_hidden_paths(self, base_url: str) -> List[Endpoint]:
        """Discover hidden/common paths on the target."""
        discovered = []
        
        for path in self.common_paths:
            url = urllib.parse.urljoin(base_url, path)
            
            try:
                response = await self.client.get(url, follow_redirects=True)
                
                # Interesting status codes
                if response.status_code in (200, 201, 204, 301, 302, 401, 403, 500):
                    endpoint = Endpoint(
                        url=url,
                        method="GET",
                        status_code=response.status_code,
                        content_type=response.headers.get('content-type', '').split(';')[0],
                    )
                    discovered.append(endpoint)
                    
            except Exception:
                pass  # Silently ignore connection errors for hidden path discovery
        
        return discovered


class EndpointDiscovery:
    """Advanced endpoint discovery using multiple techniques."""
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        self.wordlist = [
            'api', 'v1', 'v2', 'admin', 'auth', 'login', 'logout', 'register',
            'user', 'users', 'account', 'profile', 'dashboard', 'settings',
            'search', 'upload', 'download', 'file', 'files', 'image', 'images',
            'config', 'configuration', 'env', 'environment', 'debug', 'test',
            'backup', 'backups', 'old', 'new', 'temp', 'tmp', 'cache',
            'public', 'private', 'internal', 'external', 'proxy',
            'graphql', 'graphiql', 'playground', 'swagger', 'docs',
            'health', 'status', 'ping', 'ready', 'alive', 'metrics',
            'webhook', 'webhooks', 'callback', 'callbacks', 'hook',
            'oauth', 'oauth2', 'sso', 'saml', 'openid', 'jwt',
            'payment', 'payments', 'billing', 'invoice', 'subscription',
            'notification', 'notifications', 'email', 'sms', 'push',
            'report', 'reports', 'analytics', 'stats', 'metrics', 'logs',
            'export', 'import', 'migrate', 'migration', 'seed',
            'reset', 'password', 'forgot', 'recover', 'verify',
            'token', 'tokens', 'session', 'sessions', 'cookie', 'cookies',
            'cart', 'checkout', 'order', 'orders', 'product', 'products',
            'category', 'categories', 'tag', 'tags', 'comment', 'comments',
            'post', 'posts', 'article', 'articles', 'blog', 'news',
        ]
    
    async def discover_api_endpoints(self, base_url: str) -> List[Endpoint]:
        """Discover API endpoints through common patterns."""
        discovered = []
        base = base_url.rstrip('/')
        
        # Common API patterns
        patterns = [
            '/api/{word}',
            '/api/v1/{word}',
            '/api/v2/{word}',
            '/v1/{word}',
            '/v2/{word}',
            '/rest/{word}',
            '/{word}',
            '/{word}s',
            '/{word}/list',
            '/{word}/all',
            '/{word}/search',
        ]
        
        for word in self.wordlist:
            for pattern in patterns:
                path = pattern.format(word=word)
                url = f"{base}{path}"
                
                try:
                    response = await self.client.get(url, follow_redirects=True, timeout=5.0)
                    
                    # Check for API-like responses
                    content_type = response.headers.get('content-type', '')
                    is_api_like = (
                        response.status_code == 200 and
                        ('json' in content_type or 
                         response.text.strip().startswith(('{', '[')))
                    )
                    
                    if is_api_like or response.status_code in (401, 403, 405):
                        endpoint = Endpoint(
                            url=url,
                            method="GET",
                            status_code=response.status_code,
                            content_type=content_type.split(';')[0] if content_type else None,
                        )
                        discovered.append(endpoint)
                        
                except Exception:
                    pass
        
        return discovered
    
    async def discover_parameters(self, url: str) -> List[str]:
        """Discover hidden parameters on an endpoint."""
        common_params = [
            'id', 'page', 'limit', 'offset', 'sort', 'order', 'filter',
            'search', 'q', 'query', 'term', 'keyword',
            'user', 'user_id', 'username', 'email',
            'token', 'api_key', 'key', 'secret',
            'callback', 'redirect', 'return', 'next', 'url',
            'format', 'type', 'view', 'mode',
            'debug', 'test', 'dev', 'admin', 'root',
            'action', 'cmd', 'command', 'exec', 'run',
            'file', 'path', 'dir', 'folder', 'location',
            'data', 'content', 'body', 'payload', 'input',
            'start', 'end', 'from', 'to', 'date', 'time',
            'status', 'state', 'active', 'enabled', 'visible',
            'lang', 'language', 'locale', 'country', 'region',
            'version', 'v', 'api_version', 'format',
        ]
        
        discovered = []
        
        for param in common_params:
            test_url = f"{url}?{param}=1"
            
            try:
                response = await self.client.get(test_url, follow_redirects=True, timeout=3.0)
                
                # If response differs from base, parameter might be valid
                # This is a simple heuristic
                if response.status_code != 404:
                    discovered.append(param)
                    
            except Exception:
                pass
        
        return discovered
