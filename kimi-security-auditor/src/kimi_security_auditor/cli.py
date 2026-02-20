"""
Main CLI entry point for Kimi Security Auditor.
"""

import asyncio
import sys
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

import click
import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .models import ScanResult
from .recon import TechDetector, WebCrawler, EndpointDiscovery
from .attacks import (
    SQLInjectionScanner, 
    CommandInjectionScanner, 
    JWTScanner,
    NoSQLInjectionScanner,
    SSTIScanner,
    XXEScanner,
    CORSChecker,
    SecurityHeadersAnalyzer,
    DirectoryTraversalScanner,
    FileUploadScanner,
)
from .reporting import save_report, ConsoleReporter


console = Console()


class SecurityAuditor:
    """Main security auditor orchestrator."""
    
    def __init__(self, target: str, timeout: float = 30.0, max_depth: int = 3):
        self.target = target
        self.timeout = timeout
        self.max_depth = max_depth
        self.result = ScanResult(
            target=target,
            start_time=datetime.now(timezone.utc),
        )
        
        # Initialize HTTP client
        headers = {
            'User-Agent': 'Kimi-Security-Auditor/0.2.0 (Security Testing Tool)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        self.client = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            verify=False,  # Allow self-signed certs for testing
        )
    
    async def run_recon(self, enable_crawl: bool = True, enable_tech_detection: bool = True) -> None:
        """Run reconnaissance phase."""
        console.print("[blue]Running reconnaissance...[/blue]")
        
        self.result.metadata['recon'] = {}
        
        if enable_tech_detection:
            detector = TechDetector(self.client)
            technologies = await detector.detect(self.target)
            self.result.metadata['recon']['technologies'] = [
                {
                    'name': t.name,
                    'category': t.category,
                    'version': t.version,
                    'confidence': t.confidence,
                }
                for t in technologies
            ]
            console.print(f"  Detected {len(technologies)} technologies")
        
        if enable_crawl:
            crawler = WebCrawler(self.client, max_depth=self.max_depth)
            
            # Crawl main site
            endpoints = await crawler.crawl(self.target)
            console.print(f"  Discovered {len(endpoints)} pages via crawling")
            
            # Discover hidden paths
            hidden = await crawler.discover_hidden_paths(self.target)
            console.print(f"  Discovered {len(hidden)} interesting paths")
            
            # Discover API endpoints
            discovery = EndpointDiscovery(self.client)
            api_endpoints = await discovery.discover_api_endpoints(self.target)
            console.print(f"  Discovered {len(api_endpoints)} potential API endpoints")
            
            # Store all endpoints
            all_endpoints = endpoints + hidden + api_endpoints
            self.result.metadata['recon']['endpoints'] = [
                {
                    'url': e.url,
                    'method': e.method,
                    'status_code': e.status_code,
                    'parameters': e.parameters,
                }
                for e in all_endpoints
            ]
            self.result.metadata['recon']['crawled_endpoints'] = len(endpoints)
            self.result.metadata['recon']['hidden_paths'] = len(hidden)
            self.result.metadata['recon']['api_endpoints'] = len(api_endpoints)
    
    async def run_attacks(self, 
                         enable_sql: bool = True,
                         enable_cmd: bool = True,
                         enable_jwt: bool = True,
                         enable_nosql: bool = True,
                         enable_ssti: bool = True,
                         enable_xxe: bool = True,
                         enable_cors: bool = True,
                         enable_headers: bool = True,
                         enable_traversal: bool = True,
                         enable_upload: bool = True) -> None:
        """Run attack/scanning phase."""
        console.print("[blue]Running vulnerability scans...[/blue]")
        
        # Get endpoints to scan
        endpoints = self.result.metadata.get('recon', {}).get('endpoints', [])
        if not endpoints:
            # If no recon, just scan the target
            endpoints = [{'url': self.target, 'method': 'GET', 'parameters': []}]
        
        # Limit endpoints to scan for performance
        urls_to_scan = [e['url'] for e in endpoints[:20]]  # Scan first 20
        
        # Security Headers Analysis (always run on main target)
        if enable_headers:
            console.print("  Analyzing security headers...")
            headers_analyzer = SecurityHeadersAnalyzer(self.client)
            findings = await headers_analyzer.scan_url(self.target)
            for finding in findings:
                self.result.add_finding(finding)
        
        # CORS Check (always run on main target)
        if enable_cors:
            console.print("  Checking CORS configuration...")
            cors_checker = CORSChecker(self.client)
            findings = await cors_checker.scan_url(self.target)
            for finding in findings:
                self.result.add_finding(finding)
        
        # SQL Injection Scan
        if enable_sql:
            console.print("  Scanning for SQL injection...")
            sql_scanner = SQLInjectionScanner(self.client)
            
            for url_data in urls_to_scan:
                url = url_data if isinstance(url_data, str) else url_data['url']
                findings = await sql_scanner.scan_url(url)
                for finding in findings:
                    self.result.add_finding(finding)
        
        # NoSQL Injection Scan
        if enable_nosql:
            console.print("  Scanning for NoSQL injection...")
            nosql_scanner = NoSQLInjectionScanner(self.client)
            
            for url_data in urls_to_scan:
                url = url_data if isinstance(url_data, str) else url_data['url']
                findings = await nosql_scanner.scan_url(url)
                for finding in findings:
                    self.result.add_finding(finding)
                
                # Also test API endpoints specifically
                if '/api' in url.lower():
                    findings = await nosql_scanner.scan_api(url)
                    for finding in findings:
                        self.result.add_finding(finding)
        
        # Command Injection Scan
        if enable_cmd:
            console.print("  Scanning for command injection...")
            cmd_scanner = CommandInjectionScanner(self.client)
            
            for url_data in urls_to_scan:
                url = url_data if isinstance(url_data, str) else url_data['url']
                findings = await cmd_scanner.scan_url(url)
                for finding in findings:
                    self.result.add_finding(finding)
        
        # SSTI Scan
        if enable_ssti:
            console.print("  Scanning for SSTI...")
            ssti_scanner = SSTIScanner(self.client)
            
            for url_data in urls_to_scan:
                url = url_data if isinstance(url_data, str) else url_data['url']
                findings = await ssti_scanner.scan_url(url)
                for finding in findings:
                    self.result.add_finding(finding)
                
                # Also detect template engines
                findings = await ssti_scanner.detect_template_engine(url)
                for finding in findings:
                    self.result.add_finding(finding)
        
        # XXE Scan
        if enable_xxe:
            console.print("  Scanning for XXE...")
            xxe_scanner = XXEScanner(self.client)
            
            for url_data in urls_to_scan:
                url = url_data if isinstance(url_data, str) else url_data['url']
                findings = await xxe_scanner.scan_url(url)
                for finding in findings:
                    self.result.add_finding(finding)
                
                # Test specific API endpoints
                findings = await xxe_scanner.scan_endpoint(url)
                for finding in findings:
                    self.result.add_finding(finding)
        
        # Directory Traversal Scan
        if enable_traversal:
            console.print("  Scanning for directory traversal...")
            traversal_scanner = DirectoryTraversalScanner(self.client)
            
            for url_data in urls_to_scan:
                url = url_data if isinstance(url_data, str) else url_data['url']
                findings = await traversal_scanner.scan_url(url)
                for finding in findings:
                    self.result.add_finding(finding)
                
                # Test file endpoints specifically
                findings = await traversal_scanner.scan_file_endpoint(url)
                for finding in findings:
                    self.result.add_finding(finding)
        
        # File Upload Scan
        if enable_upload:
            console.print("  Scanning for file upload vulnerabilities...")
            upload_scanner = FileUploadScanner(self.client)
            
            # Detect upload endpoints first
            for url_data in urls_to_scan:
                url = url_data if isinstance(url_data, str) else url_data['url']
                indicators = await upload_scanner.detect_upload_endpoints(url)
                
                if indicators:
                    # Found potential upload endpoint, scan it
                    findings = await upload_scanner.scan_upload_endpoint(url)
                    for finding in findings:
                        self.result.add_finding(finding)
        
        # JWT Scan
        if enable_jwt:
            console.print("  Scanning for JWT vulnerabilities...")
            jwt_scanner = JWTScanner(self.client)
            
            for url_data in urls_to_scan:
                url = url_data if isinstance(url_data, str) else url_data['url']
                findings = await jwt_scanner.scan(url)
                for finding in findings:
                    self.result.add_finding(finding)
        
        console.print(f"  Found {len(self.result.findings)} vulnerabilities")
    
    async def run(self,
                  recon: bool = True,
                  sql: bool = True,
                  cmd: bool = True,
                  jwt: bool = True,
                  nosql: bool = True,
                  ssti: bool = True,
                  xxe: bool = True,
                  cors: bool = True,
                  headers: bool = True,
                  traversal: bool = True,
                  upload: bool = True) -> ScanResult:
        """Run the full security audit."""
        try:
            if recon:
                await self.run_recon()
            
            await self.run_attacks(
                enable_sql=sql, 
                enable_cmd=cmd, 
                enable_jwt=jwt,
                enable_nosql=nosql,
                enable_ssti=ssti,
                enable_xxe=xxe,
                enable_cors=cors,
                enable_headers=headers,
                enable_traversal=traversal,
                enable_upload=upload,
            )
            
        finally:
            await self.client.aclose()
            self.result.end_time = datetime.utcnow()
        
        return self.result


@click.command()
@click.argument('target')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', '-f', 'output_format', 
              type=click.Choice(['auto', 'markdown', 'md', 'json', 'sarif', 'console']),
              default='auto', help='Output format')
@click.option('--no-recon', is_flag=True, help='Skip reconnaissance phase')
@click.option('--no-sql', is_flag=True, help='Skip SQL injection scans')
@click.option('--no-cmd', is_flag=True, help='Skip command injection scans')
@click.option('--no-jwt', is_flag=True, help='Skip JWT scans')
@click.option('--no-nosql', is_flag=True, help='Skip NoSQL injection scans')
@click.option('--no-ssti', is_flag=True, help='Skip SSTI scans')
@click.option('--no-xxe', is_flag=True, help='Skip XXE scans')
@click.option('--no-cors', is_flag=True, help='Skip CORS checks')
@click.option('--no-headers', is_flag=True, help='Skip security headers analysis')
@click.option('--no-traversal', is_flag=True, help='Skip directory traversal scans')
@click.option('--no-upload', is_flag=True, help='Skip file upload vulnerability scans')
@click.option('--timeout', '-t', default=30.0, help='Request timeout in seconds')
@click.option('--max-depth', '-d', default=3, help='Maximum crawl depth')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def main(target: str,
         output: Optional[str],
         output_format: str,
         no_recon: bool,
         no_sql: bool,
         no_cmd: bool,
         no_jwt: bool,
         no_nosql: bool,
         no_ssti: bool,
         no_xxe: bool,
         no_cors: bool,
         no_headers: bool,
         no_traversal: bool,
         no_upload: bool,
         timeout: float,
         max_depth: int,
         verbose: bool):
    """
    Kimi Security Auditor - Web Application Security Scanner
    
    TARGET: The URL to scan (e.g., https://example.com)
    
    Examples:
    
        \b
        # Basic scan
        kimi-audit https://example.com
        
        \b
        # Save report to file
        kimi-audit https://example.com -o report.md
        
        \b
        # JSON output
        kimi-audit https://example.com -f json -o report.json
        
        \b
        # Quick scan (no recon)
        kimi-audit https://example.com --no-recon
        
        \b
        # Scan only specific vulnerability types
        kimi-audit https://example.com --no-nosql --no-ssti --no-xxe
    """
    # Validate target
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    parsed = urlparse(target)
    if not parsed.netloc:
        console.print("[red]Error: Invalid target URL[/red]")
        sys.exit(1)
    
    console.print(f"[bold]Kimi Security Auditor[/bold]")
    console.print(f"Target: {target}")
    console.print("")
    
    # Run audit
    async def run_audit():
        auditor = SecurityAuditor(target, timeout=timeout, max_depth=max_depth)
        return await auditor.run(
            recon=not no_recon,
            sql=not no_sql,
            cmd=not no_cmd,
            jwt=not no_jwt,
            nosql=not no_nosql,
            ssti=not no_ssti,
            xxe=not no_xxe,
            cors=not no_cors,
            headers=not no_headers,
            traversal=not no_traversal,
            upload=not no_upload,
        )
    
    try:
        result = asyncio.run(run_audit())
        
        # Print console report
        console.print("")
        reporter = ConsoleReporter()
        reporter.generate(result)
        
        # Save to file if requested
        if output:
            save_report(result, output, output_format)
            console.print(f"\n[green]Report saved to: {output}[/green]")
        
        # Exit with error code if critical/high findings
        critical_high = len([f for f in result.findings 
                            if f.severity.value in ('critical', 'high')])
        if critical_high > 0:
            sys.exit(1)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
