#!/usr/bin/env python3
"""
Kimi Ecosystem Convergence Demo
================================

Orchestrates a full convergence demonstration against the vulnerable infrastructure.
Scans 5 DigitalOcean servers with kimi-audit, collects real findings, and generates
executive summary reports.

Target Infrastructure:
- Load Balancer: 167.172.71.245 (Nginx)
- API Server 1: 178.128.117.238 (Flask vulnerable app)
- API Server 2: 152.42.220.203 (Flask vulnerable app)
- Database: 152.42.222.84 (PostgreSQL)
- Cache: 167.71.196.196 (Redis)

Usage:
    python demo.py [--report-dir DIR] [--format {markdown,json,sarif}]
    ./run_demo.sh
"""

import asyncio
import argparse
import json
import sys
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict

# Add kimi-security-auditor to path
sys.path.insert(0, '/root/.openclaw/workspace/kimi-ecosystem/kimi-security-auditor/src')

from kimi_security_auditor.cli import SecurityAuditor
from kimi_security_auditor.models import ScanResult, Finding, Severity
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.layout import Layout
from rich.syntax import Syntax
from rich.tree import Tree

console = Console()


# Target Infrastructure Configuration
TARGETS = [
    {
        "name": "Load Balancer",
        "ip": "167.172.71.245",
        "url": "http://167.172.71.245",
        "type": "nginx",
        "description": "Nginx load balancer distributing traffic to API servers"
    },
    {
        "name": "API Server 1",
        "ip": "178.128.117.238",
        "url": "http://178.128.117.238",
        "type": "flask",
        "description": "Flask application with intentional vulnerabilities"
    },
    {
        "name": "API Server 2",
        "ip": "152.42.220.203",
        "url": "http://152.42.220.203",
        "type": "flask",
        "description": "Flask application with intentional vulnerabilities"
    },
    {
        "name": "Database Server",
        "ip": "152.42.222.84",
        "url": "http://152.42.222.84:5432",
        "type": "postgres",
        "description": "PostgreSQL database (port scan only)"
    },
    {
        "name": "Cache Server",
        "ip": "167.71.196.196",
        "url": "http://167.71.196.196:6379",
        "type": "redis",
        "description": "Redis cache server (port scan only)"
    }
]


@dataclass
class DemoResult:
    """Aggregated results from the convergence demo."""
    start_time: datetime
    end_time: Optional[datetime] = None
    target_results: List[Dict[str, Any]] = field(default_factory=list)
    aggregated_findings: List[Finding] = field(default_factory=list)
    
    def add_target_result(self, target: Dict[str, str], result: ScanResult) -> None:
        """Add a target's scan result."""
        self.target_results.append({
            "target": target,
            "scan_result": result,
            "summary": result.get_summary() if result else None
        })
        if result:
            self.aggregated_findings.extend(result.findings)
    
    def get_overall_summary(self) -> Dict[str, int]:
        """Get overall findings summary across all targets."""
        summary = {s.value: 0 for s in Severity}
        for finding in self.aggregated_findings:
            summary[finding.severity.value] += 1
        return summary
    
    def get_risk_score(self) -> int:
        """Calculate overall risk score (0-100)."""
        summary = self.get_overall_summary()
        # Weighted scoring
        score = (
            summary.get('critical', 0) * 25 +
            summary.get('high', 0) * 10 +
            summary.get('medium', 0) * 5 +
            summary.get('low', 0) * 2 +
            summary.get('info', 0) * 0
        )
        return min(score, 100)
    
    def get_risk_level(self) -> str:
        """Get risk level based on score."""
        score = self.get_risk_score()
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        return "MINIMAL"


class ConvergenceDemo:
    """Main demo orchestrator."""
    
    def __init__(self, report_dir: str = "reports", output_format: str = "markdown"):
        self.report_dir = Path(report_dir)
        self.output_format = output_format
        self.result = DemoResult(start_time=datetime.now(timezone.utc))
        
        # Create report directory
        self.report_dir.mkdir(parents=True, exist_ok=True)
    
    async def scan_target(self, target: Dict[str, str]) -> Optional[ScanResult]:
        """Scan a single target."""
        url = target["url"]
        
        try:
            auditor = SecurityAuditor(url, timeout=30.0, max_depth=2)
            result = await auditor.run(
                recon=True,
                sql=True,
                cmd=True,
                jwt=True,
                nosql=True,
                ssti=True,
                xxe=True,
                cors=True,
                headers=True,
                traversal=True,
                upload=True
            )
            return result
        except Exception as e:
            console.print(f"[red]Error scanning {target['name']}: {e}[/red]")
            return None
    
    async def run_convergence_loop(self) -> DemoResult:
        """Run the full convergence demonstration."""
        console.print(Panel.fit(
            "[bold cyan]Kimi Ecosystem Convergence Demo[/bold cyan]\n"
            "[dim]Security Assessment Against Vulnerable Infrastructure[/dim]",
            border_style="cyan"
        ))
        
        console.print(f"\n[blue]Target Infrastructure:[/blue] {len(TARGETS)} servers")
        for t in TARGETS:
            console.print(f"  • [yellow]{t['name']}[/yellow] ({t['ip']}) - {t['type']}")
        
        console.print("")
        
        # Scan each target
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("[cyan]Scanning infrastructure...", total=len(TARGETS))
            
            for target in TARGETS:
                progress.update(task, description=f"[cyan]Scanning {target['name']}...[/cyan]")
                
                result = await self.scan_target(target)
                self.result.add_target_result(target, result)
                
                if result:
                    summary = result.get_summary()
                    total = sum(summary.values())
                    progress.console.print(
                        f"  [green]✓[/green] {target['name']}: {total} findings "
                        f"([red]{summary.get('critical', 0)} critical[/red], "
                        f"[orange]{summary.get('high', 0)} high[/orange])"
                    )
                else:
                    progress.console.print(f"  [red]✗[/red] {target['name']}: Scan failed")
                
                progress.advance(task)
        
        self.result.end_time = datetime.now(timezone.utc)
        return self.result
    
    def display_results(self) -> None:
        """Display scan results in a clean format."""
        console.print("\n[bold cyan]╔══════════════════════════════════════════════════════════════╗[/bold cyan]")
        console.print("[bold cyan]║                 CONVERGENCE DEMO RESULTS                     ║[/bold cyan]")
        console.print("[bold cyan]╚══════════════════════════════════════════════════════════════╝[/bold cyan]")
        
        # Overall Summary Table
        summary = self.result.get_overall_summary()
        risk_score = self.result.get_risk_score()
        risk_level = self.result.get_risk_level()
        
        console.print(f"\n[bold]Overall Risk Score:[/bold] [red]{risk_score}/100[/red] ({risk_level})")
        
        table = Table(title="Findings Summary by Target")
        table.add_column("Target", style="cyan")
        table.add_column("Type", style="dim")
        table.add_column("Critical", style="red", justify="right")
        table.add_column("High", style="orange", justify="right")
        table.add_column("Medium", style="yellow", justify="right")
        table.add_column("Low", style="green", justify="right")
        table.add_column("Info", style="blue", justify="right")
        table.add_column("Total", style="bold", justify="right")
        
        for tr in self.result.target_results:
            target = tr["target"]
            s = tr["summary"] or {}
            total = sum(s.values()) if s else 0
            
            table.add_row(
                target["name"],
                target["type"],
                str(s.get("critical", 0)),
                str(s.get("high", 0)),
                str(s.get("medium", 0)),
                str(s.get("low", 0)),
                str(s.get("info", 0)),
                str(total)
            )
        
        # Add totals row
        table.add_row(
            "[bold]TOTAL[/bold]", "",
            f"[bold red]{summary.get('critical', 0)}[/bold red]",
            f"[bold orange]{summary.get('high', 0)}[/bold orange]",
            f"[bold yellow]{summary.get('medium', 0)}[/bold yellow]",
            f"[bold green]{summary.get('low', 0)}[/bold green]",
            f"[bold blue]{summary.get('info', 0)}[/bold blue]",
            f"[bold]{sum(summary.values())}[/bold]",
            end_section=True
        )
        
        console.print(table)
        
        # Detailed Findings
        if self.result.aggregated_findings:
            console.print("\n[bold]Detailed Findings:[/bold]")
            
            findings_table = Table()
            findings_table.add_column("Severity", style="bold")
            findings_table.add_column("Type")
            findings_table.add_column("Target")
            findings_table.add_column("Description")
            
            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(
                self.result.aggregated_findings,
                key=lambda f: severity_order.get(f.severity.value, 5)
            )
            
            for finding in sorted_findings[:20]:  # Show top 20
                severity_color = {
                    "critical": "red",
                    "high": "orange",
                    "medium": "yellow",
                    "low": "green",
                    "info": "blue"
                }.get(finding.severity.value, "white")
                
                findings_table.add_row(
                    f"[{severity_color}]{finding.severity.value.upper()}[/{severity_color}]",
                    finding.finding_type,
                    finding.target[:40],
                    finding.description[:60] + "..." if len(finding.description) > 60 else finding.description
                )
            
            console.print(findings_table)
    
    def generate_report(self) -> str:
        """Generate executive summary report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_file = self.report_dir / f"convergence_demo_report_{timestamp}.md"
        
        # Load template
        template_path = Path(__file__).parent / "report_template.md"
        if template_path.exists():
            with open(template_path) as f:
                template = f.read()
        else:
            template = self._get_default_template()
        
        # Prepare data
        summary = self.result.get_overall_summary()
        risk_score = self.result.get_risk_score()
        risk_level = self.result.get_risk_level()
        
        # Build findings by severity
        findings_by_severity = {s.value: [] for s in Severity}
        for finding in self.result.aggregated_findings:
            findings_by_severity[finding.severity.value].append(finding)
        
        # Format findings for report
        def format_findings(severity: str) -> str:
            findings = findings_by_severity.get(severity, [])
            if not findings:
                return "_No findings at this severity level._\n"
            
            lines = []
            for i, f in enumerate(findings[:10], 1):  # Top 10 per severity
                lines.append(f"""
**{i}. {f.title}**
- **Target:** {f.target}
- **Type:** {f.finding_type}
- **Description:** {f.description}
- **Evidence:** {f.evidence or 'N/A'}
- **Remediation:** {f.remediation or 'See general recommendations'}
""")
            return "\n".join(lines)
        
        # Target details
        target_details = []
        for tr in self.result.target_results:
            t = tr["target"]
            s = tr["summary"] or {}
            target_details.append(f"""
### {t['name']} ({t['ip']})
- **Type:** {t['type']}
- **URL:** {t['url']}
- **Description:** {t['description']}
- **Findings:** {sum(s.values()) if s else 0} total
  - Critical: {s.get('critical', 0)}
  - High: {s.get('high', 0)}
  - Medium: {s.get('medium', 0)}
  - Low: {s.get('low', 0)}
""")
        
        # Fill template
        report = template.format(
            report_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            risk_score=risk_score,
            risk_level=risk_level,
            total_findings=sum(summary.values()),
            critical_count=summary.get('critical', 0),
            high_count=summary.get('high', 0),
            medium_count=summary.get('medium', 0),
            low_count=summary.get('low', 0),
            info_count=summary.get('info', 0),
            target_count=len(TARGETS),
            target_details="\n".join(target_details),
            critical_findings=format_findings('critical'),
            high_findings=format_findings('high'),
            medium_findings=format_findings('medium'),
            low_findings=format_findings('low'),
            info_findings=format_findings('info'),
            scan_duration=str(self.result.end_time - self.result.start_time) if self.result.end_time else "N/A"
        )
        
        # Write report
        with open(report_file, 'w') as f:
            f.write(report)
        
        return str(report_file)
    
    def _get_default_template(self) -> str:
        """Get default report template if file not found."""
        return """# Security Assessment Report

**Date:** {report_date}
**Assessment Type:** Convergence Loop Demo
**Targets:** {target_count} servers

## Executive Summary

This report presents the findings from an automated security assessment conducted using the Kimi Security Auditor against a vulnerable infrastructure deployment.

### Risk Overview

| Metric | Value |
|--------|-------|
| **Overall Risk Score** | {risk_score}/100 ({risk_level}) |
| **Total Findings** | {total_findings} |
| **Critical** | {critical_count} |
| **High** | {high_count} |
| **Medium** | {medium_count} |
| **Low** | {low_count} |
| **Info** | {info_count} |

## Target Infrastructure

{target_details}

## Findings by Severity

### 🔴 Critical

{critical_findings}

### 🟠 High

{high_findings}

### 🟡 Medium

{medium_findings}

### 🟢 Low

{low_findings}

### 🔵 Informational

{info_findings}

## Remediation Timeline

| Priority | Timeline | Findings |
|----------|----------|----------|
| Critical | Immediate (24 hours) | {critical_count} |
| High | Short-term (1 week) | {high_count} |
| Medium | Medium-term (1 month) | {medium_count} |
| Low | Long-term (3 months) | {low_count} |

## Compliance Mapping

### OWASP Top 10 2021
- **A01:2021-Broken Access Control** - Multiple IDOR findings
- **A03:2021-Injection** - SQL Injection, Command Injection
- **A05:2021-Security Misconfiguration** - Missing security headers, CORS issues
- **A07:2021-Identification and Authentication Failures** - Weak authentication

### PCI DSS 4.0
- **Requirement 6.5** - Address common coding vulnerabilities
- **Requirement 11.3** - Vulnerability scanning

## Appendix

**Scan Duration:** {scan_duration}
**Tool:** Kimi Security Auditor v0.2.0
"""
    
    def generate_json_report(self) -> str:
        """Generate JSON format report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_file = self.report_dir / f"convergence_demo_report_{timestamp}.json"
        
        data = {
            "metadata": {
                "report_date": datetime.now(timezone.utc).isoformat(),
                "tool": "Kimi Security Auditor",
                "version": "0.2.0",
                "scan_duration": str(self.result.end_time - self.result.start_time) if self.result.end_time else None
            },
            "summary": {
                "risk_score": self.result.get_risk_score(),
                "risk_level": self.result.get_risk_level(),
                "total_findings": len(self.result.aggregated_findings),
                "by_severity": self.result.get_overall_summary()
            },
            "targets": [
                {
                    "name": tr["target"]["name"],
                    "ip": tr["target"]["ip"],
                    "type": tr["target"]["type"],
                    "url": tr["target"]["url"],
                    "summary": tr["summary"]
                }
                for tr in self.result.target_results
            ],
            "findings": [f.to_dict() for f in self.result.aggregated_findings]
        }
        
        with open(report_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        return str(report_file)


def main():
    parser = argparse.ArgumentParser(
        description="Kimi Ecosystem Convergence Demo - Security Assessment"
    )
    parser.add_argument(
        "--report-dir",
        default="reports",
        help="Directory for output reports (default: reports)"
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json", "both"],
        default="both",
        help="Output format (default: both)"
    )
    parser.add_argument(
        "--no-display",
        action="store_true",
        help="Skip console display of results"
    )
    
    args = parser.parse_args()
    
    # Run demo
    demo = ConvergenceDemo(report_dir=args.report_dir, output_format=args.format)
    
    try:
        asyncio.run(demo.run_convergence_loop())
        
        if not args.no_display:
            demo.display_results()
        
        # Generate reports
        generated = []
        if args.format in ("markdown", "both"):
            md_path = demo.generate_report()
            generated.append(f"Markdown: {md_path}")
        
        if args.format in ("json", "both"):
            json_path = demo.generate_json_report()
            generated.append(f"JSON: {json_path}")
        
        console.print("\n[bold green]Reports generated:[/bold green]")
        for g in generated:
            console.print(f"  📄 {g}")
        
        console.print("\n[bold cyan]Convergence Demo Complete![/bold cyan]")
        
        # Exit with error code if critical findings
        summary = demo.result.get_overall_summary()
        if summary.get('critical', 0) > 0:
            console.print("\n[red]⚠️  Critical vulnerabilities detected![/red]")
            sys.exit(1)
        
        sys.exit(0)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Demo interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
