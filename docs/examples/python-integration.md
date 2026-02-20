# Python Integration Examples

## Overview

This guide demonstrates how to use the Kimi Ecosystem libraries directly in your Python applications.

## Table of Contents

1. [Basic Integration](#basic-integration)
2. [Security Auditor Integration](#security-auditor-integration)
3. [Sysadmin AI Integration](#sysadmin-ai-integration)
4. [Convergence Loop Integration](#convergence-loop-integration)
5. [Dashboard Integration](#dashboard-integration)
6. [Combined Workflows](#combined-workflows)

## Basic Integration

### Installation

```bash
# Install all components
pip install kimi-security-auditor kimi-sysadmin-ai kimi-convergence-loop kimi-dashboard

# Or install individually
pip install kimi-security-auditor
pip install kimi-sysadmin-ai
```

### Import Structure

```python
# Security Auditor
from kimi_security_auditor import SecurityAuditor
from kimi_security_auditor.models import Finding, Severity, ScanResult
from kimi_security_auditor.attacks import SQLInjectionScanner, JWTScanner

# Sysadmin AI
from kimi_sysadmin_ai import SafetyFilter, PolicyEngine, HostExecutor
from kimi_sysadmin_ai.safety import SafetyLevel

# Convergence Loop
from kimi_convergence_loop import Pipeline, Config, EventBus
from kimi_convergence_loop.steps import DiagnoseStep, FixStep

# Dashboard
from kimi_dashboard import DashboardClient, WebSocketClient
```

## Security Auditor Integration

### Basic Scanning

```python
import asyncio
from kimi_security_auditor import SecurityAuditor

async def basic_scan():
    """Run a basic security scan."""
    auditor = SecurityAuditor("https://example.com")
    result = await auditor.run()
    
    print(f"Scan completed: {result.target}")
    print(f"Duration: {result.duration_seconds:.2f}s")
    print(f"Findings: {len(result.findings)}")
    
    # Group by severity
    summary = result.get_summary()
    for severity, count in summary.items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    return result

# Run
asyncio.run(basic_scan())
```

### Custom Scan Configuration

```python
from kimi_security_auditor import SecurityAuditor
import httpx

async def custom_scan():
    """Scan with custom configuration."""
    
    # Custom HTTP client with authentication
    headers = {
        "Authorization": "Bearer token123",
        "X-Custom-Header": "value"
    }
    
    async with httpx.AsyncClient(headers=headers) as client:
        auditor = SecurityAuditor(
            target="https://api.example.com",
            client=client,
            timeout=60.0,
            max_depth=5,
            concurrency=20
        )
        
        # Run specific scans
        result = await auditor.run()
        
        # Filter findings
        critical = result.get_findings_by_severity(Severity.CRITICAL)
        print(f"Critical findings: {len(critical)}")
        
        return result
```

### Batch Scanning

```python
import asyncio
from kimi_security_auditor import SecurityAuditor

async def scan_multiple(targets: list[str]) -> list:
    """Scan multiple targets concurrently."""
    
    async def scan_one(target: str):
        auditor = SecurityAuditor(target)
        return await auditor.run()
    
    # Run all scans concurrently
    results = await asyncio.gather(
        *[scan_one(t) for t in targets],
        return_exceptions=True
    )
    
    # Process results
    for target, result in zip(targets, results):
        if isinstance(result, Exception):
            print(f"❌ {target}: {result}")
        else:
            print(f"✅ {target}: {len(result.findings)} findings")
    
    return results

# Usage
targets = [
    "https://app1.example.com",
    "https://app2.example.com",
    "https://api.example.com"
]
asyncio.run(scan_multiple(targets))
```

### Custom Reporter

```python
from kimi_security_auditor.models import ScanResult
import json

class JSONReporter:
    """Custom JSON reporter."""
    
    def generate(self, result: ScanResult) -> str:
        report = {
            "scan_info": {
                "target": result.target,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None,
            },
            "summary": result.get_summary(),
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "target": f.target,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in result.findings
            ]
        }
        return json.dumps(report, indent=2)

# Usage
async def generate_report():
    auditor = SecurityAuditor("https://example.com")
    result = await auditor.run()
    
    reporter = JSONReporter()
    report = reporter.generate(result)
    
    with open("report.json", "w") as f:
        f.write(report)
```

## Sysadmin AI Integration

### Safe Command Execution

```python
import asyncio
from kimi_sysadmin_ai import HostExecutor, SafetyFilter

async def safe_administration():
    """Execute commands safely."""
    
    executor = HostExecutor(require_confirmation=True)
    
    # Safe command - executes immediately
    result = await executor.execute("ls -la")
    print(f"Output: {result.stdout}")
    
    # Gray command - requires confirmation
    # result = await executor.execute("apt update")
    # Will prompt: "Execute? [y/N]:"
    
    # Blocked command - raises exception
    try:
        await executor.execute("rm -rf /")
    except Exception as e:
        print(f"Blocked: {e}")

asyncio.run(safe_administration())
```

### Batch Command Execution

```python
from kimi_sysadmin_ai import HostExecutor

async def run_playbook(commands: list[str]):
    """Execute a playbook of commands."""
    
    executor = HostExecutor()
    results = []
    
    for cmd in commands:
        print(f"Running: {cmd}")
        
        # Check safety before execution
        safety, policy = executor.check(cmd)
        
        if safety.level.value == "block":
            print(f"  ❌ Blocked: {safety.reason}")
            continue
        
        if safety.level.value == "gray":
            print(f"  ⚠️  Requires confirmation: {safety.reason}")
            # In automation, you might skip or have pre-approval
            continue
        
        # Execute
        result = await executor.execute(cmd)
        results.append({
            "command": cmd,
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr
        })
        
        if result.returncode != 0:
            print(f"  ❌ Failed: {result.stderr}")
        else:
            print(f"  ✅ Success")
    
    return results

# Usage
playbook = [
    "pwd",
    "ls -la",
    "df -h",
    "whoami"
]
asyncio.run(run_playbook(playbook))
```

### Custom Policy Enforcement

```python
from kimi_sysadmin_ai import PolicyEngine, PolicyInput

class ProductionPolicy:
    """Strict policy for production environment."""
    
    def __init__(self):
        self.engine = PolicyEngine()
        self.allowed_readonly = [
            "ls", "cat", "grep", "ps", "df", "du",
            "top", "htop", "free", "uptime", "whoami"
        ]
    
    async def can_execute(self, command: str, user: str) -> bool:
        """Check if command is allowed in production."""
        
        input_data = PolicyInput(
            command=command,
            user=user,
            working_dir="/app",
            environment={"ENV": "production"},
            executor_type="host"
        )
        
        result = self.engine.evaluate(input_data)
        
        # Additional production checks
        if result.decision.value == "allow":
            # Still check against readonly list for extra safety
            cmd_base = command.split()[0]
            if cmd_base not in self.allowed_readonly:
                return False
        
        return result.decision.value == "allow"

# Usage
policy = ProductionPolicy()
can_run = asyncio.run(policy.can_execute("ls -la", "deploy"))
print(f"Can execute: {can_run}")
```

## Convergence Loop Integration

### Basic Pipeline

```python
import asyncio
from kimi_convergence_loop import Pipeline, Config, load_config

async def run_basic_pipeline():
    """Run a basic convergence pipeline."""
    
    # Create configuration
    config = Config(
        target="https://example.com",
        loop={
            "max_iterations": 5,
            "convergence_threshold": 0.95,
            "timeout_seconds": 1800,
            "backoff_seconds": 5
        },
        steps={
            "diagnose": {
                "enabled": True,
                "tool": "kimi-security-auditor",
                "args": []
            },
            "fix": {
                "enabled": True,
                "tool": "kimi-sysadmin-ai",
                "args": []
            },
            "attack": {
                "enabled": True,
                "tool": "kimi-security-auditor",
                "args": ["--attack-mode"]
            },
            "validate": {
                "enabled": True,
                "tool": "pytest",
                "args": ["-v"]
            }
        }
    )
    
    # Create and run pipeline
    pipeline = Pipeline(config)
    result = await pipeline.run()
    
    # Report results
    print(f"Success: {result.success}")
    print(f"Iterations: {result.iterations}")
    print(f"Converged: {result.convergence_reached}")
    print(f"Duration: {result.duration_seconds:.2f}s")
    
    return result

asyncio.run(run_basic_pipeline())
```

### Event-Driven Pipeline

```python
from kimi_convergence_loop import Pipeline, Config, EventBus, EventType

async def monitored_pipeline():
    """Pipeline with event monitoring."""
    
    # Create event bus
    bus = EventBus()
    
    # Register event handlers
    @bus.register_handler
    async def on_iteration_start(event):
        if event.event_type == EventType.ITERATION_STARTED:
            print(f"\n🔄 Iteration {event.iteration} started")
    
    @bus.register_handler
    async def on_step_complete(event):
        if event.event_type == EventType.STEP_COMPLETE:
            step = event.data.get("step")
            print(f"  ✅ {step} complete")
    
    @bus.register_handler
    async def on_convergence(event):
        if event.event_type == EventType.CONVERGENCE_REACHED:
            print(f"\n🎉 Converged after {event.iteration} iterations!")
    
    # Create pipeline with event bus
    config = Config.load("convergence.yaml")
    pipeline = Pipeline(config, event_bus=bus)
    
    # Run
    result = await pipeline.run()
    return result
```

### Custom Step Implementation

```python
from kimi_convergence_loop.steps import Step, StepResult
from dataclasses import dataclass, field
from typing import List

@dataclass
class CustomStepResult(StepResult):
    custom_data: dict = field(default_factory=dict)

class NotificationStep(Step):
    """Send notifications after each iteration."""
    
    def __init__(self, config, event_bus, webhook_url: str):
        super().__init__("notify", config, event_bus)
        self.webhook_url = webhook_url
    
    async def execute(self, context: dict) -> CustomStepResult:
        await self.emit_start()
        
        # Send notification
        import httpx
        async with httpx.AsyncClient() as client:
            await client.post(
                self.webhook_url,
                json={
                    "message": f"Iteration {context.get('iteration', 0)} complete",
                    "findings": len(context.get("findings", [])),
                    "fixes": len(context.get("fixes", []))
                }
            )
        
        result = CustomStepResult(
            step_name=self.name,
            success=True,
            custom_data={"notified": True}
        )
        
        await self.emit_complete(result)
        return result
```

## Dashboard Integration

### Real-Time Monitoring

```python
import asyncio
from kimi_dashboard import WebSocketClient, EventType

class PipelineMonitor(WebSocketClient):
    """Monitor pipeline execution in real-time."""
    
    def __init__(self):
        super().__init__("ws://localhost:8766")
        self.findings = []
        self.current_iteration = 0
    
    async def on_event(self, event):
        """Handle incoming events."""
        
        if event.event_type == EventType.ITERATION_STARTED:
            self.current_iteration = event.iteration
            print(f"\n{'='*50}")
            print(f"Iteration {self.current_iteration}")
            print('='*50)
        
        elif event.event_type == EventType.STEP_STARTED:
            step = event.data.get("step")
            print(f"\n▶️  {step}...")
        
        elif event.event_type == EventType.STEP_COMPLETE:
            step = event.data.get("step")
            print(f"✅ {step} complete")
            
            if step == "diagnose":
                findings = event.data.get("findings", [])
                print(f"   Found {len(findings)} issues")
        
        elif event.event_type == EventType.CONVERGENCE_REACHED:
            print(f"\n🎉 CONVERGENCE REACHED!")
            print(f"   Total iterations: {event.iteration}")
    
    async def on_connect(self):
        print("Connected to dashboard")
        await self.subscribe(["*"])
    
    async def on_disconnect(self):
        print("Disconnected from dashboard")

# Usage
async def monitor():
    client = PipelineMonitor()
    await client.connect()
    await client.run_forever()

asyncio.run(monitor())
```

### Historical Data Analysis

```python
from kimi_dashboard import DashboardClient
import pandas as pd

async def analyze_history():
    """Analyze historical pipeline runs."""
    
    client = DashboardClient("http://localhost:8766")
    
    # Get all sessions
    sessions = await client.list_sessions(limit=100)
    
    # Convert to DataFrame for analysis
    data = []
    for session in sessions:
        metrics = await client.get_session_metrics(session.session_id)
        data.append({
            "session_id": session.session_id,
            "start_time": session.start_time,
            "duration": metrics.duration_seconds,
            "iterations": metrics.iterations,
            "total_findings": sum(metrics.findings_per_iteration),
            "converged": session.status == "converged"
        })
    
    df = pd.DataFrame(data)
    
    # Analysis
    print(f"Total sessions: {len(df)}")
    print(f"Convergence rate: {df['converged'].mean():.1%}")
    print(f"Average iterations: {df['iterations'].mean():.1f}")
    print(f"Average duration: {df['duration'].mean():.0f}s")
    
    return df
```

## Combined Workflows

### Complete Security Workflow

```python
import asyncio
from datetime import datetime
from kimi_security_auditor import SecurityAuditor
from kimi_sysadmin_ai import HostExecutor
from kimi_convergence_loop import Pipeline, Config

class SecurityWorkflow:
    """Complete security scanning and remediation workflow."""
    
    def __init__(self, target: str):
        self.target = target
        self.findings_history = []
    
    async def scan(self) -> list:
        """Run security scan."""
        print(f"\n🔍 Scanning {self.target}...")
        
        auditor = SecurityAuditor(self.target)
        result = await auditor.run()
        
        self.findings_history.append({
            "timestamp": datetime.now(),
            "findings": result.findings
        })
        
        print(f"Found {len(result.findings)} issues")
        return result.findings
    
    async def remediate(self, findings: list) -> list:
        """Apply fixes for findings."""
        print(f"\n🔧 Applying fixes...")
        
        executor = HostExecutor(require_confirmation=False)
        fixes_applied = []
        
        for finding in findings:
            if finding.remediation:
                # Parse remediation into commands
                # This is simplified - real implementation would be smarter
                print(f"  Fixing: {finding.title}")
                fixes_applied.append(finding.title)
        
        return fixes_applied
    
    async def verify(self) -> bool:
        """Verify fixes by re-scanning."""
        print(f"\n✅ Verifying fixes...")
        
        new_findings = await self.scan()
        
        # Check if critical findings remain
        from kimi_security_auditor.models import Severity
        critical = [f for f in new_findings if f.severity == Severity.CRITICAL]
        
        return len(critical) == 0
    
    async def run(self, max_iterations: int = 3):
        """Run complete workflow."""
        
        for iteration in range(1, max_iterations + 1):
            print(f"\n{'='*60}")
            print(f"Iteration {iteration}/{max_iterations}")
            print('='*60)
            
            # Scan
            findings = await self.scan()
            
            if not findings:
                print("\n🎉 No issues found!")
                break
            
            # Remediate
            fixes = await self.remediate(findings)
            
            # Verify
            if await self.verify():
                print("\n🎉 All critical issues resolved!")
                break
        
        return self.findings_history

# Usage
async def main():
    workflow = SecurityWorkflow("https://example.com")
    history = await workflow.run()
    
    print(f"\n{'='*60}")
    print("WORKFLOW COMPLETE")
    print('='*60)
    print(f"Total scans: {len(history)}")

asyncio.run(main())
```

### CI/CD Integration

```python
import asyncio
import sys
from kimi_security_auditor import SecurityAuditor
from kimi_security_auditor.models import Severity

async def ci_security_check():
    """Security check for CI/CD pipeline."""
    
    target = sys.argv[1] if len(sys.argv) > 1 else "https://staging.example.com"
    
    print(f"🔍 Running security check on {target}...")
    
    auditor = SecurityAuditor(target)
    result = await auditor.run()
    
    # Check for blocking issues
    critical = result.get_findings_by_severity(Severity.CRITICAL)
    high = result.get_findings_by_severity(Severity.HIGH)
    
    print(f"\nFindings Summary:")
    print(f"  Critical: {len(critical)}")
    print(f"  High: {len(high)}")
    print(f"  Medium: {len(result.get_findings_by_severity(Severity.MEDIUM))}")
    print(f"  Low: {len(result.get_findings_by_severity(Severity.LOW))}")
    
    # Fail build if critical issues found
    if critical:
        print(f"\n❌ CRITICAL ISSUES FOUND - Blocking deployment")
        for finding in critical:
            print(f"  - {finding.title}: {finding.description[:100]}...")
        sys.exit(1)
    
    if high:
        print(f"\n⚠️  HIGH severity issues found - Review required")
    
    print(f"\n✅ Security check passed")
    
    # Save report
    report = result.to_json(indent=2)
    with open("security-report.json", "w") as f:
        f.write(report)
    print(f"Report saved to security-report.json")

if __name__ == "__main__":
    asyncio.run(ci_security_check())
```

### Scheduled Monitoring

```python
import asyncio
from datetime import datetime, timedelta
from kimi_security_auditor import SecurityAuditor
from kimi_dashboard import DashboardClient

class ScheduledMonitor:
    """Scheduled security monitoring."""
    
    def __init__(self, targets: list[str], interval_hours: int = 24):
        self.targets = targets
        self.interval = timedelta(hours=interval_hours)
        self.dashboard = DashboardClient("http://localhost:8766")
    
    async def check_target(self, target: str):
        """Check a single target."""
        print(f"[{datetime.now()}] Checking {target}...")
        
        auditor = SecurityAuditor(target)
        result = await auditor.run()
        
        # Report findings
        if result.findings:
            await self.report_findings(target, result.findings)
        
        return result
    
    async def report_findings(self, target: str, findings: list):
        """Report findings to dashboard and alert if needed."""
        
        # Send to dashboard
        await self.dashboard.submit_findings(target, findings)
        
        # Alert on critical
        from kimi_security_auditor.models import Severity
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        
        if critical:
            await self.send_alert(target, critical)
    
    async def send_alert(self, target: str, findings: list):
        """Send alert for critical findings."""
        # Implementation depends on your alerting system
        print(f"🚨 ALERT: {len(findings)} critical findings on {target}")
    
    async def run(self):
        """Run monitoring loop."""
        
        while True:
            print(f"\n{'='*60}")
            print(f"Monitoring run at {datetime.now()}")
            print('='*60)
            
            for target in self.targets:
                try:
                    await self.check_target(target)
                except Exception as e:
                    print(f"Error checking {target}: {e}")
            
            # Wait for next interval
            next_run = datetime.now() + self.interval
            print(f"\nNext run at {next_run}")
            await asyncio.sleep(self.interval.total_seconds())

# Usage
async def main():
    monitor = ScheduledMonitor(
        targets=[
            "https://app1.example.com",
            "https://app2.example.com",
            "https://api.example.com"
        ],
        interval_hours=24
    )
    
    await monitor.run()

asyncio.run(main())
```
