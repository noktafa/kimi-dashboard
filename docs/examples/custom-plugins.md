# Custom Plugins Guide

## Overview

The Kimi Ecosystem supports custom plugins to extend functionality. This guide shows you how to create and integrate custom plugins.

## Plugin Architecture

```
my-kimi-plugin/
├── pyproject.toml
├── README.md
└── my_plugin/
    ├── __init__.py
    ├── scanner.py      # Custom scanner
    ├── executor.py     # Custom executor
    └── reporter.py     # Custom reporter
```

## Creating a Custom Scanner

### Plugin Structure

```python
# my_plugin/scanner.py
from kimi_security_auditor.attacks import BaseScanner
from kimi_security_auditor.models import Finding, Severity, Confidence
import httpx

class CustomVulnerabilityScanner(BaseScanner):
    """Custom scanner for specific vulnerability type."""
    
    def __init__(self, client: httpx.AsyncClient):
        super().__init__(client)
        self.name = "Custom Vulnerability Scanner"
    
    async def scan_url(self, url: str, parameters: list = None) -> list:
        """Scan URL for custom vulnerability."""
        findings = []
        
        # Your scanning logic here
        response = await self.client.get(url)
        
        if self.detect_vulnerability(response):
            finding = Finding(
                title="Custom Vulnerability Detected",
                description="Description of the vulnerability",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                target=url,
                finding_type="custom_vuln",
                evidence="Evidence of vulnerability",
                remediation="How to fix this vulnerability"
            )
            findings.append(finding)
        
        return findings
    
    def detect_vulnerability(self, response: httpx.Response) -> bool:
        """Detect if response indicates vulnerability."""
        # Your detection logic
        return "vulnerable-indicator" in response.text
```

### Registering the Scanner

```python
# my_plugin/__init__.py
from kimi_security_auditor import register_scanner
from .scanner import CustomVulnerabilityScanner

def register():
    """Register custom scanner with the security auditor."""
    register_scanner("custom", CustomVulnerabilityScanner)

__all__ = ["register", "CustomVulnerabilityScanner"]
```

### Using the Custom Scanner

```python
# Usage in your code
from kimi_security_auditor import SecurityAuditor
from my_plugin import CustomVulnerabilityScanner

async def scan_with_custom():
    auditor = SecurityAuditor("https://example.com")
    
    # Add custom scanner
    auditor.add_scanner(CustomVulnerabilityScanner)
    
    result = await auditor.run()
    return result
```

## Creating a Custom Executor

### Executor Implementation

```python
# my_plugin/executor.py
from kimi_sysadmin_ai.executors.base import BaseExecutor
from kimi_sysadmin_ai.safety import SafetyFilter
from dataclasses import dataclass

@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    returncode: int
    duration: float

class CustomExecutor(BaseExecutor):
    """Custom executor for specific environment."""
    
    def __init__(self, safety_filter: SafetyFilter, config: dict):
        super().__init__(safety_filter)
        self.config = config
        self.name = "Custom Executor"
    
    async def execute(self, command: str, **kwargs) -> ExecutionResult:
        """Execute command in custom environment."""
        
        # Pre-execution setup
        await self.setup_environment()
        
        # Execute with safety checks
        safety_result = self.safety_filter.check(command)
        if safety_result.level.value == "block":
            raise SecurityError(f"Command blocked: {safety_result.reason}")
        
        # Your execution logic
        result = await self.run_in_custom_env(command)
        
        # Post-execution cleanup
        await self.cleanup()
        
        return result
    
    async def setup_environment(self):
        """Setup custom execution environment."""
        pass
    
    async def run_in_custom_env(self, command: str) -> ExecutionResult:
        """Run command in custom environment."""
        # Implementation here
        pass
    
    async def cleanup(self):
        """Cleanup after execution."""
        pass
```

## Creating a Custom Reporter

### Reporter Implementation

```python
# my_plugin/reporter.py
from kimi_security_auditor.models import ScanResult
from abc import ABC, abstractmethod

class BaseReporter(ABC):
    """Base class for custom reporters."""
    
    @abstractmethod
    def generate(self, result: ScanResult) -> str:
        """Generate report from scan result."""
        pass

class XMLReporter(BaseReporter):
    """Generate XML report."""
    
    def generate(self, result: ScanResult) -> str:
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<security-report>',
            f'  <target>{self.escape_xml(result.target)}</target>',
            f'  <start-time>{result.start_time.isoformat()}</start-time>',
            '  <findings>'
        ]
        
        for finding in result.findings:
            lines.extend([
                '    <finding>',
                f'      <title>{self.escape_xml(finding.title)}</title>',
                f'      <severity>{finding.severity.value}</severity>',
                f'      <description>{self.escape_xml(finding.description)}</description>',
                '    </finding>'
            ])
        
        lines.extend([
            '  </findings>',
            '</security-report>'
        ])
        
        return '\n'.join(lines)
    
    def escape_xml(self, text: str) -> str:
        """Escape XML special characters."""
        return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
```

## Creating a Custom Pipeline Step

### Step Implementation

```python
# my_plugin/step.py
from kimi_convergence_loop.steps import Step, StepResult
from dataclasses import dataclass, field

@dataclass
class CustomStepResult(StepResult):
    custom_data: dict = field(default_factory=dict)

class CustomStep(Step):
    """Custom pipeline step."""
    
    def __init__(self, config: dict, event_bus):
        super().__init__("custom", config, event_bus)
    
    async def execute(self, context: dict) -> CustomStepResult:
        """Execute custom step logic."""
        
        # Emit start event
        await self.emit_start()
        
        try:
            # Your custom logic
            result_data = await self.process(context)
            
            # Create result
            step_result = CustomStepResult(
                step_name=self.name,
                success=True,
                custom_data=result_data
            )
            
            # Emit completion
            await self.emit_complete(step_result)
            
            return step_result
            
        except Exception as e:
            # Emit failure
            await self.emit_failed(str(e))
            raise
    
    async def process(self, context: dict) -> dict:
        """Process context and return results."""
        # Your processing logic
        return {"processed": True}
```

## Packaging Your Plugin

### pyproject.toml

```toml
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "my-kimi-plugin"
version = "0.1.0"
description = "Custom plugin for Kimi Ecosystem"
readme = "README.md"
requires-python = ">=3.9"
license = {text = "MIT"}
authors = [
    {name = "Your Name", email = "you@example.com"}
]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
]
dependencies = [
    "kimi-security-auditor>=0.1.0",
    "httpx>=0.24.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-asyncio>=0.21.0",
    "black>=23.0.0",
    "ruff>=0.1.0",
]

[project.entry-points."kimi.plugins"]
my_plugin = "my_plugin:register"

[tool.setuptools.packages.find]
where = ["."]
include = ["my_plugin*"]
```

## Installing and Using Plugins

### Installation

```bash
# Install from PyPI
pip install my-kimi-plugin

# Or install from source
cd my-kimi-plugin
pip install -e .
```

### Configuration

```yaml
# convergence.yaml
steps:
  custom:
    enabled: true
    plugin: my_plugin
    config:
      custom_option: value
```

### Runtime Registration

```python
# Register plugin programmatically
from my_plugin import register
from kimi_security_auditor import SecurityAuditor

# Register plugin
register()

# Use in auditor
auditor = SecurityAuditor("https://example.com")
```

## Best Practices

1. **Error Handling**: Always handle exceptions gracefully
2. **Logging**: Use proper logging for debugging
3. **Configuration**: Make your plugin configurable
4. **Documentation**: Document all configuration options
5. **Testing**: Write comprehensive tests
6. **Versioning**: Follow semantic versioning

## Example: Complete Plugin

See the [example-plugin](https://github.com/kimi-ecosystem/example-plugin) repository for a complete working example.
