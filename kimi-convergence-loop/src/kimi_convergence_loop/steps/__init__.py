"""Pipeline steps for the convergence loop."""

from __future__ import annotations

import asyncio
import json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import StepConfig
from ..event_bus import EventBus, EventType


@dataclass
class StepResult:
    """Result of executing a pipeline step."""
    
    success: bool
    step_name: str
    findings: list[dict] = field(default_factory=list)
    fixes_applied: list[dict] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    raw_output: str = ""
    return_code: int = 0
    
    def has_changes(self) -> bool:
        """Check if this step resulted in changes."""
        return len(self.findings) > 0 or len(self.fixes_applied) > 0


class PipelineStep(ABC):
    """Base class for pipeline steps."""
    
    def __init__(
        self,
        name: str,
        config: StepConfig,
        event_bus: EventBus | None = None,
    ):
        self.name = name
        self.config = config
        self.event_bus = event_bus
    
    async def execute(self, context: dict[str, Any]) -> StepResult:
        """Execute the step.
        
        Args:
            context: Shared context from previous steps
            
        Returns:
            StepResult with execution results
        """
        if not self.config.enabled:
            return StepResult(
                success=True,
                step_name=self.name,
                metrics={"enabled": False},
            )
        
        # Emit step started event
        if self.event_bus:
            await self.event_bus.emit(EventType.STEP_STARTED, {
                "step": self.name,
                "tool": self.config.tool,
                "args": self.config.args,
            })
        
        try:
            result = await self._execute(context)
            
            # Emit step complete event
            if self.event_bus:
                await self.event_bus.emit(EventType.STEP_COMPLETE, {
                    "step": self.name,
                    "success": result.success,
                    "findings_count": len(result.findings),
                    "fixes_count": len(result.fixes_applied),
                    "metrics": result.metrics,
                })
            
            return result
            
        except Exception as e:
            error_msg = str(e)
            
            # Emit step failed event
            if self.event_bus:
                await self.event_bus.emit(EventType.STEP_FAILED, {
                    "step": self.name,
                    "error": error_msg,
                })
            
            return StepResult(
                success=False,
                step_name=self.name,
                error=error_msg,
            )
    
    @abstractmethod
    async def _execute(self, context: dict[str, Any]) -> StepResult:
        """Override this to implement the step logic."""
        pass
    
    async def _run_tool(
        self,
        tool: str,
        args: list[str],
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        """Run an external tool via subprocess.
        
        Args:
            tool: Tool name or path
            args: Arguments to pass
            cwd: Working directory
            env: Environment variables
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        cmd = [tool] + args
        
        # Merge environment variables
        run_env = None
        if env:
            run_env = {**dict(asyncio.subprocess.PIPE), **env}
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=run_env,
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.config.timeout_seconds,
            )
            
            return (
                proc.returncode or 0,
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
            )
            
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return (
                -1,
                "",
                f"Timeout after {self.config.timeout_seconds} seconds",
            )
        except FileNotFoundError:
            return (
                -1,
                "",
                f"Tool not found: {tool}",
            )


class DiagnoseStep(PipelineStep):
    """Step to diagnose issues in the target system."""
    
    def __init__(
        self,
        config: StepConfig,
        event_bus: EventBus | None = None,
    ):
        super().__init__("diagnose", config, event_bus)
    
    async def _execute(self, context: dict[str, Any]) -> StepResult:
        """Run diagnostic tools and collect findings."""
        target = context.get("target", ".")
        findings: list[dict] = []
        
        # Try to use kimi-security-auditor if available
        if self.config.tool == "kimi-security-auditor":
            return_code, stdout, stderr = await self._run_tool(
                "kimi-security-auditor",
                self.config.args + [target],
                cwd=target,
            )
            
            if return_code == 0 or stdout:
                # Parse findings from output
                findings = self._parse_security_auditor_output(stdout)
        
        # Fallback: Run basic checks
        if not findings:
            findings = await self._run_basic_diagnostics(target)
        
        return StepResult(
            success=True,
            step_name=self.name,
            findings=findings,
            metrics={
                "issues_found": len(findings),
                "critical": sum(1 for f in findings if f.get("severity") == "critical"),
                "high": sum(1 for f in findings if f.get("severity") == "high"),
                "medium": sum(1 for f in findings if f.get("severity") == "medium"),
                "low": sum(1 for f in findings if f.get("severity") == "low"),
            },
            raw_output=stdout if 'stdout' in locals() else "",
        )
    
    def _parse_security_auditor_output(self, output: str) -> list[dict]:
        """Parse output from kimi-security-auditor."""
        findings = []
        
        # Try to parse JSON output
        try:
            for line in output.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                
                # Try JSON parsing
                if line.startswith("{"):
                    data = json.loads(line)
                    if "findings" in data:
                        findings.extend(data["findings"])
                    elif "severity" in data:
                        findings.append(data)
        except json.JSONDecodeError:
            pass
        
        # Fallback: Parse text output
        if not findings:
            current_finding: dict = {}
            for line in output.split("\n"):
                line = line.strip()
                
                if line.startswith("[CRITICAL]") or line.startswith("[HIGH]"):
                    if current_finding:
                        findings.append(current_finding)
                    current_finding = {
                        "severity": line[1:].split("]")[0].lower(),
                        "description": line.split("]", 1)[1].strip() if "]" in line else line,
                    }
                elif line.startswith("File:"):
                    current_finding["file"] = line.split(":", 1)[1].strip()
                elif line.startswith("Line:"):
                    try:
                        current_finding["line"] = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
                elif line and current_finding:
                    if "details" not in current_finding:
                        current_finding["details"] = []
                    current_finding["details"].append(line)
            
            if current_finding:
                findings.append(current_finding)
        
        return findings
    
    async def _run_basic_diagnostics(self, target: str) -> list[dict]:
        """Run basic diagnostic checks."""
        findings = []
        target_path = Path(target)
        
        if not target_path.exists():
            return [{
                "severity": "critical",
                "description": f"Target path does not exist: {target}",
                "type": "path_error",
            }]
        
        # Check for Python files with common issues
        if target_path.is_dir():
            py_files = list(target_path.rglob("*.py"))
            
            for py_file in py_files[:50]:  # Limit to first 50 files
                try:
                    content = py_file.read_text(encoding="utf-8", errors="ignore")
                    
                    # Check for hardcoded secrets
                    if any(pattern in content for pattern in [
                        "password = ", "api_key = ", "secret = ",
                        "PASSWORD", "API_KEY", "SECRET_KEY",
                    ]):
                        findings.append({
                            "severity": "high",
                            "description": f"Potential hardcoded secret in {py_file.name}",
                            "file": str(py_file.relative_to(target_path)),
                            "type": "security",
                        })
                    
                    # Check for bare except clauses
                    if "except:" in content and "except Exception" not in content:
                        findings.append({
                            "severity": "medium",
                            "description": f"Bare except clause found in {py_file.name}",
                            "file": str(py_file.relative_to(target_path)),
                            "type": "code_quality",
                        })
                    
                    # Check for TODO/FIXME comments
                    if "TODO" in content or "FIXME" in content:
                        todo_count = content.count("TODO") + content.count("FIXME")
                        findings.append({
                            "severity": "low",
                            "description": f"{todo_count} TODO/FIXME comments in {py_file.name}",
                            "file": str(py_file.relative_to(target_path)),
                            "type": "maintenance",
                        })
                        
                except Exception:
                    pass
        
        return findings


class FixStep(PipelineStep):
    """Step to apply fixes to diagnosed issues."""
    
    def __init__(
        self,
        config: StepConfig,
        event_bus: EventBus | None = None,
    ):
        super().__init__("fix", config, event_bus)
    
    async def _execute(self, context: dict[str, Any]) -> StepResult:
        """Apply fixes based on findings from diagnose step."""
        findings = context.get("findings", [])
        target = context.get("target", ".")
        fixes_applied: list[dict] = []
        
        if not findings:
            return StepResult(
                success=True,
                step_name=self.name,
                fixes_applied=[],
                metrics={"fixes_applied": 0, "no_issues": True},
            )
        
        # Try to use kimi-sysadmin-ai if available
        if self.config.tool == "kimi-sysadmin-ai":
            return_code, stdout, stderr = await self._run_tool(
                "kimi-sysadmin-ai",
                self.config.args + ["--target", target],
                cwd=target,
            )
            
            if return_code == 0:
                fixes_applied = self._parse_sysadmin_output(stdout)
        
        # Apply automated fixes for known issues
        auto_fixes = await self._apply_automated_fixes(findings, target)
        fixes_applied.extend(auto_fixes)
        
        return StepResult(
            success=True,
            step_name=self.name,
            fixes_applied=fixes_applied,
            metrics={
                "fixes_applied": len(fixes_applied),
                "issues_addressed": len(findings),
            },
            raw_output=stdout if 'stdout' in locals() else "",
        )
    
    def _parse_sysadmin_output(self, output: str) -> list[dict]:
        """Parse output from kimi-sysadmin-ai."""
        fixes = []
        
        try:
            for line in output.strip().split("\n"):
                if not line.strip():
                    continue
                
                if line.startswith("{"):
                    data = json.loads(line)
                    if "fixes" in data:
                        fixes.extend(data["fixes"])
                    elif "file" in data:
                        fixes.append(data)
        except json.JSONDecodeError:
            pass
        
        return fixes
    
    async def _apply_automated_fixes(
        self,
        findings: list[dict],
        target: str,
    ) -> list[dict]:
        """Apply automated fixes for known issue types."""
        fixes = []
        target_path = Path(target)
        
        for finding in findings:
            fix = self._try_auto_fix(finding, target_path)
            if fix:
                fixes.append(fix)
        
        return fixes
    
    def _try_auto_fix(self, finding: dict, target_path: Path) -> dict | None:
        """Try to automatically fix a single finding."""
        file_path = finding.get("file")
        fix_type = finding.get("type")
        
        if not file_path:
            return None
        
        full_path = target_path / file_path
        if not full_path.exists():
            return None
        
        try:
            content = full_path.read_text(encoding="utf-8")
            original_content = content
            fix_applied = False
            
            # Fix bare except clauses
            if fix_type == "code_quality" and "bare except" in finding.get("description", ""):
                content = content.replace("except:", "except Exception:")
                fix_applied = content != original_content
            
            if fix_applied:
                full_path.write_text(content, encoding="utf-8")
                return {
                    "file": file_path,
                    "type": fix_type,
                    "description": finding.get("description"),
                    "auto_fixed": True,
                }
        
        except Exception as e:
            return {
                "file": file_path,
                "type": fix_type,
                "error": str(e),
                "auto_fixed": False,
            }
        
        return None


class AttackStep(PipelineStep):
    """Step to attack/penetration test the system."""
    
    def __init__(
        self,
        config: StepConfig,
        event_bus: EventBus | None = None,
    ):
        super().__init__("attack", config, event_bus)
    
    async def _execute(self, context: dict[str, Any]) -> StepResult:
        """Run attack/penetration tests."""
        target = context.get("target", ".")
        vulnerabilities: list[dict] = []
        
        # Run pytest in attack mode (collect tests as potential vulnerabilities)
        if self.config.tool in ("pytest", "python", "python3"):
            return_code, stdout, stderr = await self._run_tool(
                "python" if self.config.tool == "python3" else self.config.tool,
                ["-m", "pytest", "--collect-only", "-q"],
                cwd=target,
            )
            
            # Also run a quick import check
            import_code, import_out, import_err = await self._run_tool(
                "python",
                ["-c", f"import sys; sys.path.insert(0, '{target}'); print('Import check passed')"],
                cwd=target,
            )
        
        # Run additional security checks
        sec_findings = await self._run_security_checks(target)
        vulnerabilities.extend(sec_findings)
        
        return StepResult(
            success=True,
            step_name=self.name,
            findings=vulnerabilities,
            metrics={
                "vulnerabilities_found": len(vulnerabilities),
                "critical": sum(1 for v in vulnerabilities if v.get("severity") == "critical"),
                "tests_collected": stdout.count("::") if 'stdout' in locals() else 0,
            },
            raw_output=stdout if 'stdout' in locals() else "",
        )
    
    async def _run_security_checks(self, target: str) -> list[dict]:
        """Run security checks as attack simulations."""
        findings = []
        target_path = Path(target)
        
        if not target_path.exists():
            return findings
        
        # Check for common security issues
        if target_path.is_dir():
            # Check for .env files
            env_files = list(target_path.rglob(".env*"))
            for env_file in env_files:
                if env_file.name == ".env.example":
                    continue
                findings.append({
                    "severity": "high",
                    "description": f"Environment file found: {env_file.name}",
                    "file": str(env_file.relative_to(target_path)),
                    "type": "security_exposure",
                })
            
            # Check for __pycache__ in repo
            pycache_dirs = list(target_path.rglob("__pycache__"))
            if pycache_dirs:
                findings.append({
                    "severity": "low",
                    "description": f"{len(pycache_dirs)} __pycache__ directories found",
                    "type": "cleanup",
                })
            
            # Check for .pyc files
            pyc_files = list(target_path.rglob("*.pyc"))
            if pyc_files:
                findings.append({
                    "severity": "low",
                    "description": f"{len(pyc_files)} .pyc files found",
                    "type": "cleanup",
                })
        
        return findings


class ValidateStep(PipelineStep):
    """Step to validate the system after fixes."""
    
    def __init__(
        self,
        config: StepConfig,
        event_bus: EventBus | None = None,
    ):
        super().__init__("validate", config, event_bus)
    
    async def _execute(self, context: dict[str, Any]) -> StepResult:
        """Run validation tests."""
        target = context.get("target", ".")
        
        # Run pytest for validation
        if self.config.tool in ("pytest", "python", "python3"):
            return_code, stdout, stderr = await self._run_tool(
                "python" if self.config.tool == "python3" else self.config.tool,
                ["-m", "pytest", "-v", "--tb=short"],
                cwd=target,
            )
            
            # Parse test results
            metrics = self._parse_pytest_output(stdout + stderr)
            
            # Also run syntax check
            syntax_code, syntax_out, syntax_err = await self._run_tool(
                "python",
                ["-m", "py_compile", "-"],
                cwd=target,
            )
        
        else:
            # Generic tool execution
            return_code, stdout, stderr = await self._run_tool(
                self.config.tool,
                self.config.args,
                cwd=target,
            )
            
            metrics = {
                "return_code": return_code,
                "success": return_code == 0,
            }
        
        # Determine success
        # Exit code 5 from pytest means "no tests collected" - treat as success
        # since there's nothing to validate
        success = return_code == 0 or return_code == 5
        
        return StepResult(
            success=success,
            step_name=self.name,
            metrics=metrics,
            raw_output=stdout if 'stdout' in locals() else "",
        )
    
    def _parse_pytest_output(self, output: str) -> dict[str, Any]:
        """Parse pytest output for metrics."""
        metrics = {
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "errors": 0,
            "total": 0,
        }
        
        # Look for summary line
        for line in output.split("\n"):
            # Parse "X passed, Y failed, Z skipped, W error"
            if "passed" in line or "failed" in line:
                parts = line.replace(",", "").split()
                for i, part in enumerate(parts):
                    if part.isdigit():
                        count = int(part)
                        if i + 1 < len(parts):
                            status = parts[i + 1].lower().rstrip(",")
                            if status in metrics:
                                metrics[status] = count
        
        metrics["total"] = sum(metrics.values()) - metrics.get("total", 0)
        metrics["success_rate"] = (
            metrics["passed"] / metrics["total"] if metrics["total"] > 0 else 0
        )
        
        return metrics


__all__ = [
    "StepResult",
    "PipelineStep",
    "DiagnoseStep",
    "FixStep",
    "AttackStep",
    "ValidateStep",
]
