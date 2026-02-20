"""Host executor for direct command execution."""

import os
import subprocess
import time
from typing import Any, Dict, Optional

from kimi_sysadmin_ai.executors.base import BaseExecutor, ExecutionResult
from kimi_sysadmin_ai.safety import SafetyFilter, SafetyLevel
from kimi_sysadmin_ai.policy_engine import PolicyEngine, PolicyInput, PolicyDecision


class HostExecutor(BaseExecutor):
    """Execute commands directly on the host system."""
    
    def __init__(
        self,
        safety_filter: Optional[SafetyFilter] = None,
        policy_engine: Optional[PolicyEngine] = None,
        allow_gray: bool = False,
        confirm_callback: Optional[callable] = None
    ) -> None:
        """Initialize host executor.
        
        Args:
            safety_filter: Safety filter instance
            policy_engine: Policy engine instance
            allow_gray: Whether to allow graylisted commands without confirmation
            confirm_callback: Callback function for graylist confirmation
        """
        super().__init__("host")
        self.safety_filter = safety_filter or SafetyFilter()
        self.policy_engine = policy_engine or PolicyEngine()
        self.allow_gray = allow_gray
        self.confirm_callback = confirm_callback
    
    def is_available(self) -> bool:
        """Host executor is always available."""
        return True
    
    def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> ExecutionResult:
        """Execute a command on the host with safety checks.
        
        Args:
            command: The command to execute
            timeout: Timeout in seconds (default: 60)
            working_dir: Working directory
            env: Environment variables
            
        Returns:
            ExecutionResult with output and status
        """
        timeout = timeout or 60
        working_dir = working_dir or os.getcwd()
        
        # Step 1: Safety filter check
        safety_result = self.safety_filter.check(command)
        
        if safety_result.level == SafetyLevel.BLOCK:
            return ExecutionResult(
                command=command,
                stdout="",
                stderr=f"SAFETY BLOCKED: {safety_result.reason}",
                returncode=-1,
                success=False,
                executor=self.name,
                metadata={"safety_result": safety_result.level.value}
            )
        
        if safety_result.level == SafetyLevel.GRAY:
            if not self.allow_gray:
                if self.confirm_callback:
                    confirmed = self.confirm_callback(command, safety_result.reason)
                    if not confirmed:
                        return ExecutionResult(
                            command=command,
                            stdout="",
                            stderr="Command rejected by user",
                            returncode=-1,
                            success=False,
                            executor=self.name,
                            metadata={"safety_result": "user_rejected"}
                        )
                else:
                    return ExecutionResult(
                        command=command,
                        stdout="",
                        stderr=f"GRAYLISTED (requires confirmation): {safety_result.reason}",
                        returncode=-1,
                        success=False,
                        executor=self.name,
                        metadata={"safety_result": safety_result.level.value}
                    )
        
        # Step 2: Policy engine check
        policy_input = PolicyInput(
            command=command,
            user=os.environ.get("USER", "unknown"),
            working_dir=working_dir,
            environment=os.environ.copy(),
            executor_type="host"
        )
        
        policy_result = self.policy_engine.evaluate(policy_input)
        
        if policy_result.decision == PolicyDecision.DENY:
            return ExecutionResult(
                command=command,
                stdout="",
                stderr=f"POLICY DENIED: {policy_result.reason}",
                returncode=-1,
                success=False,
                executor=self.name,
                metadata={
                    "safety_result": safety_result.level.value,
                    "policy_decision": policy_result.decision.value
                }
            )
        
        # Step 3: Execute the command
        start_time = time.time()
        
        try:
            merged_env = os.environ.copy()
            if env:
                merged_env.update(env)
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=working_dir,
                env=merged_env
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            duration_ms = int((time.time() - start_time) * 1000)
            
            return ExecutionResult(
                command=command,
                stdout=stdout,
                stderr=stderr,
                returncode=process.returncode,
                success=process.returncode == 0,
                executor=self.name,
                duration_ms=duration_ms,
                metadata={
                    "safety_result": safety_result.level.value,
                    "policy_decision": policy_result.decision.value,
                    "policy_reason": policy_result.reason
                }
            )
            
        except subprocess.TimeoutExpired:
            process.kill()
            duration_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                command=command,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                returncode=-1,
                success=False,
                executor=self.name,
                duration_ms=duration_ms,
                metadata={"timeout": timeout}
            )
            
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                command=command,
                stdout="",
                stderr=str(e),
                returncode=-1,
                success=False,
                executor=self.name,
                duration_ms=duration_ms,
                metadata={"error": str(e)}
            )
