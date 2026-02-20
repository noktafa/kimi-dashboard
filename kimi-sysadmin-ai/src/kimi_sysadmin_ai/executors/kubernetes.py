"""Kubernetes executor for pod-based command execution."""

import os
import time
from typing import Any, Dict, List, Optional

from kimi_sysadmin_ai.executors.base import BaseExecutor, ExecutionResult
from kimi_sysadmin_ai.safety import SafetyFilter, SafetyLevel
from kimi_sysadmin_ai.policy_engine import PolicyEngine, PolicyInput, PolicyDecision


class KubernetesExecutor(BaseExecutor):
    """Execute commands in Kubernetes pods."""
    
    def __init__(
        self,
        namespace: str = "default",
        pod_name: Optional[str] = None,
        pod_selector: Optional[Dict[str, str]] = None,
        container: Optional[str] = None,
        safety_filter: Optional[SafetyFilter] = None,
        policy_engine: Optional[PolicyEngine] = None,
        allow_gray: bool = False,
        kubeconfig: Optional[str] = None
    ) -> None:
        """Initialize Kubernetes executor.
        
        Args:
            namespace: Kubernetes namespace
            pod_name: Specific pod name (if not using selector)
            pod_selector: Label selector to find pod
            container: Container name (for multi-container pods)
            safety_filter: Safety filter instance
            policy_engine: Policy engine instance
            allow_gray: Whether to allow graylisted commands
            kubeconfig: Path to kubeconfig file
        """
        super().__init__("kubernetes")
        self.namespace = namespace
        self.pod_name = pod_name
        self.pod_selector = pod_selector or {}
        self.container = container
        self.safety_filter = safety_filter or SafetyFilter()
        self.policy_engine = policy_engine or PolicyEngine()
        self.allow_gray = allow_gray
        self.kubeconfig = kubeconfig
        self._core_v1 = None
    
    def _get_api(self):
        """Get Kubernetes CoreV1 API."""
        if self._core_v1 is None:
            from kubernetes import client, config
            
            if self.kubeconfig:
                config.load_kube_config(config_file=self.kubeconfig)
            else:
                try:
                    config.load_incluster_config()
                except config.ConfigException:
                    config.load_kube_config()
            
            self._core_v1 = client.CoreV1Api()
        
        return self._core_v1
    
    def is_available(self) -> bool:
        """Check if Kubernetes is available."""
        try:
            from kubernetes import client, config
            
            try:
                config.load_incluster_config()
            except Exception:
                config.load_kube_config()
            
            api = client.CoreV1Api()
            api.list_namespace(timeout_seconds=5)
            return True
        except Exception:
            return False
    
    def _get_target_pod(self) -> Optional[str]:
        """Get the target pod name."""
        if self.pod_name:
            return self.pod_name
        
        if self.pod_selector:
            api = self._get_api()
            selector = ",".join([f"{k}={v}" for k, v in self.pod_selector.items()])
            pods = api.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=selector
            )
            
            if pods.items:
                return pods.items[0].metadata.name
        
        return None
    
    def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> ExecutionResult:
        """Execute a command in a Kubernetes pod.
        
        Args:
            command: The command to execute
            timeout: Timeout in seconds (default: 60)
            working_dir: Working directory in pod
            env: Environment variables
            
        Returns:
            ExecutionResult with output and status
        """
        timeout = timeout or 60
        
        # Safety check
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
        
        if safety_result.level == SafetyLevel.GRAY and not self.allow_gray:
            return ExecutionResult(
                command=command,
                stdout="",
                stderr=f"GRAYLISTED (requires confirmation): {safety_result.reason}",
                returncode=-1,
                success=False,
                executor=self.name,
                metadata={"safety_result": safety_result.level.value}
            )
        
        # Get target pod
        target_pod = self._get_target_pod()
        if not target_pod:
            return ExecutionResult(
                command=command,
                stdout="",
                stderr="No target pod found",
                returncode=-1,
                success=False,
                executor=self.name
            )
        
        # Policy check
        policy_input = PolicyInput(
            command=command,
            user="kubernetes",
            working_dir=working_dir or "/",
            environment=env or {},
            executor_type="kubernetes",
            target=f"{self.namespace}/{target_pod}"
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
                metadata={"policy_decision": policy_result.decision.value}
            )
        
        # Execute in pod
        start_time = time.time()
        
        try:
            from kubernetes import client, stream
            
            api = self._get_api()
            
            # Prepare exec command
            exec_command = ["/bin/sh", "-c", command]
            if working_dir:
                exec_command = ["/bin/sh", "-c", f"cd {working_dir} && {command}"]
            
            # Execute command in pod
            exec_response = stream.stream(
                api.connect_get_namespaced_pod_exec,
                target_pod,
                self.namespace,
                container=self.container,
                command=exec_command,
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _request_timeout=timeout
            )
            
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Note: Kubernetes exec doesn't return exit code directly
            # We assume success if no exception
            return ExecutionResult(
                command=command,
                stdout=exec_response,
                stderr="",
                returncode=0,
                success=True,
                executor=self.name,
                duration_ms=duration_ms,
                metadata={
                    "pod": target_pod,
                    "namespace": self.namespace,
                    "container": self.container
                }
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
                duration_ms=duration_ms
            )
    
    def list_pods(self, label_selector: Optional[str] = None) -> List[Dict[str, Any]]:
        """List pods in the namespace."""
        try:
            api = self._get_api()
            pods = api.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=label_selector
            )
            
            return [
                {
                    "name": pod.metadata.name,
                    "status": pod.status.phase,
                    "ip": pod.status.pod_ip,
                    "node": pod.spec.node_name,
                    "containers": [c.name for c in pod.spec.containers]
                }
                for pod in pods.items
            ]
        except Exception as e:
            return [{"error": str(e)}]
    
    def get_logs(
        self,
        pod_name: Optional[str] = None,
        container: Optional[str] = None,
        tail_lines: int = 100
    ) -> str:
        """Get logs from a pod."""
        try:
            api = self._get_api()
            pod = pod_name or self._get_target_pod()
            
            if not pod:
                return "No pod specified"
            
            logs = api.read_namespaced_pod_log(
                pod,
                self.namespace,
                container=container or self.container,
                tail_lines=tail_lines
            )
            return logs
        except Exception as e:
            return f"Error getting logs: {str(e)}"
