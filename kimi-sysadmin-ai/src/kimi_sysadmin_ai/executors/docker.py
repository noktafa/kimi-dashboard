"""Docker executor for container-based command execution."""

import os
import time
from typing import Any, Dict, List, Optional

from kimi_sysadmin_ai.executors.base import BaseExecutor, ExecutionResult
from kimi_sysadmin_ai.safety import SafetyFilter, SafetyLevel
from kimi_sysadmin_ai.policy_engine import PolicyEngine, PolicyInput, PolicyDecision


class DockerExecutor(BaseExecutor):
    """Execute commands in Docker containers."""
    
    def __init__(
        self,
        image: str = "alpine:latest",
        container_name: Optional[str] = None,
        volumes: Optional[Dict[str, str]] = None,
        network: Optional[str] = None,
        safety_filter: Optional[SafetyFilter] = None,
        policy_engine: Optional[PolicyEngine] = None,
        allow_gray: bool = False
    ) -> None:
        """Initialize Docker executor.
        
        Args:
            image: Docker image to use
            container_name: Name for the container
            volumes: Volume mappings {host_path: container_path}
            network: Network mode
            safety_filter: Safety filter instance
            policy_engine: Policy engine instance
            allow_gray: Whether to allow graylisted commands
        """
        super().__init__("docker")
        self.image = image
        self.container_name = container_name
        self.volumes = volumes or {}
        self.network = network
        self.safety_filter = safety_filter or SafetyFilter()
        self.policy_engine = policy_engine or PolicyEngine()
        self.allow_gray = allow_gray
        self._client = None
    
    def _get_client(self):
        """Get or create Docker client."""
        if self._client is None:
            import docker
            self._client = docker.from_env()
        return self._client
    
    def is_available(self) -> bool:
        """Check if Docker is available."""
        try:
            import docker
            client = docker.from_env()
            client.ping()
            return True
        except Exception:
            return False
    
    def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> ExecutionResult:
        """Execute a command in a Docker container.
        
        Args:
            command: The command to execute
            timeout: Timeout in seconds (default: 60)
            working_dir: Working directory in container
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
        
        # Policy check
        policy_input = PolicyInput(
            command=command,
            user="docker",
            working_dir=working_dir or "/",
            environment=env or {},
            executor_type="docker",
            target=self.image
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
        
        # Execute in Docker
        start_time = time.time()
        
        try:
            client = self._get_client()
            
            # Prepare volumes
            docker_volumes = {}
            for host_path, container_path in self.volumes.items():
                docker_volumes[host_path] = {
                    "bind": container_path,
                    "mode": "rw"
                }
            
            # Run container
            container = client.containers.run(
                self.image,
                command=["sh", "-c", command],
                detach=True,
                remove=True,
                volumes=docker_volumes if docker_volumes else None,
                network=self.network,
                working_dir=working_dir,
                environment=env,
                name=self.container_name
            )
            
            # Wait for completion with timeout
            try:
                result = container.wait(timeout=timeout)
                logs = container.logs().decode('utf-8')
                duration_ms = int((time.time() - start_time) * 1000)
                
                # Split stdout/stderr (Docker combines them)
                return ExecutionResult(
                    command=command,
                    stdout=logs,
                    stderr="",
                    returncode=result.get("StatusCode", -1),
                    success=result.get("StatusCode", -1) == 0,
                    executor=self.name,
                    duration_ms=duration_ms,
                    metadata={
                        "container_id": container.id[:12],
                        "image": self.image
                    }
                )
            except Exception as e:
                container.kill()
                duration_ms = int((time.time() - start_time) * 1000)
                return ExecutionResult(
                    command=command,
                    stdout="",
                    stderr=f"Docker execution failed: {str(e)}",
                    returncode=-1,
                    success=False,
                    executor=self.name,
                    duration_ms=duration_ms
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
    
    def list_images(self) -> List[Dict[str, Any]]:
        """List available Docker images."""
        try:
            client = self._get_client()
            images = client.images.list()
            return [
                {
                    "id": img.id,
                    "tags": img.tags,
                    "size": img.attrs.get("Size", 0)
                }
                for img in images
            ]
        except Exception as e:
            return [{"error": str(e)}]
    
    def pull_image(self, image: str) -> bool:
        """Pull a Docker image."""
        try:
            client = self._get_client()
            client.images.pull(image)
            return True
        except Exception:
            return False
