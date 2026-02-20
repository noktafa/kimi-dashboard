"""Base executor interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ExecutionResult:
    """Result of command execution."""
    command: str
    stdout: str
    stderr: str
    returncode: int
    success: bool
    executor: str
    duration_ms: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None


class BaseExecutor(ABC):
    """Abstract base class for command executors."""
    
    def __init__(self, name: str) -> None:
        self.name = name
    
    @abstractmethod
    def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> ExecutionResult:
        """Execute a command.
        
        Args:
            command: The command to execute
            timeout: Timeout in seconds
            working_dir: Working directory
            env: Environment variables
            
        Returns:
            ExecutionResult with output and status
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if executor is available."""
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Get executor information."""
        return {
            "name": self.name,
            "available": self.is_available()
        }
