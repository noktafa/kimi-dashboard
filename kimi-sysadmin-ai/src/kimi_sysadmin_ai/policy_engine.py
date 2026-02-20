"""Policy engine with Rego/OPA support and Python fallback."""

import json
import os
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Dict, List


class PolicyDecision(Enum):
    """Policy decision outcomes."""
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"


@dataclass
class PolicyInput:
    """Input data for policy evaluation."""
    command: str
    user: str
    working_dir: str
    environment: Dict[str, str]
    executor_type: str = "host"
    target: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyResult:
    """Result of policy evaluation."""
    decision: PolicyDecision
    reason: str
    policy_name: str
    input_data: Dict[str, Any]


class PolicyBackend(ABC):
    """Abstract base class for policy backends."""
    
    @abstractmethod
    def evaluate(self, input_data: PolicyInput) -> PolicyResult:
        """Evaluate policy against input data."""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if backend is available."""
        pass


class OpaBackend(PolicyBackend):
    """OPA/Rego policy backend."""
    
    def __init__(self, opa_url: str = "http://localhost:8181", 
                 policy_path: Optional[str] = None) -> None:
        self.opa_url = opa_url
        self.policy_path = policy_path or self._default_policy_path()
        self._available: Optional[bool] = None
    
    def _default_policy_path(self) -> str:
        """Get default policy file path."""
        pkg_dir = Path(__file__).parent
        return str(pkg_dir / "policies" / "default.rego")
    
    def is_available(self) -> bool:
        """Check if OPA server is available."""
        if self._available is not None:
            return self._available
        
        try:
            import requests
            response = requests.get(f"{self.opa_url}/health", timeout=2)
            self._available = response.status_code == 200
        except Exception:
            self._available = False
        
        return self._available
    
    def evaluate(self, input_data: PolicyInput) -> PolicyResult:
        """Evaluate policy using OPA."""
        try:
            import requests
            
            # Prepare OPA query
            query_url = f"{self.opa_url}/v1/data/sysadmin/allow"
            payload = {"input": input_data.to_dict()}
            
            response = requests.post(
                query_url,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            
            result = response.json()
            allowed = result.get("result", False)
            
            if allowed:
                return PolicyResult(
                    decision=PolicyDecision.ALLOW,
                    reason="OPA policy allowed the command",
                    policy_name="opa_default",
                    input_data=input_data.to_dict()
                )
            else:
                return PolicyResult(
                    decision=PolicyDecision.DENY,
                    reason="OPA policy denied the command",
                    policy_name="opa_default",
                    input_data=input_data.to_dict()
                )
                
        except Exception as e:
            return PolicyResult(
                decision=PolicyDecision.UNKNOWN,
                reason=f"OPA evaluation failed: {str(e)}",
                policy_name="opa_default",
                input_data=input_data.to_dict()
            )
    
    def load_policy(self, policy_file: str) -> bool:
        """Load a Rego policy file into OPA."""
        try:
            import requests
            
            with open(policy_file, 'r') as f:
                policy_content = f.read()
            
            # Create or update policy
            policy_name = Path(policy_file).stem
            put_url = f"{self.opa_url}/v1/policies/{policy_name}"
            
            response = requests.put(
                put_url,
                data=policy_content,
                headers={"Content-Type": "text/plain"},
                timeout=10
            )
            
            return response.status_code in (200, 204)
            
        except Exception:
            return False


class PythonBackend(PolicyBackend):
    """Python-based policy backend (fallback)."""
    
    def __init__(self, policy_rules: Optional[List[Dict[str, Any]]] = None) -> None:
        self.rules = policy_rules or self._default_rules()
    
    def _default_rules(self) -> List[Dict[str, Any]]:
        """Get default policy rules."""
        return [
            {
                "name": "block_root_destructive",
                "description": "Block destructive commands as root",
                "condition": {
                    "user": "root",
                    "command_patterns": ["rm -rf /", "mkfs", "dd if=/dev/zero"]
                },
                "action": "deny"
            },
            {
                "name": "allow_readonly",
                "description": "Allow read-only commands",
                "condition": {
                    "command_patterns": ["^ls", "^cat", "^grep", "^find", "^ps", "^df", "^du", "^top", "^htop", "^free", "^uname", "^whoami", "^pwd", "^echo", "^head", "^tail", "^less", "^more", "^wc", "^sort", "^uniq", "^awk", "^sed"]
                },
                "action": "allow"
            },
            {
                "name": "require_confirmation_network",
                "description": "Require confirmation for network commands",
                "condition": {
                    "command_patterns": ["curl", "wget", "nc", "netcat", "nmap", "ping", "traceroute"]
                },
                "action": "gray"
            }
        ]
    
    def is_available(self) -> bool:
        """Python backend is always available."""
        return True
    
    def evaluate(self, input_data: PolicyInput) -> PolicyResult:
        """Evaluate policy using Python rules."""
        import re
        
        command = input_data.command
        user = input_data.user
        
        # Check deny rules first
        for rule in self.rules:
            if rule.get("action") == "deny":
                if self._matches_rule(command, user, rule.get("condition", {})):
                    return PolicyResult(
                        decision=PolicyDecision.DENY,
                        reason=f"Rule '{rule['name']}' denied: {rule['description']}",
                        policy_name=rule["name"],
                        input_data=input_data.to_dict()
                    )
        
        # Check allow rules
        for rule in self.rules:
            if rule.get("action") == "allow":
                if self._matches_rule(command, user, rule.get("condition", {})):
                    return PolicyResult(
                        decision=PolicyDecision.ALLOW,
                        reason=f"Rule '{rule['name']}' allowed: {rule['description']}",
                        policy_name=rule["name"],
                        input_data=input_data.to_dict()
                    )
        
        # Default deny if no rules match
        return PolicyResult(
            decision=PolicyDecision.UNKNOWN,
            reason="No matching policy rule found",
            policy_name="default",
            input_data=input_data.to_dict()
        )
    
    def _matches_rule(self, command: str, user: str, condition: Dict[str, Any]) -> bool:
        """Check if input matches rule condition."""
        import re
        
        # Check user condition
        if "user" in condition:
            if condition["user"] != user:
                return False
        
        # Check command patterns
        if "command_patterns" in condition:
            patterns = condition["command_patterns"]
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    return True
            return False
        
        return True


class PolicyEngine:
    """Policy engine with multiple backend support."""
    
    def __init__(self, 
                 opa_url: Optional[str] = None,
                 policy_file: Optional[str] = None,
                 use_opa: bool = True) -> None:
        """Initialize policy engine.
        
        Args:
            opa_url: URL of OPA server (default: http://localhost:8181)
            policy_file: Path to Rego policy file
            use_opa: Whether to try OPA first
        """
        self.opa_backend: Optional[OpaBackend] = None
        self.python_backend = PythonBackend()
        self.use_opa = use_opa
        
        if use_opa:
            opa_url = opa_url or os.environ.get("OPA_URL", "http://localhost:8181")
            self.opa_backend = OpaBackend(opa_url, policy_file)
    
    def evaluate(self, input_data: PolicyInput) -> PolicyResult:
        """Evaluate policy using available backends.
        
        Tries OPA first if enabled and available, falls back to Python backend.
        """
        if self.use_opa and self.opa_backend and self.opa_backend.is_available():
            result = self.opa_backend.evaluate(input_data)
            if result.decision != PolicyDecision.UNKNOWN:
                return result
        
        # Fall back to Python backend
        return self.python_backend.evaluate(input_data)
    
    def can_execute(self, input_data: PolicyInput) -> bool:
        """Quick check if command can be executed."""
        result = self.evaluate(input_data)
        return result.decision == PolicyDecision.ALLOW
    
    def get_backend_info(self) -> Dict[str, Any]:
        """Get information about available backends."""
        info = {
            "python_backend": {"available": True},
            "opa_backend": {"available": False, "url": None}
        }
        
        if self.opa_backend:
            info["opa_backend"]["available"] = self.opa_backend.is_available()
            info["opa_backend"]["url"] = self.opa_backend.opa_url
        
        return info
