"""Configuration management for the convergence loop."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class StepConfig:
    """Configuration for a pipeline step."""
    
    enabled: bool = True
    tool: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 300
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StepConfig:
        """Create from dictionary."""
        return cls(
            enabled=data.get("enabled", True),
            tool=data.get("tool", ""),
            args=data.get("args", []),
            env=data.get("env", {}),
            timeout_seconds=data.get("timeout_seconds", 300),
        )


@dataclass
class LoopConfig:
    """Configuration for the convergence loop."""
    
    max_iterations: int = 10
    convergence_threshold: float = 0.95
    timeout_seconds: int = 3600
    backoff_seconds: float = 1.0
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LoopConfig:
        """Create from dictionary."""
        return cls(
            max_iterations=data.get("max_iterations", 10),
            convergence_threshold=data.get("convergence_threshold", 0.95),
            timeout_seconds=data.get("timeout_seconds", 3600),
            backoff_seconds=data.get("backoff_seconds", 1.0),
        )


@dataclass
class EventConfig:
    """Configuration for event bus."""
    
    webhook_url: str = ""
    emit_interval: int = 5
    buffer_size: int = 1000
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EventConfig:
        """Create from dictionary."""
        return cls(
            webhook_url=data.get("webhook_url", ""),
            emit_interval=data.get("emit_interval", 5),
            buffer_size=data.get("buffer_size", 1000),
        )


@dataclass
class Config:
    """Main configuration for the convergence loop."""
    
    loop: LoopConfig = field(default_factory=LoopConfig)
    steps: dict[str, StepConfig] = field(default_factory=dict)
    events: EventConfig = field(default_factory=EventConfig)
    target: str = "."
    
    def __post_init__(self) -> None:
        """Set default step configurations if not provided."""
        defaults = {
            "diagnose": StepConfig(
                tool="kimi-security-auditor",
                args=["--scan", "."],
            ),
            "fix": StepConfig(
                tool="kimi-sysadmin-ai",
                args=["--fix"],
            ),
            "attack": StepConfig(
                tool="pytest",
                args=["--co", "-q"],  # Collect only, quiet
            ),
            "validate": StepConfig(
                tool="pytest",
                args=["-v"],
            ),
        }
        
        for name, default in defaults.items():
            if name not in self.steps:
                self.steps[name] = default
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Create from dictionary."""
        steps_data = data.get("steps", {})
        steps = {
            name: StepConfig.from_dict(step_data)
            for name, step_data in steps_data.items()
        }
        
        return cls(
            loop=LoopConfig.from_dict(data.get("loop", {})),
            steps=steps,
            events=EventConfig.from_dict(data.get("events", {})),
            target=data.get("target", "."),
        )
    
    @classmethod
    def from_yaml(cls, path: Path | str) -> Config:
        """Load configuration from YAML file."""
        path = Path(path)
        
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        
        return cls.from_dict(data or {})
    
    def to_yaml(self, path: Path | str) -> None:
        """Save configuration to YAML file."""
        path = Path(path)
        
        data = {
            "loop": {
                "max_iterations": self.loop.max_iterations,
                "convergence_threshold": self.loop.convergence_threshold,
                "timeout_seconds": self.loop.timeout_seconds,
                "backoff_seconds": self.loop.backoff_seconds,
            },
            "steps": {
                name: {
                    "enabled": step.enabled,
                    "tool": step.tool,
                    "args": step.args,
                    "env": step.env,
                    "timeout_seconds": step.timeout_seconds,
                }
                for name, step in self.steps.items()
            },
            "events": {
                "webhook_url": self.events.webhook_url,
                "emit_interval": self.events.emit_interval,
                "buffer_size": self.events.buffer_size,
            },
            "target": self.target,
        }
        
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def load_config(
    config_path: Path | str | None = None,
    target: str | None = None,
) -> Config:
    """Load configuration with optional overrides.
    
    Args:
        config_path: Path to YAML config file
        target: Target path to analyze/fix
        
    Returns:
        Config instance
    """
    # Try to load from file if provided
    if config_path:
        config = Config.from_yaml(config_path)
    else:
        # Try default locations
        default_paths = [
            Path("convergence.yaml"),
            Path("convergence.yml"),
            Path(".convergence.yaml"),
            Path.home() / ".config" / "kimi-convergence" / "config.yaml",
        ]
        
        config = None
        for path in default_paths:
            if path.exists():
                config = Config.from_yaml(path)
                break
        
        if config is None:
            config = Config()  # Use defaults
    
    # Apply overrides
    if target:
        config.target = target
    
    # Apply environment variable overrides
    if max_iter := os.getenv("CONVERGENCE_MAX_ITERATIONS"):
        config.loop.max_iterations = int(max_iter)
    
    if timeout := os.getenv("CONVERGENCE_TIMEOUT"):
        config.loop.timeout_seconds = int(timeout)
    
    if webhook := os.getenv("CONVERGENCE_WEBHOOK_URL"):
        config.events.webhook_url = webhook
    
    return config
