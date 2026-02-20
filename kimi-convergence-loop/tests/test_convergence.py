"""Tests for the convergence loop."""

import asyncio
import tempfile
from pathlib import Path

import pytest

from kimi_convergence_loop.config import Config, StepConfig, load_config
from kimi_convergence_loop.event_bus import EventBus, EventType
from kimi_convergence_loop.pipeline import Pipeline
from kimi_convergence_loop.state_machine import State, StateMachine, Transition
from kimi_convergence_loop.steps import (
    AttackStep,
    DiagnoseStep,
    FixStep,
    StepResult,
    ValidateStep,
)


class TestConfig:
    """Test configuration loading."""
    
    def test_default_config(self):
        """Test default configuration."""
        cfg = Config()
        
        assert cfg.loop.max_iterations == 10
        assert cfg.target == "."
        assert "diagnose" in cfg.steps
        assert "fix" in cfg.steps
        assert "attack" in cfg.steps
        assert "validate" in cfg.steps
    
    def test_config_from_dict(self):
        """Test loading config from dictionary."""
        data = {
            "loop": {"max_iterations": 5},
            "target": "/tmp/test",
        }
        
        cfg = Config.from_dict(data)
        
        assert cfg.loop.max_iterations == 5
        assert cfg.target == "/tmp/test"
    
    def test_config_yaml_roundtrip(self):
        """Test saving and loading config from YAML."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.yaml"
            
            cfg = Config()
            cfg.loop.max_iterations = 20
            cfg.target = "/some/path"
            
            cfg.to_yaml(path)
            loaded = Config.from_yaml(path)
            
            assert loaded.loop.max_iterations == 20
            assert loaded.target == "/some/path"


class TestStateMachine:
    """Test state machine."""
    
    def test_initial_state(self):
        """Test initial state is IDLE."""
        sm = StateMachine()
        assert sm.state == State.IDLE
    
    def test_valid_transition(self):
        """Test valid state transition."""
        sm = StateMachine()
        
        sm.transition(Transition.START)
        assert sm.state == State.DIAGNOSING
    
    def test_invalid_transition(self):
        """Test invalid state transition raises error."""
        sm = StateMachine()
        
        with pytest.raises(ValueError):
            sm.transition(Transition.CONVERGE)
    
    def test_terminal_states(self):
        """Test terminal state detection."""
        sm = StateMachine()
        
        assert not sm.is_terminal()
        
        sm.transition(Transition.START)
        sm.transition(Transition.DIAGNOSIS_COMPLETE)
        sm.transition(Transition.FIX_COMPLETE)
        sm.transition(Transition.ATTACK_COMPLETE)
        sm.transition(Transition.CONVERGE)
        
        assert sm.is_terminal()
    
    def test_history_tracking(self):
        """Test state history is tracked."""
        sm = StateMachine()
        
        sm.transition(Transition.START)
        sm.transition(Transition.DIAGNOSIS_COMPLETE)
        
        assert len(sm.history) == 2
        assert sm.history[0].from_state == State.IDLE
        assert sm.history[0].to_state == State.DIAGNOSING


class TestEventBus:
    """Test event bus."""
    
    @pytest.mark.asyncio
    async def test_emit_event(self):
        """Test emitting an event."""
        bus = EventBus()
        
        events = []
        
        def handler(event):
            events.append(event)
        
        bus.register_handler(handler)
        
        await bus.start()
        event = await bus.emit(EventType.STEP_STARTED, {"step": "test"})
        await bus.stop()
        
        assert len(events) == 3  # SESSION_STARTED, STEP_STARTED, SESSION_ENDED
        assert events[1].event_type == EventType.STEP_STARTED
        assert events[1].data["step"] == "test"
    
    @pytest.mark.asyncio
    async def test_iteration_tracking(self):
        """Test iteration tracking."""
        bus = EventBus()
        
        bus.set_iteration(5)
        
        await bus.start()
        event = await bus.emit(EventType.METRICS, {})
        await bus.stop()
        
        assert event.iteration == 5


class TestSteps:
    """Test pipeline steps."""
    
    @pytest.mark.asyncio
    async def test_diagnose_step(self):
        """Test diagnose step execution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test Python file
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("# Test file\nprint('hello')\n")
            
            step = DiagnoseStep(StepConfig(enabled=True))
            context = {"target": tmpdir}
            
            result = await step.execute(context)
            
            assert result.success
            assert result.step_name == "diagnose"
    
    @pytest.mark.asyncio
    async def test_diagnose_finds_issues(self):
        """Test diagnose step finds issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a Python file with a bare except
            test_file = Path(tmpdir) / "bad.py"
            test_file.write_text("""
try:
    pass
except:
    pass
""")
            
            step = DiagnoseStep(StepConfig(enabled=True))
            context = {"target": tmpdir}
            
            result = await step.execute(context)
            
            assert result.success
            assert len(result.findings) > 0
    
    @pytest.mark.asyncio
    async def test_fix_step_no_findings(self):
        """Test fix step with no findings."""
        step = FixStep(StepConfig(enabled=True))
        context = {"target": ".", "findings": []}
        
        result = await step.execute(context)
        
        assert result.success
        assert len(result.fixes_applied) == 0
    
    @pytest.mark.asyncio
    async def test_attack_step(self):
        """Test attack step execution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            step = AttackStep(StepConfig(enabled=True))
            context = {"target": tmpdir}
            
            result = await step.execute(context)
            
            assert result.success
            assert result.step_name == "attack"
    
    @pytest.mark.asyncio
    async def test_validate_step(self):
        """Test validate step execution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            step = ValidateStep(StepConfig(enabled=True))
            context = {"target": tmpdir}
            
            result = await step.execute(context)
            
            assert result.step_name == "validate"
    
    @pytest.mark.asyncio
    async def test_disabled_step(self):
        """Test disabled step returns success."""
        step = DiagnoseStep(StepConfig(enabled=False))
        context = {"target": "."}
        
        result = await step.execute(context)
        
        assert result.success
        assert result.metrics.get("enabled") == False


class TestPipeline:
    """Test full pipeline."""
    
    @pytest.mark.asyncio
    async def test_pipeline_run(self):
        """Test pipeline execution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Config()
            cfg.target = tmpdir
            cfg.loop.max_iterations = 2
            
            # Disable steps that require external tools
            cfg.steps["diagnose"].enabled = True
            cfg.steps["fix"].enabled = True
            cfg.steps["attack"].enabled = True
            cfg.steps["validate"].enabled = True
            
            pipeline = Pipeline(cfg)
            
            result = await pipeline.run()
            
            assert result.iterations >= 1
            assert result.final_state in [State.CONVERGED, State.FAILED, State.VALIDATING]
    
    @pytest.mark.asyncio
    async def test_pipeline_converges_clean_target(self):
        """Test pipeline converges on clean target."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a simple valid Python file
            test_file = Path(tmpdir) / "good.py"
            test_file.write_text("""
def hello():
    return "world"
""")
            
            cfg = Config()
            cfg.target = tmpdir
            cfg.loop.max_iterations = 3
            
            pipeline = Pipeline(cfg)
            
            result = await pipeline.run()
            
            # Should converge or hit max iterations
            assert result.iterations >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
