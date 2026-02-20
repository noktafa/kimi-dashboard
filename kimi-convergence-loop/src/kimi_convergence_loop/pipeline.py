"""Main pipeline orchestrator."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import Config
from .event_bus import EventBus, EventType
from .state_machine import State, StateMachine, Transition
from .steps import AttackStep, DiagnoseStep, FixStep, StepResult, ValidateStep


@dataclass
class PipelineResult:
    """Result of running the convergence pipeline."""
    
    success: bool
    iterations: int
    final_state: State
    convergence_reached: bool
    step_results: list[StepResult] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    start_time: datetime | None = None
    end_time: datetime | None = None
    error: str = ""
    
    @property
    def duration_seconds(self) -> float:
        """Calculate duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


class Pipeline:
    """Main pipeline that orchestrates the convergence loop."""
    
    def __init__(
        self,
        config: Config,
        event_bus: EventBus | None = None,
    ):
        self.config = config
        self.event_bus = event_bus or EventBus()
        self.state_machine = StateMachine()
        
        # Initialize steps
        self.diagnose_step = DiagnoseStep(
            config.steps.get("diagnose", config.steps.get("diagnose")),
            event_bus,
        )
        self.fix_step = FixStep(
            config.steps.get("fix", config.steps.get("fix")),
            event_bus,
        )
        self.attack_step = AttackStep(
            config.steps.get("attack", config.steps.get("attack")),
            event_bus,
        )
        self.validate_step = ValidateStep(
            config.steps.get("validate", config.steps.get("validate")),
            event_bus,
        )
        
        # Setup state change handlers
        self._setup_state_handlers()
        
        self._iteration = 0
        self._step_results: list[StepResult] = []
        self._context: dict[str, Any] = {}
        self._running = False
    
    def _setup_state_handlers(self) -> None:
        """Setup handlers for state changes."""
        def on_state_change(from_state: State, to_state: State, transition: Transition, data: Any):
            if self.event_bus:
                asyncio.create_task(self.event_bus.emit(EventType.STATE_CHANGED, {
                    "from": from_state.name,
                    "to": to_state.name,
                    "transition": transition.name,
                }))
        
        for transition in Transition:
            self.state_machine.on_transition(transition, on_state_change)
    
    async def run(self) -> PipelineResult:
        """Run the convergence pipeline.
        
        Returns:
            PipelineResult with full execution results
        """
        start_time = datetime.now(timezone.utc)
        self._running = True
        self._iteration = 0
        self._step_results = []
        
        # Initialize context
        self._context = {
            "target": self.config.target,
            "findings": [],
            "fixes": [],
            "vulnerabilities": [],
            "validation_results": {},
        }
        
        # Start event bus
        await self.event_bus.start()
        
        try:
            # Start the state machine
            self.state_machine.transition(Transition.START)
            
            # Main convergence loop - each iteration runs all 4 steps
            while self._running and not self.state_machine.is_terminal():
                self._iteration += 1
                
                if self._iteration > self.config.loop.max_iterations:
                    await self.event_bus.emit(EventType.ERROR, {
                        "error": f"Max iterations ({self.config.loop.max_iterations}) reached",
                    })
                    break
                
                # Update event bus iteration
                self.event_bus.set_iteration(self._iteration)
                await self.event_bus.emit(EventType.ITERATION_STARTED, {
                    "iteration": self._iteration,
                })
                
                # Execute all 4 steps in sequence
                try:
                    converged = await self._execute_iteration()
                    if converged:
                        break
                except Exception as e:
                    await self.event_bus.emit(EventType.ERROR, {
                        "error": str(e),
                        "state": self.state_machine.state.name,
                    })
                    self.state_machine.transition(Transition.FAIL, {"error": str(e)})
                    break
                
                await self.event_bus.emit(EventType.ITERATION_ENDED, {
                    "iteration": self._iteration,
                    "state": self.state_machine.state.name,
                })
                
                # Small delay between iterations
                await asyncio.sleep(self.config.loop.backoff_seconds)
            
            # Determine final result
            convergence_reached = self.state_machine.state == State.CONVERGED
            
            if convergence_reached:
                await self.event_bus.emit(EventType.CONVERGENCE_REACHED, {
                    "iterations": self._iteration,
                    "metrics": self._calculate_metrics(),
                })
            
            end_time = datetime.now(timezone.utc)
            
            return PipelineResult(
                success=self.state_machine.state != State.FAILED,
                iterations=self._iteration,
                final_state=self.state_machine.state,
                convergence_reached=convergence_reached,
                step_results=self._step_results,
                metrics=self._calculate_metrics(),
                start_time=start_time,
                end_time=end_time,
            )
            
        except Exception as e:
            end_time = datetime.now(timezone.utc)
            return PipelineResult(
                success=False,
                iterations=self._iteration,
                final_state=State.FAILED,
                convergence_reached=False,
                step_results=self._step_results,
                start_time=start_time,
                end_time=end_time,
                error=str(e),
            )
        finally:
            self._running = False
            await self.event_bus.stop()
    
    async def _execute_iteration(self) -> bool:
        """Execute one full iteration of all 4 steps.
        
        Returns:
            True if convergence reached, False to continue
        """
        # If we're in IDLE (from a previous RETRY), transition to DIAGNOSING
        if self.state_machine.state == State.IDLE:
            self.state_machine.transition(Transition.RETRY)
        
        # Step 1: Diagnose (state is already DIAGNOSING from initial START or previous iteration)
        diagnose_result = await self.diagnose_step.execute(self._context)
        self._step_results.append(diagnose_result)
        self._context["findings"] = diagnose_result.findings
        
        # Step 2: Fix
        self.state_machine.transition(Transition.DIAGNOSIS_COMPLETE)
        fix_result = await self.fix_step.execute(self._context)
        self._step_results.append(fix_result)
        self._context["fixes"].extend(fix_result.fixes_applied)
        
        # Step 3: Attack
        self.state_machine.transition(Transition.FIX_COMPLETE)
        attack_result = await self.attack_step.execute(self._context)
        self._step_results.append(attack_result)
        self._context["vulnerabilities"] = attack_result.findings
        
        # Step 4: Validate
        self.state_machine.transition(Transition.ATTACK_COMPLETE)
        validate_result = await self.validate_step.execute(self._context)
        self._step_results.append(validate_result)
        self._context["validation_results"] = validate_result.metrics
        
        # Check for convergence
        changes_made = diagnose_result.has_changes() or fix_result.has_changes() or attack_result.has_changes()
        tests_pass = validate_result.success
        
        if not changes_made and tests_pass:
            # Convergence reached
            self.state_machine.transition(Transition.CONVERGE, {
                "tests_pass": tests_pass,
                "changes_made": changes_made,
                "iteration": self._iteration,
            })
            return True
        else:
            # Continue to next iteration
            self.state_machine.transition(Transition.RETRY, {
                "tests_pass": tests_pass,
                "changes_made": changes_made,
                "iteration": self._iteration,
            })
            return False
    
    def _calculate_metrics(self) -> dict[str, Any]:
        """Calculate aggregate metrics from all step results."""
        metrics = {
            "total_findings": 0,
            "total_fixes": 0,
            "total_vulnerabilities": 0,
            "tests_passed": 0,
            "tests_failed": 0,
            "iterations": self._iteration,
        }
        
        for result in self._step_results:
            if result.step_name == "diagnose":
                metrics["total_findings"] += len(result.findings)
            elif result.step_name == "fix":
                metrics["total_fixes"] += len(result.fixes_applied)
            elif result.step_name == "attack":
                metrics["total_vulnerabilities"] += len(result.findings)
            elif result.step_name == "validate":
                if result.success:
                    metrics["tests_passed"] += 1
                else:
                    metrics["tests_failed"] += 1
        
        return metrics
    
    def stop(self) -> None:
        """Stop the pipeline."""
        self._running = False
