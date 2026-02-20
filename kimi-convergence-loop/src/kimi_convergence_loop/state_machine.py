"""State machine for managing the convergence loop."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Callable


class State(Enum):
    """States in the convergence loop state machine."""
    
    IDLE = auto()
    DIAGNOSING = auto()
    FIXING = auto()
    ATTACKING = auto()
    VALIDATING = auto()
    CONVERGED = auto()
    FAILED = auto()


class Transition(Enum):
    """Valid state transitions."""
    
    START = auto()
    DIAGNOSIS_COMPLETE = auto()
    FIX_COMPLETE = auto()
    ATTACK_COMPLETE = auto()
    VALIDATION_PASS = auto()
    VALIDATION_FAIL = auto()
    CONVERGE = auto()
    FAIL = auto()
    RETRY = auto()


# Define valid transitions
VALID_TRANSITIONS: dict[tuple[State, Transition], State] = {
    # Start the pipeline (first iteration)
    (State.IDLE, Transition.START): State.DIAGNOSING,
    
    # Iteration flow: DIAGNOSING -> FIXING -> ATTACKING -> VALIDATING
    (State.DIAGNOSING, Transition.DIAGNOSIS_COMPLETE): State.FIXING,
    (State.DIAGNOSING, Transition.FAIL): State.FAILED,
    
    (State.FIXING, Transition.FIX_COMPLETE): State.ATTACKING,
    (State.FIXING, Transition.FAIL): State.FAILED,
    
    (State.ATTACKING, Transition.ATTACK_COMPLETE): State.VALIDATING,
    (State.ATTACKING, Transition.FAIL): State.FAILED,
    
    # From VALIDATING: either converge or go back for another iteration
    (State.VALIDATING, Transition.VALIDATION_PASS): State.CONVERGED,
    (State.VALIDATING, Transition.CONVERGE): State.CONVERGED,
    (State.VALIDATING, Transition.RETRY): State.IDLE,  # Will restart with START
    (State.VALIDATING, Transition.VALIDATION_FAIL): State.IDLE,  # Will restart with START
    (State.VALIDATING, Transition.FAIL): State.FAILED,
    
    # From IDLE (after RETRY): start next iteration
    (State.IDLE, Transition.RETRY): State.DIAGNOSING,
    
    # Terminal states can restart
    (State.CONVERGED, Transition.START): State.DIAGNOSING,
    (State.FAILED, Transition.START): State.DIAGNOSING,
}


@dataclass
class StateHistoryEntry:
    """Record of a state transition."""
    
    from_state: State
    to_state: State
    transition: Transition
    timestamp: datetime
    data: dict = field(default_factory=dict)


class StateMachine:
    """State machine for the convergence loop."""
    
    def __init__(self):
        self._state = State.IDLE
        self._history: list[StateHistoryEntry] = []
        self._handlers: dict[Transition, list[Callable]] = {}
        self._state_handlers: dict[State, list[Callable]] = {}
    
    @property
    def state(self) -> State:
        """Get current state."""
        return self._state
    
    @property
    def history(self) -> list[StateHistoryEntry]:
        """Get state transition history."""
        return self._history.copy()
    
    def is_terminal(self) -> bool:
        """Check if current state is terminal."""
        return self._state in (State.CONVERGED, State.FAILED)
    
    def can_transition(self, transition: Transition) -> bool:
        """Check if a transition is valid from current state."""
        return (self._state, transition) in VALID_TRANSITIONS
    
    def transition(
        self,
        transition: Transition,
        data: dict | None = None,
    ) -> State:
        """Execute a state transition.
        
        Args:
            transition: The transition to execute
            data: Optional data associated with the transition
            
        Returns:
            The new state
            
        Raises:
            ValueError: If the transition is invalid
        """
        key = (self._state, transition)
        
        if key not in VALID_TRANSITIONS:
            raise ValueError(
                f"Invalid transition {transition.name} from state {self._state.name}"
            )
        
        from_state = self._state
        to_state = VALID_TRANSITIONS[key]
        
        # Record the transition
        entry = StateHistoryEntry(
            from_state=from_state,
            to_state=to_state,
            transition=transition,
            timestamp=datetime.now(timezone.utc),
            data=data or {},
        )
        self._history.append(entry)
        
        # Update state
        self._state = to_state
        
        # Call transition handlers
        for handler in self._handlers.get(transition, []):
            try:
                handler(from_state, to_state, transition, data)
            except Exception as e:
                print(f"Transition handler error: {e}")
        
        # Call state handlers
        for handler in self._state_handlers.get(to_state, []):
            try:
                handler(from_state, to_state, transition, data)
            except Exception as e:
                print(f"State handler error: {e}")
        
        return to_state
    
    def on_transition(
        self,
        transition: Transition,
        handler: Callable,
    ) -> None:
        """Register a handler for a transition."""
        if transition not in self._handlers:
            self._handlers[transition] = []
        self._handlers[transition].append(handler)
    
    def on_state(
        self,
        state: State,
        handler: Callable,
    ) -> None:
        """Register a handler for entering a state."""
        if state not in self._state_handlers:
            self._state_handlers[state] = []
        self._state_handlers[state].append(handler)
    
    def get_state_path(self) -> list[State]:
        """Get the sequence of states visited."""
        if not self._history:
            return [self._state]
        
        path = [self._history[0].from_state]
        for entry in self._history:
            path.append(entry.to_state)
        return path
    
    def get_loop_count(self) -> int:
        """Count how many full loops have been completed."""
        path = self.get_state_path()
        loop_count = 0
        
        for i in range(len(path) - 3):
            # A full loop: DIAGNOSING -> FIXING -> ATTACKING -> VALIDATING -> DIAGNOSING
            if (
                path[i] == State.DIAGNOSING and
                path[i+1] in (State.FIXING, State.ATTACKING) and
                path[i+2] == State.ATTACKING and
                path[i+3] == State.VALIDATING and
                i + 4 < len(path) and
                path[i+4] == State.DIAGNOSING
            ):
                loop_count += 1
        
        return loop_count
    
    def reset(self) -> None:
        """Reset the state machine to initial state."""
        self._state = State.IDLE
        self._history.clear()
    
    def __repr__(self) -> str:
        return f"StateMachine(state={self._state.name}, history={len(self._history)})"
