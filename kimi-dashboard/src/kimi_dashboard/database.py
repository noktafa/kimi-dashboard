"""Database models and operations for dashboard."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite


@dataclass
class SessionRecord:
    """Record of a convergence session."""
    
    session_id: str
    start_time: datetime
    end_time: datetime | None = None
    final_state: str = "RUNNING"
    iterations: int = 0
    convergence_reached: bool = False
    metrics: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    
    @property
    def duration_seconds(self) -> float:
        """Calculate duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now() - self.start_time).total_seconds()


@dataclass
class EventRecord:
    """Record of a convergence event."""
    
    event_id: str
    session_id: str
    timestamp: datetime
    iteration: int
    state: str
    event_type: str
    data: dict[str, Any] = field(default_factory=dict)


class Database:
    """SQLite database for dashboard data."""
    
    def __init__(self, db_path: str | Path = "./dashboard.db"):
        self.db_path = Path(db_path)
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize database tables."""
        if self._initialized:
            return
        
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        async with aiosqlite.connect(self.db_path) as db:
            # Sessions table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP,
                    final_state TEXT DEFAULT 'RUNNING',
                    iterations INTEGER DEFAULT 0,
                    convergence_reached BOOLEAN DEFAULT 0,
                    metrics TEXT DEFAULT '{}',
                    error TEXT DEFAULT ''
                )
            """)
            
            # Events table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    iteration INTEGER DEFAULT 0,
                    state TEXT DEFAULT 'IDLE',
                    event_type TEXT NOT NULL,
                    data TEXT DEFAULT '{}',
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)
            
            # Create indexes
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_session 
                ON events(session_id)
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_timestamp 
                ON events(timestamp)
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_start_time 
                ON sessions(start_time DESC)
            """)
            
            await db.commit()
        
        self._initialized = True
    
    async def create_session(self, session: SessionRecord) -> None:
        """Create a new session record."""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO sessions 
                (session_id, start_time, end_time, final_state, iterations, 
                 convergence_reached, metrics, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.start_time.isoformat(),
                    session.end_time.isoformat() if session.end_time else None,
                    session.final_state,
                    session.iterations,
                    session.convergence_reached,
                    json.dumps(session.metrics),
                    session.error,
                )
            )
            await db.commit()
    
    async def update_session(self, session: SessionRecord) -> None:
        """Update an existing session record."""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                UPDATE sessions SET
                    end_time = ?,
                    final_state = ?,
                    iterations = ?,
                    convergence_reached = ?,
                    metrics = ?,
                    error = ?
                WHERE session_id = ?
                """,
                (
                    session.end_time.isoformat() if session.end_time else None,
                    session.final_state,
                    session.iterations,
                    session.convergence_reached,
                    json.dumps(session.metrics),
                    session.error,
                    session.session_id,
                )
            )
            await db.commit()
    
    async def add_event(self, event: EventRecord) -> None:
        """Add an event record."""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO events 
                (event_id, session_id, timestamp, iteration, state, event_type, data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.session_id,
                    event.timestamp.isoformat(),
                    event.iteration,
                    event.state,
                    event.event_type,
                    json.dumps(event.data),
                )
            )
            await db.commit()
    
    async def get_sessions(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> list[SessionRecord]:
        """Get historical sessions."""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT * FROM sessions 
                ORDER BY start_time DESC 
                LIMIT ? OFFSET ?
                """,
                (limit, offset)
            )
            rows = await cursor.fetchall()
            
            return [
                SessionRecord(
                    session_id=row["session_id"],
                    start_time=datetime.fromisoformat(row["start_time"]),
                    end_time=datetime.fromisoformat(row["end_time"]) if row["end_time"] else None,
                    final_state=row["final_state"],
                    iterations=row["iterations"],
                    convergence_reached=bool(row["convergence_reached"]),
                    metrics=json.loads(row["metrics"]),
                    error=row["error"],
                )
                for row in rows
            ]
    
    async def get_session_events(
        self,
        session_id: str,
        limit: int = 1000,
    ) -> list[EventRecord]:
        """Get events for a specific session."""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT * FROM events 
                WHERE session_id = ?
                ORDER BY timestamp ASC 
                LIMIT ?
                """,
                (session_id, limit)
            )
            rows = await cursor.fetchall()
            
            return [
                EventRecord(
                    event_id=row["event_id"],
                    session_id=row["session_id"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    iteration=row["iteration"],
                    state=row["state"],
                    event_type=row["event_type"],
                    data=json.loads(row["data"]),
                )
                for row in rows
            ]
    
    async def get_session_stats(self) -> dict[str, Any]:
        """Get aggregate statistics."""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            # Total sessions
            cursor = await db.execute("SELECT COUNT(*) FROM sessions")
            total_sessions = (await cursor.fetchone())[0]
            
            # Converged sessions
            cursor = await db.execute(
                "SELECT COUNT(*) FROM sessions WHERE convergence_reached = 1"
            )
            converged_sessions = (await cursor.fetchone())[0]
            
            # Average iterations
            cursor = await db.execute(
                "SELECT AVG(iterations) FROM sessions WHERE iterations > 0"
            )
            row = await cursor.fetchone()
            avg_iterations = row[0] if row[0] else 0
            
            # Total events
            cursor = await db.execute("SELECT COUNT(*) FROM events")
            total_events = (await cursor.fetchone())[0]
            
            return {
                "total_sessions": total_sessions,
                "converged_sessions": converged_sessions,
                "convergence_rate": converged_sessions / total_sessions if total_sessions > 0 else 0,
                "avg_iterations": round(avg_iterations, 2),
                "total_events": total_events,
            }
