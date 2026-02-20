# kimi-dashboard

A real-time web dashboard for the Kimi Convergence Loop.

## Features

- Real-time WebSocket connection to convergence loop events
- Live visualization of pipeline state
- Iteration counter and progress tracking
- Live logs from each step
- Findings/vulnerabilities count
- Convergence progress with beautiful animations
- Historical runs from SQLite database
- Dark mode UI

## Architecture

```
┌─────────────────┐     WebSocket      ┌──────────────────┐
│  Convergence    │◄──────────────────►│  Dashboard       │
│  Loop (8765)    │                    │  Server (8766)   │
└─────────────────┘                    └────────┬─────────┘
                                                │
                                         ┌──────┴──────┐
                                         │  Web UI     │
                                         │  (8766)     │
                                         └─────────────┘
```

## Quick Start

```bash
# Install dependencies
pip install -e .

# Start the dashboard server
python -m kimi_dashboard.server

# Or use the CLI
kimi-dashboard

# Open browser to http://localhost:8766
```

## Configuration

Environment variables:
- `DASHBOARD_HOST` - Server host (default: 0.0.0.0)
- `DASHBOARD_PORT` - Server port (default: 8766)
- `CONVERGENCE_WS_URL` - WebSocket URL for convergence loop (default: ws://localhost:8765)
- `DASHBOARD_DB_PATH` - SQLite database path (default: ./dashboard.db)

## Development

```bash
# Run in development mode with auto-reload
python -m kimi_dashboard.server --reload
```
