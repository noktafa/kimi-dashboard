"""CLI for dashboard server."""

import argparse
import os


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Kimi Dashboard Server")
    parser.add_argument(
        "--host",
        default=os.getenv("DASHBOARD_HOST", "0.0.0.0"),
        help="Server host (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("DASHBOARD_PORT", "8766")),
        help="Server port (default: 8766)",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use mock convergence data for testing",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )
    parser.add_argument(
        "--convergence-url",
        default=os.getenv("CONVERGENCE_WS_URL", "ws://localhost:8765"),
        help="WebSocket URL for convergence loop (default: ws://localhost:8765)",
    )
    parser.add_argument(
        "--db-path",
        default=os.getenv("DASHBOARD_DB_PATH", "./dashboard.db"),
        help="SQLite database path (default: ./dashboard.db)",
    )
    
    args = parser.parse_args()
    
    # Set environment variables
    if args.mock:
        os.environ["DASHBOARD_MOCK"] = "true"
    os.environ["CONVERGENCE_WS_URL"] = args.convergence_url
    os.environ["DASHBOARD_DB_PATH"] = args.db_path
    
    import uvicorn
    uvicorn.run(
        "kimi_dashboard.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
