"""CLI entry point for kimi-converge."""

from __future__ import annotations

import asyncio
import signal
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .config import Config, load_config
from .event_bus import ConsoleEventHandler, EventBus
from .pipeline import Pipeline


console = Console()


def print_banner() -> None:
    """Print the CLI banner."""
    banner = Panel.fit(
        f"[bold cyan]Kimi Convergence Loop[/bold cyan]\n"
        f"[dim]Version {__version__}[/dim]\n"
        f"[dim]Self-healing pipeline for iterative system improvement[/dim]",
        border_style="cyan",
    )
    console.print(banner)
    console.print()


def print_results(result) -> None:
    """Print pipeline results."""
    console.print()
    
    if result.convergence_reached:
        console.print(Panel(
            f"[bold green]✓ Convergence reached![/bold green]\n"
            f"Completed in {result.iterations} iterations "
            f"({result.duration_seconds:.2f}s)",
            title="Success",
            border_style="green",
        ))
    elif result.final_state.name == "FAILED":
        console.print(Panel(
            f"[bold red]✗ Pipeline failed[/bold red]\n"
            f"{result.error or 'Unknown error'}\n"
            f"Completed {result.iterations} iterations "
            f"({result.duration_seconds:.2f}s)",
            title="Failed",
            border_style="red",
        ))
    else:
        console.print(Panel(
            f"[bold yellow]⚠ Did not converge[/bold yellow]\n"
            f"Completed {result.iterations} iterations "
            f"({result.duration_seconds:.2f}s)",
            title="Incomplete",
            border_style="yellow",
        ))
    
    # Print metrics table
    if result.metrics:
        console.print()
        table = Table(title="Metrics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        for key, value in result.metrics.items():
            table.add_row(key.replace("_", " ").title(), str(value))
        
        console.print(table)


@click.group()
@click.version_option(version=__version__, prog_name="kimi-converge")
def cli() -> None:
    """Kimi Convergence Loop - Self-healing pipeline for iterative system improvement."""
    pass


@cli.command("run")
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file",
)
@click.option(
    "--target", "-t",
    type=click.Path(path_type=Path),
    help="Target path to analyze/fix",
)
@click.option(
    "--max-iterations", "-i",
    type=int,
    help="Maximum number of iterations",
)
@click.option(
    "--webhook-url", "-w",
    type=str,
    help="Webhook URL for events",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="Suppress non-error output",
)
def run(
    config: Path | None,
    target: Path | None,
    max_iterations: int | None,
    webhook_url: str | None,
    verbose: bool,
    quiet: bool,
) -> None:
    """Run the Kimi Convergence Loop.
    
    The convergence loop iteratively diagnoses, fixes, attacks, and validates
    a target system until convergence is reached or max iterations exceeded.
    """
    if not quiet:
        print_banner()
    
    # Load configuration
    try:
        cfg = load_config(
            config_path=config,
            target=str(target) if target else None,
        )
    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    
    # Apply CLI overrides
    if max_iterations is not None:
        cfg.loop.max_iterations = max_iterations
    
    if webhook_url is not None:
        cfg.events.webhook_url = webhook_url
    
    if not quiet:
        console.print(f"[dim]Target:[/dim] {cfg.target}")
        console.print(f"[dim]Max iterations:[/dim] {cfg.loop.max_iterations}")
        console.print()
    
    # Create event bus
    event_bus = EventBus(
        webhook_url=cfg.events.webhook_url,
        emit_interval=cfg.events.emit_interval,
        buffer_size=cfg.events.buffer_size,
    )
    
    # Add console handler if not quiet
    if not quiet:
        console_handler = ConsoleEventHandler(verbose=verbose)
        event_bus.register_handler(console_handler)
    
    # Create pipeline
    pipeline = Pipeline(cfg, event_bus)
    
    # Setup signal handlers
    def signal_handler(sig, frame):
        console.print("\n[yellow]Received interrupt signal, stopping...[/yellow]")
        pipeline.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the pipeline
    try:
        result = asyncio.run(pipeline.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    
    # Print results
    if not quiet:
        print_results(result)
    
    # Exit with appropriate code
    if result.convergence_reached:
        sys.exit(0)
    elif result.final_state.name == "FAILED":
        sys.exit(1)
    else:
        sys.exit(2)


@cli.group("config")
def config_group() -> None:
    """Configuration management commands."""
    pass


@config_group.command("init")
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default="convergence.yaml",
    help="Output file path",
)
def config_init(output: Path) -> None:
    """Initialize a new configuration file."""
    if output.exists():
        if not click.confirm(f"{output} already exists. Overwrite?"):
            return
    
    cfg = Config()
    cfg.to_yaml(output)
    
    console.print(f"[green]Created configuration file: {output}[/green]")


@config_group.command("validate")
@click.argument("config_file", type=click.Path(exists=True, path_type=Path))
def config_validate(config_file: Path) -> None:
    """Validate a configuration file."""
    try:
        cfg = Config.from_yaml(config_file)
        console.print(f"[green]✓ Configuration is valid[/green]")
        console.print()
        console.print(f"[dim]Target:[/dim] {cfg.target}")
        console.print(f"[dim]Max iterations:[/dim] {cfg.loop.max_iterations}")
        console.print(f"[dim]Steps:[/dim] {', '.join(cfg.steps.keys())}")
    except Exception as e:
        console.print(f"[red]✗ Invalid configuration: {e}[/red]")
        sys.exit(1)


# Alias 'run' as default command
def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
