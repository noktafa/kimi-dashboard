"""CLI entry point for kimi-admin."""

import os
import sys
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm

from kimi_sysadmin_ai import __version__
from kimi_sysadmin_ai.llm_client import LLMClient
from kimi_sysadmin_ai.safety import SafetyFilter, SafetyLevel
from kimi_sysadmin_ai.policy_engine import PolicyEngine, PolicyInput
from kimi_sysadmin_ai.executors.host import HostExecutor
from kimi_sysadmin_ai.executors.docker import DockerExecutor
from kimi_sysadmin_ai.executors.kubernetes import KubernetesExecutor


console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="kimi-admin")
@click.option('--api-key', envvar='OPENAI_API_KEY', help='OpenAI API key')
@click.option('--base-url', envvar='OPENAI_BASE_URL', help='API base URL')
@click.option('--model', default='gpt-4o-mini', help='Model to use')
@click.pass_context
def cli(ctx: click.Context, api_key: Optional[str], base_url: Optional[str], 
        model: str) -> None:
    """Kimi Sysadmin AI - Secure system administration assistant."""
    ctx.ensure_object(dict)
    ctx.obj['api_key'] = api_key
    ctx.obj['base_url'] = base_url
    ctx.obj['model'] = model


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show system status and availability."""
    console.print(Panel.fit("[bold blue]Kimi Sysadmin AI Status[/bold blue]"))
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Component")
    table.add_column("Status")
    table.add_column("Details")
    
    # Safety filter
    safety = SafetyFilter()
    table.add_row(
        "Safety Filter",
        "[green]✓ Ready[/green]",
        f"{len(safety.BLOCKLIST)} block patterns, {len(safety.GRAYLIST)} gray patterns"
    )
    
    # Policy engine
    policy = PolicyEngine()
    backend_info = policy.get_backend_info()
    opa_status = "[green]✓ Connected[/green]" if backend_info["opa_backend"]["available"] else "[yellow]✗ Not available[/yellow]"
    table.add_row(
        "Policy Engine",
        "[green]✓ Ready[/green]",
        f"OPA: {opa_status}"
    )
    
    # Executors
    host_exec = HostExecutor()
    table.add_row(
        "Host Executor",
        "[green]✓ Available[/green]" if host_exec.is_available() else "[red]✗ Unavailable[/red]",
        "Direct host execution"
    )
    
    docker_exec = DockerExecutor()
    docker_available = docker_exec.is_available()
    table.add_row(
        "Docker Executor",
        "[green]✓ Available[/green]" if docker_available else "[yellow]✗ Not available[/yellow]",
        "Docker execution" if docker_available else "Docker not found"
    )
    
    k8s_exec = KubernetesExecutor()
    k8s_available = k8s_exec.is_available()
    table.add_row(
        "Kubernetes Executor",
        "[green]✓ Available[/green]" if k8s_available else "[yellow]✗ Not available[/yellow]",
        "K8s pod execution" if k8s_available else "K8s not configured"
    )
    
    # API
    api_key = ctx.obj.get('api_key') or os.environ.get('OPENAI_API_KEY')
    table.add_row(
        "LLM API",
        "[green]✓ Configured[/green]" if api_key else "[yellow]✗ Not configured[/yellow]",
        f"Model: {ctx.obj.get('model', 'gpt-4o-mini')}" if api_key else "Set OPENAI_API_KEY"
    )
    
    console.print(table)


@cli.command()
@click.argument('command')
@click.option('--executor', '-e', default='host', 
              type=click.Choice(['host', 'docker', 'kubernetes']),
              help='Executor to use')
@click.option('--timeout', '-t', default=60, help='Timeout in seconds')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation for graylisted commands')
@click.pass_context
def run(ctx: click.Context, command: str, executor: str, timeout: int, yes: bool) -> None:
    """Run a command with safety checks."""
    # First check safety
    safety = SafetyFilter()
    safety_result = safety.check(command)
    
    if safety_result.level == SafetyLevel.BLOCK:
        console.print(f"[bold red]✗ BLOCKED:[/bold red] {safety_result.reason}")
        sys.exit(1)
    
    if safety_result.level == SafetyLevel.GRAY and not yes:
        console.print(f"[bold yellow]⚠ GRAYLISTED:[/bold yellow] {safety_result.reason}")
        if not Confirm.ask("Do you want to proceed?"):
            console.print("[yellow]Aborted[/yellow]")
            sys.exit(0)
    
    # Execute
    if executor == 'host':
        exec_impl = HostExecutor(allow_gray=yes)
    elif executor == 'docker':
        exec_impl = DockerExecutor(allow_gray=yes)
    else:
        exec_impl = KubernetesExecutor(allow_gray=yes)
    
    if not exec_impl.is_available():
        console.print(f"[bold red]✗ {executor} executor is not available[/bold red]")
        sys.exit(1)
    
    console.print(f"[dim]Executing with {executor} executor...[/dim]")
    result = exec_impl.execute(command, timeout=timeout)
    
    if result.stdout:
        console.print(result.stdout)
    
    if result.stderr:
        console.print(f"[red]{result.stderr}[/red]")
    
    if result.success:
        console.print(f"[green]✓ Success[/green] (took {result.duration_ms}ms)")
    else:
        console.print(f"[red]✗ Failed with code {result.returncode}[/red]")
        sys.exit(result.returncode)


@cli.command()
@click.option('--executor', '-e', default='host',
              type=click.Choice(['host', 'docker', 'kubernetes']),
              help='Default executor')
@click.option('--yes', '-y', is_flag=True, help='Auto-confirm graylisted commands')
@click.pass_context
def chat(ctx: click.Context, executor: str, yes: bool) -> None:
    """Start interactive chat with the AI assistant."""
    api_key = ctx.obj.get('api_key') or os.environ.get('OPENAI_API_KEY')
    
    if not api_key:
        console.print("[bold red]Error:[/bold red] OPENAI_API_KEY not set")
        sys.exit(1)
    
    try:
        client = LLMClient(
            api_key=api_key,
            base_url=ctx.obj.get('base_url'),
            model=ctx.obj.get('model', 'gpt-4o-mini')
        )
        client.register_default_tools()
    except Exception as e:
        console.print(f"[bold red]Error initializing LLM client:[/bold red] {e}")
        sys.exit(1)
    
    # Set up executor
    if executor == 'host':
        exec_impl: HostExecutor = HostExecutor(allow_gray=yes)
    elif executor == 'docker':
        exec_impl = DockerExecutor(allow_gray=yes)
    else:
        exec_impl = KubernetesExecutor(allow_gray=yes)
    
    # Override tool handlers to use our executor with safety
    safety = SafetyFilter()
    
    def safe_run_command(command: str, timeout: int = 60, working_dir: str = "."):
        """Safe command execution with our executor."""
        result = exec_impl.execute(command, timeout=timeout, working_dir=working_dir)
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.success
        }
    
    # Replace the handler
    client.handlers['run_command'] = safe_run_command
    
    console.print(Panel.fit(
        "[bold green]Kimi Sysadmin AI[/bold green]\n"
        "Type your questions or tasks. Use /quit to exit.\n"
        f"Executor: [cyan]{executor}[/cyan] | Safety: [cyan]Enabled[/cyan]"
    ))
    
    messages = [
        {
            "role": "system",
            "content": (
                "You are a helpful system administration assistant. "
                "You have access to tools for reading files, listing directories, "
                "running commands, and getting system info. "
                "Always prioritize safety and explain what you're doing. "
                "All commands are filtered for dangerous operations."
            )
        }
    ]
    
    while True:
        try:
            user_input = console.input("[bold blue]You:[/bold blue] ")
            
            if user_input.lower() in ['/quit', '/exit', '/q']:
                console.print("[dim]Goodbye![/dim]")
                break
            
            if user_input.lower() == '/help':
                console.print(
                    "[bold]Available commands:[/bold]\n"
                    "  /quit, /exit, /q - Exit the chat\n"
                    "  /help - Show this help\n"
                    "  /status - Show system status"
                )
                continue
            
            if user_input.lower() == '/status':
                ctx.invoke(status)
                continue
            
            if not user_input.strip():
                continue
            
            messages.append({"role": "user", "content": user_input})
            
            with console.status("[bold green]Thinking...[/bold green]"):
                response = client.chat(messages)
            
            console.print(f"[bold green]AI:[/bold green] {response}")
            messages.append({"role": "assistant", "content": response})
            
        except KeyboardInterrupt:
            console.print("\n[dim]Use /quit to exit[/dim]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


@cli.command()
@click.argument('command')
def check(command: str) -> None:
    """Check if a command would be allowed (dry-run)."""
    safety = SafetyFilter()
    result = safety.check(command)
    
    table = Table(show_header=False)
    table.add_column("Property")
    table.add_column("Value")
    
    table.add_row("Command", command)
    
    if result.level.value == "safe":
        table.add_row("Status", "[green]✓ SAFE[/green]")
    elif result.level.value == "gray":
        table.add_row("Status", "[yellow]⚠ GRAYLISTED (requires confirmation)[/yellow]")
    else:
        table.add_row("Status", "[red]✗ BLOCKED[/red]")
    
    table.add_row("Reason", result.reason)
    
    console.print(table)


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()
