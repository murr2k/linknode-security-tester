#!/usr/bin/env python3
"""Main CLI entry point for Linknode Security Tester."""

import click
import asyncio
import logging
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.logging import RichHandler
import json

from src.core.orchestrator import ScanOrchestrator
from src.core.config import settings

# Setup rich console
console = Console()

# Setup logging with rich
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version=settings.version, prog_name=settings.app_name)
def cli():
    """Linknode Security Tester - Comprehensive website quality and penetration testing tool."""
    pass


@cli.command()
@click.argument('target_url')
@click.option(
    '--scan-types',
    '-t',
    multiple=True,
    default=['security'],
    help='Types of scans to run (security, quality, performance)'
)
@click.option(
    '--output',
    '-o',
    type=click.Path(),
    help='Output file for results'
)
@click.option(
    '--format',
    '-f',
    type=click.Choice(['json', 'html', 'pdf']),
    default='json',
    help='Output format'
)
def scan(target_url: str, scan_types: tuple, output: str, format: str):
    """Run security scan on target URL."""
    console.print(f"\n[bold cyan]{settings.app_name} v{settings.version}[/bold cyan]")
    console.print(f"[yellow]Target:[/yellow] {target_url}")
    console.print(f"[yellow]Scan Types:[/yellow] {', '.join(scan_types)}\n")
    
    # Initialize orchestrator
    orchestrator = ScanOrchestrator()
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            # Initialize components
            task = progress.add_task("Initializing components...", total=None)
            orchestrator.initialize()
            progress.update(task, completed=True)
            
            # Run scan
            task = progress.add_task(f"Running {', '.join(scan_types)} scan...", total=None)
            results = asyncio.run(
                orchestrator.run_comprehensive_scan(target_url, list(scan_types))
            )
            progress.update(task, completed=True)
        
        # Display results summary
        display_scan_summary(results)
        
        # Save results if output specified
        if output:
            save_results(results, output, format)
            console.print(f"\n[green]✓[/green] Results saved to: {output}")
        
    except Exception as e:
        console.print(f"\n[red]✗ Error:[/red] {str(e)}")
        logger.exception("Scan failed")
        sys.exit(1)
    finally:
        orchestrator.cleanup()


@cli.command()
@click.argument('target_url')
def check_owasp(target_url: str):
    """Check target for OWASP Top 10 vulnerabilities."""
    console.print(f"\n[bold cyan]OWASP Top 10 Check[/bold cyan]")
    console.print(f"[yellow]Target:[/yellow] {target_url}\n")
    
    orchestrator = ScanOrchestrator()
    
    try:
        orchestrator.initialize()
        
        # Run OWASP check
        from src.scanners.security import SecurityScanner
        scanner = SecurityScanner(orchestrator.zap_client)
        
        with console.status("Checking for OWASP Top 10 vulnerabilities..."):
            results = scanner.check_owasp_top_10(target_url)
        
        # Display results
        table = Table(title="OWASP Top 10 Results")
        table.add_column("Category", style="cyan")
        table.add_column("Found", style="red")
        table.add_column("Count", style="yellow")
        
        for category, data in results['owasp_top_10_results'].items():
            found = "✓" if data['found'] else "✗"
            table.add_row(category, found, str(data['count']))
        
        console.print(table)
        
    except Exception as e:
        console.print(f"\n[red]✗ Error:[/red] {str(e)}")
        sys.exit(1)
    finally:
        orchestrator.cleanup()


@cli.command()
@click.option('--port', '-p', default=8000, help='API server port')
@click.option('--host', '-h', default='0.0.0.0', help='API server host')
def serve(port: int, host: str):
    """Start the web dashboard and API server."""
    console.print(f"\n[bold cyan]Starting Linknode Security Tester API[/bold cyan]")
    console.print(f"[yellow]Host:[/yellow] {host}")
    console.print(f"[yellow]Port:[/yellow] {port}")
    console.print(f"\n[green]Dashboard:[/green] http://localhost:{port}")
    console.print(f"[green]API Docs:[/green] http://localhost:{port}/docs\n")
    
    # Import and run FastAPI app
    try:
        import uvicorn
        uvicorn.run(
            "src.api.main:app",
            host=host,
            port=port,
            reload=settings.debug
        )
    except ImportError:
        console.print("[red]✗ Error:[/red] API dependencies not installed")
        console.print("Run: pip install fastapi uvicorn")
        sys.exit(1)


@cli.command()
def start_zap():
    """Start OWASP ZAP daemon in Docker."""
    console.print("\n[bold cyan]Starting OWASP ZAP Daemon[/bold cyan]\n")
    
    import subprocess
    
    cmd = [
        "docker", "run",
        "-u", "zap",
        "-p", "8080:8080",
        "-d",
        "--name", "zap-daemon",
        "owasp/zap2docker-stable",
        "zap.sh",
        "-daemon",
        "-host", "0.0.0.0",
        "-port", "8080",
        "-config", f"api.key={settings.zap.api_key}"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            console.print("[green]✓[/green] ZAP daemon started successfully")
            console.print(f"[yellow]Container ID:[/yellow] {result.stdout.strip()}")
            console.print(f"\n[cyan]ZAP API:[/cyan] http://localhost:8080")
            console.print(f"[cyan]API Key:[/cyan] {settings.zap.api_key}")
        else:
            console.print(f"[red]✗ Error:[/red] {result.stderr}")
    except FileNotFoundError:
        console.print("[red]✗ Error:[/red] Docker not found. Please install Docker.")
        sys.exit(1)


@cli.command()
def stop_zap():
    """Stop OWASP ZAP daemon."""
    console.print("\n[bold cyan]Stopping OWASP ZAP Daemon[/bold cyan]\n")
    
    import subprocess
    
    try:
        # Stop container
        subprocess.run(["docker", "stop", "zap-daemon"], capture_output=True)
        # Remove container
        subprocess.run(["docker", "rm", "zap-daemon"], capture_output=True)
        console.print("[green]✓[/green] ZAP daemon stopped")
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {str(e)}")


def display_scan_summary(results: Dict):
    """Display scan results summary."""
    summary = results.get('summary', {})
    
    # Summary table
    table = Table(title="\nScan Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="yellow")
    
    table.add_row("Total Issues", str(summary.get('total_issues', 0)))
    table.add_row("High Risk", str(summary.get('high_risk_issues', 0)))
    table.add_row("Medium Risk", str(summary.get('medium_risk_issues', 0)))
    table.add_row("Low Risk", str(summary.get('low_risk_issues', 0)))
    
    if 'security' in results['results']:
        security = results['results']['security']
        table.add_row("Risk Score", f"{security.get('risk_score', 0)}/100")
    
    table.add_row("Scan Duration", f"{results.get('duration', 0):.2f}s")
    
    console.print(table)
    
    # Recommendations
    if summary.get('recommendations'):
        console.print("\n[bold yellow]Recommendations:[/bold yellow]")
        for rec in summary['recommendations']:
            console.print(f"  • {rec}")


def save_results(results: Dict, output_path: str, format: str):
    """Save scan results to file."""
    if format == 'json':
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    elif format == 'html':
        # TODO: Implement HTML report generation
        console.print("[yellow]HTML reports coming soon![/yellow]")
        # For now, save as JSON
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    elif format == 'pdf':
        # TODO: Implement PDF report generation
        console.print("[yellow]PDF reports coming soon![/yellow]")
        # For now, save as JSON
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)


if __name__ == '__main__':
    cli()