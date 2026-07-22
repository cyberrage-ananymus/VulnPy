import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional, List
from .core.scanner import ScanEngine
from .core.target import Target
from .core.report import ReportGenerator
from .scanners.port_scan import PortScanner
from .scanners.sqli import SQLIScanner
from .scanners.xss import XSSScanner
from .scanners.traversal import TraversalScanner
from .scanners.ssl_check import SSLChecker
from .scanners.weak_cred import WeakCredScanner
from .scanners.cve_match import CVEMatcher
from .scanners.crawler import Crawler
from .utils.logger import setup_logger

app = typer.Typer(
    name="vulnpy",
    help="🔒 VulnPy - Professional Vulnerability Scanner",
    no_args_is_help=True
)
console = Console()

engine = ScanEngine()
engine.register(PortScanner())
engine.register(SQLIScanner())
engine.register(XSSScanner())
engine.register(TraversalScanner())
engine.register(SSLChecker())
engine.register(WeakCredScanner())
engine.register(CVEMatcher())
engine.register(Crawler())

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP, domain, or URL"),
    ports: str = typer.Option("1-1000", "--ports", "-p", help="Port range to scan"),
    scanners: Optional[List[str]] = typer.Option(None, "--scanner", "-s", help="Specific scanners to run"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option("html", "--format", "-f", help="Output format (html/json/csv)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Scan a target for vulnerabilities"""
    logger = setup_logger(verbose)

    console.print(f"\n[bold green]🔒 VulnPy Scanner[/bold green]")
    console.print(f"[dim]Target: {target}[/dim]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)
        results = engine.scan(target, scanner_names=scanners, ports=ports)
        progress.update(task, completed=True)

    for result in results:
        if result.findings:
            console.print(f"\n[bold cyan]{result.scanner_name}[/bold cyan] - {len(result.findings)} findings")
            for f in result.findings:
                severity_color = {
                    "critical": "red", "high": "orange1",
                    "medium": "yellow", "low": "green", "info": "blue"
                }.get(f.severity.value, "white")
                console.print(f"  [{severity_color}]●[/{severity_color}] {f.title}")

    total_findings = sum(len(r.findings) for r in results)
    console.print(f"\n[bold]Total findings: {total_findings}[/bold]\n")

    if output:
        reporter = ReportGenerator()
        reporter.generate(results, output, format)
        console.print(f"[green]Report saved to {output}[/green]")

@app.command()
def list_scanners():
    """List available scanners"""
    table = Table(title="Available Scanners")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    for name, desc in engine.list_scanners():
        table.add_row(name, desc)
    console.print(table)

@app.command()
def version():
    """Show VulnPy version"""
    console.print("[bold green]VulnPy v1.0.0[/bold green]")
    console.print("Professional Vulnerability Scanner")

if __name__ == "__main__":
    app()
