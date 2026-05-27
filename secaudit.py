#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║  SecAudit v1.0 — Web Security Audit Tool                      ║
║  Comprehensive scanner for vibe-coded web applications        ║
╚═══════════════════════════════════════════════════════════════╝
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.banner import print_banner
from core.scanner import SecurityScanner
from core.reporter import Reporter
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
import re

console = Console()


def validate_url(url: str) -> str:
    """Validate and normalize URL."""
    url = url.strip()
    if not url:
        return ""
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = 'https://' + url
    # Remove trailing slash
    url = url.rstrip('/')
    return url


def main():
    os.system('clear' if os.name != 'nt' else 'cls')
    print_banner()

    console.print()
    url = Prompt.ask(
        "[bold cyan]🎯 Enter target URL[/bold cyan]",
        default="https://example.com"
    )

    url = validate_url(url)
    if not url:
        console.print("[bold red]✗ Invalid URL provided. Exiting.[/bold red]")
        sys.exit(1)

    console.print()
    console.print(Panel(
        f"[bold white]Target:[/bold white] [cyan]{url}[/cyan]",
        title="[bold yellow]⚡ Scan Configuration[/bold yellow]",
        border_style="yellow"
    ))
    console.print()

    # Initialize scanner
    scanner = SecurityScanner(url, console)

    # Run all scan modules
    results = scanner.run_full_scan()

    # Generate report
    reporter = Reporter(console)
    reporter.generate_report(results, url)

    console.print()
    console.print(Panel(
        "[bold green]✓ Scan complete. Review findings above.[/bold green]\n"
        "[dim]Disclaimer: This tool is for authorized security testing only.[/dim]",
        border_style="green"
    ))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠ Scan interrupted by user.[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]✗ Fatal error: {e}[/bold red]")
        sys.exit(1)
