"""ASCII Banner and UI elements for SecAudit."""

from rich.console import Console
from rich.text import Text
from rich.panel import Panel

BANNER = r"""
   ▄████████    ▄████████  ▄████████    ▄████████ ███    █▄  ████████▄   ▄█      ███     
  ███    ███   ███    ███ ███    ███   ███    ███ ███    ███ ███   ▀███ ███  ▀█████████▄ 
  ███    █▀    ███    █▀  ███    █▀    ███    ███ ███    ███ ███    ███ ███▌    ▀███▀▀██ 
  ███         ▄███▄▄▄     ███          ███    ███ ███    ███ ███    ███ ███▌     ███   ▀ 
▀███████████ ▀▀███▀▀▀     ███        ▀███████████ ███    ███ ███    ███ ███▌     ███     
         ███   ███    █▄  ███    █▄    ███    ███ ███    ███ ███    ███ ███      ███     
   ▄█    ███   ███    ███ ███    ███   ███    ███ ███    ███ ███   ▄███ ███      ███     
 ▄████████▀    ██████████  ████████▀   ███    █▀  ████████▀  ████████▀  █▀      ▄████▀   
"""

SUBTITLE = "Web Security Audit Tool v1.0 — For Authorized Testing Only"


def print_banner():
    """Print the ASCII art banner."""
    console = Console()

    # Print banner in gradient colors
    lines = BANNER.split('\n')
    colors = [
        "#ff6b6b", "#ff8e72", "#ffb347", "#ffd700",
        "#98fb98", "#87ceeb", "#9b59b6", "#e74c3c",
        "#ff6b6b", "#ff8e72"
    ]

    for i, line in enumerate(lines):
        if line.strip():
            color = colors[i % len(colors)]
            console.print(f"[bold {color}]{line}[/bold {color}]")

    console.print()
    console.print(Panel(
        f"[bold white]{SUBTITLE}[/bold white]\n"
        "[dim cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim cyan]\n"
        "[dim]🔍 Scans: Headers · Secrets · Stack · SSL · Cookies · Forms · JS[/dim]\n"
        "[dim]🛡️  Detects: API Keys · Tokens · Misconfigs · Info Leaks · XSS[/dim]\n"
        "[dim]📋 Reports: Findings · Exploit Details · Patch Guidance[/dim]",
        title="[bold red]☠  SECAUDIT[/bold red]",
        subtitle="[dim]github.com/secaudit[/dim]",
        border_style="bright_red",
        padding=(1, 4)
    ))
