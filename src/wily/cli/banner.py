"""Startup banner, in the spirit of nuclei's:
- always printed to STDERR only, so stdout stays clean for piping
  (e.g. `wily scan target.com -o report.json` or `wily scan target.com | jq .`)
- uses rich.console.Console instead of hand-rolled ANSI escapes so it also
  renders correctly on Windows (older cmd/PowerShell), not just Linux/macOS.
"""

from rich.console import Console

from wily import __version__

_console_err = Console(stderr=True)

_ASCII_LOGO = r"""
 ██╗    ██╗██╗██╗  ██╗   ██╗
 ██║    ██║██║██║  ╚██╗ ██╔╝
 ██║ █╗ ██║██║██║   ╚████╔╝
 ██║███╗██║██║██║    ╚██╔╝
 ╚███╔███╔╝██║███████╗██║
  ╚══╝╚══╝ ╚═╝╚══════╝╚═╝
"""

TAGLINE = "Cloud-native, black-box API security scanner"


def print_banner(quiet: bool = False) -> None:
    """Print the banner to stderr. If quiet=True (e.g. --quiet, or inside
    Docker/CI), print nothing at all."""
    if quiet:
        return

    _console_err.print(f"[bold cyan]{_ASCII_LOGO}[/bold cyan]")
    _console_err.print(f"[white][[/white][bold cyan]*[/bold cyan][white]][/white] "
                        f"Wily - {TAGLINE}")
    _console_err.print(f"[white][[/white][bold cyan]*[/bold cyan][white]][/white] "
                        f"Version {__version__}\n")
