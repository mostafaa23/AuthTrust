"""Main entry point for the Typer app.

After `pip install .` (or `pip install -e .` during development), this
command is available directly in any terminal as `wily`:

    wily --help
    wily scan example.com                          # the full bundle, automatic
    wily scan example.com --token JWT_VALUE         # + JWT
    wily scan example.com --identity a=Bearer-x --identity b=Bearer-y  # + BOLA
    wily scan example.com --iam-file auth.json      # + IAM
    wily scan example.com --blind                   # + SSRF level 4
    wily scan example.com --confirm-destructive      # + write-method authz probes
    wily scan example.com --confirm-owned-infra      # + SSRF/IMDS checks

    wily jwt <url> --token TOKEN_VALUE              # a single, focused module
    wily authz <url>
    wily ssrf <url> --param url
    wily iam <authorization-details.json>
    wily discover <domain>
"""

import asyncio
import logging

import typer

from wily import __version__
from wily.cli.banner import print_banner
from wily.cli.commands import authz_cmd, discover_cmd, iam_cmd, jwt_cmd, scan_all, ssrf_cmd

logger = logging.getLogger("wily.cli")

app = typer.Typer(
    name="wily",
    help="Cloud-native, black-box API security scanner.",
    add_completion=True,
    no_args_is_help=True,
)


@app.command("scan")
def scan_command(
    domain: str = typer.Argument(
        None, help="Target domain (e.g. example.com). Leave empty if using --iam-file alone."
    ),
    token: str = typer.Option(None, "--token", "-t", help="A valid JWT - enables JWT Tampering checks."),
    identity: list[str] = typer.Option(
        None, "--identity",
        help="name=HeaderValue (e.g. tenant_a='Bearer xyz'). Repeat at least twice to enable BOLA.",
    ),
    iam_file: str = typer.Option(
        None, "--iam-file", help="Path to the output of: aws iam get-account-authorization-details - enables IAM checks."
    ),
    allow_local: bool = typer.Option(False, "--allow-local", help="Allow scanning 127.0.0.1/localhost (local testing only)."),
    blind: bool = typer.Option(False, "--blind", help="Enable Blind SSRF checks via a local OOB canary (level 4)."),
    confirm_destructive: bool = typer.Option(
        True, "--confirm-destructive/--no-destructive",
        help=(
            "Probe write methods (POST/PUT/DELETE/PATCH) in the Auth Bypass "
            "check. ON by default (offensive). These requests can create, "
            "modify, or delete real data on the target - pass --no-destructive "
            "to restrict to safe read methods only."
        ),
    ),
    confirm_owned_infra: bool = typer.Option(
        True, "--confirm-owned-infra/--no-owned-infra",
        help=(
            "Run the SSRF/IMDS check. ON by default (offensive). This check "
            "makes the target fetch internal metadata endpoints on your "
            "behalf - pass --no-owned-infra to skip it."
        ),
    ),
    output: str = typer.Option("wily-report.json", "-o", "--output", help="Path to write the unified report to."),
) -> None:
    """The full bundle, automatically (Discovery + Auth Bypass + CORS + SSRF)
    against any domain, enabling JWT/BOLA/IAM based on the inputs you provide."""
    if not domain and not iam_file:
        typer.echo("You must provide a domain or --iam-file at minimum. Try: wily scan --help")
        raise typer.Exit(code=1)

    asyncio.run(
        scan_all.run_full_scan(
            domain=domain,
            token=token,
            identities_raw=identity or [],
            iam_file=iam_file,
            allow_local=allow_local,
            blind=blind,
            output=output,
            confirm_destructive=confirm_destructive,
            confirm_owned_infra=confirm_owned_infra,
        )
    )


app.command("jwt", help="JWT Tampering checks only (a single, focused module).")(jwt_cmd.run)
app.command("authz", help="API Auth Bypass checks only.")(authz_cmd.run)
app.command("iam", help="IAM Privilege Escalation analysis only.")(iam_cmd.run)
app.command("ssrf", help="IMDS Cloud SSRF checks only.")(ssrf_cmd.run)
app.command("discover", help="Discover real endpoints (OpenAPI/JS/wordlist) only, with no scanning.")(discover_cmd.run)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"wily {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Don't print the banner."),
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Print the version and exit."
    ),
) -> None:
    print_banner(quiet=quiet)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
