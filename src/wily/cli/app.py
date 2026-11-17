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
    confirm_s3_writes: bool = typer.Option(
        False, "--confirm-s3-writes/--no-s3-writes",
        help=(
            "Report S3 write/delete exposure. OFF by default (safe). Even when "
            "on, Wily only READS the bucket ACL/policy and infers writability "
            "from a public WRITE grant - it never sends a PUT/DELETE, so it "
            "cannot overwrite or delete objects on any target."
        ),
    ),
    probe_live: bool = typer.Option(
        False, "--probe-live/--no-probe-live",
        help=(
            "Before scanning, drop discovered/imported endpoints that don't "
            "answer a cheap HEAD/GET liveness probe. OFF by default; "
            "de-duplication of near-identical URLs always runs regardless. The "
            "probe goes through the shared, scope-enforced HTTP engine."
        ),
    ),
    cloud_enum: bool = typer.Option(
        False, "--cloud-enum/--no-cloud-enum",
        help=(
            "Enumerate cloud storage (AWS S3 / Azure Blob / GCP) by generating "
            "candidate bucket names from the target keyword(s) and mutations "
            "(cloud_enum-style), then probing each - read-only. Existing AWS "
            "buckets are auto-handed to the deep s3_bucket scan. OFF by default."
        ),
    ),
    cloud_keyword: list[str] = typer.Option(
        None, "--cloud-keyword",
        help=(
            "Extra keyword(s) to seed cloud-enum name generation (repeatable). "
            "The target's own name is derived from the domain automatically."
        ),
    ),
    cloud_enum_wordlist: str = typer.Option(
        None, "--cloud-enum-wordlist",
        help=(
            "Path to a mutations wordlist (one per line, e.g. cloud_enum's "
            "fuzz.txt) replacing the built-in default list."
        ),
    ),
    cloud_enum_max: int = typer.Option(
        300, "--cloud-enum-max",
        help="Cap on generated candidate names probed per run (default 300).",
    ),
    output: str = typer.Option("wily-report.json", "-o", "--output", help="Path to write the unified report to."),
    report_format: list[str] = typer.Option(
        None, "-f", "--format",
        help=(
            "Report format(s): json, html, sarif. Repeatable and/or "
            "comma-separated (e.g. --format html,sarif). Default: json. "
            "Non-JSON formats are written as siblings of -o with their own "
            "extension (wily-report.html, wily-report.sarif)."
        ),
    ),
    show_leak: bool = typer.Option(
        False, "--show-leak",
        help=(
            "Write evidence UNREDACTED (captured AWS keys/tokens stay visible "
            "in the report). For a controlled demo only - off by default, which "
            "redacts secrets."
        ),
    ),
    burp_xml: str = typer.Option(
        None, "--burp-xml",
        help=(
            "Import a Burp Suite 'Save items' XML export instead of (or alongside) "
            "live discovery. Endpoints/tokens/S3 links are parsed offline and the "
            "in-scope endpoints are fed into the scan queue."
        ),
    ),
    import_har: str = typer.Option(
        None, "--import-har",
        help=(
            "Import a HAR capture (browser/DevTools). Same offline parse as "
            "--burp-xml: endpoints, bearer tokens and S3 links are extracted."
        ),
    ),
    scope_bucket: list[str] = typer.Option(
        None, "--scope-bucket",
        help="S3 bucket name or glob pattern in scope (e.g. 'target-*'). Repeatable.",
    ),
    scope_account: list[str] = typer.Option(
        None, "--scope-account",
        help=(
            "AWS account id or ARN prefix in scope (e.g. 123456789012 or "
            "'arn:aws:iam::123456789012:*'). Restricts IAM analysis. Repeatable."
        ),
    ),
    scope_config: str = typer.Option(
        None, "--scope-config",
        help="JSON/YAML file with 'buckets', 'accounts' and 'exclude' scope lists.",
    ),
) -> None:
    """The full bundle, automatically (Discovery + Auth Bypass + CORS + SSRF)
    against any domain, enabling JWT/BOLA/IAM based on the inputs you provide."""
    if not domain and not iam_file and not burp_xml and not import_har:
        typer.echo(
            "You must provide a domain, --iam-file, --burp-xml or --import-har at "
            "minimum. Try: wily scan --help"
        )
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
            report_formats=report_format or [],
            confirm_destructive=confirm_destructive,
            confirm_owned_infra=confirm_owned_infra,
            confirm_s3_writes=confirm_s3_writes,
            probe_live=probe_live,
            cloud_enum=cloud_enum,
            cloud_keywords=cloud_keyword or [],
            cloud_enum_wordlist=cloud_enum_wordlist,
            cloud_enum_max=cloud_enum_max,
            show_leak=show_leak,
            burp_xml=burp_xml,
            import_har=import_har,
            scope_buckets=scope_bucket or [],
            scope_accounts=scope_account or [],
            scope_config=scope_config,
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
