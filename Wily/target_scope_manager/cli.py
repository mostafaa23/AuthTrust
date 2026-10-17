import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from target_scope_manager.scope_manager import ScopeError, ScopeManager


def load_scope_file(path: str) -> dict:
    """Load and validate a previously saved scope configuration."""

    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ScopeError(f"Scope file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ScopeError("Scope file contains invalid JSON.") from exc
    except OSError as exc:
        raise ScopeError(f"Cannot read scope file: {exc}") from exc

    if not isinstance(data, dict):
        raise ScopeError("Scope configuration must be a JSON object.")

    target = data.get("target")
    allow_subdomains = data.get("allow_subdomains", False)
    excluded_hosts = data.get("excluded_hosts", [])

    if not isinstance(target, str) or not target.strip():
        raise ScopeError("Scope file is missing a valid target.")

    if not isinstance(allow_subdomains, bool):
        raise ScopeError("'allow_subdomains' must be true or false.")

    if (
        not isinstance(excluded_hosts, list)
        or not all(isinstance(host, str) for host in excluded_hosts)
    ):
        raise ScopeError("'excluded_hosts' must be a list of hostnames.")

    return {
        "target": target,
        "allow_subdomains": allow_subdomains,
        "excluded_hosts": excluded_hosts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Wily - Target & Scope Manager"
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Authorized target domain, e.g. example.com",
    )

    parser.add_argument(
        "--load-scope",
        help="Load a previously saved scope JSON file.",
    )

    parser.add_argument(
        "--include-subdomains",
        action="store_true",
        help="Include subdomains in the authorized scope.",
    )

    parser.add_argument(
        "--exclude-host",
        action="append",
        default=[],
        help="Exclude a host and its subdomains. Can be repeated.",
    )

    parser.add_argument(
        "--check",
        action="append",
        default=[],
        help="Check a URL against the scope. Can be repeated.",
    )

    parser.add_argument(
        "--save-scope",
        help="Save the scope configuration to a JSON file.",
    )

    args = parser.parse_args()

    try:
        if args.load_scope and args.target:
            raise ScopeError(
                "Provide either a target domain or --load-scope, not both."
            )

        if args.load_scope:
            config = load_scope_file(args.load_scope)

            scope = ScopeManager(
                config["target"],
                allow_subdomains=(
                    config["allow_subdomains"]
                    or args.include_subdomains
                ),
                excluded_hosts=tuple(
                    config["excluded_hosts"] + args.exclude_host
                ),
            )
        else:
            if not args.target:
                parser.error(
                    "Provide a target domain or use --load-scope."
                )

            scope = ScopeManager(
                args.target,
                allow_subdomains=args.include_subdomains,
                excluded_hosts=tuple(args.exclude_host),
            )

        print("\n=== Wily: Target & Scope Manager ===")
        print(f"Target: {scope.target}")
        print(
            "Subdomains:",
            "Allowed" if scope.allow_subdomains else "Not allowed",
        )

        if scope.excluded_hosts:
            print("Excluded hosts:", ", ".join(scope.excluded_hosts))

        out_of_scope = False

        for url in args.check:
            allowed = scope.is_in_scope(url)
            status = "IN SCOPE" if allowed else "OUT OF SCOPE"
            print(f"[{status}] {url}")

            if not allowed:
                out_of_scope = True

        if args.save_scope:
            output_path = Path(args.save_scope)

            config = {
                "target": scope.target,
                "allow_subdomains": scope.allow_subdomains,
                "excluded_hosts": list(scope.excluded_hosts),
                "created_at": datetime.now(
                    timezone.utc
                ).isoformat(),
            }

            output_path.write_text(
                json.dumps(config, indent=2),
                encoding="utf-8",
            )

            print(f"Scope saved to: {output_path.resolve()}")

        return 1 if out_of_scope else 0

    except (ScopeError, OSError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())