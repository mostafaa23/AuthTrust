import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from target_scope_manager.scope_manager import (
    ScopeError,
    ScopeManager,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Wily - Target & Scope Manager"
    )

    parser.add_argument(
        "target",
        help="Authorized target domain, e.g. example.com",
    )

    parser.add_argument(
        "--check",
        action="append",
        default=[],
        help="Check whether a URL is inside scope. Can be repeated.",
    )

    parser.add_argument(
        "--exclude-host",
        action="append",
        default=[],
        help="Exclude a host and its subdomains. Can be repeated.",
    )

    parser.add_argument(
        "--no-subdomains",
        action="store_true",
        help="Allow only the exact target domain.",
    )

    parser.add_argument(
        "--save-scope",
        help="Save the scope configuration to a JSON file.",
    )

    args = parser.parse_args()

    try:
        scope = ScopeManager(
            args.target,
            allow_subdomains=not args.no_subdomains,
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