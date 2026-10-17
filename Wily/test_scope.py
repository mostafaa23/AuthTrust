from target_scope_manager.scope_manager import ScopeManager


tests = [
    (
        "base domain",
        ScopeManager("example.com"),
        "https://example.com",
        True,
    ),
    (
        "subdomain denied by default",
        ScopeManager("example.com"),
        "https://api.example.com/v1/users",
        False,
    ),
    (
        "subdomain explicitly allowed",
        ScopeManager("example.com", allow_subdomains=True),
        "https://api.example.com",
        True,
    ),
    (
        "nested subdomain allowed",
        ScopeManager("example.com", allow_subdomains=True),
        "https://sub.api.example.com",
        True,
    ),
    (
        "suffix trick rejected",
        ScopeManager("example.com", allow_subdomains=True),
        "https://example.com.attacker.net",
        False,
    ),
    (
        "similar domain rejected",
        ScopeManager("example.com", allow_subdomains=True),
        "https://attacker-example.com",
        False,
    ),
    (
        "userinfo trick rejected",
        ScopeManager("example.com", allow_subdomains=True),
        "https://example.com@attacker.net",
        False,
    ),
    (
        "localhost rejected",
        ScopeManager("example.com", allow_subdomains=True),
        "http://localhost",
        False,
    ),
    (
        "IPv4 literal rejected",
        ScopeManager("example.com", allow_subdomains=True),
        "http://127.0.0.1",
        False,
    ),
    (
        "excluded host rejected",
        ScopeManager(
            "example.com",
            allow_subdomains=True,
            excluded_hosts=("admin.example.com",),
        ),
        "https://admin.example.com",
        False,
    ),
]

failures = []

for name, scope, url, expected in tests:
    actual = scope.is_in_scope(url)
    passed = actual == expected
    print(f"[{'PASS' if passed else 'FAIL'}] {name}: {url}")

    if not passed:
        failures.append(name)

print(f"\nResults: {len(tests) - len(failures)}/{len(tests)} passed")

if failures:
    raise SystemExit(1)