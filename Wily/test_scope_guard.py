from target_scope_manager.scope_manager import ScopeManager, ScopeError
from target_scope_manager.scope_guard import ScopeGuard


scope = ScopeManager(
    "example.com",
    allow_subdomains=True,
    excluded_hosts=("admin.example.com",),
)

guard = ScopeGuard(scope)

tests = [
    ("valid subdomain", lambda: guard.validate_url(
        "https://api.example.com/v1"
    ), True),

    ("base domain", lambda: guard.validate_url(
        "https://example.com"
    ), True),

    ("external domain", lambda: guard.validate_url(
        "https://attacker.net"
    ), False),

    ("excluded host", lambda: guard.validate_url(
        "https://admin.example.com"
    ), False),

    ("userinfo trick", lambda: guard.validate_url(
        "https://example.com@attacker.net"
    ), False),

    ("file scheme", lambda: guard.validate_url(
        "file:///etc/passwd"
    ), False),

    ("protocol-relative URL", lambda: guard.validate_url(
        "//attacker.net/path"
    ), False),

    ("relative same-host redirect", lambda: guard.validate_redirect(
        "https://api.example.com/v1/users",
        "../account",
    ), True),

    ("external redirect", lambda: guard.validate_redirect(
        "https://api.example.com/",
        "https://attacker.net/",
    ), False),

    ("redirect to excluded host", lambda: guard.validate_redirect(
        "https://api.example.com/",
        "https://admin.example.com/",
    ), False),
]

failures = []

for name, action, expected in tests:
    try:
        action()
        actual = True
    except ScopeError:
        actual = False

    passed = actual == expected
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")

    if not passed:
        failures.append(name)

print(f"\nResults: {len(tests) - len(failures)}/{len(tests)} passed")

if failures:
    raise SystemExit(1)