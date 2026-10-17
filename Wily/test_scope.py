from target_scope_manager.scope_manager import ScopeManager

scope = ScopeManager("example.com")

tests = {
    "https://example.com": True,
    "https://api.example.com/v1/users": True,
    "https://sub.api.example.com": True,
    "https://example.com.attacker.net": False,
    "https://attacker-example.com": False,
    "https://attacker.net": False,
    "http://localhost": False,
    "http://127.0.0.1": False,
}

for url, expected in tests.items():
    result = scope.is_in_scope(url)
    status = "PASS" if result == expected else "FAIL"
    print(f"[{status}] {url} -> {result}")