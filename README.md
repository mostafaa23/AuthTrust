# Wily

> Cloud-native, black-box API security scanner.
> Starts from a domain you're authorized to test, discovers assets and
> cloud services, routes each one to the appropriate checks, and produces
> a unified report with evidence and a severity/confidence rating.

## Current status

Five scanner modules are implemented and tested end-to-end against local
demo targets (see `demo/`): JWT Tampering, API Auth Bypass (+ CORS +
stage inconsistency), BOLA / cross-tenant access, IAM privilege
escalation, and cloud SSRF/IMDS. Endpoint discovery (`recon/
api_discovery.py`) and parameter discovery/classification
(`recon/parameter_discovery.py`) are also implemented. The unified `wily
scan` CLI command runs the full bundle automatically.

Not yet implemented: subdomain enumeration, standalone DNS/HTTP fingerprinting
and JS analysis as separate modules (their core logic already lives inside
`api_discovery.py`), the YAML template engine (`templates/loader.py`),
HTML/SARIF reporting, and the ML ranking/dedup layer (`risk/ml/`). These
raise `NotImplementedError` rather than pretending to work - see the
module-level docstrings in each file for what's planned.

## Install

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# The full bundle, automatically: discovery + auth bypass + CORS + SSRF
wily scan example.com -o report.json

# Add JWT Tampering (needs a valid sample token)
wily scan example.com --token eyJhbGciOi... -o report.json

# Add BOLA (needs at least two identities to compare)
wily scan example.com --identity tenant_a="Bearer xyz" --identity tenant_b="Bearer abc"

# Add IAM privilege-escalation analysis (fully independent of the domain)
wily scan example.com --iam-file authorization-details.json

# Enable Blind SSRF (level 4, via a local OOB canary)
wily scan example.com --blind

# Explicitly confirm destructive-method probes (POST/PUT/DELETE/PATCH) in Auth Bypass
wily scan example.com --confirm-destructive

# Explicitly confirm the SSRF/IMDS check (it makes the target fetch
# internal metadata on your behalf - only for infrastructure you own)
wily scan example.com --confirm-owned-infra

# A single, focused module
wily jwt https://api.example.com/profile --token eyJhbGciOi...
wily authz https://api.example.com/orders/123
wily ssrf https://api.example.com/fetch --param url --confirm-owned-infra
wily iam authorization-details.json
wily discover example.com
```

Run any demo end-to-end locally (spins up its own vulnerable Flask app,
no external network access needed):

```bash
python demo/run_jwt_demo.py
python demo/run_authz_demo.py
python demo/run_ssrf_demo.py
python demo/run_iam_demo.py
python demo/run_bola_demo.py
python demo/run_discovery_demo.py
```

## Project layout

- `cli/`        : command-line interface (Typer + Rich)
- `core/`       : scope & consent validation, adaptive rate limiting, the
                   OOB canary server, shared HTTP redirect/scope policy
- `recon/`      : asset discovery (endpoint discovery, parameter discovery)
- `classify/`   : routes each discovered asset to the right scanner (planned)
- `templates/`  : the YAML rule system + pydantic schema (planned)
- `scanners/`   : the implementation of each vulnerability class (BOLA,
                   SSRF/IMDS, IAM, JWT, Auth Bypass/CORS)
- `evidence/`   : evidence storage and redaction (secrets/tokens/cookies/API keys)
- `risk/`       : a deterministic rules engine + Risk Score + ML ranking (planned)
- `report/`     : JSON (implemented), HTML/SARIF (planned) output
- `lambda/`     : AWS Lambda function to send the report via SES (planned)

## Safety model

- Every HTTP request goes through a single, mandatory `HttpEngine` that
  enforces scope on the original URL *and* every redirect hop, resolves
  and rejects private/loopback/link-local/metadata addresses, and
  applies adaptive per-host rate limiting with 429 backoff.
- Non-destructive checks (GET/HEAD) are the default everywhere. Tests
  that can mutate target state (write-method authz probes) or that
  require you to own the target infrastructure (the SSRF/IMDS check)
  require an explicit, separate confirmation flag and are excluded from
  an ordinary scan otherwise.
- Evidence is redacted (AWS credentials, bearer tokens, generic API
  keys, sensitive headers) before it is written to any report.

## License

MIT (subject to change as needed)
