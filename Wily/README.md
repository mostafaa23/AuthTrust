# Wily — Cloud Vulnerability Discovery Tool

This repository is a **starter folder scaffold** based on the agreed Wily architecture. It organizes the major components, but does not yet implement scanners or cloud integrations.

## Structure

```text
Wily/
├── target_scope_manager/
├── recon_orchestrator/
│   ├── subdomain_live_host_discovery/
│   ├── http_dns_tls_fingerprinting/
│   ├── html_javascript_secret_discovery/
│   ├── openapi_swagger_discovery/
│   └── proxy_traffic_import/
├── cloud_asset_inventory/
│   ├── s3_cloud_storage/
│   ├── api_inventory/
│   ├── public_configuration_exposure/
│   └── service_dependency_signals/
├── template_engine/
│   ├── yaml_schema_validation/
│   ├── nuclei_integration/
│   ├── tls_checks/
│   ├── cloud_storage_checks/
│   ├── web_api_checks/
│   └── optional_authenticated_checks/
├── evidence_normalizer_secret_redactor/
├── risk_scoring_ml_intelligence/
├── findings_database_report_generator/
└── email_delivery_trigger/
    ├── aws_lambda/
    └── amazon_ses/
```

## Component responsibilities

- **Target & Scope Manager** — records the authorized target, allowed hosts, exclusions, and scan profile. Every module should honor this scope.
- **Recon Orchestrator** — coordinates discovery tasks and collects their outputs.
- **Cloud Asset Inventory** — normalizes discovered cloud assets, APIs, exposed configuration signals, and service/dependency signals.
- **Template Engine** — validates YAML checks and dispatches suitable checks, including optional Nuclei integration.
- **Evidence Normalizer & Secret Redactor** — standardizes evidence and removes credentials, cookies, tokens, and other secrets before persistence or reporting.
- **Risk Scoring + ML Intelligence** — prioritizes and deduplicates candidate findings. ML scores are advisory and must not independently confirm a vulnerability.
- **Findings Database / Report Generator** — stores normalized findings and produces reports with evidence, severity, confidence, and remediation.
- **Email Delivery Trigger** — prepares report delivery through AWS Lambda and Amazon SES.

## Suggested implementation order

1. Define shared data models and the target/scope rules.
2. Implement passive reconnaissance and asset inventory.
3. Add evidence normalization and secret redaction before storing any captured data.
4. Add safe, non-destructive checks and YAML schema validation.
5. Integrate external scanners behind explicit scope and timeout/rate-limit controls.
6. Add confidence/risk scoring, report generation, and optional email delivery.
7. Add authenticated and potentially state-changing tests only as explicit opt-in features for targets the operator is authorized to assess.

## Status

All component directories are scaffolding placeholders. No scans are run by this scaffold, and no AWS resources or email settings are configured.
