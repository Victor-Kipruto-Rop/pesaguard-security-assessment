# PesaGuard Security Assessment

A permission-first Python toolkit for low-impact security checks against explicitly authorized PesaGuard local and staging environments.

**Release:** 0.1.0 foundation. This is not a completed penetration-testing suite, security certification, or evidence that PesaGuard is secure.

## What is implemented

- FastAPI assessment endpoint protected by an API key.
- CLI assessment runner.
- Target authorization manifest with owner, approval reference, time window, environment, and per-check allowlist.
- Policy gate before network activity.
- Local HTTP restricted to loopback; staging requires HTTPS; production is blocked.
- URL userinfo, query strings, and fragments are rejected.
- Low-impact HTTP security-header and cookie-attribute checks.
- TLS certificate validation and common OpenAPI schema exposure check.
- JSON and escaped HTML reports.
- Docker runtime with non-root user, read-only root filesystem, dropped Linux capabilities, and loopback-only port binding.
- Pytest suite and GitHub Actions CI configuration.

## Not yet implemented

Tenant-isolation probing, identity/token lifecycle verification, transaction replay and idempotency tests, ledger invariants, M-Pesa callback signature/replay validation, database privilege review, data-pipeline controls, infrastructure-as-code analysis, authenticated browser testing, PDF reporting, and persistent assessment history. See docs/ASSESSMENT-PLAN.md. These must not be represented as completed assessments.

## Quick start

See docs/QUICKSTART.md. Requires Python 3.12+.

    python -m venv .venv
    source .venv/bin/activate
    pip install -e '.[dev]'
    cp .env.example .env

Set a strong unique ASSESSMENT_API_KEY in .env before starting the API. The API refuses the placeholder key. Create an authorization manifest for a local loopback service and run:

    pg-assess run --authorization-file authorization.local.json
    pytest -q

## Authorization model and important limitation

Each run requires an explicit manifest containing target, environment, owner, approval reference, approver, UTC approval/expiry timestamps, active status, and allowed checks. The manifest is an operator attestation; v0.1 does not cryptographically verify a signature or independently validate the underlying written authorization. The operator remains responsible for confirming written permission before running it. Do not treat manifest fields as proof of legal authorization.

## Safety rules

- Assess only assets you own or have written authorization to test.
- Production assessment is blocked in this release.
- Use synthetic accounts and data for future staging integration tests.
- No credential stuffing, brute force, exploit chaining, destructive payloads, denial of service, persistence, data extraction, or real-money activity.
- Never use real customer records or live Daraja credentials in tests or reports.
- Store reports and authorization records outside source control.
- Stop immediately if a run behaves unexpectedly.

Read docs/SAFETY.md and docs/STAGING-CHECKLIST.md before any staging assessment.

## Development

    make install
    make lint
    make test
    make security

CI runs Ruff, pytest, and Bandit. A CI workflow being present does not mean it has passed; inspect the Actions tab for actual run results.

## Reports

Reports are written to the configured ASSESSMENT_DATA_DIR (default ./reports). Reports can reveal internal hostnames and security posture; protect them accordingly. Generated report files are ignored by Git.

## License

No license has been added. All rights are reserved unless the repository owner adds a license.
