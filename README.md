# PesaGuard Security Assessment

A permission-first Python security assessment toolkit for PesaGuard local and staging environments. It combines bounded active HTTP checks, non-executing source review, offline domain adapters, read-only PostgreSQL posture inspection, JUnit result import, risk prioritization, and a local evidence journal.

**Status:** Advanced assessment foundation. It is not a penetration-test certification or a guarantee that PesaGuard is secure. The tool only verifies the controls supported by the evidence you provide or the checks it actually runs.

## Implemented capabilities

### 1. Authorized active checks
- Expiring target authorization manifests with owner, approver, approval reference, environment, and per-check allowlist.
- Local HTTP is restricted to loopback.
- Staging requires an exact hostname in ASSESSMENT_ALLOWED_STAGING_HOSTS and explicitly approved destination IPs.
- HTTP/TLS connections are pinned to the approved IP. TLS certificate validation still uses the authorized hostname.
- Production scanning is blocked.
- Redirects are not followed; only bounded GET requests are made.
- Checks: HTTP security headers, cookie flags, TLS certificate validation, and common OpenAPI schema exposure.

### 2. PesaGuard domain adapters
- Identity/session configuration controls.
- Synthetic tenant authorization observations.
- Transaction idempotency, duplicate provider receipt, and concurrency observations.
- Double-entry journal balance and posted-entry immutability checks, with per-currency grouping.
- Daraja callback trust controls and synthetic callback correlation/mismatch/replay cases.
- PesaGuard outbound webhook HMAC and replay controls.
- Database privilege/TLS configuration snapshots.
- Data-pipeline controls and secret-pattern detection.
- Docker/Kubernetes/deployment text configuration checks.

### 3. PesaGuard source integration
- Fixed allowlist source audit for the current api.pesaguard module layout.
- Reads source text only; it does not import or execute application code.
- Detects source indicators for JWT/session controls, tenant query scoping, database uniqueness, EventStore replay handling, Daraja callback token checks, payload protection, and data lineage.
- Imports JUnit XML from PesaGuard's own regression tests without executing tests or copying captured failure output.

### 4. Database and evidence
- Optional PostgreSQL inspector using a read-only transaction, strict host allowlist, short statement timeout, and no DDL/DML.
- JSON and escaped HTML reports.
- Transparent severity/confidence risk prioritization.
- Local SQLite SHA-256 hash-chain evidence journal with verification command.

## Not claimed as implemented

- Automated live cross-tenant requests against a running PesaGuard instance.
- Automated transaction mutation/replay or concurrency tests against a real staging deployment.
- Live Daraja callback injection or live M-Pesa transactions.
- Automatic discovery of a financial ledger schema or a full accounting-system audit.
- Full PostgreSQL role inventory, backup encryption verification, or database audit configuration proof.
- Kubernetes admission control, Terraform plan evaluation, ZAP/Nmap/Greenbone integrations.
- Signed authorization manifests, external immutable evidence storage, multi-user RBAC, and enterprise key management.

Use the application-owned synthetic tests and JUnit importer for behavior-level validation. Use the static source audit only as implementation evidence.

## Quick start

Requires Python 3.12+.

    python -m venv .venv
    source .venv/bin/activate
    pip install -e '.[dev]'
    cp .env.example .env

Set a strong unique ASSESSMENT_API_KEY in .env before starting the API.

Run unit tests and checks:

    pytest -q
    ruff check .
    bandit -q -r src

Run the sample offline assessment:

    pg-assess assess-bundle --bundle-file examples/synthetic-assessment.json

Run the static audit against a local PesaGuard API checkout:

    pg-assess assess-source --repo-root ../api.pesaguard

Run the optional read-only PostgreSQL inspector after installing the database extra and configuring exact host/IP allowlists:

    pip install -e '.[db]'
    pg-assess assess-database --confirm-read-only

Import PesaGuard JUnit results:

    pg-assess import-junit --junit-file reports/pesaguard-security-tests.xml

Verify the local evidence chain:

    pg-assess verify-evidence --database reports/evidence.sqlite3

See docs/QUICKSTART.md, docs/SAFETY.md, docs/DOMAIN-ADAPTERS.md, docs/PESAGUARD-INTEGRATION.md, and docs/DATABASE-INSPECTION.md.

## API service

    uvicorn pg_assess.api:app --host 127.0.0.1 --port 8080

- GET /healthz
- POST /v1/assessments (authorized, pinned-address HTTP checks)
- POST /v1/bundle-assessments (offline sanitized bundle; no network activity)

The service should remain bound to loopback unless a separately reviewed deployment includes TLS, strict network controls, request-size limits, audit controls, and managed secrets.

## Safety rules

- Only assess systems you own or have written permission to test.
- Never put credentials, real customer data, real phone numbers, M-Pesa receipts, live Daraja callback payloads, or production tokens in assessment bundles.
- Use synthetic fixtures and disposable databases for behavioral tests.
- Do not perform credential stuffing, destructive payloads, denial of service, persistence, lateral movement, or real-money operations.
- Keep reports and authorization records out of Git.

## CI

GitHub Actions is configured to run Ruff, pytest, and Bandit. Check the Actions tab for the actual run status. A workflow definition or a started run is not evidence that the tests passed.

## License

No license has been added. All rights are reserved unless the repository owner adds a license.
