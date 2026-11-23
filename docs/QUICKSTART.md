# Quickstart

Requires Python 3.12+.

## Install
    python -m venv .venv
    source .venv/bin/activate
    pip install -e '.[dev]'
    cp .env.example .env

Set a unique, strong ASSESSMENT_API_KEY in .env. Never reuse production credentials.

## Local authorization manifest
Create authorization.local.json locally; do not commit actual approval records.

    {
      "target_id": "pesaguard-local-api",
      "base_url": "http://127.0.0.1:8000",
      "environment": "local",
      "owner": "PesaGuard engineering",
      "authorization_reference": "LOCAL-CHANGE-001",
      "approved_by": "system owner",
      "approved_at": "2026-11-24T00:00:00Z",
      "expires_at": "2026-11-25T00:00:00Z",
      "allowed_checks": ["http_headers", "tls", "openapi_exposure", "cookie_flags"],
      "max_requests_per_minute": 5,
      "active": true
    }

Replace timestamps with the real approval window. Then run:

    pg-assess run --authorization-file authorization.local.json
    pytest -q

## Staging authorization
Set ASSESSMENT_ALLOWED_STAGING_HOSTS to a comma-separated exact hostname allowlist in the assessor's environment. Add approved_ip_addresses to the staging manifest, containing the exact IP address or addresses approved by the system owner. The scanner connects to those IPs directly and validates the TLS certificate against the hostname. Do not use broad wildcard domains.

## Offline PesaGuard assessment
Run the synthetic example bundle:

    pg-assess assess-bundle --bundle-file examples/synthetic-assessment.json

Inspect the JSON/HTML reports and verify the local evidence chain:

    pg-assess verify-evidence --database reports/evidence.sqlite3

For a local PesaGuard API checkout:

    pg-assess assess-source --repo-root ../api.pesaguard

For an explicitly authorized PostgreSQL target, install the optional driver, set PG_ASSESS_DATABASE_URL and (for remote hosts) PG_ASSESS_DATABASE_HOSTS in the process environment, then run:

    pip install -e '.[db]'
    pg-assess assess-database --confirm-read-only

## API
Start locally with:

    uvicorn pg_assess.api:app --host 127.0.0.1 --port 8080

POST /v1/assessments with the authorization manifest and checks array. Supply X-Assessment-Key. POST /v1/bundle-assessments with sanitized snapshots and synthetic fixture observations. Keep the service bound to loopback unless a separately reviewed deployment includes TLS, authentication, network restrictions, request-size limits, and audit controls.

## Docker
    cp .env.example .env
    # Set a unique ASSESSMENT_API_KEY before starting
    docker compose up --build
