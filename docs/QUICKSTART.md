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

Replace timestamps with the real approval window. Run:

    pg-assess run --authorization-file authorization.local.json
    pytest -q

## API
Start locally with:

    uvicorn pg_assess.api:app --host 127.0.0.1 --port 8080

POST /v1/assessments with the authorization manifest and checks array. Supply X-Assessment-Key. Keep the service bound to loopback unless a separately reviewed deployment includes TLS, authentication, network restrictions, and audit controls.

## Docker
    cp .env.example .env
    # Set a unique ASSESSMENT_API_KEY before starting
    docker compose up --build
