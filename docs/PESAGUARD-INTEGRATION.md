# PesaGuard repository integration

The source adapter is tailored to the current api.pesaguard layout. It reads a fixed allowlist under pesaguard_backend_pipeline/, including:

- auth_rbac.py and authorization_policy.py
- transaction_routes.py, event_store.py, and models.py
- mpesa_operation_webhooks.py, mpesa_operation_service.py, and daraja_tenant_routing.py
- validators.py, mpesa_configuration.py, and data_protection.py
- etl_pipeline.py, lineage.py, and selected regression tests

It uses text indicators only. It does not import PesaGuard modules, evaluate Python code, open database connections, run migrations, call Daraja, or mutate application state.

## Run against a local checkout

    git clone <your-private-api-repository-url> api.pesaguard
    pg-assess assess-source --repo-root ./api.pesaguard

The source audit surfaces implementation evidence and gaps. It is not a replacement for running the PesaGuard test suite. PostgreSQL concurrency tests may be marked opt-in and must be run only against a disposable database.

## Existing code areas recognized

- Access JWT TTL is configured with a 15-minute upper bound and required tenant claims.
- Refresh-token state is persisted and token digests are stored.
- Transaction routes derive tenant context from the authenticated principal and scope database queries.
- Models define tenant-scoped uniqueness and non-empty tenant constraints.
- EventStore classifies duplicate and conflicting provider replays and handles integrity races.
- Daraja operation callbacks use high-entropy callback tokens, stored token digests, constant-time comparison, request correlation, and terminal callback payload digests.
- Daraja tenant routing resolves active provider/integration ownership and rejects unknown or ambiguous shortcodes.
- M-Pesa credentials use authenticated encryption; sensitive payload fields have application-level protection.
- ETL ingestion carries tenant scope; lineage records include tenant identity.

## Known review gap

The inspected ORM models expose transaction, processed-transaction, reconciliation, idempotency, and lineage entities. The source adapter did not identify an explicit double-entry journal/ledger-entry model in the inspected models.py. Confirm whether the financial ledger is an external source of truth or whether a dedicated immutable journal should be added to PesaGuard.
