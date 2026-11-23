# PesaGuard repository integration

The source adapter is tailored to the current api.pesaguard layout. It reads a fixed allowlist under pesaguard_backend_pipeline/, including auth_rbac.py, authorization_policy.py, transaction_routes.py, event_store.py, models.py, the Daraja callback and tenant-routing modules, validators.py, mpesa_configuration.py, data_protection.py, etl_pipeline.py, lineage.py, and selected regression tests.

It uses text indicators only. It does not import PesaGuard modules, evaluate Python code, open database connections, run migrations, call Daraja, or mutate application state.

## Static source review

    pg-assess assess-source --repo-root ../api.pesaguard

## Import actual PesaGuard regression test results

From the security-assessment checkout, explicitly approve the isolated test runner. It checks the API checkout, clears inherited deployment credentials, and relies on PesaGuard's test conftest to create a temporary SQLite database. PostgreSQL race tests are not enabled:

    PESAGUARD_SECURITY_TESTS_APPROVED=YES bash scripts/run_pesaguard_regression_tests.sh

If the API checkout is not the sibling directory ../api.pesaguard, set PESAGUARD_API_REPO to its local path. The runner creates reports/pesaguard-security-tests.xml.

Then import the test results:

    cd ../pesaguard-security-assessment
    pg-assess import-junit --junit-file reports/pesaguard-security-tests.xml

Do not point PesaGuard tests at production or a database containing customer data. PostgreSQL race tests are opt-in and must only use a disposable test database. The importer reads a bounded JUnit XML report; it does not execute tests. It deliberately omits failure output and stdout/stderr from reports because those may contain secrets or customer data.

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
