# Phase 2: PesaGuard-specific security adapters

## Scope and execution model

This phase separates three evidence types:

1. **Source inventory**: static discovery of the current PesaGuard package layout. It does not import or execute application code.
2. **Behavioral regression evidence**: results from PesaGuard-owned pytest tests, imported from a bounded JUnit XML report.
3. **Synthetic invariant evidence**: normalized fixtures evaluated by the security assessor without contacting Daraja, changing financial records, or accessing customer data.

A discovered source file or test file is not proof that a control works. Only an executed test result can support a behavioral claim. A missing adapter is reported as a coverage gap, not as a confirmed vulnerability.

## Domain adapter matrix

| Domain | Existing PesaGuard test modules | Remaining dedicated coverage |
|---|---|---|
| Identity, authentication, sessions | auth lifecycle, fail-closed sessions, RBAC | Execute and import JUnit; test privilege-change revocation and refresh-family reuse cases |
| Tenant isolation and authorization | tenant constraints, export scoping, RBAC | Expand route matrix for list/search, reads, writes, exports, and service identities |
| Transaction replay, idempotency, concurrency | idempotency contract, transaction routes | Run race tests only against a disposable PostgreSQL database |
| Financial ledger invariants | no dedicated test module discovered by the current runner | Confirm authoritative ledger ownership; add balanced journal, immutable posting, and compensating-entry tests |
| M-Pesa Daraja callbacks | Daraja validation, tenant routing, M-Pesa operations | Expand synthetic callback replay, unknown correlation, amount/shortcode mismatch, and terminal-state tests |
| Database privileges and configuration | static database configuration/source checks | Add dedicated role privilege and TLS posture tests against a disposable database |
| Data pipeline security | data protection, ETL, lineage | Add negative tests for tenant loss, sensitive-field leakage, retention, and service-account scope |
| Infrastructure and deployment | static Docker/Kubernetes/config review | Add policy tests for deployment manifests and Terraform plans |
| Evidence and reporting | assessor evidence-chain unit tests | Add tamper, truncation, report escaping, and evidence-to-finding linkage tests |

The matrix is intentionally honest about ledger and database behavioral coverage. Do not infer that PesaGuard has a dedicated double-entry ledger merely because it has transaction or reconciliation models.

## Commands

Inventory expected source and test coverage without executing PesaGuard:

    pg-assess assess-pesaguard-coverage --repo-root ../api.pesaguard

Execute the approved isolated PesaGuard regression set:

    PESAGUARD_SECURITY_TESTS_APPROVED=YES bash scripts/run_pesaguard_regression_tests.sh

Import only the resulting bounded JUnit evidence:

    pg-assess import-junit --junit-file reports/pesaguard-security-tests.xml

Run static source review separately:

    pg-assess assess-source --repo-root ../api.pesaguard

## Daraja callback semantics

Do not invent an inbound Safaricom HMAC signature contract. Test the callback authentication actually implemented by PesaGuard, including high-entropy route token handling, digest storage, constant-time comparison, request correlation, pending-state enforcement, receipt uniqueness, payload validation, and reconciliation. Verify source-IP restrictions against current Safaricom guidance before relying on them. HMAC-SHA256 is a separate control for PesaGuard outbound webhooks, where the exact raw body and timestamp/replay window must be covered.

## Safety boundaries

- Never use live M-Pesa transactions, real phone numbers, real receipts, or production callback payloads.
- Never point the regression runner at production or a database containing customer data.
- Do not enable PostgreSQL concurrency tests unless a disposable test database is explicitly configured and separately approved.
- Do not store raw secrets, tokens, customer identifiers, or full callback bodies in reports.
- Local SHA-256 hash-chain evidence is tamper-evident, not immutable/WORM evidence storage.
