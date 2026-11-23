# Domain assessment adapters

The offline bundle runner evaluates sanitized configuration snapshots and synthetic observations. It does not pretend to exercise application behavior when no application adapter has supplied observations.

## Bundle format

See examples/synthetic-assessment.json. Supported top-level sections:

- `identity`: sanitized identity/session control configuration.
- `tenancy_cases`: synthetic expected-versus-observed authorization decisions.
- `transaction_cases`: idempotency, duplicate receipt, and concurrency observations.
- `ledger_entries`: synthetic journal entries grouped by transaction ID.
- `daraja` and `daraja_callbacks`: callback controls and synthetic callback observations.
- `database`: sanitized database privilege and TLS posture.
- `pipeline` and `pipeline_source_files`: pipeline controls and source snippets for secret-pattern detection.
- `infrastructure_files`: bounded Docker/Kubernetes/deployment text files for static pattern checks.
- `outbound_webhook`: PesaGuard outbound webhook signing and replay controls.

Never place production secrets, raw customer records, access tokens, real phone numbers, M-Pesa receipts, or live callback payloads in a bundle. Use synthetic identifiers only.

## Application-owned adapters

The application team must produce tenancy, transaction, ledger, and callback observations by executing tests against disposable fixtures. The assessor consumes normalized results; it does not invent endpoint paths or attempt to mutate real PesaGuard records.

### Identity
Export boolean control states and numeric TTL values. Do not export password hashes, session tokens, signing keys, or user details.

### Tenant isolation
Create at least two synthetic tenants and test same-tenant access, cross-tenant reads, cross-tenant writes, list/search filtering, export endpoints, and privileged-role boundaries. For each case record expected_allowed and observed_allowed. A forbidden grant is critical.

### Transaction processing
Run duplicate idempotency requests and concurrent submissions in an isolated staging fixture. Record side_effect_count, concurrent_duplicate_writes, and response_fingerprint. The adapter should use unique synthetic references and clean up its own test data.

### Ledger
Export only synthetic journal rows. Group by transaction_id, use exact decimal strings, and include side (debit/credit), status, and whether posted rows can be mutated. Debits and credits must balance per transaction and currency. This initial adapter assumes each supplied group is a single-currency journal; multi-currency systems must group by currency before submission.

### Daraja callbacks
Do not assume a standard Safaricom inbound HMAC signature. Validate the actual Safaricom-supported callback security model with Safaricom. Check callback URL secrecy, verified edge source restrictions, correlation to initiated requests, amount/shortcode match, receipt uniqueness, body limits, and independent reconciliation. Synthetic callback fixtures only. PesaGuard outbound webhook signatures are a separate control and should sign the exact raw body with HMAC-SHA256.

### Database and data pipelines
Provide sanitized read-only role/configuration exports. Never supply a connection string containing credentials. Runtime SQL inspection is intentionally not enabled in this release.

### Infrastructure
Supply only the relevant configuration files. Static checks are indicators and do not replace a Kubernetes admission-policy, Terraform plan, or deployment review.

## Evidence and risk
Each bundle assessment writes JSON and escaped HTML reports plus a local SQLite hash-chain journal. The hash chain detects modification but is not a substitute for signed immutable storage or external audit retention. The risk score is a deterministic prioritization aid, not a probability or compliance score.
