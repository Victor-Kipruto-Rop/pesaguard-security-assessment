# Architecture

The project has three assessment paths that share the same finding, risk, and reporting models.

## 1. Authorized active HTTP path

1. Authorization manifest validates owner, approval reference, UTC approval window, environment, and check allowlist.
2. Policy gate restricts local checks to loopback. Staging requires an exact hostname allowlist plus explicit approved IP addresses.
3. Scanner pins TCP connections to an approved IP and validates TLS against the original hostname. It does not follow redirects or re-resolve DNS.
4. Bounded GET requests collect response headers only.
5. JSON and escaped HTML reports are written locally.

Production active scanning is blocked.

## 2. Offline domain bundle path

The bundle runner evaluates sanitized configuration snapshots and synthetic observations for identity, tenancy, transactions, ledger, Daraja callbacks, database posture, data pipelines, infrastructure, and outbound webhooks. It performs no network calls. Missing domains are listed as not assessed.

The application team owns adapters that produce trustworthy expected-versus-observed results. The assessor does not invent API endpoints or mutate PesaGuard business records.

## 3. Source and test evidence path

The PesaGuard source adapter reads a fixed allowlist of local source files as text. It never imports or executes application code. The JUnit adapter imports bounded XML output from PesaGuard-owned tests, omitting failure text and captured output to avoid sensitive-data leakage.

## 4. Read-only database path

An optional PostgreSQL adapter requires an explicit CLI confirmation, a connection URL from process environment, and an exact database hostname allowlist for remote connections. It begins a read-only transaction, applies short timeouts, inspects current-role privileges and TLS state, then rolls back and closes the connection.

## 5. Evidence and risk

Findings include severity, confidence, verification state, evidence references, and remediation. Risk scoring is deterministic and transparent. The local SQLite hash chain detects unauthorized edits to existing journal records but is not immutable against an attacker who can rewrite the database and recompute the chain. Export evidence to signed, immutable storage for production use.

## Trust boundaries

- Target manifests are operator attestations, not cryptographic proof of written authorization.
- Source-code indicators do not prove runtime enforcement.
- JUnit XML is imported evidence, not cryptographically attested CI output.
- Configuration snapshots can omit relevant controls.
- Synthetic tests do not prove production behavior.
- A clean report is not a certification or guarantee against compromise.
