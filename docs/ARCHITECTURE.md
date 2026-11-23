# Architecture

1. Authorization manifest: explicit target, owner, environment, expiry, approver, and check allowlist.
2. Policy gate: validates freshness, environment and transport constraints before network activity.
3. Deterministic check engine: dispatches only allowlisted checks.
4. Evidence model: records bounded evidence without cookie values or credentials.
5. Reporting: emits JSON and escaped HTML artifacts.

The API and CLI share the same policy gate. The initial release avoids a database-backed queue and autonomous agent behavior to keep the assessment surface small.

## Implemented checks
- HTTP response security headers
- Cookie Secure, HttpOnly, and SameSite attributes
- TLS trust-chain handshake
- Common OpenAPI schema exposure (informational only)

## Planned controlled extensions
Tenant isolation, authentication lifecycle, callback replay/idempotency, ledger invariants, dependency/SAST checks, and infrastructure configuration review require isolated adapters, synthetic data, explicit staging approval, cleanup procedures, and regression tests. They are not implemented or claimed by v0.1.
