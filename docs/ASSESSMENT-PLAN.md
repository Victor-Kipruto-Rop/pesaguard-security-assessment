# PesaGuard assessment coverage

| Domain | Available adapter | Evidence required | Current limitation |
|---|---|---|---|
| Public website | Active pinned HTTP/TLS checks | Approved local/staging manifest | Header-only checks; no browser crawling |
| API gateway | Active OpenAPI exposure check; source review | Approved target and local source checkout | No authenticated API fuzzing |
| Identity and security | Config snapshot + source review + JUnit import | Sanitized settings and test results | No automated live login/session probing |
| Core services / tenancy | Synthetic expected/observed fixture + source review + JUnit import | Two or more synthetic tenants | No autonomous cross-tenant request generation |
| Transaction processing | Synthetic idempotency/receipt/concurrency fixture + source review + JUnit import | Disposable staging test output | Does not create real transactions |
| Financial ledger | Synthetic journal invariant fixture | Exported synthetic debit/credit rows | Dedicated PesaGuard ledger schema was not found in inspected ORM models |
| M-Pesa Daraja | Callback configuration and synthetic callback checks + source review | Sanitized callback config and synthetic fixtures | No live Daraja requests or real callback replay |
| Operational database | Config snapshot + optional read-only PostgreSQL inspector | Dedicated assessor connection and hostname allowlist | Cannot verify backups/audit policy or prove migration-role separation |
| Data engineering | Config snapshot, source secret patterns, lineage/tenant source review | Sanitized pipeline config and source snippets | No full runtime data-flow tracing |
| Infrastructure | Static Docker/Kubernetes/deployment text checks | Bounded config files | No live cloud enumeration or admission-control evaluation |
| Outbound webhooks | HMAC/replay configuration checks | Sanitized webhook config | Does not deliver real webhooks |

## Evidence rules

- Report only domains actually supplied or inspected.
- Distinguish a failed assertion from a missing/unconfirmed configuration value.
- Do not mark an unexecuted test as passed.
- Use synthetic identifiers and amounts only.
- Keep real credentials, customer records, callback payloads, and production data out of bundles.
