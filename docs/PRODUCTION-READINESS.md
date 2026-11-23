# Production readiness gates

This tool itself is not production-ready merely because it can run. Before hosting the assessor as a service:

- Change repository visibility to private and review all existing commits for accidentally committed secrets.
- Store the API key in a managed secret store and rotate it; never use the placeholder.
- Put the API behind TLS, a private network, strict authentication, request-size limits, rate limits, and audit monitoring.
- Restrict outbound network egress to explicitly enrolled assessment targets. Do not permit arbitrary URLs or IP ranges.
- Add signed authorization manifests and independent approval workflow before any active staging checks.
- Use separate identities for assessor API access, database read-only inspection, and application test adapters.
- Encrypt evidence at rest; export evidence to immutable, access-controlled storage and define retention.
- Review threat model, dependency vulnerabilities, container image, backup/restore, and incident response.
- Require human approval for every stateful staging integration test and keep a tested kill switch.
- Keep production active scanning disabled unless a separately reviewed authorization and safety design is implemented.

The current tool's domain bundle path is offline and non-destructive. It should be the default for security reviews.
