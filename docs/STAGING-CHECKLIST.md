# Staging authorization checklist

Before staging assessment, the system owner must approve and record all of the following:

- Exact HTTPS hostname and owning team confirmed.
- Written authorization reference and approver recorded.
- Assessment window and expiry timestamp set in UTC.
- Explicit checks allowlisted in the target manifest.
- Staging environment verified; production hostnames excluded.
- Synthetic tenant identities and test fixtures prepared by the application team.
- Backups and rollback procedure confirmed for any separately approved integration tests.
- Rate limits, monitoring, and an operator kill switch confirmed.
- Reports stored in restricted access storage and retention period agreed.
- No live Daraja credentials, real customer data, or real-money movement involved.

The v0.1 scanner only performs low-impact HTTP/TLS checks. Transaction, tenant-isolation, callback, and ledger tests are not yet implemented.
