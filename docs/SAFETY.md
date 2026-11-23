# Safety and authorization policy

## Scope
Only assess assets owned by the operator or covered by written authorization. Every run requires a target manifest containing the owner, authorization reference, approver, approval and expiry timestamps, environment, and explicit check allowlist. Keep the underlying approval record with assessment evidence.

## Environment restrictions
- Local: HTTP is permitted only for loopback addresses (localhost, 127.0.0.1, ::1).
- Staging: HTTPS only. The exact hostname must be listed in ASSESSMENT_ALLOWED_STAGING_HOSTS and one or more approved destination IP addresses must be supplied in the manifest. Connections are pinned to the approved IP, while TLS hostname verification still uses the authorized hostname. DNS is not re-resolved by the scanner.
- Production: blocked by this release.

## Prohibited actions
No credential stuffing or brute force, exploitation, persistence, destructive payloads, denial of service, lateral movement, data extraction, real-money transactions, or changes to real ledger/customer data. Redirects are not followed. Do not add arbitrary target discovery or unbounded port scanning.

## Operational controls
Use dedicated test accounts, short-lived credentials, outbound network controls, a low request rate, a defined maintenance window, and a human operator able to stop the run. Stop on unexpected load, errors, sensitive data exposure, or activity outside scope.

## Evidence handling
Reports may reveal internal hostnames and security posture. Store them with restricted access and retention limits. Never include tokens, cookie values, customer records, or live Daraja credentials.

## Limitations
A clean result is not proof of security. These checks are indicators, not a penetration test, certification, or guarantee against compromise. Human review is mandatory.
