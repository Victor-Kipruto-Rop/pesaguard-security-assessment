"""Offline, deterministic checks for PesaGuard-owned configuration and synthetic fixtures.

These checks never contact Daraja, mutate a ledger, or access customer data.
"""
from __future__ import annotations

import hashlib
import re
from decimal import Decimal, InvalidOperation
from pathlib import PurePosixPath
from typing import Any

from .models import Finding


def _finding(check: str, title: str, severity: str, description: str,
             recommendation: str, evidence: dict[str, str] | None = None,
             confidence: str = "high", verified: bool | None = None) -> Finding:
    if verified is None:
        verified = confidence == "high"
    return Finding(check=check, title=title, severity=severity, confidence=confidence,
                   description=description, recommendation=recommendation,
                   evidence=evidence or {}, verified=verified)


def _bool(config: dict[str, Any], key: str) -> bool:
    return config.get(key) is True


def identity_checks(config: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    required_true = {
        "password_hashing_argon2id_or_bcrypt": "Use a memory-hard password hash such as Argon2id with reviewed parameters.",
        "mfa_for_privileged_users": "Require MFA for privileged and administrative identities.",
        "refresh_token_rotation": "Rotate refresh tokens and detect reuse of revoked token families.",
        "session_revocation": "Support immediate session and token-family revocation.",
        "login_rate_limiting": "Apply per-account and per-source authentication throttling with abuse monitoring.",
        "secure_cookie_flags": "Set Secure, HttpOnly, and an appropriate SameSite policy on session cookies.",
        "csrf_protection": "Protect cookie-authenticated state-changing requests against CSRF.",
        "audit_admin_actions": "Record attributable, tamper-resistant audit events for privileged actions.",
        "jwt_issuer_audience_validated": "Validate JWT issuer and audience on every token verification.",
        "jwt_key_rotation_enabled": "Use managed signing-key rotation with key identifiers and a documented rollover process.",
        "refresh_token_reuse_detection": "Detect reuse of rotated refresh tokens and revoke the affected token family.",
        "session_absolute_expiry": "Enforce an absolute session expiry in addition to the idle timeout.",
        "privilege_change_revokes_sessions": "Revoke sessions or advance authorization versions after role or permission changes.",
        "password_reset_single_use": "Make password reset tokens short-lived, single-use, and bound to the intended account.",
        "sensitive_audit_fields_redacted": "Redact credentials, bearer tokens, payment references, and personal data from audit logs.",
        "service_tokens_least_privilege": "Use short-lived service identities with explicit audience and narrow scopes.",
    }
    for key, recommendation in required_true.items():
        if not _bool(config, key):
            out.append(_finding("identity", f"Identity control not confirmed: {key}", "high",
                f"The supplied identity configuration does not confirm {key}.",
                recommendation, {"control": key, "configured": str(config.get(key, "missing"))},
                "medium"))
    ttl = config.get("access_token_ttl_seconds")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0 or ttl > 900:
        out.append(_finding("identity", "Access-token lifetime is missing or excessive", "medium",
            "The access token TTL is absent, invalid, or greater than 15 minutes.",
            "Use short-lived access tokens and a documented refresh lifecycle.",
            {"access_token_ttl_seconds": str(ttl)}, "medium"))
    refresh_days = config.get("refresh_token_ttl_days")
    if isinstance(refresh_days, bool) or not isinstance(refresh_days, int) or refresh_days <= 0 or refresh_days > 30:
        out.append(_finding("identity", "Refresh-token lifetime is missing or excessive", "medium",
            "The refresh token TTL is absent, invalid, or greater than 30 days.",
            "Use a bounded refresh lifetime with rotation and reuse detection.",
            {"refresh_token_ttl_days": str(refresh_days)}, "medium"))
    idle = config.get("session_idle_timeout_minutes")
    if isinstance(idle, bool) or not isinstance(idle, int) or idle <= 0 or idle > 60:
        out.append(_finding("identity", "Session idle timeout is not bounded", "medium",
            "The supplied idle timeout is missing or exceeds 60 minutes.",
            "Set a risk-appropriate idle timeout and enforce an absolute session lifetime.",
            {"session_idle_timeout_minutes": str(idle)}, "medium"))
    if not config:
        out.append(_finding("identity", "Identity configuration snapshot is empty", "high",
            "No identity controls were supplied for review.",
            "Provide a sanitized configuration export; never include secrets."))
    return out


def tenancy_checks(cases: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    if not cases:
        return [_finding("tenancy", "No tenant-isolation cases supplied", "high",
            "No synthetic tenant authorization observations were provided.",
            "Run the application test adapter with at least two synthetic tenants and record expected versus observed access.")]
    for index, case in enumerate(cases):
        expected = case.get("expected_allowed")
        observed = case.get("observed_allowed")
        if not isinstance(expected, bool) or not isinstance(observed, bool):
            out.append(_finding("tenancy", "Malformed tenant authorization case", "medium",
                "A test case is missing boolean expected_allowed or observed_allowed values.",
                "Emit normalized test results from the application-owned tenant test adapter.",
                {"case": str(index), "case_id": str(case.get("case_id", index))}))
            continue
        if expected != observed:
            severity = "critical" if observed and not expected else "high"
            out.append(_finding("tenancy", "Tenant authorization result differs from policy", severity,
                "The observed access decision does not match the expected tenant policy.",
                "Enforce tenant ownership in the service/data-access boundary and add regression tests.",
                {"case_id": str(case.get("case_id", index))[:80],
                 "expected_allowed": str(expected), "observed_allowed": str(observed)}))
    return out


def _safe_count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value

def transaction_checks(cases: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    if not cases:
        return [_finding("transactions", "No transaction idempotency cases supplied", "high",
            "No synthetic transaction processing observations were provided.",
            "Exercise duplicate request keys, provider references, and concurrent submissions in an isolated staging fixture.")]
    key_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    receipt_groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for case in cases:
        tenant_id = str(case.get("tenant_id", "synthetic-default"))
        provider = str(case.get("provider", "mpesa"))
        provider_account = str(case.get("provider_account_id", "synthetic-account"))
        key = str(case.get("idempotency_key", ""))
        receipt = str(case.get("provider_receipt", ""))
        if not key or (key and not case.get("response_fingerprint")):
            out.append(_finding("transactions", "Transaction fixture is missing idempotency evidence", "medium",
                "Each idempotency observation must include an idempotency key and response fingerprint.",
                "Record the tenant-scoped idempotency key and a non-sensitive fingerprint of the stable response.",
                {"case_id": str(case.get("case_id", ""))[:80]}, "medium"))
        else:
            key_groups.setdefault((tenant_id, key), []).append(case)
        if receipt:
            if not case.get("transaction_id"):
                out.append(_finding("transactions", "Provider receipt fixture has no transaction ID", "medium",
                    "A provider receipt observation is missing its internal transaction identifier.",
                    "Record the synthetic internal transaction ID associated with each provider receipt.",
                    {"case_id": str(case.get("case_id", ""))[:80]}, "medium"))
            else:
                receipt_groups.setdefault((tenant_id, provider, provider_account, receipt), []).append(case)
        side_effects = _safe_count(case.get("side_effect_count", 0))
        concurrent_writes = _safe_count(case.get("concurrent_duplicate_writes", 0))
        if side_effects is None or concurrent_writes is None:
            out.append(_finding("transactions", "Malformed transaction test observation", "medium",
                "Side-effect and concurrent-write counts must be non-negative integers.",
                "Normalize test adapter counters to integers before producing the assessment bundle.",
                {"case_id": str(case.get("case_id", ""))[:80]}))
            continue
        if side_effects > 1:
            out.append(_finding("transactions", "Duplicate request caused multiple side effects", "critical",
                "A synthetic idempotency case recorded more than one business side effect.",
                "Enforce an atomic idempotency record and unique constraint before applying effects.",
                {"case_id": str(case.get("case_id", ""))[:80],
                 "side_effect_count": str(side_effects)}))
        if concurrent_writes > 0:
            out.append(_finding("transactions", "Concurrent duplicate write observed", "critical",
                "The fixture reports duplicate writes under concurrent request execution.",
                "Use database-backed uniqueness and transaction isolation; do not rely on in-process locks.",
                {"case_id": str(case.get("case_id", ""))[:80]}))
    for (tenant_id, key), group in key_groups.items():
        fingerprints = {str(item.get("response_fingerprint", "")) for item in group}
        if len(fingerprints) > 1:
            out.append(_finding("transactions", "Idempotency key returned inconsistent outcomes", "high",
                "Repeated use of one idempotency key produced different response fingerprints.",
                "Persist and replay the original result for a given tenant-scoped idempotency key.",
                {"idempotency_key_scope_sha256": hashlib.sha256(f"{tenant_id}|{key}".encode()).hexdigest(),
                 "observed_outcomes": str(len(fingerprints))}))
    for (tenant_id, provider, provider_account, receipt), group in receipt_groups.items():
        distinct = {str(item.get("transaction_id", "")) for item in group}
        if len(distinct) > 1:
            out.append(_finding("transactions", "Provider receipt linked to multiple transactions", "critical",
                "One synthetic provider receipt is associated with multiple internal transaction IDs.",
                "Enforce uniqueness on provider identity plus receipt/reference and quarantine conflicts.",
                {"provider_receipt_scope_sha256": hashlib.sha256(f"{tenant_id}|{provider}|{provider_account}|{receipt}".encode()).hexdigest(),
                 "transaction_count": str(len(distinct))}))
    return out


def ledger_checks(entries: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    if not entries:
        return [_finding("ledger", "No ledger invariant fixture supplied", "high",
            "No synthetic journal entries were supplied.",
            "Run invariant checks against a disposable database snapshot or synthetic journal export.")]
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for index, entry in enumerate(entries):
        tenant_id = str(entry.get("tenant_id", "synthetic-default"))
        txid = str(entry.get("transaction_id", ""))
        currency = str(entry.get("currency", "KES")).upper()
        if not txid:
            out.append(_finding("ledger", "Ledger entry has no transaction identifier", "high",
                "A journal entry is missing its transaction grouping key.",
                "Require immutable transaction identifiers and enforce foreign-key constraints.",
                {"entry_index": str(index)}))
            continue
        if not re.fullmatch(r"[A-Z]{3}", currency):
            out.append(_finding("ledger", "Ledger entry has an invalid currency code", "critical",
                "A journal entry currency is missing or is not a three-letter code.",
                "Require an ISO 4217 currency code and never combine entries across currencies.",
                {"entry_index": str(index), "transaction_id_sha256": hashlib.sha256(f"{tenant_id}|{txid}".encode()).hexdigest()}))
            continue
        groups.setdefault((tenant_id, txid, currency), []).append(entry)
        try:
            amount = Decimal(str(entry.get("amount", "0")))
        except (InvalidOperation, ValueError):
            amount = Decimal("-1")
        if not amount.is_finite() or amount <= 0:
            out.append(_finding("ledger", "Ledger entry amount is invalid", "critical",
                "A journal entry has a non-positive, non-finite, or invalid amount.",
                "Reject invalid monetary values and use fixed-precision decimal arithmetic.",
                {"transaction_id_scope_sha256": hashlib.sha256(f"{tenant_id}|{txid}".encode()).hexdigest()}))
        if entry.get("status") == "posted" and entry.get("mutable_after_posting") is True:
            out.append(_finding("ledger", "Posted ledger entry is mutable", "critical",
                "A fixture indicates that a posted journal entry can be edited in place.",
                "Make posted entries immutable; correct mistakes with linked compensating entries.",
                {"transaction_id_sha256": hashlib.sha256(txid.encode()).hexdigest()}))
    for (tenant_id, txid, currency), group in groups.items():
        debit = Decimal("0")
        credit = Decimal("0")
        valid = True
        for entry in group:
            try:
                amount = Decimal(str(entry.get("amount", "0")))
                side = entry.get("side")
                if side == "debit":
                    debit += amount
                elif side == "credit":
                    credit += amount
                else:
                    valid = False
            except (InvalidOperation, ValueError):
                valid = False
        if not valid or debit != credit:
            out.append(_finding("ledger", "Journal transaction is not balanced", "critical",
                "Debits and credits are unequal or one or more journal sides are invalid.",
                "Post journal entries atomically and enforce total debits equal total credits per currency and transaction.",
                {"transaction_id_scope_sha256": hashlib.sha256(f"{tenant_id}|{txid}".encode()).hexdigest(),
                 "currency": currency, "debit_total": str(debit), "credit_total": str(credit)}))
    return out


def daraja_checks(config: dict[str, Any], callbacks: list[dict[str, Any]] | None = None) -> list[Finding]:
    out: list[Finding] = []
    controls = {
        "callback_url_secret_enabled": "Use a high-entropy callback route secret and prevent URL leakage in access logs.",
        "callback_token_digest_stored": "Store only a digest of the callback route token.",
        "constant_time_token_comparison": "Compare callback token digests with a constant-time comparison.",
        "terminal_callback_payload_digest": "Persist a canonical callback payload digest to distinguish exact replays from conflicting callbacks.",
        "pending_request_only": "Accept callbacks only for an existing pending operation correlation.",
        "provider_source_restrictions_verified": "Apply source restrictions only using Safaricom-confirmed current ranges at the edge.",
        "correlate_to_initiated_request": "Accept a callback only when it correlates to a locally initiated, pending request.",
        "validate_amount_and_shortcode": "Match amount, currency, business shortcode, and expected transaction context.",
        "deduplicate_provider_receipt": "Enforce a unique provider receipt/reference and idempotent callback processing.",
        "independent_status_reconciliation": "Use an independent provider status/statement reconciliation path before final financial action.",
        "callback_payload_size_limited": "Apply strict request-body size and schema limits to callback endpoints.",
    }
    for key, recommendation in controls.items():
        if not _bool(config, key):
            out.append(_finding("daraja", f"Daraja callback control not confirmed: {key}", "high",
                f"The sanitized Daraja configuration does not confirm {key}.",
                recommendation, {"control": key}, "medium"))
    if config.get("assumes_safaricom_hmac_signature") is True:
        out.append(_finding("daraja", "Inbound callback HMAC assumption requires verification", "high",
            "The configuration claims an inbound Safaricom callback HMAC signature. Do not rely on an undocumented signature header.",
            "Verify callback authentication mechanisms with current Safaricom documentation/support. Keep downstream PesaGuard webhook signing separate.",
            {"control": "assumes_safaricom_hmac_signature"}))
    for index, callback in enumerate(callbacks or []):
        if callback.get("known_initiated_request") is False:
            out.append(_finding("daraja", "Callback references an unknown initiated request", "critical",
                "A synthetic callback was not correlated to a locally initiated request.",
                "Reject or quarantine callbacks that do not map to a pending internal request.",
                {"fixture": str(index)}))
        if callback.get("amount_matches") is False or callback.get("shortcode_matches") is False:
            out.append(_finding("daraja", "Callback financial context mismatch", "critical",
                "The synthetic callback amount or business shortcode differs from the expected request.",
                "Do not mark the transaction successful; reconcile with the provider independently.",
                {"fixture": str(index)}))
        if callback.get("duplicate_receipt_accepted") is True:
            out.append(_finding("daraja", "Duplicate provider receipt was accepted", "critical",
                "A repeated synthetic callback receipt was accepted as a new financial event.",
                "Enforce atomic receipt deduplication and idempotent state transitions.",
                {"fixture": str(index)}))
    return out


def database_checks(config: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    controls = {
        "tls_required": ("high", "Require encrypted database transport and validate certificates where supported."),
        "application_role_not_superuser": ("critical", "Use a least-privilege application role without superuser or ownership privileges."),
        "separate_migration_role": ("high", "Separate runtime application privileges from schema migration privileges."),
        "public_schema_create_revoked": ("high", "Revoke unnecessary CREATE privileges on public schemas."),
        "backup_encryption_enabled": ("high", "Encrypt database backups and test restore access controls."),
        "audit_logging_enabled": ("medium", "Enable security-relevant database audit logging with protected retention."),
        "read_only_transaction_enforced": ("critical", "Require a read-only database inspection transaction before running posture queries."),
    }
    for key, (severity, recommendation) in controls.items():
        if not _bool(config, key):
            out.append(_finding("database", f"Database control not confirmed: {key}", severity,
                f"The database snapshot does not confirm {key}.", recommendation, {"control": key}, "medium"))
    if config.get("sslmode") not in {"verify-full", "verify-ca"}:
        out.append(_finding("database", "Database TLS verification mode is weak or unspecified", "high",
            "The configured SSL mode is not verify-ca or verify-full.",
            "Use certificate-verifying TLS modes and a trusted CA bundle.",
            {"sslmode": str(config.get("sslmode", "missing"))}))
    for key, title, recommendation in [
        ("role_has_create_database", "Application database role can create databases",
         "Remove CREATEDB from the runtime application role."),
        ("role_has_create_role", "Application database role can create roles",
         "Remove CREATEROLE from the runtime application role."),
        ("role_has_replication", "Application database role has replication privilege",
         "Remove REPLICATION from the runtime application role unless it is a dedicated replication identity."),
        ("role_has_create_schema", "Application database role can create objects in public schema",
         "Revoke CREATE on public from the runtime role."),
    ]:
        if _bool(config, key):
            out.append(_finding("database", title, "critical",
                "The read-only role inspection found an elevated database privilege.",
                recommendation, {"privilege": key}))
    if config.get("read_only_transaction_enforced") is False:
        out.append(_finding("database", "Database inspection transaction was not read-only", "critical",
            "The database inspection did not confirm read-only transaction mode.",
            "Abort database inspection unless PostgreSQL confirms transaction_read_only=on."))
    return out


def pipeline_checks(config: dict[str, Any], source_files: list[dict[str, str]] | None = None) -> list[Finding]:
    out: list[Finding] = []
    for key, recommendation in {
        "service_account_least_privilege": "Use dedicated pipeline identities scoped to required source, sink, and schema permissions.",
        "sensitive_fields_classified": "Classify and tag sensitive fields before ingestion and transformation.",
        "secrets_managed_outside_code": "Use a secrets manager or deployment secret store, never source files or notebooks.",
        "logs_redact_sensitive_values": "Redact tokens, phone numbers, account identifiers, and payment references in logs.",
        "transport_encryption_enabled": "Encrypt data in transit between ingestion, brokers, workers, and storage.",
        "retention_policy_enforced": "Define and enforce retention and deletion policies for raw and derived data.",
        "lineage_and_audit_enabled": "Record data lineage, access, and privileged pipeline changes.",
    }.items():
        if not _bool(config, key):
            out.append(_finding("data_pipeline", f"Pipeline control not confirmed: {key}", "medium",
                f"The pipeline snapshot does not confirm {key}.", recommendation, {"control": key}, "medium"))
    patterns = [
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("cloud_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("generic_secret_assignment", re.compile(r"(?i)(password|secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ]
    for file in source_files or []:
        path = str(PurePosixPath(file.get("path", "unknown")))
        content = file.get("content", "")
        for name, pattern in patterns:
            if pattern.search(content):
                out.append(_finding("data_pipeline", "Possible secret material in source artifact", "critical",
                    f"A secret-like pattern was detected in {path}. The matching value is intentionally not recorded.",
                    "Revoke exposed credentials, move secrets to managed secret storage, and add secret scanning to CI.",
                    {"file": path[:160], "pattern": name}))
                break
    return out


def infrastructure_checks(files: list[dict[str, str]]) -> list[Finding]:
    out: list[Finding] = []
    if not files:
        return [_finding("infrastructure", "No infrastructure configuration supplied", "medium",
            "No Docker, Kubernetes, Terraform, or deployment configuration files were supplied.",
            "Provide a bounded set of infrastructure configuration files for static review.", "{}", "low")]
    patterns = [
        (re.compile(r"(?im)^\s*privileged\s*:\s*true\b"), "Privileged container configured", "critical",
         "Avoid privileged containers; drop capabilities and use a restrictive security context."),
        (re.compile(r"(?im)^\s*network_mode\s*:\s*host\b"), "Host networking configured", "high",
         "Use isolated container networks and explicitly publish only required ports."),
        (re.compile(r"(?im)^\s*runAsUser\s*:\s*0\b"), "Container configured to run as root", "high",
         "Run workloads as a dedicated non-root UID and enforce runAsNonRoot."),
        (re.compile(r"(?im)^\s*allowPrivilegeEscalation\s*:\s*true\b"), "Privilege escalation allowed", "high",
         "Set allowPrivilegeEscalation to false and drop unnecessary Linux capabilities."),
        (re.compile(r"(?im)^\s*runAsNonRoot\s*:\s*false\b"), "Kubernetes workload may run as root", "high",
         "Set runAsNonRoot to true and configure a non-root runAsUser."),
        (re.compile(r"(?im)^\s*(?:read_only|readOnlyRootFilesystem)\s*:\s*false\b"), "Container root filesystem is writable", "medium",
         "Use a read-only root filesystem and mount only required writable paths."),
        (re.compile(r"(?im)^\s*hostPath\s*:"), "Kubernetes hostPath volume configured", "high",
         "Avoid hostPath mounts unless there is a documented, tightly scoped operational need."),
        (re.compile(r"(?im)^\s*hostNetwork\s*:\s*true\b"), "Kubernetes host networking enabled", "high",
         "Use isolated pod networking and explicit service exposure."),
        (re.compile(r"(?im)^\s*user\s*:\s*['\"]?root\b"), "Container explicitly runs as root", "high",
         "Run containers as a dedicated non-root UID."),
        (re.compile(r"(?im)0\.0\.0\.0:(?:5432|6379|9092)"), "Internal data service bound to all interfaces", "high",
         "Do not publish database, cache, or broker ports publicly; use private networking."),
        (re.compile(r"(?im)(?:^|[\[\s,'\"])(?:5432:5432|6379:6379|9092:9092)"), "Internal data service port published without an explicit loopback bind", "high",
         "Do not publish database, cache, or broker ports publicly; use private networking."),
        (re.compile(r"(?im)^\s*image\s*:\s*[^#\s]+:latest\s*$"), "Container image uses the mutable latest tag", "medium",
         "Pin container images to immutable digests or reviewed version tags."),
        (re.compile(r"(?im)\b(?:AWS_SECRET_ACCESS_KEY|DARAJA_CONSUMER_SECRET|MPESA_PASSKEY)\s*[:=]\s*['\"]?[^\s'\"$]{8,}"), "Potential hard-coded infrastructure secret", "critical",
         "Rotate exposed secrets and use a managed secret store."),
    ]
    for file in files:
        path = str(PurePosixPath(file.get("path", "unknown")))
        source = file.get("content", "")
        for pattern, title, severity, recommendation in patterns:
            if pattern.search(source):
                out.append(_finding("infrastructure", title, severity,
                    f"A risky configuration pattern was found in {path}.",
                    recommendation, {"file": path[:160]}))
    return out

def outbound_webhook_checks(config: dict[str, Any], secret: str | None = None) -> list[Finding]:
    out: list[Finding] = []
    webhook_controls = {
        "hmac_sha256_enabled": "Sign the exact raw request body with HMAC-SHA256.",
        "sign_exact_raw_body": "Sign the exact raw bytes, not a re-serialized JSON object.",
        "constant_time_signature_comparison": "Verify signatures using constant-time comparison.",
        "per_tenant_signing_secret": "Use independently rotatable tenant-scoped webhook secrets.",
        "timestamp_and_replay_window_enforced": "Include a signed timestamp and reject stale events.",
        "event_id_deduplication": "Deduplicate delivery attempts by stable event ID.",
        "bounded_retry_policy": "Use bounded exponential retry and a dead-letter path.",
    }
    for key, recommendation in webhook_controls.items():
        if not _bool(config, key):
            out.append(_finding("webhook", f"Downstream webhook control not confirmed: {key}", "high",
                f"The PesaGuard outbound webhook configuration does not confirm {key}.",
                recommendation, {"control": key}, "medium"))
    if secret is not None and len(secret) < 32:
        out.append(_finding("webhook", "Webhook signing secret is too short", "critical",
            "The supplied test secret is shorter than 32 characters.",
            "Generate a cryptographically random secret of at least 32 bytes. The value is never recorded."))
    return out
