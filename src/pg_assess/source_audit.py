"""Static, non-executing audit adapter for a local PesaGuard source checkout.

The adapter reads a fixed allowlist of source and test files. It never imports,
executes, or modifies the target application.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .models import AssessmentReport, Environment, Finding
from .risk import score_findings

PIPELINE = Path("pesaguard_backend_pipeline")
FILES = {
    "auth": PIPELINE / "auth_rbac.py",
    "policy": PIPELINE / "authorization_policy.py",
    "transactions": PIPELINE / "transaction_routes.py",
    "event_store": PIPELINE / "event_store.py",
    "models": PIPELINE / "models.py",
    "callback_route": PIPELINE / "mpesa_operation_webhooks.py",
    "callback_service": PIPELINE / "mpesa_operation_service.py",
    "daraja_routing": PIPELINE / "daraja_tenant_routing.py",
    "validators": PIPELINE / "validators.py",
    "protection": PIPELINE / "data_protection.py",
    "etl": PIPELINE / "etl_pipeline.py",
    "lineage": PIPELINE / "lineage.py",
    "auth_tests": PIPELINE / "tests/test_auth_lifecycle.py",
    "tenant_tests": PIPELINE / "tests/test_tenant_scope_constraints.py",
    "daraja_tests": PIPELINE / "tests/test_daraja_validation.py",
    "race_tests": PIPELINE / "tests/test_postgres_concurrency.py",
}

def _read(root: Path, relative: Path) -> str:
    candidate = (root / relative).resolve()
    base = root.resolve()
    if base not in candidate.parents:
        return ""
    try:
        if candidate.is_file() and candidate.stat().st_size <= 2_000_000:
            return candidate.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    return ""

def _check(findings: list[Finding], domain: str, source: str, file: str,
           indicator: str, title: str, severity: str, recommendation: str) -> None:
    if indicator not in source:
        findings.append(Finding(
            check=domain, title=title, severity=severity, confidence="medium",
            description=f"Expected source indicator was not found in {file}. This is a static-review gap, not proof the control is absent at runtime.",
            evidence={"file": file, "missing_indicator": indicator[:120]},
            recommendation=recommendation, verified=False))

def audit_source_tree(repo_root: str | Path) -> tuple[AssessmentReport, dict]:
    root = Path(repo_root)
    sources = {key: _read(root, path) for key, path in FILES.items()}
    findings: list[Finding] = []
    checks = ["identity", "tenancy", "transactions", "ledger", "daraja",
              "database", "data_pipeline", "test_coverage"]

    # Identity and session lifecycle.
    for indicator, title, severity, recommendation in [
        ("ACCESS_TOKEN_TTL_MINUTES <= 15", "Access-token TTL is not visibly capped at 15 minutes", "high", "Keep access tokens short-lived and enforce the maximum in configuration."),
        ('"tenant_id"', "JWT tenant claim is not visibly required", "critical", "Require and validate tenant identity in every user and service token."),
        ("RefreshTokenRecord", "Persisted refresh-token state is not visible", "high", "Persist refresh token hashes, families, expiry, and revocation state."),
        ("_hash_refresh_token", "Refresh tokens are not visibly stored as hashes", "high", "Store a one-way digest of refresh tokens, never the bearer token."),
        ("absolute_expires_at", "Absolute session expiry enforcement is not visible", "medium", "Enforce both idle and absolute session expiry."),
    ]:
        _check(findings, "identity", sources["auth"], str(FILES["auth"]), indicator, title, severity, recommendation)
    for indicator in ("deny by default", "wildcard_rejected", "unknown_permission"):
        _check(findings, "identity", sources["policy"], str(FILES["policy"]), indicator,
               f"Authorization policy indicator missing: {indicator}", "high",
               "Reject unknown, wildcard, and internal scopes unless explicitly granted.")

    # Tenant boundaries and M-Pesa tenant routing.
    for indicator, title, severity, recommendation in [
        ("requested_tenant != authenticated_tenant", "Authenticated tenant mismatch guard not visible", "critical", "Reject caller-supplied tenant overrides when they differ from the authenticated principal."),
        ("tenant_access_denied", "Tenant mismatch denial response not visible", "critical", "Return a deny response before reading or writing tenant data."),
        ("Transaction.tenant_id == tenant_id", "Tenant predicate not visible in transaction queries", "critical", "Scope every transaction read/write query to the authenticated tenant."),
    ]:
        _check(findings, "tenancy", sources["transactions"], str(FILES["transactions"]), indicator, title, severity, recommendation)
    for indicator in ('UniqueConstraint("tenant_id"', 'CheckConstraint("tenant_id IS NOT NULL'):
        _check(findings, "tenancy", sources["models"], str(FILES["models"]), indicator,
               "Database-level tenant integrity constraint not visible", "high",
               "Enforce tenant ownership and non-empty tenant IDs with database constraints.")
    for indicator in ("UnknownDarajaShortcode", "AmbiguousDarajaShortcode", "PaymentProvider.status == \"active\"", "MpesaIntegration.environment == environment"):
        _check(findings, "daraja", sources["daraja_routing"], str(FILES["daraja_routing"]), indicator,
               f"Fail-closed Daraja routing indicator missing: {indicator}", "critical",
               "Resolve callbacks only through one active server-managed M-Pesa integration.")

    # Transaction replay and race controls.
    for indicator, title, severity, recommendation in [
        ("with_for_update()", "Replay comparison row lock not visible", "high", "Serialize conflicting callback state transitions with database locking or equivalent concurrency controls."),
        ("ProcessResult.DUPLICATE", "Duplicate callback outcome not visible", "high", "Return a durable no-op result for exact duplicate provider callbacks."),
        ("ProcessResult.CONFLICT", "Conflicting replay quarantine not visible", "critical", "Quarantine same provider identity with conflicting transaction facts."),
        ("IntegrityError", "Database uniqueness race handling not visible", "high", "Treat unique constraints as the final idempotency guarantee and classify conflicts."),
    ]:
        _check(findings, "transactions", sources["event_store"], str(FILES["event_store"]), indicator, title, severity, recommendation)
    for indicator in ("uq_transaction_scope_trans_id", "uq_idempotency_request", "uq_processed_scope_trans_id"):
        _check(findings, "transactions", sources["models"], str(FILES["models"]), indicator,
               f"Scoped uniqueness constraint not visible: {indicator}", "critical",
               "Use database-enforced unique constraints scoped by tenant and provider identity.")

    # Ledger: never assume a transaction table is a double-entry accounting ledger.
    ledger_evidence = any(word in sources["models"].lower() for word in ("ledgerentry", "journalentry", "double_entry", "journal_entries"))
    if not ledger_evidence:
        findings.append(Finding(check="ledger", title="Dedicated double-entry ledger model not found in inspected models",
            severity="high", confidence="medium",
            description="The inspected PesaGuard ORM models show transaction and reconciliation records, but no explicit journal/ledger-entry model indicator.",
            evidence={"file": str(FILES["models"])},
            recommendation="Identify the authoritative financial ledger system. If PesaGuard owns it, add immutable journal entries, debit/credit balancing, currency partitioning, and compensating-entry tests.",
            verified=False))

    # Daraja callback trust and synthetic validation.
    for indicator, title, severity, recommendation in [
        ("_CALLBACK_TOKEN", "Callback token format validation not visible", "high", "Use a high-entropy callback token with strict length and character validation."),
        ("hmac.compare_digest", "Constant-time callback token comparison not visible", "high", "Compare token digests using constant-time comparison."),
        ("callback_token_digest", "Stored callback-token digest not visible", "high", "Persist only a digest of callback secrets, not the raw token."),
        ("callback_payload_digest", "Callback payload replay digest not visible", "high", "Store a canonical payload digest and reject conflicting terminal callbacks."),
        ("correlation.state != \"PENDING\"", "Pending-state gate not visible", "critical", "Only accept callbacks for an existing pending operation correlation."),
        ("request.args.get(\"token\")", "Callback route does not visibly pass its route token to the service", "critical", "Pass and validate the high-entropy callback token before accepting the callback."),
    ]:
        source = sources["callback_route"] if indicator == 'request.args.get("token")' else sources["callback_service"]
        file = str(FILES["callback_route"] if indicator == 'request.args.get("token")' else FILES["callback_service"])
        _check(findings, "daraja", source, file, indicator, title, severity, recommendation)
    _check(findings, "daraja", sources["validators"], str(FILES["validators"]),
           "validate_daraja_payload", "Daraja payload schema validation not visible", "high",
           "Validate supported C2B/STK/B2C callback envelopes and reject malformed types before persistence.")

    # Database and sensitive data handling.
    for indicator, title, severity, recommendation in [
        ("AESGCM", "Authenticated encryption for M-Pesa credentials not visible", "high", "Use authenticated encryption with key versioning and rotation for provider credentials."),
        ("MPESA_CREDENTIALS_ENCRYPTION_KEY", "Dedicated M-Pesa credential encryption key not visible", "critical", "Load encryption keys from a secret manager and fail closed when unavailable."),
    ]:
        _check(findings, "database", sources["protection"], str(FILES["protection"]), indicator, title, severity, recommendation)
    _check(findings, "database", sources["models"], str(FILES["models"]),
           "UniqueConstraint", "Database uniqueness constraints not visible", "high",
           "Enforce idempotency and tenant constraints in the database, not only application code.")

    # Data engineering lineage and tenant propagation.
    for source_key, indicator, title in [
        ("etl", "tenant_id=dataset.tenant_id", "ETL ingestion does not visibly propagate the dataset tenant"),
        ("lineage", "tenant_id", "Lineage implementation does not visibly carry tenant scope"),
        ("protection", "protect_payload", "Sensitive provider payload protection is not visible"),
    ]:
        _check(findings, "data_pipeline", sources[source_key], str(FILES[source_key]), indicator,
               title, "high", "Preserve tenant scope, lineage, and sensitive-data protection across ingestion and transformation.")

    # Existing regression coverage. These files may contain opt-in tests; this is presence, not execution.
    for source_key, title in [
        ("auth_tests", "Authentication/session lifecycle tests not found"),
        ("tenant_tests", "Tenant database isolation tests not found"),
        ("daraja_tests", "Daraja callback validation tests not found"),
        ("race_tests", "PostgreSQL concurrency test not found"),
    ]:
        if not sources[source_key]:
            findings.append(Finding(check="test_coverage", title=title, severity="medium",
                confidence="high", description="The expected test file was not readable in the supplied source tree.",
                evidence={"file": str(FILES[source_key])},
                recommendation="Add an isolated regression test and execute it in CI or a disposable integration environment.",
                verified=False))

    now = datetime.now(timezone.utc)
    report = AssessmentReport(assessment_id=str(uuid4()), target_id="pesaguard-source-checkout",
        target_url="file://local-pesaguard-checkout", environment=Environment.LOCAL,
        started_at=now, completed_at=now, status="completed", findings=findings,
        checks_run=checks,
        notes=["Static source inspection only. No application code was imported or executed.",
               "A detected source indicator does not prove runtime enforcement.",
               "PostgreSQL integration tests are only present in source; their execution status is not inferred.",
               "A dedicated double-entry ledger implementation was not identified in the inspected ORM model file."])
    return report, score_findings(findings)
