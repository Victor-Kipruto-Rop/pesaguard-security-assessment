"""PesaGuard-specific adapter coverage inventory.

This adapter inspects the expected application-owned test modules and source
modules without importing or executing the PesaGuard application. It makes
coverage gaps explicit instead of treating static indicators as runtime proof.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .models import AssessmentReport, Environment, Finding
from .risk import score_findings

PIPELINE = Path("pesaguard_backend_pipeline")
TEST_ROOT = PIPELINE / "tests"

# Existing PesaGuard regression tests, grouped by the security property they
# exercise. Missing files are reported as coverage gaps, not as vulnerabilities.
DOMAIN_TESTS: dict[str, tuple[str, ...]] = {
    "identity": (
        "test_auth_lifecycle.py",
        "test_session_lifecycle_fail_closed.py",
        "test_rbac_enforcement.py",
    ),
    "tenancy": (
        "test_tenant_scope_constraints.py",
        "test_export_tenant_scoping.py",
    ),
    "transactions": (
        "test_api_idempotency_contract.py",
        "test_transaction_routes.py",
    ),
    "ledger": ("test_ledger_invariants.py",),
    "daraja": (
        "test_daraja_validation.py",
        "test_daraja_tenant_routing.py",
        "test_mpesa_operations.py",
    ),
    "database": ("test_database_privileges.py",),
    "data_pipeline": (
        "test_data_protection.py",
        "test_etl_pipeline.py",
        "test_lineage.py",
    ),
    "infrastructure": ("test_deployment_security.py",),
}

SOURCE_MODULES: dict[str, tuple[str, ...]] = {
    "identity": ("auth_rbac.py", "authorization_policy.py"),
    "tenancy": ("transaction_routes.py", "models.py"),
    "transactions": ("event_store.py", "transaction_routes.py", "models.py"),
    "ledger": ("models.py",),
    "daraja": (
        "mpesa_operation_service.py",
        "mpesa_operation_webhooks.py",
        "daraja_tenant_routing.py",
        "validators.py",
    ),
    "database": ("models.py", "mpesa_configuration.py"),
    "data_pipeline": ("data_protection.py", "etl_pipeline.py", "lineage.py"),
    "infrastructure": (),
}


def inspect_adapter_coverage(repo_root: str | Path) -> tuple[AssessmentReport, dict]:
    """Inventory domain test/source coverage without running target code."""
    root = Path(repo_root).resolve()
    test_dir = root / TEST_ROOT
    source_dir = root / PIPELINE
    findings: list[Finding] = []
    checks_run: list[str] = []

    for domain, expected_tests in DOMAIN_TESTS.items():
        present = [name for name in expected_tests if (test_dir / name).is_file()]
        missing = [name for name in expected_tests if name not in present]
        source_expected = SOURCE_MODULES[domain]
        source_present = [name for name in source_expected if (source_dir / name).is_file()]
        source_missing = [name for name in source_expected if name not in source_present]
        if present or source_present:
            checks_run.append(domain)
        if missing:
            findings.append(Finding(
                check=domain,
                title=f"{domain.replace('_', ' ').title()} behavioral test coverage is incomplete",
                severity="medium" if present else "high",
                confidence="high",
                description=(
                    "The adapter inventory did not find all expected PesaGuard-owned "
                    "regression test modules. This is a coverage gap, not proof of an exploitable defect."
                ),
                evidence={
                    "present_tests": ",".join(present) or "none",
                    "missing_tests": ",".join(missing),
                },
                recommendation=(
                    "Add isolated application-owned tests for this domain, using synthetic tenants, "
                    "transactions, callbacks, and disposable databases. Do not use production data."
                ),
                verified=False,
            ))
        if source_missing:
            findings.append(Finding(
                check=domain,
                title=f"{domain.replace('_', ' ').title()} source modules are not fully discoverable",
                severity="medium",
                confidence="medium",
                description=(
                    "One or more expected source modules were not found at the current "
                    "PesaGuard package path. The project may have moved or renamed these modules."
                ),
                evidence={"missing_modules": ",".join(source_missing)},
                recommendation=(
                    "Review the adapter's fixed source map against the current PesaGuard package layout "
                    "before interpreting source-audit results."
                ),
                verified=False,
            ))

    # Evidence/reporting are owned by this assessor repository, not api.pesaguard.
    assessor_tests = Path(__file__).resolve().parents[2] / "tests"
    evidence_tests = ("test_evidence.py", "test_reporting.py", "test_junit_adapter.py")
    evidence_present = [name for name in evidence_tests if (assessor_tests / name).is_file()]
    evidence_missing = [name for name in evidence_tests if name not in evidence_present]
    if evidence_missing:
        findings.append(Finding(
            check="evidence",
            title="Evidence and reporting regression coverage is incomplete",
            severity="medium",
            confidence="high",
            description="The assessment toolkit is missing expected evidence/reporting regression test modules.",
            evidence={"present_tests": ",".join(evidence_present) or "none",
                      "missing_tests": ",".join(evidence_missing)},
            recommendation="Add tests for hash-chain tampering, report escaping, evidence linkage, and domain coverage rendering.",
            verified=False,
        ))
    checks_run.append("evidence")

    now = datetime.now(timezone.utc)
    report = AssessmentReport(
        assessment_id=str(uuid4()),
        target_id="pesaguard-adapter-coverage",
        target_url="file://pesaguard-source-checkout",
        environment=Environment.LOCAL,
        started_at=now,
        completed_at=now,
        status="completed",
        findings=findings,
        checks_run=checks_run,
        notes=[
            "Coverage inventory only: this command does not import PesaGuard or execute its tests.",
            "A present test file does not prove its assertions passed; import a JUnit report for execution evidence.",
            "Ledger, database, and infrastructure application-owned test gaps are reported separately from this toolkit’s evidence/reporting tests.",
        ],
    )
    risk = score_findings(findings)
    risk["domain_coverage"] = {
        domain: {
            "tests_present": sum((test_dir / name).is_file() for name in tests),
            "tests_expected": len(tests),
            "source_modules_present": sum((source_dir / name).is_file() for name in SOURCE_MODULES[domain]),
            "source_modules_expected": len(SOURCE_MODULES[domain]),
        }
        for domain, tests in DOMAIN_TESTS.items()
    }
    risk["domain_coverage"]["evidence"] = {
        "tests_present": len(evidence_present),
        "tests_expected": len(evidence_tests),
        "source_modules_present": 2,
        "source_modules_expected": 2,
    }
    return report, risk
