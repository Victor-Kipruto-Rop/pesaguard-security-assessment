from pathlib import Path

from pg_assess.pesaguard_adapter import DOMAIN_TESTS, inspect_adapter_coverage


def _fixture_repo(tmp_path: Path) -> Path:
    root = tmp_path
    pipeline = root / "pesaguard_backend_pipeline"
    tests = pipeline / "tests"
    tests.mkdir(parents=True)
    for name in ("auth_rbac.py", "authorization_policy.py", "transaction_routes.py",
                 "event_store.py", "models.py", "mpesa_operation_service.py",
                 "mpesa_operation_webhooks.py", "daraja_tenant_routing.py",
                 "validators.py", "mpesa_configuration.py", "data_protection.py",
                 "etl_pipeline.py", "lineage.py"):
        (pipeline / name).write_text("# synthetic fixture\n", encoding="utf-8")
    for name in DOMAIN_TESTS["identity"] + DOMAIN_TESTS["tenancy"]:
        (tests / name).write_text("# synthetic test fixture\n", encoding="utf-8")
    return root


def test_adapter_coverage_reports_missing_ledger_and_database_tests(tmp_path):
    report, risk = inspect_adapter_coverage(_fixture_repo(tmp_path))
    titles = [finding.title.lower() for finding in report.findings]
    assert any("ledger behavioral test coverage" in title for title in titles)
    assert any("database behavioral test coverage" in title for title in titles)
    assert risk["domain_coverage"]["identity"]["tests_present"] == 3
    assert risk["domain_coverage"]["ledger"]["tests_present"] == 0


def test_adapter_coverage_does_not_claim_tests_were_executed(tmp_path):
    report, _ = inspect_adapter_coverage(_fixture_repo(tmp_path))
    assert any("does not import pesaguard or execute its tests" in note.lower()
               for note in report.notes)
    assert all(not finding.verified for finding in report.findings)
