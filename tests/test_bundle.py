from pg_assess.bundle import run_bundle
from pg_assess.risk import score_findings
from pg_assess.models import Finding

def test_bundle_reports_only_supplied_domains():
    report, risk = run_bundle({"assessment_target_id":"local-fixture",
        "tenancy_cases":[{"case_id":"bad","expected_allowed":False,"observed_allowed":True}]})
    assert report.checks_run == ["tenancy"]
    assert report.findings[0].severity == "critical"
    assert risk["band"] == "critical"

def test_risk_score_is_bounded():
    findings = [Finding(check="x", title="x", severity="critical", confidence="high",
        description="x", recommendation="x") for _ in range(50)]
    assert score_findings(findings)["score"] == 100


def test_bundle_rejects_unknown_domain_keys():
    import pytest
    from pg_assess.bundle import validate_bundle
    with pytest.raises(ValueError, match="Unknown bundle sections"):
        validate_bundle({"identitiy": {}})

def test_bundle_reports_empty_scope_as_unassessed():
    report, risk = run_bundle({})
    assert any("contains no domains" in f.title.lower() for f in report.findings)
    assert "ledger" in report.notes[1]

def test_daraja_callback_fixtures_can_run_without_config_snapshot():
    report, _ = run_bundle({"daraja_callbacks":[{"known_initiated_request":False}]})
    assert "daraja" in report.checks_run
    assert any(f.severity == "critical" for f in report.findings)
