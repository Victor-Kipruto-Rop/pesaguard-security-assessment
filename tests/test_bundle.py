from pg_assess.bundle import run_bundle
from pg_assess.risk import score_findings
from pg_assess.models import Finding

def test_bundle_reports_only_supplied_domains():
    report, risk = run_bundle({"assessment_target_id":"local-fixture",
        "tenancy_cases":[{"case_id":"bad","expected_allowed":False,"observed_allowed":True}]})
    assert report.checks_run == ["tenancy"]
    assert report.findings[0].severity == "critical"
    assert risk["band"] == "moderate" or risk["band"] == "high" or risk["band"] == "critical"

def test_risk_score_is_bounded():
    findings = [Finding(check="x", title="x", severity="critical", confidence="high",
        description="x", recommendation="x") for _ in range(50)]
    assert score_findings(findings)["score"] == 100
