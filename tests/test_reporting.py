from datetime import datetime, timezone
from pg_assess.models import AssessmentReport, Environment, Finding
from pg_assess.reporting import save_report

def test_report_writes_json_and_escaped_html(tmp_path):
    now = datetime.now(timezone.utc)
    report = AssessmentReport(assessment_id="test-123", target_id="local",
        target_url="http://127.0.0.1", environment=Environment.LOCAL,
        started_at=now, completed_at=now, status="completed",
        findings=[Finding(check="x", title="<script>", severity="low", confidence="high",
            description="test", recommendation="fix")], checks_run=["x"])
    json_path, html_path = save_report(report, str(tmp_path))
    assert json_path.exists()
    assert html_path.exists()
    assert "&lt;script&gt;" in html_path.read_text()

def test_bundle_report_renders_domain_coverage(tmp_path):
    from pg_assess.reporting import save_bundle_report
    now = datetime.now(timezone.utc)
    report = AssessmentReport(assessment_id="coverage-test", target_id="local",
        target_url="file://coverage", environment=Environment.LOCAL,
        started_at=now, completed_at=now, status="completed", findings=[],
        checks_run=["identity"])
    _, html_path = save_bundle_report(report, {
        "band": "low", "score": 0, "verified_findings": 0,
        "unverified_or_unconfirmed_findings": 0, "method": "test",
        "domain_coverage": {"identity": {"tests_present": 2, "tests_expected": 3,
            "source_modules_present": 2, "source_modules_expected": 2}},
    }, str(tmp_path))
    page = html_path.read_text(encoding="utf-8")
    assert "Domain adapter coverage" in page
    assert "2/3 discovered" in page
    assert "Not executed / not imported" in page
