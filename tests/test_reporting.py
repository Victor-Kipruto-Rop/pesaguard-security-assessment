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
