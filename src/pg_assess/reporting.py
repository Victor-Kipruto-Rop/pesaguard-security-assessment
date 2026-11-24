import html
import json
from pathlib import Path
from .models import AssessmentReport


def save_report(report: AssessmentReport, directory: str) -> tuple[Path, Path]:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    data = report.model_dump(mode="json")
    json_path = root / f"{report.assessment_id}.json"
    html_path = root / f"{report.assessment_id}.html"
    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    rows = "".join(
        "<tr><td>" + html.escape(f.severity) + "</td><td>" + html.escape(f.title) +
        "</td><td>" + html.escape(f.description) + "</td><td>" +
        html.escape(f.recommendation) + "</td></tr>" for f in report.findings)
    page = ("<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
        "<title>Assessment report</title><style>body{font:15px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;color:#17231d}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:10px;text-align:left}"
        "th{background:#f1f5f2}</style><h1>PesaGuard Security Assessment</h1><p>Target: " +
        html.escape(report.target_url) + " | Environment: " + html.escape(report.environment.value) +
        " | Status: " + html.escape(report.status) + "</p><p>Assessment ID: " +
        html.escape(report.assessment_id) + "</p><table><thead><tr><th>Severity</th><th>Finding</th>"
        "<th>Description</th><th>Recommendation</th></tr></thead><tbody>" + rows + "</tbody></table></html>")
    html_path.write_text(page, encoding="utf-8")
    return json_path, html_path


def save_bundle_report(report: AssessmentReport, risk: dict, directory: str) -> tuple[Path, Path]:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    json_path = root / f"{report.assessment_id}.json"
    html_path = root / f"{report.assessment_id}.html"
    payload = {"report": report.model_dump(mode="json"), "risk": risk}
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    rows = "".join(
        "<tr><td>" + html.escape(f.severity) + "</td><td>" + html.escape(f.check) +
        "</td><td>" + html.escape(f.title) + "</td><td>" + html.escape(f.description) +
        "</td><td>" + html.escape(f.recommendation) + "</td></tr>"
        for f in report.findings
    )
    coverage = risk.get("domain_coverage", {})
    test_counts = risk.get("domain_test_counts", {})
    coverage_rows = ""
    for domain in sorted(set(coverage) | set(test_counts)):
        item = coverage.get(domain, {})
        executed = test_counts.get(domain, {})
        test_label = (
            f"{item.get('tests_present', 0)}/{item.get('tests_expected', 0)} discovered"
            if item else "JUnit execution"
        )
        source_label = (
            f"{item.get('source_modules_present', 0)}/{item.get('source_modules_expected', 0)} source modules"
            if item else ""
        )
        result_label = ", ".join(f"{key}: {value}" for key, value in sorted(executed.items()))
        coverage_rows += (
            "<tr><td>" + html.escape(domain) + "</td><td>" + html.escape(test_label) +
            "</td><td>" + html.escape(source_label) + "</td><td>" +
            html.escape(result_label or "Not executed / not imported") + "</td></tr>"
        )
    coverage_section = ""
    if coverage_rows:
        coverage_section = (
            "<h2>Domain adapter coverage</h2><p>Discovery is not execution evidence. "
            "JUnit counts below represent only tests present in the imported report.</p>"
            "<table><thead><tr><th>Domain</th><th>Test modules</th><th>Source modules</th>"
            "<th>JUnit results</th></tr></thead><tbody>" + coverage_rows + "</tbody></table>"
        )
    page = ("<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
        "<title>PesaGuard security assessment</title><style>body{font:15px system-ui;max-width:1200px;margin:36px auto;padding:0 20px;color:#17231d}"
        "table{border-collapse:collapse;width:100%;margin:12px 0 28px}td,th{border:1px solid #ddd;padding:9px;text-align:left;vertical-align:top}"
        "th{background:#f1f5f2}code{overflow-wrap:anywhere}</style><h1>PesaGuard Security Assessment</h1>"
        "<h2>Risk prioritization: " + html.escape(str(risk.get("band"))) + " (" +
        html.escape(str(risk.get("score"))) + "/100)</h2><p>Verified findings: " +
        html.escape(str(risk.get("verified_findings", 0))) + " | Unverified or unconfirmed: " +
        html.escape(str(risk.get("unverified_or_unconfirmed_findings", 0))) + "</p><p>" +
        html.escape(str(risk.get("method"))) + "</p><p>Assessment: " +
        html.escape(report.assessment_id) + "</p><p>Checks run: " +
        html.escape(", ".join(report.checks_run)) + "</p>" + coverage_section +
        "<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Domain</th>"
        "<th>Finding</th><th>Description</th><th>Recommendation</th></tr></thead><tbody>" +
        rows + "</tbody></table></html>")
    html_path.write_text(page, encoding="utf-8")
    return json_path, html_path
