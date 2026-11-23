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
        "<th>Description</th><th>Recommendation</th></tr></thead><tbody>" + rows +
        "</tbody></table></html>")
    html_path.write_text(page, encoding="utf-8")
    return json_path, html_path
