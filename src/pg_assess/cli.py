import asyncio
import json
from pathlib import Path
import typer
from rich import print
from .engine import assess
from .models import CheckName, TargetAuthorization
from .reporting import save_report

app = typer.Typer(help="Run explicitly authorized PesaGuard security assessments.")

@app.command()
def run(authorization_file: Path = typer.Option(..., exists=True, readable=True),
        checks: str = typer.Option("http_headers,tls,cookie_flags,openapi_exposure"),
        output: Path = typer.Option(Path("reports"))):
    """Execute only checks listed in the supplied authorization manifest."""
    auth = TargetAuthorization.model_validate_json(authorization_file.read_text(encoding="utf-8"))
    selected = [CheckName(item.strip()) for item in checks.split(",") if item.strip()]
    report = asyncio.run(assess(auth, selected))
    paths = save_report(report, str(output))
    print(f"[green]Assessment complete[/green] {report.assessment_id}")
    print(f"JSON: {paths[0]}\nHTML: {paths[1]}")



@app.command("assess-bundle")
def assess_bundle(bundle_file: Path = typer.Option(..., exists=True, readable=True,
                                                    help="Sanitized JSON configuration and synthetic fixture bundle."),
                  output: Path = typer.Option(Path("reports"))):
    """Run offline PesaGuard domain checks. This command never contacts target systems."""
    from .bundle import run_bundle
    from .evidence import EvidenceStore
    from .reporting import save_bundle_report
    bundle = json.loads(bundle_file.read_text(encoding="utf-8"))
    if not isinstance(bundle, dict):
        raise typer.BadParameter("Assessment bundle root must be a JSON object.")
    report, risk = run_bundle(bundle)
    json_path, html_path = save_bundle_report(report, risk, str(output))
    store = EvidenceStore(str(output / "evidence.sqlite3"))
    event = store.append("assessment.completed", {
        "assessment_id": report.assessment_id,
        "risk_score": risk["score"],
        "finding_count": risk["finding_count"],
    })
    print(f"[green]Offline assessment complete[/green] {report.assessment_id}")
    print(f"Risk prioritization: {risk['band']} ({risk['score']}/100)")
    print(f"Findings: {risk['finding_count']}")
    print(f"JSON: {json_path}\\nHTML: {html_path}")
    print(f"Evidence chain event: {event['sequence']}")

@app.command("verify-evidence")
def verify_evidence(database: Path = typer.Option(Path("reports/evidence.sqlite3"), exists=True)):
    """Verify the local evidence journal hash chain."""
    from .evidence import EvidenceStore
    result = EvidenceStore(database).verify()
    if not result["valid"]:
        raise typer.Exit(code=2)
    print(f"[green]Evidence chain valid[/green] ({result['verified_events']} events)")


@app.command("assess-source")
def assess_source(repo_root: Path = typer.Option(..., exists=True, file_okay=False, readable=True,
                                                 help="Local root of a PesaGuard API checkout."),
                  output: Path = typer.Option(Path("reports"))):
    """Statically inspect a PesaGuard source checkout without importing or executing it."""
    from .source_audit import audit_source_tree
    from .reporting import save_bundle_report
    report, risk = audit_source_tree(repo_root)
    json_path, html_path = save_bundle_report(report, risk, str(output))
    print(f"[green]Static source audit complete[/green] {report.assessment_id}")
    print(f"Risk prioritization: {risk['band']} ({risk['score']}/100)")
    print(f"Findings: {risk['finding_count']}")
    print(f"JSON: {json_path}\\nHTML: {html_path}")

if __name__ == "__main__":
    app()


@app.command("assess-database")
def assess_database(confirm_read_only: bool = typer.Option(False, "--confirm-read-only",
        help="Confirm that the tool may open a read-only PostgreSQL session."),
        output: Path = typer.Option(Path("reports"))):
    """Inspect PostgreSQL role/TLS posture using a read-only transaction."""
    if not confirm_read_only:
        raise typer.BadParameter("Pass --confirm-read-only after confirming the target database is authorized.")
    from .database_runtime import inspect_postgres_readonly
    from .bundle import run_bundle
    from .reporting import save_bundle_report
    from .evidence import EvidenceStore
    snapshot = inspect_postgres_readonly()
    report, risk = run_bundle({"database": snapshot})
    json_path, html_path = save_bundle_report(report, risk, str(output))
    store = EvidenceStore(str(output / "evidence.sqlite3"))
    store.append("database.read_only_assessment.completed", {
        "assessment_id": report.assessment_id,
        "risk_score": risk["score"],
        "finding_count": risk["finding_count"],
    })
    print(f"[green]Read-only database assessment complete[/green] {report.assessment_id}")
    print(f"Risk prioritization: {risk['band']} ({risk['score']}/100)")
    print(f"JSON: {json_path}\\nHTML: {html_path}")
