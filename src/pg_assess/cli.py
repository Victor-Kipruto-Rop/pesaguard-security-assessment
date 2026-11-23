import asyncio
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

if __name__ == "__main__":
    app()
