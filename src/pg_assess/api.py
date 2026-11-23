import hmac
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from .config import settings
from .engine import assess
from .models import CheckName, TargetAuthorization
from .policy import PolicyError
from .reporting import save_report, save_bundle_report\nfrom .bundle import run_bundle\nfrom .evidence import EvidenceStore

app = FastAPI(title="PesaGuard Security Assessment", version="0.1.0",
    description="Authorized, bounded, non-destructive security checks.")

@app.middleware("http")
async def assessment_body_limit(request: Request, call_next):
    if request.method == "POST" and request.url.path in {"/v1/assessments", "/v1/bundle-assessments"}:
        raw_length = request.headers.get("content-length")
        if raw_length is None:
            return JSONResponse(status_code=411, content={"detail": "Content-Length is required."})
        try:
            length = int(raw_length)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length."})
        if length < 0 or length > 5_000_000:
            return JSONResponse(status_code=413, content={"detail": "Assessment request exceeds the 5 MB limit."})
    return await call_next(request)

def require_key(x_assessment_key: str | None = Header(default=None)):
    if len(settings.assessment_api_key) < 32 or settings.assessment_api_key in {"change-me", "replace-with-a-long-random-local-key"}:
        raise HTTPException(status_code=503, detail="Assessment API key is not configured securely.")
    if not x_assessment_key or not hmac.compare_digest(x_assessment_key, settings.assessment_api_key):
        raise HTTPException(status_code=401, detail="Valid assessment API key required.")

class RunRequest(BaseModel):
    authorization: TargetAuthorization
    checks: list[CheckName]

@app.get("/healthz")
def health():
    return {"status": "ok", "service": "pg-assess"}

@app.post("/v1/assessments", dependencies=[Depends(require_key)])
async def create_assessment(request: RunRequest):
    try:
        report = await assess(request.authorization, request.checks)
    except PolicyError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Assessment failed: {type(exc).__name__}") from exc
    json_path, html_path = save_report(report, settings.assessment_data_dir)
    store = EvidenceStore(f"{settings.assessment_data_dir}/evidence.sqlite3")
    event = store.append("assessment.active.completed", {
        "assessment_id": report.assessment_id,
        "target_id": report.target_id,
        "environment": report.environment.value,
        "checks_run": report.checks_run,
        "finding_count": len(report.findings),
    })
    return {"report": report, "artifacts": {"json": json_path.name, "html": html_path.name},
            "evidence_event": event}


class SourceFile(BaseModel):
    path: str = Field(min_length=1, max_length=512)
    content: str = Field(max_length=100_000)

class BundleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_target_id: str = Field(default="offline-bundle", min_length=3, max_length=100)
    identity: dict = Field(default_factory=dict)
    tenancy_cases: list[dict] = Field(default_factory=list, max_length=5000)
    transaction_cases: list[dict] = Field(default_factory=list, max_length=5000)
    ledger_entries: list[dict] = Field(default_factory=list, max_length=10000)
    daraja: dict = Field(default_factory=dict)
    daraja_callbacks: list[dict] = Field(default_factory=list, max_length=5000)
    database: dict = Field(default_factory=dict)
    pipeline: dict = Field(default_factory=dict)
    pipeline_source_files: list[SourceFile] = Field(default_factory=list, max_length=20)
    infrastructure_files: list[SourceFile] = Field(default_factory=list, max_length=20)
    outbound_webhook: dict = Field(default_factory=dict)

@app.post("/v1/bundle-assessments", dependencies=[Depends(require_key)])
def create_bundle_assessment(request: BundleRequest):
    """Assess supplied sanitized snapshots and synthetic observations only; makes no network calls."""
    try:
        report, risk = run_bundle(request.model_dump(exclude_unset=True))
        json_path, html_path = save_bundle_report(report, risk, settings.assessment_data_dir)
        store = EvidenceStore(f"{settings.assessment_data_dir}/evidence.sqlite3")
        event = store.append("assessment.completed", {
            "assessment_id": report.assessment_id,
            "target_id": report.target_id,
            "risk_score": risk["score"],
            "finding_count": risk["finding_count"],
        })
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid assessment bundle: {type(exc).__name__}") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Bundle assessment failed: {type(exc).__name__}") from exc
    return {"report": report, "risk": risk,
            "artifacts": {"json": json_path.name, "html": html_path.name},
            "evidence_event": event}
