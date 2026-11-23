import hmac
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel
from .config import settings
from .engine import assess
from .models import CheckName, TargetAuthorization
from .policy import PolicyError
from .reporting import save_report

app = FastAPI(title="PesaGuard Security Assessment", version="0.1.0",
    description="Authorized, bounded, non-destructive security checks.")

def require_key(x_assessment_key: str | None = Header(default=None)):
    if settings.assessment_api_key in {"", "change-me", "replace-with-a-long-random-local-key"}:
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
    return {"report": report, "artifacts": {"json": json_path.name, "html": html_path.name}}
